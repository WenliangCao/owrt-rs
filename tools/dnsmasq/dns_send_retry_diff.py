#!/usr/bin/env python3
"""Compare unchanged pinned C retry_send with the private Rust UDP send helper.

Syscall outcomes and nanosleep interruption are controlled; this is a helper
oracle, not evidence of naturally occurring socket pressure or daemon equality.
"""
import argparse
import copy
import errno
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE_HASHES = {
    "util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973",
    "forward.c": "ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95",
}
C_PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
static int sleep_error, waits, used;
static char events[50000];
static int controlled_sleep(const struct timespec *request, struct timespec *remaining)
{
  assert(request->tv_sec == 0 && request->tv_nsec == 10000 && remaining == NULL);
  events[used++] = 'W';
  waits++;
  if (sleep_error) { errno = sleep_error; return -1; }
  return 0;
}
#define nanosleep controlled_sleep
'''
C_MAIN = r'''
int main(void)
{
  char line[200000];
  while (fgets(line, sizeof(line), stdin))
    {
      int sends = 0, error;
      long rc = 0;
      char *token = strtok(line, " \n");
      waits = used = 0;
      do {
        assert(token && sscanf(token, "%ld,%d,%d", &rc, &error, &sleep_error) == 3);
        errno = error;
        sends++;
        events[used++] = 'S';
        if (!retry_send(rc)) break;
        token = strtok(NULL, " \n");
      } while (1);
      events[used] = 0;
      printf("%ld %d %d %d %s\n", rc, errno, sends, waits, events);
    }
  return 0;
}
'''
RUST_MAIN = r'''
fn main() {
    use std::cell::{Cell, RefCell};
    use std::io::BufRead;
    for line in io::stdin().lock().lines() {
        let input: Vec<Vec<i64>> = line.unwrap().split_whitespace()
            .map(|item| item.split(',').map(|number| number.parse().unwrap()).collect()).collect();
        let sends = Cell::new(0);
        let waits = Cell::new(0);
        let sleep_error = Cell::new(0);
        let events = RefCell::new(String::new());
        let result = send_udp_with_retry(|| {
            let item = &input[sends.get()];
            sends.set(sends.get() + 1);
            sleep_error.set(item[2] as i32);
            events.borrow_mut().push('S');
            if item[0] < 0 { Err(io::Error::from_raw_os_error(item[1] as i32)) }
            else { Ok(item[0] as usize) }
        }, || {
            waits.set(waits.get() + 1);
            events.borrow_mut().push('W');
            if sleep_error.get() == 0 { Ok(()) }
            else { Err(io::Error::from_raw_os_error(sleep_error.get())) }
        });
        let (length, error) = match result {
            Ok(length) => (length as i64, 0),
            Err(error) => (-1, error.raw_os_error().unwrap()),
        };
        println!("{} {} {} {} {}", length, error, sends.get(), waits.get(), events.borrow());
    }
}
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def function(source, signature):
    start = source.index(signature)
    end = source.index("\n}\n", start) + 3
    return source[start:end]


def corpus():
    success = (64, 0, 0)
    for length in (0, 1, 64):
        for stale in (0, errno.EINTR, errno.EAGAIN, errno.ENETUNREACH):
            yield f"success-{length}-stale-{stale}", [(length, stale, 0)]
    for error in (errno.EINVAL, errno.EMSGSIZE, errno.ENETUNREACH, errno.ECONNREFUSED, errno.ENOMEM, errno.ENOBUFS):
        yield f"terminal-{error}", [(-1, error, 0), success]
    for count in (1, 2, 999):
        yield f"interrupted-{count}", [(-1, errno.EINTR, 0)] * count + [success]
    for label, error in (("again", errno.EAGAIN), ("wouldblock", errno.EWOULDBLOCK)):
        for count in (0, 1, 999, 1000, 1001, 1002):
            yield f"{label}-{count}", [(-1, error, 0)] * count + [success]
    for before in (1, 999, 1000):
        for after in (1, 1000, 1001):
            yield f"reset-{before}-{after}", ([(-1, errno.EAGAIN, 0)] * before
                + [(-1, errno.EINTR, 0)] + [(-1, errno.EAGAIN, 0)] * after + [success])
    for index in (0, 500, 999, 1000):
        for error in (errno.EINTR, errno.EINVAL):
            rows = [(-1, errno.EAGAIN, 0)] * 1001 + [success]
            rows[index] = (-1, errno.EAGAIN, error)
            yield f"sleep-error-{index}-{error}", rows
    yield "interrupted-final-wait-new-budget", ([(-1, errno.EAGAIN, 0)] * 1000
        + [(-1, errno.EAGAIN, errno.EINTR)] + [(-1, errno.EAGAIN, 0)] * 1000 + [success])
    yield "terminal-resets-next-call", [(-1, errno.EAGAIN, 0)] * 999 + [(-1, errno.ENOBUFS, 0)]
    yield "next-call-fresh-budget", [(-1, errno.EAGAIN, 0)] * 1000 + [success]


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("observation count differs")
    return [index for index, (left, right) in enumerate(zip(expected, actual)) if left != right]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    assert "private" in out.parts and not out.exists()
    out.mkdir(parents=True)
    source = args.reference_source.resolve() / "src"
    for name, expected in SOURCE_HASHES.items():
        assert digest(source / name) == expected, name
    rust = ROOT / "components/dnsmasq/src/dns/upstream.rs"
    c_body = function((source / "util.c").read_text(), "int retry_send(ssize_t rc)\n")
    rust_body = function(rust.read_text(), "fn send_udp_with_retry(\n")
    (out / "oracle.c").write_text(C_PREFIX + c_body + C_MAIN)
    (out / "probe.rs").write_text("use std::io;\n" + rust_body + RUST_MAIN)
    commands = [["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(out / "oracle.c"), "-o", str(out / "oracle")],
                [args.rustc, "+1.98.1", "--edition=2021", str(out / "probe.rs"), "-o", str(out / "probe")]]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, text=True)
        (out / f"build-{index}.json").write_text(json.dumps({"command": command, "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
        result.check_returncode()
    cases = list(corpus())
    wire = "".join(" ".join(",".join(map(str, row)) for row in rows) + "\n" for _, rows in cases)
    (out / "input").write_text(wire)
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    outputs = []
    for side in ("oracle", "probe"):
        result = subprocess.run([str(out / side)], input=wire, capture_output=True, text=True)
        (out / f"{side}.stdout").write_text(result.stdout)
        (out / f"{side}.stderr").write_text(result.stderr)
        result.check_returncode()
        rows = result.stdout.splitlines()
        assert len(rows) == len(cases)
        outputs.append(rows)
    expected, actual = outputs
    assert not compare(expected, copy.copy(expected))
    changed = copy.copy(expected)
    changed[0] += "W"
    assert compare(expected, changed) == [0]
    try:
        compare(expected, expected[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing observation calibration")
    if args.inject_error:
        actual[0] += "W"
    differences = compare(expected, actual)
    report = {"scope": "source-derived send retry helper; controlled syscall outcomes",
              "reference_sources": SOURCE_HASHES, "rust_source_sha256": digest(rust),
              "rust_helper_sha256": hashlib.sha256(rust_body.encode()).hexdigest(),
              "tool_sha256": digest(__file__), "c_binary_sha256": digest(out / "oracle"),
              "rust_binary_sha256": digest(out / "probe"), "cases": len(cases),
              "sends": sum(int(row.split()[2]) for row in expected),
              "waits": sum(int(row.split()[3]) for row in expected),
              "differences": [cases[index][0] for index in differences],
              "injected_error": args.inject_error, "negative_calibrations": ["extra-wait", "missing-row"]}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(differences))


if __name__ == "__main__":
    raise SystemExit(main())
