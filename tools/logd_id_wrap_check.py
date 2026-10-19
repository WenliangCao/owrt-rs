#!/usr/bin/env python3
"""Compare Ring::list with exact ubox C log_list around the u32 ID wrap.

Run on Linux, never on the router. Seed the retained records, as in the V030
review harness; this does not claim to write four billion records or exercise
C signed-integer overflow. Every current_id used here is nonnegative.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name, declaration):
    start = source.rfind(declaration, 0, source.index("\n" + name + "("))
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


C_PREFIX = r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
struct log_head { unsigned int size, id; int priority, source; struct timespec ts; char data[]; };
static struct log_head *log, *log_end, *oldest, *newest;
static int current_id;
#define PAD(x) ((x % 4) ? (((x) - (x % 4)) + 4) : (x))
'''
C_MAIN = r'''
int main(void) {
    const struct { const char *name; uint32_t start; unsigned n; } cases[] = {
        { "normal", 0, 2 }, { "wrapped", UINT32_MAX - 1, 2 },
        { "both-sides", UINT32_MAX - 1, 4 }, { "ordinary-tail", 10, 3 }
    };
    const int counts[] = { -1, 0, 1, 2, 8 };
    for (unsigned c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        static _Alignas(struct log_head) unsigned char storage[4096];
        memset(storage, 0, sizeof(storage));
        log = (void *)storage; log_end = (void *)(storage + sizeof(storage)); oldest = log;
        struct log_head *head = log;
        for (unsigned i = 0; i < cases[c].n; i++) {
            head->size = 2; head->id = cases[c].start + i; memcpy(head->data, "x", 2);
            head = log_next(head, 2);
        }
        newest = head; current_id = (uint32_t)(cases[c].start + cases[c].n);
        for (unsigned i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
            printf("%s %d", cases[c].name, counts[i]);
            for (head = log_list(counts[i], NULL); head; head = log_list(counts[i], head))
                printf(" %u", head->id);
            puts("");
        }
    }
}
'''
RUST_MAIN = r'''
fn main() {
    for (name, start, n) in [("normal", 0, 2), ("wrapped", u32::MAX - 1, 2),
                              ("both-sides", u32::MAX - 1, 4), ("ordinary-tail", 10, 3)] {
        let mut ring = Ring::new(4096);
        ring.next_id = start;
        for _ in 0..n { ring.add(b"x", 0, 1, 0); }
        for count in [-1, 0, 1, 2, 8] {
            print!("{name} {count}");
            for record in ring.list(count) { print!(" {}", record.id); }
            println!();
        }
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ring", type=Path, required=True)
    parser.add_argument("--c-syslog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect", choices=("red", "green"), required=True)
    args = parser.parse_args()
    assert platform.system() == "Linux" and not Path("/etc/openwrt_release").exists()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = args.c_syslog.read_text()
    c = out / "wrap.c"
    c.write_text(C_PREFIX + function(source, "log_next", "static struct log_head*") + "\n"
                 + function(source, "log_list", "struct log_head*") + C_MAIN)
    rust = out / "wrap.rs"
    rust.write_text(args.ring.read_text() + RUST_MAIN)
    for name, command in (
        ("c", ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(c), "-o", str(out / "wrap-c")]),
        ("rust", ["rustc", "--edition=2021", "-O", str(rust), "-o", str(out / "wrap-rust")]),
    ):
        with (out / (name + "-build.log")).open("wb") as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    rounds = []
    for repeat in range(1, 5):
        outputs = {}
        for name in ("c", "rust"):
            output = subprocess.check_output([out / ("wrap-" + name)], text=True)
            (out / f"{name}-{repeat}.log").write_text(output)
            outputs[name] = output.splitlines()
        assert len(outputs["c"]) == len(outputs["rust"]) == 20
        differences = [dict(c=c, rust=r) for c, r in zip(outputs["c"], outputs["rust"]) if c != r]
        assert all(c == r for c, r in zip(outputs["c"], outputs["rust"])
                   if c.startswith(("normal ", "ordinary-tail ")))
        if args.expect == "green":
            assert not differences, differences
        else:
            assert differences and any(d["c"].startswith("wrapped 0 ") for d in differences)
        rounds.append({"repeat": repeat, "differences": differences, "normal_control_matches": True})
    result = {"expected": args.expect, "passed": True, "rounds": rounds,
              "ring_sha256": sha(args.ring), "c_syslog_sha256": sha(args.c_syslog),
              "harness_sha256": {p.name: sha(p) for p in (c, rust)},
              "binary_sha256": {name: sha(out / ("wrap-" + name)) for name in ("c", "rust")},
              "boundary": "seeded retained IDs; no C signed overflow or four-billion-message run"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
