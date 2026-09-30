#!/usr/bin/env python3
"""Extract original C get_block(), then compare netascii bytes and state.

The oracle compiles the actual verified source, not a translated expectation.
Generated binaries, packets and results are confined to ignored private/.
"""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]


def function(source, signature):
    start = source.index(signature + "\n{")
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    # get_block contains no braces inside string literals/comments.
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


C_PREFIX = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#define OP_OACK 6
#define OP_DATA 3
#define RW_READ 1
struct tftp_file { off_t size, posn; int fd; };
struct tftp_transfer {
 unsigned int block, blocksize, windowsize, timeout, expansion;
 off_t offset;
 unsigned char opt_blocksize, opt_transize, opt_windowsize, opt_timeout;
 unsigned char netascii, carrylf, lastcarrylf;
 struct tftp_file *file;
};
static struct { char packet[8196]; size_t packet_buff_sz; struct tftp_transfer *srv_save; } state;
#define daemon (&state)
static unsigned char input[8192];
static int read_write(int fd, void *out, size_t n, int mode) {
 (void)fd; (void)mode; memcpy(out, input, n); return 1;
}
'''
C_MAIN = r'''
int main(void) {
 char hex[16385]; unsigned blocksize, carry;
 while (scanf("%u %u %16384s", &blocksize, &carry, hex) == 3) {
  size_t n = strcmp(hex, "-") ? strlen(hex)/2 : 0;
  if (blocksize < 1 || blocksize > 8192 || n > blocksize) return 2;
  for (size_t i = 0; i < n; i++) { unsigned b; if (sscanf(hex+2*i, "%2x", &b) != 1) return 3; input[i] = b; }
  struct tftp_file file = { .size=n, .posn=0, .fd=-1 };
  struct tftp_transfer t = { .block=1, .blocksize=blocksize, .netascii=1, .lastcarrylf=carry, .file=&file };
  state.srv_save = NULL; state.packet_buff_sz = sizeof(state.packet);
  ssize_t len = get_block(&t);
  printf("%u %u ", t.expansion, t.carrylf);
  if (len == 4) printf("-");
  for (ssize_t i=4; i<len; i++) printf("%02x", (unsigned char)state.packet[i]);
  puts("");
 }
 return 0;
}
'''
RS_MAIN = r'''
#[path = "TFTP_PATH"] mod tftp;
use std::io::{self, BufRead};
fn main() {
 for line in io::stdin().lock().lines() {
  let line = line.unwrap(); let fields: Vec<_> = line.split_whitespace().collect();
  let size: usize = fields[0].parse().unwrap(); let carry = fields[1] == "1";
  let bytes = if fields[2] == "-" { Vec::new() } else {
   fields[2].as_bytes().chunks_exact(2).map(|h| u8::from_str_radix(std::str::from_utf8(h).unwrap(),16).unwrap()).collect()
  };
  let mut out = vec![0;size]; let result = tftp::encode_netascii(&bytes, carry, &mut out);
  let mut inplace = vec![0;size]; inplace[..bytes.len()].copy_from_slice(&bytes);
  let inplace_result = tftp::encode_netascii_in_place(&mut inplace, bytes.len(), carry).unwrap();
  assert_eq!(inplace_result, result); assert_eq!(inplace[..result.len], out[..result.len]);
  print!("{} {} ", result.expansion, u8::from(result.carry_lf));
  if result.len == 0 { print!("-"); }
  for b in &out[..result.len] { print!("{b:02x}"); } println!();
 }
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, default=REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/tftp.c")
    ap.add_argument("--out", type=Path, default=REPO / "private/dnsmasq-rewrite/tftp-oracle")
    ap.add_argument("--random-cases", type=int, default=10000)
    args = ap.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(REPO / "private"):
        ap.error("output must be ignored private/")
    out.mkdir(parents=True, exist_ok=True)
    source = args.source.read_text()
    expected = json.loads((args.source.parents[2] / "identity.json").read_text())["patched_files"]["src/tftp.c"]
    if hashlib.sha256(args.source.read_bytes()).hexdigest() != expected:
        raise SystemExit("C source identity mismatch")
    (out / "oracle.c").write_text(C_PREFIX + function(source, "static ssize_t get_block(struct tftp_transfer *transfer)") + C_MAIN)
    (out / "driver.rs").write_text(RS_MAIN.replace("TFTP_PATH", str(REPO / "components/dnsmasq/src/tftp.rs")))
    subprocess.run(["cc", "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    rustc = shutil.which("rustc")
    if not rustc:
        rustc = str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc")
    subprocess.run([rustc, "--edition=2021", "-O", "-A", "dead_code", str(out / "driver.rs"), "-o", str(out / "driver")], check=True)
    cases = []
    for n in range(8):
        for value in itertools.product([0, 10, 13, 65], repeat=n):
            for carry in (0, 1):
                for size in {max(1, n), max(1, n + 1)}:
                    cases.append((size, carry, bytes(value)))
    rng = random.Random(0x293001)
    # Regression from independent review: the DATA header needs four extra
    # bytes beyond the largest permitted block in the C driver's buffer.
    for value in (b"A", b"\n", b"\r"):
        for carry in (0, 1):
            cases.append((8192, carry, value * 8192))
    for _ in range(args.random_cases):
        size = rng.choice([1, 8, 512, 1468, 4092])
        data = bytes(rng.choice([10, 10, rng.randrange(256)]) for _ in range(rng.randrange(size + 1)))
        cases.append((size, rng.randrange(2), data))
    payload = "".join(f"{size} {carry} {data.hex() or '-'}\n" for size, carry, data in cases)
    (out / "input.txt").write_text(payload)
    c = subprocess.run([str(out / "oracle")], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    rust = subprocess.run([str(out / "driver")], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    # Calibrate the comparator with both an exact match and a deliberate mismatch.
    assert c[0] == rust[0] and c[0] != rust[0] + "mutated"
    failures = [{"case": i, "c": a, "rust": b} for i, (a, b) in enumerate(zip(c, rust)) if a != b]
    complete = len(c) == len(rust) == len(cases)
    report = {"cases": len(cases), "c_outputs": len(c), "rust_outputs": len(rust), "failures": failures,
              "complete": complete, "c_source_sha256": expected,
              "rust_source_sha256": hashlib.sha256((REPO / "components/dnsmasq/src/tftp.rs").read_bytes()).hexdigest(),
              "input_sha256": hashlib.sha256(payload.encode()).hexdigest(),
              "scope": "get_block netascii byte transform, expansion and carry state; not whole TFTP service"}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k:v for k,v in report.items() if k != "failures"} | {"failure_count":len(failures)}))
    raise SystemExit(0 if complete and not failures else 1)


if __name__ == "__main__":
    main()
