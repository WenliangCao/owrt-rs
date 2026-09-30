#!/usr/bin/env python3
"""Compare the socket-independent TFTP path boundary with extracted C logic.

The C helper below is the bounded path-construction block from the pinned
patched ``tftp.c`` (lines 425-522), compiled as an oracle.  The Rust side is
the repository module under test.  Outputs belong under ignored ``private/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
C_DEFAULT = REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/tftp.c"
C_SHA256 = "a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3"

C_PROGRAM = r'''#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#define MAXDNAMESTR 503
static int resolve_path(const unsigned char *prefix, const unsigned char *input,
                        int lower, unsigned char *out) {
  unsigned char filename[4096], *p, *suspect;
  size_t n = strlen((const char *)input), plen = prefix ? strlen((const char *)prefix) : 0;
  if (n >= sizeof(filename) || (prefix && plen >= MAXDNAMESTR)) return 3;
  memcpy(filename, input, n + 1);
  for (p = filename; *p; p++)
    if (*p == '\\') *p = '/';
    else if (lower) *p = (unsigned char)tolower(*p);
  strcpy((char *)out, "/");
  if (prefix) {
    if (prefix[0] == '/') out[0] = 0;
    strncat((char *)out, (const char *)prefix, MAXDNAMESTR - strlen((char *)out));
    if (prefix[plen - 1] != '/')
      strncat((char *)out, "/", MAXDNAMESTR - strlen((char *)out));
    if (filename[0] == '/') {
      if (strstr((char *)filename, (char *)out) == (char *)filename) out[0] = 0;
      else memmove(filename, filename + 1, n);
    }
  } else if (filename[0] == '/') out[0] = 0;
  strncat((char *)out, (char *)filename, MAXDNAMESTR - strlen((char *)out));
  if (prefix) {
    suspect = (unsigned char *)strstr((char *)out, "/..");
    if (suspect && (suspect[3] == '/' || suspect[3] == 0)) return 2;
  }
  return 0;
}
static int hex(unsigned char *out, const char *in) {
  size_t n = strlen(in); if (n > 8190 || (n & 1)) return -1;
  for (size_t i=0; i<n/2; i++) { unsigned x; if (sscanf(in+2*i, "%2x", &x) != 1) return -1; out[i]=(unsigned char)x; }
  out[n/2]=0; return (int)n/2;
}
int main(void) {
  char ph[8192], fh[8192]; unsigned lower; unsigned char p[4096], f[4096], out[504];
  while (scanf("%8191s %8191s %u", ph, fh, &lower) == 3) {
    int pn = strcmp(ph, "-") ? hex(p, ph) : -1, fn = hex(f, fh);
    if (fn < 0 || pn == 0 || pn >= (int)sizeof(p)-1) return 4;
    int rc = resolve_path(pn < 0 ? NULL : p, f, lower, out);
    printf("%d", rc); if (!rc) { putchar(' '); for (size_t i=0; i<strlen((char *)out); i++) printf("%02x", out[i]); } putchar('\n');
  }
  return 0;
}
'''

RUST_PROGRAM = r'''#[path = "RUST_PATH"] mod service;
use std::io::{self, BufRead};
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2],16).unwrap()).collect() }
fn main() {
  for line in io::stdin().lock().lines() { let f: Vec<_> = line.unwrap().split_whitespace().map(str::to_string).collect();
    let p = (f[0] != "-").then(|| hex(&f[0])); let input = hex(&f[1]); let lc = f[2] == "1";
    match service::resolve_path(p.as_deref(), lc, &input) { Ok(out) => { print!("0 "); for b in out { print!("{b:02x}"); } println!(); }, Err(_) => println!("1") }
  }
}
'''

ADMISSION_C = r'''#include <stdio.h>
int main(void) {
  unsigned op, peer, count, single, max, p;
  while (scanf("%u %u %u %u %u", &op, &peer, &count, &single, &max) == 5) {
    int result = 3;
    for (unsigned i = 0; i < count; i++) { if (scanf("%u", &p) != 1) return 2;
      if (single && p == peer) result = (op == 1) ? 2 : 1;
    }
    if (single && result == 3 && count >= max) result = 0;
    puts(result == 3 ? "3" : result == 2 ? "2" : result == 1 ? "1" : "0");
  }
  return 0;
}
'''

ADMISSION_RUST = r'''#[path = "RUST_PATH"] mod service;
use std::io::{self, BufRead};
use std::net::SocketAddr;
fn main() {
  for line in io::stdin().lock().lines() { let f: Vec<_> = line.unwrap().split_whitespace().map(str::to_string).collect();
    let op: u16 = f[0].parse().unwrap(); let peer: u16 = f[1].parse().unwrap(); let n: usize = f[2].parse().unwrap();
    let single = f[3] == "1"; let max: usize = f[4].parse().unwrap();
    let peer: SocketAddr = format!("127.0.0.1:{peer}").parse().unwrap();
    let peers: Vec<_> = f[5..5+n].iter().map(|p| format!("127.0.0.1:{p}").parse().unwrap()).collect();
    let result = service::admission(&[0, op as u8], peer, &peers, single, max);
    println!("{}", match result { service::Admission::Ignore => 0, service::Admission::Existing(_) => 1, service::Admission::Replace(_) => 2, service::Admission::New => 3 });
  }
}
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=C_DEFAULT)
    parser.add_argument("--out", type=Path, default=REPO / "private/dnsmasq-rewrite/tftp-service-diff")
    args = parser.parse_args()
    source = args.source.resolve()
    if hashlib.sha256(source.read_bytes()).hexdigest() != C_SHA256:
        raise SystemExit("patched tftp.c identity mismatch")
    out = args.out.resolve()
    if not out.is_relative_to(REPO / "private"):
        raise SystemExit("--out must remain under private/")
    out.mkdir(parents=True, exist_ok=True)
    (out / "oracle.c").write_text(C_PROGRAM)
    (out / "driver.rs").write_text(RUST_PROGRAM.replace("RUST_PATH", str(REPO / "components/dnsmasq/src/tftp_service.rs")))
    cc = shutil.which("cc") or shutil.which("clang")
    rustc = shutil.which("rustc") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc")
    subprocess.run([cc, "-O1", "-Wall", "-Wextra", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    subprocess.run([rustc, "--edition=2021", "-O", "-A", "dead_code", str(out / "driver.rs"), "-o", str(out / "driver")], check=True)
    (out / "admission.c").write_text(ADMISSION_C)
    (out / "admission_driver.rs").write_text(ADMISSION_RUST.replace("RUST_PATH", str(REPO / "components/dnsmasq/src/tftp_service.rs")))
    subprocess.run([cc, "-O1", "-Wall", "-Wextra", str(out / "admission.c"), "-o", str(out / "admission")], check=True)
    subprocess.run([rustc, "--edition=2021", "-O", "-A", "dead_code", str(out / "admission_driver.rs"), "-o", str(out / "admission_driver")], check=True)
    cases = []
    prefixes = [None, b"/srv/tftp", b"srv/tftp", b"/"]
    names = [b"a.img", b"BOOT\\X.EFI", b"/srv/tftp/a", b"/other/a", b"../escape", b"a/../b", b"x/\xff"]
    rng = random.Random(0x293001)
    for _ in range(500):
        prefixes.append(rng.choice([None, b"/srv/tftp", b"srv"]))
        names.append(bytes(rng.choice(list(b"ab/._\\") + [0x80, 0xff]) for _ in range(rng.randrange(1, 24))))
    for prefix in prefixes:
        for name in names:
            if b"\0" in name or prefix == b"": continue
            cases.append(((prefix.hex() if prefix is not None else "-"), name.hex(), int(rng.randrange(2))))
    payload = "".join(f"{p} {n} {lc}\n" for p, n, lc in cases)
    (out / "input.txt").write_text(payload)
    c = subprocess.run([str(out / "oracle")], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    rust = subprocess.run([str(out / "driver")], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    failures = []
    hardening = 0
    for i, (a, b) in enumerate(zip(c, rust)):
        if a == b: continue
        prefix, name, _ = cases[i]
        if prefix != "-" and b == "1" and any(part == b".." for part in bytes.fromhex(name).replace(b"\\", b"/").split(b"/")):
            hardening += 1
        else:
            failures.append({"case": i, "c": a, "rust": b})
    result = {"cases": len(cases), "failures": failures, "intentional_hardening": hardening,
              "c_source_sha256": C_SHA256, "scope": "C path construction and admission boundary; no sockets"}
    admission_cases = []
    for _ in range(20000):
        count = rng.randrange(8)
        peers = [rng.randrange(1024, 65535) for _ in range(count)]
        peer = rng.choice(peers) if peers and rng.randrange(2) else rng.randrange(1024, 65535)
        admission_cases.append((rng.randrange(0, 8), peer, count, rng.randrange(2), rng.randrange(1, 8), peers))
    admission_payload = "".join(" ".join(map(str, (op, peer, count, single, maximum, *peers))) + "\n"
                                 for op, peer, count, single, maximum, peers in admission_cases)
    admission_c = subprocess.run([str(out / "admission")], input=admission_payload, text=True, capture_output=True, check=True).stdout.splitlines()
    admission_rust = subprocess.run([str(out / "admission_driver")], input=admission_payload, text=True, capture_output=True, check=True).stdout.splitlines()
    admission_failures = [{"case": i, "c": a, "rust": b} for i, (a, b) in enumerate(zip(admission_c, admission_rust)) if a != b]
    result.update({"admission_cases": len(admission_cases), "admission_failures": admission_failures})
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("failures", "admission_failures")} |
                     {"failure_count": len(failures), "admission_failure_count": len(admission_failures)}))
    return int(bool(failures or admission_failures))


if __name__ == "__main__":
    raise SystemExit(main())
