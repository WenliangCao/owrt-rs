#!/usr/bin/env python3
"""Differential check for the small EDNS boundary used by forward_service.

The generated C/Rust drivers and outputs stay below ignored ``private/``.
Only the exact OpenWrt dnsmasq ``skip_*``, ``find_pseudoheader`` and
``add_pseudoheader`` functions are compiled; no daemon or socket is started.
The comparison is intentionally limited to the ``optno == 0`` operation used
when forwarding a client query.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "private/network-research-20260929/dns/dnsmasq-2.93-openwrt/src"
HASHES = {
    "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
    "edns0.c": "420a55386ee3d41cef391b6443f735b18f7f205bf5c6d24cea6d28d5f2b55ed2",
    "dns-protocol.h": "4c6ed1c818c6a9b00bcdc1193bd364129780a3ef2b88c29475ee7bd6f6a826fe",
}


def extract(text: str, start: str, stop: str) -> str:
    begin = text.index(start)
    return text[begin : text.index(stop, begin)]


C_DRIVER = r'''
int main(void) {
  char *line = NULL; size_t cap = 0;
  while (getline(&line, &cap, stdin) > 0) {
    unsigned max; char hex[131074];
    if (sscanf(line, "%u %131073s", &max, hex) != 2 || max > 65535) return 3;
    union { struct dns_header aligned; unsigned char bytes[65536]; } storage = {0};
    unsigned char *packet = storage.bytes;
    size_t n = strcmp(hex, "-") == 0 ? 0 : strlen(hex) / 2;
    if (n > sizeof(storage.bytes)) return 4;
    for (size_t i = 0; i < n; i++) {
      unsigned byte; if (sscanf(hex + 2*i, "%2x", &byte) != 1) return 5;
      packet[i] = (unsigned char)byte;
    }
    dns_state.edns_pktsz = (int)max;
    size_t out = add_pseudoheader((struct dns_header *)packet, n, max, 0, NULL, 0, 0, 0);
    printf("%zu ", out);
    for (size_t i = 0; i < out; i++) printf("%02x", packet[i]);
    puts("");
  }
  free(line); return 0;
}
'''

RUST_DRIVER = r'''
#[path = "WIRE"] mod wire;
#[path = "FORWARD"] mod forward;
#[path = "SERVICE"] mod forward_service;
use std::io::{self, BufRead};
fn main() {
  for line in io::stdin().lock().lines() {
    let line = line.unwrap();
    let mut words = line.split_whitespace();
    let max: u16 = words.next().unwrap().parse().unwrap();
    let encoded = words.next().unwrap();
    let packet = if encoded == "-" { Vec::new() } else {
      (0..encoded.len()).step_by(2).map(|i| u8::from_str_radix(&encoded[i..i+2], 16).unwrap()).collect()
    };
    match forward_service::prepare_query(&packet, max) {
      Ok((output, _)) => {
        print!("{} ", output.len());
        for byte in output { print!("{byte:02x}"); }
        println!();
      },
      Err(_) => println!("0 -"),
    }
  }
}
'''


def build(output: Path, rustc: str, cc: str) -> None:
    actual = {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in HASHES}
    if actual != HASHES:
        raise SystemExit(f"reference source hash mismatch: {actual}")
    rfc = (SOURCE / "rfc1035.c").read_text()
    edns = (SOURCE / "edns0.c").read_text()
    c = r'''#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#include "dns-protocol.h"
struct dns_state { int edns_pktsz; } dns_state;
#define daemon (&dns_state)
void *whine_malloc(size_t);
int rrfilter(void *, ...);
#define RRFILTER_EDNS0 1
'''
    c += extract(rfc, "unsigned char *skip_name(", "size_t resize_packet(")
    c += extract(edns, "unsigned char *find_pseudoheader(", "/* replace == 0")
    c += extract(edns, "size_t add_pseudoheader(", "size_t add_do_bit(")
    c += r'''
void *whine_malloc(size_t n) { return calloc(1, n); }
int rrfilter(void *unused, ...) { (void)unused; return 0; }
'''
    # The extracted add_pseudoheader sees daemon as a pointer in the source.
    # C's declaration above intentionally matches that access shape.
    c += C_DRIVER
    (output / "oracle.c").write_text(c)
    rust = (RUST_DRIVER.replace("WIRE", str(ROOT / "components/dnsmasq/src/dns/wire.rs"))
            .replace("FORWARD", str(ROOT / "components/dnsmasq/src/dns/forward.rs"))
            .replace("SERVICE", str(ROOT / "components/dnsmasq/src/dns/forward_service.rs")))
    (output / "driver.rs").write_text(rust)
    subprocess.run([cc, "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-I", str(SOURCE),
                    str(output / "oracle.c"), "-o", str(output / "oracle")], check=True)
    subprocess.run([rustc, "--edition=2021", "-A", "dead_code", str(output / "driver.rs"),
                    "-o", str(output / "driver")], check=True)


def query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
    packet = bytearray(b"\0\0\x01\0\0\x01\0\0\0\0\0\0")
    for label in name.split("."):
        packet.extend((len(label),)); packet.extend(label.encode())
    packet.append(0); packet.extend(qtype.to_bytes(2, "big")); packet.extend(qclass.to_bytes(2, "big"))
    return bytes(packet)


def corpus(seed: int, count: int) -> list[tuple[int, bytes]]:
    rng = random.Random(seed); cases: list[tuple[int, bytes]] = []
    for name in ["a.test", "Mixed.Example", "x", "a." + "b" * 60 + ".test"]:
        cases.append((512, query(name)))
    # Existing OPT, multiple additional records, signed TKEY, and a trailing
    # opaque suffix exercise the C insertion and signed boundaries.
    base = query("a.test")
    opt = base + bytes([0, 0, 41]) + (1232).to_bytes(2, "big") + bytes(6)
    opt = bytearray(opt); opt[10:12] = (1).to_bytes(2, "big")
    cases.extend([(512, bytes(opt)), (1400, bytes(opt))])
    tkey = bytearray(query("gss.test", 249, 1)); cases.append((1232, bytes(tkey)))
    for _ in range(count):
        packet = bytearray(query(rng.choice(["a.test", "x.example", "long." + "z" * rng.randrange(1, 20)])))
        if rng.randrange(3) == 0:
            packet.extend(rng.randbytes(rng.randrange(0, 8)))
        cases.append((rng.choice([512, 768, 1232, 1400, 4096]), bytes(packet)))
    # A counted opaque RR positions end-of-message exactly at each output
    # boundary. Trailing bytes reveal C's buffer mutations when it returns
    # the original plen after writing an OPT but cannot increment arcount.
    for maximum in [512, 768, 1232, 1400, 4096]:
        for remaining in range(10, 17):
            base = bytearray(query("boundary.test"))
            base[10:12] = (1).to_bytes(2, "big")
            length = maximum - remaining - len(base) - 11
            base.extend(bytes([0]) + (65000).to_bytes(2, "big") + (1).to_bytes(2, "big"))
            base.extend(bytes(4) + length.to_bytes(2, "big") + b"x" * length)
            for tail in [0, 1, 4, 10, 11, 17]:
                cases.append((maximum, bytes(base) + b"z" * tail))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--output", type=Path, default=ROOT / "private/dnsmasq-rs/forward-service/differential")
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args(); output = args.output.resolve()
    if not output.is_relative_to(ROOT / "private") or output.exists():
        parser.error("choose a fresh directory under ignored private/")
    output.mkdir(parents=True)
    build(output, args.rustc, args.cc)
    cases = corpus(293, args.count)
    input_text = "".join(f"{limit} {packet.hex()}\n" for limit, packet in cases)
    (output / "input.txt").write_text(input_text)
    outputs = {}
    for name in ["oracle", "driver"]:
        run = subprocess.run([str(output / name)], input=input_text, text=True, capture_output=True, check=True)
        outputs[name] = run.stdout.splitlines(); (output / f"{name}.stdout").write_text(run.stdout)
        assert len(outputs[name]) == len(cases), f"{name}: output-count calibration failed"
    mismatches = [
        {"index": i, "limit": cases[i][0], "packet": cases[i][1].hex(), "c": c, "rust": r}
        for i, (c, r) in enumerate(zip(outputs["oracle"], outputs["driver"])) if c != r
    ]
    summary = {"cases": len(cases), "mismatches": len(mismatches), "seed": 293,
               "new_boundary_cases": 210,
               "source_sha256": HASHES, "scope": "edns0 add_pseudoheader optno=0"}
    (output / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2)); return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
