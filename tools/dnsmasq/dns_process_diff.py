#!/usr/bin/env python3
"""Differential address-policy check against exact dnsmasq C helpers.

The C executable is built from the pinned ``private_net`` and ``private_net6``
implementations in the reference tree.  The Rust executable runs the bounded
``process_reply`` address-policy path on independently generated packets.  The
scope is deliberately narrow: C transaction lifetime, cache/SOA, DNSSEC,
doctor/UBus, EDE and TCP fallback are not claimed here.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
HASHES = {
    "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
}


def extract_function(text: str, name: str) -> str:
    marker = text.index(name)
    start = text.rfind("\n", 0, marker)
    brace = text.index("{", marker)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


C_PREFIX = r"""
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
"""
C_DRIVER = r"""
int main(void) {
  char family, text[128];
  while (scanf(" %c %127s", &family, text) == 2) {
    if (family == '4') {
      struct in_addr address;
      if (inet_pton(AF_INET, text, &address) != 1) return 2;
      printf("%d\n", private_net(address, 1));
    } else if (family == '6') {
      struct in6_addr address;
      if (inet_pton(AF_INET6, text, &address) != 1) return 3;
      printf("%d\n", private_net6(&address, 1));
    } else return 4;
  }
  return 0;
}
"""

RUST_DRIVER = r"""
mod dns {
  #[path = "WIRE"] pub mod wire;
  #[path = "DOCTOR"] pub mod doctor;
  #[path = "PROCESS"] pub mod process;
}
use std::io::{self, BufRead};
use std::net::IpAddr;
use dns::process::{process_reply, AddressPolicy};
fn main() {
  for line in io::stdin().lock().lines() {
    let words: Vec<_> = line.unwrap().split_whitespace().map(str::to_owned).collect();
    let qtype: u16 = words[0].parse().unwrap();
    let encoded = &words[1];
    let mut packet: Vec<u8> = (0..encoded.len()).step_by(2)
      .map(|i| u8::from_str_radix(&encoded[i..i+2], 16).unwrap()).collect();
    let report = process_reply(&mut packet, &AddressPolicy { stop_rebind: true, ..Default::default() });
    match report {
      Ok(report) => {
        let header = dns::wire::Header::parse(&packet).unwrap();
        println!("{} {} {} {}", qtype, u8::from(report.blocked_rebind), header.answers, header.rcode());
      },
      Err(_) => println!("{} error", qtype),
    }
  }
}
"""


def packet(address: ipaddress._BaseAddress) -> bytes:
    name = b"\x06target\x04test\0"
    qtype = 1 if address.version == 4 else 28
    data = address.packed
    header = (7).to_bytes(2, "big") + (0x8180).to_bytes(2, "big") + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + b"\0\0\0\0"
    question = name + qtype.to_bytes(2, "big") + b"\0\1"
    answer = b"\xc0\x0c" + qtype.to_bytes(2, "big") + b"\0\1\0\0\0\x3c" + len(data).to_bytes(2, "big") + data
    return header + question + answer


def build(output: Path, cc: str, rustc: str) -> None:
    text = (SOURCE / "rfc1035.c").read_text()
    c = C_PREFIX + extract_function(text, "int private_net(") + extract_function(text, "int private_net6(") + C_DRIVER
    (output / "oracle.c").write_text(c)
    rust = RUST_DRIVER.replace("WIRE", str(ROOT / "components/dnsmasq/src/dns/wire.rs"))
    rust = rust.replace("DOCTOR", str(ROOT / "components/dnsmasq/src/dns/doctor.rs"))
    rust = rust.replace("PROCESS", str(ROOT / "components/dnsmasq/src/dns/process.rs"))
    (output / "driver.rs").write_text(rust)
    commands = [
        [cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(output / "oracle.c"), "-o", str(output / "oracle")],
        [rustc, "--edition=2021", "-A", "dead_code", str(output / "driver.rs"), "-o", str(output / "driver")],
    ]
    with (output / "build.log").open("w") as log:
        for command in commands:
            run = subprocess.run(command, text=True, capture_output=True)
            log.write(run.stdout + run.stderr)
            run.check_returncode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "private/dnsmasq-rewrite/dns-process/run-01")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    parser.add_argument("--seed", type=int, default=293004)
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "private"):
        parser.error("output must stay under ignored private/")
    if output.exists() and any(output.iterdir()):
        parser.error("output must be a fresh directory")
    output.mkdir(parents=True, exist_ok=True)
    actual = hashlib.sha256((SOURCE / "rfc1035.c").read_bytes()).hexdigest()
    if actual != HASHES["rfc1035.c"]:
        raise SystemExit(f"reference source hash mismatch: {actual}")
    build(output, args.cc, args.rustc)

    rng = random.Random(args.seed)
    addresses = [
        ipaddress.ip_address(value)
        for value in [
            "0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "172.16.0.1",
            "192.168.1.1", "169.254.1.1", "192.0.2.1", "198.51.100.1",
            "203.0.113.1", "127.0.0.1", "255.255.255.255", "8.8.8.8",
            "::", "::1", "fe80::1", "fec0::1", "fc00::1", "2001:db8::1", "2001:4860:4860::8888",
        ]
    ]
    for _ in range(args.count):
        addresses.append(ipaddress.ip_address(rng.getrandbits(32)))
        addresses.append(ipaddress.ip_address(rng.getrandbits(128)))
    c_lines, rust_lines, labels = [], [], []
    for address in addresses:
        family = "4" if address.version == 4 else "6"
        c_lines.append(f"{family} {address}\n")
        rust_lines.append(f"{1 if address.version == 4 else 28} {packet(address).hex()}\n")
        labels.append(str(address))
    (output / "input.c").write_text("".join(c_lines))
    (output / "input.rust").write_text("".join(rust_lines))
    c_run = subprocess.run([str(output / "oracle")], input="".join(c_lines), text=True, capture_output=True, check=True)
    rust_run = subprocess.run([str(output / "driver")], input="".join(rust_lines), text=True, capture_output=True, check=True)
    c_values = c_run.stdout.splitlines()
    rust_values = rust_run.stdout.splitlines()
    mismatches = []
    if len(c_values) != len(rust_values):
        raise RuntimeError(f"output count differs: C={len(c_values)} Rust={len(rust_values)}")
    for index, (c_value, rust_value) in enumerate(zip(c_values, rust_values)):
        expected = c_value == "1"
        rust_blocked = rust_value.split()[1] == "1"
        if expected != rust_blocked:
            mismatches.append({"label": labels[index], "c_private": expected, "rust": rust_value})
    (output / "oracle.stdout").write_text(c_run.stdout)
    (output / "driver.stdout").write_text(rust_run.stdout)
    summary = {
        "addresses": len(addresses), "mismatches": len(mismatches), "seed": args.seed,
        "source_sha256": HASHES, "scope": "private_net/private_net6 plus one matching A/AAAA answer; no transaction/cache/TCP claims",
    }
    (output / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(mismatches))


if __name__ == "__main__":
    raise SystemExit(main())
