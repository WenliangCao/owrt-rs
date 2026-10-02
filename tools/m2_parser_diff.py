#!/usr/bin/env python3
"""Bounded exact-C differential screen for DNS/DHCP packet parsers.

The corpus is deterministic and deliberately small enough to rerun in a fresh
directory.  The C side is extracted from the hash-pinned dnsmasq source and
the Rust side imports the current DHCP packet parser.  This is a parser safety
and compatibility check only: no daemon, socket, router, performance window,
or exploit payload is involved.

All generated sources, inputs, stdout/stderr, identities, and comparison rows
are written below ``private/``.  The default M2 evidence location is
``private/dnsmasq-rewrite/evidence/M2/parsers/run-01``.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
DEFAULT_OUT = ROOT / "private/dnsmasq-rewrite/evidence/M2/parsers/run-01"
SOURCE_HASHES = {
    "rfc2131.c": "14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c",
    "dhcp-protocol.h": "88c60df465d1038c8cc6655e42d4fdc4bcdd9bc44519c2f4b8e380e56bab8772",
    "config.h": "dacbe1f8d0e03d93e53a81901956b07ab7a5059d1e5db3225150a9688a1122da",
}
PACKET_HASH = "components/dnsmasq/src/dhcp/packet.rs"
MAX_INPUT = 4096


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_function(source: str, name: str) -> str:
    pattern = re.compile(
        r"\n(?:static\s+)?[A-Za-z_][\w \t*]*[ \t*]\b"
        + re.escape(name)
        + r"\([^;{}]*\)\s*\{"
    )
    match = pattern.search(source)
    if not match:
        raise ValueError(f"missing C function {name}")
    brace = source.index("{", match.start())
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start() : end]


C_PREFIX = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define OPTION_PAD 0
#define OPTION_OVERLOAD 52
#define OPTION_MESSAGE_TYPE 53
#define OPTION_HOSTNAME 12
#define OPTION_REQUESTED_OPTIONS 55
#define OPTION_MAXMESSAGE 57
#define OPTION_VENDOR_ID 60
#define OPTION_CLIENT_ID 61
#define OPTION_CLIENT_FQDN 81
#define OPTION_REQUESTED_IP 50
#define OPTION_SERVER_IDENTIFIER 54
#define OPTION_END 255
#define BOOTREQUEST 1
#define DHCP_CHADDR_MAX 16
#define DHCP_COOKIE 0x63825363
#define option_len(opt) ((unsigned)(opt)[1])
#define option_ptr(opt, offset) ((opt) + 2 + (offset))
struct dhcp_packet {
  u8 op, htype, hlen, hops; u32 xid; u16 secs, flags;
  u8 ciaddr[4], yiaddr[4], siaddr[4], giaddr[4];
  u8 chaddr[16], sname[64], file[128], options[312];
};
'''

C_DRIVER = r'''
static size_t decode(const char *text, unsigned char *out) {
  if (!strcmp(text, "-")) return 0;
  size_t n = strlen(text);
  if ((n & 1) || n / 2 > 4096) return (size_t)-1;
  for (size_t i = 0; i < n / 2; i++) {
    unsigned value;
    if (sscanf(text + i * 2, "%2x", &value) != 1) return (size_t)-1;
    out[i] = (unsigned char)value;
  }
  return n / 2;
}
static void print_hex(const unsigned char *bytes, size_t length) {
  if (!length) { putchar('-'); return; }
  for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}
static void print_option(struct dhcp_packet *mess, size_t size, int code, int minsize) {
  unsigned char *found = option_find(mess, size, code, minsize);
  if (!found) { printf("-"); return; }
  unsigned length = option_len(found);
  printf("%u:", length);
  print_hex(option_ptr(found, 0), length);
}
int main(void) {
  char *line = NULL; size_t cap = 0;
  while (getline(&line, &cap, stdin) > 0) {
    char encoded[8194];
    if (sscanf(line, "%8193s", encoded) != 1) return 2;
    union { max_align_t align; unsigned char bytes[4096]; } storage;
    memset(storage.bytes, 0, sizeof(storage.bytes));
    size_t size = decode(encoded, storage.bytes);
    if (size == (size_t)-1) return 3;
    struct dhcp_packet *mess = (struct dhcp_packet *)storage.bytes;
    int status = 0;
    if (size < 236) status = 1;                 /* TruncatedHeader */
    else if (mess->op != BOOTREQUEST) status = 2; /* NotRequest */
    else if (mess->hlen > DHCP_CHADDR_MAX) status = 3; /* HardwareAddressTooLong */
    else if (mess->htype == 0 && mess->hlen != 0) status = 4; /* HardwareTypeMissing */
    unsigned char *message_type = NULL;
    if (!status) message_type = option_find(mess, size, OPTION_MESSAGE_TYPE, 1);
    if (!status && message_type && size >= 240) {
      const unsigned char cookie[4] = {0x63, 0x82, 0x53, 0x63};
      if (memcmp(mess->options, cookie, 4) != 0) status = 5; /* BadCookie */
    }
    printf("%d", status);
    if (!status) {
      putchar(' '); print_option(mess, size, OPTION_MESSAGE_TYPE, 1);
      putchar(' '); print_option(mess, size, OPTION_OVERLOAD, 1);
      putchar(' '); print_option(mess, size, OPTION_HOSTNAME, 1);
      putchar(' '); print_option(mess, size, OPTION_REQUESTED_OPTIONS, 0);
      putchar(' '); print_option(mess, size, OPTION_MAXMESSAGE, 2);
      putchar(' '); print_option(mess, size, OPTION_VENDOR_ID, 0);
      putchar(' '); print_option(mess, size, OPTION_CLIENT_ID, 1);
      putchar(' '); print_option(mess, size, OPTION_CLIENT_FQDN, 3);
      putchar(' '); print_option(mess, size, OPTION_REQUESTED_IP, 4);
      putchar(' '); print_option(mess, size, OPTION_SERVER_IDENTIFIER, 4);
    }
    putchar('\n');
  }
  free(line); return 0;
}
'''

RUST_DRIVER = r'''
#[path = "HOSTS"] mod hosts;
#[path = "PACKET"] mod packet;
use packet::Packet;
use std::io::{self, BufRead};
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_owned(); }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn option(packet: Packet<'_>, code: u8, min: usize) -> String {
    packet.option(code, min).map_or_else(|| "-".to_owned(), |v| format!("{}:{}", v.len(), hex(v)))
}
fn status(error: packet::ParseError) -> u8 {
    match error {
        packet::ParseError::TruncatedHeader => 1,
        packet::ParseError::NotRequest => 2,
        packet::ParseError::HardwareAddressTooLong => 3,
        packet::ParseError::HardwareTypeMissing => 4,
        packet::ParseError::BadCookie => 5,
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let encoded = line.trim();
        if encoded == "-" { println!("1"); continue; }
        if encoded.len() & 1 != 0 || encoded.len() / 2 > 4096 { panic!("invalid input"); }
        let bytes: Vec<u8> = (0..encoded.len()).step_by(2)
            .map(|i| u8::from_str_radix(&encoded[i..i + 2], 16).unwrap()).collect();
        let parsed = Packet::parse(&bytes);
        match parsed {
            Err(error) => println!("{}", status(error)),
            Ok(packet) => println!("0 {} {} {} {} {} {} {} {} {} {}",
                option(packet, 53, 1), option(packet, 52, 1), option(packet, 12, 1),
                option(packet, 55, 0), option(packet, 57, 2), option(packet, 60, 0),
                option(packet, 61, 1), option(packet, 81, 3), option(packet, 50, 4),
                option(packet, 54, 4)),
        }
    }
}
'''


def build(out: Path, source: Path, cc: str, rustc: str) -> dict[str, str]:
    hashes = {name: sha256(source / name) for name in SOURCE_HASHES}
    if hashes != SOURCE_HASHES:
        raise RuntimeError(f"exact source identity mismatch: {hashes}")
    rfc = (source / "rfc2131.c").read_text()
    c = C_PREFIX + extract_function(rfc, "option_find1") + extract_function(rfc, "option_find") + C_DRIVER
    (out / "oracle.c").write_text(c)
    rust = RUST_DRIVER.replace("HOSTS", str(ROOT / "components/dnsmasq/src/hosts.rs"))
    rust = rust.replace("PACKET", str(ROOT / PACKET_HASH))
    (out / "driver.rs").write_text(rust)
    commands = [
        [cc, "-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-Wall", "-Wextra",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"),
         "-o", str(out / "oracle")],
        [rustc, "--edition=2021", "-A", "dead_code", "-A", "unused_imports", str(out / "driver.rs"),
         "-o", str(out / "driver")],
    ]
    log = out / "build.log"
    log.write_text("")
    for command in commands:
        run = subprocess.run(command, text=True, capture_output=True)
        with log.open("a") as stream:
            stream.write("$ " + " ".join(command) + "\n")
            stream.write(run.stdout + run.stderr)
        if run.returncode:
            raise RuntimeError(f"build failed ({run.returncode}); see {log}")
    return hashes | {PACKET_HASH: sha256(ROOT / PACKET_HASH)}


def put_option(region: bytearray, code: int, value: bytes) -> None:
    region.extend((code, len(value))); region.extend(value)


def packet(options: bytes = b"", *, length: int = 548, op: int = 1,
           htype: int = 1, hlen: int = 6, cookie: bool = True) -> bytes:
    data = bytearray(max(236, length))
    data[0], data[1], data[2] = op, htype, hlen
    data[4:8] = b"M2PK"
    if cookie:
        data[236:240] = b"\x63\x82\x53\x63"
    data[240:240 + len(options)] = options
    return bytes(data[:length])


def corpus(seed: int, mutations: int) -> list[tuple[str, bytes]]:
    rng = random.Random(seed)
    rows: list[tuple[str, bytes]] = []
    def add(label: str, value: bytes) -> None:
        if len(value) <= MAX_INPUT:
            rows.append((label, value))

    for length in [0, 1, 2, 15, 44, 107, 108, 235, 236, 237, 239, 240, 241, 242,
                   255, 299, 300, 548, 549, 1024, 4096]:
        add(f"zero/{length}", bytes(length))
        add(f"header/{length}", packet(length=length))
    for op in [0, 1, 2, 255]:
        for htype in [0, 1, 255]:
            for hlen in [0, 1, 6, 16, 17, 255]:
                add(f"header-fields/{op}/{htype}/{hlen}", packet(op=op, htype=htype, hlen=hlen))

    fixed = [
        ("empty", b"\xff"),
        ("pad-end", b"\0\0\xff"),
        ("duplicate-short-valid", bytes([53, 0, 53, 1, 3, 255])),
        ("duplicate-valid", bytes([53, 1, 3, 53, 4, 1, 2, 3, 4, 255])),
        ("truncated-tag", b"\x35"),
        ("truncated-length", b"\x35\x04\x01"),
        ("declared-long", b"\x35\xff\x01\x02\x03\xff"),
        ("end-then-data", b"\xff\x35\x01\x03"),
        ("overload-file", bytes([52, 1, 1, 53, 1, 3, 255])),
        ("overload-sname", bytes([52, 1, 2, 53, 1, 3, 255])),
        ("overload-both", bytes([52, 1, 3, 53, 1, 3, 255])),
        ("fqdn-short", bytes([81, 2, 0, 0, 255])),
        ("max-message-short", bytes([57, 1, 0, 255])),
    ]
    for label, options in fixed:
        for cookie in [False, True]:
            add(f"fixed/{label}/cookie-{int(cookie)}", packet(options, cookie=cookie))

    # Valid options with explicit boundaries and all overload regions.
    options = bytearray(b"\x63\x82\x53\x63")
    put_option(options, 53, b"\x01")
    put_option(options, 55, bytes(range(0, 32)))
    put_option(options, 57, b"\x05\xdc")
    put_option(options, 60, b"PXEClient")
    put_option(options, 61, b"\x01client")
    put_option(options, 81, b"\x00\x00\x00")
    options.append(255)
    add("valid/mixed", packet(bytes(options[4:])))
    for overload in [1, 2, 3, 4, 7, 255]:
        data = bytearray([52, 1, overload, 255])
        value = bytes([53, 1, overload, 255])
        base = bytearray(packet(bytes(data)))
        base[108:108 + len(value)] = value
        base[44:44 + len(value)] = value
        add(f"overload/{overload}", bytes(base))

    seeds = [packet(bytes([53, 1, 1, 255])), packet(bytes([53, 1, 3, 12, 4]) + b"node" + bytes([255]))]
    for index in range(mutations):
        base = bytearray(rng.choice(seeds))
        action = index % 4
        if action == 0:
            base = base[:rng.randrange(len(base) + 1)]
        elif action == 1:
            for _ in range(1 + rng.randrange(4)):
                base[rng.randrange(len(base))] = rng.randrange(256)
        elif action == 2:
            at = rng.randrange(236, len(base) + 1)
            base[at:at] = rng.randbytes(rng.randrange(1, 12))
        else:
            base.extend(rng.randbytes(rng.randrange(1, 16)))
        add(f"mutation/{index:04}", bytes(base))
    return rows


def run(binary: Path, inputs: str, out: Path, name: str) -> list[str]:
    result = subprocess.run([str(binary)], input=inputs, text=True, capture_output=True)
    (out / f"{name}.stdout").write_text(result.stdout)
    (out / f"{name}.stderr").write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f"{name} exited {result.returncode}; see {out}/{name}.stderr")
    lines = result.stdout.splitlines()
    if len(lines) != len(inputs.splitlines()):
        raise RuntimeError(f"{name} emitted {len(lines)} rows for {len(inputs.splitlines())} inputs")
    return lines


def compare_rows(reference: list[str], candidate: list[str]) -> list[int]:
    if len(reference) != len(candidate):
        raise ValueError(f"row count differs: {len(reference)} != {len(candidate)}")
    return [index for index, (left, right) in enumerate(zip(reference, candidate)) if left != right]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=20261002)
    parser.add_argument("--mutations", type=int, default=512)
    parser.add_argument("--cc", default=shutil.which("cc") or "cc")
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    if not out.is_relative_to(ROOT / "private"):
        parser.error("--out must stay below ignored private/")
    if out.exists() and any(out.iterdir()):
        parser.error("--out must be a fresh directory")
    out.mkdir(parents=True, exist_ok=True)
    identities = build(out, source, args.cc, args.rustc)
    cases = corpus(args.seed, args.mutations)
    inputs = "".join(f"{data.hex() or '-'}\n" for _, data in cases)
    (out / "inputs.txt").write_text(inputs)
    (out / "labels.json").write_text(json.dumps([label for label, _ in cases], indent=2) + "\n")
    (out / "plan.json").write_text(json.dumps({
        "schema": 1,
        "seed": args.seed,
        "mutations": args.mutations,
        "max_input_bytes": MAX_INPUT,
        "directed_classes": [
            "zero-length and fixed-header truncation (0..235 bytes)",
            "BOOTREQUEST/op, hardware type and hlen boundaries",
            "PAD, END, duplicate, short and overlong DHCP TLVs",
            "cookie-required DHCP versus cookie-free BOOTP",
            "option 52 filename/sname/both overload regions",
            "message type, hostname, PRL, max-message, vendor, client-id, FQDN and address options",
            "seeded byte, truncation, insertion and extension mutations",
        ],
        "oracle": "rfc2131.c option_find1/option_find plus admission checks copied from dhcp_reply",
        "candidate": "components/dnsmasq/src/dhcp/packet.rs Packet::parse/find_option",
        "comparison": "five numbered admission statuses; accepted options compare length and bytes",
        "raw_input_sha256": hashlib.sha256(inputs.encode()).hexdigest(),
    }, indent=2) + "\n")
    c_rows = run(out / "oracle", inputs, out, "c")
    rust_rows = run(out / "driver", inputs, out, "rust")
    changed_control = compare_rows(["ok"], ["changed"]) == [0]
    try:
        compare_rows(["ok"], [])
    except ValueError:
        missing_control = True
    else:
        missing_control = False
    if not (changed_control and missing_control):
        raise RuntimeError("comparison negative controls are not calibrated")
    mismatches = [
        {"index": i, "label": cases[i][0], "packet": cases[i][1].hex(), "c": left, "rust": right}
        for i, (left, right) in enumerate(zip(c_rows, rust_rows)) if left != right
    ]
    (out / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    status_counts = Counter(row.split()[0] for row in c_rows)
    summary = {
        "schema": 1,
        "scope": "bounded DHCPv4 packet admission and option_find/overload semantics",
        "reference": "exact patched dnsmasq 2.93 source extraction",
        "source_sha256": identities,
        "seed": args.seed,
        "mutations": args.mutations,
        "cases": len(cases),
        "max_input_bytes": MAX_INPUT,
        "c_status_counts": dict(sorted(status_counts.items())),
        "mismatches": len(mismatches),
        "corpus_sha256": hashlib.sha256(inputs.encode()).hexdigest(),
        "normalization": "ParseError and C admission status use the same five numbered outcomes; accepted rows compare option lengths and bytes exactly",
        "negative_controls": {"changed_row_detected": changed_control, "missing_row_guard": missing_control},
        "outside_scope": ["DNS daemon/cache/transport", "DHCP state and lease lifecycle", "performance", "physical router", "exploit development"],
    }
    (out / "identities.json").write_text(json.dumps({"reference": identities, "rust_packet_sha256": identities[PACKET_HASH]}, indent=2) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(mismatches))


if __name__ == "__main__":
    raise SystemExit(main())
