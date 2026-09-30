#!/usr/bin/env python3
"""Compare DNS primitives against functions extracted from exact dnsmasq C.

The generated C/Rust drivers, executables, input corpus, outputs and summary
stay under ignored private/. This is a correctness tool, not a benchmark.
No daemon, socket or network namespace is created.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "private/network-research-20260929/dns/dnsmasq-2.93-openwrt/src"
EXPECTED_SOURCE = {
    "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
    "edns0.c": "420a55386ee3d41cef391b6443f735b18f7f205bf5c6d24cea6d28d5f2b55ed2",
    "dns-protocol.h": "4c6ed1c818c6a9b00bcdc1193bd364129780a3ef2b88c29475ee7bd6f6a826fe",
    "rrfilter.c": "38f4c92a5529cf45c8011d35876214fc0a5a09b9d840c435f617f42a9e7d364d",
}

C_DRIVER = r'''
int main(void) {
  char *line = NULL;
  size_t cap = 0;
  while (getline(&line, &cap, stdin) > 0) {
    char op, hex[131074];
    unsigned start, extra;
    union { max_align_t align; unsigned char bytes[65536]; } storage;
    unsigned char *packet = storage.bytes;
    memset(packet, 0, sizeof(storage.bytes));
    if (sscanf(line, "%c %u %u %131073s", &op, &start, &extra, hex) != 4) return 3;
    size_t n = strcmp(hex, "-") == 0 ? 0 : strlen(hex)/2;
    if (n > 65535 || start > 65535) return 4;
    for (size_t i = 0; i < n; i++) {
      unsigned byte;
      if (sscanf(hex + 2*i, "%2x", &byte) != 1) return 5;
      packet[i] = (unsigned char)byte;
    }
    struct dns_header *h = (struct dns_header *)packet;
    unsigned char *p = packet + start;
    if (op == 'N') {
      char name[MAXDNAMESTR+1];
      int rc = extract_name(h, n, &p, name, EXTR_NAME_EXTRACT, extra);
      if (!rc) { puts("0"); continue; }
      printf("1 %td ", p - packet);
      if (!name[0]) printf("-");
      for (size_t i = 0; name[i]; i++) printf("%02x", (unsigned char)name[i]);
      puts("");
    } else if (op == 'S') {
      p = skip_name(p, h, n, extra);
      if (p) printf("1 %td\n", p - packet); else puts("0");
    } else if (n < sizeof(*h)) {
      puts("0");
    } else if (op == 'Q') {
      p = skip_questions(h, n);
      if (p) printf("1 %td\n", p - packet); else puts("0");
    } else if (op == 'P') {
      p = skip_questions(h, n);
      if (p) p = skip_section(p, ntohs(h->ancount) + ntohs(h->nscount) + ntohs(h->arcount), h, n);
      if (p) printf("1 %td\n", p - packet); else puts("0");
    } else if (op == 'R') {
      unsigned char *data = NULL;
      size_t size = 0;
      int ok = canonical_rr(h, n, start, &data, &size);
      if (!ok) puts("0");
      else {
        printf("1 ");
        if (!size) printf("-");
        for (size_t i = 0; i < size; i++) printf("%02x", data[i]);
        puts("");
        free(data);
      }
    } else if (op == 'E' || op == 'T') {
      int is_sign = 0, is_last = 0;
      size_t len = 0;
      unsigned char *udp = NULL;
      p = find_pseudoheader(h, n, &len, &udp, (start || op == 'T') ? &is_sign : NULL, &is_last);
      if (op == 'T') printf("1 %d\n", is_sign);
      else if (p) printf("1 %td %zu %td %d %d\n", p - packet, len, udp - packet, is_sign, is_last);
      else puts("0");
    } else return 6;
  }
  free(line);
  return 0;
}
'''

RUST_DRIVER = r'''
#[path = "WIRE_PATH"]
mod wire;
use std::io::{self, BufRead};
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_owned(); }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut words = line.split_whitespace();
        let op = words.next().unwrap();
        let start: usize = words.next().unwrap().parse().unwrap();
        let extra: usize = words.next().unwrap().parse().unwrap();
        let encoded = words.next().unwrap();
        let packet: Vec<u8> = if encoded == "-" { vec![] } else {
            (0..encoded.len()).step_by(2).map(|i| u8::from_str_radix(&encoded[i..i+2], 16).unwrap()).collect()
        };
        match op {
            "N" => match wire::decode_name(&packet, start, extra) {
                Ok((name, next)) => println!("1 {next} {}", hex(&name.dnsmasq_bytes())),
                Err(_) => println!("0"),
            },
            "S" => match wire::skip_name(&packet, start, extra) {
                Ok(next) => println!("1 {next}"), Err(_) => println!("0"),
            },
            "Q" => match wire::skip_questions(&packet) {
                Ok(next) => println!("1 {next}"), Err(_) => println!("0"),
            },
            "P" => match wire::Message::parse(&packet) {
                Ok(message) => println!("1 {}", message.end), Err(_) => println!("0"),
            },
            "E" => match wire::find_pseudoheader(&packet, start != 0) {
                Ok(scan) if scan.opt.is_some() => {
                    let edns = scan.opt.unwrap();
                    println!("1 {} {} {} {} {}", edns.record.start, edns.record.end - edns.record.start,
                             edns.record.fixed + 2, u8::from(scan.signed), u8::from(edns.is_last));
                },
                _ => println!("0"),
            },
            "T" => match wire::find_pseudoheader(&packet, true) {
                Ok(scan) => println!("1 {}", u8::from(scan.signed)),
                Err(_) => println!("0"),
            },
            "R" => match wire::RecordRef::parse(&packet, start).and_then(|rr| rr.canonical_rdata()) {
                Ok(data) => println!("1 {}", hex(&data)),
                Err(_) => println!("0"),
            },
            _ => panic!("unknown operation"),
        }
    }
}
'''


def extract(text, start, stop):
    return text[text.index(start):text.index(stop, text.index(start))]


def build(source, output, rustc, cc, sanitize):
    rfc = (source / "rfc1035.c").read_text()
    edns = (source / "edns0.c").read_text()
    rrfilter = (source / "rrfilter.c").read_text()
    c = """#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#include "dns-protocol.h"
#define EXTR_NAME_EXTRACT 1
#define EXTR_NAME_COMPARE 2
#define EXTR_NAME_NOCASE 3
#define EXTR_NAME_FLIP 4
"""
    c += extract(rfc, "int extract_name(", "/* Max size of input string")
    c += extract(rfc, "unsigned char *skip_name(", "size_t resize_packet(")
    c += extract(edns, "unsigned char *find_pseudoheader(", "/* replace == 0")
    c += extract(rrfilter, "short *rrfilter_desc(", "/* Note: no compression")
    # Preserve the exact cache-copy loop; only its storage dependency is stubbed.
    c += r'''
struct blockdata { unsigned char bytes[66048]; };
static struct blockdata *blockdata_alloc(void *data, size_t n) {
  (void)data; (void)n; return malloc(sizeof(struct blockdata));
}
static void blockdata_free(struct blockdata *data) { free(data); }
static int blockdata_expand(struct blockdata *data, size_t offset, char *from, size_t n) {
  if (offset > sizeof(data->bytes) || n > sizeof(data->bytes) - offset) return 0;
  memcpy(data->bytes + offset, from, n); return 1;
}
static int copy_rdata(struct dns_header *header, size_t qlen, unsigned char *p1,
                     unsigned char *endrr, short *rrdesc, unsigned char **output, size_t *size) {
  struct { struct { unsigned short datalen; struct blockdata *rrdata; } rrblock; } addr = {0};
  int desc;
  char name[MAXDNAMESTR+1];
'''
    start = rfc.index("if (!(addr.rrblock.rrdata = blockdata_alloc(NULL, 0)))", rfc.index("If the data has no names"))
    stop = rfc.index("} while (desc != -1);", start) + len("} while (desc != -1);")
    c += rfc[start:stop]
    c += r'''
  *size = addr.rrblock.datalen;
  *output = malloc(*size ? *size : 1);
  if (!*output) { free(addr.rrblock.rrdata); return 0; }
  memcpy(*output, addr.rrblock.rrdata->bytes, *size);
  free(addr.rrblock.rrdata);
  return 1;
}
static int canonical_rr(struct dns_header *header, size_t qlen, size_t start,
                        unsigned char **output, size_t *size) {
  unsigned char *p = (unsigned char *)header + start;
  unsigned short type, rdlen;
  if (!(p = skip_name(p, header, qlen, 10))) return 0;
  GETSHORT(type, p);
  p += 6;
  GETSHORT(rdlen, p);
  if (!CHECK_LEN(header, p, qlen, rdlen)) return 0;
  return copy_rdata(header, qlen, p, p + rdlen, rrfilter_desc(type), output, size) == 1;
}
'''
    (output / "oracle.c").write_text(c + C_DRIVER)
    rust_source = RUST_DRIVER.replace("WIRE_PATH", str(ROOT / "components/dnsmasq/src/dns/wire.rs"))
    (output / "driver.rs").write_text(rust_source)
    flags = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-Wall", "-Wextra"]
    if sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    subprocess.run([cc, *flags, "-I", str(source), str(output / "oracle.c"), "-o", str(output / "oracle")], check=True)
    subprocess.run([rustc, "--edition=2021", "-A", "dead_code", str(output / "driver.rs"), "-o", str(output / "driver")], check=True)


def corpus(seed, mutations):
    rng = random.Random(seed)
    cases = []

    def add(op, packet, start=0, extra=0):
        cases.append((op, start, extra, bytes(packet)))

    names = [b"", b"\0", b"\xc0\0", b"\xc0\x02\0", b"\xc0\xff", b"\x41\x08\xff\0", b"\x42\0", b"\x80\0",
             b"\x05\0\x01.\xffA\0", b"\x03www\x07example\0", b"\x41\0" + bytes(32) + b"\0"]
    for lengths in ([63, 63, 63, 60], [63, 63, 63, 61], [63, 63, 63, 62]):
        names.append(b"".join(bytes([length]) + bytes(length) for length in lengths) + b"\0")
    chain = b"".join(struct.pack("!H", 0xc000 | ((i + 1) * 2)) for i in range(256)) + b"\0"
    names.extend([chain, chain[2:]])
    for name in names:
        for extra in (0, 1, 4, 10):
            for start in (0, 1, 2, len(name), len(name) + 1):
                for op in ("N", "S"):
                    add(op, name, start, extra)
    # Explicit 255-hop success with pointers still referring to the original packet.
    add("N", chain, 2)

    header = lambda q, a, ns, ar, flags=0x0100: struct.pack("!6H", 0x1234, flags, q, a, ns, ar)
    q = b"\x03www\x07example\0\0\x01\0\x01"
    answer = b"\xc0\x0c\0\x01\0\x01\0\0\0\x3c\0\x04\xc0\0\x02\x07"
    opt = b"\0\0\x29\x04\xd0\0\0\x80\0\0\x09\0\x0c\0\0\0\x0f\0\x01\x09"
    tsig = b"\0\0\xfa\0\xff\0\0\0\0\0\0"
    packets = [header(1, 0, 0, 0) + q, header(1, 1, 0, 0, 0x8180) + q + answer,
               header(1, 0, 0, 1) + q + opt, header(1, 0, 0, 2) + q + opt + opt,
               header(1, 0, 0, 2) + q + opt + tsig, header(1, 0, 0, 2) + q + tsig + opt,
               header(1, 0, 0, 1) + b"\0\0\xf9\0\x01" + opt,
               header(1, 0, 0, 1, 0x0900) + q + opt,
               header(65535, 65535, 65535, 65535), header(0, 0, 0, 0)]
    # T preserves signed status even when no OPT exists. These are structurally
    # complete QUERY packets, so C's NULL never conceals a malformed section.
    for typ in [1, 249, 250, 65535]:
        for cls in [1, 3, 255]:
            question = b"\0" + struct.pack("!HH", typ, cls)
            for records in [[], [tsig], [tsig, answer], [answer, tsig]]:
                add("T", header(1, 0, 0, len(records)) + question + b"".join(records))

    # Per-type RDATA descriptors, names both compressed and uncompressed,
    # unknown type payloads, zero data and every fixed-seed truncation point.
    descriptors = {2: [0], 3: [0], 4: [0], 5: [0], 6: [0, 0], 7: [0], 8: [0], 9: [0], 12: [0],
                   14: [0, 0], 15: [2, 0], 17: [0, 0], 18: [2, 0], 21: [2, 0], 24: [18, 0],
                   26: [2, 0, 0], 30: [0], 33: [6, 0], 36: [2, 0], 39: [0], 1: [], 16: [],
                   28: [], 64: [], 65: [], 65535: []}
    rr_packets = []
    for typ, descriptor in descriptors.items():
        for wire_name in [b"\xc0\x0c", b"\x03A\0.\0", b"\0", b"\xc0\xff", b"\xc0\x16"]:
            data = b"".join(wire_name if part == 0 else bytes(range(part)) for part in descriptor)
            data += b"\0\xff\xc0\x0c"
            record = b"\x01A\0" + struct.pack("!HHIH", typ, 1, 60, len(data)) + data
            packet = header(0, 1, 0, 0) + record
            rr_packets.append(packet)
            for length in range(12, len(packet) + 1):
                add("R", packet[:length], 12)
            # RDLEN can lie while bytes after it are present.
            for rdlen in range(len(data)):
                add("R", packet[:23] + struct.pack("!H", rdlen) + packet[25:], 12)
    for packet in packets:
        for length in range(len(packet) + 1):
            for op in ("Q", "P", "E"):
                add(op, packet[:length])
            add("E", packet[:length], 1)
        for op in ("N", "S"):
            add(op, packet, 12, 4)
    for _ in range(mutations):
        packet = bytearray(rng.choice(packets + names))
        for _ in range(rng.randrange(1, 6)):
            action = rng.randrange(4)
            if action == 0 and packet:
                packet[rng.randrange(len(packet))] = rng.randrange(256)
            elif action == 1 and packet:
                del packet[rng.randrange(len(packet)):]
            elif action == 2:
                packet.extend(rng.randbytes(rng.randrange(16)))
            else:
                packet[rng.randrange(len(packet) + 1):rng.randrange(len(packet) + 1)] = rng.randbytes(rng.randrange(8))
        for op in ("N", "S"):
            add(op, packet, rng.randrange(len(packet) + 2), rng.choice([0, 1, 4, 10]))
        for op in ("Q", "P", "E"):
            add(op, packet, 0)
        add("E", packet, 1)
        packet = bytearray(rng.choice(rr_packets))
        for _ in range(rng.randrange(1, 4)):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        add("R", packet, 12)
    return cases


def overflow_regression(output):
    """Pin the known C u16 truncation separately from equivalence coverage."""
    name = b"".join(bytes([n]) + b"A" * n for n in [63, 63, 63, 61]) + b"\0"
    cases, expected_c, expected_rust = [], [], []
    for expanded in [65534, 65535, 65536, 65765]:
        size = expanded - 253
        data = b"\0\x0a\xc0\x1b" + name + bytes(size - 4 - len(name))
        packet = struct.pack("!6H", 0x1234, 0x8180, 0, 1, 0, 0)
        packet += b"\0" + struct.pack("!HHIH", 15, 1, 60, len(data)) + data
        canonical = data[:2] + name.lower() + data[4:]
        assert len(canonical) == expanded and len(packet) <= 65535
        cases.append(f"R 12 0 {packet.hex()}\n")
        expected_c.append("1 " + (canonical[:expanded % 65536].hex() or "-"))
        expected_rust.append("0" if expanded > 65535 else "1 " + canonical.hex())
    inputs = "".join(cases)
    (output / "overflow-inputs.txt").write_text(inputs)
    for binary, expected in [("oracle", expected_c), ("driver", expected_rust)]:
        run = subprocess.run([str(output / binary)], input=inputs, capture_output=True, text=True)
        (output / f"overflow-{binary}.stdout").write_text(run.stdout)
        (output / f"overflow-{binary}.stderr").write_text(run.stderr)
        if run.returncode or run.stdout.splitlines() != expected:
            raise RuntimeError(f"{binary}: expanded RDATA boundary regression failed")
    result = {"cases": 4, "boundary_agreements": 2, "intentional_safe_rejections": 2,
              "c_expanded_lengths": [65534, 65535, 0, 229],
              "rust_result": [65534, 65535, "RecordTooLong", "RecordTooLong"],
              "scope": "extracted C RDATA copy loop only; no daemon-level reproduction",
              "corpus_sha256": hashlib.sha256(inputs.encode()).hexdigest()}
    (output / "overflow-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=ROOT / "private/dnsmasq-rs/wire/differential")
    parser.add_argument("--seed", type=int, default=293)
    parser.add_argument("--mutations", type=int, default=10000)
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", shutil.which("rustc") or "rustc"))
    parser.add_argument("--cc", default=os.environ.get("CC", shutil.which("cc") or "cc"))
    parser.add_argument("--no-sanitize", action="store_true")
    parser.add_argument("--overflow-only", action="store_true", help="only pin the known C expanded-RDATA u16 truncation")
    args = parser.parse_args()
    output = args.output.resolve()
    private = (ROOT / "private").resolve()
    if not output.is_relative_to(private):
        parser.error("output must be under ignored private/")
    output.mkdir(parents=True, exist_ok=True)
    source_hashes = {name: hashlib.sha256((args.source / name).read_bytes()).hexdigest() for name in EXPECTED_SOURCE}
    if source_hashes != EXPECTED_SOURCE:
        raise RuntimeError("reference source identity differs from the verified OpenWrt patched dnsmasq 2.93 tree")
    build(args.source.resolve(), output, args.rustc, args.cc, not args.no_sanitize)
    if args.overflow_only:
        print(json.dumps(overflow_regression(output), indent=2))
        return 0
    cases = corpus(args.seed, args.mutations)
    inputs = "".join(f"{op} {start} {extra} {packet.hex() or '-'}\n" for op, start, extra, packet in cases)
    (output / "inputs.txt").write_text(inputs)
    results = {}
    for binary in ("oracle", "driver"):
        run = subprocess.run([str(output / binary)], input=inputs, capture_output=True, text=True)
        (output / f"{binary}.stdout").write_text(run.stdout)
        (output / f"{binary}.stderr").write_text(run.stderr)
        if run.returncode != 0:
            raise RuntimeError(f"{binary} failed ({run.returncode}); see {output}/{binary}.stderr")
        results[binary] = run.stdout.splitlines()
        if len(results[binary]) != len(cases):
            raise RuntimeError(f"{binary} returned {len(results[binary])} results for {len(cases)} cases")
    # Calibrate both success and failure channels against independently fixed inputs.
    for op in ("N", "S", "Q", "P", "E", "R"):
        observed = {row.split()[0] for case, row in zip(cases, results["oracle"]) if case[0] == op}
        if observed != {"0", "1"}:
            raise RuntimeError(f"uncalibrated {op} success/failure coverage: {observed}")
    mismatches = []
    for index, (reference, actual) in enumerate(zip(results["oracle"], results["driver"])):
        if reference != actual:
            op, start, extra, packet = cases[index]
            mismatches.append({"index": index, "op": op, "start": start, "extra": extra,
                               "packet": packet.hex(), "c": reference, "rust": actual})
    (output / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    counts = {}
    for case, result in zip(cases, results["oracle"]):
        key = case[0] + ("_success" if result.startswith("1 ") else "_failure")
        counts[key] = counts.get(key, 0) + 1
    summary = {
        "reference": "dnsmasq 2.93 OpenWrt patched source functions, compiled without algorithm edits",
        "scope": "extract_name, skip_name, skip_questions, skip_section, find_pseudoheader, rrfilter_desc/to_wire and actual cache RDATA-copy loop",
        "source_sha256": source_hashes,
        "seed": args.seed, "mutations": args.mutations, "cases": len(cases), "counts": counts,
        "mismatches": len(mismatches), "sanitizers": not args.no_sanitize,
        "corpus_sha256": hashlib.sha256(inputs.encode()).hexdigest(),
        "normalization": "C NULL / Rust error or absent OPT normalize to 0 for E; T compares signed status with/without OPT on complete QUERY packets; successful decoded byte strings, offsets, lengths, signed status with OPT and last-OPT flags compare exactly",
        "not_covered": "daemon forwarding, cache policy, DHCP, EDNS mutation, DNS transport, allocator failure and malformed-packet partial signed state",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return bool(mismatches)


if __name__ == "__main__":
    sys.exit(main())
