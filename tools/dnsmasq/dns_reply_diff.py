#!/usr/bin/env python3
"""Exact-C oracle for OPT removal, reply envelope flags, and UDP truncation.

Extracts the actual C functions/blocks; the harness only supplies memory,
configuration scalars and stdout. No network or daemon is started. Raw inputs,
excluded malformed cases, generated C, executables and output remain private.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess

from bootp_vendor_diff import extract_function

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src"
HASHES = {
    "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
    "edns0.c": "420a55386ee3d41cef391b6443f735b18f7f205bf5c6d24cea6d28d5f2b55ed2",
    "rrfilter.c": "38f4c92a5529cf45c8011d35876214fc0a5a09b9d840c435f617f42a9e7d364d",
    "forward.c": "ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95",
    "dns-protocol.h": "4c6ed1c818c6a9b00bcdc1193bd364129780a3ef2b88c29475ee7bd6f6a826fe",
}

C_PREFIX = r'''
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#include "dns-protocol.h"
#define RRFILTER_EDNS0 0
#define RRFILTER_DNSSEC 1
#define RRFILTER_CONF 2
#define OPT_CLIENT_SUBNET 1
#define OPT_DNSSEC_PROXY 2
#define FREC_CHECKING_DISABLED 2
#define LOG_WARNING 0
#define _(x) (x)
struct { void *filter_rr; unsigned edns_pktsz; int proxy; } dns_state;
#define daemon (&dns_state)
#define option_bool(x) ((x) == OPT_DNSSEC_PROXY && daemon->proxy)
#define check_source(...) 1
#define my_syslog(...) ((void)0)
static int rr_on_list(void *list, int type) { (void)list; (void)type; return 0; }
static int expand_workspace(unsigned char ***space, int *size, int index) {
  if (*size > index) return 1;
  int new_size = index + 5;
  unsigned char **p = realloc(*space, (size_t)new_size * sizeof(*p));
  if (!p) return 0;
  memset(p + *size, 0, (size_t)(new_size - *size) * sizeof(*p));
  *size = new_size; *space = p; return 1;
}
short *rrfilter_desc(int);
'''

C_DRIVER = r'''
static void hex_print(const unsigned char *packet, size_t len) {
  for (size_t i = 0; i < len; i++) printf("%02x", packet[i]);
  puts("");
}
int main(void) {
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) > 0) {
    char op, hex[131074]; unsigned had_opt, cd, proxy, max, limit;
    if (sscanf(line, "%c %u %u %u %u %u %131073s", &op, &had_opt, &cd,
               &proxy, &max, &limit, hex) != 7) return 2;
    union { max_align_t align; unsigned char bytes[65536]; } storage;
    unsigned char *packet = storage.bytes;
    size_t len = strlen(hex) / 2;
    if (len < 12 || len > 65535) return 3;
    memset(packet, 0, sizeof(storage.bytes));
    for (size_t i = 0; i < len; i++) {
      unsigned value;
      if (sscanf(hex + 2*i, "%2x", &value) != 1) return 4;
      packet[i] = (unsigned char)value;
    }
    struct dns_header *h = (struct dns_header *)packet;
    if (op == 'S') {
      unsigned before = ntohs(h->arcount);
      size_t found = rrfilter(h, &len, RRFILTER_EDNS0);
      printf("S %zu %u %zu ", found / 2, before - ntohs(h->arcount), len);
    } else if (op == 'E') {
      unsigned rcode; int signed_packet;
      dns_state.edns_pktsz = max; dns_state.proxy = proxy;
      len = envelope(h, len, !had_opt, cd, &rcode, &signed_packet);
      printf("E %u %d %zu ", rcode, signed_packet, len);
    } else if (op == 'T') {
      if (len > limit) len = truncate_reply(h, len);
      printf("T %zu ", len);
    } else return 5;
    hex_print(packet, len);
  }
  free(line); return 0;
}
'''

RUST_DRIVER = r'''
#[path = "WIRE"] mod wire;
#[path = "REPLY"] mod reply;
use std::io::{self, BufRead};
fn emit(packet: &[u8]) {
  for byte in packet { print!("{byte:02x}"); }
  println!();
}
fn main() {
  for line in io::stdin().lock().lines() {
    let line = line.unwrap(); let words: Vec<_> = line.split_whitespace().collect();
    let number = |i: usize| words[i].parse::<u16>().unwrap();
    let encoded = words[6];
    let mut packet: Vec<u8> = (0..encoded.len()).step_by(2)
      .map(|i| u8::from_str_radix(&encoded[i..i+2], 16).unwrap()).collect();
    match words[0] {
      "S" => match reply::strip_opt(&mut packet) {
        Ok(r) => { print!("S {} {} {} ", r.matched, r.removed, packet.len()); emit(&packet); },
        Err(e) => println!("ERR {e:?}"),
      },
      "E" => match reply::prepare_reply(&packet, reply::ReplyPolicy {
        client_had_opt: number(1) != 0, checking_disabled: number(2) != 0,
        proxy_dnssec: number(3) != 0, edns_packet_max: number(4),
      }) {
        Ok(r) => { print!("E {} {} {} ", r.rcode, u8::from(r.signed), r.packet.len()); emit(&r.packet); },
        Err(e) => println!("ERR {e:?}"),
      },
      "T" => match reply::limit_udp_reply(&packet, number(5)) {
        Ok(r) => { print!("T {} ", r.len()); emit(&r); },
        Err(e) => println!("ERR {e:?}"),
      },
      _ => panic!("invalid operation"),
    }
  }
}
'''


def block(text: str, start: str, stop: str) -> str:
    begin = text.index(start)
    return text[begin:text.index(stop, begin)]


def build(output: Path, source: Path, cc: str, rustc: str) -> None:
    texts = {}
    for name, expected in HASHES.items():
        data = (source / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"source identity mismatch for {name}: {actual}")
        texts[name] = data.decode()
    c = C_PREFIX
    for name in ["skip_name", "skip_questions", "skip_section", "resize_packet"]:
        c += extract_function(texts["rfc1035.c"], name)
    c += extract_function(texts["edns0.c"], "find_pseudoheader")
    for name in ["check_name", "check_rrs", "rrfilter", "rrfilter_desc"]:
        c += extract_function(texts["rrfilter.c"], name)
    forward = texts["forward.c"]
    process = extract_function(forward, "process_reply")
    returning = extract_function(forward, "return_reply")
    c += r'''
static size_t envelope(struct dns_header *header, size_t n, int added_pheader,
                       int cd, unsigned *rcode_out, int *signed_out) {
  unsigned char *pheader, *sizep; size_t plen = 0;
  int is_sign = 0; unsigned int rcode = RCODE(header);
  struct { unsigned flags; } f = { cd ? FREC_CHECKING_DISABLED : 0 };
  typeof(f) *forward = &f;
'''
    c += block(returning, "/* restore CD bit", "/* Never cache answers")
    c += block(process, "if ((pheader = find_pseudoheader", "/* Complain loudly")
    c += block(process, "header->hb4 |= HB4_RA;", "if (OPCODE(header)")
    c += "*rcode_out = rcode; *signed_out = is_sign;\nreturn resize_packet(header, n, pheader, plen);\n}\n"
    c += "static size_t truncate_reply(struct dns_header *header, size_t nn) {\n"
    c += block(returning, "size_t hlen, new;", "daemon->log_display_id = forward->frec_src.log_id;")
    c += "return new;\n}\n"
    (output / "oracle.c").write_text(c + C_DRIVER)
    rust = RUST_DRIVER.replace("WIRE", str(ROOT / "components/dnsmasq/src/dns/wire.rs"))
    rust = rust.replace("REPLY", str(ROOT / "components/dnsmasq/src/dns/reply.rs"))
    (output / "driver.rs").write_text(rust)
    for command in [
        [cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined",
         "-fno-sanitize-recover=all", "-I", str(source), str(output / "oracle.c"), "-o", str(output / "oracle")],
        [rustc, "--edition=2021", "-A", "dead_code", str(output / "driver.rs"), "-o", str(output / "driver")],
    ]:
        run = subprocess.run(command, text=True, capture_output=True)
        with (output / "build.log").open("a") as log:
            log.write(run.stdout + run.stderr)
        run.check_returncode()


DESCRIPTORS = {**{t: (0,) for t in [2, 3, 4, 5, 7, 8, 9, 12, 30, 39]},
               **{t: (0, 0) for t in [6, 14, 17]},
               **{t: (2, 0) for t in [15, 18, 21, 36]}, 24: (18, 0), 26: (2, 0, 0), 33: (6, 0)}


def bounded_name(packet: bytes, at: int, end: int) -> int:
    while at < end:
        length = packet[at]; at += 1
        if length == 0:
            return at
        if length <= 63:
            at += length
        elif length == 65:
            if at >= end:
                break
            bits = packet[at]; at += 1 + (32 if bits == 0 else (bits + 7) // 8)
        elif length >= 192:
            if at < end:
                return at + 1
            break
        else:
            raise ValueError("reserved_label")
    raise ValueError("truncated_name")


def gate(packet: bytes) -> str | None:
    """Independent C safety-domain gate, never deriving expected output from Rust."""
    try:
        if len(packet) < 12 or len(packet) > 65535:
            return "header_or_packet_length"
        _, _, questions, answers, authorities, additionals = struct.unpack("!6H", packet[:12])
        at = 12
        for _ in range(questions):
            at = bounded_name(packet, at, len(packet)) + 4
            if at > len(packet):
                return "truncated_question"
        for _ in range(answers + authorities + additionals):
            at = bounded_name(packet, at, len(packet))
            if at + 10 > len(packet):
                return "truncated_rr_header"
            rrtype, rrclass, _, length = struct.unpack("!HHIH", packet[at:at + 10])
            at += 10; end = at + length
            if end > len(packet):
                return "truncated_rdata"
            if rrclass == 1:
                cursor = at
                for part in DESCRIPTORS.get(rrtype, ()):
                    cursor = bounded_name(packet, cursor, end) if part == 0 else cursor + part
                    if cursor > end:
                        return "descriptor_exceeds_rdlength"
            at = end
    except (ValueError, IndexError) as error:
        return str(error) or type(error).__name__
    return None


def question(name: bytes = b"\x05reply\x04test\0", rrtype: int = 1) -> bytes:
    return name + struct.pack("!HH", rrtype, 1)


def rr(rrtype: int, data: bytes = b"", owner: bytes = b"\0", rrclass: int = 1, ttl: int = 60) -> bytes:
    return owner + struct.pack("!HHIH", rrtype, rrclass, ttl, len(data)) + data


def packet(additional=(), answer=(), authority=(), questions=None, flags=0x8130, tail=b"") -> bytes:
    if questions is None:
        questions = [question()]
    return struct.pack("!6H", 7, flags, len(questions), len(answer), len(authority), len(additional)) + b"".join(questions) + b"".join(answer) + b"".join(authority) + b"".join(additional) + tail


def corpus(seed: int, count: int):
    rng = random.Random(seed)
    opt = rr(41, b"\0\x0c\0\0", rrclass=4096, ttl=0x01808000)
    a = rr(1, bytes([192, 0, 2, 1]), b"\xc0\x0c")
    tsig = rr(250, b"opaque-signed-payload", rrclass=255)
    cases = [("plain", packet(answer=[a])), ("opt", packet([opt], [a])),
             ("unknown", packet([opt, rr(65280, b"\xc0\x20\x80\xff")])),
             ("multiple_opt", packet([opt, a, opt])),
             ("signed_tsig", packet([opt, tsig])), ("tsig_not_last", packet([tsig, opt])),
             ("signed_tkey", packet([opt], questions=[question(rrtype=249)])),
             ("signed_tkey_no_opt", packet(questions=[question(rrtype=249)])),
             ("trailing", packet([opt], [a], tail=b"trailing\xc0\x0c")),
             ("nonadditional_opt", packet([opt], [opt], [opt])),
             ("two_questions", packet([opt], questions=[question(), question()])),
             ("no_question", packet([opt], questions=[])),
             ("bitstring", packet([opt, rr(5, b"\x41\x08\xff\0", owner=b"\x41\x08\xff\0")])),
             ("noanswer_signed_tsig", packet([tsig]))]
    opt_start = 12 + len(question())
    pointer = lambda offset: struct.pack("!H", 0xc000 | offset)
    for offset in [opt_start, opt_start + 1, opt_start + len(opt) - 1]:
        cases.append(("pointer_into_removed_owner", packet([opt, rr(1, bytes(4), pointer(offset))])))
        cases.append(("pointer_into_removed_rdata", packet([opt, rr(5, pointer(offset))])))
        cases.append(("opaque_non_in_rdata", packet([opt, rr(5, pointer(offset), rrclass=3)])))
    target = opt_start + len(opt)
    named = rr(1, bytes(4), b"\x04kept\0")
    cases.append(("relocate_after_removed", packet([opt, named, rr(5, pointer(target), pointer(target))])))
    cases.append(("relocate_two_removed", packet([opt, named, opt, rr(5, pointer(target), pointer(target))])))
    # Encoded forward pointers in the question must also be relocated.
    q = question(pointer(18 + len(opt)))
    cases.append(("question_forward_pointer", packet([opt, named], questions=[q])))
    q = question(pointer(18))
    cases.append(("question_points_into_removed", packet([opt], questions=[q])))
    for _ in range(count):
        additions, answers = [], []
        questions = [question(rrtype=rng.choice([1, 28, 249]))]
        if rng.randrange(10) == 0:
            questions *= rng.choice([0, 2])
        for _ in range(rng.randrange(8)):
            kind = rng.choice([1, 5, 15, 41, 41, 41, 250, 65281])
            owner = rng.choice([b"\0", b"\xc0\x0c", b"\x03aux\0"])
            data = rng.randbytes(rng.randrange(30))
            cls = rng.choice([1, 3, 255])
            if kind == 41:
                owner, cls = b"\0", rng.choice([512, 1232, 4096])
            elif kind in DESCRIPTORS and cls == 1:
                data = b"".join(bytes(part) if part else rng.choice([b"\0", b"\xc0\x0c"]) for part in DESCRIPTORS[kind])
            additions.append(rr(kind, data, owner, cls, rng.getrandbits(32)))
        if rng.randrange(2):
            answers.append(a)
        cases.append(("random_structured", packet(additions, answers, questions=questions,
                      flags=0x8000 | rng.randrange(1024), tail=rng.randbytes(rng.randrange(6)))))
    # Keep malformed inputs and exclusion reasons; never count them as passes.
    valid_seeds = [data for _, data in cases[:28]]
    for index in range(count):
        data = bytearray(rng.choice(valid_seeds))
        if index % 2:
            data = data[:rng.randrange(len(data) + 1)]
        else:
            for _ in range(rng.randrange(1, 4)):
                data[rng.randrange(len(data))] = rng.randrange(256)
        cases.append(("mutation", bytes(data)))
    return cases


def mismatch_rows(expected, observed):
    if len(expected) != len(observed):
        raise RuntimeError(f"oracle output count differs: {len(expected)} != {len(observed)}")
    return [{"index": i, "c": left, "rust": right} for i, (left, right) in enumerate(zip(expected, observed)) if left != right]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--output", type=Path, default=ROOT / "private/dnsmasq-rewrite/dns-reply/run-01")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--rustc", default=shutil.which("rustc") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc"))
    parser.add_argument("--seed", type=int, default=293003)
    parser.add_argument("--count", type=int, default=1200)
    args = parser.parse_args(); output = args.output.resolve()
    if not output.is_relative_to(ROOT / "private"):
        parser.error("output must stay in ignored private/")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "result.json").exists():
        parser.error("output already has results; use a fresh run directory")
    build(output, args.source, args.cc, args.rustc)
    generated = corpus(args.seed, args.count)
    cases, excluded = [], []
    for label, data in generated:
        reason = gate(data)
        if reason:
            excluded.append({"label": label, "reason": reason, "packet": data.hex()})
        else:
            cases.append((label, data))
    lines, labels = [], []
    for label, data in cases:
        for op, had_opt, cd, proxy, limit in [
            ("S", 0, 0, 0, 0),
            *[("E", h, c, p, 0) for h in [0, 1] for c in [0, 1] for p in [0, 1]],
            *[("T", 0, 0, 0, value) for value in [0, len(data) - 1, len(data), 65535]],
        ]:
            lines.append(f"{op} {had_opt} {cd} {proxy} 1232 {limit} {data.hex()}")
            labels.append(f"{label}:{op}")
    input_text = "\n".join(lines) + "\n"
    (output / "input.txt").write_text(input_text)
    (output / "labels.json").write_text(json.dumps(labels))
    (output / "excluded.json").write_text(json.dumps(excluded, indent=2) + "\n")
    results = {}
    for name in ["oracle", "driver"]:
        run = subprocess.run([str(output / name)], input=input_text, text=True, capture_output=True)
        (output / f"{name}.stdout").write_text(run.stdout)
        (output / f"{name}.stderr").write_text(run.stderr)
        run.check_returncode()
        results[name] = run.stdout.splitlines()
        if len(results[name]) != len(lines):
            raise RuntimeError(f"{name} emitted {len(results[name])} results for {len(lines)} commands")
    # Calibration must demonstrate failure detection, not just an equal pair.
    assert mismatch_rows(["a", "b"], ["a", "x"]) == [{"index": 1, "c": "b", "rust": "x"}]
    try:
        mismatch_rows(["a"], [])
    except RuntimeError:
        pass
    else:
        raise RuntimeError("count calibration failed")
    mismatches = mismatch_rows(results["oracle"], results["driver"])
    for row in mismatches:
        row["label"] = labels[row["index"]]
    (output / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    summary = {
        "generated_packets": len(generated), "accepted_packets": len(cases),
        "excluded_packets": len(excluded), "excluded_reasons": dict(Counter(row["reason"] for row in excluded)),
        "commands": len(lines), "successful": len(lines) - len(mismatches), "mismatches": len(mismatches),
        "seed": args.seed, "source_sha256": HASHES, "sanitizers": "address,undefined",
        "normalization": "C rrfilter returns two range boundaries per matched RR; divided by two only",
        "scope": "bounded OPT strip, extracted process_reply envelope and return_reply CD/truncation; no cache/address/rebind/EDE/socket integration",
    }
    (output / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(mismatches))


if __name__ == "__main__":
    raise SystemExit(main())
