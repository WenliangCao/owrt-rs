#!/usr/bin/env python3
"""Differential check for the Rust BOOTP vendor-field serializer.

The C side is built from the exact patched dnsmasq ``rfc2131.c`` source.  It
extracts ``dhcp_skip_opts``, ``find_overload`` and ``free_space`` and runs the
same append/final-END sequence used by ``dhcp_packet_size``.  Input options
are generated independently and are kept in ignored ``private/`` output.

This is a wire-primitive check, not a DHCP socket test.  The C helper also
reports filename/server-name overload so a 64-byte vend-field assumption is
visible rather than silently treated as equivalent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/rfc2131.c"
EXPECTED_SHA256 = "14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c"


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
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef uint32_t u32;
#define OPTION_OVERLOAD 52
#define OPTION_END 255
#define OPT_LOG_OPTS 1
#define MS_DHCP 0
#define LOG_WARNING 0
#define _(text) (text)
#define option_bool(flag) 0
struct dhcp_packet {
  unsigned char op, htype, hlen, hops;
  u32 xid;
  unsigned short secs, flags;
  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
  unsigned char chaddr[16];
  unsigned char sname[64];
  unsigned char file[128];
  // The BOOTP vend end pointer is options+64, but the real packet has a
  // larger zeroed backing buffer.  find_overload() scans until zero after
  // seeing END (255), so keep that trailing sentinel outside the vend field.
  unsigned char options[256];
};
static unsigned int option_uint(const unsigned char *opt, int offset, int len) {
  unsigned int result = 0;
  for (int i = 0; i < len; i++) result = (result << 8) | opt[offset + i + 2];
  return result;
}
static void my_syslog(int priority, const char *format, ...) {
  (void)priority; (void)format;
}
'''

C_MAIN = r'''
static size_t decode(const char *text, unsigned char *out) {
  if (!strcmp(text, "-")) return 0;
  size_t n = strlen(text) / 2;
  for (size_t i = 0; i < n; i++) {
    unsigned value;
    if (sscanf(text + i * 2, "%2x", &value) != 1) return (size_t)-1;
    out[i] = (unsigned char)value;
  }
  return n;
}
static void print_hex(const unsigned char *bytes, size_t length) {
  for (size_t i = 0; i < length; i++) printf("%02x", bytes[i]);
}
int main(void) {
  char line[65536];
  while (fgets(line, sizeof(line), stdin)) {
    char *word = strtok(line, " \t\r\n");
    if (!word) continue;
    unsigned count = (unsigned)strtoul(word, NULL, 10);
    if (count > 128) return 2;
    struct dhcp_packet packet;
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.options, (unsigned char[]){99, 130, 83, 99}, 4);
    unsigned accepted = 0;
    for (unsigned i = 0; i < count; i++) {
      word = strtok(NULL, " \t\r\n");
      if (!word) return 3;
      unsigned code = (unsigned)strtoul(word, NULL, 10);
      word = strtok(NULL, " \t\r\n");
      if (!word || code > 255) return 4;
      unsigned char value[256];
      size_t length = decode(word, value);
      if (length > 255) return 5;
      unsigned char *destination = free_space(&packet, packet.options + 64, (int)code, (int)length);
      if (destination) {
        memcpy(destination, value, length);
        accepted++;
      }
    }
    unsigned char *end = dhcp_skip_opts(packet.options + 4);
    *end = OPTION_END;
    unsigned char *overload = find_overload(&packet);
    if (overload && (option_uint(overload, 0, 1) & 1))
      *dhcp_skip_opts(packet.file) = OPTION_END;
    if (overload && (option_uint(overload, 0, 1) & 2))
      *dhcp_skip_opts(packet.sname) = OPTION_END;
    printf("%u %u|", accepted, count - accepted);
    print_hex(packet.options, 64);
    putchar('|'); print_hex(packet.file, sizeof(packet.file));
    putchar('|'); print_hex(packet.sname, sizeof(packet.sname));
    putchar('\n');
  }
  return 0;
}
'''

RUST_MAIN = r'''
#[path = "PACKET_PATH"] mod packet;
use std::io::{self, BufRead};
fn decode(text: &str) -> Vec<u8> {
    if text == "-" { return Vec::new(); }
    text.as_bytes().chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}
fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let words: Vec<_> = line.split_whitespace().collect();
        let count: usize = words[0].parse().unwrap();
        let mut values = Vec::with_capacity(count);
        for pair in words[1..].chunks_exact(2) {
            values.push((pair[0].parse::<u8>().unwrap(), decode(pair[1])));
        }
        let options: Vec<_> = values
            .iter()
            .map(|(code, value)| packet::VendorOption { code: *code, value })
            .collect();
        let mut output = [0u8; packet::BOOTP_VENDOR_LEN];
        match packet::encode_bootp_vendor(&options, &mut output) {
            Ok(result) => {
                print!("{} {}|", count - result.omitted, result.omitted);
                for byte in output { print!("{byte:02x}"); }
                println!("|{}|{}", "00".repeat(128), "00".repeat(64));
            }
            Err(error) => println!("ERR:{error:?}||||"),
        }
    }
}
'''


def generate_cases(random_cases: int) -> list[str]:
    cases: list[str] = []
    fixed = [
        [],
        [(1, b"")],
        [(1, bytes(56))],
        [(1, bytes(57))],
        [(1, bytes(60)), (2, b"ok")],
        [(0, b"")],
        [(255, b"")],
        [(1, b"ok"), (255, b""), (2, b"ignored")],
    ]
    for options in fixed:
        fields = [str(len(options))]
        for code, value in options:
            fields.extend((str(code), value.hex() or "-"))
        cases.append(" ".join(fields))
    rng = random.Random(0x293001)
    for _ in range(random_cases):
        count = rng.randrange(0, 10)
        fields = [str(count)]
        for _ in range(count):
            # free_space() expects generated options, so PAD (code 0) and
            # END (255) are only exercised in the explicit fixed cases.  A
            # non-empty code-0 value would make the C scanner treat its first
            # byte as a terminator and then read an undefined suffix.
            code = rng.choice([1, 2, 3, 52, 53, 54])
            length = rng.randrange(0, 65)
            fields.extend((str(code), bytes(rng.randrange(256) for _ in range(length)).hex() or "-"))
        cases.append(" ".join(fields))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=REPO / "private/dnsmasq-rewrite/bootp-vendor-diff")
    parser.add_argument("--random-cases", type=int, default=2000)
    args = parser.parse_args()
    source = args.source.resolve()
    out = args.out.resolve()
    private = REPO / "private"
    if not out.is_relative_to(private):
        parser.error("--out must stay under ignored private/")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if source_hash != EXPECTED_SHA256:
        raise SystemExit(f"C source identity mismatch: {source_hash}")
    out.mkdir(parents=True, exist_ok=True)
    source_text = source.read_text()
    c_source = C_PREFIX + "\n".join(
        extract_function(source_text, name) for name in ("dhcp_skip_opts", "find_overload", "free_space")
    ) + C_MAIN
    (out / "oracle.c").write_text(c_source)
    rust_source = RUST_MAIN.replace("PACKET_PATH", str(REPO / "components/dnsmasq/src/dhcp/packet.rs"))
    (out / "driver.rs").write_text(rust_source)
    cc = shutil.which("cc")
    if not cc:
        raise SystemExit("cc is required")
    rustc = shutil.which("rustc") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc")
    subprocess.run([cc, "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    subprocess.run([rustc, "--edition=2021", "-O", "-A", "dead_code", str(out / "driver.rs"), "-o", str(out / "driver")], check=True)
    cases = generate_cases(args.random_cases)
    payload = "\n".join(cases) + "\n"
    c_run = subprocess.run([str(out / "oracle")], input=payload, text=True, capture_output=True, check=True)
    rust_run = subprocess.run([str(out / "driver")], input=payload, text=True, capture_output=True, check=True)
    c_lines = c_run.stdout.splitlines()
    rust_lines = rust_run.stdout.splitlines()
    if len(c_lines) != len(cases) or len(rust_lines) != len(cases):
        raise SystemExit(f"line count mismatch C={len(c_lines)} Rust={len(rust_lines)} cases={len(cases)}")
    mismatches = []
    defined_cases = 0
    defined_matches = 0
    defined_mismatches = []
    special_cases = 0
    same_vend = 0
    overload_cases = 0
    for index, (case, c_line, rust_line) in enumerate(zip(cases, c_lines, rust_lines)):
        c_prefix, c_vend, c_file, c_sname = c_line.split("|")
        r_prefix, r_vend, _, _ = rust_line.split("|")
        c_accepted, c_omitted = map(int, c_prefix.split())
        fields = case.split()
        codes = [int(fields[offset]) for offset in range(1, len(fields), 2)]
        has_special_code = any(code in (0, 255) for code in codes)
        has_overload = any(byte != "0" for byte in (c_file + c_sname))
        if has_overload:
            overload_cases += 1
        if has_special_code:
            special_cases += 1
        if c_vend == r_vend:
            same_vend += 1
        else:
            mismatch = {"index": index, "case": case, "c": c_line, "rust": rust_line}
            mismatches.append(mismatch)
        # free_space() is only defined for generated options (codes 1..254)
        # and may legally move an option to file/sname when vend is full. The
        # Rust primitive deliberately has no filename/sname ownership, so only
        # defined, non-overloaded cases are a strict wire equivalence gate.
        if not has_special_code and not has_overload:
            defined_cases += 1
            if c_vend == r_vend:
                defined_matches += 1
            else:
                defined_mismatches.append(mismatch)
    result = {
        "source_sha256": source_hash,
        "cases": len(cases),
        "same_vendor": same_vend,
        "vendor_mismatches": len(mismatches),
        "defined_no_overload_cases": defined_cases,
        "defined_no_overload_matches": defined_matches,
        "defined_no_overload_mismatches": len(defined_mismatches),
        "special_code_cases": special_cases,
        "c_overload_cases": overload_cases,
        "mismatches": mismatches[:20],
        "defined_mismatches": defined_mismatches[:20],
        "scope": "free_space/dhcp_skip_opts/find_overload C oracle versus Rust BOOTP vendor primitive",
    }
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 1 if defined_mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
