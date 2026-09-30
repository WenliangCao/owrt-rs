#!/usr/bin/env python3
"""Differentially exercise the DHCP reply wire boundary.

The oracle compiles `clear_packet`, `free_space`, `find_overload` and the
option-size rule from the hash-pinned patched `rfc2131.c`. The Rust side is
the crate's `dhcp_reply_probe` binary. Inputs/results are kept in ignored
`private/`; this is not a socket or lease-state test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/rfc2131.c"
EXPECTED_SHA256 = "14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c"


def extract(source: str, name: str) -> str:
    match = re.search(
        r"\n(?:static\s+)?[A-Za-z_][\w \t*]*[ \t*]" + re.escape(name) + r"\([^;{}]*\)\s*\{",
        source,
    )
    if not match:
        raise ValueError(f"missing C function {name}")
    brace = source.index("{", match.start())
    depth, end = 1, brace + 1
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
typedef uint32_t u32;
#define OPTION_OVERLOAD 52
#define OPTION_END 255
#define OPTION_MESSAGE_TYPE 53
#define OPTION_SERVER_IDENTIFIER 54
#define OPTION_LEASE_TIME 51
#define OPTION_MESSAGE 56
#define OPTION_RAPID_COMMIT 80
#define MIN_PACKETSZ 300
#define BOOTREQUEST 1
#define BOOTREPLY 2
#define DHCP_COOKIE 0x63825363
#define _(x) (x)
#define MS_DHCP 0
#define LOG_WARNING 0
#define OPT_LOG_OPTS 0
struct dhcp_packet {
  unsigned char op, htype, hlen, hops;
  u32 xid; unsigned short secs, flags;
  struct in_addr ciaddr, yiaddr, siaddr, giaddr;
  unsigned char chaddr[16], sname[64], file[128], options[16384];
};
static unsigned int option_uint(unsigned char *opt, int offset, int size) {
  unsigned int ret = 0; for (int i = 0; i < size; i++) ret = (ret << 8) | opt[offset + i + 2]; return ret;
}
static void my_syslog(int p, const char *f, ...) { (void)p; (void)f; }
'''

C_MAIN = r'''
static size_t decode(const char *text, unsigned char *out) {
  if (!strcmp(text, "-")) return 0;
  size_t n = strlen(text) / 2;
  for (size_t i = 0; i < n; i++) { unsigned value; if (sscanf(text + 2*i, "%2x", &value) != 1) return (size_t)-1; out[i] = (unsigned char)value; }
  return n;
}
static unsigned char *find_opt(unsigned char *start, unsigned char *end, int code, int min) {
  while (start < end) {
    if (*start == 0) { start++; continue; }
    if (*start == 255) return code == 255 ? start : NULL;
    if (start + 2 > end || start + 2 + start[1] > end) return NULL;
    if (*start == code && start[1] >= min) return start;
    start += start[1] + 2;
  }
  return NULL;
}
static void clear_request(struct dhcp_packet *p, unsigned char *end) {
  p->op = BOOTREPLY;
  memset(p->sname, 0, sizeof(p->sname)); memset(p->file, 0, sizeof(p->file));
  memset(p->options + 4, 0, end - (p->options + 4)); p->siaddr.s_addr = 0;
}
static unsigned char *put(struct dhcp_packet *p, unsigned char *end, int code, int len, const unsigned char *value) {
  unsigned char *q = free_space(p, end, code, len);
  if (q) { memcpy(q, value, len); }
  return q;
}
static size_t final_size(struct dhcp_packet *p) {
  unsigned char *q = dhcp_skip_opts(p->options + 4); unsigned char *over = find_overload(p);
  if (over && (option_uint(over, 0, 1) & 1)) *dhcp_skip_opts(p->file) = 255;
  if (over && (option_uint(over, 0, 1) & 2)) *dhcp_skip_opts(p->sname) = 255;
  *q++ = 255; size_t result = (size_t)(q - (unsigned char *)p); return result < MIN_PACKETSZ ? MIN_PACKETSZ : result;
}
int main(void) {
  char line[65536];
  while (fgets(line, sizeof(line), stdin)) {
    char *kind = strtok(line, " \t\r\n"), *req = strtok(NULL, " \t\r\n"), *lease_word = strtok(NULL, " \t\r\n"), *rapid_word = strtok(NULL, " \t\r\n"), *options = strtok(NULL, " \t\r\n");
    if (!kind || !req || !lease_word || !rapid_word || !options) return 2;
    unsigned char request_options[8192]; size_t request_len = decode(req, request_options); if (request_len == (size_t)-1) return 3;
    struct dhcp_packet packet; memset(&packet, 0, sizeof(packet)); packet.op = BOOTREQUEST; packet.htype = 1; packet.hlen = 6; packet.xid = htonl(0x01020304); memcpy(packet.options, (unsigned char[]){99,130,83,99}, 4); memcpy(packet.options + 4, request_options, request_len);
    unsigned char *raw57 = find_opt(packet.options + 4, packet.options + 4 + request_len, 57, 2); size_t size = 548;
    if (raw57) { unsigned advertised = option_uint(raw57, 0, 2); size = (size_t)advertised - 28; if (size > 16384) size = 16384; else if (size < 548) size = 548; }
    unsigned char *end = (unsigned char *)&packet + size;
    unsigned char *request_prl = find_opt(packet.options + 4, packet.options + 4 + request_len, 55, 0);
    unsigned char *request_fqdn = find_opt(packet.options + 4, packet.options + 4 + request_len, 81, 3);
    unsigned char *request_hostname = find_opt(packet.options + 4, packet.options + 4 + request_len, 12, 1);
    int broken = request_fqdn ? (!(request_fqdn[2] & 4) && request_fqdn[1] > 3 && request_fqdn[1 + request_fqdn[1]] == 0) : (request_hostname && request_hostname[1] && request_hostname[1 + request_hostname[1]] == 0);
    clear_request(&packet, end);
    if (!request_prl) { packet.file[0] = 1; packet.sname[0] = 1; } else end -= 3;
    unsigned char type, server[4] = {192,0,2,1}, lease[4]; unsigned lease_value = (unsigned)strtoul(lease_word, NULL, 10); lease[0]=lease_value>>24; lease[1]=lease_value>>16; lease[2]=lease_value>>8; lease[3]=lease_value; int is_nak = kind[0] == 'N';
    if (kind[0] == 'O') type = 2; else if (kind[0] == 'A' || kind[0] == 'I') type = 5; else if (is_nak) type = 6; else return 4;
    if (kind[0] == 'O' || kind[0] == 'A') packet.yiaddr.s_addr = htonl(0xc000022a);
    put(&packet, end, 53, 1, &type); put(&packet, end, 54, 4, server);
    if (kind[0] == 'O' || kind[0] == 'A') put(&packet, end, 51, 4, lease);
    if (kind[0] == 'A' && rapid_word[0] == '1') put(&packet, end, 80, 0, NULL);
    if (is_nak) {
      unsigned char message[64] = "wrong network"; put(&packet, end, 56, strlen((char *)message) + broken, message);
    } else {
      if (strcmp(options, "-")) for (char *word = options; word && *word; ) { char *next = strchr(word, ','); if (next) *next++ = 0; char *colon = strchr(word, ':'); if (!colon) return 5; *colon = 0; unsigned code = strtoul(word, NULL, 10); unsigned char value[256]; size_t len = decode(colon + 1, value); if (len == (size_t)-1 || len > 255) return 6; put(&packet, end, code, (int)len, value); word = next; }
    }
    if (!request_prl) { packet.file[0] = 0; packet.sname[0] = 0; }
    size_t length = final_size(&packet); printf("%zu ", length); for (size_t i = 0; i < length; i++) printf("%02x", ((unsigned char *)&packet)[i]); putchar('\n');
  }
  return 0;
}
'''


def cases(random_count: int) -> list[str]:
    result = []
    fixed = [
        ("O", bytes([53, 1, 1, 255]), 600, 0, ""),
        ("A", bytes([53, 1, 3, 55, 2, 1, 3, 255]), 600, 1, "1:c0000200,2:01"),
        ("I", bytes([53, 1, 8, 255]), 0, 0, "1:" + ("07" * 250)),
        ("N", bytes([53, 1, 3, 81, 4, 0, 0, 0, 0, 12, 2, 120, 0, 255]), 0, 0, "1:ffffff00"),
        ("N", bytes([53, 1, 3, 55, 1, 6, 255]), 0, 0, ""),
        ("O", bytes([53, 1, 1, 57, 2, 0x02, 0x00, 255]), 600, 0, ""),
        ("O", bytes([53, 1, 1, 57, 2, 0x05, 0xdc, 255]), 600, 0, ""),
        ("O", bytes([53, 1, 1, 57, 2, 0x00, 0x01, 255]), 600, 0, ""),
    ]
    for kind, request, lease, rapid, options in fixed:
        result.append(f"{kind} {request.hex()} {lease} {rapid} {options or '-'}")
    rng = random.Random(0x2131_2930)
    for _ in range(random_count):
        kind = rng.choice("OAIN")
        request = bytearray([53, 1, rng.choice([1, 3, 8])])
        if rng.randrange(2): request.extend([55, rng.randrange(0, 8), *[rng.randrange(1, 90) for _ in range(rng.randrange(0, 8))]])
        if rng.randrange(3) == 0: request.extend([81, 4, rng.choice([0, 4]), 0, 0, 0])
        elif rng.randrange(2) == 0: request.extend([12, 2, 120, 0])
        request.append(255)
        options = []
        for code in rng.sample([1, 2, 3, 6, 15, 42, 119], rng.randrange(0, 4)):
            options.append(f"{code}:{bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80))).hex() or '-'}")
        result.append(f"{kind} {bytes(request).hex()} {rng.randrange(0, 3601)} {rng.randrange(2)} {','.join(options) or '-'}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, default=REPO / "private/dnsmasq-rewrite/dhcp-reply-diff")
    parser.add_argument("--random-cases", type=int, default=1000)
    args = parser.parse_args()
    source = args.source.resolve()
    if hashlib.sha256(source.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("C source identity mismatch")
    out = args.out.resolve()
    if not out.is_relative_to(REPO / "private"):
        raise SystemExit("output must stay under private/")
    out.mkdir(parents=True, exist_ok=True)
    text = source.read_text()
    (out / "oracle.c").write_text(C_PREFIX + extract(text, "dhcp_skip_opts") + extract(text, "find_overload") + extract(text, "free_space") + C_MAIN)
    cc = shutil.which("cc") or shutil.which("clang")
    subprocess.run([cc, "-O1", "-g", "-Wall", "-Wextra", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    payload = "\n".join(cases(args.random_cases)) + "\n"
    (out / "input.txt").write_text(payload)
    c = subprocess.run([str(out / "oracle")], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    cargo = shutil.which("cargo") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/cargo")
    cargo_bin = str(Path(cargo).parent)
    cargo_env = os.environ.copy()
    cargo_env["PATH"] = cargo_bin + os.pathsep + cargo_env.get("PATH", "")
    subprocess.run([cargo, "build", "--quiet", "--manifest-path", str(REPO / "components/dnsmasq/Cargo.toml"), "--bin", "dhcp_reply_probe"], check=True, env=cargo_env)
    probe = REPO / "components/dnsmasq/target/debug/dhcp_reply_probe"
    rust = subprocess.run([str(probe)], input=payload, text=True, capture_output=True, check=True).stdout.splitlines()
    normalized_rust = []
    for line in rust:
        fields = line.split(" ", 3)
        normalized_rust.append(f"{fields[0]} {fields[3]}" if len(fields) == 4 else line)
    mismatches = [{"case": i, "input": case, "c": a, "rust": b} for i, (case, a, b) in enumerate(zip(payload.splitlines(), c, normalized_rust)) if a != b]
    result = {"source_sha256": EXPECTED_SHA256, "cases": len(payload.splitlines()), "c_lines": len(c), "rust_lines": len(rust), "mismatches": mismatches[:20], "mismatch_count": len(mismatches), "scope": "clear_packet/free_space/dhcp_packet_size plus mandatory DHCP reply wire"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "mismatches"}))
    return int(bool(mismatches) or len(c) != len(rust))


if __name__ == "__main__":
    raise SystemExit(main())
