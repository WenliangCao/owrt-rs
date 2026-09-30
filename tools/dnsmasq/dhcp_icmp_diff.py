#!/usr/bin/env python3
"""Build exact C DHCP ping cache/ICMP oracles and compare socket-free inputs.

The generated C also accepts N ADDRESS for a real Linux-only isolated probe.
Use dhcp_icmp_linux.py for network/permission/cancellation/resource checks.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess

from dhcp_reply_diff import extract
from dhcp_destination_diff import compare, calibrate

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "dhcp.c": "600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001",
    "dnsmasq.c": "d4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1",
    "config.h": "dacbe1f8d0e03d93e53a81901956b07ab7a5059d1e5db3225150a9688a1122da",
    "util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973",
    "network.c": "8229872d30a2fb2d86ec9a9e550e51fbb8d8d97926e7a02b0137f2a7b40c40c9",
}
PREFIX = r'''
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
typedef uint16_t u16;
#define HAVE_LINUX_NETWORK
#define PING_WAIT 3
#define PING_CACHE_TIME 30
#define OPT_NO_PING 0
#define whine_malloc malloc
struct ping_result { struct in_addr addr; time_t time; unsigned int hash; struct ping_result *next; };
static struct { struct ping_result *ping_results; int port; } state;
#define daemon (&state)
static int no_ping, response, calls;
static int option_bool(int value) { (void)value; return no_ping; }
static int icmp_ping(struct in_addr address) { (void)address; calls++; return response; }
static unsigned short rand16(void) { return 0x2930; }
static struct pollfd waited;
static void poll_reset(void) { waited.fd = -1; waited.events = waited.revents = 0; }
static void poll_listen(int fd, int events) { waited.fd = fd; waited.events = events; }
static int do_poll(int timeout) { return poll(&waited, 1, timeout); }
static int poll_check(int fd, int events) { return waited.fd == fd && (waited.revents & events); }
static void set_dns_listeners(void) {}
static void set_log_writer(void) {}
static void check_log_writer(int unused) { (void)unused; }
static void check_dns_listeners(time_t now) { (void)now; }
static int delay_dhcp(time_t start, int sec, int fd, uint32_t addr, unsigned short id);
'''
MAIN = r'''
static void reset(void) {
  while (state.ping_results) { struct ping_result *next = state.ping_results->next; free(state.ping_results); state.ping_results = next; }
}
static void print_result(struct ping_result *result) {
  if (result) printf("A %u", result->hash); else printf("I");
}
int main(void) {
  if (sizeof(struct ip) != 20 || sizeof(struct icmp) != 28) return 10;
  char *line = NULL; size_t capacity = 0;
  while (getline(&line, &capacity, stdin) > 0) {
    char op; if (sscanf(line, "%c", &op) != 1) return 2;
    if (op == 'R') { reset(); puts("R"); }
    else if (op == 'C') {
      long long now; char address[32]; unsigned hash; int loopback;
      if (sscanf(line, "C %lld %31s %u %d %d %d", &now, address, &hash, &no_ping, &loopback, &response) != 6) return 2;
      struct in_addr target; if (inet_pton(AF_INET, address, &target) != 1) return 2;
      calls = 0; print_result(do_icmp_ping(now, target, hash, loopback)); printf("|%d|", calls);
      for (struct ping_result *entry = state.ping_results; entry; entry = entry->next) {
        char text[32]; inet_ntop(AF_INET, &entry->addr, text, sizeof(text)); printf("%s,%lld,%u;", text, (long long)entry->time, entry->hash);
      }
      puts("");
    } else if (op == 'W') {
      unsigned id; if (sscanf(line, "W %u", &id) != 1) return 2;
      wire_request(id);
    } else if (op == 'T') {
      long long start, now; int timeout_count, sec=PING_WAIT;
      if (sscanf(line, "T %lld %lld %d", &start, &now, &timeout_count) != 3) return 2;
      printf("%d\n", (difftime(now, start) <= (float)sec) && (timeout_count < sec * 4));
    } else if (op == 'M') {
      unsigned id; char peer[32], target[32], hex[4096];
      if (sscanf(line, "M %u %31s %31s %4095s", &id, peer, target, hex) != 4) return 2;
      unsigned char bytes[2048] = {0}; size_t len = !strcmp(hex, "-") ? 0 : strlen(hex) / 2;
      for (size_t index = 0; index < len; index++) { unsigned v; if (sscanf(hex + 2*index, "%2x", &v) != 1) return 2; bytes[index] = v; }
      struct in_addr from, to; if (inet_pton(AF_INET, peer, &from) != 1 || inet_pton(AF_INET, target, &to) != 1) return 2;
      printf("%d\n", wire_matches(bytes, len, from, to.s_addr, id));
    } else if (op == 'N') {
      if (!getenv("DNSMASQ_TEST_ISOLATED") || strcmp(getenv("DNSMASQ_TEST_ISOLATED"), "1")) return 3;
      char target[32]; struct in_addr address;
      if (sscanf(line, "N %31s", target) != 1 || inet_pton(AF_INET, target, &address) != 1) return 2;
      print_result(network_cached_ping(100, address, 7, 0)); puts("");
    } else return 2;
    fflush(stdout);
  }
  reset(); free(line); return 0;
}
'''


def oracle(sources: dict[str, str]) -> str:
    dhcp, daemon = sources["dhcp.c"], sources["dnsmasq.c"]
    cache = extract(dhcp, "do_icmp_ping")
    start = daemon.index("  memset(&packet.icmp, 0, sizeof(packet.icmp));")
    end = daemon.index("  while (retry_send", start)
    wire = "static void wire_request(unsigned short id) { struct { struct ip ip; struct icmp icmp; } packet; unsigned int i, j;\n" + daemon[start:end]
    wire += 'for (size_t n=0; n<sizeof(packet.icmp); n++) printf("%02x", ((unsigned char *)&packet.icmp)[n]); puts(""); }\n'
    start = daemon.index("addr == faddr.sin_addr.s_addr &&")
    end = daemon.index("return 1;", start) + len("return 1;")
    wire += "static int wire_matches(const unsigned char *bytes, size_t len, struct in_addr from, uint32_t addr, unsigned short id) {\n"
    wire += "struct { struct ip ip; struct icmp icmp; } packet = {0}; struct sockaddr_in faddr = {0}; faddr.sin_addr=from; size_t got=len<sizeof(packet)?len:sizeof(packet); memcpy(&packet,bytes,got); if (got == sizeof(packet) && "
    wire += daemon[start:end] + " return 0; }\n"
    network = extract(sources["network.c"], "fix_fd")
    network += extract(sources["util.c"], "retry_send") + extract(sources["util.c"], "dnsmasq_time")
    network += extract(daemon, "make_icmp_sock")
    network += "\n#define icmp_ping reference_network_ping\n" + extract(daemon, "icmp_ping") + "\n#undef icmp_ping\n"
    network += extract(daemon, "delay_dhcp")
    network += "\n#define do_icmp_ping network_cached_ping\n#define icmp_ping reference_network_ping\n" + cache + "\n#undef do_icmp_ping\n#undef icmp_ping\n"
    return PREFIX + cache + wire + network + MAIN


def cases() -> list[str]:
    fixed = ["R", "C 100 192.0.2.10 11 0 0 0", "C 130 192.0.2.10 22 0 0 1", "C 131 192.0.2.10 22 0 0 1", "R"]
    for index in range(1, 7): fixed.append(f"C 100 192.0.2.{index} {index} 0 0 0")
    fixed += ["C 130 192.0.2.7 7 0 0 1", "C 131 192.0.2.7 7 0 0 0", "R"]
    fixed += ["C 100 192.0.2.10 0 0 0 0", "C 100 192.0.2.10 9 1 1 1", "R"]
    rng = random.Random(0x2931c4)
    for _ in range(1000):
        if rng.randrange(20) == 0: fixed.append("R")
        fixed.append(f"C {rng.choice([99,100,101,129,130,131,160,161])} 192.0.2.{rng.randrange(1,10)} {rng.getrandbits(32)} {rng.randrange(2)} {rng.randrange(2)} {rng.randrange(2)}")
    fixed.extend(f"W {value}" for value in range(65536))
    fixed.extend(f"T 100 {now} {count}" for now in [90,99,100,102,103,104,200] for count in [0,1,11,12,13])
    for index in range(1000):
        target, peer = "192.0.2.10", rng.choice(["192.0.2.10", "192.0.2.11"])
        id_value = rng.randrange(65536)
        packet = bytearray(rng.randbytes(rng.choice([0,19,20,27,28,47,48,49,100])))
        if len(packet) >= 48:
            packet[20] = rng.choice([0,0,8,3])
            packet[24:26] = (id_value if index % 2 else id_value ^ 1).to_bytes(2, byteorder=os.sys.byteorder)
            packet[26:28] = rng.choice([b"\0\0", b"\0\1"])
        fixed.append(f"M {id_value} {peer} {target} {packet.hex() or '-'}")
    return fixed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    calibrate()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "private"): raise SystemExit("output must stay under private/")
    out.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name, expected in SOURCES.items():
        raw = (args.source / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected: raise SystemExit(f"identity mismatch: {name}")
        sources[name] = raw.decode()
    assert "#define PING_WAIT 3" in sources["config.h"] and "#define PING_CACHE_TIME 30" in sources["config.h"]
    (out / "oracle.c").write_text(oracle(sources))
    subprocess.run([shutil.which("cc"), "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    cargo = shutil.which("cargo")
    if not cargo: raise SystemExit("cargo/rustc must be on PATH")
    subprocess.run([cargo, "build", "--quiet", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"), "--lib"], check=True)
    target = ROOT / "components/dnsmasq/target/debug"
    subprocess.run([shutil.which("rustc"), "--edition=2021", str(ROOT / "tools/dnsmasq/dhcp_icmp_probe.rs"), "--extern", f"dnsmasq_rs={target / 'libdnsmasq_rs.rlib'}", "-L", f"dependency={target / 'deps'}", "-o", str(out / "rust-probe")], check=True)
    inputs = cases()
    payload = "\n".join(inputs) + "\n"
    (out / "input.txt").write_text(payload)
    outputs = []
    for name in ["oracle", "rust-probe"]:
        run = subprocess.run([str(out / name)], input=payload, text=True, capture_output=True)
        (out / f"{name}.stdout").write_text(run.stdout)
        (out / f"{name}.stderr").write_text(run.stderr)
        run.check_returncode()
        outputs.append(run.stdout.splitlines())
    assert outputs[0][:4] == ["R", "A 11|1|192.0.2.10,100,11;", "A 11|0|192.0.2.10,100,11;", "I|1|192.0.2.10,100,11;"]
    result = compare(inputs, *outputs)
    result.update(source_sha256=SOURCES, scope="exact C ping cache, all 65536 echo IDs, bounded reply matching and 35 wait-boundary cases; no network",
                  binary_sha256={name: hashlib.sha256((out / name).read_bytes()).hexdigest() for name in ["oracle", "rust-probe"]},
                  rust_source_sha256=hashlib.sha256((ROOT / "components/dnsmasq/src/dhcp/probe.rs").read_bytes()).hexdigest())
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key:value for key,value in result.items() if key != "mismatches"}))
    return int(result["error_count"] != 0)


if __name__ == "__main__": raise SystemExit(main())
