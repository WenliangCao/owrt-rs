#!/usr/bin/env python3
"""Compare DHCP local destinations and ARP requests with exact dhcp.c branches.

No sockets or ioctls are executed. The C ioctl stub records ARP metadata; the
Rust adapter exercises runtime::destination with the same completed header.
This does not validate packet construction, interface control data or sending.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/dhcp.c"
SOURCE_SHA256 = "600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001"

C_PREFIX = r'''
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define SIOCSARP 0
#define ATF_COM 2
#define MS_DHCP 0
#define LOG_ERR 0
#define _(x) (x)
struct { int dhcp_client_port, dhcpfd; } settings = {68, -1};
/* The Linux target's sockaddr.sa_data is 14 bytes, including on macOS hosts. */
struct { struct { char sa_data[14]; } ifr_addr; } ifr;
struct arp_request {
  struct sockaddr_in arp_pa;
  struct { unsigned short sa_family; unsigned char sa_data[14]; } arp_ha;
  int arp_flags;
};
static int did_arp;
static int record_ioctl(int fd, int command, struct arp_request *request) {
  (void)fd; (void)command; (void)request; did_arp = 1; return 0;
}
#define ioctl record_ioctl
static void my_syslog(int priority, const char *format, ...) {
  (void)priority; (void)format;
}
int main(void) {
  unsigned inform, ciaddr, yiaddr, peer, port, flags, htype, hlen;
  while (scanf("%u %u %u %u %u %u %u %u", &inform, &ciaddr, &yiaddr,
               &peer, &port, &flags, &htype, &hlen) == 8) {
    struct { struct in_addr ciaddr, yiaddr; unsigned short flags;
             unsigned char htype, hlen, chaddr[16]; } packet, *mess = &packet;
    __typeof__(settings) *daemon = &settings;
    struct sockaddr_in dest = {0};
    struct arp_request arp_req = {0};
    int is_inform = inform, is_relay_reply = 0;
    memset(mess, 0, sizeof(*mess));
    mess->ciaddr.s_addr = htonl(ciaddr); mess->yiaddr.s_addr = htonl(yiaddr);
    mess->flags = htons(flags); mess->htype = htype; mess->hlen = hlen;
    for (int i = 0; i < 16; i++) mess->chaddr[i] = i + 1;
    dest.sin_addr.s_addr = htonl(peer); dest.sin_port = htons(port); did_arp = 0;
'''
C_SUFFIX = r'''
    printf("%u %u", ntohl(dest.sin_addr.s_addr), ntohs(dest.sin_port));
    if (did_arp) {
      printf(" %u ", arp_req.arp_ha.sa_family);
      for (unsigned i = 0; i < hlen; i++) printf("%02x", arp_req.arp_ha.sa_data[i]);
      putchar('\n');
    } else puts(" - -");
  }
  return feof(stdin) ? 0 : 2;
}
'''


def oracle(source: str) -> str:
    start = source.index("  else if (mess->ciaddr.s_addr)\n")
    end = source.index("#if defined(HAVE_LINUX_NETWORK)", start)
    configured = source[start:end].replace("  else if", "  if", 1)
    start = source.index("      if ((ntohs(mess->flags)", end)
    end = source.index("#elif defined(HAVE_SOLARIS_NETWORK)", start)
    # This exact suffix contains the close brace of the outer Linux branch.
    unconfigured = source[start:end]
    return C_PREFIX + configured + "  else {\n" + unconfigured + C_SUFFIX


def compare(inputs: list[str], expected: list[str], actual: list[str]) -> dict:
    mismatches = [
        {"case": index, "input": case, "c": left, "rust": right}
        for index, (case, left, right) in enumerate(
            itertools.zip_longest(inputs, expected, actual)
        )
        if case is None or left is None or right is None or left != right
    ]
    return {
        "cases": len(inputs), "c_lines": len(expected), "rust_lines": len(actual),
        "success_count": len(inputs) - sum(item["input"] is not None for item in mismatches),
        "error_count": len(mismatches), "mismatches": mismatches,
    }


def calibrate() -> None:
    assert compare(["one"], ["good"], ["good"])["success_count"] == 1
    for expected, actual in [(["good"], ["bad"]), ([], []), (["good"], []),
                             (["good"], ["good", "extra"])]:
        assert compare(["one"], expected, actual)["error_count"] > 0


def calibrate_oracle(inputs: list[str], outputs: list[str]) -> None:
    observed = dict(zip(inputs, outputs))
    client, offered, peer = 0xc0000209, 0xc000022a, 0xc000020a
    # Hand-checked dhcp.c branches pin the harness setup as well as counting.
    fixed = [
        ([1, client, offered, peer, 0, 0, 1, 6], f"{client} 68 - -"),
        ([1, client, offered, 0, 1068, 0, 1, 6], f"{client} 68 - -"),
        ([1, client, offered, peer, 1068, 0, 1, 6], f"{peer} 1068 - -"),
        ([0, client, offered, peer, 1068, 0, 1, 6], f"{client} 68 - -"),
        ([0, 0, offered, peer, 1068, 0, 1, 6], f"{offered} 68 1 010203040506"),
        ([0, 0, offered, peer, 1068, 0x8000, 1, 6], "4294967295 68 - -"),
        ([0, 0, offered, peer, 1068, 0, 1, 15], "4294967295 68 - -"),
    ]
    for values, expected in fixed:
        assert observed.get(" ".join(map(str, values))) == expected


def cases() -> list[str]:
    # Header values are bounded by Packet::parse: htype=0 requires hlen=0.
    addresses = [0, 0xc0000209, 0xc000020a]
    hardware = [(0, 0)] + [(kind, length) for kind in [1, 6, 255] for length in [0, 1, 6, 14, 15, 16]]
    return [
        " ".join(map(str, (*values, *hw)))
        for values in itertools.product([0, 1], [0, 0xc0000209], [0, 0xc000022a],
                                        addresses, [0, 68, 1068, 65535], [0, 0x8000])
        for hw in hardware
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    calibrate()
    source = args.source.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise SystemExit("C source identity mismatch")
    out = args.out.resolve()
    if not out.is_relative_to(REPO / "private"):
        raise SystemExit("output must stay under ignored private/")
    out.mkdir(parents=True, exist_ok=False)
    (out / "oracle.c").write_text(oracle(source.decode()))
    subprocess.run([shutil.which("cc") or "cc", "-O1", "-g", "-Wall", "-Wextra",
                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    cargo = shutil.which("cargo") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/cargo")
    env = os.environ.copy()
    env["PATH"] = str(Path(cargo).parent) + os.pathsep + env.get("PATH", "")
    subprocess.run([cargo, "build", "--quiet", "--manifest-path",
                    str(REPO / "components/dnsmasq/Cargo.toml"), "--lib"], check=True, env=env)
    target = REPO / "components/dnsmasq/target/debug"
    subprocess.run([str(Path(cargo).with_name("rustc")), "--edition=2021",
                    str(REPO / "tools/dnsmasq/dhcp_destination_probe.rs"),
                    "--extern", f"dnsmasq_rs={target / 'libdnsmasq_rs.rlib'}",
                    "-L", f"dependency={target / 'deps'}", "-o", str(out / "rust-probe")], check=True, env=env)
    inputs = cases()
    payload = "\n".join(inputs) + "\n"
    (out / "input.txt").write_text(payload)
    outputs = []
    for name in ["oracle", "rust-probe"]:
        run = subprocess.run([str(out / name)], input=payload, capture_output=True, text=True, check=True)
        (out / f"{name}.stdout").write_text(run.stdout)
        (out / f"{name}.stderr").write_text(run.stderr)
        outputs.append(run.stdout.splitlines())
    calibrate_oracle(inputs, outputs[0])
    result = compare(inputs, *outputs)
    result.update(source_sha256=SOURCE_SHA256,
                  calibration="success/mismatch/missing/extra outputs and seven hand-checked C branches",
                  scope="local IPv4 destination and ARP metadata; no sockets, sends or interface control data")
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "mismatches"}))
    return int(result["error_count"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
