#!/usr/bin/env python3
"""Independent exact-image audit of accepted inactive options and integer edges.

Run with run_isolated.sh. This creates only an evidence-owned rootfs overlay;
it does not modify product files or contact a physical router.
"""
import argparse
import json
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

from m2_rootfs import command, prepare, sha256


A05 = [
    "quiet-ra", "quiet-dhcp6", "no-dhcpv6-interface=lo", "enable-ra",
    "auth-ttl=60", "auth-soa=1", "auth-server=ns.audit.test,lo",
    "auth-sec-servers=ns.audit.test", "auth-peer=192.0.2.1",
    "dnssec-debug", "dnssec-no-timecheck",
]
INACTIVE = [
    "quiet-ra", "quiet-dhcp6", "no-dhcpv6-interface=lo", "enable-ra",
    "auth-ttl=60", "auth-soa=1", "auth-server=ns.audit.test,lo",
    "auth-zone=audit.test", "auth-sec-servers=ns.audit.test",
    "auth-peer=192.0.2.1", "dnssec-debug", "dnssec-no-timecheck",
    "dnssec-check-unsigned", "dnssec-check-unsigned=no", "dnssec",
    "dnssec-timestamp=/m2/timestamp", "dnssec-limits=1,2,3,4",
    "conntrack", "enable-dbus", "dhcp-duid=1,00:01", "dhcp-luascript=/m2/script",
    "ra-param=lo,10,20", "ipset=/audit.test/audit", "nftset=/audit.test/4#inet#fw4#audit",
]
INTEGER = [
    f"{name}={value}"
    for name in ("cache-size", "local-ttl", "max-tcp-connections", "fast-dns-retry")
    for value in ("2147483647", "2147483648", "4294967296", "4294967356")
] + ["fast-dns-retry=1000,2147483648", "fast-dns-retry=1000,4294968296"]


def invoke(root, side, config, startup=False):
    args = ["-C", config]
    if startup:
        args += ["-k", "--user=root", "--group=root", "--pid-file=", "--log-facility=-"]
    else:
        args += ["--test"]
    proc = subprocess.Popen(command(root, side, *args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    alive = False
    try:
        out, err = proc.communicate(timeout=0.3 if startup else 3)
    except subprocess.TimeoutExpired:
        alive = startup
        proc.send_signal(signal.SIGTERM)
        try:
            out, err = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
    return {"exit": proc.returncode, "alive_after_300ms": alive,
            "stdout": out.decode(errors="backslashreplace"),
            "stderr": err.decode(errors="backslashreplace")}


def invoke_dns(root, side, config):
    args = ["-C", config, "-k", "--user=root", "--group=root", "--pid-file=", "--log-facility=-"]
    proc = subprocess.Popen(command(root, side, *args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    packet = struct.pack("!6H", 321, 0x100, 1, 0, 0, 0) + b"\x05audit\x04test\0\0\1\0\1"
    response = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.1)
        deadline = time.monotonic() + 1
        while proc.poll() is None and time.monotonic() < deadline:
            client.sendto(packet, ("127.0.0.1", 15353))
            try:
                response = client.recv(65535)
                break
            except socket.timeout:
                pass
    alive = proc.poll() is None
    if alive:
        proc.send_signal(signal.SIGTERM)
    try:
        out, err = proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return {"exit": proc.returncode, "alive_before_term": alive,
            "query_hex": packet.hex(), "response_hex": response.hex() if response else None,
            "expected_local_a": response is not None and response.endswith(bytes([192, 0, 2, 42])),
            "stdout": out.decode(errors="backslashreplace"),
            "stderr": err.decode(errors="backslashreplace")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--a05-only", action="store_true",
                        help="assert A05's 11 runtime regressions and the no-ident control")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out, args.rust)
    rows = []
    cases = ["no-ident", *(A05 if args.a05_only else [*INACTIVE, *INTEGER])]
    for index, directive in enumerate(cases):
        path = f"/m2/case-{index}.conf"
        (root / path.lstrip("/")).write_text("port=0\nno-hosts\nno-resolv\n" + directive + "\n")
        row = {"directive": directive, "syntax": {}}
        for side in ("c", "rust"):
            row["syntax"][side] = invoke(root, side, path)
        if directive in INACTIVE or directive == "no-ident":
            row["startup"] = {side: invoke(root, side, path, True) for side in ("c", "rust")}
            if row["startup"]["c"]["alive_after_300ms"]:
                (root / path.lstrip("/")).write_text(
                    "port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\n"
                    "host-record=audit.test,192.0.2.42\n" + directive + "\n")
                row["dns"] = {side: invoke_dns(root, side, path) for side in ("c", "rust")}
        rows.append(row)
    failures = []
    if args.a05_only:
        for row in rows:
            for side in ("c", "rust"):
                if row["syntax"][side]["exit"] != 0:
                    failures.append(f'{row["directive"]}: {side} syntax rejected')
                if not row["startup"][side]["alive_after_300ms"] or row["startup"][side]["exit"] != 0:
                    failures.append(f'{row["directive"]}: {side} startup failed')
                dns = row.get("dns", {}).get(side, {})
                if not dns.get("alive_before_term") or not dns.get("expected_local_a") or dns.get("exit") != 0:
                    failures.append(f'{row["directive"]}: {side} DNS failed')
            if row.get("dns", {}).get("c", {}).get("response_hex") != row.get("dns", {}).get("rust", {}).get("response_hex"):
                failures.append(f'{row["directive"]}: DNS wire mismatch')
    result = {"scope": "A05 runtime compatibility" if args.a05_only else __doc__,
              "timestamp": time.time(), "failures": failures,
              "c_sha256": sha256(root / "usr/sbin/dnsmasq"),
              "rust_sha256": sha256(root / "usr/sbin/dnsmasq-rs"),
              "tool_sha256": sha256(Path(__file__)), "rows": rows}
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"cases": len(rows), "syntax_differences": [r["directive"] for r in rows
          if r["syntax"]["c"]["exit"] != r["syntax"]["rust"]["exit"]],
          "startup_differences": [r["directive"] for r in rows if "startup" in r
          and r["startup"]["c"]["alive_after_300ms"] != r["startup"]["rust"]["alive_after_300ms"]],
          "failures": failures}))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
