#!/usr/bin/env python3
"""Independent functional audit; no physical router and no performance measurements.

Pre-experiment model: existing dynamic leases cache pool leasetime in Rust, whereas
C resolves it per reply. Predict 600 -> 1200 reload produces Rust=600, C=1200.
Second hypothesis: IAPREFIX /128 withdrawal is serialized as IAADDR in Rust.
Packet bytes and exact-ELF responses decide both; no timing/performance inference.
Both cases share one isolated fixture to minimize setup cost. Preserve every result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback

import odhcpd_baseline as base


def exercise(fixture):
    path = fixture.root / "etc/config/dhcp"
    path.write_text(path.read_text().replace("option leasetime '12h'", "option leasetime '600'"))
    fixture.start_daemon()
    fixture.request("ready_ra", "ra")
    offer = fixture.dhcp("na_offer_600", 1, [(3, struct.pack("!III", 1, 0, 0))])
    raw = base.options(bytes.fromhex(offer["hex"])[4:])
    server = next(b for c, b in raw if c == 2)
    na = next(b for c, b in raw if c == 3)
    fixture.dhcp("na_request_600", 3, [(3, na)], server=server)
    path.write_text(path.read_text().replace("option leasetime '600'", "option leasetime '1200'"))
    fixture.daemon.send_signal(signal.SIGHUP)
    time.sleep(.3)
    fixture.dhcp("na_renew_after_1200_reload", 5, [(3, na)], server=server)
    fixture.dhcp("na_rebind_after_1200_reload", 6, [(3, na)])
    fixture.dhcp("fresh_na_after_1200_reload", 3, [(3, struct.pack("!III", 9, 0, 0))], server=server)
    pd_offer = fixture.dhcp("pd_offer", 1, [(25, struct.pack("!III", 2, 0, 0))])
    pd = next(b for c, b in base.options(bytes.fromhex(pd_offer["hex"])[4:]) if c == 25)
    fixture.dhcp("pd_request", 3, [(25, pd)], server=server)
    old = base.opt(26, struct.pack("!IIB", 600, 600, 128) + socket.inet_pton(socket.AF_INET6, "fd12:3456:789a:4::1234"))
    fixture.dhcp("pd_renew_old_128", 5, [(25, struct.pack("!III", 2, 0, 0) + old)], server=server)
    fixture.snapshot("final_state")
    fixture.record("complete", True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--candidate-sha", help="require this exact SHA-256 instead of the frozen C/Rust identities")
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.candidate_sha is not None:
        args.candidate_sha = args.candidate_sha.lower()
        if len(args.candidate_sha) != 64 or any(c not in "0123456789abcdef" for c in args.candidate_sha):
            parser.error("--candidate-sha must contain exactly 64 hexadecimal characters")
    expected = {args.candidate_sha} if args.candidate_sha else {
        base.C_SHA, "79f1349e845722d3824fab855b18f39e86e0ed5a1fb87cdc32374dc734302b55"
    }
    actual = hashlib.sha256(Path(args.daemon).read_bytes()).hexdigest()
    if actual not in expected:
        parser.error(f"daemon SHA-256 {actual} does not match expected {sorted(expected)}")
    if not args.inside:
        Path(args.out).mkdir(mode=0o700, parents=True, exist_ok=False)
        shutil.copy2(__file__, Path(args.out) / "instrument.py")
        command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child=KILL", "--mount-proc",
                   sys.executable, str(Path(__file__).resolve()), "--inside", "--rootfs", args.rootfs,
                   "--daemon", args.daemon, "--out", args.out]
        if args.candidate_sha:
            command += ["--candidate-sha", args.candidate_sha]
        sys.exit(subprocess.run(command, timeout=120).returncode)
    fixture = base.Fixture(args)
    fixture.record("expected_elf_sha256", sorted(expected))
    try:
        fixture.setup()
        exercise(fixture)
    except Exception:
        fixture.record("error", traceback.format_exc())
        raise
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
