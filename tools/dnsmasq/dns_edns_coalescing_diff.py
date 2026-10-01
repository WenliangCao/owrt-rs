#!/usr/bin/env python3
"""Exact-daemon empty/option-bearing OPT coalescing and client retry boundary.

Hold the first reply, submit the same question with different OPT data, retry
that second client, and verify first-query EDNS bytes and both recipients.
This gate does not claim option-bearing query cache support.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess

import cache_answer_diff as base
from cache_clipped_service_diff import observation, query
from dns_service_probe import semantics
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference

ROOT = Path(__file__).resolve().parents[2]


def opt_query(ident, data):
    packet = bytearray(query("shared.test", 1, ident, True))
    packet[-2:] = struct.pack("!H", len(data))
    return bytes(packet) + data


def run(binary, first, second, address, out):
    out.mkdir(); trace = {"upstream": [], "replies": []}
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as upstream, socket.socket(family, socket.SOCK_DGRAM) as one, socket.socket(family, socket.SOCK_DGRAM) as two:
        upstream.bind((address, 0)); upstream.settimeout(.5)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        config = out / "dnsmasq.conf"
        config.write_text(f"no-hosts\nno-resolv\ncache-size=100\nlisten-address=127.0.0.1,::1\nport={port}\n"
                          f"host-record=ready.test,192.0.2.254\nserver={address}#{upstream.getsockname()[1]}\n")
        with (out / "stderr.log").open("wb") as log:
            daemon = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    assert daemon.poll() is None, "startup failure"
                    one.sendto(query("ready.test", 1, 1), (address, port))
                    if receive(one, .03) is not None: break
                else: raise AssertionError("readiness timeout")
                one.sendto(opt_query(0x5101, first), (address, port))
                initial, peer = upstream.recvfrom(65535)
                two.sendto(opt_query(0x5102, second), (address, port))
                assert not select.select([upstream], [], [], .05)[0], "second OPT variant did not coalesce"
                two.sendto(opt_query(0x5102, second), (address, port))
                retried, retry_peer = upstream.recvfrom(65535)
                assert initial == retried and peer == retry_peer, "client retry changed first-query bytes or upstream socket"
                for packet in (initial, retried):
                    decoded = semantics(packet); decoded["id"] = 0
                    trace["upstream"].append(decoded)
                response = bytearray(base.packet("shared.test", 1, 0x8180,
                                                 [("shared.test", 1, 53, bytes([8, 8, 4, 4]))]))
                response[11] = 1
                response.extend(initial[len(base.packet("shared.test", 1)):])
                upstream.sendto(initial[:2] + response[2:], peer)
                for client, ident in ((one, 0x5101), (two, 0x5102)):
                    packet = receive(client, .5)
                    assert packet is not None and int.from_bytes(packet[:2], "big") == ident
                    trace["replies"].append(observation(packet))
                    assert receive(client, .02) is None, "duplicate client received extra reply"
            finally:
                if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
                try: daemon.wait(3)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(3)
                (out / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
            assert daemon.returncode == 0
    return trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True); parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True); parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = verify_reference(args.c, None)
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists(); out.mkdir(parents=True)
    padding = bytes.fromhex("000c0000"); other = bytes.fromhex("fde90002aabb")
    cases = [("empty-then-padding", b"", padding), ("padding-then-empty", padding, b""),
             ("padding-then-other", padding, other), ("other-then-padding", other, padding)]
    sample = {"upstream": [1], "replies": [1, 2]}; changed = copy.deepcopy(sample); changed["replies"].pop()
    assert sample == copy.deepcopy(sample) and sample != changed
    report = {"reference": reference, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "injected_error": args.inject_error,
              "rounds": [], "failures": [], "calibration": {"equal": 1, "missing_recipient": 1, "coalesced_second": 1, "identical_retry": 1}}
    for address in ("127.0.0.1", "::1"):
        family = "v6" if ":" in address else "v4"; work = out / family; work.mkdir()
        for label, first, second in cases:
            case = work / label; case.mkdir()
            try:
                expected = run(args.c, first, second, address, case / "c")
                actual = run(args.rust, first, second, address, case / "rust")
                if args.inject_error and family == "v4" and label == "empty-then-padding": actual["replies"].pop()
                report["rounds"].append({"family": family, "case": label, "matches": expected == actual,
                                         "client_replies": len(expected["replies"]), "upstream_sends": len(expected["upstream"])})
            except Exception as error: report["failures"].append({"family": family, "case": label, "error": repr(error)})
            (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["mismatches"] = sum(not row["matches"] for row in report["rounds"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report)); return int(bool(report["mismatches"] or report["failures"]))


if __name__ == "__main__": raise SystemExit(main())
