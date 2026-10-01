#!/usr/bin/env python3
"""Isolated UDP pending-reply effects after an independent query warms cache.

Hold a cold A reply, warm that owner through a CNAME, verify the old hit, then
release the held policy/malformed reply. Compare later A/AAAA replies and actual
upstream sends against exact C. No CD/OPT query is used to bypass the cache.
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
import time

import cache_answer_diff as base
from cache_policy_transaction_diff import fixtures
from cache_clipped_service_diff import observation, query
from dns_service_probe import semantics
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference

ROOT = Path(__file__).resolve().parents[2]


def selected():
    labels = {"replacement-before-clipped", "clipped-before-replacement",
              "unrelated-owner-before-clipped", "unrelated-type-before-clipped",
              "cname-before-clipped", "old-rrset-before-clipped",
              "cname-target-before-clipped", "rebind-first", "public-before-rebind",
              "rebind-before-clipped", "cname-before-rebind", "bogus-before-clipped",
              "public-before-bogus", "bogus-target-after-cname",
              "doctor-rebind-first", "doctor-rebind-after-public",
              "doctor-unblocks-before-clipped", "doctor-bogus-before-clipped",
              "zero-ttl-before-clipped", "cname-invalid-target", "bogus-no-negcache"}
    rows = [row for row in fixtures() if row["label"] in labels]
    assert len(rows) == len(labels)
    return rows


def run(binary, case, address, out):
    out.mkdir(); trace = {"replies": [], "upstream": []}
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as upstream, socket.socket(family, socket.SOCK_DGRAM) as client:
        upstream.bind((address, 0)); upstream.settimeout(.5)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        config = out / "dnsmasq.conf"
        config.write_text(f"no-hosts\nno-resolv\nno-round-robin\ncache-size=100\nneg-ttl=30\n"
                          f"listen-address=127.0.0.1,::1\nport={port}\nhost-record=ready.test,192.0.2.254\n"
                          f"server={address}#{upstream.getsockname()[1]}\n" + case["config"])
        def send(owner, kind, ident): client.sendto(query(owner, kind, ident), (address, port))
        def upstream_query(stage):
            packet, peer = upstream.recvfrom(65535)
            decoded = semantics(packet); decoded["id"] = 0
            trace["upstream"].append({"stage": stage, "query": decoded})
            return packet, peer
        def reply(stage, ident):
            packet = receive(client, .5)
            assert packet is not None and int.from_bytes(packet[:2], "big") == ident, stage
            trace["replies"].append({"stage": stage, **observation(packet)})
        def complete_lookup(stage, kind, ident):
            send("replace.test", kind, ident)
            ready = select.select([client, upstream], [], [], .5)[0]
            assert ready, stage
            if upstream in ready:
                packet, peer = upstream_query(stage)
                data = bytes([8, 8, 4, 5]) if kind == 1 else bytes.fromhex("20014860000000000000000000008888")
                answer = base.packet("replace.test", kind, 0x8180, [("replace.test", kind, 53, data)])
                upstream.sendto(packet[:2] + answer[2:], peer)
            reply(stage, ident)
        with (out / "stderr.log").open("wb") as log:
            daemon = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    assert daemon.poll() is None, "startup failure"
                    send("ready.test", 1, 1)
                    if receive(client, .03) is not None: break
                else: raise AssertionError("readiness timeout")
                fraction = time.time() % 1
                if fraction > .35: time.sleep(1.03 - fraction)
                begin = int(time.time())
                send("replace.test", 1, 0x5101)
                pending, peer = upstream_query("held-cold-query")
                send("seed.test", 1, 0x5102)
                seed, seed_peer = upstream_query("seed-through-cname")
                warm = bytearray(base.packet("seed.test", 1, 0x8180,
                                              [("seed.test", 5, 53, base.name("replace.test"))]))
                count = int.from_bytes(case["old"][6:8], "big")
                warm[6:8] = struct.pack("!H", count + 1)
                warm.extend(case["old"][len(base.packet("replace.test", 1)):])
                upstream.sendto(seed[:2] + warm[2:], seed_peer)
                reply("seed-reply", 0x5102)
                send("replace.test", 1, 0x5103)
                reply("preexisting-hit", 0x5103)
                assert not select.select([upstream], [], [], 0)[0], "preexisting hit unexpectedly forwarded"
                upstream.sendto(pending[:2] + case["new"][2:], peer)
                reply("held-completion", 0x5101)
                complete_lookup("after-a", 1, 0x5104)
                complete_lookup("after-aaaa", 28, 0x5105)
                assert int(time.time()) == begin, "case crossed a wall-clock second"
                assert not select.select([upstream], [], [], 0)[0], "unexpected extra upstream query"
            finally:
                if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
                try: daemon.wait(3)
                except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(3)
                (out / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
            assert daemon.returncode == 0
    return trace


def differences(left, right):
    return [key for key in ("replies", "upstream") if left[key] != right[key]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = verify_reference(args.c, None)
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists(); out.mkdir(parents=True)
    rows = selected(); plan = {"cases": [row["label"] for row in rows], "families": ["127.0.0.1", "::1"],
        "replies_per_case": 5, "cache_capacity": 100, "normalization": "upstream random ID and DNS compression; exact TTL/order/flags/addresses"}
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    sample = {"replies": [1], "upstream": [1]}; changed = copy.deepcopy(sample); changed["upstream"].append(2)
    assert not differences(sample, sample) and differences(sample, changed) == ["upstream"]
    report = {"reference": reference, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "rounds": [], "failures": [], "injected_error": args.inject_error}
    for address in plan["families"]:
        family = "v6" if ":" in address else "v4"; work = out / family; work.mkdir()
        for case in rows:
            path = work / case["label"]; path.mkdir()
            try:
                expected = run(args.c, case, address, path / "c")
                stages = [row["stage"] for row in expected["upstream"]]
                if case["label"] == "replacement-before-clipped": assert "after-a" in stages
                if case["label"] in ("clipped-before-replacement", "rebind-first", "zero-ttl-before-clipped", "bogus-before-clipped"):
                    assert "after-a" not in stages
                if case["label"] == "bogus-before-clipped": assert "after-aaaa" not in stages
                actual = run(args.rust, case, address, path / "rust")
                if args.inject_error and family == "v4" and case["label"] == "replacement-before-clipped":
                    actual["upstream"].append({"stage": "injected-extra-send"})
                report["rounds"].append({"family": family, "case": case["label"], "client_replies": len(expected["replies"]),
                    "c_upstream": len(expected["upstream"]), "rust_upstream": len(actual["upstream"]), "differences": differences(expected, actual)})
            except Exception as error: report["failures"].append({"family": family, "case": case["label"], "error": repr(error)})
            (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["mismatches"] = sum(bool(row["differences"]) for row in report["rounds"])
    report["calibration"] = {"equal": 1, "extra_upstream": 1, "reference_hit_miss": 1, "preexisting_hit": 1}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report)); return int(bool(report["mismatches"] or report["failures"]))


if __name__ == "__main__": raise SystemExit(main())
