#!/usr/bin/env python3
"""Actual isolated-daemon cache replay after clipped upstream DNS sections.

Each fixture uses a unique owner and target. Both requests finish within one
observed wall-clock second, keeping original and cache-hit TTLs comparable
without erasing TTL fields. Crossing a second is an infrastructure failure.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from cache_clipped_diff import fixtures
from dns_service_probe import name, read_name, semantics
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference

ROOT = Path(__file__).resolve().parents[2]


def cases():
    rows = []
    for label, _, _ in fixtures():
        host = label + ".test"
        for chosen, wire, kind in fixtures(host, "target." + host):
            if chosen == label:
                rows.append((label, host, wire, kind))
                break
    return rows


def query(host, kind, ident):
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack("!HH", kind, 1)


class Upstream:
    def __init__(self, address, rows):
        self.socket = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, 0)); self.socket.settimeout(.02)
        self.port = self.socket.getsockname()[1]
        self.replies = {host: wire for _, host, wire, _ in rows}
        self.events, self.errors = [], []
        self.stop = threading.Event(); self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: packet, peer = self.socket.recvfrom(65535)
            except socket.timeout: continue
            try:
                host, end = read_name(packet, 12); template = self.replies[host.lower()]
                _, qend = read_name(template, 12)
                reply = packet[:2] + template[2:12] + packet[12:end+4] + template[qend+4:]
                request = semantics(packet); request["id"] = 0
                self.events.append({"host": host.lower(), "query": request, "response_body": reply[2:].hex()})
                self.socket.sendto(reply, peer)
            except Exception as error: self.errors.append(repr(error))

    def close(self):
        self.stop.set(); self.thread.join(2); self.socket.close(); assert not self.thread.is_alive()


def observation(packet):
    if packet is None: return None
    try: return {"semantics": semantics(packet)}
    except (ValueError, IndexError, struct.error): return {"raw": packet.hex()}


def run(binary, config, port, address, rows, upstream, out):
    out.mkdir(); observed = []
    with (out / "stderr.log").open("wb") as log:
        daemon = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                for _ in range(100):
                    assert daemon.poll() is None, "startup failure"
                    client.sendto(query("ready.test", 1, 1), (address, port))
                    if receive(client, .03) is not None: break
                else: raise AssertionError("readiness timeout")
                for index, (label, host, _, kind) in enumerate(rows):
                    fraction = time.time() % 1
                    if fraction > .6: time.sleep(1.05 - fraction)
                    begin = int(time.time()); events = len(upstream.events); replies = []
                    for attempt in range(2):
                        client.sendto(query(host, kind, 0x5100 + index * 2 + attempt), (address, port))
                        reply = receive(client, .3)
                        assert reply is not None, f"missing client reply: {label}/{attempt}"
                        replies.append(observation(reply))
                    end = int(time.time())
                    assert begin == end, f"fixture crossed a wall-clock second: {label}"
                    observed.append({"case": label, "replies": replies,
                                     "upstream": copy.deepcopy(upstream.events[events:])})
        finally:
            if daemon.poll() is None: daemon.send_signal(signal.SIGTERM)
            try: daemon.wait(3)
            except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(3)
            (out / "trace.json").write_text(json.dumps(observed, indent=2) + "\n")
    assert daemon.returncode == 0 and len(observed) == len(rows)
    return observed


def compare(left, right):
    if len(left) != len(right): raise ValueError("observation count mismatch")
    return [a["case"] for a, b in zip(left, right) if a != b]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = verify_reference(args.c, None)
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists(); out.mkdir(parents=True)
    rows = cases(); assert len(rows) == 16
    plan = {"cases": [row[0] for row in rows], "families": ["127.0.0.1", "::1"], "queries_per_case": 2,
            "cache_capacity": 100, "neg_ttl": 30, "normalization": "upstream random ID and complete-packet DNS compression only; exact TTL/order/flags/errors; incomplete packets compare raw"}
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    sample = [{"case": "calibration", "upstream": [1]}]
    assert not compare(sample, copy.deepcopy(sample)) and compare(sample, [{"case": "calibration", "upstream": [1, 2]}])
    try: compare(sample, [])
    except ValueError: pass
    else: raise AssertionError("missing observation calibration")
    report = {"reference": reference, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "calibration": {"equal": 1, "extra_upstream_send": 1, "missing_observation": 1}, "rounds": [], "failures": []}
    for address in plan["families"]:
        family = "v6" if ":" in address else "v4"; work = out / family; work.mkdir()
        upstream = Upstream(address, rows)
        with socket.socket() as reserve: reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        config = work / "dnsmasq.conf"
        config.write_text(f"no-hosts\nno-resolv\nno-round-robin\ncache-size=100\nneg-ttl=30\nlisten-address=127.0.0.1,::1\nport={port}\nhost-record=ready.test,192.0.2.254\nserver={address}#{upstream.port}\n")
        try:
            expected = run(args.c, config, port, address, rows, upstream, work / "c")
            invalid = {"clipped-answer", "complete-answer-before-clipped-answer", "cname-before-clipped-answer"}
            assert all(len(row["upstream"]) == (2 if row["case"] in invalid else 1) for row in expected), "C cache-hit/miss calibration"
            actual = run(args.rust, config, port, address, rows, upstream, work / "rust")
            assert not upstream.errors, upstream.errors
            report["rounds"].append({"family": family, "cases": len(rows), "client_replies": len(rows) * 2,
                                     "c_upstream_queries": sum(len(row["upstream"]) for row in expected),
                                     "rust_upstream_queries": sum(len(row["upstream"]) for row in actual),
                                     "mismatches": compare(expected, actual)})
        except Exception as error: report["failures"].append({"family": family, "error": repr(error)})
        finally:
            upstream.close(); (work / "upstream.json").write_text(json.dumps(upstream.events, indent=2) + "\n")
            (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["mismatches"] = sum(len(row["mismatches"]) for row in report["rounds"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report)); return int(bool(report["mismatches"] or report["failures"]))


if __name__ == "__main__": raise SystemExit(main())
