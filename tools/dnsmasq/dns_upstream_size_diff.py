#!/usr/bin/env python3
"""Exact-daemon upstream UDP receive-boundary comparison in private netns.

The frozen corpus distinguishes valid large records, kernel receive clipping,
trailing bytes, complete/partial OPT and TC. Client responses compare as raw
bytes, including structurally incomplete TC responses from the C reference.
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

from dns_service_probe import name, read_name, semantics
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference

ROOT = Path(__file__).resolve().parents[2]
REPLY_WAIT = .30


def corpus(maximum):
    capacity = maximum + 255 + 10
    rows = [{"label": f"opaque-{size}", "kind": 65280, "size": size, "mode": "record", "tc": False}
            for size in [maximum-1, maximum, maximum+1, capacity-1, capacity, capacity+1, capacity+32]]
    rows += [{"label": f"txt-{size}", "kind": 16, "size": size, "mode": "record", "tc": False}
             for size in [maximum-1, capacity+1]]
    rows += [{"label": "standard-tc", "kind": 1, "size": None, "mode": "empty", "tc": True},
             {"label": "oversize-tc", "kind": 65280, "size": capacity+1, "mode": "record", "tc": True},
             {"label": "last-opt-clipped", "kind": 65280, "size": capacity+1, "mode": "last-opt", "tc": False},
             {"label": "last-opt-clipped-tc", "kind": 65280, "size": capacity+1, "mode": "last-opt", "tc": True},
             {"label": "opt-before-clipped-additional", "kind": 1, "size": capacity+1, "mode": "early-opt", "tc": False},
             {"label": "oversize-trailing-padding", "kind": 1, "size": capacity+32, "mode": "padding", "tc": False},
             {"label": "short-address", "kind": 1, "size": None, "mode": "short-a", "tc": False},
             {"label": "short-address-tc", "kind": 1, "size": None, "mode": "short-a", "tc": True}]
    return rows


def policy_corpus():
    labels = ["clipped-authority", "clipped-additional", "private-before-clipped",
              "bogus-before-clipped", "ignore-before-clipped", "private-clipped-tail",
              "bogus-clipped-tail", "ignore-clipped-tail", "cname-clipped-tail",
              "cname-to-private-before-clipped", "alias-to-private-before-clipped",
              "alias-to-public-before-clipped", "short-declared-public-trailing",
              "short-declared-private-trailing", "nxdomain-clipped-answer", "tc-clipped-answer"]
    return [{"label": label, "kind": 1, "mode": "policy"} for label in labels]


def query(case, ident):
    return (struct.pack("!6H", ident, 0x100, 1, 0, 0, 1) + name(case["label"] + ".test")
            + struct.pack("!HH", case["kind"], 1) + b"\0" + struct.pack("!HHIH", 41, 4096, 0x8000, 0))


def response(packet, case):
    _, end = read_name(packet, 12)
    question = packet[12:end+4]
    mode = case["mode"]
    if mode == "policy": return policy_response(packet[:2], question, case["label"])
    opt = b"\0" + struct.pack("!HHIH", 41, 4096, 0x8000, 0)
    flags = 0x8180 | (0x200 if case["tc"] else 0)
    answers = int(mode not in {"empty", "padding", "early-opt"})
    additional = 2 if mode == "early-opt" else int(mode == "last-opt")
    result = packet[:2] + struct.pack("!5H", flags, 1, answers, 0, additional) + question
    if mode == "empty": return result
    if mode == "padding": return result + bytes(case["size"] - len(result))
    if mode == "short-a": return result + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 53, 4) + bytes([192, 0, 2])
    if mode == "early-opt": result += opt
    size = case["size"] - len(result) - 12 - (len(opt) if mode == "last-opt" else 0)
    assert size >= 0
    if case["kind"] == 16:
        data = b""
        while len(data) < size:
            count = min(255, size - len(data) - 1); data += bytes([count]) + b"x" * count
    else: data = b"z" * size
    result += b"\xc0\x0c" + struct.pack("!HHIH", 65280 if mode == "early-opt" else case["kind"], 1, 53, len(data)) + data
    if mode == "last-opt": result += opt
    assert len(result) == case["size"]
    return result


def policy_response(ident, question, label):
    def rr(address, declared=4, owner=b"\xc0\x0c"):
        return owner + struct.pack("!HHIH", 1, 1, 53, declared) + socket.inet_aton(address)
    flags, answers, authority, additional = 0x8180, 1, 0, 0
    data = rr("8.8.8.8")
    if label == "clipped-authority": authority, data = 1, data + b"\0"
    elif label == "clipped-additional": additional, data = 1, data + b"\0"
    elif label.endswith("before-clipped"):
        address = {"private-before-clipped": "10.0.0.1", "bogus-before-clipped": "203.0.113.99",
                   "ignore-before-clipped": "198.51.100.77", "alias-to-private-before-clipped": "8.8.4.4",
                   "alias-to-public-before-clipped": "10.0.0.9"}.get(label, "10.0.0.1")
        answers, data = 2, rr(address) + b"\0"
        if label.startswith("cname-"):
            target = name("policy-target.test")
            cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 53, len(target)) + target
            answers, data = 3, cname + rr(address, owner=target) + b"\0"
    elif label.endswith("clipped-tail"):
        address = {"private-clipped-tail": "10.0.0.1", "bogus-clipped-tail": "203.0.113.99",
                   "ignore-clipped-tail": "198.51.100.77"}.get(label, "10.0.0.1")
        data = rr(address, declared=5)
        if label == "cname-clipped-tail":
            target = name("policy-target.test")
            data = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 53, len(target) + 1) + target
    elif label.startswith("short-declared-"):
        data = rr("10.0.0.1" if "private" in label else "8.8.8.8", declared=3)
    elif label == "nxdomain-clipped-answer": flags, data = 0x8183, data[:-1]
    elif label == "tc-clipped-answer": flags, data = 0x8380, data[:-1]
    else: raise AssertionError(label)
    return ident + struct.pack("!5H", flags, 1, answers, authority, additional) + question + data


class Upstream:
    def __init__(self, address, cases):
        self.socket = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, 0)); self.socket.settimeout(.03); self.port = self.socket.getsockname()[1]
        self.cases = {row["label"] + ".test": row for row in cases}
        self.events, self.errors = [], []; self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: packet, peer = self.socket.recvfrom(65535)
            except socket.timeout: continue
            try:
                host, _ = read_name(packet, 12); case = self.cases[host.lower()]
                semantic = semantics(packet); semantic["id"] = 0
                reply = response(packet, case)
                self.events.append({"case": case["label"], "query": semantic, "response": reply.hex(), "response_length": len(reply)})
                self.socket.sendto(reply, peer)
            except Exception as error: self.errors.append(repr(error))

    def close(self):
        self.stop.set(); self.thread.join(2); self.socket.close()
        assert not self.thread.is_alive()


def run(binary, config, port, address, cases, server, out):
    out.mkdir(); rows = []
    with (out / "stderr.log").open("wb") as log:
        process = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as client:
                for _ in range(100):
                    assert process.poll() is None, "daemon startup failed"
                    ready = struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + name("ready.test") + struct.pack("!HH", 1, 1)
                    client.sendto(ready, (address, port))
                    if receive(client, .03) is not None: break
                else: raise AssertionError("readiness timeout")
            for index, case in enumerate(cases):
                with socket.socket(family, socket.SOCK_DGRAM) as client:
                    request = query(case, 0x6200 + index)
                    begin = len(server.events); client.sendto(request, (address, port))
                    reply = receive(client, REPLY_WAIT)
                    events = copy.deepcopy(server.events[begin:])
                    assert len(events) == 1 and events[0]["case"] == case["label"], "upstream event count/name"
                    # Upstream transaction IDs are intentionally random. Keep
                    # the raw upstream reply privately, compare its body only.
                    upstream = {"query": events[0]["query"], "response_body": events[0]["response"][4:], "response_length": events[0]["response_length"]}
                    rows.append({"case": case["label"], "request": request.hex(), "reply": None if reply is None else reply.hex(), "upstream": upstream})
        finally:
            if process.poll() is None: process.send_signal(signal.SIGTERM)
            try: process.wait(3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(3)
            (out / "trace.json").write_text(json.dumps(rows, indent=2) + "\n")
    assert process.returncode == 0 and len(rows) == len(cases), "incomplete daemon run"
    return rows


def compare(expected, actual):
    if len(expected) != len(actual): raise ValueError("observation count mismatch")
    return [left["case"] for left, right in zip(expected, actual) if left != right]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--c", type=Path, required=True); p.add_argument("--c-identity", type=Path)
    p.add_argument("--rust", type=Path); p.add_argument("--output", type=Path, required=True)
    p.add_argument("--corpus", choices=["sizes", "policy"], default="sizes")
    args = p.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = verify_reference(args.c, args.c_identity)
    out = args.output.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists(); out.mkdir(parents=True)
    sample = [{"case": "calibration", "reply": "008180"}]
    assert not compare(sample, copy.deepcopy(sample))
    assert compare(sample, [{"case": "calibration", "reply": "008182"}]) == ["calibration"]
    try: compare(sample, [])
    except ValueError: pass
    else: raise AssertionError("count calibration")
    plan = {"corpus": args.corpus, "maximums": [512, 1232], "families": ["127.0.0.1", "::1"],
            "cases_per_round": 17 if args.corpus == "sizes" else 16,
            "reply_wait_seconds": REPLY_WAIT, "rounds": 1, "normalization": "random upstream ID only; exact client bytes, counts and event order"}
    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    report = {"reference": reference, "rust_sha256": None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "calibration": {"equal": 1, "changed_rcode": 1, "missing_observation": 1}, "rounds": [], "failures": []}
    for maximum in plan["maximums"]:
        cases = corpus(maximum) if args.corpus == "sizes" else policy_corpus()
        assert len(cases) == plan["cases_per_round"]
        for address in plan["families"]:
            label = f"{maximum}-{'v6' if ':' in address else 'v4'}"; work = out / label; work.mkdir()
            server = Upstream(address, cases)
            with socket.socket() as reserve: reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
            config = work / "dnsmasq.conf"
            config.write_text(f"no-hosts\nno-resolv\ncache-size=0\nlisten-address=127.0.0.1,::1\nport={port}\nedns-packet-max={maximum}\nhost-record=ready.test,192.0.2.254\nserver={address}#{server.port}\n")
            if args.corpus == "policy":
                with config.open("a") as stream:
                    stream.write("stop-dns-rebind\nbogus-nxdomain=203.0.113.99\nignore-address=198.51.100.77\nalias=8.8.4.4,10.0.0.1\nalias=10.0.0.9,8.8.8.8\n")
            try:
                expected = run(args.c, config, port, address, cases, server, work / "c")
                # Source-contract anchors prevent an all-timeout equality from
                # passing. Only the two configured ignore-address fixtures
                # deliberately have no client reply.
                ignored = {"ignore-before-clipped", "ignore-clipped-tail"}
                assert all((row["reply"] is not None) == (row["case"] not in ignored)
                           for row in expected), "C reference reply-count calibration"
                actual = run(args.rust, config, port, address, cases, server, work / "rust") if args.rust else None
                assert not server.errors, server.errors
                mismatches = compare(expected, actual) if actual is not None else []
                report["rounds"].append({"round": label, "planned": len(cases), "compared": len(cases) if actual is not None else 0,
                    "c_replies": sum(row["reply"] is not None for row in expected),
                    "rust_replies": None if actual is None else sum(row["reply"] is not None for row in actual), "mismatches": mismatches})
            except Exception as error: report["failures"].append({"round": label, "error": repr(error)})
            finally:
                server.close(); (work / "upstream.json").write_text(json.dumps(server.events, indent=2) + "\n")
                (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["mismatches"] = sum(len(row["mismatches"]) for row in report["rounds"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n"); print(json.dumps(report))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
