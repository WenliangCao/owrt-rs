#!/usr/bin/env python3
"""Isolated stale-answer/refresh service differential against exact C.

The upstream is advanced explicitly: seed TTL=1, wait past expiry, retain the
refresh, query from a second client, release the new data and check that it is
cached without sending a second reply to already-answered clients. Raw packets,
configuration, observation timing and failures stay in private/. No performance
conclusion follows from these deliberate waits.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import time

from dns_service_probe import name, query, read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference

LISTEN = ("127.0.0.1", 19353)
UPSTREAM = ("127.0.0.1", 19354)


def response(request, scenario, generation):
    _, end = read_name(request, 12)
    question = request[12:end + 4]
    ttl = 1 if generation == 0 else 120
    kind = 28 if scenario == "aaaa" else 1
    host = "alias.test" if scenario == "cname" else "stale.test"
    records = b""
    count = 0
    if scenario != "negative" or generation:
        if scenario == "cname":
            records += rr(5, name("target.test"), ttl)
            count += 1
        address = (f"2001:db8::{7 + generation}" if kind == 28 else f"192.0.2.{7 + generation}")
        records += rr(kind, ipaddress.ip_address(address).packed, ttl,
                      name("target.test") if scenario == "cname" else name(host))
        count += 1
    flags = 0x8183 if scenario == "negative" and generation == 0 else 0x8180
    return request[:2] + struct.pack("!5H", flags, 1, count, 0, 0) + question + records


def receive(sock, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recvfrom(65535)
    except socket.timeout:
        return None


def run(binary, scenario, config, folder):
    folder.mkdir()
    trace = {"status": "failed", "events": [], "upstream": [], "packets": []}
    def save_packet(direction, packet):
        trace["packets"].append({"direction": direction, "packet": packet.hex()})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
         (folder / "daemon.log").open("wb") as log:
        upstream.bind(UPSTREAM)
        first.bind(("127.0.0.1", 0)); second.bind(("127.0.0.1", 0))
        process = subprocess.Popen([str(binary), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "daemon exited before readiness"
                try:
                    with socket.create_connection(LISTEN, .05):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("startup timeout")
                    time.sleep(.01)
            host = "alias.test" if scenario == "cname" else "stale.test"
            kind = 28 if scenario == "aaaa" else 1
            def send(client, ident):
                packet = query(host, kind, ident)
                save_packet("client-query", packet)
                client.sendto(packet, LISTEN)
            def incoming(label, timeout=.4):
                received = receive(upstream, timeout)
                trace["events"].append({"case": label, "forwarded": received is not None})
                if received:
                    packet, peer = received
                    save_packet("upstream-query", packet)
                    parsed = semantics(packet); parsed["id"] = 0
                    trace["upstream"].append(parsed)
                    return packet, peer
                return None
            def send_upstream(received, generation):
                if received:
                    packet, peer = received
                    reply = response(packet, scenario, generation)
                    save_packet("upstream-response", reply)
                    upstream.sendto(reply, peer)
            def downstream(client, label, timeout=1, fresh_since=None):
                received = receive(client, timeout)
                row = {"case": label, "reply": None}
                if received:
                    packet, peer = received
                    assert peer == LISTEN, "wrong listener address"
                    save_packet("client-response", packet)
                    row["reply"] = semantics(packet)
                    if fresh_since is not None:
                        elapsed = time.monotonic() - fresh_since
                        for record in row["reply"]["records"]:
                            assert 120 - math.ceil(elapsed) - 1 <= record["ttl"] <= 120, "fresh TTL outside clock interval"
                        row["fresh_elapsed"] = elapsed
                trace["events"].append(row)
            send(first, 0x7100)
            seed = incoming("seed-forward")
            assert seed is not None, "positive forwarding calibration failed"
            send_upstream(seed, 0)
            downstream(first, "seed-reply")
            assert trace["events"][-1]["reply"] is not None, "seed reply missing"
            # Expiry/stale marking are second-granularity in C; 3 s is strictly
            # past the one-second TTL even at either wall-clock phase.
            time.sleep(3)
            send(first, 0x7101)
            downstream(first, "stale-first")
            pending = incoming("refresh-forward")
            send(second, 0x7102)
            downstream(second, "stale-second")
            extra = incoming("refresh-coalesced", .15)
            refreshed = time.monotonic()
            send_upstream(pending, 1)
            send_upstream(extra, 1)
            downstream(first, "no-second-reply-first", .2)
            downstream(second, "no-second-reply-second", .2)
            send(first, 0x7103)
            downstream(first, "refreshed-answer", fresh_since=refreshed if pending else None)
            incoming("refreshed-answer-not-forwarded", .15)
            process.send_signal(signal.SIGTERM)
            trace["exit"] = process.wait(5)
            assert trace["exit"] == 0
            trace["status"] = "passed"
        except Exception as error:
            trace["error"] = repr(error)
        finally:
            if process.poll() is None:
                process.kill(); process.wait(5)
            trace["reaped"] = process.poll() is not None
            (folder / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")
    return trace


def normalized(trace):
    result = copy.deepcopy(trace)
    result.pop("packets")
    for row in result["events"]:
        if "fresh_elapsed" in row:
            del row["fresh_elapsed"]
            for record in row["reply"]["records"]:
                record["ttl"] = {"initial": 120, "elapsed_checked": True}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-baseline", type=Path, help="reuse matching archived C observations")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert [name for _, name in socket.if_nameindex()] == ["lo"]
    out = args.out.resolve(); assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    verify_reference(args.c.resolve(), None)
    baseline = args.c_baseline.resolve() if args.c_baseline else None
    if baseline:
        old = json.loads((baseline / "result.json").read_text())
        assert old["identity"]["c"] == hashlib.sha256(args.c.read_bytes()).hexdigest()
        assert not old["failures"], "cannot reuse an incomplete C baseline"
    report = {"status": "failed", "cases": 0, "compared": 0, "mismatches": [], "failures": [],
              "identity": {key: hashlib.sha256(path.read_bytes()).hexdigest()
                           for key in ("c", "rust") if (path := getattr(args, key)) is not None}}
    for scenario in ("a", "aaaa", "cname", "negative"):
        work = out / scenario; work.mkdir()
        config = work / "dnsmasq.conf"
        config.write_text(f"no-resolv\nno-hosts\nlisten-address={LISTEN[0]}\nport={LISTEN[1]}\n"
                          f"server={UPSTREAM[0]}#{UPSTREAM[1]}\ncache-size=32\nneg-ttl=1\nuse-stale-cache=30\n")
        if baseline:
            assert (baseline / scenario / "dnsmasq.conf").read_bytes() == config.read_bytes()
            shutil.copytree(baseline / scenario / "c", work / "c")
            c = json.loads((work / "c/trace.json").read_text())
        else:
            c = run(args.c.resolve(), scenario, config, work / "c")
        report["cases"] += 1
        if c["status"] != "passed":
            report["failures"].append({"case": scenario, "side": "c", "error": c.get("error")})
        else:
            assert len(c["events"]) == 10
            assert c["events"][3] == {"case": "refresh-forward", "forwarded": True}
            assert c["events"][6]["reply"] is None and c["events"][7]["reply"] is None
            for row in c["events"][2:5:2]:
                assert row["reply"] is not None
                assert all(record["ttl"] == 0 for record in row["reply"]["records"])
        if args.rust:
            rust = run(args.rust.resolve(), scenario, config, work / "rust")
            if rust["status"] != "passed":
                report["failures"].append({"case": scenario, "side": "rust", "error": rust.get("error")})
            left, right = normalized(c), normalized(rust)
            if len(left["events"]) == len(right["events"]):
                for i, (expected, actual) in enumerate(zip(left["events"], right["events"], strict=True)):
                    report["compared"] += 1
                    if expected != actual:
                        report["mismatches"].append({"case": scenario, "step": i, "c": expected, "rust": actual})
            else:
                report["failures"].append({"case": scenario, "error": "observation count differs"})
            if left["upstream"] != right["upstream"]:
                report["mismatches"].append({"case": scenario, "step": "upstream-trace", "c": left["upstream"], "rust": right["upstream"]})
            report["compared"] += 1
    # Calibrate a real semantic difference, preserving the untouched C trace.
    changed = normalized(c); changed["events"][3]["forwarded"] = False
    assert changed != normalized(c)
    report["calibration"] = {"missing_refresh_detected": 1, "known_stale_and_no_second_reply": 1}
    if args.rust and not report["failures"]:
        assert report["compared"] == 11 * report["cases"], "counter calibration failed"
    report["matched"] = report["compared"] - len(report["mismatches"])
    report["comparison_boundary"] = "ten ordered events and one complete upstream trace per scenario"
    report["c_baseline"] = str(baseline) if baseline else None
    report["tool_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["status"] = "passed" if not report["mismatches"] and not report["failures"] else "failed"
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value if key not in ("mismatches", "failures") else len(value)
                      for key, value in report.items()}))
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
