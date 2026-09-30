#!/usr/bin/env python3
"""Real exact-C/Rust UDP no-route replies in a loopback-only Linux namespace."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
C_HASH = "bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def name(host):
    return b"".join(bytes([len(label)]) + label.encode() for label in host.split(".")) + b"\0"


def question_end(packet):
    pos = 12
    while packet[pos]:
        assert packet[pos] < 64
        pos += packet[pos] + 1
    return pos + 5


def query(host, kind, cls, flags, ident, opt=None):
    packet = struct.pack("!6H", ident, flags, 1, 0, 0, int(opt is not None))
    packet += name(host) + struct.pack("!HH", kind, cls)
    if opt is not None:
        size, do = opt
        packet += b"\0" + struct.pack("!HHIH", 41, size, 0x8000 if do else 0, 0)
    return packet


def corpus():
    rows = []
    flags = [rd | cd | ad for rd in [0, 0x100] for cd in [0, 0x10] for ad in [0, 0x20]]
    for bits in flags:
        for kind, cls in [(1, 1), (28, 1), (65280, 1), (1, 3), (65280, 65535)]:
            for opt in [None, (1232, False), (1232, True)]:
                label = f"flags-{bits:x}-type-{kind}-class-{cls}-opt-{opt}"
                rows.append((label, query("missing.test", kind, cls, bits, 0x4000 + len(rows), opt)))
    for size in [0, 1, 511, 512, 4096, 65535]:
        for do in [False, True]:
            rows.append((f"edns-{size}-do-{do}", query("missing.test", 1, 1, 0x130, 0x4000 + len(rows), (size, do))))
    for bits in [0x760, 0x143]:  # AA/TC/Z and nonzero request RCODE.
        rows.append((f"extra-flags-{bits:x}", query("missing.test", 65280, 1, bits, 0x4000 + len(rows), (1232, True))))
    return rows


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(.05)
        self.port = self.socket.getsockname()[1]
        self.events = []
        self.errors = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                end = question_end(packet)
                kind, cls = struct.unpack_from("!HH", packet, end - 4)
                self.events.append({"question": packet[12:end].hex(), "kind": kind, "class": cls})
                data = bytes([203, 0, 113, 17]) if kind == 1 else bytes.fromhex("20010db8000000000000000000000017") if kind == 28 else b"opaque"
                flags = 0x8080 | (struct.unpack_from("!H", packet, 2)[0] & 0x110)
                response = packet[:2] + struct.pack("!5H", flags, 1, 1, 0, 0) + packet[12:end]
                response += b"\xc0\x0c" + struct.pack("!HHIH", kind, cls, 42, len(data)) + data
                self.socket.sendto(response, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stopped.set()
        self.thread.join(2)
        self.socket.close()
        assert not self.thread.is_alive() and not self.errors, self.errors


def exchange(port, ip, packet):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.connect((ip, port))
        client.send(packet)
        return client.recv(65535)


def run(binary, side, out, maximum, rows, upstream, with_upstream=True):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    service_label = f"{maximum}-{side}" if with_upstream else f"empty-{maximum}-{side}"
    config = out / f"{service_label}.conf"
    config.write_text(f"port={port}\nno-resolv\nno-hosts\ncache-size=0\nno-0x20-encode\n"
                      f"listen-address=127.0.0.1,::1\nedns-packet-max={maximum}\n"
                      "host-record=ready.test,192.0.2.1\n" +
                      (f"server=/forward.test/127.0.0.1#{upstream.port}\n" if with_upstream else ""))
    results, wires = [], []
    with (out / f"{service_label}.log").open("wb") as log:
        process = subprocess.Popen([str(binary), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            ready = query("ready.test", 1, 1, 0x100, 0x1000)
            for _ in range(100):
                assert process.poll() is None, "daemon exited during startup"
                try:
                    packet = exchange(port, "127.0.0.1", ready)
                    assert struct.unpack_from("!H", packet, 6)[0] == 1
                    break
                except OSError:
                    time.sleep(.01)
            else:
                raise AssertionError("readiness timeout")
            for ip in ["127.0.0.1", "::1"]:
                before_no_route = len(upstream.events)
                for label, request in rows:
                    response = exchange(port, ip, request)
                    actual = struct.unpack_from("!6H", response)
                    assert actual[0] == struct.unpack_from("!H", request)[0]
                    assert actual[1] & 15 == 5 and actual[2:5] == (1, 0, 0), label
                    assert response[12:question_end(response)] == request[12:question_end(request)], label
                    results.append({"case": label, "family": ip, "reply": response.hex()})
                    wires.append({"case": label, "request": request.hex(), "reply": response.hex()})
                assert len(upstream.events) == before_no_route, "no-route reply contacted an upstream"
                if not with_upstream:
                    continue
                before = len(upstream.events)
                for kind, cls in [(1, 1), (28, 1), (65280, 1), (1, 3)]:
                    request = query("via.forward.test", kind, cls, 0x100, 0x7000 + len(results))
                    response = exchange(port, ip, request)
                    header = struct.unpack_from("!6H", response)
                    assert header[1] & 15 == 0 and header[3] == 1, "configured upstream lost"
                    label = f"upstream-type-{kind}-class-{cls}"
                    results.append({"case": label, "family": ip, "reply": response.hex()})
                    wires.append({"case": label, "request": request.hex(), "reply": response.hex()})
                assert len(upstream.events) - before == 4, "upstream count calibration"
        finally:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            wire_path = out / f"{service_label}.wire.json"
            assert not wire_path.exists(), "wire evidence path collision"
            wire_path.write_text(json.dumps(wires, indent=2) + "\n")
    assert process.returncode == 0, "daemon did not exit cleanly"
    return results


def compare(c, rust):
    assert len(c) == len(rust), "reply count mismatch"
    return [c[index]["case"] + "/" + c[index]["family"] for index in range(len(c)) if c[index] != rust[index]]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    assert digest(args.c) == C_HASH, "exact reference ELF changed"
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    sample = [{"case": "calibration", "family": "ipv4", "reply": "00058185"}]
    assert compare(sample, sample) == []
    assert compare(sample, [dict(sample[0], reply="00058183")]) == ["calibration/ipv4"]
    try:
        compare(sample, [])
    except AssertionError:
        pass
    else:
        raise AssertionError("count calibration failed")
    source_paths = [ROOT / "components/dnsmasq/src/dns" / filename
                    for filename in ["daemon.rs", "tcp_service.rs", "reply.rs", "wire.rs"]]
    source_paths.append(Path(__file__))
    report = {"c_sha256": digest(args.c), "rust_sha256": digest(args.rust) if args.rust else None,
              "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in source_paths} if args.rust else {},
              "calibration": {"positive": 1, "negative": 2}, "rounds": [], "failures": []}
    rows = corpus()
    upstream = Upstream()
    try:
        empty_rows = [("empty-a", query("unowned.test", 1, 1, 0x100, 0x8100)),
                      ("empty-unknown-edns", query("unowned.test", 65280, 1, 0x130, 0x8101, (512, True))),
                      ("empty-non-in", query("unowned.test", 28, 3, 0x110, 0x8102))]
        for maximum, planned, with_upstream in [(512, rows, True), (1232, rows, True), (1232, empty_rows, False)]:
            c_start = len(upstream.events)
            c = run(args.c, "c", out, maximum, planned, upstream, with_upstream)
            c_events = upstream.events[c_start:]
            rust = None
            if args.rust:
                r_start = len(upstream.events)
                rust = run(args.rust, "rust", out, maximum, planned, upstream, with_upstream)
                assert upstream.events[r_start:] == c_events, "upstream side effects differ"
            mismatch = compare(c, rust) if rust is not None else []
            report["rounds"].append({"edns_max": maximum, "queries_per_side": len(c),
                                     "scoped_upstream_configured": with_upstream,
                                     "compared": rust is not None, "mismatches": mismatch})
            assert not mismatch, mismatch
    except Exception as error:
        report["failures"].append(repr(error))
        raise
    finally:
        try:
            upstream.close()
        except Exception as error:
            report["failures"].append("upstream cleanup: " + repr(error))
        (out / "upstream.json").write_text(json.dumps(upstream.events, indent=2) + "\n")
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    assert not report["failures"], report["failures"]
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
