#!/usr/bin/env python3
"""Real C/Rust forwarded UDP policy gate in a private network namespace.

Compares bytes, upstream query semantics and counts. Covers known-name
NXDOMAIN, advertised size, EDE and client-size truncation; not full cache policy.
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
from dns_udp_refusal_diff import verify_reference


def query(host, kind, cls, flags, ident, advertised):
    packet = struct.pack("!6H", ident, flags, 1, 0, 0, int(advertised is not None)) + name(host) + struct.pack("!HH", kind, cls)
    if advertised is not None:
        packet += b"\0" + struct.pack("!HHIH", 41, advertised, 0x8000, 0)
    return packet


def rr(kind, data, owner=b"\xc0\x0c"):
    return owner + struct.pack("!HHIH", kind, 1, 41, len(data)) + data


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0)); self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.events, self.failures = [], []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: packet, peer = self.socket.recvfrom(65535)
            except socket.timeout: continue
            try:
                parsed = semantics(packet); parsed["id"] = 0
                self.events.append(parsed)
                host, end = read_name(packet, 12)
                qflags = struct.unpack_from("!H", packet, 2)[0]
                flags, body, answers, opt_ttl = 0x80b3 | (qflags & 0x100), b"", 0, 0x8000
                if host == "public.test":
                    flags &= ~15; body = rr(1, bytes([192, 0, 2, 7])); answers = 1
                elif host == "rebind.test":
                    flags &= ~15; body = rr(1, bytes([10, 0, 0, 7])); answers = 1
                elif host == "malformed.test":
                    flags &= ~15; body = rr(5, b"\xff\xff"); answers = 1
                elif host == "large.test":
                    flags &= ~15; body = rr(16, (b"\xff" + b"x" * 255) * 3); answers = 1
                elif host == "extended.known.test":
                    opt_ttl |= 1 << 24
                response = packet[:2] + struct.pack("!5H", flags, 1, answers, 0, 1) + packet[12:end+4] + body
                response += b"\0" + struct.pack("!HHIH", 41, 4096, opt_ttl, 0)
                self.socket.sendto(response, peer)
            except Exception as error:
                self.failures.append(repr(error))

    def close(self):
        self.stop.set(); self.thread.join(timeout=2); self.socket.close()
        assert not self.thread.is_alive(), "upstream thread leaked"


def corpus():
    cases = [("host.known.test", 28, 1), ("host.known.test", 16, 1),
             ("known.test", 28, 1), ("files.known.test", 65400, 1),
             ("txt.known.test", 1, 1), ("literal.test", 16, 1),
             ("upstream.test", 1, 1), ("unknown.test", 1, 1),
             ("host.known.test", 65400, 3), ("public.test", 1, 1),
             ("rebind.test", 1, 1), ("malformed.test", 1, 1),
             ("large.test", 16, 1), ("extended.known.test", 28, 1)]
    return [(host, kind, cls, flags, maximum)
            for host, kind, cls in cases for flags in (0x100, 0x130) for maximum in (None, 512, 1232)]


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("completed reply count mismatch")
    return [left["case"] for left, right in zip(expected, actual) if left != right]


def run(binary, config, port, work, upstream):
    work.mkdir()
    rows = []
    with (work / "stderr.log").open("wb") as log:
        process = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(.1)
                ready = query("ready.test", 1, 1, 0x100, 1, None)
                for _ in range(100):
                    assert process.poll() is None, "daemon exited"
                    client.sendto(ready, ("127.0.0.1", port))
                    try: client.recv(65535); break
                    except socket.timeout: time.sleep(.01)
                else: raise RuntimeError("readiness timeout")
                client.settimeout(2)
                for index, (host, kind, cls, flags, maximum) in enumerate(corpus()):
                    request = query(host, kind, cls, flags, 0x4000 + index, maximum)
                    start = len(upstream.events)
                    client.sendto(request, ("127.0.0.1", port))
                    response = client.recv(65535)
                    rows.append({"case": index, "request": request.hex(), "response": response.hex(),
                                 "upstream": copy.deepcopy(upstream.events[start:])})
                    assert response[:2] == request[:2], "client ID changed"
        finally:
            process.send_signal(signal.SIGTERM); process.wait(timeout=3)
            (work / "trace.json").write_text(json.dumps(rows, indent=2) + "\n")
            (work / "process.json").write_text(json.dumps({"exit":process.returncode,"completed":len(rows)}) + "\n")
    assert len(rows) == 84 and process.returncode == 0
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    identity = verify_reference(args.c, args.c_identity)
    output = args.output.resolve()
    assert "private" in output.parts and not output.exists()
    output.mkdir(parents=True)
    sample = [{"case":0,"response":"good"}]
    assert compare(sample, copy.deepcopy(sample)) == []
    assert compare(sample, [{"case":0,"response":"changed"}]) == [0]
    try:
        compare(sample, [])
    except ValueError:
        pass
    else:
        raise AssertionError("count calibration failed")
    hosts = output / "hosts"; hosts.write_text("192.0.2.8 files.known.test\n")
    upstream = Upstream()
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
    config = output / "dnsmasq.conf"
    config.write_text(f"no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\ncache-size=0\nlocal-ttl=37\nedns-packet-max=1232\nstop-dns-rebind\nserver=127.0.0.1#{upstream.port}\nhost-record=host.known.test,192.0.2.7\nhost-record=extended.known.test,192.0.2.9\ntxt-record=txt.known.test,value\naddress=/literal.test/192.0.2.10\nserver=/upstream.test/127.0.0.1#{upstream.port}\naddn-hosts={hosts}\n")
    report = {"planned":84,"compared":0,"matched":0,"unexecuted":84,"failures":[],
              "calibration":{"equal":1,"deliberate_mismatches":2},"reference":identity,
              "rust_sha256":hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "scope":"forwarded UDP caller policy/bytes/upstream queries; no binding-policy or general EDNS cacheability equivalence"}
    try:
        expected = run(args.c, config, port, output / "c", upstream)
        actual = run(args.rust, config, port, output / "rust", upstream)
        assert not upstream.failures
        failures = compare(expected, actual)
        report.update(compared=84,matched=84-len(failures),unexecuted=0,failures=failures)
    except Exception as error:
        report["failures"].append({"infrastructure_or_protocol":repr(error)})
    finally:
        upstream.close()
    (output / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
