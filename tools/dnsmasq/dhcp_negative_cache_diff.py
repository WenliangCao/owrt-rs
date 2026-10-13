#!/usr/bin/env python3
"""Exact-image DHCP publication after a proved dynamic negative DNS cache hit.

Run with run_isolated.sh. Every case starts a fresh daemon/lease database, warms
A/AAAA/TXT over UDP/TCP, proves the cache with the upstream disabled, completes
real DHCP DISCOVER/REQUEST, then queries the published name over both transports.
Full packets, decoded responses, upstream transactions and DHCP ACKs are retained.
"""
import argparse
import copy
import itertools
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

from dhcp_lease_lifecycle import Daemon, rows
from dns_service_probe import exact_read, name, query, read_name, rr, semantics
from m2_rootfs import command, prepare, sha256

TTL = 3600
HOST = "client1.leases.test"
QTYPES = (1, 28, 16, 15, 6, 33, 5, 65401)


class Upstream:
    def __init__(self):
        self.events = []
        self.errors = []
        self.stop = threading.Event()
        self.enabled = True
        self.soa = False
        self.rcode = 3
        self.sockets = []
        self.threads = []
        for transport, kind in (("udp", socket.SOCK_DGRAM), ("tcp", socket.SOCK_STREAM)):
            sock = socket.socket(socket.AF_INET, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 15354))
            sock.settimeout(.1)
            if transport == "tcp":
                sock.listen()
            self.sockets.append(sock)
            thread = threading.Thread(target=self.run, args=(sock, transport))
            self.threads.append(thread)
            thread.start()

    def response(self, packet, transport):
        host, end = read_name(packet, 12)
        kind, cls = struct.unpack_from("!HH", packet, end)
        body = b""
        if self.soa:
            soa = name("ns.leases.test") + name("hostmaster.leases.test")
            soa += struct.pack("!5I", 1, 60, 60, 600, TTL)
            body = rr(6, soa, TTL, name("leases.test"))
        reply = packet[:2] + struct.pack("!5H", 0x8180 | self.rcode, 1, 0, int(self.soa), 0)
        reply += packet[12:end + 4] + body
        self.events.append({"transport": transport, "host": host, "type": kind,
                            "class": cls, "query": packet.hex(), "reply": reply.hex(),
                            "enabled": self.enabled})
        return reply if self.enabled else None

    def run(self, sock, transport):
        while not self.stop.is_set():
            try:
                if transport == "udp":
                    packet, peer = sock.recvfrom(65535)
                    reply = self.response(packet, transport)
                    if reply is not None:
                        sock.sendto(reply, peer)
                else:
                    connection, _ = sock.accept()
                    with connection:
                        connection.settimeout(.5)
                        while not self.stop.is_set():
                            packet = exact_read(connection, struct.unpack("!H", exact_read(connection, 2))[0])
                            reply = self.response(packet, transport)
                            if reply is not None:
                                connection.sendall(struct.pack("!H", len(reply)) + reply)
            except (socket.timeout, EOFError, ConnectionError):
                pass
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(2)
            assert not thread.is_alive()
        for sock in self.sockets:
            sock.close()
        assert not self.errors, self.errors


class ImageDaemon(Daemon):
    def __init__(self, root, binary, debug, output):
        super().__init__(binary, root / "m2/dns.conf", root / "m2/leases", output, [], binary)
        self.root = root
        self.debug = debug

    def start(self):
        self.starts += 1
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 68))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
        self.socket.settimeout(3)
        self.log = (self.folder / "daemon.log").open("wb")
        argv = command(self.root, self.binary, "-C", "/m2/dns.conf", "-d" if self.debug else "-k",
                       "--user=root", "--group=root", "--pid-file=", "--log-facility=-")
        (self.folder / "command.json").write_text(json.dumps(argv) + "\n")
        self.process = subprocess.Popen(argv, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 5
        while True:
            if self.process.poll() is not None:
                raise RuntimeError("daemon exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", 15353), .1):
                    return
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("startup timeout")
                time.sleep(.01)


def ask(host, kind, ident, transport):
    request = query(host, kind, ident)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(("127.0.0.1", 15353))
        if transport == "tcp":
            client.sendall(struct.pack("!H", len(request)) + request)
            packet = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
        else:
            client.send(request)
            packet = client.recv(65535)
    reply = semantics(packet)
    assert reply["id"] == ident
    return {"request": request.hex(), "packet": packet.hex(), "reply": reply,
            "started": started, "ended": time.monotonic()}


def run(root, binary, case, output, upstream):
    output.mkdir()
    result = {"events": [], "dhcp_checks": [], "dhcp_replies": [], "status": "failed"}
    daemon = ImageDaemon(root, binary, case["debug"], output)
    upstream.soa = case["soa"]
    upstream.rcode = case["rcode"]
    upstream.enabled = True
    first = len(upstream.events)
    (root / "m2/leases").write_bytes(b"")

    def dns(label, kind, transport, host=HOST):
        start = len(upstream.events)
        event = ask(host, kind, 0x5100 + len(result["events"]), transport)
        event.update(label=label, host=host, qtype=kind, transport=transport,
                     upstream=upstream.events[start:].copy(), alive=daemon.process.poll() is None)
        result["events"].append(event)
        return event

    try:
        daemon.start()
        cold = dns("cold-negative", case["warm_type"], case["warm_transport"])
        assert len(cold["upstream"]) == 1 and cold["reply"]["flags"] & 15 == case["rcode"]
        # Normal-mode TCP closes its child-to-parent cache transaction on EOF.
        # This barrier precedes DHCP and is never used to delay ACK visibility.
        if case["warm_transport"] == "tcp":
            time.sleep(.025)
        upstream.enabled = False
        for transport in ("udp", "tcp"):
            warm = dns("proved-negative-" + transport, case["warm_type"], transport)
            assert warm["reply"]["flags"] & 15 == case["rcode"] and not warm["upstream"]
        upstream.enabled = True
        daemon.exchange(1, address="127.0.0.10")
        daemon.exchange(3, address="127.0.0.10", selecting=True)
        # First post-ACK DNS query is immediate, with no sleep or polling.
        visible = dns("ack-visible-a", 1, "udp")
        assert visible["reply"]["flags"] & 15 == 0
        assert visible["reply"]["records"][0]["data"] == "127.0.0.10"
        # Observe forwarding rather than assuming every subsequent type hits.
        # A fresh NXDOMAIN also exposes known-local-name conversion on misses.
        upstream.rcode = 3
        for kind, transport in itertools.product(QTYPES, ("udp", "tcp")):
            dns(f"after-ack-{kind}-{transport}", kind, transport)
        dns("published-short-a", 1, "tcp", "client1")
        result["lease_rows"] = rows(daemon.leasefile)
        (output / "leases").write_bytes(daemon.leasefile.read_bytes())
        assert len(result["lease_rows"]) == 1 and result["lease_rows"][0]["name"] == "client1"
        daemon.stop()
        assert all(check["pass"] for check in daemon.checks), daemon.checks
        assert all(event["alive"] for event in result["events"])
        result["status"] = "passed"
    except Exception as error:
        result["error"] = repr(error)
    finally:
        daemon.stop()
        result["dhcp_checks"] = daemon.checks
        result["dhcp_replies"] = daemon.responses
        result["upstream"] = upstream.events[first:].copy()
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare(reference, actual):
    """Compare every decoded field; permit only clock-bounded dynamic SOA TTL age."""
    differences = []
    exact = aged = 0
    assert len(reference["events"]) == len(actual["events"])
    for left, right in zip(reference["events"], actual["events"]):
        expected, observed = copy.deepcopy(left["reply"]), copy.deepcopy(right["reply"])
        if expected == observed:
            exact += 1
        else:
            # Configured DHCP TTL must remain exact. Only cached SOA authority
            # ages can differ because independent daemons use wall-clock ticks.
            for c, rust in zip(expected["records"], observed["records"]):
                if c["section"] == rust["section"] == "authority" and c["type"] == rust["type"] == 6:
                    for event, record, result in ((left, c, reference), (right, rust, actual)):
                        elapsed = event["ended"] - result["events"][0]["started"]
                        assert TTL - int(elapsed) - 1 <= record["ttl"] <= TTL
                    if abs(c["ttl"] - rust["ttl"]) <= 1:
                        rust["ttl"] = c["ttl"]
            if expected == observed:
                aged += 1
            else:
                differences.append({"case": left["label"], "c": left, "rust": right})
        c_upstream = [(e["transport"], e["host"], e["type"], e["class"], e["enabled"]) for e in left["upstream"]]
        r_upstream = [(e["transport"], e["host"], e["type"], e["class"], e["enabled"]) for e in right["upstream"]]
        if c_upstream != r_upstream:
            differences.append({"case": left["label"] + "-upstream", "c": c_upstream, "rust": r_upstream})
    return {"exact_responses": exact, "clock_bounded_soa_responses": aged, "differences": differences}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    parser.add_argument("--nodata-controls", action="store_true",
                        help="also run A/AAAA NODATA controls; generic TXT NODATA is not cached by this image")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists()
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, out, args.rust)
    config = """no-resolv
no-hosts
listen-address=127.0.0.1
bind-interfaces
port=15353
no-ping
dhcp-authoritative
dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s
dhcp-leasefile=/m2/leases
domain=leases.test
local-ttl=17
dhcp-ttl=5
cache-size=32
neg-ttl=3600
server=127.0.0.1#15354
"""
    (root / "m2/dns.conf").write_text(config)
    summary = {"status": "failed", "identities": {"c": sha256(root / "usr/sbin/dnsmasq"),
               "rust": sha256(args.rust), "driver": sha256(__file__)},
               "helpers": {module: sha256(sys.modules[module].__file__) for module in
                           ("dhcp_lease_lifecycle", "dhcp_daemon_smoke", "dns_service_probe", "m2_rootfs")},
               "config": config, "runs": []}
    upstream = Upstream()
    try:
        for rcode, soa, debug, warm_type, warm_transport in itertools.product(
                (3, 0) if args.nodata_controls else (3,), (False, True), (False, True), (1, 28, 16), ("udp", "tcp")):
            if rcode == 0 and warm_type == 16:
                continue
            case = dict(rcode=rcode, soa=soa, debug=debug, warm_type=warm_type, warm_transport=warm_transport)
            label = f"rcode{rcode}-soa{int(soa)}-debug{int(debug)}-q{warm_type}-{warm_transport}"
            directory = out / label
            directory.mkdir()
            results = {side: run(root, side, case, directory / side, upstream) for side in ("c", "rust")}
            row = {"name": label, **case, "status": {side: result["status"] for side, result in results.items()}}
            if all(result["status"] == "passed" for result in results.values()):
                if args.inject_error and not summary["runs"]:
                    results["rust"]["events"][-1]["reply"]["flags"] ^= 1
                row.update(compare(results["c"], results["rust"]))
                row["post_ack_rcodes"] = {side: {event["label"]: event["reply"]["flags"] & 15
                                         for event in result["events"] if event["label"].startswith("after-ack-")}
                                         for side, result in results.items()}
                row["post_ack_upstream"] = {side: sum(len(event["upstream"]) for event in result["events"][3:])
                                           for side, result in results.items()}
            else:
                row["errors"] = {side: result.get("error") for side, result in results.items()}
            summary["runs"].append(row)
            (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
            print(json.dumps({"name": label, "status": row["status"], "differences": len(row.get("differences", [])), "errors": row.get("errors")}), flush=True)
        assert len(summary["runs"]) == (40 if args.nodata_controls else 24)
        summary["status"] = "passed" if all(all(value == "passed" for value in row["status"].values()) and not row.get("differences") for row in summary["runs"]) else "failed"
    finally:
        upstream.close()
        (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"status": summary["status"], "runs": len(summary["runs"])}))
    return int(summary["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
