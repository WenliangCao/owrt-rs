#!/usr/bin/env python3
"""C-first -k TCP ordinary CD prefix effects and independent bogus transaction.

DO forces a query past an unsigned IN A/AAAA cache entry; it is not a no_cache
packet bit. SERVFAIL inspection replies neither heal a miss nor start ordinary
extraction. All daemon and UBus execution requires run_isolated.sh.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, query, read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
PROFILES = [
    {"name": "a-request-cd", "kind": 1, "request_cd": True, "raw_cd": False, "capacity": 8},
    {"name": "aaaa-request-and-raw-cd", "kind": 28, "request_cd": True, "raw_cd": True, "capacity": 8},
    {"name": "plain-request-raw-cd", "kind": 1, "request_cd": False, "raw_cd": True, "capacity": 8, "cold": True},
    {"name": "a-cd-pressure", "kind": 1, "request_cd": True, "raw_cd": False, "capacity": 3, "pressure": True},
    {"name": "a-bogus-cd-no-negcache", "kind": 1, "request_cd": True, "raw_cd": False, "capacity": 8, "bogus": True},
]


def address(kind, value):
    return f"192.0.2.{value}" if kind == 1 else f"2001:db8::{value:x}"


def request(host, kind, ident, cd=False, do=False):
    packet = bytearray(query(host, kind, ident))
    struct.pack_into("!H", packet, 2, 0x100 | (0x10 if cd else 0))
    if do:
        struct.pack_into("!H", packet, 10, 1)
        packet += b"\0" + struct.pack("!HHIH", 41, 1232, 0x8000, 0)
    return bytes(packet)


def answer(packet, plan):
    host, end = read_name(packet, 12)
    kind = struct.unpack_from("!H", packet, end)[0]
    records = []
    target = plan.get("target")
    if target:
        records.append(rr(5, name(target), 120, name(host)))
    for value in plan.get("values", []):
        records.append(rr(kind, ipaddress.ip_address(address(kind, value)).packed, 120, name(target or host)))
    flags = 0x8180 | plan.get("rcode", 0) | (0x10 if plan.get("raw_cd") else 0)
    return packet[:2] + struct.pack("!5H", flags, 1, len(records), 0, 0) + packet[12:end + 4] + b"".join(records)


class Upstream:
    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.plan = {"rcode": 2}
        self.events, self.errors, self.workers = [], [], []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for sock in (self.udp, self.tcp):
            sock.bind(("127.0.0.1", 15354))
            sock.settimeout(.1)
        self.tcp.listen()
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:
            thread.start()

    def arm(self, stage, plan):
        with self.lock:
            self.plan = {"stage": stage, **plan}
            return len(self.events)

    def response(self, packet, transport):
        with self.lock:
            plan = self.plan.copy()
            reply = answer(packet, plan)
            self.events.append({"stage": plan["stage"], "transport": transport,
                                "query": packet.hex(), "reply": reply.hex()})
            return reply

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                self.udp.sendto(self.response(packet, "udp"), peer)
            except Exception as error:
                self.errors.append(repr(error))

    def connection(self, client):
        try:
            with client:
                client.settimeout(.1)
                while not self.stop.is_set():
                    try:
                        prefix = exact_read(client, 2)
                    except socket.timeout:
                        continue
                    except ConnectionError:
                        break
                    packet = exact_read(client, struct.unpack("!H", prefix)[0])
                    reply = self.response(packet, "tcp")
                    client.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception as error:
            self.errors.append(repr(error))

    def tcp_loop(self):
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            worker = threading.Thread(target=self.connection, args=(client,))
            self.workers.append(worker)
            worker.start()

    def close(self):
        self.stop.set()
        for thread in self.threads + self.workers:
            thread.join(3)
        self.udp.close()
        self.tcp.close()
        assert not any(thread.is_alive() for thread in self.threads + self.workers), "upstream thread leak"


class Product(Fixture):
    def __init__(self, args, out, profile, binary):
        super().__init__(args, out)
        self.upstream.close()
        self.upstream = Upstream()
        self.profile, self.binary = profile, binary

    def start_product(self):
        config = self.out / "dnsmasq.conf"
        extra = "bogus-nxdomain=192.0.2.66\nno-negcache\n" if self.profile.get("bogus") else ""
        config.write_text("no-hosts\nno-resolv\nno-0x20-encode\nno-round-robin\n"
                          "listen-address=127.0.0.1\nport=15353\nserver=127.0.0.1#15354\n"
                          f"cache-size={self.profile['capacity']}\nenable-ubus={OBJECT}\n" + extra)
        command = [str(self.binary), "-k", "-C", str(config)]
        if self.binary == self.args.reference_build / "dnsmasq/dnsmasq":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(self.out / "pid")]
        self.daemon, _ = self.spawn(command, "daemon")
        self.wait_registered()

    def wait_metric(self, key, expected):
        deadline = time.monotonic() + 3
        while True:
            result = self.metrics()
            if result[key] == expected:
                return result
            assert self.daemon.poll() is None and time.monotonic() < deadline, (key, expected, result)
            time.sleep(.005)


def run_profile(args, out, profile, binary):
    out.mkdir()
    fixture = Product(args, out, profile, binary)
    rows, client = [], None
    trace = {"profile": profile, "rows": rows}
    try:
        fixture.start_bus()
        fixture.start_product()
        rows.append({"stage": "initial", "metrics": fixture.metrics()})
        client = socket.create_connection(LISTEN, 3)
        client.settimeout(3)
        fixture.wait_metric("tcp_connections", 1)

        def ask(stage, host, tcp=True, kind=None, cd=False, do=False, plan=None, inserted=None):
            first = fixture.upstream.arm(stage, plan if plan is not None else {"rcode": 2})
            packet = request(host, kind or profile["kind"], 0x5200 + len(rows), cd, do)
            if tcp:
                client.sendall(struct.pack("!H", len(packet)) + packet)
                reply = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(3)
                    udp.sendto(packet, LISTEN)
                    reply = udp.recv(65535)
            assert packet[:2] == reply[:2], (stage, "transaction ID mismatch")
            metrics = fixture.wait_metric("dns_cache_inserted", inserted) if inserted is not None else fixture.metrics()
            row = {"stage": stage, "request": packet.hex(), "wire": reply.hex(), "response": semantics(reply),
                   "upstream": copy.deepcopy(fixture.upstream.events[first:]), "metrics": metrics}
            rows.append(row)
            return row

        if profile.get("cold"):
            ask("plain-raw-cd-fill", "owner.test", plan={"values": [21], "raw_cd": True}, inserted=1)
            ask("child-owner", "owner.test")
            ask("parent-owner", "owner.test", tcp=False)
        else:
            ask("warm-child-alias", "alias.test", plan={"values": [11], "target": "owner.test"}, inserted=2)
            count = 2
            if profile.get("pressure"):
                count += 1
                ask("fill-child-capacity", "filler.test", plan={"values": [55]}, inserted=count)
            ask("old-child-owner", "owner.test")
            ask("old-child-alias", "alias.test")
            values = [66] if profile.get("bogus") else [21, 22] if profile.get("pressure") else [21]
            if profile.get("bogus"):
                count += 1
            ask("forced-cd-reply", "owner.test", cd=profile["request_cd"], do=True,
                plan={"values": values, "raw_cd": profile["raw_cd"]}, inserted=count)
            ask("child-alias-cname-before-reset", "alias.test", kind=5)
            ask("child-owner-after-prefix", "owner.test")
            if profile.get("pressure"):
                ask("child-filler-after-prefix", "filler.test")
            ask("parent-owner-after-prefix", "owner.test", tcp=False)
            ask("parent-alias-after-prefix", "alias.test", tcp=False)
            if profile.get("bogus"):
                # A newly inserted NXDOMAIN may coexist with the old positive
                # A. AAAA has no positive record and exposes that transaction.
                ask("child-bogus-negative-aaaa", "owner.test", kind=28)
                ask("parent-bogus-negative-aaaa", "owner.test", kind=28, tcp=False)
            if profile.get("pressure"):
                ask("parent-filler-after-prefix", "filler.test", tcp=False)
            if not profile.get("bogus"):
                ask("child-alias-cname-after-servfail", "alias.test", kind=5)
                ask("empty-cd-reset", "empty.test", cd=True, plan={"values": []})
                ask("child-alias-cname-after-reset", "alias.test", kind=5)
                ask("child-owner-after-reset", "owner.test")
                ask("parent-owner-after-reset", "owner.test", tcp=False)
        client.close()
        client = None
        closed = fixture.wait_metric("tcp_connections", 0)
        children = Path(f"/proc/{fixture.daemon.pid}/task/{fixture.daemon.pid}/children").read_text().split()
        rows.append({"stage": "closed", "metrics": closed, "children": children})
        assert not fixture.upstream.errors, fixture.upstream.errors
        return trace
    finally:
        if client:
            client.close()
        fixture.stop(fixture.daemon)
        fixture.stop(fixture.bus)
        fixture.upstream.close()
        trace.update(fixture_checks=fixture.checks, raw_ubus=fixture.raw,
                     upstream=fixture.upstream.events, upstream_errors=fixture.upstream.errors)
        (out / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")


def calibrate(trace, inject_error=False):
    profile = trace["profile"]
    rows = {row["stage"]: row for row in trace["rows"]}
    checks = []

    def check(stage, actual, expected):
        checks.append({"case": profile["name"] + "/" + stage, "actual": actual, "expected": expected, "pass": actual == expected})

    def hit(stage, value=None, rcode=0):
        row = rows[stage]
        check(stage + "/no-upstream", row["upstream"], [])
        check(stage + "/rcode", row["response"]["flags"] & 15, rcode)
        if value is not None:
            check(stage + "/address", row["response"]["records"][-1]["data"], address(profile["kind"], value))

    def miss(stage):
        row = rows[stage]
        check(stage + "/one-upstream", len(row["upstream"]), 1)
        check(stage + "/servfail", row["response"]["flags"] & 15, 2)

    if profile.get("cold"):
        check("plain-request-no-OPT", struct.unpack_from("!H", bytes.fromhex(rows["plain-raw-cd-fill"]["request"]), 10)[0], 0)
        check("raw-cd-fill/response-cd-cleared", rows["plain-raw-cd-fill"]["response"]["flags"] & 0x10, 0)
        check("raw-cd-fill/inserted", rows["plain-raw-cd-fill"]["metrics"]["dns_cache_inserted"], 1)
        hit("child-owner", 21)
        hit("parent-owner", 21)
        expected_count = 5
    else:
        hit("old-child-owner", 11)
        hit("old-child-alias", 11)
        held = rows["forced-cd-reply"]
        check("DO-forces-forward", len(held["upstream"]), 1)
        check("request-CD-restored", held["response"]["flags"] & 0x10, 0x10)
        check("forwarded-full-flags", held["response"]["flags"], 0x8193 if profile.get("bogus") else 0x8190)
        expected_inserted = 3 if profile.get("pressure") or profile.get("bogus") else 2
        check("prefix-parent-insertions", held["metrics"]["dns_cache_inserted"], expected_inserted + int(inject_error))
        check("parent-no-child-eviction-count", held["metrics"]["dns_cache_live_freed"], 0)
        check("alias-CNAME-pending-visible", rows["child-alias-cname-before-reset"]["upstream"], [])
        if profile.get("bogus"):
            check("bogus-reply-NXDOMAIN", held["response"]["flags"] & 15, 3)
            hit("child-owner-after-prefix", 11)
            hit("parent-owner-after-prefix", 11)
            hit("parent-alias-after-prefix", 11)
            hit("child-bogus-negative-aaaa", rcode=3)
            hit("parent-bogus-negative-aaaa", rcode=3)
            expected_count = 12
        else:
            miss("child-owner-after-prefix")
            hit("parent-owner-after-prefix", 11)
            hit("parent-alias-after-prefix", 11)
            check("SERVFAIL-does-not-clear-pending", rows["child-alias-cname-after-servfail"]["upstream"], [])
            check("empty-CD-clears-without-commit", rows["empty-cd-reset"]["metrics"]["dns_cache_inserted"], expected_inserted)
            miss("child-alias-cname-after-reset")
            miss("child-owner-after-reset")
            hit("parent-owner-after-reset", 11)
            expected_count = 15
            if profile.get("pressure"):
                miss("child-filler-after-prefix")
                hit("parent-filler-after-prefix", 55)
                expected_count += 3
    check("observation-count", len(rows), expected_count)
    check("all-slots-released", rows["closed"]["metrics"]["tcp_connections"], 0)
    check("all-workers-reaped", rows["closed"]["children"], [])
    check("no-upstream-errors", trace["upstream_errors"], [])
    check("fixture-checks", all(row["pass"] for row in trace["fixture_checks"]), True)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    out = args.out.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [n for _, n in socket.if_nameindex()] == ["lo"]
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    binary = args.reference_build / "dnsmasq/dnsmasq"
    identity = verify_reference(binary, None)
    out.mkdir(parents=True)
    report = {"scope": "C-only real -k ordinary CD prefix and independent bogus transaction",
              "reference": identity, "tool_sha256": digest(Path(__file__)), "checks": [], "failures": [], "profiles": []}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run"], check=True)
    Path(BUS).parent.mkdir(parents=True)
    try:
        for profile in PROFILES:
            try:
                trace = run_profile(args, out / profile["name"], profile, binary)
                report["checks"] += calibrate(trace, args.inject_error and profile["name"] == "a-request-cd")
                report["profiles"].append({**profile, "observations": len(trace["rows"]),
                                           "trace_sha256": digest(out / profile["name"] / "trace.json")})
            except Exception as error:
                report["failures"].append({"profile": profile["name"], "error": repr(error)})
    finally:
        subprocess.run(["umount", "/run"], check=True)
    report["passed"] = sum(row["pass"] for row in report["checks"])
    report["failed"] = sum(not row["pass"] for row in report["checks"]) + len(report["failures"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
