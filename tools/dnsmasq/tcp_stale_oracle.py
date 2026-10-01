#!/usr/bin/env python3
"""Exact C -k stale TCP ownership oracle; run only through run_isolated.sh.

The upstream receives the refresh but cannot reply until the downstream EOF,
worker and parent-pipe observations have completed. All packet bytes and real
UBus calls are retained privately. This is a functionality gate, not a timer
or performance measurement. No Rust implementation generates expectations.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, query, read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
PROFILES = [
    {"name": "finite-success", "stale_seconds": 30, "wait": 2.2, "stale": True, "refresh": "reply"},
    {"name": "finite-refresh-eof", "stale_seconds": 30, "wait": 2.2, "stale": True, "refresh": "eof"},
    {"name": "forever-success", "stale_seconds": 0, "wait": 3.2, "stale": True, "refresh": "reply"},
    {"name": "finite-cutoff", "stale_seconds": 1, "wait": 3.2, "stale": False, "refresh": "reply"},
    {"name": "finite-empty-opt", "stale_seconds": 30, "wait": 2.2, "stale": True, "refresh": "reply", "empty_opt": True},
]


class Upstream:
    def __init__(self, profile):
        self.profile = profile
        self.stop = threading.Event()
        self.received = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
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

    def event(self, kind, **fields):
        with self.lock:
            self.events.append({"event": kind, **fields})

    def answer(self, packet, refreshed):
        _, end = read_name(packet, 12)
        return (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:end + 4]
                + rr(1, bytes([192, 0, 2, 2 if refreshed else 1]), 120 if refreshed else 1))

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                self.event("upstream-query", transport="udp", wire=packet.hex())
                reply = self.answer(packet, False)
                self.udp.sendto(reply, peer)
                self.event("upstream-reply", transport="udp", wire=reply.hex())
            except Exception as error:
                self.errors.append(repr(error))

    def connection(self, client):
        try:
            with client:
                client.settimeout(3)
                packet = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
                self.event("upstream-query", transport="tcp", wire=packet.hex())
                self.received.set()
                assert self.release.wait(8), "upstream release was never supplied"
                if self.profile["refresh"] == "eof":
                    self.event("upstream-eof", transport="tcp")
                else:
                    reply = self.answer(packet, True)
                    client.sendall(struct.pack("!H", len(reply)) + reply)
                    self.event("upstream-reply", transport="tcp", wire=reply.hex())
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
        self.release.set()
        for thread in self.threads + self.workers:
            thread.join(4)
        self.udp.close()
        self.tcp.close()
        assert not any(thread.is_alive() for thread in self.threads + self.workers), "upstream thread leak"


class Product(Fixture):
    def __init__(self, args, out, profile):
        super().__init__(args, out)
        self.upstream.close()
        self.upstream = Upstream(profile)
        self.profile = profile

    def start_product(self):
        config = self.out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "server=127.0.0.1#15354\ncache-size=32\n"
                          f"use-stale-cache={self.profile['stale_seconds']}\nenable-ubus={OBJECT}\n")
        binary = self.args.reference_build / "dnsmasq/dnsmasq"
        self.daemon, _ = self.spawn([str(binary), "-k", "-C", str(config), "--user=root", "--group=root",
                                     "--log-facility=-", "--pid-file=" + str(self.out / "pid")], "daemon")
        self.wait_registered()

    def wait_metric(self, key, expected):
        deadline = time.monotonic() + 3
        while True:
            result = self.metrics()
            if result[key] == expected:
                return result
            assert self.daemon.poll() is None and time.monotonic() < deadline, (key, expected, result)
            time.sleep(.005)

    def children_and_pipes(self):
        parent = Path(f"/proc/{self.daemon.pid}")
        children = (parent / f"task/{self.daemon.pid}/children").read_text().split()
        pipes, pipe_fds = {}, {}
        for pid in [str(self.daemon.pid), *children]:
            pipe_fds[pid] = []
            for fd in Path(f"/proc/{pid}/fd").iterdir():
                target = fd.readlink().as_posix()
                if target.startswith("pipe:"):
                    info = Path(f"/proc/{pid}/fdinfo/{fd.name}").read_text().splitlines()
                    mode = int(next(line.split()[1] for line in info if line.startswith("flags:")), 8) & os.O_ACCMODE
                    pipe_fds[pid].append({"fd": int(fd.name), "target": target, "mode": mode})
            pipes[pid] = sorted({fd["target"] for fd in pipe_fds[pid]})
        parent_pipes = set(pipes[str(self.daemon.pid)])
        new_parent_readers = {fd["target"] for fd in pipe_fds[str(self.daemon.pid)] if fd["mode"] == os.O_RDONLY}
        new_parent_readers -= getattr(self, "initial_pipes", set())
        return {"children": children, "pipes": pipes, "pipe_fds": pipe_fds,
                "parent_child_shared_pipes": {pid: sorted(parent_pipes.intersection(pipes[pid])) for pid in children},
                "writeback_pipes": {pid: sorted(new_parent_readers.intersection(
                    fd["target"] for fd in pipe_fds[pid] if fd["mode"] == os.O_WRONLY)) for pid in children}}


def run_profile(args, out, profile):
    out.mkdir()
    fixture = Product(args, out, profile)
    rows, clients = [], []
    trace = {"profile": profile, "rows": rows}
    try:
        fixture.start_bus()
        fixture.start_product()
        baseline = fixture.metrics()
        initial_resources = fixture.children_and_pipes()
        fixture.initial_pipes = set(initial_resources["pipes"][str(fixture.daemon.pid)])

        def receive(client):
            return exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])

        def record(label, request=None, packet=None):
            row = {"label": label, "metrics": fixture.metrics()}
            if packet is not None:
                assert request[:2] == packet[:2]
                row.update(request=request.hex(), wire=packet.hex(), response=semantics(packet))
            rows.append(row)
            return row

        def ask(label, client=None):
            request = make_query()
            if client is None:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(3)
                    udp.sendto(request, LISTEN)
                    packet = udp.recv(65535)
            else:
                client.sendall(struct.pack("!H", len(request)) + request)
                packet = receive(client)
            return record(label, request, packet)

        def make_query():
            request = query("stale.test", ident=0x5100 + len(rows))
            if profile.get("empty_opt"):
                request = request[:10] + b"\0\1" + request[12:] + b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
            return request

        def connect(expected):
            client = socket.create_connection(LISTEN, 3)
            client.settimeout(3)
            clients.append(client)
            fixture.wait_metric("tcp_connections", expected)
            return client

        trace["baseline_metrics"] = baseline
        trace["baseline_resources"] = initial_resources
        ask("parent-udp-seed")
        old = connect(1)
        ask("old-tcp-fresh", old)
        time.sleep(profile["wait"])
        ask("old-tcp-after-wall-expiry", old)
        later = connect(2)
        request = make_query()
        later.sendall(struct.pack("!H", len(request)) + request)
        assert fixture.upstream.received.wait(3), "new connection did not start upstream TCP query"
        if profile["stale"]:
            record("new-tcp-stale", request, receive(later))
            eof = later.recv(1)
            fixture.upstream.event("downstream-eof", wire=eof.hex())
            assert eof == b"", "expected EOF immediately after one stale reply"
        else:
            later.settimeout(.15)
            try:
                before_release = later.recv(1)
            except socket.timeout:
                before_release = None
            later.settimeout(3)
            record("new-tcp-miss-blocked")["received_before_release"] = before_release
            assert before_release is None, "retention-cutoff miss unexpectedly replied before upstream release"
        assert not fixture.upstream.release.is_set()
        held = record("refresh-held")
        held["resources"] = fixture.children_and_pipes()
        held["release_set"] = fixture.upstream.release.is_set()
        fixture.upstream.event("upstream-release")
        fixture.upstream.release.set()
        if profile["stale"]:
            fixture.wait_metric("tcp_connections", 1)
        else:
            record("new-tcp-refreshed", request, receive(later))
        if profile["refresh"] == "reply":
            fixture.wait_metric("dns_cache_inserted", 2)
        record("refresh-finished")
        if profile["refresh"] == "reply":
            ask("parent-udp-writeback")
            if not profile["stale"]:
                ask("new-tcp-cache-hit", later)
        for client in clients:
            client.close()
        clients.clear()
        fixture.wait_metric("tcp_connections", 0)
        closed = record("all-clients-closed")
        closed["resources"] = fixture.children_and_pipes()
        assert not fixture.upstream.errors, fixture.upstream.errors
        return trace
    finally:
        for client in clients:
            client.close()
        fixture.stop(fixture.daemon)
        fixture.stop(fixture.bus)
        fixture.upstream.close()
        trace.update(raw_ubus=fixture.raw, fixture_checks=fixture.checks,
                     upstream=fixture.upstream.events, upstream_errors=fixture.upstream.errors)
        (out / "trace.json").write_text(json.dumps(trace, indent=2) + "\n")


def calibrate(trace, inject_error=False):
    profile = trace["profile"]
    rows = {row["label"]: row for row in trace["rows"]}
    checks = []

    def check(label, actual, expected):
        checks.append({"case": profile["name"] + "/" + label, "actual": actual,
                       "expected": expected, "pass": actual == expected})

    def packet(label, ttl, address):
        response = rows[label]["response"]
        check(label + "-flags", response["flags"], 0x8180)
        # The synthetic seed server returns no OPT; a locally cached response
        # adds an OPT for this query, including EDE only on stale delivery.
        opt = bool(profile.get("empty_opt")) and label != "parent-udp-seed"
        check(label + "-counts", list(struct.unpack_from("!4H", bytes.fromhex(rows[label]["wire"]), 4)), [1, 1, 0, int(opt)])
        check(label + "-ttl", response["records"][0]["ttl"], ttl)
        check(label + "-address", response["records"][0]["data"], address)

    check("row-count", len(rows), 10 if profile["name"] == "finite-cutoff" else 8 if profile["refresh"] == "reply" else 7)
    packet("parent-udp-seed", 1, "192.0.2.1")
    fresh_ttl = rows["old-tcp-fresh"]["response"]["records"][0]["ttl"]
    check("accepted-before-stale", fresh_ttl in (0, 1), True)
    packet("old-tcp-after-wall-expiry", fresh_ttl, "192.0.2.1")
    if profile["stale"]:
        packet("new-tcp-stale", 1 if inject_error else 0, "192.0.2.1")
        if profile.get("empty_opt"):
            check("stale-empty-opt-ede3", rows["new-tcp-stale"]["response"]["records"][1],
                  {"section": "additional", "name": "", "type": 41, "class": 1232, "ttl": 0, "data": "000f00020003"})
    else:
        check("miss-waits-for-release", rows["new-tcp-miss-blocked"]["received_before_release"], None)
        packet("new-tcp-refreshed", 120, "192.0.2.2")
    events = trace["upstream"]
    queries = [row["transport"] for row in events if row["event"] == "upstream-query"]
    check("exactly-one-seed-and-one-refresh", queries, ["udp", "tcp"])
    kinds = [row["event"] for row in events]
    if profile["stale"]:
        check("downstream-eof-before-release", kinds.index("downstream-eof") < kinds.index("upstream-release"), True)
    terminal = "upstream-eof" if profile["refresh"] == "eof" else "upstream-reply"
    check("upstream-result-after-release", kinds.index("upstream-release") < max(i for i, k in enumerate(kinds) if k == terminal), True)
    held = rows["refresh-held"]
    check("gate-held", held["release_set"], False)
    check("slot-held-after-downstream-eof", held["metrics"]["tcp_connections"], 2)
    check("both-workers-present", len(held["resources"]["children"]), 2)
    check("both-parent-writeback-pipes-present", [len(p) for p in held["resources"]["writeback_pipes"].values()], [1, 1])
    check("parent-no-writeback-before-release", held["metrics"]["dns_cache_inserted"], 1)
    finished = rows["refresh-finished"]["metrics"]
    check("slot-after-refresh", finished["tcp_connections"], 1 if profile["stale"] else 2)
    check("insertions-after-refresh", finished["dns_cache_inserted"], 2 if profile["refresh"] == "reply" else 1)
    # These are parent counters from real UBus; child-local hit/stale counters
    # are not merged by C's cache transaction channel.
    check("parent-forwarded-counter", finished["dns_queries_forwarded"], 1)
    check("parent-stale-counter", finished["dns_stale_answered"], 0)
    check("parent-local-counter", finished["dns_local_answered"], 0)
    if profile["refresh"] == "reply":
        reply = rows["parent-udp-writeback"]["response"]
        check("parent-refreshed-address", reply["records"][0]["data"], "192.0.2.2")
        check("parent-refreshed-ttl-positive", 0 < reply["records"][0]["ttl"] <= 120, True)
    closed = rows["all-clients-closed"]
    check("all-slots-released", closed["metrics"]["tcp_connections"], 0)
    check("all-workers-reaped", closed["resources"]["children"], [])
    check("upstream-no-errors", trace["upstream_errors"], [])
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
    identity = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out.mkdir(parents=True)
    report = {"scope": "exact native C -k stale TCP functional baseline; no Rust/performance acceptance",
              "reference": identity, "tool_sha256": digest(Path(__file__)), "checks": [], "failures": [],
              "inject_error": args.inject_error, "profiles": []}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run"], check=True)
    Path(BUS).parent.mkdir(parents=True)
    try:
        for profile in PROFILES:
            trace = run_profile(args, out / profile["name"], profile)
            report["checks"] += calibrate(trace, args.inject_error and profile["name"] == "finite-success")
            report["profiles"].append({**profile, "observations": len(trace["rows"]),
                                       "trace_sha256": digest(out / profile["name"] / "trace.json")})
    except Exception as error:
        report["failures"].append(repr(error))
    finally:
        subprocess.run(["umount", "/run"], check=True)
    report["passed"] = sum(row["pass"] for row in report["checks"])
    report["failed"] = sum(not row["pass"] for row in report["checks"]) + len(report["failures"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
