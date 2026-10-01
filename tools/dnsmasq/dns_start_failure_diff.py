#!/usr/bin/env python3
"""Real isolated-daemon initial upstream send/socket failures and metrics.

Only loopback exists. Nonlocal documentation/benchmark destinations have no
route; strace must observe ENETUNREACH. RLIMIT_NOFILE is lowered only after
startup/readiness, and socket EMFILE must be observed. Raw evidence stays private.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import signal
import socket
import struct
import subprocess
import time

import cache_answer_diff as base
from cache_clipped_service_diff import observation
from dns_service_probe import read_name, semantics
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import Fixture, BUS, OBJECT

ROOT = Path(__file__).resolve().parents[2]
VARIANTS = [("plain", 0x100, None, 0), ("cd", 0x110, None, 0),
            ("ad", 0x120, None, 0), ("empty-opt", 0x100, 1232, 0),
            ("do-opt", 0x100, 1232, 0x8000), ("small-opt", 0, 0, 0)]


def query(host, ident, flags=0x100, advertised=None, metadata=0):
    packet = struct.pack("!6H", ident, flags, 1, 0, 0, int(advertised is not None)) + base.name(host) + struct.pack("!HH", 1, 1)
    return packet + (b"\0" + struct.pack("!HHIH", 41, advertised, metadata, 0) if advertised is not None else b"")


def tracee(parent):
    children = Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
    assert len(children) == 1, children
    return int(children[0])


def run(f, binary, profile, out):
    out.mkdir(); observed = {}; upstream_events = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as duplicate:
        upstream.bind(("127.0.0.1", 0)); upstream.settimeout(.5)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
        reachable = f"127.0.0.1#{upstream.getsockname()[1]}"
        servers = "" if profile == "no-server" else f"server={reachable}\n"
        if profile in ("no-route4", "pending"):
            servers = "server=198.18.0.53#53000\n"
        if profile == "no-route6": servers = "server=2001:db8::53#53000\n"
        if profile == "mixed": servers += "server=198.18.0.53#53000\nall-servers\n"
        if profile == "pending": servers += f"server=/healthy.test/{reachable}\n"
        config = out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nno-round-robin\ncache-size=20\ndns-forward-max=1\n"
                          f"listen-address=127.0.0.1\nport={port}\n"
                          f"host-record=ready.test,192.0.2.254\nenable-ubus={OBJECT}\n"
                          + ("use-stale-cache=60\n" if profile == "stale-fd" else "") + servers)
        command = ["strace", "-f", "-qq", "-s", "100", "-e", "trace=network,close,poll,ppoll", "-o", str(out / "syscalls.log"),
                   str(binary.resolve()), "-d", "-C", str(config)]
        if binary.resolve() == (f.args.reference_build / "dnsmasq/dnsmasq").resolve():
            command += ["--user=root", "--group=root"]
        f.daemon, _ = f.spawn(command, profile)
        pid = None; original_limit = None
        def send(wire, sock=client): sock.sendto(wire, ("127.0.0.1", port))
        def answer_upstream(ttl=53):
            packet, peer = upstream.recvfrom(65535)
            host, _ = read_name(packet, 12)
            decoded = semantics(packet); decoded["id"] = 0; upstream_events.append(decoded)
            reply = base.packet(host, 1, 0x8180, [(host, 1, ttl, bytes([8, 8, 4, 4]))])
            upstream.sendto(packet[:2] + reply[2:], peer)
        def record(label, sock=client):
            wire = receive(sock, .25)
            observed[label] = {"reply": observation(wire), "metrics": f.metrics()}
            return wire
        try:
            f.wait_registered(); pid = tracee(f.daemon.pid)
            uid = next(line for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("Uid:"))
            assert uid.split()[1:] == ["0"] * 4, "both isolated daemons must have identical root credentials"
            send(query("ready.test", 1)); assert receive(client, .5) is not None
            observed["initial"] = f.metrics()
            assert f.daemon.poll() is None and Path(f"/proc/{pid}/fd").exists()
            if profile == "stale-fd":
                send(query("stale.test", 0x5001)); answer_upstream(1); assert record("seed") is not None
                time.sleep(2.1)
            if profile == "pending":
                send(query("healthy.test", 0x5001)); pending, pending_peer = upstream.recvfrom(65535)
                decoded = semantics(pending); decoded["id"] = 0; upstream_events.append(decoded)
                send(query("healthy.test", 0x5002), duplicate)
                assert receive(upstream, .05) is None, "healthy duplicate did not coalesce"
                observed["pending-before"] = f.metrics()
            if profile in ("fd-full", "stale-fd"):
                original_limit = resource.prlimit(pid, resource.RLIMIT_NOFILE)
                opened = sorted(int(path.name) for path in Path(f"/proc/{pid}/fd").iterdir())
                limit = next(fd for fd in range(max(opened) + 2) if fd not in opened)
                assert limit >= 4, "cannot exhaust descriptor allocation without constraining poll"
                # Equal resource boundary: zero allocatable descriptor slots.
                # Keep poll's nfds limit usable; RLIMIT=0 also breaks poll.
                (out / "fd-limit.json").write_text(json.dumps({"open": opened, "soft": limit, "headroom": 0}) + "\n")
                resource.prlimit(pid, resource.RLIMIT_NOFILE, (limit, original_limit[1]))
                assert resource.prlimit(pid, resource.RLIMIT_NOFILE)[0] == limit
            variants = VARIANTS if profile not in ("mixed", "stale-fd") else [VARIANTS[0], VARIANTS[3]]
            if profile == "stale-fd": variants = [VARIANTS[3]]
            for index, (label, flags, advertised, metadata) in enumerate(variants):
                host = "stale.test" if profile == "stale-fd" else f"q{index}.test"
                send(query(host, 0x5100 + index, flags, advertised, metadata))
                if profile == "mixed": answer_upstream()
                record(label)
                if profile == "stale-fd":
                    assert receive(client, .2) is None, "refresh failure sent an extra reply"
                    observed["after-refresh"] = f.metrics()
            if original_limit is not None:
                resource.prlimit(pid, resource.RLIMIT_NOFILE, original_limit); original_limit = None
                send(query("recovered.test", 0x5200)); answer_upstream(); assert record("recovered") is not None
            if profile == "pending":
                reply = base.packet("healthy.test", 1, 0x8180, [("healthy.test", 1, 53, bytes([8, 8, 4, 4]))])
                upstream.sendto(pending[:2] + reply[2:], pending_peer)
                assert record("pending-original") is not None
                assert record("pending-duplicate", duplicate) is not None
            observed["upstream"] = upstream_events
        finally:
            if pid and Path(f"/proc/{pid}").exists():
                if original_limit is not None: resource.prlimit(pid, resource.RLIMIT_NOFILE, original_limit)
                os.kill(pid, signal.SIGTERM)
            try: f.daemon.wait(3)
            except subprocess.TimeoutExpired: f.daemon.kill(); f.daemon.wait(3)
            observed["closed"] = pid is not None and not Path(f"/proc/{pid}").exists()
            (out / "observed.json").write_text(json.dumps(observed, indent=2) + "\n")
        assert observed["closed"] and f.daemon.returncode == 0, "daemon resources did not close normally"
        syscalls = (out / "syscalls.log").read_text()
        errors = {name: syscalls.count(name) for name in ("ENETUNREACH", "EMFILE", "EINVAL")}
        pending_calls = {}; calls = []
        for line in syscalls.splitlines():
            match = re.match(r"(\d+)\s+(.*)", line)
            if not match: continue
            thread, call = match.groups()
            if call.endswith("<unfinished ...>"):
                pending_calls[thread] = call.removesuffix("<unfinished ...>")
                continue
            resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", call)
            if resumed: call = pending_calls.pop(thread, "") + resumed.group(1)
            calls.append(call)
        errors["udp_socket_emfile"] = sum(bool(re.match(r"socket\(AF_INET6?, SOCK_DGRAM.*= -1 EMFILE", call)) for call in calls)
        (out / "error-coverage.json").write_text(json.dumps(errors, indent=2) + "\n")
        if profile in ("no-route4", "no-route6", "pending", "mixed"): assert errors["ENETUNREACH"] > 0, "no send error coverage"
        if profile in ("fd-full", "stale-fd"):
            assert errors["udp_socket_emfile"] >= len(variants), "not every query reached UDP socket exhaustion"
            assert errors["EINVAL"] == 0, "descriptor limit invalidated poll"
    return observed, errors


def compare(left, right):
    if left.keys() != right.keys(): raise ValueError("observation count/labels mismatch")
    return [label for label in left if left[label] != right[label]]


def calibrate_reference(profile, observed):
    assert observed["initial"]["dns_queries_forwarded"] == 0
    assert observed["initial"]["dns_local_answered"] == 1
    if profile in ("no-server", "no-route4", "no-route6", "fd-full", "pending"):
        for index, (label, flags, advertised, _) in enumerate(VARIANTS):
            row = observed[label]; reply = row["reply"]["semantics"]; metrics = row["metrics"]
            assert reply["id"] == 0x5100 + index
            assert reply["flags"] == (flags & 0x110) | 0x8085
            assert reply["questions"] == [[f"q{index}.test", 1, 1]]
            ede = "000e" if profile == "no-server" else "0017"
            assert reply["records"] == ([] if advertised is None else [
                {"section": "additional", "name": "", "type": 41, "class": 1232, "ttl": 0, "data": "000f0002" + ede}])
            assert metrics["dns_queries_forwarded"] == int(profile == "pending")
            assert metrics["dns_local_answered"] == index + 2
            assert metrics["dns_unanswered"] == 0
    if profile == "pending":
        assert len(observed["upstream"]) == 1
        assert observed["pending-original"]["reply"]["semantics"]["id"] == 0x5001
        assert observed["pending-duplicate"]["reply"]["semantics"]["id"] == 0x5002
    if profile == "mixed":
        assert len(observed["upstream"]) == 2
        assert observed["empty-opt"]["metrics"]["dns_queries_forwarded"] == 2
        assert observed["empty-opt"]["metrics"]["dns_local_answered"] == 1
    if profile == "stale-fd":
        assert observed["after-refresh"]["dns_queries_forwarded"] == 1
        assert observed["after-refresh"]["dns_stale_answered"] == 1
        assert observed["after-refresh"]["dns_local_answered"] == 2
        assert observed["after-refresh"]["dns_unanswered"] == 0
    assert observed["closed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true"); parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.c_only and args.inject_error: parser.error("negative control needs Rust")
    args.reference_build = args.reference_build.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    routes = {family: json.loads(subprocess.check_output(["ip", family, "-j", "route"])) for family in ("-4", "-6")}
    assert all(not any(row.get("dst") == "default" or row.get("dev") != "lo" for row in rows) for rows in routes.values())
    c = args.reference_build / "dnsmasq/dnsmasq"; reference = verify_reference(c, None)
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists(); out.mkdir(parents=True)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-start-failure", "/run"], check=True)
    Path(BUS).parent.mkdir()
    profiles = ["no-server", "no-route4", "no-route6", "fd-full", "mixed", "pending", "stale-fd"]
    report = {"reference": reference, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest(),
              "routes": routes, "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "profiles": [], "failures": [], "injected_error": args.inject_error, "c_only": args.c_only}
    f = Fixture(args, out); f.start_bus()
    try:
        for profile in profiles:
            work = out / profile; work.mkdir()
            stage = "c"
            try:
                expected, c_errors = run(f, c, profile, work / "c")
                calibrate_reference(profile, expected)
                assert not compare(expected, copy.deepcopy(expected))
                mutated = copy.deepcopy(expected); mutated["initial"]["dns_queries_forwarded"] += 1
                assert compare(expected, mutated) == ["initial"]
                try: compare(expected, {})
                except ValueError: pass
                else: raise AssertionError("missing observation calibration")
                stage = "rust"
                actual, rust_errors = (expected, {}) if args.c_only else run(f, args.rust, profile, work / "rust")
                if args.inject_error and profile == "no-route4": actual["initial"]["dns_queries_forwarded"] += 1
                report["profiles"].append({"profile": profile, "observations": len(expected), "differences": compare(expected, actual),
                                             "c_errors": c_errors, "rust_errors": rust_errors})
            except Exception as error: report["failures"].append({"profile": profile, "stage": stage, "error": repr(error)})
            (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    finally: f.close()
    report["fixture_failures"] = [row for row in f.checks if not row["pass"]]
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    report["compared"] = 0 if args.c_only else sum(row["observations"] for row in report["profiles"])
    report["calibration"] = {"reference_reply_ids_flags_ede": 1, "reference_counters": 1, "retained_pending": 1, "stale_no_second_reply": 1, "changed_counter": 1, "missing_observation": 1, "real_errno": 1}
    (out / "fixture-observations.json").write_text(json.dumps({"checks": f.checks, "raw": f.raw}, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report)); return int(bool(report["failures"] or report["fixture_failures"] or report["mismatches"]))


if __name__ == "__main__": raise SystemExit(main())
