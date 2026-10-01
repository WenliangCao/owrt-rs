#!/usr/bin/env python3
"""Exact-C/Rust -k TCP listener survival and recovery under actual EMFILE."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from dns_start_failure_diff import tracee
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)


def resources(pid):
    root = Path(f"/proc/{pid}")
    return {
        "fds": {path.name: os.readlink(path) for path in (root / "fd").iterdir()},
        "threads": sorted(path.name for path in (root / "task").iterdir()),
        "children": (root / f"task/{pid}/children").read_text().split(),
    }


def listener(pid):
    inodes = {row.split()[9] for row in Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]
              if row.split()[1].endswith(f":{LISTEN[1]:04X}") and row.split()[3] == "0A"}
    result = {fd: target for fd, target in resources(pid)["fds"].items()
              if target in {f"socket:[{inode}]" for inode in inodes}}
    assert len(result) == 1, ("expected one IPv4 listener", result)
    return result


def accept_errors(path):
    pending, calls = {}, []
    for line in path.read_text().splitlines():
        match = re.match(r"(\d+)\s+(.*)", line)
        if not match:
            continue
        thread, call = match.groups()
        if call.endswith("<unfinished ...>"):
            pending[thread] = call.removesuffix("<unfinished ...>")
            continue
        resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", call)
        if resumed:
            call = pending.pop(thread, "") + resumed.group(1)
        calls.append(call)
    return sum(bool(re.match(r"accept4?\(.*= -1 EMFILE", call)) for call in calls)


def run(args, binary, out):
    out.mkdir()
    fixture = Fixture(args, out)
    rows, wires, samples, clients = [], [], {}, []
    pid = original_limit = None
    trace = out / "syscalls.log"
    clean_exit = False

    def metric(value):
        deadline = time.monotonic() + 3
        while True:
            current = fixture.metrics()
            if current["tcp_connections"] == value:
                return current
            assert time.monotonic() < deadline, ("TCP gauge", value, current)
            time.sleep(.005)

    def record(label, **values):
        rows.append({"label": label, **values})

    def response(label, request, packet):
        assert packet[:2] == request[:2], "client query ID changed"
        wires.append({"label": label, "request": request.hex(), "response": packet.hex()})
        record(label, response=semantics(packet))

    def udp(label, ident):
        request = query("ready.test", ident=ident)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(request, LISTEN)
            response(label, request, client.recv(65535))

    def tcp_response(label, client, request):
        client.settimeout(2)
        packet = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
        response(label, request, packet)

    try:
        fixture.start_bus()
        config = out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "cache-size=0\nlocal-ttl=37\nhost-record=ready.test,192.0.2.41\n"
                          f"enable-ubus={OBJECT}\n")
        command = ["strace", "-f", "-qq", "-e", "trace=network,close,poll,ppoll", "-o", str(trace),
                   str(binary), "-k", "-C", str(config)]
        if binary == args.reference_build / "dnsmasq/dnsmasq":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        pid = tracee(fixture.daemon.pid)
        udp("initial-udp", 0x6001)
        record("initial-metrics", metrics=metric(0))
        samples["initial"] = resources(pid)
        before_listener = listener(pid)
        opened = sorted(int(fd) for fd in samples["initial"]["fds"])
        limit = next(fd for fd in range(max(opened) + 2) if fd not in opened)
        assert limit >= 4, "descriptor limit would invalidate poll"
        original_limit = resource.prlimit(pid, resource.RLIMIT_NOFILE)
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (limit, original_limit[1]))
        samples["limit"] = {"soft": limit, "original": original_limit, "headroom": 0}

        queued = socket.create_connection(LISTEN, 2)
        clients.append(queued)
        request = query("ready.test", ident=0x6002)
        queued.sendall(struct.pack("!H", len(request)) + request)
        deadline = time.monotonic() + 2
        while not accept_errors(trace):
            assert time.monotonic() < deadline, "no actual accept EMFILE"
            assert fixture.daemon.poll() is None, "daemon exited under pressure"
            time.sleep(.005)
        queued.settimeout(.08)
        try:
            data = queued.recv(1, socket.MSG_PEEK)
        except socket.timeout:
            record("queued-under-pressure", no_response=True)
        else:
            raise AssertionError(("queued client completed or disconnected under pressure", data.hex()))
        record("pressure-listener", preserved=listener(pid) == before_listener)
        udp("pressure-udp", 0x6003)
        record("pressure-metrics", metrics=metric(0))
        samples["pressure"] = resources(pid)
        samples["pressure"]["accept_emfile"] = accept_errors(trace)
        assert samples["pressure"]["fds"] == samples["initial"]["fds"], "pressure changed parent descriptors"

        resource.prlimit(pid, resource.RLIMIT_NOFILE, original_limit)
        original_limit = None
        tcp_response("queued-recovered", queued, request)
        record("queued-active", metrics=metric(1))
        fresh = socket.create_connection(LISTEN, 2)
        clients.append(fresh)
        request = query("ready.test", ident=0x6004)
        fresh.sendall(struct.pack("!H", len(request)) + request)
        tcp_response("fresh-recovered", fresh, request)
        record("two-active", metrics=metric(2))
        record("recovered-listener", preserved=listener(pid) == before_listener)
        udp("active-udp", 0x6005)
        record("active-metrics", metrics=metric(2))
        samples["active"] = resources(pid)
        queued.close()
        clients.remove(queued)
        record("one-closed", metrics=metric(1))
        fresh.close()
        clients.remove(fresh)
        record("all-closed", metrics=metric(0))
        deadline = time.monotonic() + 3
        while True:
            samples["closed"] = resources(pid)
            if (samples["closed"]["fds"] == samples["initial"]["fds"]
                    and len(samples["closed"]["threads"]) == len(samples["initial"]["threads"])
                    and not samples["closed"]["children"]):
                break
            assert time.monotonic() < deadline, "connection descriptors, threads or child processes leaked"
            time.sleep(.01)
        record("resources-returned", same_parent_fds=True, same_thread_count=True, children=0)
        os.kill(pid, signal.SIGTERM)
        fixture.daemon.wait(3)
        clean_exit = fixture.daemon.returncode == 0 and not Path(f"/proc/{pid}").exists()
        record("shutdown", clean=clean_exit)
        assert clean_exit, "daemon failed to exit normally"
        assert accept_errors(trace) > 0
        assert "EINVAL" not in trace.read_text(), "descriptor limit invalidated poll"
        assert not fixture.upstream.requests, "local queries unexpectedly reached upstream"
        return rows
    finally:
        for client in clients:
            client.close()
        if pid is not None and Path(f"/proc/{pid}").exists():
            if original_limit is not None:
                resource.prlimit(pid, resource.RLIMIT_NOFILE, original_limit)
            os.kill(pid, signal.SIGTERM)
            try:
                fixture.daemon.wait(3)
            except subprocess.TimeoutExpired:
                os.kill(pid, signal.SIGKILL)
                fixture.daemon.wait(3)
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires, "resources": samples,
                                                  "metrics_raw": fixture.raw, "checks": fixture.checks,
                                                  "clean_exit": clean_exit}, indent=2) + "\n")
        assert all(row["pass"] for row in fixture.checks), fixture.checks


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("observation count or labels differ")
    return [{"label": c["label"], "c": c, "rust": rust}
            for c, rust in zip(expected, actual) if c != rust]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build, args.rust = args.reference_build.resolve(), args.rust.resolve()
    out = args.out.resolve()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    reference = args.reference_build / "dnsmasq/dnsmasq"
    report = {"reference": verify_reference(reference, None), "rust_sha256": digest(args.rust),
              "tool_sha256": digest(__file__), "injected_error": args.inject_error,
              "compared": 0, "differences": [], "failures": []}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "tcp-accept-failure", "/run"], check=True)
    Path(BUS).parent.mkdir()
    stage = "C"
    try:
        expected = run(args, reference, out / "c")
        assert len(expected) == 17, ("C observation count", len(expected))
        by_label = {row["label"]: row for row in expected}
        assert by_label["pressure-metrics"]["metrics"]["tcp_connections"] == 0
        assert by_label["two-active"]["metrics"]["tcp_connections"] == 2
        assert by_label["pressure-listener"]["preserved"] and by_label["recovered-listener"]["preserved"]
        assert not compare(expected, copy.deepcopy(expected))
        mutated = copy.deepcopy(expected)
        next(row for row in mutated if row["label"] == "pressure-listener")["preserved"] = False
        assert len(compare(expected, mutated)) == 1
        try:
            compare(expected, expected[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("missing observation calibration")
        stage = "Rust"
        actual = run(args, args.rust, out / "rust")
        if args.inject_error:
            next(row for row in actual if row["label"] == "recovered-listener")["preserved"] = False
        report["compared"] = len(expected)
        report["differences"] = compare(expected, actual)
        report["calibration"] = {"changed_listener": True, "missing_observation": True,
                                 "real_accept_emfile": True, "normal_mode_gauge": True}
    except Exception as error:
        report["failures"].append({"stage": stage, "error": repr(error)})
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(report["differences"] or report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
