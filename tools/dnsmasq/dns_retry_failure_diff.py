#!/usr/bin/env python3
"""Real same-frec retry send failures in a verified private network namespace."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import query, semantics, read_name
from dns_start_failure_diff import tracee
from dns_udp_admission_diff import receive
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
ISOLATED_ADDRESS = "198.18.0.53"
LISTEN = ("127.0.0.1", 15353)
PROFILES = ["original-plain", "original-opt", "coalesced-opt", "fast-opt", "stale-opt"]


def request(host, ident, opt, do=True):
    packet = query(host, ident=ident)
    if opt:
        packet = packet[:10] + b"\0\1" + packet[12:] + b"\0" + struct.pack("!HHIH", 41, 1232, 0x8000 if do else 0, 0)
    return packet


def answer(packet, ttl=53):
    _, end = read_name(packet, 12)
    question = packet[12:end + 4]
    return (packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + question
            + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes([8, 8, 4, 4]))


def ip(*arguments):
    result = subprocess.run(["ip", *arguments], capture_output=True, text=True)
    result.check_returncode()
    return json.loads(result.stdout) if result.stdout.strip() else None


def namespace_gate():
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    host = os.environ["DNSMASQ_HOST_NETNS"]
    current = os.readlink("/proc/self/ns/net")
    assert current != host, "network namespace was not isolated from host"
    assert sorted(row["ifname"] for row in ip("-j", "link")) == ["lo"]
    assert not ip("-j", "-4", "route") and not ip("-j", "-6", "route")
    return {"host": host, "private": current}


def owns_udp_port(pid, port):
    inodes = {row.split()[9] for row in Path(f"/proc/{pid}/net/udp").read_text().splitlines()[1:]
              if row.split()[1].endswith(f":{port:04X}")}
    owned = {os.readlink(path) for path in Path(f"/proc/{pid}/fd").iterdir()}
    return bool(owned & {f"socket:[{inode}]" for inode in inodes})


def run(args, binary, profile, out):
    out.mkdir()
    fixture = Fixture(args, out)
    rows, wires, network, upstream_rows = [], [], [], []
    pid = None
    attached = False
    trace = out / "syscalls.log"
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    healthy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def record(label, **values):
        rows.append({"label": label, **values})

    def send(client, packet):
        client.sendto(packet, LISTEN)

    def recv(label, client, timeout=.15):
        packet = receive(client, timeout)
        wires.append({"label": label, "wire": None if packet is None else packet.hex()})
        record(label, response=None if packet is None else semantics(packet),
               question=None if packet is None else packet[12:read_name(packet, 12)[1] + 4].hex())
        return packet

    def upstream_request(server, label):
        packet, peer = server.recvfrom(65535)
        decoded = semantics(packet)
        decoded["id"] = 0
        upstream_rows.append({"label": label, "query": decoded})
        return packet, peer

    try:
        ip("address", "add", ISOLATED_ADDRESS + "/32", "dev", "lo")
        attached = True
        network.append({"phase": "added", "routes": ip("-j", "-4", "route", "show", "table", "all")})
        upstream.bind((ISOLATED_ADDRESS, 0))
        healthy.bind(("127.0.0.1", 0))
        for server in (upstream, healthy):
            server.settimeout(2)
        fixture.start_bus()
        config = out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\ncache-size=20\nlocal-ttl=37\nhost-record=ready.test,192.0.2.41\n"
                          f"server={ISOLATED_ADDRESS}#{upstream.getsockname()[1]}\n"
                          f"server=/healthy.test/127.0.0.1#{healthy.getsockname()[1]}\nenable-ubus={OBJECT}\n"
                          + ("fast-dns-retry=1000,5000\n" if profile == "fast-opt" else "")
                          + ("use-stale-cache=60\n" if profile == "stale-opt" else ""))
        command = ["strace", "-f", "-qq", "-s", "256", "-e", "trace=network,close,poll,ppoll",
                   "-o", str(trace), str(binary), "-k", "-C", str(config)]
        if binary == args.reference_build / "dnsmasq/dnsmasq":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        pid = tracee(fixture.daemon.pid)
        send(clients[2], query("ready.test", ident=0x6000))
        assert receive(clients[2], 1) is not None
        opt = profile != "original-plain"
        original = request("Mixed.retry.test", 0x6101, opt, do=profile != "stale-opt")
        duplicate = request("mixed.RETRY.test", 0x6102, opt, do=profile != "stale-opt")
        if profile == "stale-opt":
            send(clients[0], original)
            seed, seed_peer = upstream_request(upstream, "seed")
            upstream.sendto(answer(seed, 1), seed_peer)
            assert recv("seed-response", clients[0], 1) is not None
            time.sleep(2.1)
        send(clients[0], original)
        held, held_peer = upstream_request(upstream, "held")
        if profile == "stale-opt":
            assert recv("first-stale", clients[0], 1) is not None
        send(clients[1], duplicate)
        if profile == "stale-opt":
            assert recv("second-stale", clients[1], 1) is not None
        assert receive(upstream, .03) is None, "early duplicate did not coalesce"
        if profile == "fast-opt":
            # Keep the unrelated query younger than the failing timer by a
            # known margin; an accidental healthy timer retry is a hard error.
            time.sleep(.55)
        # Control replies exercise ordinary cache admission; DO-query caching
        # has a separate retained difference from the initial broader replay.
        send(clients[2], request("healthy.test", 0x6201, opt, do=False))
        held_healthy, healthy_peer = upstream_request(healthy, "healthy")
        record("before-failure", metrics=fixture.metrics())
        record("pending-sockets", failed=owns_udp_port(pid, held_peer[1]), healthy=owns_udp_port(pid, healthy_peer[1]))

        ip("address", "del", ISOLATED_ADDRESS + "/32", "dev", "lo")
        attached = False
        network.append({"phase": "removed", "routes": ip("-j", "-4", "route", "show", "table", "all")})
        unreachable = subprocess.run(["ip", "-4", "route", "get", ISOLATED_ADDRESS], capture_output=True, text=True)
        assert unreachable.returncode != 0, "removed upstream still has a route"
        (out / "unreachable.txt").write_text(unreachable.stdout + unreachable.stderr)
        if profile != "fast-opt":
            send(clients[1] if profile == "coalesced-opt" else clients[0],
                 duplicate if profile == "coalesced-opt" else original)
        deadline = time.monotonic() + 2
        while "ENETUNREACH" not in trace.read_text():
            assert time.monotonic() < deadline and fixture.daemon.poll() is None, "no real retry send error"
            time.sleep(.005)
        recv("failure-original", clients[0])
        recv("failure-coalesced", clients[1])
        record("after-failure", metrics=fixture.metrics())
        record("failure-sockets", failed=owns_udp_port(pid, held_peer[1]), healthy=owns_udp_port(pid, healthy_peer[1]))
        assert receive(healthy, .01) is None, "healthy query retried before its preserved reply"
        healthy.sendto(answer(held_healthy), healthy_peer)
        assert recv("healthy-survived", clients[2], 1) is not None
        record("healthy-metrics", metrics=fixture.metrics())
        record("completed-sockets", failed=owns_udp_port(pid, held_peer[1]), healthy=owns_udp_port(pid, healthy_peer[1]))

        ip("address", "add", ISOLATED_ADDRESS + "/32", "dev", "lo")
        attached = True
        network.append({"phase": "restored", "routes": ip("-j", "-4", "route", "show", "table", "all")})
        upstream.sendto(answer(held), held_peer)
        recv("late-original", clients[0])
        recv("late-coalesced", clients[1])
        record("late-metrics", metrics=fixture.metrics())
        recovery = request("recovered.test", 0x6301, opt, do=False)
        send(clients[0], recovery)
        packet, peer = upstream_request(upstream, "recovery")
        upstream.sendto(answer(packet), peer)
        assert recv("recovery-response", clients[0], 1) is not None
        record("recovery-metrics", metrics=fixture.metrics())
        assert receive(upstream, .02) is None and receive(healthy, .02) is None, "unexpected upstream sends"
        os.kill(pid, signal.SIGHUP)
        deadline = time.monotonic() + 2
        while True:
            reloaded = fixture.metrics()
            if reloaded["dns_cache_inserted"] == 0:
                break
            assert time.monotonic() < deadline, "HUP did not clear the cache window"
            time.sleep(.01)
        record("after-hup", metrics=reloaded)
        record("upstream", observations=upstream_rows)
        os.kill(pid, signal.SIGTERM)
        fixture.daemon.wait(3)
        record("shutdown", clean=fixture.daemon.returncode == 0 and not Path(f"/proc/{pid}").exists())
        assert rows[-1]["clean"]
        return rows
    finally:
        for client in clients:
            client.close()
        upstream.close()
        healthy.close()
        if pid is not None and Path(f"/proc/{pid}").exists():
            os.kill(pid, signal.SIGTERM)
            try:
                fixture.daemon.wait(3)
            except subprocess.TimeoutExpired:
                os.kill(pid, signal.SIGKILL)
                fixture.daemon.wait(3)
        fixture.close()
        if attached:
            ip("address", "del", ISOLATED_ADDRESS + "/32", "dev", "lo")
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires, "network": network,
            "metrics_raw": fixture.raw, "checks": fixture.checks, "upstream": upstream_rows}, indent=2) + "\n")
        assert all(row["pass"] for row in fixture.checks)


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("observation count or labels differ")
    return [{"label": c["label"], "c": c, "rust": rust} for c, rust in zip(expected, actual) if c != rust]


def calibrate_reference(profile, rows):
    assert len(rows) == (20 if profile == "stale-opt" else 17)
    by_label = {row["label"]: row for row in rows}
    before = by_label["before-failure"]["metrics"]
    after = by_label["after-failure"]["metrics"]
    assert before["dns_local_answered"] == 1 and after["dns_local_answered"] == 2
    assert before["dns_queries_forwarded"] == after["dns_queries_forwarded"] == (3 if profile == "stale-opt" else 2)
    assert before["dns_unanswered"] == after["dns_unanswered"] == 0
    assert by_label["pending-sockets"] == {"label": "pending-sockets", "failed": True, "healthy": True}
    assert by_label["failure-sockets"] == {"label": "failure-sockets", "failed": False, "healthy": True}
    assert by_label["completed-sockets"] == {"label": "completed-sockets", "failed": False, "healthy": False}
    original = by_label["failure-original"]["response"]
    coalesced = by_label["failure-coalesced"]["response"]
    if profile == "fast-opt":
        assert original is None and coalesced is None
    elif profile == "stale-opt":
        assert original["id"] == 0x6101 and original["flags"] & 15 == 0
        assert after["dns_stale_answered"] == 3 and coalesced is None
    else:
        refused = coalesced if profile == "coalesced-opt" else original
        assert refused["id"] == 0x6101 and refused["flags"] == 0x8185
        assert (original if profile == "coalesced-opt" else coalesced) is None
        assert refused["records"] == ([] if profile == "original-plain" else [
            {"section": "additional", "name": "", "type": 41, "class": 1232, "ttl": 0, "data": "000f00020017"}])
    assert by_label["healthy-survived"]["response"]["id"] == 0x6201
    assert by_label["late-original"]["response"] is None and by_label["late-coalesced"]["response"] is None
    assert by_label["late-metrics"]["metrics"] == by_label["healthy-metrics"]["metrics"]
    assert by_label["recovery-response"]["response"]["id"] == 0x6301
    assert by_label["after-hup"]["metrics"]["dns_local_answered"] == 2
    assert by_label["after-hup"]["metrics"]["dns_cache_inserted"] == 0
    assert by_label["shutdown"]["clean"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.inject_error and args.rust is None:
        parser.error("negative control requires Rust")
    args.reference_build = args.reference_build.resolve()
    if args.rust is not None:
        args.rust = args.rust.resolve()
    identity = namespace_gate()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    reference = args.reference_build / "dnsmasq/dnsmasq"
    report = {"reference": verify_reference(reference, None), "namespace": identity,
              "tool_sha256": digest(__file__), "rust_sha256": None if args.rust is None else digest(args.rust),
              "profiles": [], "failures": [], "c_only": args.rust is None, "injected_error": args.inject_error,
              "reference_defects": [{"profile": "coalesced-opt", "label": "failure-coalesced",
                                     "description": "C returns first recipient ID/question to a different retrying recipient"}]}
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-retry-failure", "/run"], check=True)
    Path(BUS).parent.mkdir()
    for profile in PROFILES:
        work = out / profile
        work.mkdir()
        stage = "C"
        try:
            expected = run(args, reference, profile, work / "c")
            calibrate_reference(profile, expected)
            assert not compare(expected, copy.deepcopy(expected))
            changed = copy.deepcopy(expected)
            next(row for row in changed if row["label"] == "after-failure")["metrics"]["dns_local_answered"] += 1
            assert len(compare(expected, changed)) == 1
            try:
                compare(expected, expected[:-1])
            except ValueError:
                pass
            else:
                raise AssertionError("missing row calibration")
            actual = expected
            if args.rust is not None:
                stage = "Rust"
                actual = run(args, args.rust, profile, work / "rust")
                if args.inject_error and profile == "original-plain":
                    next(row for row in actual if row["label"] == "after-failure")["metrics"]["dns_local_answered"] += 1
            report["profiles"].append({"profile": profile, "observations": len(expected),
                                       "differences": [] if args.rust is None else compare(expected, actual)})
        except Exception as error:
            report["failures"].append({"profile": profile, "stage": stage, "error": repr(error)})
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(report["failures"] or any(row["differences"] for row in report["profiles"])))


if __name__ == "__main__":
    raise SystemExit(main())
