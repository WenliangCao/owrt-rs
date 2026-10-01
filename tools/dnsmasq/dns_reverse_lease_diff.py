#!/usr/bin/env python3
"""C-first real DHCP/UDP reverse ownership, publication and coexistence gate."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from dhcp_lease_lifecycle import Daemon, rows as lease_rows
from dhcp_reverse_lifecycle_diff import read_closed, watch_reads
from dns_do_cache_diff import request
from dns_reverse_cache_diff import decode
from dns_service_probe import name, read_name, rr
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
ADDRESS = "127.0.0.10"
OWNER = "10.0.0.127.in-addr.arpa"
ALTERNATE = "266.0.0.127.in-addr.arpa"
DYNAMIC = "Dynamic.reverse.test"
FQDN = "client1.leases.test"


def dns(label, host=OWNER, kind=12, targets=None, cached=False, shape="failure", ttl=120, sends=None):
    result = {"op": "dns", "label": label, "host": host, "kind": kind,
            "targets": targets or [], "cached": cached, "shape": shape, "ttl": ttl}
    if sends is not None:
        result["sends"] = sends
    return result


def dhcp(label, kind, client=1):
    return {"op": "dhcp", "label": label, "kind": kind, "client": client,
            "address": f"127.0.0.{9 + client}"}


def profiles():
    result = [
        {"label": "dynamic-before-lease", "extra": "", "static": None, "actions": [
            dns("seed-dynamic", targets=[DYNAMIC], shape="positive", ttl=4),
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("short-published", "client1", 1, [ADDRESS], True),
            dns("fqdn-published", FQDN, 1, [ADDRESS], True),
            dns("dynamic-keeps-ptr", targets=[DYNAMIC], cached=True),
            {"op": "wait", "after": "seed-dynamic", "seconds": 5.1},
            dns("expired-no-auto-ownership"),
            dhcp("offer-two", 1, 2), dhcp("ack-two", 3, 2),
            dns("republish-selects-lease", targets=[FQDN], cached=True),
            dhcp("release-one", 7), dns("released-short", "client1", 1), dns("released-ptr"),
        ]},
        {"label": "expired-before-publication", "extra": "", "static": None, "actions": [
            dns("seed-dynamic", targets=[DYNAMIC], shape="positive", ttl=1),
            {"op": "wait", "after": "seed-dynamic", "seconds": 2.1},
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("short-published", "client1", 1, [ADDRESS], True),
            dns("time-zero-suppressed-ptr"),
            dhcp("offer-two", 1, 2), dhcp("ack-two", 3, 2),
            dns("republish-selects-lease", targets=[FQDN], cached=True),
        ]},
        {"label": "late-reply-coexist", "extra": "", "static": None, "actions": [
            {"op": "hold", "label": "hold-forwarded-ptr"},
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("lease-before-late-reply", targets=[FQDN], cached=True),
            {"op": "deliver", "label": "deliver-late-ptr"},
            dns("local-first-and-dynamic", targets=[FQDN, DYNAMIC], cached=True),
            dns("short-published", "client1", 1, [ADDRESS], True),
            dhcp("release-one", 7), dns("dynamic-survives-release", targets=[DYNAMIC], cached=True),
            {"op": "hup", "label": "hup-clears-dynamic", "static": None}, dns("post-hup-miss"),
        ]},
        {"label": "static-host-priority", "extra": "dhcp-host=02:00:00:00:00:01,127.0.0.10,client1,600s\n", "static": "static.leases.test", "actions": [
            dns("static-before-lease", targets=["static.leases.test"], cached=True),
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("static-after-lease", targets=["static.leases.test"], cached=True),
            dns("short-published", "client1", 1, [ADDRESS], True),
            dns("fqdn-published", FQDN, 1, [ADDRESS], True),
            dhcp("release-one", 7), dns("static-after-release", targets=["static.leases.test"], cached=True),
            {"op": "hup", "label": "hup-changes-host", "static": "changed.leases.test"},
            dns("changed-static-owner", targets=["changed.leases.test"], cached=True),
        ]},
        {"label": "explicit-ptr-priority", "extra": f"ptr-record={OWNER},explicit.reverse.test\n", "static": None, "actions": [
            dns("seed-alternate", ALTERNATE, targets=[DYNAMIC], shape="positive"),
            dns("explicit-before-lease", targets=["explicit.reverse.test"], cached=True),
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("explicit-after-lease", targets=["explicit.reverse.test"], cached=True),
            dns("alternate-stays-dynamic", ALTERNATE, targets=[DYNAMIC], cached=True),
            dns("fqdn-published", FQDN, 1, [ADDRESS], True),
            {"op": "hup", "label": "active-hup-republishes", "static": None},
            dns("alternate-now-lease", ALTERNATE, targets=[FQDN], cached=True),
            dhcp("release-one", 7),
            dns("explicit-after-release", targets=["explicit.reverse.test"], cached=True),
            dns("alternate-after-release", ALTERNATE),
        ]},
        {"label": "fqdn-only", "extra": "dhcp-fqdn\n", "static": None, "actions": [
            dhcp("offer-one", 1), dhcp("ack-one", 3),
            dns("fqdn-published", FQDN, 1, [ADDRESS], True),
            dns("short-not-published", "client1", 1, sends=1),
            dns("fqdn-owns-ptr", targets=[FQDN], cached=True),
            dhcp("release-one", 7), dns("released-fqdn", FQDN, 1), dns("released-ptr"),
        ]},
    ]
    assert len(result) == 6 and sum(action["op"] != "wait" for profile in result for action in profile["actions"]) == 62
    return result


def response(packet, shape, ttl=120):
    _, end = read_name(packet, 12)
    question = packet[12:end + 4]
    flags = 0x8180 if shape == "positive" else 0x8182
    answers = [rr(12, name(DYNAMIC), ttl)] if shape == "positive" else []
    opt = next((record for record in decode(packet)["records"] if record["type"] == 41), None)
    return (packet[:2] + struct.pack("!5H", flags, 1, len(answers), 0, int(opt is not None)) + question
            + b"".join(answers) + (b"\0" + struct.pack("!HHIH", 41, 1232, opt["ttl"] & 0x8000, 0) if opt else b""))


def wait_bound(process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, "daemon exited before socket readiness"
        table = Path(f"/proc/{process.pid}/net/udp")
        if table.exists():
            ports = {int(row.split()[1].split(":")[1], 16) for row in table.read_text().splitlines()[1:]}
            if {67, 15353} <= ports:
                return
        time.sleep(.005)
    raise TimeoutError("DNS/DHCP sockets did not bind")


def canonical_dhcp(reply):
    return None if reply is None else {key: value for key, value in reply.items() if key not in ("sent", "received")}


def file_snapshot(daemon, path):
    result = lease_rows(path)
    for row in result:
        ack = next(reply for reply in reversed(daemon.responses) if reply["message"] == "05" and reply["address"] == socket.inet_aton(row["address"]).hex())
        assert int(ack["sent"]) + 599 <= row["expiry"] <= int(ack["received"]) + 601, "lease expiry is not tied to its ACK"
        row["expiry"] = "ack+600s"
    return result


class ManagedDaemon(Daemon):
    def __init__(self, *args, fixture, side):
        super().__init__(*args)
        self.fixture, self.side = fixture, side

    def start(self):
        self.starts += 1
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 68))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
        self.socket.settimeout(3)
        command = [str(self.binary), "--no-daemon", "--conf-file=" + str(self.config)]
        if self.side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(self.folder / "pid")]
        self.process, _ = self.fixture.spawn(command, "daemon")
        self.fixture.daemon = self.process
        self.fixture.wait_registered()
        wait_bound(self.process)


def run_service(args, binary, side, profile, out):
    out.mkdir()
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    held = None
    observations, wires, waits, checks = [], [], [], []
    times, active = {}, {}
    leases, hosts, marker = out / "leases", out / "hosts", out / "dhcp-hosts"
    leases.write_bytes(b"")
    marker.write_bytes(b"")
    def write_hosts(static):
        hosts.write_text("192.0.2.41 ready.test\n" + (f"{ADDRESS} {static}\n" if static else ""))
    write_hosts(profile["static"])
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\nno-ping\n"
                      "dhcp-authoritative\ndhcp-lease-max=150\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                      "domain=leases.test\nlocal-ttl=17\ndhcp-ttl=60\ncache-size=32\n"
                      "no-0x20-encode\nno-round-robin\n"
                      + f"dhcp-leasefile={leases}\naddn-hosts={hosts}\ndhcp-hostsfile={marker}\n"
                      + f"server=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n" + profile["extra"])
    daemon = ManagedDaemon(binary, config, leases, out, checks, profile["label"], fixture=fixture, side=side)
    def exchange(label, packet, shape, ttl):
        observed, raw = [], []
        client.sendto(packet, LISTEN)
        deadline = time.monotonic() + 3
        while True:
            ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
            assert ready, (label, "DNS response timeout")
            if upstream in ready:
                sent, peer = upstream.recvfrom(65535)
                decoded = decode(sent)
                decoded["id"] = 0
                observed.append(decoded)
                answer = response(sent, shape, ttl)
                raw.append({"request": sent.hex(), "response": answer.hex(), "peer": peer})
                upstream.sendto(answer, peer)
            if client in ready:
                reply = client.recv(65535)
                break
        assert reply[:2] == packet[:2], "DNS recipient ID changed"
        assert not select.select([client, upstream], [], [], .01)[0], "extra DNS datagram"
        wires.append({"label": label, "request": packet.hex(), "response": reply.hex(), "upstream": raw})
        times[label] = time.monotonic()
        return {"response": decode(reply), "question": reply[12:read_name(reply, 12)[1] + 4].hex(), "upstream": observed, "cached": not observed}
    try:
        fixture.start_bus()
        daemon.start()
        ready = exchange("ready", request("ready.test", 1, 0x3000, opt=False), "failure", 0)
        assert ready["cached"] and ready["response"]["records"][0]["type"] == 1
        assert ready["response"]["records"][0]["data"] == ipaddress.ip_address("192.0.2.41").packed.hex()
        for item in profile["actions"]:
            op = item["op"]
            if op == "wait":
                started = time.monotonic()
                until = times[item["after"]] + item["seconds"]
                while time.monotonic() < until:
                    assert daemon.process.poll() is None
                    time.sleep(max(0, min(.05, until - time.monotonic())))
                waits.append({**item, "started": started, "finished": time.monotonic(), "wall": time.time()})
                continue
            label = item["label"]
            row = {"label": label, "op": op}
            if op == "dns":
                row.update(exchange(label, request(item["host"], item["kind"], 0x4100 + len(observations), opt=False), item["shape"], item["ttl"]))
            elif op == "dhcp":
                kind = item["kind"]
                reply = daemon.exchange(kind, item["client"], item["address"], selecting=kind == 3)
                if kind == 3:
                    active[item["address"]] = f"client{item['client']}"
                elif kind == 7:
                    active.pop(item["address"], None)
                    daemon.wait_rows(lambda rows: all(lease["address"] != item["address"] for lease in rows), 3)
                row["reply"] = canonical_dhcp(reply)
                row["leases"] = file_snapshot(daemon, leases)
                (out / f"{label}.leases").write_bytes(leases.read_bytes())
                row["expected_lease_owners"] = dict(active)
            elif op == "hold":
                assert held is None
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                packet = request(OWNER, 12, 0x4100 + len(observations), opt=False)
                sock.sendto(packet, LISTEN)
                assert select.select([upstream], [], [], 3)[0], "held request did not forward"
                sent, peer = upstream.recvfrom(65535)
                assert not select.select([sock], [], [], .01)[0], "held request answered before upstream release"
                held = (sock, packet, sent, peer)
                decoded = decode(sent)
                decoded["id"] = 0
                row.update(upstream=[decoded], recipient_answered=False)
                wires.append({"label": label, "request": packet.hex(), "upstream_request": sent.hex(), "peer": peer})
            elif op == "deliver":
                assert held is not None
                sock, packet, sent, peer = held
                answer = response(sent, "positive", 120)
                upstream.sendto(answer, peer)
                reply = sock.recv(65535)
                assert reply[:2] == packet[:2]
                row.update(response=decode(reply), question=reply[12:read_name(reply, 12)[1] + 4].hex(), cached=False, upstream=[])
                wires.append({"label": label, "response": reply.hex(), "upstream_response": answer.hex()})
                sock.close()
                held = None
            elif op == "hup":
                write_hosts(item["static"])
                watch = watch_reads(marker)
                try:
                    daemon.process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 3
                    while not read_closed(watch):
                        assert daemon.process.poll() is None and time.monotonic() < deadline, "HUP read-close marker missing"
                        time.sleep(.005)
                finally:
                    os.close(watch)
                row["leases"] = file_snapshot(daemon, leases)
                (out / f"{label}.leases").write_bytes(leases.read_bytes())
            else:
                raise AssertionError(op)
            row["metrics"] = fixture.metrics()
            observations.append(row)
        assert held is None
        daemon.stop()
        assert all(check["pass"] for check in checks), checks
        return observations
    finally:
        if held is not None:
            held[0].close()
        daemon.stop()
        client.close()
        upstream.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"observations": observations, "wires": wires, "waits": waits,
                                                   "dhcp_checks": checks, "dhcp_responses": daemon.responses,
                                                   "ubus_raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)


def semantic(row):
    row = copy.deepcopy(row)
    row.pop("expected_lease_owners", None)
    return row


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("missing observation or reordered labels")
    differences = []
    dynamic_data = name(DYNAMIC.lower()).hex()
    for left, right in zip(expected, actual):
        c, rust = semantic(left), semantic(right)
        if c.get("cached") and rust.get("cached"):
            for a, b in zip(c["response"]["records"], rust["response"]["records"]):
                if a["type"] == b["type"] == 12 and a["data"] == b["data"] == dynamic_data and abs(a["ttl"] - b["ttl"]) <= 1:
                    b["ttl"] = a["ttl"]
        if c != rust:
            differences.append({"label": left["label"], "c": c, "rust": rust})
    return differences


def calibrate(rows, profile):
    actions = [item for item in profile["actions"] if item["op"] != "wait"]
    assert [row["label"] for row in rows] == [item["label"] for item in actions]
    for row, item in zip(rows, actions):
        if item["op"] == "dns":
            assert row["cached"] == item["cached"], (row["label"], "cache", row["cached"], item["cached"])
            sends = item.get("sends", 0 if item["cached"] else 1 if item["shape"] == "positive" else 2)
            assert len(row["upstream"]) == sends, (row["label"], "upstream count", len(row["upstream"]), sends)
            response = row["response"]
            assert response["flags"] & 15 == (0 if item["targets"] else 2), (row["label"], "rcode")
            records = [record for record in response["records"] if record["section"] == "answer"]
            assert [record["type"] for record in records] == [item["kind"]] * len(item["targets"])
            if item["kind"] == 12:
                assert response["ptr_case"] == item["targets"], (row["label"], "PTR order", response["ptr_case"], item["targets"])
                for record, target in zip(records, item["targets"]):
                    if target == DYNAMIC:
                        assert 0 < record["ttl"] <= (item["ttl"] if not item["cached"] else 120)
                    else:
                        assert record["ttl"] == (60 if target == FQDN else 17), (row["label"], "local TTL")
            else:
                assert [record["data"] for record in records] == [ipaddress.ip_address(target).packed.hex() for target in item["targets"]]
                assert all(record["ttl"] == 60 for record in records)
        elif item["op"] == "dhcp":
            assert {lease["address"]: lease["name"] for lease in row["leases"]} == row["expected_lease_owners"], (row["label"], "durable lease owners")
            assert (row["reply"] is None) == (item["kind"] == 7)
        elif item["op"] == "hold":
            assert len(row["upstream"]) == 1 and not row["recipient_answered"]
        elif item["op"] == "deliver":
            assert row["response"]["ptr_case"] == [DYNAMIC] and row["response"]["flags"] & 15 == 0
        elif item["op"] == "hup":
            assert row["metrics"]["dns_cache_inserted"] == row["metrics"]["dns_cache_live_freed"] == 0
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows)
    index = next(i for i, row in enumerate(changed) if "response" in row)
    changed[index]["response"]["flags"] ^= 0x20
    assert len(compare(rows, changed)) == 1
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing observation accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if args.inject_error and args.rust is None:
        parser.error("negative requires a passing frozen Rust ELF")
    args.reference_build = args.reference_build.resolve()
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "reverse-lease-service", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "profiles": [], "failures": [], "injected_error": args.inject_error}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    expected_profiles = []
    for profile in profiles():
        work = out / profile["label"]
        work.mkdir()
        try:
            expected = run_service(args, c, "C", profile, work / "c")
            calibrate(expected, profile)
            expected_profiles.append((profile, expected, work))
        except Exception as error:
            report["failures"].append({"profile": profile["label"], "stage": "C", "error": repr(error)})
        save()
    if not report["failures"]:
        for index, (profile, expected, work) in enumerate(expected_profiles):
            try:
                differences = []
                if args.rust is not None:
                    actual = run_service(args, args.rust.resolve(), "Rust", profile, work / "rust")
                    if args.inject_error and index == 0:
                        actual[0]["response"]["flags"] ^= 0x20
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile["label"], "observations": len(expected), "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile["label"], "stage": "Rust", "error": repr(error)})
            save()
    report["c_calibrated"] = sum(len(rows) for _, rows, _ in expected_profiles)
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    save()
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
