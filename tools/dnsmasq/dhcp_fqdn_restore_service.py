#!/usr/bin/env python3
"""C-first real lease-file FQDN recovery and live hostname collision gate."""
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

from dhcp_daemon_smoke import decode as decode_dhcp
from dhcp_lease_lifecycle import packet as dhcp_packet, rows as lease_rows
from dns_do_cache_diff import request
from dns_reverse_cache_diff import decode
from dns_reverse_lease_diff import wait_bound
from dns_service_probe import read_name
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
FIRST, SECOND, LIVE = "127.0.0.10", "127.0.0.11", "127.0.0.12"
ONE, TWO = "client1.one.restore.test", "client1.two.restore.test"
INITIAL = (f"0 02:00:00:00:00:01 {FIRST} client1 *\n"
           f"0 02:00:00:00:00:02 {SECOND} client1 *\n").encode()


def dns(label, host, kind=1, values=None):
    return {"op": "dns", "label": label, "host": host, "kind": kind, "values": values or []}


def reverse(address):
    return ipaddress.ip_address(address).reverse_pointer


def profiles():
    cases = []
    for fqdn in (False, True):
        cases.append({"label": "restore-fqdn" if fqdn else "restore-default", "fqdn": fqdn, "actions": [
            {"op": "file", "label": "startup-file"},
            dns("short", "client1", values=[] if fqdn else [SECOND]),
            dns("first-fqdn", ONE, values=[FIRST] if fqdn else []),
            dns("second-fqdn", TWO, values=[SECOND]),
            dns("first-ptr", reverse(FIRST), 12, [ONE] if fqdn else []),
            dns("second-ptr", reverse(SECOND), 12, [TWO]),
        ]})
    cases.append({"label": "restore-fqdn-live-collision", "fqdn": True, "actions": [
        {"op": "file", "label": "startup-file"},
        dns("restored-first-fqdn", ONE, values=[FIRST]),
        dns("restored-second-fqdn", TWO, values=[SECOND]),
        {"op": "dhcp", "label": "offer-competing-name", "kind": 1},
        {"op": "dhcp", "label": "ack-competing-name", "kind": 3},
        dns("short-stays-unpublished", "client1"),
        dns("first-fqdn-moved", ONE, values=[LIVE]),
        dns("second-fqdn-retained", TWO, values=[SECOND]),
        dns("old-first-ptr-removed", reverse(FIRST), 12),
        dns("new-ptr", reverse(LIVE), 12, [ONE]),
    ]})
    assert len(cases) == 3 and sum(len(case["actions"]) for case in cases) == 22
    return cases


def upstream_reply(packet):
    _, end = read_name(packet, 12)
    opt = any(record["type"] == 41 for record in decode(packet)["records"])
    answer = packet[:2] + struct.pack("!5H", 0x8183, 1, 0, 0, int(opt)) + packet[12:end + 4]
    if opt:
        answer += b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return answer


def run(args, binary, side, profile, out):
    out.mkdir()
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcp.bind(("0.0.0.0", 68))
    dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    dhcp.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
    dhcp.settimeout(3)
    rows, wires, ack_window = [], [], None
    leasefile = out / "leases"
    leasefile.write_bytes(INITIAL)
    (out / "initial.leases").write_bytes(INITIAL)
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                      "no-ping\ndhcp-authoritative\ndhcp-lease-max=150\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                      "domain=base.restore.test\n"
                      f"domain=one.restore.test,{FIRST}\ndomain=two.restore.test,{SECOND}\n"
                      f"domain=one.restore.test,{LIVE}\n"
                      "local-ttl=17\ndhcp-ttl=60\nno-negcache\nno-0x20-encode\nno-round-robin\n"
                      "host-record=ready.test,192.0.2.41\n"
                      + f"dhcp-leasefile={leasefile}\nserver=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n"
                      + ("dhcp-fqdn\n" if profile["fqdn"] else ""))

    def snapshot(label):
        result = lease_rows(leasefile)
        (out / f"{label}.leases").write_bytes(leasefile.read_bytes())
        for record in result:
            if record["address"] == LIVE:
                assert ack_window is not None
                assert int(ack_window[0]) + 599 <= record["expiry"] <= int(ack_window[1]) + 601
                record["expiry"] = "ack+600s"
            else:
                assert record["expiry"] == 0, "restored infinite lifetime changed"
        return result

    def exchange_dns(label, packet):
        observed, raw = [], []
        client.sendto(packet, LISTEN)
        deadline = time.monotonic() + 3
        while True:
            ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
            assert ready, (label, "DNS timeout")
            if upstream in ready:
                sent, peer = upstream.recvfrom(65535)
                decoded = decode(sent)
                decoded["id"] = 0
                observed.append(decoded)
                answer = upstream_reply(sent)
                raw.append({"request": sent.hex(), "response": answer.hex(), "peer": peer})
                upstream.sendto(answer, peer)
            if client in ready:
                answer = client.recv(65535)
                break
        assert answer[:2] == packet[:2], "recipient ID changed"
        assert not select.select([client, upstream], [], [], .01)[0], "extra DNS datagram"
        wires.append({"label": label, "protocol": "dns", "request": packet.hex(), "response": answer.hex(), "upstream": raw})
        return {"response": decode(answer), "question": answer[12:read_name(answer, 12)[1] + 4].hex(),
                "upstream": observed, "cached": not observed}

    def exchange_dhcp(item):
        nonlocal ack_window
        kind = item["kind"]
        xid = 0x7200 + kind
        packet = dhcp_packet(kind, xid, client=3, address=LIVE, selecting=kind == 3)
        original, renamed = b"\x0c\x07client3", b"\x0c\x07client1"
        assert packet.count(original) == 1
        packet = packet.replace(original, renamed)
        sent = time.time()
        dhcp.sendto(packet, ("255.255.255.255", 67))
        answer, peer = dhcp.recvfrom(16384)
        received = time.time()
        options = decode_dhcp(answer, xid)
        assert peer[1] == 67 and socket.inet_ntoa(answer[16:20]) == LIVE
        assert options[53] == bytes([2 if kind == 1 else 5])
        assert struct.unpack("!I", options[51])[0] == 600
        assert [struct.unpack("!I", options[code])[0] for code in (58, 59)] == [300, 525]
        if kind == 3:
            ack_window = (sent, received)
            deadline = time.monotonic() + 3
            while not any(row["address"] == LIVE for row in lease_rows(leasefile)):
                assert fixture.daemon.poll() is None and time.monotonic() < deadline, "ACK lease not persisted"
                time.sleep(.01)
        wires.append({"label": item["label"], "protocol": "dhcp", "request": packet.hex(), "response": answer.hex(),
                      "peer": peer, "sent": sent, "received": received})
        return {"fixed_prefix": answer[:4].hex(), "flags": answer[10:12].hex(),
                "ciaddr": answer[12:16].hex(), "yiaddr": answer[16:20].hex(),
                "siaddr": answer[20:24].hex(), "giaddr": answer[24:28].hex(),
                "chaddr": answer[28:44].hex(), "options": {str(code): value.hex() for code, value in options.items()}}

    try:
        fixture.start_bus()
        command = [str(binary), "--no-daemon", "--conf-file=" + str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        wait_bound(fixture.daemon)
        ready = exchange_dns("ready", request("ready.test", 1, 0x3000, opt=False))
        assert ready["cached"] and ready["response"]["records"][0]["data"] == ipaddress.ip_address("192.0.2.41").packed.hex()
        for index, item in enumerate(profile["actions"]):
            row = {"label": item["label"], "op": item["op"]}
            if item["op"] == "file":
                row["leases"] = snapshot(item["label"])
            elif item["op"] == "dns":
                row.update(exchange_dns(item["label"], request(item["host"], item["kind"], 0x4100 + index, opt=False)))
            else:
                row["reply"] = exchange_dhcp(item)
                row["leases"] = snapshot(item["label"])
            row["metrics"] = fixture.metrics()
            rows.append(row)
        fixture.daemon.send_signal(signal.SIGTERM)
        fixture.daemon.wait(3)
        assert fixture.daemon.returncode == 0
        return rows
    finally:
        dhcp.close()
        client.close()
        upstream.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires,
                                                   "checks": fixture.checks, "ubus": fixture.raw}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("missing, extra or reordered rows")
    return [{"label": left["label"], "c": left, "rust": right}
            for left, right in zip(expected, actual) if left != right]


def calibrate(rows, profile):
    assert len(rows) == len(profile["actions"])
    for row, action in zip(rows, profile["actions"]):
        assert row["label"] == action["label"]
        if action["op"] == "file":
            assert len(row["leases"]) == 2
        elif action["op"] == "dns":
            values = action["values"]
            assert row["cached"] == bool(values), (action["label"], "cache", row["cached"])
            assert len(row["upstream"]) == int(not values)
            assert row["response"]["flags"] & 15 == (0 if values else 3), (action["label"], "rcode")
            answers = [record for record in row["response"]["records"] if record["section"] == "answer"]
            if action["kind"] == 1:
                actual = [str(ipaddress.ip_address(bytes.fromhex(record["data"]))) for record in answers]
            else:
                actual = row["response"]["ptr_case"]
            assert actual == values, (action["label"], actual, values)
            assert all(record["type"] == action["kind"] and record["ttl"] == 60 for record in answers)
        elif action["kind"] == 3:
            owners = {record["address"]: record["name"] for record in row["leases"]}
            assert owners == {FIRST: "*", SECOND: "client1", LIVE: "client1"}, owners
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows)
    index = next(i for i, row in enumerate(changed) if row["op"] == "dns")
    changed[index]["response"]["flags"] ^= 0x20
    assert [row["label"] for row in compare(rows, changed)] == [changed[index]["label"]]
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing row accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("c", "rust"))
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--c-baseline", type=Path, action="append", default=[])
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(label for _, label in socket.if_nameindex()) == ["lo"]
    args.reference_build = args.reference_build.resolve()
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    if args.phase == "c":
        binary = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
        reference = verify_reference(binary, args.c_identity)
        baselines = []
    else:
        assert args.rust is not None and len(args.c_baseline) == 2
        binary, reference = args.rust.resolve(), None
        baselines = []
        for path in args.c_baseline:
            result = json.loads((path / "result.json").read_text())
            assert not result["failures"] and result["observed"] == 22 and result["phase"] == "c"
            assert result["tool_sha256"] == digest(__file__)
            assert json.loads((path / "matrix.json").read_text()) == profiles()
            baselines.append((path, result))
        assert {result["reference"]["kind"] for _, result in baselines} == {"native-glibc", "image-aarch64-musl"}
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "fqdn-restore", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"phase": args.phase, "reference": reference, "native_client_build": native,
              "rust_sha256": digest(binary) if args.phase == "rust" else None,
              "tool_sha256": digest(__file__), "profiles": [], "failures": [],
              "baselines": [{"reference": result["reference"], "result_sha256": digest(path / "result.json"),
                             "matrix_sha256": digest(path / "matrix.json")} for path, result in baselines]}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    for profile in profiles():
        work = out / profile["label"]
        rows, failures, comparisons = [], [], []
        try:
            rows = run(args, binary, "C" if args.phase == "c" else "Rust", profile, work)
            if args.phase == "c":
                calibrate(rows, profile)
            else:
                for baseline, result in baselines:
                    expected = json.loads((baseline / profile["label"] / "trace.json").read_text())["rows"]
                    calibrate(expected, profile)
                    differences = compare(expected, rows)
                    comparisons.append({"reference": result["reference"]["kind"], "differences": differences})
        except Exception as error:
            failures.append(repr(error))
            if not rows and (work / "trace.json").exists():
                rows = json.loads((work / "trace.json").read_text())["rows"]
        report["profiles"].append({"label": profile["label"], "observed": len(rows), "failures": failures,
                                   "comparisons": comparisons})
        report["failures"].extend({"profile": profile["label"], "error": error} for error in failures)
        save()
    report["observed"] = sum(profile["observed"] for profile in report["profiles"])
    report["mismatches"] = sum(len(compare["differences"]) for profile in report["profiles"] for compare in profile["comparisons"])
    save()
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
