#!/usr/bin/env python3
"""Independent C-first reachable CNAME/local-reverse metadata addon (28 events)."""
import argparse
import copy
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

from dns_do_cache_diff import request
from dns_generic_malformed_diff import ede_codes
from dns_reverse_cache_diff import decode
from dns_reverse_lease_diff import ADDRESS, DYNAMIC, FQDN, OWNER, ManagedDaemon, canonical_dhcp, file_snapshot
from dns_service_probe import name, read_name, rr
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)
TERMINAL = "terminal.alias.test"
RESULT = "cname.result.test"


def query(label, kind=12, rd=True, do=False, cd=False, opt=None, shape="failure", cached=True, targets=None, chain=False):
    return {"op": "dns", "label": label, "kind": kind, "rd": rd, "do": do, "cd": cd,
            "opt": do if opt is None else opt, "shape": shape, "cached": cached,
            "targets": targets or [], "chain": chain}


def profiles():
    cname = [
        query("seed-cname", shape="cname", cached=False, targets=[RESULT], chain=True),
        {"op": "offer", "label": "offer"}, {"op": "ack", "label": "ack"},
        {**query("short-published", kind=1, targets=[ADDRESS]), "host": "client1"},
        query("cname-before-local", targets=[RESULT], chain=True),
        query("rd0-rejects-cname", rd=False, cached=False),
        query("do-rejects-cname", do=True, cached=False),
        query("cname-still-cached", targets=[RESULT], chain=True),
    ]
    setup = [{"op": "hold", "label": "hold"}, {"op": "offer", "label": "offer"},
             {"op": "ack", "label": "ack"}, {"op": "deliver", "label": "deliver", "ttl": 120}]
    coexist = copy.deepcopy(setup)
    for kind in (12, 255):
        for rd in (True, False):
            for do in (False, True):
                coexist.append(query(f"k{kind}-rd{int(rd)}-do{int(do)}", kind, rd, do,
                                     targets=[FQDN, DYNAMIC] if kind == 12 else [FQDN]))
    for kind in (12, 255):
        coexist.append(query(f"k{kind}-do-cd", kind, do=True, cd=True,
                             targets=[FQDN, DYNAMIC] if kind == 12 else [FQDN]))
    stale = copy.deepcopy(setup)
    stale[-1]["ttl"] = 1
    stale += [{"op": "wait", "after": "deliver", "seconds": 2.1},
              {**query("stale-any", 255, opt=True, targets=[FQDN]), "op": "stale"},
              {"op": "refresh", "label": "background-refresh"}]
    result = [{"label": "cname-before-lease", "extra": "", "actions": cname},
              {"label": "coexist-flags", "extra": "", "actions": coexist},
              {"label": "stale-any-visit", "extra": "use-stale-cache=60\n", "actions": stale}]
    assert [sum(item["op"] != "wait" for item in profile["actions"]) for profile in result] == [8, 14, 6]
    return result


def response(packet, shape, ttl=120):
    _, end = read_name(packet, 12)
    question = packet[12:end + 4]
    flags = 0x8080 | (struct.unpack_from("!H", packet, 2)[0] & 0x110)
    if shape == "cname":
        answers = [rr(5, name(TERMINAL), 90), rr(12, name(RESULT), 120, name(TERMINAL))]
    elif shape == "positive":
        answers = [rr(12, name(DYNAMIC), ttl)]
    else:
        assert shape in ("failure", "empty")
        answers = []
        if shape == "failure":
            flags |= 2
    opt = next((record for record in decode(packet)["records"] if record["type"] == 41), None)
    return (packet[:2] + struct.pack("!5H", flags, 1, len(answers), 0, int(opt is not None)) + question
            + b"".join(answers) + (b"\0" + struct.pack("!HHIH", 41, 1232, opt["ttl"] & 0x8000, 0) if opt else b""))


def packet_for(item, ident):
    packet = bytearray(request(item.get("host", OWNER), item.get("kind", 12), ident,
                               do=item.get("do", False), cd=item.get("cd", False), opt=item.get("opt", False)))
    if not item.get("rd", True):
        packet[2] &= ~1
    return bytes(packet)


def run_service(args, binary, side, profile, out):
    out.mkdir()
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    leases, hosts = out / "leases", out / "hosts"
    leases.write_bytes(b"")
    hosts.write_text("192.0.2.41 ready.test\n")
    config = out / "dnsmasq.conf"
    config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\nno-ping\n"
                      "dhcp-authoritative\ndhcp-lease-max=150\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                      "domain=leases.test\nlocal-ttl=17\ndhcp-ttl=60\ncache-size=32\nno-0x20-encode\nno-round-robin\n"
                      + f"dhcp-leasefile={leases}\naddn-hosts={hosts}\nserver=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n"
                      + profile["extra"])
    rows, wires, waits, checks = [], [], [], []
    held, delivered_at, refresh_client = None, None, None
    daemon = ManagedDaemon(binary, config, leases, out, checks, profile["label"], fixture=fixture, side=side)
    def receive_client(label, packet, observed, raw):
        reply = client.recv(65535)
        assert reply[:2] == packet[:2], "recipient ID changed"
        wires.append({"label": label, "request": packet.hex(), "response": reply.hex(), "upstream": raw})
        return {"response": decode(reply), "question": reply[12:read_name(reply, 12)[1] + 4].hex(),
                "cached": not observed, "upstream": observed}
    def exchange(label, packet, shape):
        observed, raw = [], []
        client.sendto(packet, LISTEN)
        deadline = time.monotonic() + 3
        while True:
            ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
            assert ready, (label, "DNS response timeout")
            if upstream in ready:
                sent, peer = upstream.recvfrom(65535)
                decoded = decode(sent); decoded["id"] = 0
                observed.append(decoded)
                answer = response(sent, shape)
                raw.append({"request": sent.hex(), "response": answer.hex(), "peer": peer})
                upstream.sendto(answer, peer)
            if client in ready:
                row = receive_client(label, packet, observed, raw)
                break
        assert not select.select([client, upstream], [], [], .01)[0], "extra datagram"
        return row
    try:
        fixture.start_bus()
        daemon.start()
        ready = exchange("ready", request("ready.test", 1, 0x3000, opt=False), "failure")
        assert ready["cached"] and ready["response"]["records"][0]["data"] == "c0000229"
        for item in profile["actions"]:
            op = item["op"]
            if op == "wait":
                assert delivered_at is not None
                start = time.monotonic()
                until = delivered_at + item["seconds"]
                while time.monotonic() < until:
                    assert daemon.process.poll() is None
                    time.sleep(max(0, min(.05, until - time.monotonic())))
                waits.append({**item, "started": start, "finished": time.monotonic(), "wall": time.time()})
                continue
            label = item["label"]
            row = {"op": op, "label": label}
            if op == "dns":
                row.update(exchange(label, packet_for(item, 0x6100 + len(rows)), item["shape"]))
            elif op in ("offer", "ack"):
                reply = daemon.exchange(1 if op == "offer" else 3, 1, ADDRESS, selecting=op == "ack")
                row.update(reply=canonical_dhcp(reply), leases=file_snapshot(daemon, leases))
                (out / f"{label}.leases").write_bytes(leases.read_bytes())
            elif op == "hold":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(3)
                packet = packet_for({}, 0x6100 + len(rows)); sock.sendto(packet, LISTEN)
                assert select.select([upstream], [], [], 3)[0], "held query did not forward"
                sent, peer = upstream.recvfrom(65535)
                assert not select.select([sock], [], [], .01)[0], "premature recipient answer"
                held = (sock, packet, sent, peer)
                decoded = decode(sent); decoded["id"] = 0
                row.update(upstream=[decoded], recipient_answered=False)
                wires.append({"label": label, "request": packet.hex(), "upstream_request": sent.hex(), "peer": peer})
            elif op == "deliver":
                assert held is not None
                sock, packet, sent, peer = held
                answer = response(sent, "positive", item["ttl"]); upstream.sendto(answer, peer)
                reply = sock.recv(65535); assert reply[:2] == packet[:2]
                delivered_at = time.monotonic()
                row.update(response=decode(reply), question=reply[12:read_name(reply, 12)[1] + 4].hex(), cached=False, upstream=[])
                wires.append({"label": label, "response": reply.hex(), "upstream_response": answer.hex()})
                sock.close(); held = None
            elif op == "stale":
                packet = packet_for(item, 0x6100 + len(rows)); client.sendto(packet, LISTEN)
                # Deliberately withhold any refresh response until the client
                # receives the stale answer; this is a logical ordering gate.
                assert select.select([client], [], [], 3)[0], "stale answer waited for upstream"
                row.update(receive_client(label, packet, [], []))
                row["received_before_refresh_answer"] = True
                refresh_client = packet
            elif op == "refresh":
                assert refresh_client is not None
                assert select.select([upstream], [], [], 3)[0], "background refresh missing"
                sent, peer = upstream.recvfrom(65535)
                decoded = decode(sent); decoded["id"] = 0
                answer = response(sent, "empty"); upstream.sendto(answer, peer)
                row["upstream"] = [decoded]
                wires.append({"label": label, "upstream_request": sent.hex(), "upstream_response": answer.hex(), "peer": peer})
                row["metrics"] = fixture.metrics()
                row["extra_recipient_or_upstream"] = bool(select.select([client, upstream], [], [], .05)[0])
                assert not row["extra_recipient_or_upstream"], "extra refresh or duplicate recipient answer"
                refresh_client = None
            else:
                raise AssertionError(op)
            if "metrics" not in row:
                row["metrics"] = fixture.metrics()
            rows.append(row)
        assert held is None and refresh_client is None
        daemon.stop()
        assert all(check["pass"] for check in checks), checks
        return rows
    finally:
        if held is not None: held[0].close()
        daemon.stop(); client.close(); upstream.close(); fixture.close()
        (out / "trace.json").write_text(json.dumps({"observations": rows, "wires": wires, "waits": waits,
                                                   "dhcp_checks": checks, "dhcp_responses": daemon.responses,
                                                   "ubus_raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(check["pass"] for check in fixture.checks)


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("missing observation or reordered labels")
    result = []
    dynamic = {name(DYNAMIC.lower()).hex(), name(RESULT).hex()}
    for left, right in zip(expected, actual):
        c, rust = copy.deepcopy(left), copy.deepcopy(right)
        if c.get("cached") and rust.get("cached"):
            for a, b in zip(c["response"]["records"], rust["response"]["records"]):
                phase = a["type"] == b["type"] == 5 or (a["type"] == b["type"] == 12 and a["data"] == b["data"] and a["data"] in dynamic)
                if phase and abs(a["ttl"] - b["ttl"]) <= 1:
                    b["ttl"] = a["ttl"]
        if c != rust:
            result.append({"label": left["label"], "c": c, "rust": rust})
    return result


def calibrate(rows, profile):
    actions = [item for item in profile["actions"] if item["op"] != "wait"]
    assert [row["label"] for row in rows] == [item["label"] for item in actions]
    for row, item in zip(rows, actions):
        op = item["op"]
        if op in ("dns", "stale"):
            message = row["response"]
            assert row["cached"] == item["cached"], (row["label"], "cache")
            assert len(row["upstream"]) == (0 if item["cached"] else 1 if item["shape"] == "cname" else 2), (row["label"], "upstream")
            assert message["flags"] & 15 == (0 if item["targets"] else 2), (row["label"], "rcode")
            assert bool(message["flags"] & 0x10) == item["cd"] and not message["flags"] & 0x20
            assert bool(message["flags"] & 0x100) == item["rd"]
            records = [record for record in message["records"] if record["section"] == "answer"]
            if item["kind"] == 1:
                assert [record["data"] for record in records] == ["7f00000a"]
            else:
                assert message["ptr_case"] == item["targets"], (row["label"], "PTR order", message["ptr_case"])
                kinds = ([5] if item["chain"] else []) + [12] * len(item["targets"])
                assert [record["type"] for record in records] == kinds
                if item["targets"]:
                    local_only = item["targets"] == [FQDN]
                    assert bool(message["flags"] & 0x400) == local_only, (row["label"], "AA")
                    for record in records:
                        if record["type"] == 12 and record["data"] == name(FQDN).hex():
                            assert record["ttl"] == 60
            if op == "stale":
                assert ede_codes(message) == [3] and row["received_before_refresh_answer"]
                assert row["metrics"]["dns_stale_answered"] == 1
        elif op == "offer":
            assert row["leases"] == []
        elif op == "ack":
            assert len(row["leases"]) == 1 and row["leases"][0]["address"] == ADDRESS and row["leases"][0]["name"] == "client1"
        elif op == "hold":
            assert len(row["upstream"]) == 1 and not row["recipient_answered"]
        elif op == "deliver":
            assert row["response"]["ptr_case"] == [DYNAMIC]
        elif op == "refresh":
            assert len(row["upstream"]) == 1 and row["upstream"][0]["questions"] == [[OWNER, 255, 1]]
            assert not row["extra_recipient_or_upstream"]
            assert row["metrics"]["dns_queries_forwarded"] == 2 and row["metrics"]["dns_cache_inserted"] == 1
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows); at = next(i for i, row in enumerate(changed) if "response" in row)
    changed[at]["response"]["flags"] ^= 0x20
    assert len(compare(rows, changed)) == 1
    try: compare(rows, rows[:-1])
    except ValueError: pass
    else: raise AssertionError("missing observation accepted")


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
    if args.inject_error and args.rust is None: parser.error("negative requires Rust")
    args.reference_build = args.reference_build.resolve()
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(profiles(), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "reverse-local-addon", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "base_helper_sha256": digest(Path(__file__).with_name("dns_reverse_lease_diff.py")),
              "rust_sha256": None if args.rust is None else digest(args.rust), "profiles": [], "failures": [], "injected_error": args.inject_error}
    save = lambda: (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    expected_profiles = []
    for profile in profiles():
        work = out / profile["label"]; work.mkdir()
        try:
            expected = run_service(args, c, "C", profile, work / "c"); calibrate(expected, profile)
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
                    if args.inject_error and index == 0: actual[0]["response"]["flags"] ^= 0x20
                    differences = compare(expected, actual)
                report["profiles"].append({"profile": profile["label"], "observations": len(expected), "differences": differences})
            except Exception as error:
                report["failures"].append({"profile": profile["label"], "stage": "Rust", "error": repr(error)})
            save()
    report["c_calibrated"] = sum(len(rows) for _, rows, _ in expected_profiles)
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    save(); print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
