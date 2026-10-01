#!/usr/bin/env python3
"""C-first DO/AD/CD cache admission, replay and forwarding identity boundary."""
import argparse
import copy
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import name, query, read_name, rr, semantics
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, Fixture, digest

ROOT = Path(__file__).resolve().parents[2]
LISTEN = ("127.0.0.1", 15353)


def request(host, kind, ident, ad=False, cd=False, do=False, opt=True):
    packet = bytearray(query(host, kind, ident))
    struct.pack_into("!H", packet, 2, 0x100 | (0x20 if ad else 0) | (0x10 if cd else 0))
    if opt:
        packet[11] = 1
        packet.extend(b"\0" + struct.pack("!HHIH", 41, 1232, 0x8000 if do else 0, 0))
    return bytes(packet)


def answer(packet, ad, cd, shape="address"):
    decoded = semantics(packet)
    _, end = read_name(packet, 12)
    host, kind, _ = decoded["questions"][0]
    data = bytes([8, 8, 4, 4]) if kind == 1 else bytes.fromhex("20014860486000000000000000008888")
    opt = next((row for row in decoded["records"] if row["type"] == 41), None)
    answers, authority = [], []
    target = "target." + host
    if shape.startswith("cname"):
        answers.append(rr(5, name(target), 90))
    if shape in ("address", "cname"):
        answers.append(rr(kind, data, 120, name(target) if shape == "cname" else b"\xc0\x0c"))
    if shape.endswith("nodata"):
        soa = name("ns.cache.test") + name("hostmaster.cache.test") + struct.pack("!5I", 1, 2, 3, 4, 60)
        authority.append(rr(6, soa, 120, name("cache.test")))
    flags = 0x8180 | (3 if shape.endswith("nx") else 0) | (0x20 if ad else 0) | (0x10 if cd else 0)
    response = (packet[:2] + struct.pack("!5H", flags, 1, len(answers), len(authority), int(opt is not None))
                + packet[12:end + 4] + b"".join(answers + authority))
    if opt is not None:
        response += b"\0" + struct.pack("!HHIH", 41, 1232, opt["ttl"] & 0x8000, 0)
    return response


def matrix():
    for kind in (1, 28):
        for do in (False, True):
            for ad in (False, True):
                for cd in (False, True):
                    for reply_ad in (False, True):
                        for reply_cd in (False, True):
                            label = f"k{kind}-d{int(do)}-a{int(ad)}-c{int(cd)}-ra{int(reply_ad)}-rc{int(reply_cd)}"
                            yield {"label": label, "host": label + ".cache.test", "kind": kind,
                                   "do": do, "ad": ad, "cd": cd, "reply_ad": reply_ad, "reply_cd": reply_cd,
                                   "shape": "address", "cache_records": 1}
    for kind in (1, 28):
        for shape, cache_records in (("cname", 2), ("nx", 1), ("nodata", 2), ("cname-nx", 2), ("cname-nodata", 3)):
            label = f"anchor-{shape}-k{kind}"
            yield {"label": label, "host": label + ".cache.test", "kind": kind, "do": True,
                   "ad": True, "cd": False, "reply_ad": True, "reply_cd": False,
                   "shape": shape, "cache_records": cache_records}


PAIRS = [
    ("do-ad-toggle", (False, False, True), (True, False, True), True),
    ("ad-do-toggle", (True, False, False), (True, False, True), False),
    ("ordinary-ad-toggle", (False, False, False), (True, False, False), False),
    ("do-cd-toggle", (False, False, True), (False, True, True), False),
    ("ordinary", (False, False, False), (False, False, False), True),
]


def run(args, binary, side, proxy, out):
    out.mkdir()
    fixture = Fixture(args, out)
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.settimeout(2)
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
    rows, wires, upstream_wires = [], [], []
    for client in clients:
        client.settimeout(2)

    def upstream_read():
        packet, peer = upstream.recvfrom(65535)
        upstream_wires.append({"wire": packet.hex(), "peer": peer})
        return packet, peer

    def decode_upstream(packet):
        decoded = semantics(packet)
        decoded["id"] = 0
        return decoded

    def decoded(packet):
        return {"response": semantics(packet), "question": packet[12:read_name(packet, 12)[1] + 4].hex()}

    def exchange(label, client, packet, reply_ad=False, reply_cd=False, shape="address"):
        observed = []
        client.sendto(packet, LISTEN)
        deadline = time.monotonic() + 2
        while True:
            ready, _, _ = select.select([client, upstream], [], [], max(0, deadline - time.monotonic()))
            assert ready, ("DNS response timeout", label)
            if upstream in ready:
                sent, peer = upstream_read()
                observed.append(decode_upstream(sent))
                upstream.sendto(answer(sent, reply_ad, reply_cd, shape), peer)
            if client in ready:
                response = client.recv(65535)
                break
        assert response[:2] == packet[:2], "recipient ID changed"
        assert len(observed) <= 1, (label, "unexpected extra upstream send")
        wires.append({"label": label, "request": packet.hex(), "response": response.hex()})
        return {"label": label, **decoded(response), "upstream": observed, "metrics": fixture.metrics(),
                "cached": not observed}

    try:
        fixture.start_bus()
        config = out / "dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
                          "no-0x20-encode\nno-round-robin\ncache-size=512\nneg-ttl=30\n"
                          "host-record=ready.test,192.0.2.41\n"
                          f"server=127.0.0.1#{upstream.getsockname()[1]}\nenable-ubus={OBJECT}\n"
                          + ("proxy-dnssec\n" if proxy else ""))
        command = [str(binary), "-k", "-C", str(config)]
        if side == "C":
            command += ["--user=root", "--group=root", "--log-facility=-", "--pid-file=" + str(out / "pid")]
        fixture.daemon, _ = fixture.spawn(command, "daemon")
        fixture.wait_registered()
        ready = exchange("ready", clients[0], request("ready.test", 1, 0x3000, opt=False))
        assert ready["cached"]
        for index, case in enumerate(matrix()):
            start = 0x4000 + index * 5
            before = fixture.metrics()
            steps = [
                ("seed", case["ad"], case["cd"], case["do"], True),
                ("plain", False, False, False, False),
                ("ad", True, False, False, True),
                ("do", False, False, True, True),
                ("cd", False, True, False, True),
            ]
            for offset, (step, ad, cd, do, opt) in enumerate(steps):
                row = exchange(case["label"] + "/" + step, clients[0],
                               request(case["host"], case["kind"], start + offset, ad, cd, do, opt),
                               case["reply_ad"], case["reply_cd"], case["shape"])
                row["case"], row["step"], row["before"] = case, step, before
                rows.append(row)
                before = row["metrics"]

        for index, (label, first_flags, second_flags, coalesces) in enumerate(PAIRS):
            host = label + ".Coalesce.test"
            first = request(host, 1, 0x7000 + 2 * index, *first_flags)
            second = request(host.swapcase(), 1, 0x7001 + 2 * index, *second_flags)
            before = fixture.metrics()
            clients[0].sendto(first, LISTEN)
            held, peer = upstream_read()
            clients[1].sendto(second, LISTEN)
            ready, _, _ = select.select([upstream], [], [], .05)
            another = upstream_read() if ready else None
            clients[0].sendto(first, LISTEN)
            retried, retry_peer = upstream_read()
            same_retry = peer == retry_peer and held == retried
            upstream.sendto(answer(held, True, False), peer)
            if another is not None:
                upstream.sendto(answer(another[0], True, False), another[1])
            replies = [client.recv(65535) for client in clients]
            for packet, reply in zip((first, second), replies):
                assert packet[:2] == reply[:2]
            wires.append({"label": label, "requests": [first.hex(), second.hex()], "responses": [p.hex() for p in replies]})
            rows.append({"label": "coalesce/" + label, "coalesced": another is None,
                         "same_retry_socket_and_packet": same_retry,
                         "responses": [decoded(packet) for packet in replies],
                         "upstream": [decode_upstream(held)] + ([] if another is None else [decode_upstream(another[0])])
                                     + [decode_upstream(retried)], "before": before, "metrics": fixture.metrics()})
            assert not select.select([clients[0], clients[1], upstream], [], [], .02)[0], "extra datagram after completion"
        fixture.daemon.send_signal(signal.SIGTERM)
        fixture.daemon.wait(3)
        assert fixture.daemon.returncode == 0
        assert not Path(f"/proc/{fixture.daemon.pid}").exists()
        return rows
    finally:
        for client in clients:
            client.close()
        upstream.close()
        fixture.close()
        (out / "trace.json").write_text(json.dumps({"rows": rows, "wires": wires, "upstream_wires": upstream_wires,
                                                   "raw": fixture.raw, "checks": fixture.checks}, indent=2) + "\n")
        assert all(row["pass"] for row in fixture.checks)


def calibrate(rows, proxy):
    assert len(rows) == len(list(matrix())) * 5 + len(PAIRS)
    for row in rows:
        if "case" not in row:
            label = row["label"].removeprefix("coalesce/")
            expected = next(pair[3] for pair in PAIRS if pair[0] == label)
            assert row["coalesced"] == expected and row["same_retry_socket_and_packet"]
            continue
        case, step = row["case"], row["step"]
        if step == "seed":
            delta = row["metrics"]["dns_cache_inserted"] - row["before"]["dns_cache_inserted"]
            assert delta == case["cache_records"] * int(not case["cd"] and not case["reply_cd"]), (row["label"], delta)
        if step == "do":
            assert len(row["upstream"]) == 1, "DO bypasses dynamic cache in nodhcpv6"
        if step == "ad":
            assert row["cached"] == (not case["reply_cd"])
        if row["cached"]:
            assert row["response"]["flags"] & 0x20 == 0, "unsigned cache must not assert AD"
        else:
            assert bool(row["response"]["flags"] & 0x20) == (proxy and case["reply_ad"])
        expected_cd = case["cd"] if step == "seed" else step == "cd"
        assert bool(row["response"]["flags"] & 0x10) == expected_cd


def compare(expected, actual):
    if [row["label"] for row in expected] != [row["label"] for row in actual]:
        raise ValueError("observation count or labels differ")
    differences = []
    for left, right in zip(expected, actual):
        c, rust = copy.deepcopy(left), copy.deepcopy(right)
        if c.get("cached") and rust.get("cached"):
            for a, b in zip(c["response"]["records"], rust["response"]["records"]):
                if a["type"] != 41 and abs(a["ttl"] - b["ttl"]) <= 1:
                    b["ttl"] = a["ttl"]
        if c != rust:
            differences.append({"label": c["label"], "c": c, "rust": rust})
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-binary", type=Path)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    if args.inject_error and args.rust is None:
        parser.error("negative control requires Rust")
    c = (args.c_binary or args.reference_build / "dnsmasq/dnsmasq").resolve()
    reference = verify_reference(c, args.c_identity)
    native = verify_reference(args.reference_build / "dnsmasq/dnsmasq", None)
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    (out / "tool.py").write_bytes(Path(__file__).read_bytes())
    (out / "matrix.json").write_text(json.dumps(list(matrix()), indent=2) + "\n")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dns-do-cache", "/run"], check=True)
    Path(BUS).parent.mkdir()
    report = {"reference": reference, "native_client_build": native, "tool_sha256": digest(__file__),
              "rust_sha256": None if args.rust is None else digest(args.rust), "c_only": args.rust is None,
              "profiles": [], "failures": [], "injected_error": args.inject_error}
    for proxy in (False, True):
        work = out / ("proxy" if proxy else "ordinary")
        work.mkdir()
        stage = "C"
        try:
            expected = run(args, c, "C", proxy, work / "c")
            calibrate(expected, proxy)
            assert not compare(expected, copy.deepcopy(expected))
            changed = copy.deepcopy(expected)
            changed[0]["response"]["flags"] ^= 0x20
            assert len(compare(expected, changed)) == 1
            try:
                compare(expected, expected[:-1])
            except ValueError:
                pass
            else:
                raise AssertionError("missing row calibration")
            differences = []
            if args.rust is not None:
                stage = "Rust"
                actual = run(args, args.rust.resolve(), "Rust", proxy, work / "rust")
                if args.inject_error and not proxy:
                    actual[0]["response"]["flags"] ^= 0x20
                differences = compare(expected, actual)
            report["profiles"].append({"proxy": proxy, "observations": len(expected), "differences": differences})
        except Exception as error:
            report["failures"].append({"proxy": proxy, "stage": stage, "error": repr(error)})
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    report["compared"] = 0 if args.rust is None else sum(row["observations"] for row in report["profiles"])
    report["mismatches"] = sum(len(row["differences"]) for row in report["profiles"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "profiles"}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__ == "__main__":
    raise SystemExit(main())
