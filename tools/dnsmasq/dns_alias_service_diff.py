#!/usr/bin/env python3
"""Exact C/Rust static alias service gate in a loopback-only namespace.

The exact C daemon always runs first. Raw packets, configurations, events and
ELF identities are retained under private/. This is a correctness gate, not a
benchmark or a claim about synchronous ubus notifications.
"""
import argparse
import copy
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, read_name, semantics
from dns_udp_refusal_diff import verify_reference


def rr(kind, data, owner=b"\xc0\x0c", cls=1, ttl=120):
    return owner + struct.pack("!HHIH", kind, cls, ttl, len(data)) + data


def address(text):
    return ipaddress.ip_address(text).packed


def query(host, ident, kind=1, edns=False):
    packet = struct.pack("!6H", ident, 0x100, 1, 0, 0, int(edns))
    packet += name(host) + struct.pack("!HH", kind, 1)
    if edns:
        packet += rr(41, b"", b"\0", 1232, 0)
    return packet


def answer(packet):
    host, end = read_name(packet, 12)
    kind = struct.unpack_from("!H", packet, end)[0]
    prefix = host.split(".")[0]
    flags, answers, authorities, additionals = 0x85a0, [], [], []
    data = address("192.0.2.10")
    if prefix == "private":
        data = address("10.0.0.10")
    elif prefix == "to-private":
        data = address("192.0.2.40")
    elif prefix.startswith("range-"):
        data = address("192.0.2." + prefix.removeprefix("range-"))
    if prefix == "sections":
        answers = [rr(1, data)]
        authorities = [rr(1, data, name("ns.test"))]
        additionals = [rr(1, data, name("extra.test"))]
    elif prefix == "cname":
        answers = [rr(5, name("target.test")), rr(1, data, name("target.test"))]
    elif prefix == "unknown":
        answers = [rr(kind, b"\xc0\x0c" + data)]
    elif prefix == "aaaa":
        answers = [rr(28, address("2001:db8::10"))]
    elif prefix == "non-in":
        answers = [rr(1, data, cls=3)]
    else:
        answers = [rr(1, data)]
    if prefix in ("nx", "known-nx"):
        flags |= 3
    elif prefix == "tc":
        flags |= 0x200
    elif prefix == "error":
        flags |= 2
    elif prefix == "opcode":
        flags |= 1 << 11
    if prefix == "extended":
        additionals.append(rr(41, b"", b"\0", 4096, 1 << 24))
    elif semantics(packet)["records"]:
        additionals.append(rr(41, b"", b"\0", 4096, 0))
    return (packet[:2] + struct.pack("!5H", flags, 1, len(answers), len(authorities), len(additionals))
            + packet[12:end + 4] + b"".join(answers + authorities + additionals))


class Upstream:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0)); self.udp.settimeout(.05)
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port)); self.tcp.listen(); self.tcp.settimeout(.05)
        self.stop = threading.Event()
        self.events, self.failures = [], []
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:
            thread.start()

    def response(self, packet, transport):
        host, _ = read_name(packet, 12)
        self.events.append({"transport": transport, "query": (b"\0\0" + packet[2:]).hex()})
        if host == "merged.test":
            time.sleep(.08)
        return answer(packet)

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                self.udp.sendto(self.response(packet, "udp"), peer)
            except Exception as error:
                self.failures.append(repr(error))

    def tcp_loop(self):
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
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
                        response = self.response(packet, "tcp")
                        client.sendall(struct.pack("!H", len(response)) + response)
            except Exception as error:
                self.failures.append(repr(error))

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(2)
        self.udp.close(); self.tcp.close()
        assert all(not thread.is_alive() for thread in self.threads), "upstream thread leaked"


BASE = "alias=192.0.2.10,198.51.100.20\nalias=198.51.100.20,203.0.113.30\n"


def schedule():
    base = [(host, kind, edns) for host, kind in [
        ("normal", 1), ("sections", 1), ("cname", 1), ("unknown", 65400),
        ("aaaa", 28), ("non-in", 1), ("nx", 1), ("known-nx", 16),
        ("tc", 1), ("error", 1), ("opcode", 1), ("extended", 1), ("local", 1)]
        for edns in (False, True)]
    return [
        ("ordinary", BASE, base),
        ("newest", BASE + "alias=192.0.2.10,203.0.113.99\n", [("normal", 1, False)]),
        ("range", "alias=192.0.2.10-192.0.2.20,198.51.100.0,255.255.255.0\n",
         [("range-" + str(value), 1, False) for value in (9, 10, 20, 21)]),
        ("zero-mask", "alias=0.0.0.0,203.0.113.0,0.0.0.0\n", [("normal", 1, False)]),
        ("rebind", BASE + "stop-dns-rebind\nalias=192.0.2.10,8.8.8.20\nalias=192.0.2.40,10.0.0.40\nalias=10.0.0.10,8.8.8.10\n",
         [(host, 1, edns) for host in ("normal", "to-private", "private") for edns in (False, True)]),
        ("bogus-destination", BASE + "bogus-nxdomain=198.51.100.20\n",
         [(host, 1 if host != "known-nx" else 16, edns) for host in ("normal", "nx", "known-nx") for edns in (False, True)]),
        ("bogus-source", BASE + "bogus-nxdomain=192.0.2.10\n", [("normal", 1, False)]),
        ("ignore-destination", BASE + "ignore-address=198.51.100.20\n", [("normal", 1, False)]),
        ("ignore-source", BASE + "ignore-address=192.0.2.10\n", [("normal", 1, False)]),
    ]


def check_equal(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("completed observation count mismatch")
    failures = []
    for left, right in zip(expected, actual):
        a, b = copy.deepcopy(left), copy.deepcopy(right)
        for row in (a, b):
            row.pop("raw", None)
            row.pop("elapsed", None)
            row.pop("cache_age_window", None)
        if "cache_age_window" in left and "cache_age_window" in right:
            for x, y in zip(a["responses"], b["responses"]):
                if x is None or y is None:
                    continue
                for c, r in zip(x["records"], y["records"]):
                    tolerance = math.ceil(max(left["cache_age_window"], right["cache_age_window"]))
                    # OPT's TTL-shaped field contains protocol flags/RCODE,
                    # not cache time, and must always compare exactly.
                    if c["type"] != 41 and r["type"] != 41 and abs(c["ttl"] - r["ttl"]) <= tolerance:
                        r["ttl"] = c["ttl"]
        if a != b:
            failures.append({"label": left["label"], "c": a, "rust": b})
    return failures


def count_observations(counts, rows):
    for row in rows:
        counts["observations"] += 1
        counts["upstream_queries"] += len(row["upstream"])
        for response in row["responses"]:
            counts["client_requests"] += 1
            if response is None:
                counts["client_timeouts"] += 1
                continue
            counts["client_replies"] += 1
            rcode = response["flags"] & 15
            for record in response["records"]:
                if record["section"] == "additional" and record["type"] == 41:
                    rcode |= (record["ttl"] >> 24) << 4
                    break
            key = str(rcode)
            counts["rcode_counts"][key] = counts["rcode_counts"].get(key, 0) + 1


def observe(port, transport, label, packets, upstream):
    start = len(upstream.events)
    before = time.monotonic()
    raw, clients = [], []
    try:
        for packet in packets:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
            client.settimeout(.35)
            clients.append(client)
            if transport == "udp":
                client.sendto(packet, ("127.0.0.1", port))
            else:
                client.connect(("127.0.0.1", port))
                client.sendall(struct.pack("!H", len(packet)) + packet)
        for client, request in zip(clients, packets):
            try:
                response = client.recv(65535) if transport == "udp" else exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
            except socket.timeout:
                raw.append(None)
                continue
            assert response[:2] == request[:2], "client ID changed"
            raw.append(response.hex())
    finally:
        for client in clients:
            client.close()
    return {"label": label, "responses": [semantics(bytes.fromhex(value)) if value else None for value in raw],
            "raw": raw, "upstream": copy.deepcopy(upstream.events[start:]), "elapsed": time.monotonic() - before}


def run(binary, config, port, work, upstream, cases, transport, cache=False):
    work.mkdir()
    rows = []
    with (work / "stderr.log").open("wb") as log:
        process = subprocess.Popen([str(binary.resolve()), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "daemon exited before readiness"
                try:
                    with socket.create_connection(("127.0.0.1", port), .05):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("readiness timeout")
                    time.sleep(.02)
            primed_at = {}
            for index, (host, kind, edns) in enumerate(cases):
                label = f"{transport}-{host}-type{kind}-edns{int(edns)}"
                start = time.monotonic()
                rows.append(observe(port, transport, label, [query(host + ".test", 0x4000 + index, kind, edns)], upstream))
                # This fixed subset is established by the exact C baseline:
                # plain first query fills an ordinary positive cache entry.
                if cache and host in ("normal", "sections", "cname", "aaaa"):
                    if edns:
                        rows[-1]["cache_age_window"] = time.monotonic() - primed_at[host]
                    else:
                        primed_at[host] = start
            if cache:
                start = time.monotonic()
                rows.append(observe(port, "udp", "udp-cache-miss", [query("cached.test", 0x5000)], upstream))
                rows.append(observe(port, "udp", "udp-cache-hit", [query("cached.test", 0x5001)], upstream))
                rows[-1]["cache_age_window"] = time.monotonic() - start
                rows.append(observe(port, "udp", "udp-merged", [query("merged.test", 0x5100), query("merged.test", 0x5101)], upstream))
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            process.wait(timeout=3)
            (work / "trace.json").write_text(json.dumps(rows, indent=2) + "\n")
            (work / "process.json").write_text(json.dumps({"exit": process.returncode, "observations": len(rows)}) + "\n")
    assert process.returncode == 0
    assert len(rows) == len(cases) + (3 if cache else 0)
    return rows


def calibrate_reference(group, transport, rows):
    normal = next((row for row in rows if row["label"].endswith("normal-type1-edns0")), None)
    if normal:
        response = normal["responses"][0]
        if group == "ignore-source" and transport == "udp":
            assert response is None and len(normal["upstream"]) == 1
        else:
            assert response is not None
            if group == "bogus-destination":
                assert response["flags"] & 15 == 3 and not response["records"]
            else:
                target = {"newest": "203.0.113.99", "zero-mask": "192.0.2.10", "rebind": "8.8.8.20"}.get(group, "198.51.100.20")
                assert response["records"][0]["data"] == target, (group, response)
                assert response["flags"] & 0x400 == 0
    for row in rows:
        if row["label"].endswith("cache-hit"):
            assert len(row["upstream"]) == 0 and row["responses"][0]["records"][0]["data"] == "198.51.100.20"
        elif row["label"].endswith("merged"):
            assert len(row["upstream"]) == 1 and len(row["responses"]) == 2
            assert all(reply["records"][0]["data"] == "198.51.100.20" for reply in row["responses"])
        elif "-local-" in row["label"]:
            assert not row["upstream"] and row["responses"][0]["records"][0]["data"] == "192.0.2.10"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--c-identity", type=Path)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.inject_error and not args.rust:
        parser.error("--inject-error requires --rust")
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [n for _, n in socket.if_nameindex()] == ["lo"]
    identity = verify_reference(args.c, args.c_identity)
    output = args.output.resolve()
    assert "private" in output.parts and not output.exists()
    output.mkdir(parents=True)
    sample = [{"label": "calibration", "responses": [], "upstream": []}]
    assert not check_equal(sample, copy.deepcopy(sample))
    changed = copy.deepcopy(sample); changed[0]["upstream"].append("unexpected")
    assert len(check_equal(sample, changed)) == 1
    try:
        check_equal(sample, [])
    except ValueError:
        pass
    else:
        raise AssertionError("count calibration failed")
    counters = {"observations": 0, "upstream_queries": 0, "client_requests": 0,
                "client_replies": 0, "client_timeouts": 0, "rcode_counts": {}}
    count_observations(counters, [{"upstream": ["query"], "responses": [
        {"flags": 0, "records": []}, {"flags": 3, "records": []}, None]}])
    assert counters == {"observations": 1, "upstream_queries": 1, "client_requests": 3,
                        "client_replies": 2, "client_timeouts": 1, "rcode_counts": {"0": 1, "3": 1}}
    ttl_sample = [{"label": "ttl-calibration", "cache_age_window": .01,
                   "responses": [{"records": [{"type": 1, "ttl": 120}]}]}]
    changed = copy.deepcopy(ttl_sample); changed[0]["responses"][0]["records"][0]["ttl"] = 119
    assert not check_equal(ttl_sample, changed)
    changed[0]["responses"][0]["records"][0]["ttl"] = 118
    assert len(check_equal(ttl_sample, changed)) == 1
    ttl_sample[0]["responses"][0]["records"][0]["type"] = 41
    changed = copy.deepcopy(ttl_sample); changed[0]["responses"][0]["records"][0]["ttl"] = 119
    assert len(check_equal(ttl_sample, changed)) == 1
    planned = sum(len(cases) * 2 for _, _, cases in schedule()) + 3
    report = {"planned": planned, "c_observations": 0, "compared": 0, "matched": 0,
              "failures": [], "reference": identity, "calibration": {"equal": 1, "mismatch": 1, "count": 1, "response_counters": 1, "ttl_boundaries": 3},
              "tool_sha256": {file.name: hashlib.sha256(file.read_bytes()).hexdigest() for file in
                              [Path(__file__), Path(__file__).with_name("dns_service_probe.py"), Path(__file__).with_name("dns_udp_refusal_diff.py")]},
              "schedule_sha256": hashlib.sha256(json.dumps(schedule(), sort_keys=True).encode()).hexdigest(),
              "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest() if args.rust else None,
              "scope": "static alias upstream UDP/TCP processing, original ignore admission, UDP cache/coalescing; no ubus subscriber"}
    for side in ("c", "rust"):
        report[side + "_counts"] = {"observations": 0, "upstream_queries": 0, "client_requests": 0,
                                    "client_replies": 0, "client_timeouts": 0, "rcode_counts": {}}
    upstream = Upstream()
    injected = False
    try:
        for group, body, cases in schedule():
            for transport in ("udp", "tcp"):
                folder = output / (group + "-" + transport); folder.mkdir()
                with socket.socket() as reserve:
                    reserve.bind(("127.0.0.1", 0)); port = reserve.getsockname()[1]
                cache = group == "ordinary" and transport == "udp"
                config = folder / "dnsmasq.conf"
                config.write_text(f"no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\ncache-size={100 if cache else 0}\nlocal-ttl=120\nedns-packet-max=1232\nserver=127.0.0.1#{upstream.port}\nhost-record=local.test,192.0.2.10\nhost-record=known-nx.test,192.0.2.10\n" + body)
                expected = run(args.c, config, port, folder / "c", upstream, cases, transport, cache)
                calibrate_reference(group, transport, expected)
                report["c_observations"] += len(expected)
                count_observations(report["c_counts"], expected)
                if args.rust:
                    actual = run(args.rust, config, port, folder / "rust", upstream, cases, transport, cache)
                    count_observations(report["rust_counts"], actual)
                    if args.inject_error and not injected:
                        actual[0]["responses"][0]["flags"] ^= 0x400
                        injected = True
                    failures = check_equal(expected, actual)
                    report["compared"] += len(expected)
                    report["matched"] += len(expected) - len(failures)
                    report["failures"].extend({"group": group, **failure} for failure in failures)
        assert not upstream.failures, upstream.failures
    except Exception as error:
        report["failures"].append({"infrastructure_or_protocol": repr(error)})
    finally:
        upstream.close()
        (output / "upstream.json").write_text(json.dumps({"events": upstream.events, "failures": upstream.failures}, indent=2) + "\n")
    report["unexecuted"] = planned - (report["compared"] if args.rust else report["c_observations"])
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "failures"}, sort_keys=True))
    print("failures=" + str(len(report["failures"])))
    return int(bool(report["failures"] or report["unexecuted"]))


if __name__ == "__main__":
    raise SystemExit(main())
