#!/usr/bin/env python3
"""Exact-daemon local DNS size/TC/OPT comparison on isolated loopback sockets."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, semantics
from dns_udp_refusal_diff import C_HASH, ROOT, digest, query


SIZES = [497, 498, 501, 507, 512, 513, 1217, 1218, 1221, 1232, 1233, 1800]


def txt_line(host, length):
    parts = []
    while length:
        part = min(length - 1, 255)
        parts.append("x" * part)
        length -= part + 1
    return "txt-record=" + host + "," + ",".join(parts) + "\n"


def configuration(port, maximum, shared_addresses):
    config = (f"port={port}\nno-resolv\nno-hosts\ncache-size=0\nno-round-robin\n"
              f"listen-address=127.0.0.1,::1\nedns-packet-max={maximum}\nlocal-ttl=37\n"
              f"host-record=ready.test,192.0.2.{1 if shared_addresses else 254}\n"
              "address=/rule.test/203.0.113.2\nlocal=/owned.test/\n")
    for size in SIZES:
        # Header + question + pointer owner/RR header occupy exactly 40 bytes.
        config += txt_line(f"t{size:04}.test", size - 40)
    for count in [30, 31]:
        for last in range(1, count + 1):
            # Keep this sizing gate independent of cross-name PTR ownership.
            # The original shared-address counterexample is retained in
            # private/paired-01 and remains a separate known contract gap.
            prefix = "192.0.2" if count == 30 or shared_addresses else "198.51.100"
            config += f"host-record=many{count}.test,{prefix}.{last}\n"
    config += "cname=alias.test,middle.test\ncname=middle.test,t1217.test\n"
    return config


def cases():
    rows = []
    opts = [None, (0, True), (512, False), (512, True), (1232, True), (4096, False)]
    names = [(f"t{size:04}.test", 16) for size in SIZES]
    names += [("many30.test", 1), ("many31.test", 1), ("alias.test", 16),
              ("ready.test", 1), ("ready.test", 28), ("rule.test", 1), ("owned.test", 1)]
    for host, kind in names:
        for opt in opts:
            rows.append((f"udp/{host}/{kind}/{opt}", False,
                         query(host, kind, 1, 0x130, 0x2000 + len(rows), opt)))
    for host in ["t0513.test", "t1233.test", "t1800.test", "alias.test"]:
        for opt in [None, (512, True)]:
            rows.append((f"tcp/{host}/{opt}", True,
                         query(host, 16, 1, 0x130, 0x2000 + len(rows), opt)))
    for length in [0, 1, 4, 9, 10]:
        for tcp in [False, True]:
            packet = query("t0497.test", 16, 1, 0x130, 0x2000 + len(rows), (512, True))
            packet = packet[:-11] + packet[-11:][:length]
            rows.append((f"truncated-opt/{length}/tcp-{tcp}", tcp, packet))
    return rows


def exchange(ip, port, packet, tcp):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect((ip, port))
        if tcp:
            client.sendall(struct.pack("!H", len(packet)) + packet)
            return exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
        client.send(packet)
        return client.recv(65535)


def run(binary, side, out, maximum, planned, shared_addresses):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = out / f"{maximum}-{side}.conf"
    config.write_text(configuration(port, maximum, shared_addresses))
    rows = []
    with (out / f"{maximum}-{side}.log").open("wb") as log:
        process = subprocess.Popen([str(binary), "-d", "-C", str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None, "daemon exited during startup"
                try:
                    ready = exchange("127.0.0.1", port, query("ready.test", 1, 1, 0x100, 1), False)
                    assert struct.unpack_from("!H", ready, 6)[0] == 1
                    break
                except OSError:
                    time.sleep(.01)
            else:
                raise AssertionError("daemon readiness timeout")
            for ip in ["127.0.0.1", "::1"]:
                for case, tcp, packet in planned:
                    reply = exchange(ip, port, packet, tcp)
                    parsed = semantics(reply)
                    assert parsed["id"] == struct.unpack_from("!H", packet)[0]
                    rows.append({"case": case, "family": ip, "query": packet.hex(),
                                 "reply": reply.hex(), "length": len(reply), "semantics": parsed})
        finally:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            path = out / f"{maximum}-{side}.wire.json"
            assert not path.exists(), "wire path collision"
            path.write_text(json.dumps(rows, indent=2) + "\n")
    assert process.returncode == 0, "daemon did not exit cleanly"
    return rows


def compare(c, rust):
    assert len(c) == len(rust), "response count mismatch"
    return [{"case": a["case"], "family": a["family"],
             "c_length": a["length"], "rust_length": b["length"],
             "c_flags": a["semantics"]["flags"], "rust_flags": b["semantics"]["flags"]}
            for a, b in zip(c, rust) if a != b]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--shared-addresses", action="store_true",
                        help="retain the known host-record/PTR-owner ordering counterexample")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    assert digest(args.c) == C_HASH
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    out.mkdir(parents=True)
    sample = [{"case": "calibration", "family": "ipv4", "length": 40,
               "semantics": {"flags": 0x8580}, "reply": "00"}]
    assert compare(sample, sample) == []
    for changed in [dict(sample[0], length=41), dict(sample[0], reply="01"),
                    dict(sample[0], semantics={"flags": 0x8780})]:
        assert len(compare(sample, [changed])) == 1
    report = {"c_sha256": digest(args.c), "rust_sha256": digest(args.rust) if args.rust else None,
              "shared_addresses": args.shared_addresses,
              "calibration": {"positive": 1, "negative": 3}, "rounds": [], "failures": []}
    try:
        for maximum in [512, 1232]:
            c = run(args.c, "c", out, maximum, cases(), args.shared_addresses)
            rust = run(args.rust, "rust", out, maximum, cases(), args.shared_addresses) if args.rust else None
            mismatches = compare(c, rust) if rust is not None else []
            report["rounds"].append({"edns_max": maximum, "queries_per_side": len(c),
                                     "compared": rust is not None, "mismatches": mismatches})
        assert not any(row["mismatches"] for row in report["rounds"]), "local reply mismatch"
    except Exception as error:
        report["failures"].append(repr(error))
        raise
    finally:
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"rounds": [{k: v for k, v in row.items() if k != "mismatches"} for row in report["rounds"]],
                      "failures": report["failures"]}, indent=2))


if __name__ == "__main__":
    main()
