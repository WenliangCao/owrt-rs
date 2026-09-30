#!/usr/bin/env python3
"""REQUEST/RELEASE/DECLINE state kernel versus exact C in an isolated netns.

Requires DNSMASQ_TEST_ISOLATED=1 from run_isolated.sh. Both input datagrams and
all state stay in the supplied private directory; no host-network listeners.
Rust is driven offline with the same requests. This does not validate a Rust
DHCP socket, wire serializer, DISCOVER, BOOTP, PXE or all configuration options.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


def packet(message, client, requested=None, server=None, ciaddr=None, rapid=False, requested_options=None):
    data = bytearray(240)
    data[:3] = bytes([1, 1, 6])
    data[4:8] = struct.pack("!I", client * 100 + message)
    data[12:16] = ipaddress.IPv4Address(ciaddr or "0.0.0.0").packed
    data[24:28] = bytes([255] * 4)
    data[28:34] = bytes([2, 0, 0, 0, 0, client])
    data[236:240] = bytes([99, 130, 83, 99])
    if message: data.extend([53, 1, message])
    if requested: data.extend(bytes([50, 4]) + ipaddress.IPv4Address(requested).packed)
    if server: data.extend(bytes([54, 4]) + ipaddress.IPv4Address(server).packed)
    if rapid: data.extend([80, 0])
    if requested_options is not None: data.extend(bytes([55, len(requested_options)]) + bytes(requested_options))
    data.append(255)
    return bytes(data)


def semantics(data):
    if data is None: return "0 - - - - - -"
    options = {}
    pos = 240
    while pos < len(data):
        code = data[pos]
        if code == 255: break
        if code == 0: pos += 1; continue
        length = data[pos + 1]
        options[code] = data[pos + 2:pos + 2 + length]
        pos += length + 2
    message = options[53][0] if 53 in options else 16
    address = str(ipaddress.IPv4Address(data[12:16] if message in (11, 12, 13) else data[16:20]))
    duration = str(struct.unpack("!I", options[51])[0]) if 51 in options else "-"
    server = str(ipaddress.IPv4Address(options[54])) if 54 in options else "-"
    broadcast = 1 if struct.unpack("!H", data[10:12])[0] & 0x8000 else 0
    reason = options.get(56, b"").hex() or "-"
    rapid = int(80 in options)
    result = f"{message} {address} {duration} {server} {broadcast} {reason} {rapid}"
    if message in (11, 12, 13):
        number = lambda code: str(struct.unpack("!I", options[code])[0]) if code in options else "-"
        result += f" t1={number(58)} t2={number(59)} last={number(91)} mac={data[28:28 + data[2]].hex()} clid={options.get(61, b'').hex() or '-'} agent={options.get(82, b'').hex() or '-'}"
    return result


def leases(text):
    records = {}
    for line in text.replace(";", "\n").splitlines():
        if not line.strip(): continue
        expiry, hardware, address, name, client = line.split()
        records[address] = (int(expiry), hardware, name, client)
    return records


def same_leases(left, right):
    left, right = leases(left), leases(right)
    return list(left) == list(right) and all(left[key][1:] == right[key][1:] and abs(left[key][0] - right[key][0]) <= 1 for key in left)


def duplicate_recovery_proof(args):
    """Known C invariant failure, outside the equivalence pass denominator."""
    folder = args.output / "duplicate-recovery-proof"; folder.mkdir()
    leasefile = folder / "c.leases"
    expiry = int(time.time()) + 600
    leasefile.write_text(f"{expiry} 02:00:00:00:00:01 127.0.0.10 first *\n{expiry} 02:00:00:00:00:02 127.0.0.10 second *\n")
    (folder / "initial.leases").write_bytes(leasefile.read_bytes())
    config = folder / "dnsmasq.conf"
    config.write_text(f"port=0\ninterface=lo\nbind-interfaces\nno-ping\ndhcp-alternate-port=1067,1068\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,120s\ndhcp-leasefile={leasefile}\n")
    results = []
    with (folder / "c.log").open("wb") as log:
        process = subprocess.Popen([str(args.c_reference), "--no-daemon", f"--conf-file={config}"], stdout=log, stderr=subprocess.STDOUT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(("127.0.0.1", 0)); sock.settimeout(0.5)
        try:
            time.sleep(0.1)
            if process.poll() is not None: raise RuntimeError((folder / "c.log").read_text())
            for client in (1, 2):
                request = packet(3, client, ciaddr="127.0.0.10")
                (folder / f"client-{client}.request").write_bytes(request)
                sock.sendto(request, ("127.0.0.1", 1067)); response = sock.recv(16384)
                (folder / f"client-{client}.response").write_bytes(response)
                results.append(semantics(response))
        finally:
            sock.close(); process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    proof = {"responses": results, "both_clients_acknowledged_same_address": len(results) == 2 and all(reply.startswith("5 127.0.0.10 ") for reply in results), "scope": "malformed restored lease DB permits two distinct MACs to renew one address; Rust rejects ambiguous DB at startup"}
    (folder / "result.json").write_text(json.dumps(proof, indent=2) + "\n")
    if not proof["both_clients_acknowledged_same_address"]: raise RuntimeError("C duplicate-recovery proof did not reproduce")
    return proof


def scenarios():
    def select(client, last, server="127.0.0.1"): return packet(3, client, f"127.0.0.{last}", server)
    def renew(client, last): return packet(3, client, ciaddr=f"127.0.0.{last}")
    def release(client, last): return packet(7, client, server="127.0.0.1", ciaddr=f"127.0.0.{last}")
    base = [
        ("dynamic-nonauth", False, 0, [select(1, 10), select(2, 10), renew(1, 10), renew(2, 11), packet(3, 2, "127.0.0.11"), select(2, 11, "127.0.0.2"), release(2, 10), release(1, 10)]),
        ("dynamic-auth", True, 0, [packet(3, 2, "127.0.0.11"), select(3, 12, "127.0.0.2"), select(3, 99), renew(2, 11), packet(4, 2, "127.0.0.11", "127.0.0.1"), select(2, 12), release(2, 12)]),
        ("static", True, 1, [select(1, 10), renew(1, 10), select(1, 15), select(2, 15), packet(4, 1, "127.0.0.15", "127.0.0.1"), packet(3, 1, "127.0.0.14"), release(1, 14)]),
        ("static-multiple-mac", True, 2, [select(1, 15), select(2, 15), release(1, 15), renew(2, 15), release(2, 15)]),
    ]
    result = [(name, auth, static, False, False, requests) for name, auth, static, requests in base] + [
        ("discover", True, 0, False, False, [packet(1, 1, "127.0.0.10"), packet(1, 2, "127.0.0.10"), select(1, 10), packet(1, 2, "127.0.0.10"), packet(1, 1), release(1, 10)]),
        ("rapid-commit", True, 0, True, False, [packet(1, 1, "127.0.0.10", rapid=True), packet(1, 2, "127.0.0.10", rapid=True), packet(1, 3), release(1, 10)]),
        ("bootp-static", False, 1, False, False, [packet(0, 1), packet(0, 2), packet(0, 1)]),
        ("bootp-dynamic", False, 0, False, True, [packet(0, 1), packet(0, 2), packet(0, 1)]),
        ("bootp-disabled", False, 0, False, False, [packet(0, 1)]),
        ("inform", False, 0, False, False, [select(1, 10), packet(8, 1, ciaddr="127.0.0.10"), packet(8, 2, ciaddr="127.0.0.10"), packet(8, 1, ciaddr="127.0.0.10", requested_options=[1, 3, 6]), packet(8, 2, ciaddr="127.0.0.12"), packet(8, 2, ciaddr="203.0.113.7"), packet(8, 1)]),
    ]
    return [(name, auth, static, rapid, bootp, 0, requests) for name, auth, static, rapid, bootp, requests in result] + [
        ("leasequery", False, 0, False, False, 1, [select(1, 10), packet(10, 2, ciaddr="127.0.0.10", requested_options=[51, 58, 59, 61, 82, 91]), packet(10, 2, ciaddr="127.0.0.11"), packet(10, 2, ciaddr="127.0.0.99"), packet(10, 1), packet(10, 2)]),
        ("leasequery-disabled", False, 0, False, False, 0, [select(1, 10), packet(10, 2, ciaddr="127.0.0.10")]),
        ("leasequery-denied", False, 0, False, False, 2, [select(1, 10), packet(10, 2, ciaddr="127.0.0.10")]),
        ("leasequery-ipv6-acl", False, 0, False, False, 3, [packet(10, 2, ciaddr="127.0.0.11")]),
        ("leasequery-infinite", False, 0, False, True, 1, [packet(0, 1), packet(10, 1)]),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-reference", type=Path, required=True)
    parser.add_argument("--rust-probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1": raise SystemExit("refusing DHCP test without isolated network namespace")
    args.output.mkdir(parents=True, exist_ok=False)
    results = []
    for name, authoritative, static_count, rapid_commit, bootp_dynamic, leasequery_mode, requests in scenarios():
        folder = args.output / name; folder.mkdir()
        leasefile = folder / "c.leases"
        config = folder / "dnsmasq.conf"
        config.write_text(f"port=0\ninterface=lo\nbind-interfaces\nno-ping\ndhcp-alternate-port=1067,1068\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,120s\ndhcp-leasefile={leasefile}\n" + ("dhcp-authoritative\n" if authoritative else "") + ("dhcp-host=" + ",".join(f"02:00:00:00:00:{client:02x}" for client in range(1, static_count + 1)) + ",127.0.0.15\n" if static_count else ""))
        with config.open("a") as stream:
            if rapid_commit: stream.write("dhcp-rapid-commit\n")
            if bootp_dynamic: stream.write("bootp-dynamic\n")
            if leasequery_mode: stream.write("leasequery=" + {1: "127.0.0.0/8", 2: "192.0.2.0/24", 3: "::1"}[leasequery_mode] + "\n")
        with (folder / "c.log").open("wb") as log:
            c = subprocess.Popen([str(args.c_reference), "--no-daemon", f"--conf-file={config}", f"--pid-file={folder / 'c.pid'}"], stdout=log, stderr=subprocess.STDOUT)
            rust = subprocess.Popen([str(args.rust_probe), str(int(authoritative)), str(static_count), str(int(rapid_commit)), str(int(bootp_dynamic)), str(leasequery_mode)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", 0)); sock.settimeout(0.2)
            try:
                time.sleep(0.1)
                if c.poll() is not None: raise RuntimeError((folder / "c.log").read_text())
                for index, request in enumerate(requests):
                    now = int(time.time())
                    (folder / f"{index:02d}.request").write_bytes(request)
                    sock.sendto(request, ("127.0.0.1", 1067))
                    try: response = sock.recv(16384)
                    except socket.timeout: response = None
                    if response is not None: (folder / f"{index:02d}.response").write_bytes(response)
                    rust.stdin.write(f"{now} {request.hex()}\n"); rust.stdin.flush()
                    rust_response, rust_leases = rust.stdout.readline().rstrip("\n").split(" | ")
                    c_leases = leasefile.read_text() if leasefile.exists() else ""
                    c_response = semantics(response)
                    result = {"scenario": name, "index": index, "c_reply": c_response, "rust_reply": rust_response, "c_leases": c_leases, "rust_leases": rust_leases, "matched": c_response == rust_response and same_leases(c_leases, rust_leases)}
                    results.append(result)
            finally:
                sock.close()
                for process in (c, rust):
                    process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
        (folder / "results.json").write_text(json.dumps(results[-len(requests):], indent=2) + "\n")
    counts = {"cases": len(results), "successful": sum(result["matched"] for result in results), "mismatches": sum(not result["matched"] for result in results), "offers": sum(result["c_reply"].startswith("2 ") for result in results), "bootp_replies": sum(result["c_reply"].startswith("16 ") for result in results), "acks": sum(result["c_reply"].startswith("5 ") for result in results), "naks": sum(result["c_reply"].startswith("6 ") for result in results), "no_replies": sum(result["c_reply"].startswith("0 ") for result in results)}
    proof = duplicate_recovery_proof(args)
    identity = {"c_sha256": hashlib.sha256(args.c_reference.read_bytes()).hexdigest(), "rust_probe_sha256": hashlib.sha256(args.rust_probe.read_bytes()).hexdigest()}
    (args.output / "results.json").write_text(json.dumps({"counts": counts, "results": results, "duplicate_recovery_proof": proof, "identity": identity}, indent=2) + "\n")
    print(json.dumps(counts, indent=2))
    if counts["acks"] == 0 or counts["naks"] == 0 or counts["no_replies"] == 0: raise SystemExit("calibration failed")
    if counts["mismatches"]: raise SystemExit(1)


if __name__ == "__main__": main()
