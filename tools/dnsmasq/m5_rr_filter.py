#!/usr/bin/env python3
"""Daemon-level exact-image differential for filter-A/AAAA/filter-rr.

The C daemon is run first for each configuration and supplies every expected
wire reply and upstream side effect.  Rust is then run from a fresh image
copy.  The schedule deliberately covers local answers, upstream extraction,
cache replay, ANY/DO, clipped TC replies and negative responses.  Raw packets,
configs and process traces belong below private evidence only.
"""
from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, read_name, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256

LISTEN_HOST = "127.0.0.1"
UPSTREAM_HOST = "127.0.0.2"


def query(host: str, qtype: int, ident: int, *, do: bool = False, edns: bool = False, rd: bool = True, size: int = 1232) -> bytes:
    flags = 0x0100 if rd else 0
    edns = edns or do
    wire = struct.pack("!6H", ident, flags, 1, 0, 0, int(edns))
    wire += name(host) + struct.pack("!HH", qtype, 1)
    if edns:
        wire += b"\0" + struct.pack("!HHIH", 41, size, 0x8000 if do else 0, 0)
    return wire


def rr(rrtype: int, data: bytes, owner: bytes = b"\xc0\x0c", ttl: int = 60,
       rrclass: int = 1) -> bytes:
    return owner + struct.pack("!HHIH", rrtype, rrclass, ttl, len(data)) + data


def mixed_body(host: str, *, include_answer: bool = True, clipped: bool = False) -> bytes:
    owner = b"\xc0\x0c"
    target = name("mail.m5.test")
    cname_target = name("target.m5.test")
    answer = []
    if include_answer:
        answer = [
            rr(5, cname_target, owner),
            rr(1, ipaddress.ip_address("192.0.2.7").packed, owner),
            rr(28, ipaddress.ip_address("2001:db8::7").packed, owner),
            rr(15, struct.pack("!H", 10) + target, owner),
            rr(16, b"\x05hello", owner),
        ]
    authority = [rr(6, name("ns.m5.test") + name("hostmaster.m5.test") +
                     struct.pack("!5I", 1, 2, 3, 4, 5), name("m5.test"), 60)]
    additional = [rr(1, ipaddress.ip_address("192.0.2.8").packed, name("mail.m5.test"))]
    if clipped:
        # Complete header/question and a TC answer with an intentionally short
        # RDATA tail.  C's TC branch skips configured filtering entirely.
        return b"".join(answer[:2])[:-1]
    return b"".join(answer + authority + additional)


def upstream_reply(packet: bytes) -> bytes:
    host, end = read_name(packet, 12)
    qtype = struct.unpack_from("!H", packet, end)[0]
    question = packet[12:end + 4]
    had_opt = struct.unpack_from("!H", packet, 10)[0] > 0
    opt = rr(41, b"", b"\0", 0, 1232) if had_opt else b""
    if host.startswith("simple-"):
        data = {1: ipaddress.ip_address("192.0.2.17").packed,
                28: ipaddress.ip_address("2001:db8::17").packed,
                16: b"\x06cached",
                15: struct.pack("!H", 10) + name("mail.m5.test")}[qtype]
        return packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, int(bool(opt))) + question + rr(qtype, data) + opt
    if host.startswith("nx-"):
        flags = 0x8183
        soa = name("ns.m5.test") + name("hostmaster.m5.test") + struct.pack("!5I", 1, 2, 3, 4, 5)
        body = rr(6, soa, name("m5.test"), 60)
        return packet[:2] + struct.pack("!5H", flags, 1, 0, 1, int(bool(opt))) + question + body + opt
    if host.startswith("nodata-"):
        flags = 0x8180
        soa = name("ns.m5.test") + name("hostmaster.m5.test") + struct.pack("!5I", 1, 2, 3, 4, 5)
        body = rr(6, soa, name("m5.test"), 60)
        return packet[:2] + struct.pack("!5H", flags, 1, 0, 1, int(bool(opt))) + question + body + opt
    clipped = host.startswith("clipped-")
    any_q = qtype == 255
    body = mixed_body(host, clipped=clipped)
    if clipped:
        # Set TC and provide a valid prefix before cutting through the second
        # answer.  The daemon must retain the prefix and TC bit byte-for-byte.
        flags = 0x8380
        first = rr(1, ipaddress.ip_address("192.0.2.7").packed)
        second = rr(28, ipaddress.ip_address("2001:db8::7").packed)
        cut = len(second) - 2
        body = first + second[:cut]
        return packet[:2] + struct.pack("!5H", flags, 1, 2, 0, 0) + question + body
    # The answer deliberately carries all types for every qtype, including
    # ANY, so rrfilter's section/type decisions remain observable.
    flags = 0x8180
    answers = 5
    return packet[:2] + struct.pack("!5H", flags, 1, answers, 1, 1 + int(bool(opt))) + question + body + opt


class Upstream:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((UPSTREAM_HOST, 0))
        self.port = self.udp.getsockname()[1]
        self.udp.settimeout(.05)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((UPSTREAM_HOST, self.port)); self.tcp.listen()
        self.tcp.settimeout(.05)
        self.stop = threading.Event(); self.errors = []; self.events = []
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for thread in self.threads: thread.start()

    def record(self, packet, transport):
        host, end = read_name(packet, 12); qtype = struct.unpack_from("!H", packet, end)[0]
        self.events.append({"host": host, "type": qtype, "transport": transport, "query": packet.hex()})

    def udp_loop(self):
        while not self.stop.is_set():
            try: packet, peer = self.udp.recvfrom(65535)
            except socket.timeout: continue
            except OSError:
                if self.stop.is_set(): break
                raise
            try:
                self.record(packet, "udp"); self.udp.sendto(upstream_reply(packet), peer)
            except Exception as error: self.errors.append(repr(error))

    def tcp_loop(self):
        while not self.stop.is_set():
            try: client, _ = self.tcp.accept()
            except socket.timeout: continue
            except OSError:
                if self.stop.is_set(): break
                raise
            worker = threading.Thread(target=self.connection, args=(client,)); worker.start(); self.threads.append(worker)

    def connection(self, client):
        try:
            with client:
                client.settimeout(.2)
                while not self.stop.is_set():
                    try: prefix = exact_read(client, 2)
                    except socket.timeout: continue
                    packet = exact_read(client, struct.unpack("!H", prefix)[0])
                    self.record(packet, "tcp")
                    response = upstream_reply(packet)
                    client.sendall(struct.pack("!H", len(response)) + response)
        except (ConnectionError, OSError):
            pass
        except Exception as error:
            if not self.stop.is_set(): self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        for sock in (self.udp, self.tcp):
            try: sock.close()
            except OSError: pass
        for thread in self.threads: thread.join(2)
        assert not any(thread.is_alive() for thread in self.threads), "upstream thread remained live"


def normalized(packet: bytes) -> dict:
    try:
        result = semantics(packet)
    except (IndexError, ValueError, struct.error) as error:
        # A TC reply may be clipped in the middle of an RR.  Preserve the
        # exact malformed boundary as an observed result; do not turn it into
        # a harness failure before C/Rust have been compared.
        return {"id": struct.unpack_from("!H", packet)[0] if len(packet) >= 2 else None,
                "wire_length": len(packet), "malformed": repr(error), "wire": packet.hex()}
    result["id"] = 0
    for record in result["records"]:
        if record["type"] != 41: record["ttl"] = 0
    return result


def exchange(port: int, packet: bytes, tcp: bool = False) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3); client.connect((LISTEN_HOST, port))
        if tcp:
            client.sendall(struct.pack("!H", len(packet)) + packet)
            return exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
        client.send(packet); return client.recv(65535)


def schedule():
    ident = 0x5200
    rows = []
    def add(label, host, qtype, *, tcp=False, do=False, edns=False, rd=True, clipped=False):
        nonlocal ident
        if clipped: host = "clipped-" + host
        packet = query(host, qtype, ident, do=do, edns=edns, rd=rd); ident += 1
        rows.append({"label": label, "host": host, "type": qtype, "tcp": tcp, "do": do, "packet": packet})
    # Local records are intentionally retained by C even when their family is
    # configured for filtering (F_HOSTS/F_CONFIG exemption in answer_request).
    for qtype in (1, 28, 255): add("local-" + str(qtype), "local.m5.test", qtype)
    add("upstream-a-fill", "mixed-a.m5.test", 1)
    add("upstream-a-cache", "mixed-a.m5.test", 1)
    add("upstream-aaaa", "mixed-a.m5.test", 28)
    add("upstream-any", "mixed-a.m5.test", 255)
    add("upstream-do-a", "mixed-a.m5.test", 1, do=True)
    add("upstream-tcp", "mixed-a.m5.test", 1, tcp=True)
    add("negative-nx", "nx-m5.test", 1)
    add("negative-any", "nx-m5.test", 255)
    add("negative-nodata", "nodata-m5.test", 1)
    add("filtered-shortcut", "mixed-shortcut.m5.test", 1)
    add("filtered-shortcut-cached-other", "mixed-shortcut.m5.test", 28)
    add("clipped-a", "mixed-a.m5.test", 1, clipped=True)
    add("clipped-any", "mixed-a.m5.test", 255, clipped=True)
    for qtype in (1, 28, 16):
        host = f"simple-{qtype}.m5.test"
        add(f"simple-{qtype}-fill", host, qtype)
        add(f"simple-{qtype}-edns-cache", host, qtype, edns=True)
        add(f"simple-{qtype}-tcp-cache", host, qtype, tcp=True, edns=True)
    add("simple-other-fill", "simple-other.m5.test", 1)
    add("simple-filtered-other", "simple-other.m5.test", 28, edns=True)
    add("nonrecursive-cache", "simple-1.m5.test", 1, rd=False, edns=True)
    add("local-txt", "local.m5.test", 16, edns=True)
    add("local-alias-a", "alias.m5.test", 1, edns=True)
    add("local-alias-cname", "alias.m5.test", 5, edns=True)
    add("generic-filtered-other", "simple-16.m5.test", 15, edns=True)
    return rows


def free_dns_port():
    # The daemon binds both transports. A UDP-only ephemeral reservation can
    # select a port still occupied by a previous TCP connection/TIME_WAIT.
    for _ in range(100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind((LISTEN_HOST, 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind((LISTEN_HOST, port))
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
                continue
            return port
    raise RuntimeError("no port available for both DNS transports")


def run_side(args, side, folder, directive):
    folder.mkdir(parents=True)
    root = prepare(args.image_root, None, folder, args.rust)
    upstream = Upstream()
    port = free_dns_port()
    config = (f"port={port}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={LISTEN_HOST}\n"
              f"server={UPSTREAM_HOST}#{upstream.port}\ncache-size=100\nedns-packet-max=1232\n"
              f"local-ttl=60\nhost-record=local.m5.test,192.0.2.10,2001:db8::10\ntxt-record=local.m5.test,local\ncname=alias.m5.test,local.m5.test\ncache-rr=TXT\n"
              f"pid-file=/m2/rr-filter.pid\nlog-facility=/m2/rr-filter.log\nuser=root\n{directive}\n")
    (root / "m2/rr-filter.conf").write_text(config); (folder / "config").write_text(config)
    rows, process = [], None
    log = (folder / "daemon.log").open("wb")
    try:
        process = subprocess.Popen(command(root, side, "-k", "-C", "/m2/rr-filter.conf"), stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            if process.poll() is not None: raise RuntimeError(f"{side} exited {process.returncode}")
            try: exchange(port, query("ready.m5.test", 1, 0x5000)); break
            except OSError: time.sleep(.01)
        else: raise RuntimeError(f"{side} readiness timeout")
        for item in schedule():
            reply = exchange(port, item["packet"], item["tcp"])
            (folder / (item["label"] + ".query")).write_bytes(item["packet"])
            (folder / (item["label"] + ".reply")).write_bytes(reply)
            rows.append({k: item[k] for k in ("label", "host", "type", "tcp", "do")} | {"reply": normalized(reply), "wire": reply.hex()})
        result = {"rows": rows, "upstream": copy.deepcopy(upstream.events), "identity": process_identity(root, process.pid), "exit": None, "upstream_errors": copy.deepcopy(upstream.errors)}
    finally:
        if process is not None:
            if process.poll() is None: os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(4)
            except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL); process.wait(3)
            if 'result' in locals(): result["exit"] = process.returncode
        upstream.close(); log.close()
    (folder / "trace.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare(left, right):
    errors = []
    for side, result in (("c", left), ("rust", right)):
        if result["exit"] != 0 or result.get("upstream_errors"):
            errors.append({"kind": "lifecycle", "side": side, "exit": result["exit"], "upstream_errors": result.get("upstream_errors")})
    if len(left["rows"]) != len(right["rows"]): errors.append({"kind": "row-count"})
    for index, (a, b) in enumerate(zip(left["rows"], right["rows"])):
        # Raw wire is evidence. Comparison uses decoded DNS semantics so
        # compression layout and the elapsed TTL second do not create noise.
        if {k: v for k, v in a.items() if k != "wire"} != {k: v for k, v in b.items() if k != "wire"}:
            errors.append({"kind": "row", "index": index, "c": a, "rust": b})
    # Upstream side effects are part of the daemon-level contract. IDs and
    # source ports are absent from this normalized event representation.
    if [{k: e[k] for k in ("host", "type", "transport")} for e in left["upstream"]] != [{k: e[k] for k in ("host", "type", "transport")} for e in right["upstream"]]:
        errors.append({"kind": "upstream-events", "c": left["upstream"], "rust": right["upstream"]})
    return errors


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--image-root", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); out = args.out.resolve()
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1": raise SystemExit("run through run_isolated.sh")
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]: raise SystemExit("loopback-only namespace required")
    if out.exists() or "private" not in out.parts: raise SystemExit("fresh private output required")
    out.mkdir(parents=True)
    directives = ["filter-A", "filter-AAAA", "filter-rr=TXT", "filter-rr=ANY", "filter-A\nfilter-AAAA\nfilter-rr=TXT", "filter-rr=1,28", "filter-rr=CNAME,TXT,SOA", "filter-rr=MX,ANY"]
    report = {"cases": [], "failures": [], "negative_controls": [], "c_sha256": STOCK_SHA256, "rust_sha256": sha256(args.rust)}
    for index, directive in enumerate(directives):
        # Mount's overlay path list uses commas as separators.
        label = directive.replace("\n", "+").replace("=", "-").replace(",", "-").lower() or "none"
        left = run_side(args, "c", out / f"{index:02d}-{label}" / "c", directive)
        right = run_side(args, "rust", out / f"{index:02d}-{label}" / "rust", directive)
        errors = compare(left, right)
        report["cases"].append({"directive": directive, "rows": len(left["rows"]), "errors": errors})
        report["failures"].extend({"directive": directive, **error} for error in errors)
        changed = copy.deepcopy(left); changed["rows"][0]["reply"]["flags"] ^= 1
        omitted = copy.deepcopy(left); omitted["rows"].pop()
        events = copy.deepcopy(left); events["upstream"].pop()
        report["negative_controls"].append({"directive": directive, "changed_detected": bool(compare(left, changed)), "omitted_detected": bool(compare(left, omitted)), "upstream_omission_detected": bool(compare(left, events))})
    report["passed"] = not report["failures"] and all(row["changed_detected"] and row["omitted_detected"] and row["upstream_omission_detected"] for row in report["negative_controls"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(report["cases"]), "rows": sum(row["rows"] for row in report["cases"]), "failures": len(report["failures"]), "passed": report["passed"]}))
    return int(not report["passed"])


if __name__ == "__main__": raise SystemExit(main())
