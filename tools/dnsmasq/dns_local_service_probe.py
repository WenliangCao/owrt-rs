#!/usr/bin/env python3
"""Deterministic smoke probe for the loopback local-DNS development runner.

This probe deliberately exercises only the currently wired boundary. It never
starts a DHCP service or an upstream resolver. Run it through run_isolated.sh
on Linux so the listener is confined to a namespace containing only lo.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import os
import signal
import socket
import struct
import subprocess
import time


def dns_name(value: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in value.split(".")) + b"\0"


def query(host: str, rrtype: int, ident: int) -> bytes:
    return struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + dns_name(host) + struct.pack("!HH", rrtype, 1)


def exchange(port: int, packet: bytes, tcp: bool, ipv6: bool) -> bytes:
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = ("::1", port) if ipv6 else ("127.0.0.1", port)
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(1.5)
        connection.connect(address)
        if tcp:
            connection.sendall(struct.pack("!H", len(packet)) + packet)
            length = struct.unpack("!H", connection.recv(2))[0]
            result = bytearray()
            while len(result) < length:
                chunk = connection.recv(length - len(result))
                if not chunk:
                    raise ConnectionError("short TCP response")
                result.extend(chunk)
            return bytes(result)
        connection.send(packet)
        return connection.recv(65535)


def summary(packet: bytes) -> dict[str, int]:
    if len(packet) < 12:
        raise ValueError("short DNS header")
    ident, flags, questions, answers, authorities, additionals = struct.unpack("!6H", packet[:12])
    return {
        "id": ident,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        parser.error("refusing to start listeners outside a dedicated test namespace")
    if sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        parser.error("test namespace must contain only lo")
    if args.out.exists():
        parser.error("choose a new output directory")
    args.out.mkdir(parents=True)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = args.out / "dnsmasq.conf"
    config.write_text(
        f"port={port}\nno-resolv\nno-hosts\nlisten-address=127.0.0.1,::1\n"
        "host-record=a.test,192.0.2.7\n"
        "host-record=target.test,192.0.2.8,2001:db8::8\n"
        "cname=alias.test,target.test\n"
        "local=/local.test/\n"
    )
    log_path = args.out / "stderr.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [str(args.binary.resolve()), "-k", "-C", str(config.resolve())],
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        cases: list[dict[str, object]] = []
        errors: list[str] = []
        try:
            for _ in range(100):
                if process.poll() is not None:
                    errors.append(f"daemon exited {process.returncode}")
                    break
                try:
                    exchange(port, query("a.test", 1, 0x1000), False, False)
                    break
                except (ConnectionError, OSError, socket.timeout):
                    time.sleep(0.01)
            else:
                errors.append("daemon never became ready")

            checks = [
                ("udp-a", "a.test", 1, False, False, 1, 0),
                ("tcp-a", "a.test", 1, True, False, 1, 0),
                ("ipv6-aaaa", "target.test", 28, False, True, 1, 0),
                ("cname-target", "alias.test", 1, False, False, 2, 0),
                ("local-nxdomain", "local.test", 1, False, False, 0, 3),
            ]
            for name, host, rrtype, tcp, ipv6, expected_answers, expected_rcode in checks:
                try:
                    ident = 0x2000 + len(cases)
                    response = summary(exchange(port, query(host, rrtype, ident), tcp, ipv6))
                    actual_rcode = response["flags"] & 0xF
                    if (
                        response["id"] != ident
                        or response["questions"] != 1
                        or response["answers"] != expected_answers
                        or actual_rcode != expected_rcode
                    ):
                        raise ValueError(
                            f"id/questions/answers/rcode "
                            f"{response['id']:04x}/{response['questions']}/"
                            f"{response['answers']}/{actual_rcode}"
                        )
                    cases.append({"name": name, "response": response})
                except Exception as error:
                    errors.append(f"{name}: {error!r}")

            try:
                exchange(port, query("outside.test", 1, 0x2FFF), False, False)
                errors.append("unowned query unexpectedly received a response")
            except socket.timeout:
                cases.append({"name": "unowned-dropped"})
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                errors.append("shutdown required SIGKILL")

    report = {
        "planned": 6,
        "success": len(cases),
        "errors": errors,
        "daemon_exit": process.returncode,
        "scope": "local DNS UDP/TCP smoke; not full correctness or performance acceptance",
    }
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"success": len(cases), "errors": len(errors), "output": str(args.out / "result.json")}))
    return int(bool(errors) or len(cases) != 6)


if __name__ == "__main__":
    raise SystemExit(main())
