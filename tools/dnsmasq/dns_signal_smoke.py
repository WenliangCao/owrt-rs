#!/usr/bin/env python3
"""Exercise delayed DNS TCP frames and SIGTERM with live loopback clients."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import socket
import struct
import subprocess
import time
from pathlib import Path


def read_exact(stream: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise AssertionError("TCP closed before completing a DNS frame")
        result.extend(part)
    return bytes(result)


def check_answer(stream: socket.socket, expected_id: int) -> None:
    size = struct.unpack("!H", read_exact(stream, 2))[0]
    packet = read_exact(stream, size)
    ident, flags, questions, answers, _, _ = struct.unpack("!6H", packet[:12])
    assert ident == expected_id and flags & 0x8000 and flags & 15 == 0
    assert questions == 1 and answers == 1
    # The fixed local A fixture is independent of the Rust encoder.
    assert packet.endswith(bytes([192, 0, 2, 1]))


def dns_query(name: str, ident: int) -> bytes:
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    ) + b"\0\0\x01\0\x01"
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + question


def assert_closed(stream: socket.socket, timeout: float) -> None:
    stream.settimeout(timeout)
    try:
        data = stream.recv(1)
    except socket.timeout as error:
        raise AssertionError("TCP connection did not close within the short gate") from error
    if data:
        raise AssertionError("TCP connection returned a response before closing")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        default="components/dnsmasq/target/debug/dnsmasq-rs",
        help="built dnsmasq-rs binary",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be finite and positive")
    output = args.output.resolve()
    private = Path("private").resolve()
    if not output.is_relative_to(private) or output == private:
        parser.error("output must be a new directory below ignored private/")
    output.mkdir(parents=True, exist_ok=False)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = "\n".join(
        (
            "no-resolv",
            "no-hosts",
            "listen-address=127.0.0.1",
            f"port={port}",
            "host-record=router.test,192.0.2.1",
            "",
        )
    )
    binary = Path(args.binary).resolve()
    if not binary.exists():
        raise SystemExit(f"binary does not exist: {binary}")

    config_file = output / "dnsmasq.conf"
    config_file.write_text(config)
    result = {"status": "failed", "checks_passed": 0, "signal": "SIGTERM"}
    with contextlib.ExitStack() as stack:
        stderr = stack.enter_context((output / "stderr.txt").open("w"))
        process = subprocess.Popen(
            [str(binary), "-C", str(config_file), "-k"],
            stdout=subprocess.DEVNULL,
            stderr=stderr,
        )
        try:
            deadline = time.monotonic() + args.timeout
            while True:
                if process.poll() is not None:
                    raise AssertionError("daemon exited before readiness")
                try:
                    client = socket.create_connection(("127.0.0.1", port), 0.1)
                    stack.enter_context(client)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("daemon did not become ready")
                    time.sleep(0.01)
            client.settimeout(args.timeout)
            query = dns_query("router.test", 0x2345)
            frame = struct.pack("!H", len(query)) + query
            # Both initial idle and partial-frame gaps exceed the stop-check
            # interval. They must not reset the 150-second lifetime or close.
            time.sleep(0.25)
            client.sendall(frame[:1])
            time.sleep(0.25)
            client.sendall(frame[1:9])
            time.sleep(0.25)
            client.sendall(frame[9:])
            check_answer(client, 0x2345)
            result["checks_passed"] += 1
            time.sleep(0.25)
            client.sendall(frame)
            check_answer(client, 0x2345)
            result["checks_passed"] += 1
            unknown = stack.enter_context(
                socket.create_connection(("127.0.0.1", port), args.timeout)
            )
            unknown_query = dns_query("unknown.test", 0x3456)
            unknown.sendall(struct.pack("!H", len(unknown_query)) + unknown_query)
            # TCP forwarding is an explicit unsupported gate. An unowned local
            # name must close promptly rather than leave the client waiting for
            # the 150-second connection lifetime.
            assert_closed(unknown, min(args.timeout, 1.0))
            result["checks_passed"] += 1
            idle = stack.enter_context(
                socket.create_connection(("127.0.0.1", port), args.timeout)
            )
            idle.settimeout(args.timeout)
            partial = stack.enter_context(socket.create_connection(("127.0.0.1", port), args.timeout))
            partial.settimeout(args.timeout)
            partial.sendall(frame[:1])
            # Keep an idle client and an incomplete frame live at shutdown.
            time.sleep(0.1)
            start = time.monotonic()
            process.terminate()
            process.wait(timeout=args.timeout)
            result["exit_code"] = process.returncode
            result["shutdown_seconds"] = time.monotonic() - start
            assert process.returncode == 0, "SIGTERM did not exit normally"
            for stream in (client, partial, idle):
                assert stream.recv(1) == b"", "client socket remained open"
                result["checks_passed"] += 1
            result["status"] = "passed"
        except Exception as error:
            result["error"] = str(error)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=args.timeout)
            (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
