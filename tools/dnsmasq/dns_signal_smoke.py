#!/usr/bin/env python3
"""Run the foreground DNS daemon and verify SIGTERM releases its workers."""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        default="components/dnsmasq/target/debug/dnsmasq-rs",
        help="built dnsmasq-rs binary",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = "\n".join(
        (
            "no-resolv",
            "listen-address=127.0.0.1",
            f"port={port}",
            "host-record=router.test,192.0.2.1",
            "",
        )
    )
    binary = Path(args.binary)
    if not binary.exists():
        raise SystemExit(f"binary does not exist: {binary}")

    with tempfile.NamedTemporaryFile("w", prefix="dnsmasq-rs-", suffix=".conf") as file:
        file.write(config)
        file.flush()
        process = subprocess.Popen(
            [str(binary), "-C", file.name, "-k"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + args.timeout
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is not None:
            error = process.stderr.read().strip()
            raise SystemExit(f"daemon exited before signal: {process.returncode}: {error}")
        process.terminate()
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise SystemExit("daemon did not stop after SIGTERM")
        error = process.stderr.read().strip()

    result = {"signal": "SIGTERM", "exit_code": process.returncode, "stderr": error}
    print(json.dumps(result, sort_keys=True))
    return 0 if process.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
