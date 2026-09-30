#!/usr/bin/env python3
"""Measure the exact C TCP caller's per-connection OPT carry-over boundary.

Run via run_isolated.sh. Stores packets and configuration only below private/.
A reference mismatch is reported, not counted as functional equivalence.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from tcp_caller_diff import query, opt, sha

ROOT = Path(__file__).resolve().parents[2]


def exact(connection, count):
    data = b""
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ConnectionError("short TCP frame")
        data += part
    return data


def exchange(connection, packet):
    connection.sendall(struct.pack("!H", len(packet)) + packet)
    length = struct.unpack("!H", exact(connection, 2))[0]
    response = exact(connection, length)
    return {"packet": response.hex(), "header": list(struct.unpack("!6H", response[:12]))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "private"):
        parser.error("output must be new and below private/")
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1" or [name for _, name in socket.if_nameindex()] != ["lo"]:
        parser.error("dedicated loopback-only network namespace required")
    out.mkdir(parents=True)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = out / "daemon.conf"
    config.write_text(f"port={port}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address=127.0.0.1\n"
                      f"cache-size=0\nuser=root\npid-file={out}/pid\nlog-facility={out}/daemon.log\n")
    def connect():
        connection = socket.create_connection(("127.0.0.1", port), timeout=2)
        connection.settimeout(2)
        return connection
    with (out / "stderr.log").open("wb") as log:
        process = subprocess.Popen([str(args.binary.resolve()), "-k", "-C", str(config)],
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(f"daemon exited {process.returncode}")
                try:
                    connection = connect()
                    break
                except OSError:
                    time.sleep(.01)
            else:
                raise RuntimeError("daemon never ready")
            with connection:
                replies = [exchange(connection, query(options=opt(ttl=0x8000))), exchange(connection, query())]
            with connect() as connection:
                replies.append(exchange(connection, query()))
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
    differences = []
    if args.reference:
        reference = json.loads(args.reference.read_text())["replies"]
        differences = [i for i, (expected, actual) in enumerate(zip(reference, replies)) if expected != actual]
        if len(reference) != len(replies):
            differences.append("response-count")
    assert len(replies) == 3 and all(reply["header"][1] & 15 == 5 for reply in replies)
    report = {"planned": 3, "completed": len(replies), "binary_sha256": sha(args.binary),
              "daemon_exit": process.returncode, "replies": replies, "differences": differences,
              "scope": "OPT query then ordinary query on one connection, plus fresh ordinary query; not a full TCP gate"}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"completed": len(replies), "additional_counts": [r["header"][5] for r in replies], "differences": differences}))
    return int(bool(differences))


if __name__ == "__main__":
    raise SystemExit(main())
