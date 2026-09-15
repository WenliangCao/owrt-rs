#!/usr/bin/env python3
"""Exercise shared HTTP listener admission on an owned disposable daemon.

Only loopback sockets and a temporary document root are used. With --rootfs,
copy the supplied image and chroot the owned child (run as root). No installed
service, router, host resource limit or network configuration is changed.
"""
import argparse
import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import select
import shutil
import socket
import statistics
import subprocess
import tempfile
import time

BODY = b"r93-shared-cap\n"
REQUEST = b"GET /health HTTP/1.0\r\n\r\n"


def read_reply(sock, first=b""):
    output = bytearray(first)
    while True:
        part = sock.recv(4096)
        if not part:
            break
        output.extend(part)
    head, body = bytes(output).split(b"\r\n\r\n", 1)
    assert head.startswith(b"HTTP/1.0 200 "), head
    assert body == BODY, body


@contextlib.contextmanager
def daemon(binary, rootfs):
    with tempfile.TemporaryDirectory(prefix="r93-httpd-cap-") as temporary:
        base = Path(temporary)
        if rootfs:
            from r14_httpd_check import disposable_rootfs
            fixture = disposable_rootfs(rootfs, binary)
        else:
            fixture = contextlib.nullcontext((base, base))
        with fixture as (_, root):
            docroot = root / "www"
            docroot.mkdir(exist_ok=True)
            (docroot / "health").write_bytes(BODY)
            (docroot / "health").chmod(0o644)
            with contextlib.ExitStack() as reservations:
                ports = []
                for _ in range(2):
                    reserve = reservations.enter_context(socket.socket())
                    reserve.bind(("127.0.0.1", 0))
                    ports.append(reserve.getsockname()[1])
            command = (["chroot", str(root), "/tmp/httpd-rs"] if rootfs else [str(binary)])
            command += ["-f", "-h", "/www" if rootfs else str(docroot),
                        "-c", "/tmp/r93-absent.conf" if rootfs else str(base / "absent.conf"),
                        "-p", f"127.0.0.1:{ports[0]}", "-p", f"127.0.0.1:{ports[1]}",
                        "-N", "1", "-k", "1", "-T", "3", "-u", "/ubus"]
            with (base / "stderr").open("w+b") as errors:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
                try:
                    for port in ports:
                        deadline = time.monotonic() + 5
                        while True:
                            assert process.poll() is None, "owned daemon exited during startup"
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                                    sock.sendall(REQUEST)
                                    read_reply(sock)
                                break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    raise
                                time.sleep(.02)
                    yield ports, process
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def holder_at_cap(port, kind):
    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
    if kind == "active_close":
        # Receiving 100 proves the connection was accepted. The worker then
        # waits for this unfinished body; no ubus call is made.
        sock.sendall(b"POST /ubus HTTP/1.1\r\nHost: fixture\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n")
        interim = bytearray()
        while not interim.endswith(b"\r\n\r\n"):
            byte = sock.recv(1)
            assert byte, "holder closed before 100 Continue"
            interim.extend(byte)
        assert interim == b"HTTP/1.1 100 Continue\r\n\r\n", interim
    else:
        sock.sendall(b"GET /health HTTP/1.1\r\nHost: fixture\r\n\r\n")
        reply = http.client.HTTPResponse(sock)
        reply.begin()
        assert reply.status == 200 and reply.read() == BODY
    time.sleep(.075)  # Longer than the 50 ms idle parking threshold.
    return sock


def measure(ports, kind, other_listener, count):
    samples = []
    for trial in range(count):
        with holder_at_cap(ports[0], kind) as holder:
            with socket.create_connection(("127.0.0.1", ports[int(other_listener)]), timeout=3) as queued:
                queued.sendall(REQUEST)
                # Vary the release phase so one lucky 50 ms poll cannot pass.
                time.sleep(.004 + (trial % 4) * .006)
                assert not select.select([queued], [], [], 0)[0], "request answered before a shared slot was free"
                if kind == "parked_expiry":
                    assert holder.recv(1) == b"", "idle holder did not expire"
                start = time.monotonic_ns()
                holder.close()
                first = queued.recv(1)
                samples.append((time.monotonic_ns() - start) / 1e6)
                read_reply(queued, first)
        time.sleep(.005)
    return {"samples_ms": samples, "median_ms": statistics.median(samples),
            "min_ms": min(samples), "max_ms": max(samples), "requests": count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--rootfs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expect-regression", action="store_true", help="require the old cross-listener latency failure")
    args = parser.parse_args()
    binary = args.binary.resolve()
    rows = {}
    with daemon(binary, args.rootfs.resolve() if args.rootfs else None) as (ports, process):
        for kind, count in (("active_close", 20), ("parked_close", 20), ("parked_expiry", 4)):
            for other in (False, True):
                name = kind + ("_cross" if other else "_same")
                rows[name] = measure(ports, kind, other, count)
                assert process.poll() is None, "daemon exited during admission recovery"
        for port in ports:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                sock.sendall(REQUEST)
                read_reply(sock)
    # Keep the threshold far below the old 50 ms poll while tolerating normal
    # scheduling variance; raw samples always accompany the decision.
    passed = all(row["median_ms"] < 15 for row in rows.values())
    regression = rows["active_close_cross"]["median_ms"] >= 15
    result = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "threshold_ms": 15, "passed": passed, "old_failure_reproduced": regression,
              "backlog_preserved": True, "complete_replies": True, "serving_afterwards": True,
              "rows": rows}
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    assert regression if args.expect_regression else passed, "shared cap release latency did not meet the expected outcome"


if __name__ == "__main__":
    main()
