#!/usr/bin/env python3
"""Count HTTPD syscalls on the Linux build host with the frozen native client.

Uses only an owned process group, scratch files and a loopback listener. Trace
timings are diagnostic, never router benchmark results. Output must be new.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("httpd", type=Path)
    parser.add_argument("client", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--clients", type=int, choices=(1, 4), default=1)
    parser.add_argument("--bytes", type=int, dest="size", default=16384)
    parser.add_argument("--port", type=int, default=28585)
    args = parser.parse_args()
    if args.iterations <= 0 or args.iterations % args.clients or args.size <= 0:
        parser.error("iterations must be positive and divisible by clients; bytes must be positive")
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    with tempfile.TemporaryDirectory(prefix="r85-httpd-trace-") as temp:
        root = Path(temp)
        fixture = root / "static.dat"
        fixture.write_bytes(bytes(args.size))
        address = f"127.0.0.1:{args.port}"
        command = ["strace", "-f", "-c", "-S", "time", "-o", str(output / "syscalls.txt"),
                   str(args.httpd.resolve()), "-f", "-h", str(root), "-r", "OpenWrt",
                   "-x", "/cgi-bin", "-u", "/ubus", "-t", "60", "-T", "30",
                   "-k", "20", "-A", "1", "-n", "3", "-N", "100", "-R", "-p", address]
        with (output / "server.log").open("xb") as log:
            traced = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
            try:
                child = None
                for _ in range(100):
                    if traced.poll() is not None:
                        raise RuntimeError("traced server exited during startup")
                    children = Path(f"/proc/{traced.pid}/task/{traced.pid}/children").read_text().split()
                    if len(children) == 1:
                        child = int(children[0])
                        try:
                            with socket.create_connection(("127.0.0.1", args.port), timeout=.1):
                                break
                        except OSError:
                            pass
                    time.sleep(.05)
                else:
                    raise RuntimeError("traced server did not listen")
                clients = []
                count = args.iterations // args.clients
                with ExitStack() as files:
                    try:
                        for i in range(args.clients):
                            name = "client.json" if args.clients == 1 else f"client-{i+1}.json"
                            target = files.enter_context((output / name).open("xb"))
                            process = subprocess.Popen([
                                str(args.client.resolve()), "http", address, "GET", "/static.dat",
                                "-", str(fixture), str(count), "20", str(child), "bytes"], stdout=target)
                            clients.append((process, name))
                        for process, name in clients:
                            if process.wait(timeout=180) != 0:
                                raise RuntimeError("traced client failed")
                            data = json.loads((output / name).read_text())
                            if data["successful"] != count or data["errors"] != 0:
                                raise RuntimeError("invalid traced workload")
                    finally:
                        for process, _ in clients:
                            if process.poll() is None:
                                process.kill()
                            process.wait()
                os.kill(child, signal.SIGTERM)
                traced.wait(timeout=5)
            finally:
                if traced.poll() is None:
                    os.killpg(traced.pid, signal.SIGTERM)
                    try:
                        traced.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(traced.pid, signal.SIGKILL)
                        traced.wait()
    (output / "settings.json").write_text(json.dumps({
        "iterations": args.iterations, "clients": args.clients,
        "warmup_per_client": 20, "fixture_bytes": args.size,
        "subject_sha256": hashlib.sha256(args.httpd.read_bytes()).hexdigest(),
        "client_sha256": hashlib.sha256(args.client.read_bytes()).hexdigest(),
        "kernel": os.uname().release, "architecture": os.uname().machine,
        "method": "strace syscall counts; timings are diagnostic, not router performance",
    }, indent=2) + "\n")
    (output / "COMPLETE").touch()
    print((output / "syscalls.txt").read_text())


if __name__ == "__main__":
    main()
