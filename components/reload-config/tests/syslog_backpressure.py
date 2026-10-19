#!/usr/bin/env python3
"""Run as root on Linux: syslog_backpressure.py RELOAD_BINARY OUTPUT.json.

A private mount namespace supplies /dev/log. Filling a fresh sender's first
message proves the receiver queue is full, rather than just one sender buffer.
Four stalled-consumer cases and four healthy controls exercise the real CLI.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def inner(device, root, binary):
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "--bind", device, "/dev"], check=True)
    os.execv(binary, [binary, "--root", root, "--timeout-ms", "100"])


def run_case(binary, stalled):
    with tempfile.TemporaryDirectory(prefix="reload-syslog-") as directory:
        root = Path(directory) / "root"
        device = Path(directory) / "dev"
        device.mkdir()
        (root / "etc/config").mkdir(parents=True)
        receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        receiver.bind(str(device / "log"))
        receiver.settimeout(0.1)
        senders = []
        filled = 0
        if stalled:
            for _ in range(64):
                sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sender.connect(str(device / "log"))
                sender.setblocking(False)
                senders.append(sender)
                sent = 0
                while True:
                    try:
                        sender.send(b"prefill")
                        filled += 1
                        sent += 1
                    except BlockingIOError:
                        break
                if sent == 0:
                    break
            else:
                raise AssertionError("fixture did not fill receiver queue")

        traces = []
        stop = threading.Event()

        def drain():
            while not stop.is_set():
                try:
                    message = receiver.recv(65536)
                    if message != b"prefill":
                        traces.append(message.decode())
                except TimeoutError:
                    continue

        reader = threading.Thread(target=drain)
        if not stalled:
            reader.start()
        command = ["unshare", "--mount", sys.executable, str(Path(__file__).resolve()),
                   "--inner", str(device), str(root), str(binary)]
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.3)
            blocked = child.poll() is None
            if stalled and blocked:
                child.send_signal(signal.SIGTERM)
            time.sleep(0.3)
            signal_blocked = child.poll() is None
            if stalled:
                reader.start()
            stdout, stderr = child.communicate(timeout=3)
            baseline = (root / "var/run/config.md5").exists()
            result = dict(stalled=stalled, filled=filled, blocked=blocked,
                          signal_blocked=signal_blocked, exit=child.returncode,
                          baseline=baseline, stdout=stdout.decode(), stderr=stderr.decode())
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            stop.set()
            if reader.ident is not None:
                reader.join()
            receiver.close()
            for sender in senders:
                sender.close()
        result["traces"] = traces
        result["passed"] = (result["exit"] == 0 and not blocked and not signal_blocked
                            and baseline and (stalled or len(traces) == 2))
        return result


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(*sys.argv[2:])
        return
    if len(sys.argv) != 3 or sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit(__doc__)
    binary = Path(sys.argv[1]).resolve()
    rows = [dict(round=round, **run_case(binary, stalled))
            for stalled in (True, False) for round in range(4)]
    result = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), rows=rows)
    Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    raise SystemExit(0 if all(row["passed"] for row in rows) else 1)


if __name__ == "__main__":
    main()
