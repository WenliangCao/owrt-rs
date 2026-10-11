#!/usr/bin/env python3
"""Compare daemon signal behavior; run only through run_isolated.sh on Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time


def query(port):
    packet = struct.pack("!6H", 0x1234, 0x100, 1, 0, 0, 0)
    packet += b"\x05audit\x04test\0" + struct.pack("!2H", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.25)
        sock.sendto(packet, ("127.0.0.1", port))
        try:
            answer = sock.recv(4096)
        except socket.timeout:
            return False
    return answer[:2] == packet[:2] and answer.endswith(bytes([192, 0, 2, 1]))


def run_case(label, command, binary, out, signum):
    name = f"{label}-{signal.Signals(signum).name}"
    pidfile = out / f"{name}.pid"
    log = out / f"{name}.log"
    argv = command + ["-C", "/dev/null", "-k", "--user=root", "--group=root",
                      "--port=15353", "--no-resolv", "--no-hosts",
                      "--listen-address=127.0.0.1", "--bind-interfaces",
                      "--address=/audit.test/192.0.2.1", f"--pid-file={pidfile}",
                      "--log-facility=-"]
    with log.open("wb") as stream:
        proc = subprocess.Popen(argv, stdout=stream, stderr=stream)
        try:
            deadline = time.monotonic() + 5
            while not query(15353):
                if proc.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError(f"{name} failed startup: {log.read_text()}")
                time.sleep(0.02)
            proc.send_signal(signum)
            time.sleep(0.2)
            status = proc.poll()
            after = query(15353)
            row = {"implementation": label,
                   "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                   "signal": signal.Signals(signum).name,
                   "dns_before": True, "exit_status_after_signal": status,
                   "dns_after": after, "pidfile_exists_after_signal": pidfile.exists(),
                   "log_after_signal": log.read_text(errors="replace")}
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True, type=Path)
    parser.add_argument("--c-native", required=True, type=Path)
    parser.add_argument("--image-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run through tools/dnsmasq/run_isolated.sh")
    args.out.mkdir(parents=True, exist_ok=False)
    root = args.image_root
    image_binary = root / "usr/sbin/dnsmasq"
    loader = next((root / "lib").glob("ld-musl-*.so.1"))
    implementations = [
        ("c-image", [str(loader), "--library-path", f"{root}/lib:{root}/usr/lib",
                     str(image_binary)], image_binary),
        ("c-native", [str(args.c_native)], args.c_native),
        ("rust", [str(args.rust)], args.rust),
    ]
    rows = [run_case(label, command, binary, args.out, signum)
            for signum in (signal.SIGHUP, signal.SIGUSR2, signal.SIGUSR1, signal.SIGALRM)
            for label, command, binary in implementations]
    (args.out / "result.json").write_text(json.dumps({"isolated": True, "cases": rows}, indent=2) + "\n")
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
