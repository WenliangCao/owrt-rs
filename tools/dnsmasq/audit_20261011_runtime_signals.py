#!/usr/bin/env python3
"""Compare daemon signal behavior; run only through run_isolated.sh on Linux."""
import argparse
import hashlib
import json
import os
import re
import resource
import threading
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from audit_20261011_dhcp import packet as dhcp_packet, decode as dhcp_decode

from m2_rootfs import image_elf_command


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


def dump_summary(log):
    return {
        "cache": [list(map(int, row)) for row in re.findall(
            r"cache size (\d+), (\d+)/(\d+) cache insertions", log)],
        "queries": [list(map(int, row)) for row in re.findall(
            r"queries forwarded (\d+), queries answered locally (\d+)", log)],
        "tcp": [list(map(int, row)) for row in re.findall(
            r"TCP requests: in use (\d+), highest since last SIGUSR1 (\d+), max allowed (\d+)", log)],
        "server": [list(map(int, row)) for row in re.findall(
            r"server 127.0.0.1#15354: queries sent (\d+), retried (\d+), failed (\d+), nxdomain replies (\d+)", log)],
        "host_rows": len(re.findall(r"audit\.test\s+192\.0\.2\.1\s+4FRI", log)),
        "cached_rows": len(re.findall(r"cached\.test\s+192\.0\.2\.2\s+4F", log)),
    }


def run_dump(label, command, binary, out):
    """A real forwarded record and repeated dumps must preserve counters/cache."""
    log = out / f"{label}-dump.log"
    argv = command + ["-C", "/dev/null", "-k", "--user=root", "--group=root",
        "--port=15353", "--no-resolv", "--no-hosts", "--listen-address=127.0.0.1",
        "--bind-interfaces", "--host-record=audit.test,192.0.2.1",
        "--server=127.0.0.1#15354", "--bogus-nxdomain=192.0.2.3",
        "--pid-file=", "--log-facility=-", "--log-queries"]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, log.open("wb") as stream:
        upstream.bind(("127.0.0.1", 15354))
        upstream.settimeout(0.1)
        stop = threading.Event()
        received = []
        def answer():
            while not stop.is_set():
                try:
                    data, peer = upstream.recvfrom(4096)
                except socket.timeout:
                    continue
                received.append(data.hex())
                end = 12
                while data[end]:
                    end += data[end] + 1
                end += 5
                is_negative = data[12:end].lower().startswith(b"\x08nxdomain")
                address = bytes([192, 0, 2, 3 if data[12:end].lower().startswith(b"\x05bogus") else 2])
                reply = data[:2] + struct.pack("!5H", 0x8183 if is_negative else 0x8180, 1, 0 if is_negative else 1, 0, 0) + data[12:end]
                if not is_negative:
                    reply += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + address
                upstream.sendto(reply, peer)
        thread = threading.Thread(target=answer)
        thread.start()
        proc = subprocess.Popen(argv, stdout=stream, stderr=stream)
        try:
            deadline = time.monotonic() + 5
            while not query(15353):
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(f"{label} dump startup failed")
                time.sleep(.02)
            wire = struct.pack("!6H", 0x3456, 0x100, 1, 0, 0, 0) + b"\x06cached\x04test\0" + struct.pack("!2H", 1, 1)
            for _ in range(2):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(wire, ("127.0.0.1", 15353))
                    assert client.recv(4096).endswith(bytes([192, 0, 2, 2]))
            # Both ordinary NXDOMAIN and policy-converted NOERROR count as
            # NXDOMAIN replies; the transport's raw RCODE alone is insufficient.
            for name in (b"\x05bogus\x04test\0", b"\x08nxdomain\x04test\0"):
                negative_query = wire[:12] + name + struct.pack("!2H", 1, 1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(negative_query, ("127.0.0.1", 15353))
                    assert client.recv(4096)[3] & 15 == 3
            for _ in range(2):
                proc.send_signal(signal.SIGUSR1)
                time.sleep(.15)
            text = log.read_text(errors="replace")
            return {"implementation": label, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "daemon_alive": proc.poll() is None, "upstream_queries": len(received),
                    "dump": dump_summary(text)}
        finally:
            stop.set()
            thread.join()
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=5)


def run_alarm_maintenance(label, command, binary, out):
    """Restore a failed leasefile write, then ALRM must retry before its 60s timer."""
    leasefile = out / f"{label}-alarm-maintenance.leases"
    log = out / f"{label}-alarm-maintenance.log"
    argv = command + ["-C", "/dev/null", "-k", "--user=root", "--group=root",
        "--port=15353", "--no-resolv", "--no-hosts", "--listen-address=127.0.0.1",
        "--bind-interfaces", "--address=/audit.test/192.0.2.1", "--pid-file=",
        "--log-facility=-", "--no-ping", "--dhcp-authoritative",
        "--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,1h", f"--dhcp-leasefile={leasefile}"]
    # Inherit ignored SIGXFSZ: write(2) returns EFBIG, as a full lease volume
    # would return ENOSPC. The daemon's log is a pipe, unaffected by RLIMIT_FSIZE.
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            preexec_fn=lambda: signal.signal(signal.SIGXFSZ, signal.SIG_IGN))
    output = bytearray()
    def collect():
        while data := proc.stdout.read(4096):
            output.extend(data)
    thread = threading.Thread(target=collect)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not query(15353):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"{label} alarm startup failed")
            time.sleep(.02)
        previous = resource.prlimit(proc.pid, resource.RLIMIT_FSIZE)
        resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, (0, previous[1]))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
            client.bind(("0.0.0.0", 68))
            client.settimeout(2)
            client.sendto(dhcp_packet(3, 0x12345678, name="alarm-client"), ("255.255.255.255", 67))
            ack = dhcp_decode(client.recv(4096))
        resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, previous)
        before = leasefile.read_text()
        assert "alarm-client" not in before, "failure injection did not prevent lease persistence"
        proc.send_signal(signal.SIGALRM)
        deadline = time.monotonic() + 2
        after = before
        while time.monotonic() < deadline and proc.poll() is None:
            after = leasefile.read_text()
            if "alarm-client" in after:
                break
            time.sleep(.02)
        return {"implementation": label, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "ack": ack["message_type"], "lease_absent_before_alarm": "alarm-client" not in before,
                "lease_persisted_after_alarm": "alarm-client" in after,
                "daemon_alive": proc.poll() is None, "dns_after": query(15353)}
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)
        thread.join(timeout=5)
        log.write_bytes(output)


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
        ("rust", image_elf_command(root, args.rust), args.rust),
    ]
    rows = [run_case(label, command, binary, args.out, signum)
            for signum in (signal.SIGHUP, signal.SIGUSR2, signal.SIGUSR1, signal.SIGALRM)
            for label, command, binary in implementations]
    dumps = [run_dump(label, command, binary, args.out) for label, command, binary in implementations]
    maintenance = [run_alarm_maintenance(label, command, binary, args.out) for label, command, binary in implementations]
    result = {"isolated": True, "cases": rows, "cache_dumps": dumps, "alarm_maintenance": maintenance}
    result["passed"] = (all(row["dns_after"] and row["exit_status_after_signal"] is None for row in rows)
        and all(row["daemon_alive"] and row["upstream_queries"] == 3 for row in dumps)
        and all(row["dump"] == dumps[0]["dump"] for row in dumps)
        and dumps[0]["dump"]["cached_rows"] == 2
        and dumps[0]["dump"]["host_rows"] == 2
        and all(row["ack"] == 5 and row["lease_absent_before_alarm"]
                and row["lease_persisted_after_alarm"] and row["daemon_alive"] and row["dns_after"]
                for row in maintenance))
    (args.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
