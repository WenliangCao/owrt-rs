#!/usr/bin/env python3
"""Exact-C/Rust dedicated TFTP socket differential in an isolated Linux netns.

Requires prebuilt native C daemon and tftp_listener_probe.rs binaries. Wire
captures, logs and executable identities remain under ignored private/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]
C_SOURCE_HASH = "a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3"
C_ELF_HASH = "bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431"
CONTENT = bytes(range(256)) * 2 + b"final-block"
RRQ = b"\0\1boot.bin\0octet\0"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fd_count(pid):
    return len(list(Path(f"/proc/{pid}/fd").iterdir()))


def compare(left, right):
    keys = set(left) | set(right)
    return [key for key in sorted(keys) if left.get(key) != right.get(key)]


def calibrate():
    sample = {"data": [0, 3, 0, 1, 42], "error_code": 5,
              "source_tid_matches": True, "fd_delta": 0, "checks": 18}
    assert compare(sample, dict(sample)) == []
    for key, value in [("data", []), ("error_code", 0),
                       ("source_tid_matches", False), ("fd_delta", 1),
                       ("checks", 0)]:
        changed = dict(sample, **{key: value})
        assert compare(sample, changed) == [key]
    assert compare(sample, {}) == sorted(sample)
    return {"positive": 1, "negative": 6}


def run_service(kind, binary, ip, out):
    fixture = out / "root"
    fixture.mkdir(exist_ok=True)
    fixture.chmod(0o755)
    (fixture / "boot.bin").write_bytes(CONTENT)
    (fixture / "boot.bin").chmod(0o644)
    (fixture / "private.bin").write_bytes(b"private")
    (fixture / "private.bin").chmod(0o600)
    (fixture / "directory").mkdir(exist_ok=True)
    (fixture / "directory").chmod(0o755)
    (fixture / "mutable.bin").write_bytes(b"x" * 20)
    (fixture / "mutable.bin").chmod(0o644)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    listen = (ip, 69)
    label = f"{kind}-{'v6' if family == socket.AF_INET6 else 'v4'}"
    command = ([str(binary), f"[{ip}]:69" if ":" in ip else f"{ip}:69", str(fixture)]
               if kind == "rust" else
               [str(binary), "--no-daemon", "--port=0", "--no-hosts", "--no-resolv",
                "--user=root", "--group=root", "--enable-tftp", "--bind-interfaces",
                f"--listen-address={ip}", f"--tftp-root={fixture}", "--pid-file=",
                "--log-facility=-"])
    normalized, wire = {}, []
    process = None
    clients = []
    try:
        with (out / f"{label}.log").open("wb") as log:
            process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE if kind == "rust" else log,
                                       stderr=log)
            if kind == "rust":
                if not select.select([process.stdout], [], [], 5)[0]:
                    raise AssertionError("Rust readiness timeout")
                assert process.stdout.readline() == b"ready\n"
            else:
                deadline = time.monotonic() + 5
                while b"TFTP root is" not in (out / f"{label}.log").read_bytes():
                    assert process.poll() is None, "C daemon exited during startup"
                    assert time.monotonic() < deadline, "C readiness timeout"
                    time.sleep(0.01)
            baseline = fd_count(process.pid)

            def client():
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.bind((ip, 0))
                sock.settimeout(0.8)
                clients.append(sock)
                return sock

            def receive(sock, name, expected_tid=None):
                packet, source = sock.recvfrom(8192)
                wire.append({"name": name, "packet_hex": packet.hex(), "source": source})
                if packet[:2] == b"\0\5":
                    assert len(packet) >= 5 and packet[-1] == 0, name
                    value = {"opcode": 5, "code": int.from_bytes(packet[2:4], "big")}
                else:
                    value = {"packet_hex": packet.hex()}
                value["source_tid_matches"] = (source == expected_tid if expected_tid else source[1] != 69)
                normalized[name] = value
                assert value["source_tid_matches"], name
                return packet, source

            first, second, foreign = client(), client(), client()
            tids = []
            for index, sock in enumerate([first, second]):
                sock.sendto(RRQ, listen)
                packet, tid = receive(sock, f"initial_{index}")
                assert packet == b"\0\3\0\1" + CONTENT[:512]
                tids.append(tid)
            assert tids[0] != tids[1]
            normalized["distinct_transfer_tids"] = True

            # A failed new request from an existing peer uses a temporary
            # socket and leaves that peer's original transfer untouched.
            active_fds = fd_count(process.pid)
            error_requests = [("missing", b"\0\1missing\0octet\0", 1),
                              ("permission", b"\0\1private.bin\0octet\0", 2),
                              ("not_directory", b"\0\1boot.bin/child\0octet\0", 0),
                              ("directory_read", b"\0\1directory\0octet\0", 0),
                              ("malformed", b"\0\1\0octet\0", 4),
                              ("wrq", b"\0\2boot.bin\0octet\0", 4),
                              ("traversal", b"\0\1../escape\0octet\0", 2)]
            for name, request, code in error_requests:
                first.sendto(request, listen)
                reply, source = receive(first, f"request_error_{name}")
                assert reply[:4] == bytes([0, 5, 0, code]), name
                assert source != tids[0], name
                normalized[f"request_error_{name}"]["temporary_tid"] = True
                deadline = time.monotonic() + 2
                while fd_count(process.pid) != active_fds and time.monotonic() < deadline:
                    time.sleep(0.01)
                delta = fd_count(process.pid) - active_fds
                normalized[f"request_error_{name}"]["fd_delta"] = delta
                assert delta == 0, name

            for name, packet in [("short", b"\0"), ("ack", b"\0\4\0\1"),
                                 ("error", b"\0\5\0\0"), ("rrq", RRQ)]:
                foreign.sendto(packet, tids[0])
                reply, _ = receive(foreign, f"foreign_{name}", tids[0])
                assert reply[:4] == b"\0\5\0\5"
            second.sendto(b"\0\4\0\1", tids[0])
            reply, _ = receive(second, "other_active_peer", tids[0])
            assert reply[:4] == b"\0\5\0\5"

            for name, sock, packet in [("owner_rrq_ignored", first, RRQ),
                                       ("empty_foreign_ignored", foreign, b"")]:
                sock.sendto(packet, tids[0])
                readable, _, _ = select.select([sock], [], [], 0.05)
                normalized[name] = not readable
                assert not readable, name

            for index, sock in enumerate([first, second]):
                sock.sendto(b"\0\4\0\1", tids[index])
                packet, _ = receive(sock, f"valid_ack_{index}", tids[index])
                assert packet == b"\0\3\0\2" + CONTENT[512:]
            first.sendto(b"\0\4\0\2", tids[0])
            second.sendto(b"\0\5\0\0abort\0", tids[1])
            deadline = time.monotonic() + 2
            while fd_count(process.pid) != baseline and time.monotonic() < deadline:
                time.sleep(0.01)
            normalized["fd_delta_after_complete_and_error"] = fd_count(process.pid) - baseline
            assert normalized["fd_delta_after_complete_and_error"] == 0

            # The inode remains open with its original size, then shrinks.
            # C sends the successful prefix of the window and one ERR_NOTDEF
            # for each later read failure, then releases file/socket state.
            first.sendto(b"\0\1mutable.bin\0octet\0blksize\x004\0windowsize\x004\0", listen)
            packet, tid = receive(first, "read_failure_oack")
            assert packet == b"\0\6blksize\x004\0windowsize\x004\0"
            (fixture / "mutable.bin").write_bytes(b"x" * 8)
            first.sendto(b"\0\4\0\0", tid)
            for index, expected in enumerate([b"\0\3\0\1xxxx", b"\0\3\0\2xxxx", None, None]):
                packet, _ = receive(first, f"read_failure_window_{index}", tid)
                assert packet == expected if expected is not None else packet[:4] == b"\0\5\0\0"
            deadline = time.monotonic() + 2
            while fd_count(process.pid) != baseline and time.monotonic() < deadline:
                time.sleep(0.01)
            normalized["fd_delta_after_read_failure"] = fd_count(process.pid) - baseline
            assert normalized["fd_delta_after_read_failure"] == 0
            assert process.poll() is None
            normalized["checks"] = len(normalized)
    finally:
        for sock in clients:
            sock.close()
        if process is not None:
            if process.poll() is None:
                if kind == "rust":
                    process.stdin.write(b"stop\n")
                    process.stdin.flush()
                else:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            normalized["clean_exit"] = process.returncode == 0
        (out / f"{label}.json").write_text(json.dumps({"normalized": normalized, "wire": wire}, indent=2) + "\n")
    assert normalized["clean_exit"]
    return normalized


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists(), "build-host namespace only"
    assert sha(args.source) == C_SOURCE_HASH, "exact C source identity mismatch"
    assert sha(args.c) == C_ELF_HASH, "exact C executable identity mismatch"
    out = args.out.resolve()
    assert out.is_relative_to(REPO / "private"), "evidence must stay under private/"
    out.mkdir(parents=True, exist_ok=False)
    sources = ["components/dnsmasq/src/" + name for name in
               ["net.rs", "tftp.rs", "tftp_service.rs", "tftp_runtime.rs", "tftp_listener.rs"]]
    sources += ["tools/dnsmasq/tftp_listener_probe.rs", "tools/dnsmasq/tftp_listener_diff.py"]
    report = {"calibration": calibrate(), "c_sha256": sha(args.c),
              "rust_sha256": sha(args.rust), "tftp_c_sha256": sha(args.source),
              "rust_source_sha256": {name: sha(REPO / name) for name in sources},
              "rounds": [], "failures": []}
    try:
        for ip in ["127.0.0.1", "::1"]:
            c = run_service("c", args.c, ip, out)
            rust = run_service("rust", args.rust, ip, out)
            mismatches = compare(c, rust)
            report["rounds"].append({"family": "ipv6" if ":" in ip else "ipv4",
                                     "checks": c["checks"] + 1, "mismatches": mismatches})
            assert not mismatches, mismatches
    except Exception as error:
        report["failures"].append(str(error))
        raise
    finally:
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
