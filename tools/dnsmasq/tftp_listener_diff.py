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
import resource
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


def reference_defects(case, c, rust):
    """Only measured, source-explained C defects; never waive a Rust leak."""
    expected = {}
    if case == "single":
        expected = {"single_replacement_fd_delta": (3, 2),
                    "single_cleanup_fd_delta": (2, 0),
                    "single_window_cleanup_fd_delta": (2, 0),
                    "single_retry_cleanup_fd_delta": (2, 0)}
    if case == "single-stale":
        expected = {"single_stale_replacement":
                    ({"packet_hex": (b"\0\3\0\1" + CONTENT[:512]).hex(), "source_tid_matches": True},
                     {"packet_hex": b"\0\3\0\1alternate".hex(), "source_tid_matches": True}),
                    "single_stale_cleanup_fd_delta": (1, 0)}
    return {key: {"c": left, "rust": right} for key, (left, right) in expected.items()
            if key in c and key in rust and c[key] == left and rust[key] == right}


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
    key = "single_cleanup_fd_delta"
    assert key in reference_defects("single", {key: 2}, {key: 0})
    assert reference_defects("single", {key: 2}, {key: 1}) == {}
    assert reference_defects("single", {key: 3}, {key: 0}) == {}
    return {"positive": 2, "negative": 8}


def wait_for_fds(process, baseline):
    deadline = time.monotonic() + 2
    while fd_count(process.pid) != baseline and time.monotonic() < deadline:
        time.sleep(0.01)
    return fd_count(process.pid) - baseline


def check_capacity(process, client, receive, normalized, listen, baseline):
    sock = client()
    tids = []
    # C's dedicated listener accepts while count <= tftp_max, so max=1
    # admits two RRQs, even when both came from the same peer address.
    for index in range(2):
        sock.sendto(RRQ, listen)
        packet, tid = receive(sock, f"same_peer_initial_{index}")
        assert packet == b"\0\3\0\1" + CONTENT[:512]
        tids.append(tid)
    normalized["same_peer_distinct_tids"] = tids[0] != tids[1]
    assert normalized["same_peer_distinct_tids"]
    normalized["same_file_shared_fd_delta"] = fd_count(process.pid) - baseline
    assert normalized["same_file_shared_fd_delta"] == 3  # Two sockets, one file.
    sock.sendto(RRQ, listen)
    normalized["capacity_waits"] = not select.select([sock], [], [], 0.05)[0]
    assert normalized["capacity_waits"]

    sock.sendto(b"\0\4\0\1", tids[0])
    packet, _ = receive(sock, "first_progress", tids[0])
    assert packet == b"\0\3\0\2" + CONTENT[512:]
    sock.sendto(b"\0\4\0\2", tids[0])
    # No resend: the third request must still be waiting in the server queue.
    packet, third = receive(sock, "queued_after_completion")
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    assert third != tids[1]
    sock.sendto(b"\0\4\0\1", tids[1])
    packet, _ = receive(sock, "second_still_independent", tids[1])
    assert packet == b"\0\3\0\2" + CONTENT[512:]
    sock.sendto(b"\0\5\0\0abort\0", tids[1])
    sock.sendto(b"\0\4\0\1", third)
    packet, _ = receive(sock, "queued_transfer_progress", third)
    assert packet == b"\0\3\0\2" + CONTENT[512:]
    sock.sendto(b"\0\4\0\2", third)
    normalized["capacity_cleanup_fd_delta"] = wait_for_fds(process, baseline)
    assert normalized["capacity_cleanup_fd_delta"] == 0


def check_fd_pressure(process, client, receive, normalized, listen, baseline):
    sock = client()
    original_limit = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)
    try:
        for slots in [0, 1]:
            used = {int(path.name) for path in Path(f"/proc/{process.pid}/fd").iterdir()}
            free = [fd for fd in range(max(used) + 3) if fd not in used]
            # Already-open descriptors above the new soft limit remain valid.
            # This provides exactly zero or one available descriptor, even
            # when the daemon's descriptor table contains holes.
            resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (free[slots], original_limit[1]))
            sock.sendto(RRQ, listen)
            if slots == 0:
                normalized["socket_emfile_silent"] = not select.select([sock], [], [], 0.05)[0]
                assert normalized["socket_emfile_silent"]
            else:
                packet, _ = receive(sock, "file_emfile_error")
                assert packet[:4] == b"\0\5\0\0"
            normalized[f"emfile_{slots}_fd_delta"] = wait_for_fds(process, baseline)
            assert normalized[f"emfile_{slots}_fd_delta"] == 0
            assert process.poll() is None
            resource.prlimit(process.pid, resource.RLIMIT_NOFILE, original_limit)
    finally:
        resource.prlimit(process.pid, resource.RLIMIT_NOFILE, original_limit)
    sock.sendto(RRQ, listen)
    packet, tid = receive(sock, "emfile_recovery_initial")
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    sock.sendto(b"\0\4\0\1", tid)
    packet, _ = receive(sock, "emfile_recovery_progress", tid)
    assert packet == b"\0\3\0\2" + CONTENT[512:]
    sock.sendto(b"\0\4\0\2", tid)
    normalized["emfile_recovery_fd_delta"] = wait_for_fds(process, baseline)
    assert normalized["emfile_recovery_fd_delta"] == 0


def check_single(process, client, receive, normalized, listen, baseline):
    first, second, third = client(), client(), client()

    def silent(sock, name):
        normalized[name] = not select.select([sock], [], [], 0.05)[0]
        assert normalized[name], name

    third.sendto(b"\0\2boot.bin\0octet\0", listen)
    packet, _ = receive(third, "single_unmatched_wrq", listen)
    assert packet[:4] == b"\0\5\0\4"
    first.sendto(RRQ, listen)
    packet, _ = receive(first, "single_initial", listen)
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    first.sendto(b"\0\1alternate.bin\0octet\0tsize\x000\0", listen)
    packet, _ = receive(first, "single_replacement_oack", listen)
    assert packet == b"\0\6tsize\x009\0"
    first.sendto(b"\0\4\0\0", listen)
    packet, _ = receive(first, "single_replacement", listen)
    assert packet == b"\0\3\0\1alternate"
    second.sendto(RRQ, listen)
    packet, _ = receive(second, "single_other_peer", listen)
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    normalized["single_replacement_fd_delta"] = fd_count(process.pid) - baseline
    third.sendto(RRQ, listen)
    silent(third, "single_capacity_drops")
    first.sendto(b"\0\2boot.bin\0octet\0", listen)
    silent(first, "single_matched_wrq_ignored")
    first.sendto(b"\0\1missing\0octet\0", listen)
    packet, _ = receive(first, "single_failed_replacement", listen)
    assert packet[:4] == b"\0\5\0\1"
    first.sendto(b"\0\4\0\1", listen)
    silent(first, "single_abandoned_ack_ignored")
    silent(third, "single_dropped_request_not_queued")
    second.sendto(b"\0\4\0\1", listen)
    packet, _ = receive(second, "single_other_peer_progress", listen)
    assert packet == b"\0\3\0\2" + CONTENT[512:]
    second.sendto(b"\0\4\0\2", listen)
    third.sendto(RRQ, listen)
    packet, _ = receive(third, "single_reuse_after_capacity", listen)
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    third.sendto(b"\0\5\0\0abort\0", listen)
    time.sleep(0.02)
    normalized["single_cleanup_fd_delta"] = fd_count(process.pid) - baseline

    first.sendto(b"\0\1window.bin\0octet\0blksize\x004\0windowsize\x003\0", listen)
    packet, _ = receive(first, "single_window_oack", listen)
    assert packet == b"\0\6blksize\x004\0windowsize\x003\0"
    first.sendto(b"\0\4\0\0", listen)
    for block, body in [(1, b"0123"), (2, b"4567"), (3, b"89ab")]:
        packet, _ = receive(first, f"single_window_initial_{block}", listen)
        assert packet == b"\0\3" + block.to_bytes(2, "big") + body
    first.sendto(b"\0\4\0\0", listen)
    silent(first, "single_duplicate_oack_ack_ignored")
    first.sendto(b"\0\4\0\2", listen)
    for block, body in [(3, b"89ab"), (4, b"cdef"), (5, b"g")]:
        packet, _ = receive(first, f"single_partial_window_{block}", listen)
        assert packet == b"\0\3" + block.to_bytes(2, "big") + body
    first.sendto(b"\0\4\0\2", listen)
    silent(first, "single_duplicate_data_ack_ignored")
    first.sendto(b"\0\4\0\5", listen)
    time.sleep(0.02)
    normalized["single_window_cleanup_fd_delta"] = fd_count(process.pid) - baseline

    first.sendto(RRQ, listen)
    packet, _ = receive(first, "single_retry_initial", listen)
    first.settimeout(4)
    retry, _ = receive(first, "single_retry_same_data", listen)
    assert retry == packet == b"\0\3\0\1" + CONTENT[:512]
    first.sendto(b"\0\5\0\0abort\0", listen)
    time.sleep(0.02)
    normalized["single_retry_cleanup_fd_delta"] = fd_count(process.pid) - baseline


def check_single_stale(process, client, receive, normalized, listen, baseline):
    sock = client()
    sock.sendto(RRQ, listen)
    packet, _ = receive(sock, "single_stale_initial", listen)
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    sock.sendto(b"\0\1alternate.bin\0octet\0", listen)
    receive(sock, "single_stale_replacement", listen)
    sock.sendto(b"\0\4\0\1", listen)
    time.sleep(0.02)
    normalized["single_stale_cleanup_fd_delta"] = fd_count(process.pid) - baseline


def check_single_timeout(process, client, receive, normalized, listen, baseline):
    sock = client()
    sock.sendto(RRQ, listen)
    packet, _ = receive(sock, "timeout_initial", listen)
    assert packet == b"\0\3\0\1" + CONTENT[:512]
    started = time.monotonic()
    assert fd_count(process.pid) == baseline + 1
    count = 0
    while fd_count(process.pid) != baseline:
        assert process.poll() is None
        assert time.monotonic() - started < 130, "TFTP timeout failed to release file"
        if select.select([sock], [], [], 0.05)[0]:
            retry, _ = receive(sock, f"timeout_retry_{count}", listen)
            assert retry == packet
            count += 1
    elapsed = time.monotonic() - started
    normalized["timeout_waited_120_seconds"] = elapsed >= 120
    assert normalized["timeout_waited_120_seconds"]
    normalized["timeout_fd_delta"] = fd_count(process.pid) - baseline
    normalized["timeout_retransmission_count"] = count
    sock.sendto(b"\0\1alternate.bin\0octet\0", listen)
    packet, _ = receive(sock, "timeout_listener_survived", listen)
    assert packet == b"\0\3\0\1alternate"
    sock.sendto(b"\0\4\0\1", listen)
    normalized["timeout_reuse_fd_delta"] = wait_for_fds(process, baseline)
    assert normalized["timeout_reuse_fd_delta"] == 0


def run_service(kind, binary, ip, out, case="protocol"):
    capacity_case = case == "capacity"
    single = case in ["single", "single-stale", "single-timeout"]
    fixture = out / "root"
    fixture.mkdir(exist_ok=True)
    fixture.chmod(0o755)
    (fixture / "boot.bin").write_bytes(CONTENT)
    (fixture / "boot.bin").chmod(0o644)
    (fixture / "alternate.bin").write_bytes(b"alternate")
    (fixture / "alternate.bin").chmod(0o644)
    (fixture / "window.bin").write_bytes(b"0123456789abcdefg")
    (fixture / "window.bin").chmod(0o644)
    (fixture / "private.bin").write_bytes(b"private")
    (fixture / "private.bin").chmod(0o600)
    (fixture / "directory").mkdir(exist_ok=True)
    (fixture / "directory").chmod(0o755)
    (fixture / "mutable.bin").write_bytes(b"x" * 20)
    (fixture / "mutable.bin").chmod(0o644)
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    listen = (ip, 69)
    label = f"{case}-{kind}-{'v6' if family == socket.AF_INET6 else 'v4'}"
    bind_ip = ("::" if ":" in ip else "0.0.0.0") if single else ip
    command = ([str(binary), f"[{bind_ip}]:69" if ":" in bind_ip else f"{bind_ip}:69", str(fixture), "1" if capacity_case else "2" if single else "50", "single" if single else "dedicated"]
               if kind == "rust" else
               [str(binary), "--no-daemon", "--port=0", "--no-hosts", "--no-resolv",
                "--user=root", "--group=root", "--enable-tftp",
                f"--listen-address={ip}", f"--tftp-root={fixture}", "--pid-file=",
                "--log-facility=-", f"--tftp-max={1 if capacity_case else 2 if single else 50}"] + (["--tftp-single-port"] if single else ["--bind-interfaces"]))
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
                wire.append({"name": name, "packet_hex": packet.hex(), "source": source,
                             "at_monotonic": time.monotonic()})
                if packet[:2] == b"\0\5":
                    assert len(packet) >= 5 and packet[-1] == 0, name
                    value = {"opcode": 5, "code": int.from_bytes(packet[2:4], "big")}
                else:
                    value = {"packet_hex": packet.hex()}
                value["source_tid_matches"] = (source[:2] == expected_tid[:2] if expected_tid else (source[1] == 69 if single else source[1] != 69))
                normalized[name] = value
                assert value["source_tid_matches"], name
                return packet, source

            if case == "single-stale":
                check_single_stale(process, client, receive, normalized, listen, baseline)
            elif case == "single-timeout":
                check_single_timeout(process, client, receive, normalized, listen, baseline)
            elif single:
                check_single(process, client, receive, normalized, listen, baseline)
            elif capacity_case:
                check_capacity(process, client, receive, normalized, listen, baseline)
            else:
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
                check_fd_pressure(process, client, receive, normalized, listen, baseline)
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
    parser.add_argument("--cases", nargs="+", choices=["protocol", "capacity", "single", "single-stale", "single-timeout"], default=["protocol", "capacity", "single", "single-stale"])
    parser.add_argument("--families", nargs="+", choices=["ipv4", "ipv6"], default=["ipv4", "ipv6"])
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
        for ip, case in [(ip, case) for ip in ["127.0.0.1" if family == "ipv4" else "::1" for family in args.families] for case in args.cases]:
            c = run_service("c", args.c, ip, out, case)
            rust = run_service("rust", args.rust, ip, out, case)
            mismatches = compare(c, rust)
            defects = reference_defects(case, c, rust)
            unexpected = [key for key in mismatches if key not in defects]
            report["rounds"].append({"family": "ipv6" if ":" in ip else "ipv4",
                                     "case": case,
                                     "checks": c["checks"] + 1, "mismatches": mismatches,
                                     "reference_defects": defects, "unexpected_mismatches": unexpected})
            assert not unexpected, unexpected
    except Exception as error:
        report["failures"].append(str(error))
        raise
    finally:
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
