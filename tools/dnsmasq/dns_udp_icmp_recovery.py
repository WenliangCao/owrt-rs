#!/usr/bin/env python3
"""Real DNS service recovery after a private loopback UDP port refusal.

Capture only ordinary kernel-generated traffic in a fresh loopback-only netns.
Connected/unconnected harness sockets calibrate ICMP error delivery separately;
they do not change either daemon's socket options. A receive-error branch that
was not observed is explicitly uncovered even when retry recovery matches.
"""
import argparse
import copy
import errno
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import name, read_name, semantics
from dns_udp_refusal_diff import verify_reference

LISTEN = ("127.0.0.1", 19553)
UPSTREAM_PORT = 19554


def digest(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def query(host, ident):
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name(host) + b"\0\1\0\1"


def answer(request):
    _, end = read_name(request, 12)
    return request[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + request[12:end+4] + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 17])


def receive(sock, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recvfrom(65535)
    except socket.timeout:
        return None


def ip_packet(packet):
    if not packet:
        return None
    if packet[0] >> 4 == 4 and len(packet) >= 20:
        offset = (packet[0] & 15) * 4
        if offset < 20 or len(packet) < offset:
            return None
        return {"family": 4, "protocol": packet[9], "source": str(ipaddress.ip_address(packet[12:16])),
                "destination": str(ipaddress.ip_address(packet[16:20])), "payload": packet[offset:]}
    if packet[0] >> 4 == 6 and len(packet) >= 40:
        return {"family": 6, "protocol": packet[6], "source": str(ipaddress.ip_address(packet[8:24])),
                "destination": str(ipaddress.ip_address(packet[24:40])), "payload": packet[40:]}
    return None


def udp(packet):
    if packet is None or packet["protocol"] != 17 or len(packet["payload"]) < 8:
        return None
    source, destination, length, _ = struct.unpack("!4H", packet["payload"][:8])
    body = packet["payload"][8:min(length, len(packet["payload"]))]
    return {"source_port": source, "destination_port": destination,
            "dns_id": int.from_bytes(body[:2], "big") if len(body) >= 2 else None, "dns": body.hex()}


class Capture:
    def __init__(self):
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        self.socket.bind(("lo", 0)); self.socket.settimeout(.02)
        self.events, self.errors = [], []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                raw, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                if peer[2] == 4:  # Ignore loopback's duplicate outgoing capture.
                    continue
                packet = ip_packet(raw)
                if packet is None:
                    continue
                event = {"monotonic_ns": time.monotonic_ns(), "raw": raw.hex(),
                         "family": packet["family"], "source": packet["source"], "destination": packet["destination"]}
                datagram = udp(packet)
                if datagram and datagram["destination_port"] == UPSTREAM_PORT:
                    self.events.append({**event, "kind": "upstream-query", **datagram})
                elif packet["protocol"] in (1, 58) and len(packet["payload"]) >= 8:
                    kind, code = packet["payload"][:2]
                    quoted = udp(ip_packet(packet["payload"][8:]))
                    if quoted and quoted["destination_port"] == UPSTREAM_PORT:
                        self.events.append({**event, "kind": "icmp", "type": kind, "code": code, "quoted": quoted})
            except Exception as error:
                self.errors.append(repr(error))

    def wait_for(self, kind, timeout=2):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            events = [event for event in self.events if event["kind"] == kind]
            if events:
                return events[0]
            time.sleep(.005)
        raise TimeoutError("capture did not observe " + kind)

    def close(self):
        self.stop.set(); self.thread.join(2); self.socket.close()
        assert not self.thread.is_alive() and not self.errors, self.errors


def process_state(pid):
    root = Path(f"/proc/{pid}")
    fds = {}
    for fd in (root / "fd").iterdir():
        try:
            fds[fd.name] = os.readlink(fd)
        except FileNotFoundError:
            pass
    sockets = []
    for table in ["udp", "udp6"]:
        for line in (root / "net" / table).read_text().splitlines()[1:]:
            fields = line.split()
            inode = fields[9]
            owners = [fd for fd, value in fds.items() if value == f"socket:[{inode}]"]
            if owners:
                sockets.append({"table": table, "fds": owners, "inode": inode,
                                "local": fields[1], "remote": fields[2],
                                "local_port": int(fields[1].split(":")[1], 16)})
    status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
              for line in (root / "status").read_text().splitlines() if ":" in line}
    return {"fds": fds, "udp_sockets": sockets, "fd_count": len(fds),
            "threads": int(status["Threads"]), "rss_sample": status.get("VmRSS"),
            "children": (root / "task" / str(pid) / "children").read_text().split()}


def delivery_calibration():
    rows = []
    for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
        for connected in [False, True]:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.bind((host, 0)); sock.setblocking(False)
                if connected:
                    sock.connect((host, UPSTREAM_PORT))
                sock.sendto(b"isolated UDP error-delivery control", (host, UPSTREAM_PORT))
                poll = select.poll(); poll.register(sock, select.POLLIN | select.POLLERR)
                events = poll.poll(100)
                try:
                    sock.recvfrom(65535); received_errno = None
                except OSError as error:
                    received_errno = error.errno
                rows.append({"family": int(family), "connected": connected,
                             "revents": [value for _, value in events], "recv_errno": received_errno})
    assert all(row["recv_errno"] == errno.ECONNREFUSED and any(value & select.POLLERR for value in row["revents"])
               for row in rows if row["connected"]), "kernel error-delivery control failed"
    return rows


def strace_events(folder):
    lines = [line for path in sorted(folder.glob("syscalls.*")) for line in path.read_text().splitlines()]
    upstream_fds = set()
    for line in lines:
        if f"htons({UPSTREAM_PORT})" in line:
            match = re.search(r"send(?:to|msg)\((\d+)", line)
            if match:
                upstream_fds.add(int(match.group(1)))
    recv_errors = []
    poll_errors = []
    for line in lines:
        match = re.search(r"recv(?:from|msg|mmsg)\((\d+).* = -1 ([A-Z0-9_]+)", line)
        if match and int(match.group(1)) in upstream_fds and match.group(2) not in ["EAGAIN", "EWOULDBLOCK", "EINTR"]:
            recv_errors.append(line)
        if any(flag in state for state in re.findall(r"revents=([A-Z0-9_|]+)", line) for flag in ["POLLERR", "POLLHUP", "POLLNVAL"]):
            if any(re.search(rf"fd={fd}(?:<|,)", line) for fd in upstream_fds):
                poll_errors.append(line)
    return {"upstream_fds": sorted(upstream_fds), "receive_errors": recv_errors, "poll_error_results": poll_errors}


def run(binary, family, config, folder):
    folder.mkdir()
    trace = {"status": "failed", "states": {}, "packets": [], "coverage": {}}
    process = tracer = capture = None
    tracer_log = (folder / "strace.log").open("wb")
    log = (folder / "daemon.log").open("wb")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            process = subprocess.Popen([str(binary), "-d", "-C", str(config)], stdout=log, stderr=log)
            ready = query("ready.test", 0x5101)
            for _ in range(100):
                assert process.poll() is None, "daemon exited before ready"
                client.sendto(ready, LISTEN)
                if receive(client, .03):
                    break
                time.sleep(.01)
            else:
                raise TimeoutError("daemon readiness")
            tracer = subprocess.Popen(["strace", "-ff", "-ttt", "-yy", "-xx", "-s", "65535", "-e",
                                       "trace=socket,bind,connect,sendto,sendmsg,recvfrom,recvmsg,recvmmsg,close,poll,ppoll",
                                       "-o", str(folder / "syscalls"), "-p", str(process.pid)], stdout=tracer_log, stderr=tracer_log)
            deadline = time.monotonic()+3
            while True:
                status = Path(f"/proc/{process.pid}/status").read_text()
                if re.search(r"TracerPid:\s+[1-9]", status):
                    break
                assert tracer.poll() is None and time.monotonic() < deadline, "strace attach failed"
                time.sleep(.01)
            trace["states"]["ready"] = process_state(process.pid)
            capture = Capture()
            request = query("recover.test", 0x5100)
            trace["request"] = request.hex()
            client.sendto(request, LISTEN)
            first = capture.wait_for("upstream-query")
            icmp = capture.wait_for("icmp")
            trace["kernel_refusal"] = icmp["type"] == (3 if family == 4 else 1) and icmp["code"] == (3 if family == 4 else 4)
            assert trace["kernel_refusal"] and icmp["quoted"]["source_port"] == first["source_port"]
            trace["early_reply"] = receive(client, .2)
            if trace["early_reply"]:
                trace["early_reply"] = trace["early_reply"][0].hex()
            trace["states"]["after-icmp"] = process_state(process.pid)
            retained = [entry for entry in trace["states"]["after-icmp"]["udp_sockets"] if entry["local_port"] == first["source_port"]]
            trace["upstream_socket_retained"] = bool(retained)
            host = "127.0.0.1" if family == 4 else "::1"
            with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as upstream:
                upstream.bind((host, UPSTREAM_PORT))
                client.sendto(request, LISTEN)
                retried = receive(upstream, 2)
                trace["retry_received"] = retried is not None
                if retried:
                    packet, peer = retried
                    trace["retry_request"] = packet.hex()
                    trace["same_upstream_id"] = int.from_bytes(packet[:2], "big") == first["dns_id"]
                    trace["same_upstream_source_port"] = peer[1] == first["source_port"]
                    response = answer(packet); trace["upstream_response"] = response.hex()
                    upstream.sendto(response, peer)
                received = receive(client, 2)
                trace["client_reply"] = received[0].hex() if received else None
                trace["client_semantics"] = semantics(received[0]) if received else None
                trace["extra_client_reply"] = receive(client, .1) is not None
            time.sleep(.03)
            trace["states"]["completed"] = process_state(process.pid)
            trace["upstream_socket_released"] = not any(entry["local_port"] == first["source_port"] for entry in trace["states"]["completed"]["udp_sockets"])
            capture.close(); trace["packets"] = capture.events; capture = None
            trace["upstream_query_count"] = sum(event["kind"] == "upstream-query" for event in trace["packets"])
            process.terminate(); trace["exit"] = process.wait(5)
            tracer.wait(3)
            trace["coverage"] = strace_events(folder)
            trace["coverage"]["receive_error_branch_observed"] = bool(trace["coverage"]["receive_errors"] or trace["coverage"]["poll_error_results"])
            trace["status"] = "completed"
    except Exception as error:
        trace["error"] = repr(error)
    finally:
        if capture:
            capture.close(); trace["packets"] = capture.events
        if process and process.poll() is None:
            process.kill(); process.wait(5)
        if tracer and tracer.poll() is None:
            tracer.terminate(); tracer.wait(3)
        trace["reaped"] = process is not None and process.poll() is not None and not Path(f"/proc/{process.pid}").exists()
        log.close(); tracer_log.close()
        (folder / "trace.json").write_text(json.dumps(trace, indent=2)+"\n")
    return trace


def normalized(trace):
    return {key: trace.get(key) for key in ["status", "kernel_refusal", "early_reply", "retry_received", "same_upstream_id",
            "same_upstream_source_port", "upstream_socket_retained", "upstream_socket_released", "client_semantics",
            "extra_client_reply", "upstream_query_count", "exit", "reaped"]}


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("family result count differs")
    return [index for index, (left, right) in enumerate(zip(expected, actual)) if left != right]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--rust-sha256", required=True)
    parser.add_argument("--rust-revision", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert {name for _, name in socket.if_nameindex()} == {"lo"} and not Path("/etc/openwrt_release").exists()
    assert shutil.which("strace"), "strace is needed to distinguish delivered socket errors from ICMP traffic"
    c, rust, out = args.c.resolve(), args.rust.resolve(), args.out.resolve()
    c_identity = verify_reference(c, None)
    assert digest(rust) == args.rust_sha256
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    report = {"scope": "private loopback kernel ICMP and client retry; an unobserved receive-error path is not covered",
              "c_identity": c_identity, "rust_sha256": digest(rust), "rust_revision": args.rust_revision,
              "kernel": os.uname().release, "tool_sha256": digest(Path(__file__)),
              "delivery_calibration": delivery_calibration(), "rounds": [], "differences": [], "checks": []}
    c_results, rust_results = [], []
    for family in [4, 6]:
        host = "127.0.0.1" if family == 4 else "::1"
        config = out / f"family-{family}.conf"
        config.write_text(f"no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport={LISTEN[1]}\ncache-size=0\n"
                          f"no-0x20-encode\nserver={host}#{UPSTREAM_PORT}\nhost-record=ready.test,192.0.2.1\n")
        traces = {}
        for side, binary in [("c", c), ("rust", rust)]:
            trace = run(binary, family, config, out / f"{side}-v{family}")
            traces[side] = trace
            report["rounds"].append({"side": side, "family": family, "trace": trace})
            for key, expected in [("status", "completed"), ("kernel_refusal", True), ("early_reply", None),
                                  ("retry_received", True), ("same_upstream_id", True), ("upstream_socket_retained", True),
                                  ("same_upstream_source_port", True), ("extra_client_reply", False),
                                  ("upstream_socket_released", True), ("upstream_query_count", 2), ("exit", 0), ("reaped", True)]:
                report["checks"].append({"case": f"{side}-v{family}-{key}", "actual": trace.get(key), "expected": expected, "pass": trace.get(key) == expected})
            # Independent controlled-upstream success calibration: C and Rust
            # both returning no/wrong client reply must not pass by agreement.
            expected_reply = semantics(answer(query("recover.test", 0x5100)))
            report["checks"].append({"case": f"{side}-v{family}-controlled-answer", "actual": trace.get("client_semantics"),
                                      "expected": expected_reply, "pass": trace.get("client_semantics") == expected_reply})
        left, right = normalized(traces["c"]), normalized(traces["rust"])
        c_results.append(left); rust_results.append(right)
        if left != right:
            report["differences"].append({"family": family, "c": left, "rust": right})
    assert len(c_results) == len(rust_results) == 2
    assert compare(c_results, copy.deepcopy(c_results)) == []
    for field, value in [("same_upstream_id", False), ("client_semantics", None)]:
        changed = copy.deepcopy(c_results); changed[0][field] = value
        assert compare(c_results, changed) == [0], field
    try:
        compare(c_results, c_results[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("count calibration accepted a missing family")
    report["comparison_calibration"] = {"actual_C_equal": 1, "changed_ID_rejected": 1, "missing_reply_rejected": 1, "missing_family_rejected": 1}
    report["passed"] = sum(row["pass"] for row in report["checks"])
    report["failed"] = sum(not row["pass"] for row in report["checks"])
    report["receive_error_path_covered"] = all(row["trace"]["coverage"].get("receive_error_branch_observed", False) for row in report["rounds"])
    report["acceptance"] = "covered" if report["receive_error_path_covered"] else "receive-error path not reached; do not claim this source divergence reproduced"
    (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({key: report[key] for key in ["scope", "passed", "failed", "receive_error_path_covered", "acceptance"]}))
    return 1 if report["failed"] or report["differences"] else 0 if report["receive_error_path_covered"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
