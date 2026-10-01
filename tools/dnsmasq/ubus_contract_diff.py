#!/usr/bin/env python3
"""Real image-matching C daemon / private ubusd contract baseline.

This is C-only evidence until a Rust service is supplied in a later phase. No
mock counters, extracted handler or Rust-generated expectations are used. Run
through run_isolated.sh on the build host; the script additionally hides /run.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dhcp_lease_lifecycle import packet as dhcp_packet

ROOT = Path(__file__).resolve().parents[2]
NAMES = [
    "dns_cache_inserted", "dns_cache_live_freed", "dns_queries_forwarded",
    "dns_auth_answered", "dns_local_answered", "dns_stale_answered", "dns_unanswered",
    "dnssec_max_crypto_use", "dnssec_max_sig_fail", "dnssec_max_work", "bootp", "pxe",
    "dhcp_ack", "dhcp_decline", "dhcp_discover", "dhcp_inform", "dhcp_nak",
    "dhcp_offer", "dhcp_release", "dhcp_request", "noanswer", "leases_allocated_4",
    "leases_pruned_4", "leases_allocated_6", "leases_pruned_6", "tcp_connections",
    "dhcp_leasequery", "dhcp_lease_unassigned", "dhcp_lease_actve", "dhcp_lease_unknown",
]
BUS = "/run/ubus/ubus.sock"
OBJECT = "contract.dnsmasq"
ORIGINAL = {1: "192.0.2.1", 28: "2001:db8::1"}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fields(hex_payload):
    data = bytes.fromhex(hex_payload)
    result = []
    while data:
        header = struct.unpack("!I", data[:4])[0]
        size, kind = header & 0xffffff, (header >> 24) & 0x7f
        assert header >> 31 and 8 <= size <= len(data), "invalid blobmsg field"
        name_length = struct.unpack("!H", data[4:6])[0]
        name = data[6:6 + name_length].decode()
        assert data[6 + name_length] == 0
        value = data[4 + ((3 + name_length + 3) & ~3):size]
        if kind == 3:
            assert value[-1:] == b"\0"
            decoded = value[:-1].decode()
        elif kind == 5:
            assert len(value) == 4, "metric width is not u32"
            decoded = struct.unpack("!I", value)[0]
        else:
            decoded = value.hex()
        result.append({"name": name, "type": kind, "value": decoded})
        data = data[(size + 3) & ~3:]
    return result


def read_json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.endswith("}")]


def receive_exact(sock, count):
    value = bytearray()
    while len(value) < count:
        part = sock.recv(count - len(value))
        if not part:
            raise EOFError("partial DNS TCP response")
        value.extend(part)
    return bytes(value)


class Upstream:
    def __init__(self):
        self.stop = threading.Event()
        self.errors = []
        self.requests = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("127.0.0.1", 15354))
        self.tcp.bind(("127.0.0.1", 15354))
        self.tcp.listen()
        self.threads = []
        for sock, tcp in [(self.udp, False), (self.tcp, True)]:
            sock.settimeout(.1)
            thread = threading.Thread(target=self.run, args=(sock, tcp), daemon=True)
            thread.start()
            self.threads.append(thread)

    def answer(self, query, transport):
        end = 12
        while query[end]:
            end += query[end] + 1
        end += 5
        kind = struct.unpack("!H", query[end - 4:end - 2])[0]
        address = ipaddress.ip_address(ORIGINAL[kind]).packed
        self.requests.append({"transport": transport, "query": query.hex()})
        return (query[:2] + struct.pack("!HHHHH", 0x8580, 1, 1, 0, 0) + query[12:end]
                + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 120, len(address)) + address)

    def run(self, sock, tcp):
        while not self.stop.is_set():
            try:
                if tcp:
                    conn, _ = sock.accept()
                    with conn:
                        conn.settimeout(2)
                        query = receive_exact(conn, struct.unpack("!H", receive_exact(conn, 2))[0])
                        answer = self.answer(query, "tcp")
                        conn.sendall(struct.pack("!H", len(answer)) + answer)
                else:
                    query, peer = sock.recvfrom(65535)
                    sock.sendto(self.answer(query, "udp"), peer)
            except socket.timeout:
                pass
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(3)
        self.udp.close()
        self.tcp.close()


class Fixture:
    def __init__(self, args, out):
        self.args, self.out = args, out
        self.checks, self.raw, self.children = [], [], []
        self.index = 0
        self.env = dict(os.environ, LD_LIBRARY_PATH=str(args.reference_build / "deps/lib"))
        self.client = out / "ubus-contract-client"
        deps = args.reference_build / "deps"
        command = [getattr(args, "compiler", "cc"), "-Wall", "-Wextra", "-Werror", "-O2",
                   "-I" + str(deps / "include"), str(ROOT / "tools/dnsmasq/ubus_contract_client.c"),
                   "-L" + str(deps / "lib"), "-Wl,-rpath," + str(deps / "lib"),
                   "-lubus", "-lubox", "-o", str(self.client)]
        result = subprocess.run(command, capture_output=True, text=True, env=self.env)
        (out / "client-build.json").write_text(json.dumps({"command": command, "exit": result.returncode,
                                                           "stdout": result.stdout, "stderr": result.stderr}, indent=2))
        result.check_returncode()
        self.upstream = Upstream()
        self.bus = None
        self.daemon = None

    def check(self, name, actual, expected):
        self.checks.append({"case": name, "actual": actual, "expected": expected, "pass": actual == expected})

    def spawn(self, command, label):
        path = self.out / f"{self.index:03}-{label}.log"
        self.index += 1
        with path.open("wb") as log:
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=self.env)
        self.children.append(child)
        return child, path

    def stop(self, child):
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                self.check("forced-kill", True, False)
        if child:
            self.check("process-resources-released", Path(f"/proc/{child.pid}").exists(), False)

    def start_bus(self):
        Path(BUS).unlink(missing_ok=True)
        self.bus, _ = self.spawn([str(self.args.reference_build / "deps/sbin/ubusd"), "-s", BUS], "ubusd")
        end = time.monotonic() + 3
        while not Path(BUS).exists():
            assert self.bus.poll() is None and time.monotonic() < end, "private ubusd failed"
            time.sleep(.01)

    def client_call(self, action, path=OBJECT, method=None):
        cmd = [str(self.client), BUS, action, path] + ([method] if method else [])
        result = subprocess.run(cmd, capture_output=True, text=True, env=self.env, timeout=3)
        record = {"action": action, "path": path, "method": method, "exit": result.returncode,
                  "stdout": result.stdout, "stderr": result.stderr}
        self.raw.append(record)
        return [json.loads(line) for line in result.stdout.splitlines()] if result.returncode == 0 else []

    def start_daemon(self, extra="", ubus=True):
        config = self.out / f"config-{self.index}.conf"
        lease = self.out / f"leases-{self.index}"
        config.write_text("no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\n"
                          "bind-interfaces\nserver=127.0.0.1#15354\ncache-size=20\n"
                          "no-ping\ndhcp-authoritative\ndhcp-lease-max=150\n"
                          "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n"
                          f"dhcp-leasefile={lease}\npid-file={self.out / 'dnsmasq.pid'}\n"
                          + (f"enable-ubus={OBJECT}\n" if ubus else "") + extra)
        binary = self.args.reference_build / "dnsmasq/dnsmasq"
        self.daemon, _ = self.spawn([str(binary), "--keep-in-foreground", "--user=root", "--group=root",
                                     "--log-facility=-", "--conf-file=" + str(config)], "dnsmasq")
        if ubus:
            self.wait_registered()
        else:
            time.sleep(.1)
        assert self.daemon.poll() is None

    def wait_registered(self):
        end = time.monotonic() + 3
        while True:
            result = self.client_call("lookup")
            if any(row["event"] == "lookup" for row in result):
                return
            assert self.daemon.poll() is None and time.monotonic() < end, "object did not appear"
            # C retries an absent transport after a normal main-loop wakeup.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"", ("127.0.0.1", 15353))
            time.sleep(.02)

    def watch(self, response="none", delay=0, dns=True, expected_status=0):
        child, path = self.spawn([str(self.client), BUS, "watch", OBJECT + (".dns" if dns else ""),
                                  response, str(delay)], "subscriber")
        end = time.monotonic() + 3
        while True:
            rows = read_json_lines(path)
            ready = [row for row in rows if row.get("event") == "ready"]
            if ready:
                self.check("subscriber-registration", ready[0]["status"], expected_status)
                break
            assert child.poll() is None and time.monotonic() < end, "subscriber failed"
            time.sleep(.01)
        # Subscription-state messages and an invocation share the same stream;
        # this metrics call is a barrier, not a timing-based readiness guess.
        self.client_call("call", method="metrics")
        return child, path

    def dns(self, name, kind=1, tcp=False, cached=False):
        query = struct.pack("!HHHHHH", 0x1256, 0x100, 1, 0, 0, 0)
        query += b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
        query += struct.pack("!HH", kind, 1)
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            if tcp:
                sock.connect(("127.0.0.1", 15353))
                sock.sendall(struct.pack("!H", len(query)) + query)
                answer = receive_exact(sock, struct.unpack("!H", receive_exact(sock, 2))[0])
            else:
                sock.sendto(query, ("127.0.0.1", 15353))
                answer = sock.recv(65535)
        elapsed = (time.monotonic() - started) * 1000
        result = {"name": name, "kind": kind, "transport": "tcp" if tcp else "udp", "ms": elapsed,
                  "query": query.hex(), "answer": answer.hex()}
        self.raw.append(result)
        self.check(name + "-id", answer[:2], query[:2])
        self.check(name + "-answer-count", struct.unpack("!H", answer[6:8])[0], 1)
        ttl = struct.unpack("!I", answer[-(10 if kind == 1 else 22):-(6 if kind == 1 else 18)])[0]
        self.check(name + "-ttl", ttl in (119, 120) if cached else ttl == 120, True)
        return str(ipaddress.ip_address(answer[-(4 if kind == 1 else 16):])), bool(answer[2] & 4), elapsed

    def metrics(self):
        rows = self.client_call("call", method="metrics")
        data = [row for row in rows if row["event"] == "data"]
        self.check("metrics-one-reply", len(data), 1)
        self.check("metrics-success", rows[-1]["status"], 0)
        decoded = fields(data[0]["wire"])
        self.check("metrics-names-order", [field["name"] for field in decoded], NAMES)
        self.check("metrics-all-u32", [field["type"] for field in decoded], [5] * 30)
        return {field["name"]: field["value"] for field in decoded}

    def close(self):
        for child in reversed(self.children):
            self.stop(child)
        self.upstream.close()
        self.check("upstream-errors", self.upstream.errors, [])


def baseline(f):
    f.start_bus()
    f.start_daemon()
    for path, methods in [(OBJECT, ["metrics"]), (OBJECT + ".dns", [])]:
        row = next(row for row in f.client_call("lookup", path) if row["event"] == "lookup")
        f.check("object-path", row["path"], path)
        f.check("object-has-type", row["type"] > 0, True)
        f.check("method-signature", fields(row["wire"]),
                [{"name": name, "type": 2, "value": ""} for name in methods])
    f.check("absent-conntrack-method", f.client_call("call", method="set_connmark_allowlist")[-1]["status"], 3)
    initial = f.metrics()
    f.check("initial-metrics", list(initial.values()), [0] * 30)
    address, aa, _ = f.dns("unsubscribed.invalid")
    f.check("no-subscriber-address-aa", [address, aa],
            ["192.0.2.254" if f.args.inject_error else ORIGINAL[1], True])

    scenarios = [
        ("no-data", 1, "none", 0, ORIGINAL[1], True),
        ("rewrite-a", 1, "192.0.2.9", 0, "192.0.2.9", False),
        ("rewrite-aaaa", 28, "2001:db8::9", 0, "2001:db8::9", False),
        ("same-address", 1, ORIGINAL[1], 0, ORIGINAL[1], False),
        ("invalid-address", 1, "invalid", 0, ORIGINAL[1], True),
        ("wrong-family-a", 1, "2001:db8::9", 0, ORIGINAL[1], True),
        ("wrong-family-aaaa", 28, "192.0.2.9", 0, ORIGINAL[28], True),
        ("wrong-type", 1, "u32", 0, ORIGINAL[1], True),
        ("delayed", 1, "192.0.2.9", 30, "192.0.2.9", False),
        ("late", 1, "192.0.2.9", 180, ORIGINAL[1], True),
        ("silent", 1, "silent", 0, ORIGINAL[1], True),
        ("disconnect", 1, "disconnect", 0, ORIGINAL[1], True),
    ]
    for label, kind, response, delay, expected, expected_aa in scenarios:
        child, path = f.watch(response, delay)
        name = label + ".invalid"
        address, aa, elapsed = f.dns(name, kind)
        f.check(label + "-address-aa", [address, aa], [expected, expected_aa])
        if label in ("silent", "late"):
            f.check(label + "-100ms-budget", 75 <= elapsed < 500, True)
        notices = [row for row in read_json_lines(path) if row["event"] == "notify"]
        f.check(label + "-one-notification", len(notices), 1)
        if notices:
            f.check(label + "-notification", [notices[0]["method"], fields(notices[0]["wire"])],
                    ["dns_result", [{"name": "name", "type": 3, "value": name},
                                    {"name": "ttl", "type": 5, "value": 120},
                                    {"name": "type", "type": 3, "value": "A" if kind == 1 else "AAAA"},
                                    {"name": "address", "type": 3, "value": ORIGINAL[kind]}]])
        if label == "rewrite-a":
            before = f.metrics()
            cached_address, _, _ = f.dns(name, kind, cached=True)
            f.check("cache-keeps-rewrite", cached_address, expected)
            f.check("cache-hit-not-forwarded", f.metrics()["dns_queries_forwarded"], before["dns_queries_forwarded"])
            f.check("cache-hit-no-second-notification",
                    len([row for row in read_json_lines(path) if row["event"] == "notify"]), 1)
        f.stop(child)
    # Delays establish actual response order, independently of subscription order.
    for last, expected, aa in [("192.0.2.8", "192.0.2.8", False), ("invalid", ORIGINAL[1], True)]:
        first, _ = f.watch("192.0.2.7", 0)
        second, _ = f.watch(last, 30)
        address, actual_aa, _ = f.dns("multi-" + last.replace(".", "-") + ".invalid")
        f.check("last-response-wins-" + last, [address, actual_aa], [expected, aa])
        f.stop(first)
        f.stop(second)

    child, path = f.watch("192.0.2.9")
    address, aa, _ = f.dns("tcp.invalid", tcp=True)
    f.check("tcp-does-not-doctor", [address, aa], [ORIGINAL[1], True])
    time.sleep(.02)
    f.check("tcp-no-notification", [row for row in read_json_lines(path) if row["event"] == "notify"], [])
    address, aa, _ = f.dns("after-tcp.invalid")
    f.check("parent-keeps-subscription", [address, aa], ["192.0.2.9", False])
    f.stop(child)
    current = f.metrics()
    f.check("dns-live-counter", current["dns_queries_forwarded"] > 0, True)
    f.stop(f.bus)
    f.start_bus()
    f.wait_registered()
    f.check("reconnect-preserves-counters", f.metrics(), current)
    # First real-C baseline exposed an upstream defect: destroy clears only
    # the main object's IDs. The DNS object's stale type ID causes ubusd to
    # create a typeless object; lookup returns STATUS=0 without any DATA.
    # Preserve the observed failure; this is not a desired Rust contract.
    rows = f.client_call("lookup", OBJECT + ".dns")
    f.check("reference-defect-reconnect-dns-lookup-no-data", rows, [{"event": "status", "status": 0}])
    f.check("reference-defect-reconnect-dns-no-resolved-id",
            f.client_call("call", OBJECT + ".dns", "metrics"), [{"event": "status", "status": 5}])
    address, aa, _ = f.dns("after-reconnect.invalid")
    f.check("reference-defect-reconnected-subscriber-unavailable", [address, aa], [ORIGINAL[1], True])
    f.stop(f.daemon)

    for label, extra, expected_notifications in [
        ("normal", "", True), ("quiet", "quiet-dhcp\n", False),
        ("quiet-options", "quiet-dhcp\nlog-dhcp\n", True),
    ]:
        f.start_daemon(extra)
        child, path = f.watch(dns=False)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("0.0.0.0", 68))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
            sock.settimeout(1)
            for index, kind in enumerate([1, 3, 7]):
                value = dhcp_packet(kind, index + 1, address="127.0.0.10", selecting=kind == 3)
                sock.sendto(value, ("255.255.255.255", 67))
                if kind != 7:
                    reply = sock.recv(4096)
                    f.check(label + "-dhcp-id", reply[4:8], value[4:8])
                else:
                    time.sleep(.03)
        f.client_call("call", method="metrics")
        notices = [row for row in read_json_lines(path) if row["event"] == "notify"]
        f.check(label + "-dhcp-event-order", [row["method"] for row in notices],
                ["dhcp.ack", "dhcp.release"] if expected_notifications else [])
        for row in notices:
            # rfc2131's RELEASE log_packet call supplies NULL for string;
            # a name retained in the lease is not inserted into this event.
            expected_fields = [{"name": "mac", "type": 3, "value": "02:00:00:00:00:01"},
                               {"name": "ip", "type": 3, "value": "127.0.0.10"}]
            if row["method"] == "dhcp.ack":
                expected_fields.append({"name": "name", "type": 3, "value": "client1"})
            expected_fields.append({"name": "interface", "type": 3, "value": "lo"})
            f.check(label + "-dhcp-fields-" + row["method"], fields(row["wire"]),
                    expected_fields)
        metrics = f.metrics()
        for key in ["dhcp_discover", "dhcp_offer", "dhcp_request", "dhcp_ack", "dhcp_release",
                    "leases_allocated_4", "leases_pruned_4"]:
            f.check(label + "-" + key, metrics[key], 1)
        f.stop(child)
        f.stop(f.daemon)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.uname().sysname == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert os.geteuid() == 0 and not Path("/etc/openwrt_release").exists(), "isolated build host only"
    links = json.loads(subprocess.check_output(["ip", "-j", "link"]))
    assert {link["ifname"] for link in links} == {"lo"}, "loopback-only namespace required"
    args.reference_build = args.reference_build.resolve()
    binary = args.reference_build / "dnsmasq/dnsmasq"
    assert digest(binary) == args.c_sha256, "C reference identity changed"
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "dnsmasq-ubus-test", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Fixture(args, out)
    error = None
    try:
        baseline(f)
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    # Frozen after C-only baseline-04, before any Rust implementation exists.
    # The negative run changes one real DNS expectation, not the counter code.
    f.check("frozen-check-count", len(f.checks), 255)
    result = {"scope": "exact C daemon/private ubusd baseline; no Rust integration acceptance",
              "reference_defects": ["ubusd restart: stale DNS object type causes lookup STATUS=0 with no DATA; metrics reconnects"],
              "c_sha256": digest(binary), "ubusd_sha256": digest(args.reference_build / "deps/sbin/ubusd"),
              "tools": {name: digest(ROOT / "tools/dnsmasq" / name)
                        for name in ["ubus_contract_client.c", "ubus_contract_diff.py", "run_isolated.sh"]},
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks),
              "checks": f.checks, "raw": f.raw, "upstream": f.upstream.requests, "error": error}
    (out / "result.json").write_text(json.dumps(result, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: result[key] for key in ["scope", "passed", "failed", "error"]}))
    return bool(result["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
