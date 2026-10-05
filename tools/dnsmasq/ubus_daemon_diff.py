#!/usr/bin/env python3
"""Actual C/Rust daemon UBus metrics, DNS doctor and DHCP event integration.

Runs the entire C schedule first. No fixture counters or test-only daemon CLI.
Raw packets/configuration/identities remain in a new private directory.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import query, semantics, exact_read
from dhcp_lease_lifecycle import packet as dhcp_packet
from ubus_contract_diff import BUS, OBJECT, Fixture, digest, fields, read_json_lines
from dns_udp_refusal_diff import verify_reference
from ubus_config_diff import cases as config_cases
from ubus_doctor_diff import cases as doctor_cases, field


class Product(Fixture):
    def stop(self, child):
        super().stop(child)
        if child is not None and child is self.daemon:
            self.check(self.side + "-daemon-normal-exit", child.returncode, 0)

    def start_product(self, side, extra="", port=15353, bus=True, restored=False,
                      cache_size=20, upstream=True, wait_bus=True, dhcp=True):
        self.side = side
        self.hosts = self.out / f"hosts-{self.index}"
        self.hosts.write_text("192.0.2.42 local.invalid\n")
        lease = self.out / f"lease-{self.index}"
        if restored:
            lease.write_text("4102444800 02:00:00:00:00:08 127.0.0.18 restored *\n")
        config = self.out / f"config-{self.index}"
        config.write_text(f"no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\n"
                          + ("server=127.0.0.1#15354\n" if upstream else "")
                          + f"cache-size={cache_size}\nlocal-ttl=120\n"
                          + ("no-ping\ndhcp-authoritative\ndhcp-lease-max=150\n"
                             "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n" if dhcp else "")
                          + f"dhcp-leasefile={lease}\naddn-hosts={self.hosts}\n"
                          + (f"enable-ubus={OBJECT}\n" if bus else "") + extra)
        binary = (self.args.c_binary or self.args.reference_build / "dnsmasq/dnsmasq") if side == "C" else self.args.rust_binary
        # Both products must reconnect with the same credentials and sink.
        # C-only root overrides hide the private ubusd socket's access policy.
        command = [str(binary), "--keep-in-foreground", "--conf-file=" + str(config),
                   "--user=root", "--group=root", "--log-facility=-",
                   "--pid-file=" + str(self.out / "pid")]
        self.daemon, self.daemon_log = self.spawn(command, side)
        if bus and wait_bus:
            self.wait_registered()
        else:
            time.sleep(.1)
        assert self.daemon.poll() is None

    def exchange(self, host, kind=1, tcp=None):
        packet = query(host, kind)
        if tcp is None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(packet, ("127.0.0.1", 15353))
                response = client.recv(65535)
        else:
            tcp.sendall(struct.pack("!H", len(packet)) + packet)
            response = exact_read(tcp, struct.unpack("!H", exact_read(tcp, 2))[0])
        self.raw.append({"side": self.side, "query": packet.hex(), "answer": response.hex(), "tcp": tcp is not None})
        return semantics(response)

    def wait_metric(self, field, value):
        deadline = time.monotonic() + 3
        while True:
            metrics = self.metrics()
            if metrics[field] == value:
                return metrics
            assert self.daemon.poll() is None and time.monotonic() < deadline, (field, value, metrics)
            time.sleep(.005)

    def reload(self):
        self.daemon.send_signal(signal.SIGHUP)
        return self.wait_metric("dns_cache_inserted", 0)

    def notices(self, log, expected=None):
        deadline = time.monotonic() + 2
        while True:
            rows = [row for row in read_json_lines(log) if row.get("event") == "notify"]
            if expected is None or len(rows) >= expected:
                return [{"method": row["method"], "fields": fields(row["wire"])} for row in rows]
            assert time.monotonic() < deadline, (log, expected, rows)
            time.sleep(.002)


def run_side(f, side):
    observed = {}
    def record(label, value):
        assert label not in observed
        observed[label] = value
    def snapshot(label):
        record(label, f.metrics())

    f.start_product(side, "alias=192.0.2.9,198.51.100.9\n")
    for path in (OBJECT, OBJECT + ".dns"):
        row = next(row for row in f.client_call("lookup", path) if row["event"] == "lookup")
        record("signature-" + path, {"signature": fields(row["wire"]), "has_type": row["type"] != 0})
    snapshot("initial")
    record("local-answer", f.exchange("local.invalid"))
    snapshot("after-local")
    record("forward-answer", f.exchange("forward.invalid"))
    snapshot("after-forward")
    record("cache-answer", f.exchange("forward.invalid"))
    snapshot("after-cache")
    record("reload-window", f.reload())
    snapshot("after-reload")
    for label, response, kind in [
        ("rewrite", "192.0.2.9", 1), ("rewrite6", "2001:db8::9", 28),
        ("same", "192.0.2.1", 1), ("invalid", "invalid", 1),
        ("wrong-family", "2001:db8::9", 1), ("silent", "silent", 1),
    ]:
        watcher, log = f.watch(response)
        record(label + "-answer", f.exchange(label + ".invalid", kind))
        record(label + "-notice", f.notices(log, 1))
        snapshot(label + "-metrics")
        if label == "rewrite":
            record("rewritten-cache-answer", f.exchange(label + ".invalid", kind))
            snapshot("rewritten-cache-metrics")
            record("rewritten-cache-notices", f.notices(log))
        f.stop(watcher)
    # The subscriber invokes metrics before finishing its dns_result callback.
    watcher, log = f.watch("metrics")
    record("queued-before", f.metrics())
    record("queued-answer", f.exchange("queued.invalid"))
    deadline = time.monotonic() + 2
    while True:
        data = [row for row in read_json_lines(log) if row.get("event") == "data"]
        if data:
            break
        assert time.monotonic() < deadline
        time.sleep(.002)
    record("queued-during", {row["name"]: row["value"] for row in fields(data[0]["wire"])})
    snapshot("queued-after")
    f.stop(watcher)
    # Gauge and TCP no-doctor behavior use real accepted/closed sessions.
    watcher, log = f.watch("192.0.2.9")
    with socket.create_connection(("127.0.0.1", 15353), 2) as tcp:
        record("tcp-active", f.wait_metric("tcp_connections", 1))
        record("tcp-local", f.exchange("local.invalid", tcp=tcp))
        snapshot("tcp-local-metrics")
        record("tcp-forward", f.exchange("tcp-forward.invalid", tcp=tcp))
    record("tcp-closed", f.wait_metric("tcp_connections", 0))
    record("tcp-notices", f.notices(log))
    f.stop(watcher)
    current = f.metrics()
    f.stop(f.bus)
    f.start_bus()
    f.wait_registered()
    f.check(side + "-reconnect-preserves-metrics", f.metrics(), current)
    rows = f.client_call("lookup", OBJECT + ".dns")
    if side == "C":
        f.check("C-known-restart-DNS-type-defect", rows, [{"event": "status", "status": 0}])
    else:
        f.check("Rust-reconnect-DNS-type", sum(row["event"] == "lookup" for row in rows), 1)
        watcher, log = f.watch("192.0.2.9")
        answer = f.exchange("reconnected.invalid")
        f.check("Rust-reconnected-doctor", answer["records"][0]["data"], "198.51.100.9")
        f.stop(watcher)
    f.stop(f.daemon)

    for label, extra, expected in [("normal", "", 2), ("quiet", "quiet-dhcp\n", 0),
                                   ("quiet-options", "quiet-dhcp\nlog-dhcp\n", 2)]:
        f.start_product(side, extra)
        watcher, log = f.watch(dns=False)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("0.0.0.0", 68))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
            client.settimeout(2)
            for index, kind in enumerate((1, 3, 7)):
                packet = dhcp_packet(kind, index + 1, address="127.0.0.10", selecting=kind == 3)
                client.sendto(packet, ("255.255.255.255", 67))
                if kind != 7:
                    reply = client.recv(4096)
                    f.check(side + label + "-reply-id", reply[4:8], packet[4:8])
                    f.raw.append({"side": side, "dhcp": packet.hex(), "reply": reply.hex()})
                else:
                    f.wait_metric("dhcp_release", 1)
                snapshot(label + "-after-" + str(kind))
        record(label + "-dhcp-notices", f.notices(log, expected))
        f.stop(watcher)
        f.stop(f.daemon)
    f.start_product(side, port=0, restored=True)
    snapshot("port-zero-restored")
    f.daemon.send_signal(signal.SIGHUP)
    time.sleep(.05)
    snapshot("port-zero-after-hup")
    f.stop(f.daemon)
    f.start_product(side, "use-stale-cache=10\n")
    record("stale-seed", f.exchange("stale.invalid"))
    snapshot("stale-seeded-metrics")
    time.sleep(3.1)
    record("stale-answer", f.exchange("stale.invalid"))
    record("stale-refresh-metrics", f.wait_metric("dns_cache_inserted", 2))
    f.stop(f.daemon)
    f.start_product(side, cache_size=2)
    for index in range(4):
        record(f"pressure-answer-{index}", f.exchange(f"pressure-{index}.invalid"))
    snapshot("pressure-metrics")
    f.stop(f.daemon)
    f.start_product(side, upstream=False)
    record("no-server-answer", f.exchange("unowned.invalid"))
    snapshot("no-server-metrics")
    f.stop(f.daemon)
    f.stop(f.bus)
    f.start_product(side, wait_bus=False)
    record("absent-bus-local-answer", f.exchange("local.invalid"))
    f.start_bus()
    f.wait_registered()
    snapshot("delayed-bus-metrics")
    f.stop(f.daemon)
    return observed


def compare(f, expected, actual, inject_error):
    f.check("paired-observation-keys", list(actual), list(expected))
    for key, reference in expected.items():
        value = actual.get(key)
        left, right = copy.deepcopy(reference), copy.deepcopy(value)
        if key.startswith("syntax-") or key.startswith("startup-collision"):
            if right is not None:
                for output in ("stderr", "log"):
                    if output in right:
                        raw = bytes.fromhex(right[output])
                        if raw.startswith(b"\ndnsmasq-rs: "):
                            right[output] = (b"\ndnsmasq: " + raw[len(b"\ndnsmasq-rs: "):]).hex()
        if key == "empty-activation":
            guarded = (left == {"exit": -11, "log": ""}
                       and right == {"exit": 1, "log": b"\ndnsmasq-rs: empty enable-ubus object name\n".hex()}
                       and expected["syntax-cli-01"]["exit"] == actual["syntax-cli-01"]["exit"] == 0)
            f.check("guard-empty-name-image-NULL-fault-and-safe-activation-refusal", guarded, True)
            if guarded:
                left = right
        if key in ("cache-answer", "rewritten-cache-answer", "dns-only-cache") and right is not None:
            for c, r in zip(left["records"], right["records"]):
                if c["type"] != 41 and abs(c["ttl"] - r["ttl"]) <= 1:
                    r["ttl"] = c["ttl"]
        if key in ("wrong-family-answer", "doctor-wrong-family4", "doctor-string-invalid-utf8"):
            # Exact image musl inet_pton(AF_INET, "2001:db8::9", p) returns
            # zero after writing 200 to p[0]. rfc1035.c passes the live RDATA
            # destination, so its rejected subscriber response still mutates A.
            c_records = left.get("records", [])
            r_records = right.get("records", [])
            rejected = "200.0.2.1" if key != "doctor-string-invalid-utf8" else "192.0.2.9"
            guarded = (len(c_records) == len(r_records) == 1
                       and c_records[0].get("type") == r_records[0].get("type") == 1
                       and c_records[0].get("data") == rejected
                       and r_records[0].get("data") == "192.0.2.1")
            f.check("C-partial-inet-pton-rejection-and-Rust-original-A-guard", guarded, True)
            if guarded:
                left["records"][0]["data"] = right["records"][0]["data"]
        if key == "doctor-multiple-data-wrongtype-last":
            c_control = copy.deepcopy(expected["doctor-no-data"])
            r_control = copy.deepcopy(actual["doctor-ipv4"])
            for response, name in ((c_control, "multiple-data-wrongtype-last.invalid"),
                                   (r_control, "multiple-data-wrongtype-last.invalid")):
                response["questions"][0][0] = name
                response["records"][0]["name"] = name
            guarded = (left == c_control and right == r_control
                       and f.authority.get("later-DATA-reuses-address-storage", False))
            f.check("guard-image-later-DATA-storage-lifetime-with-independent-controls", guarded, True)
            if guarded:
                left = right
        if inject_error and key == "initial":
            left["dns_cache_inserted"] += 1
        f.check("paired-" + key, right, left)


def client_payload(f, path, method, payload):
    command = [str(f.client), BUS, "call-raw", path, method, payload.hex()]
    result = subprocess.run(command, capture_output=True, env=f.env, timeout=3)
    f.raw.append({"side": f.side, "action": "call-raw", "path": os.fsencode(path).hex(),
                  "method": method, "payload": payload.hex(), "exit": result.returncode,
                  "stdout": result.stdout.hex(), "stderr": result.stderr.hex()})
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def wait_lookup(f, path, present=True):
    deadline = time.monotonic() + 3
    while True:
        rows = f.client_call("lookup-hex", path)
        if any(row["event"] == "lookup" for row in rows) == present:
            return rows
        assert time.monotonic() < deadline, (path, present, rows)
        time.sleep(.002)


def run_config_contract(f, side):
    """The image executable, including real registration, observes parser state."""
    observed = {}
    f.side = side
    binary = f.args.c_binary if side == "C" else f.args.rust_binary
    common = b"no-hosts\nno-resolv\nport=0\nuser=root\ngroup=root\nlog-facility=-\n"
    for index, (label, body, arguments) in enumerate(config_cases()):
        path = f.out / f"ubus-parser-{index:02}.conf"
        path.write_bytes(common + body)
        command = [os.fsencode(binary), b"--test", b"-C", os.fsencode(path), *arguments]
        result = subprocess.run(command, capture_output=True, env=f.env, timeout=3)
        observed["syntax-" + label] = {"exit": result.returncode,
                                       "stdout": result.stdout.hex(), "stderr": result.stderr.hex()}
        f.raw.append({"side": side, "config": path.read_bytes().hex(),
                      "argv": [os.fsencode(arg).hex() for arg in command],
                      **observed["syntax-" + label]})
    for index, name in enumerate([b"dnsmasq", b"custom.name", b"dnsmasq.dns",
                                  b" opaque name ", b"raw\xff\xfe", b"a,b:c/path*?[]",
                                  b"a" * 1024]):
        path = f.out / "ubus-name.conf"
        path.write_bytes(common + b'enable-ubus="' + name + b'"\n')
        command = [os.fsencode(binary), b"--keep-in-foreground", b"-C", os.fsencode(path),
                   os.fsencode("--pid-file=" + str(f.out / "name.pid"))]
        child, log = f.spawn(command, side + "-name")
        f.daemon = child
        rows = wait_lookup(f, name)
        dns_rows = wait_lookup(f, name + b".dns")
        def signature(rows):
            return [{"path_hex": row["path_hex"], "signature": fields(row["wire"]),
                     "has_type": row["type"] > 0} for row in rows if row["event"] == "lookup"]
        observed[f"name-{index}-main"] = signature(rows)
        observed[f"name-{index}-dns"] = signature(dns_rows)
        f.stop(child)
        wait_lookup(f, name, False)
        observed[f"name-{index}-pid-removed"] = not (f.out / "name.pid").exists()
    # An explicit empty option is accepted by read_opts, then dereferences NULL
    # in image ubus_init after a successful connection. Preserve that defect.
    path = f.out / "ubus-empty.conf"
    path.write_bytes(common + b"enable-ubus=\n")
    child, log = f.spawn([str(binary), "--keep-in-foreground", "-C", str(path)], side + "-empty")
    child.wait(3)
    observed["empty-activation"] = {"exit": child.returncode, "log": log.read_bytes().hex()}
    f.daemon = None
    return observed


def hold_object(f, name):
    child, log = f.spawn([str(f.client), BUS, "hold", name], "collision-holder")
    deadline = time.monotonic() + 3
    while True:
        ready = [row for row in read_json_lines(log) if row["event"] == "ready"]
        if ready:
            assert ready[0]["status"] == 0, ready
            return child
        assert child.poll() is None and time.monotonic() < deadline
        time.sleep(.002)


def run_extended(f, side):
    observed = run_config_contract(f, side)
    def record(label, value):
        assert label not in observed
        observed[label] = value
    binary = f.args.c_binary if side == "C" else f.args.rust_binary
    for suffix in ("", ".dns"):
        holder = hold_object(f, OBJECT + suffix)
        path = f.out / "ubus-collision.conf"
        path.write_text("no-hosts\nno-resolv\nport=15353\nuser=root\ngroup=root\n"
                        "log-facility=-\nenable-ubus=" + OBJECT + "\n")
        child, log = f.spawn([str(binary), "--keep-in-foreground", "-C", str(path)], side + "-collision")
        child.wait(3)
        record("startup-collision" + suffix, {"exit": child.returncode, "log": log.read_bytes().hex()})
        other = OBJECT + (".dns" if not suffix else "")
        record("startup-collision-removed-other" + suffix, f.client_call("lookup-hex", other))
        f.stop(holder)
        wait_lookup(f, OBJECT + suffix, False)
    f.start_product(side)
    for path in (OBJECT, OBJECT + ".dns", "absent.contract"):
        for method in ("metrics", "set_connmark_allowlist", "absent.method", ""):
            for index, payload in enumerate([b"", field("ignored", 3, b"value\0"),
                                             field("ignored", 5, b"\0\0\0\1"), b"\0\0\0\3"]):
                rows = client_payload(f, path, method, payload)
                record(f"method-{path}-{method}-{index}",
                       [{"event": row["event"], **({"fields": fields(row["wire"])}
                          if row["event"] == "data" else {"status": row["status"]})} for row in rows])
    f.stop(f.daemon)
    # Each case gets a fresh daemon cache and real subscriber transition. All C
    # observations finish before any Rust invocation; no probe process is used.
    for label, kind, subscribers in doctor_cases():
        f.start_product(side)
        watchers = [f.watch(response, delay) for response, delay in subscribers]
        f.client_call("call", method="metrics")
        started = time.monotonic()
        answer = f.exchange(label + ".invalid", kind)
        elapsed = time.monotonic() - started
        record("doctor-" + label, answer)
        f.check(side + "-doctor-bounded-" + label, elapsed < .7, True)
        if label in ("late", "silent", "data-without-status", "one-peer-silent"):
            f.check(side + "-doctor-timeout-" + label, .075 <= elapsed < .7, True)
        for index, (watcher, log) in enumerate(watchers):
            if label != "disconnect":
                record(f"doctor-notices-{label}-{index}", f.notices(log, 1))
            f.stop(watcher)
        record("doctor-after-" + label, f.metrics())
        f.stop(f.daemon)
    return observed


def storage_authority(f):
    """Same exact image query; only an unrelated later DATA payload changes."""
    initial = field("address", 3, b"192.0.2.9\0").hex()
    observed = []
    for label, later in [("empty", b""), ("u32", field("address", 5, b"\0\0\0\1")),
                         ("short", field("note", 3, b"ok\0")),
                         ("long", field("note", 3, b"message received " * 8 + b"\0"))]:
        f.start_product("C")
        watcher, log = f.watch("raw:" + initial + "," + later.hex())
        observed.append({"label": label, "later": later.hex(),
                         "answer": f.exchange("reference-lifetime.invalid"),
                         "notices": f.notices(log, 1)})
        f.stop(watcher)
        f.stop(f.daemon)
    queries = [row["query"] for row in f.raw if row.get("side") == "C" and row.get("query")
               and bytes.fromhex(row["query"])[12:].startswith(b"\x12reference-lifetime")]
    distinct = {(row["answer"]["flags"], row["answer"]["records"][0]["data"]) for row in observed}
    proven = len(queries) == 4 and len(set(queries)) == 1 and len(distinct) > 1
    f.check("image-C-C-later-DATA-storage-lifetime", proven, True)
    f.authority = {"later-DATA-reuses-address-storage": proven, "observed": observed}


class FrameProxy:
    """Fixture-only relay; hold one real daemon INVOKE between its bytes."""
    def __init__(self):
        self.backend = BUS + ".backend"
        os.rename(BUS, self.backend)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(BUS)
        self.listener.listen()
        self.listener.setblocking(False)
        self.stop = threading.Event()
        self.release = threading.Event()
        self.held = threading.Event()
        self.split = None
        self.rows = []
        self.errors = []
        self.peers, self.queues = {}, {}
        self.daemon_backend = None
        self.buffer = bytearray()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                readable, writable, _ = select.select([self.listener, *self.peers],
                    [sock for sock, data in self.queues.items() if data], [], .01)
                if self.held.is_set() and self.release.is_set():
                    self.queues[self.peers[self.daemon_backend]].extend(self.buffer)
                    self.buffer.clear()
                    self.split = None
                for sock in readable:
                    if sock is self.listener:
                        client, _ = sock.accept()
                        backend = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        backend.connect(self.backend)
                        for first, second in ((client, backend), (backend, client)):
                            first.setblocking(False)
                            self.peers[first] = second
                            self.queues[first] = bytearray()
                        continue
                    data = sock.recv(65536)
                    if not data:
                        peer = self.peers.pop(sock)
                        self.peers.pop(peer)
                        self.queues.pop(sock)
                        self.queues.pop(peer)
                        sock.close()
                        peer.close()
                        continue
                    target = self.peers[sock]
                    # wait_registered may open a lookup client before the
                    # product connects. Identify its actual ADD_OBJECT frame,
                    # rather than guessing from connection arrival order.
                    if self.daemon_backend is None and len(data) >= 2 and data[1] == 6:
                        self.daemon_backend = target
                    if sock is self.daemon_backend and self.split is not None:
                        self.buffer.extend(data)
                        if self.held.is_set():
                            continue
                        if len(self.buffer) < 12:
                            continue
                        total = 8 + (struct.unpack("!I", self.buffer[8:12])[0] & 0xffffff)
                        if len(self.buffer) < total:
                            continue
                        if self.buffer[1] == 5:
                            frame = bytes(self.buffer[:total])
                            self.rows.append({"frame": frame.hex(), "split": self.split,
                                              "held_at_ns": time.monotonic_ns()})
                            self.queues[target].extend(self.buffer[:self.split])
                            del self.buffer[:self.split]
                            self.held.set()
                            continue
                        self.queues[target].extend(self.buffer[:total])
                        del self.buffer[:total]
                    else:
                        self.queues[target].extend(data)
                for sock in writable:
                    if sock not in self.queues:
                        continue
                    try:
                        sent = sock.send(self.queues[sock])
                        del self.queues[sock][:sent]
                    except BlockingIOError:
                        pass
        except Exception as error:
            if not self.stop.is_set():
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(3)
        for sock in list(self.peers):
            sock.close()
        self.listener.close()
        Path(BUS).unlink(missing_ok=True)
        os.rename(self.backend, BUS)


def ubus_log_rows(path):
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        message = line.split(": ", 1)[-1]
        if any(message.startswith(prefix) for prefix in
               ("UBus ", "Cannot reconnect to UBus", "Cannot set UBus", "Cannot poll UBus",
                "Disconnecting from UBus", "connected to system UBus")):
            rows.append(message)
    return rows


def run_lifecycle(f, side):
    observed = {}
    def record(label, value):
        assert label not in observed
        observed[label] = value
    f.start_product(side, "log-debug\n")
    watcher1, _ = f.watch(dns=False)
    watcher2, _ = f.watch(dns=False)
    f.stop(watcher1)
    f.client_call("call", method="metrics")
    f.stop(watcher2)
    f.client_call("call", method="metrics")
    watcher, _ = f.watch()
    f.stop(watcher)
    f.client_call("call", method="metrics")
    record("subscription-logs", ubus_log_rows(f.daemon_log))
    before = f.metrics()
    f.stop(f.bus)
    for _ in range(20):
        f.exchange("local.invalid")
    record("lost-bus-logs", ubus_log_rows(f.daemon_log))
    f.start_bus()
    f.wait_registered()
    after = f.metrics()
    before["dns_local_answered"] += 20
    f.check(side + "-reconnect-preserves-real-local-count", after, before)
    record("reconnected-logs", ubus_log_rows(f.daemon_log))
    f.stop(f.daemon)
    for split in (1, 11, 13, 4096):
        proxy = FrameProxy()
        try:
            f.start_product(side)
            # Registration precedes the image startup/file barrier. Use a real
            # completed service request before measuring retained descriptors.
            f.exchange("local.invalid")
            seeded_local = f.metrics()["dns_local_answered"]
            before_fds = len(list(Path(f"/proc/{f.daemon.pid}/fd").iterdir()))
            proxy.split = split
            payload = field("ignored", 3, b"x" * 5000 + b"\0") if split == 4096 else b""
            child, log = f.spawn([str(f.client), BUS, "call-raw", OBJECT, "metrics", payload.hex()],
                                 side + "-partial-call")
            assert proxy.held.wait(3), (split, proxy.errors)
            # C completes a started frame synchronously. Release it from the
            # fixture even if that owner cannot answer our concurrent DNS.
            released = []
            def release_frame():
                released.append(time.monotonic_ns())
                proxy.release.set()
            timer = threading.Timer(.35, release_frame)
            timer.start()
            first = time.monotonic_ns()
            answer = f.exchange("local.invalid")
            second = time.monotonic_ns()
            later = f.exchange("local.invalid")
            if side == "C":
                f.check(side + f"-partial-{split}-blocking-frame-authority", second - first >= 250_000_000, True)
            else:
                f.check(side + f"-partial-{split}-owner-health", second - first < 75_000_000, True)
            f.check(side + f"-partial-{split}-same-daemon", f.daemon.poll(), None)
            child.wait(3)
            timer.join(1)
            result = read_json_lines(log)
            record(f"partial-{split}-local", [answer, later])
            normalized_method = [{"event": row["event"],
                **({"fields": fields(row["wire"])} if row["event"] == "data" else {"status": row["status"]})}
                for row in result]
            data = next(row for row in normalized_method if row["event"] == "data")
            count = next(field for field in data["fields"] if field["name"] == "dns_local_answered")
            # The method still reads actual live counters. Rust answers two
            # local queries while the frame is incomplete; C answers them
            # only after the method completes. Preserve the original wire.
            f.check(side + f"-partial-{split}-actual-snapshot-local-count", count["value"], seeded_local + (0 if side == "C" else 2))
            count["value"] = "validated-owner-order"
            record(f"partial-{split}-method", normalized_method)
            record(f"partial-{split}-after", f.metrics())
            record(f"partial-{split}-fd-balance",
                   len(list(Path(f"/proc/{f.daemon.pid}/fd").iterdir())) - before_fds)
            f.raw.append({"side": side, "partial_proxy": proxy.rows,
                          "local_start_ns": first, "local_done_ns": second,
                          "frame_released_ns": released, "method_wire": result})
            f.stop(f.daemon)
        finally:
            proxy.close()
            f.check(side + f"-partial-{split}-proxy-errors", proxy.errors, [])
    return observed


def run_records(f, side):
    observed = {}
    def record(label, value):
        assert label not in observed
        observed[label] = value
    def wire_record(owner, kind, cls, ttl, data):
        return owner + struct.pack("!HHIH", kind, cls, ttl, len(data)) + data
    owner = b"\xc0\x0c"
    address4 = socket.inet_pton(socket.AF_INET, "192.0.2.1")
    address6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    a = lambda ttl=120, cls=1: wire_record(owner, 1, cls, ttl, address4)
    aaaa = wire_record(owner, 28, 1, 77, address6)
    txt = wire_record(owner, 16, 1, 77, b"\x03txt")
    # All header counts and bytes come from this independent upstream. The
    # production daemon decides which records notify and when they commit.
    cases = [
        ("answer-additional-order", [a(), a(33)], [a(44)], [a(55), aaaa], "", "192.0.2.9"),
        ("authority-only", [txt], [a()], [], "", "192.0.2.9"),
        ("class-exclusion", [a(cls=3), a(cls=255), a()], [], [], "", "192.0.2.9"),
        ("zero-and-high-ttl", [a(0), a(0xffffffff)], [], [], "", "none"),
        ("filter-before-answer", [a(), aaaa, txt], [], [], "filter-rr=A,AAAA\n", "192.0.2.9"),
        ("alias-after-subscriber", [a()], [], [], "alias=192.0.2.9,198.51.100.9\n", "192.0.2.9"),
        ("address-same-clear-aa", [a()], [], [], "", "192.0.2.1"),
    ]
    original_answer = f.upstream.answer
    try:
        for label, answers, authority, additional, extra, replacement in cases:
            def answer(packet, transport, answers=answers, authority=authority, additional=additional):
                position = 12
                while packet[position]:
                    position += packet[position] + 1
                position += 5
                f.upstream.requests.append({"transport": transport, "query": packet.hex()})
                return (packet[:2] + struct.pack("!HHHHH", 0x8580, 1, len(answers), len(authority), len(additional))
                        + packet[12:position] + b"".join(answers + authority + additional))
            f.upstream.answer = answer
            f.start_product(side, extra, dhcp=False)
            watcher, log = f.watch(replacement)
            record("records-" + label, f.exchange(label + ".invalid"))
            record("notices-" + label, f.notices(log))
            record("metrics-" + label, f.metrics())
            f.stop(watcher)
            f.stop(f.daemon)
    finally:
        f.upstream.answer = original_answer
    # DNS local answers and cache replays never enter do_doctor.
    f.start_product(side, dhcp=False)
    record("dns-only-initial", f.metrics())
    record("dns-only-seed", f.exchange("cached-no-doctor.invalid"))
    watcher, log = f.watch("192.0.2.9")
    record("dns-only-local", f.exchange("local.invalid"))
    record("dns-only-cache", f.exchange("cached-no-doctor.invalid"))
    record("dns-only-no-notices", f.notices(log))
    record("dns-only-after", f.metrics())
    f.stop(watcher)
    f.stop(f.daemon)
    for enabled in (False, True):
        f.start_product(side, port=0, dhcp=False, upstream=False, bus=enabled)
        if enabled:
            record("no-service-metrics", f.metrics())
        else:
            record("disabled-no-service-lookup", f.client_call("lookup", OBJECT))
        f.stop(f.daemon)
    return observed


def run_recovery(f, side):
    observed = {}
    def record(label, value):
        assert label not in observed
        observed[label] = value
    for suffix in ("", ".dns"):
        f.stop(f.bus)
        f.start_product(side, wait_bus=False)
        record("pending" + suffix, ubus_log_rows(f.daemon_log))
        f.daemon.send_signal(signal.SIGSTOP)
        try:
            f.start_bus()
            holder = hold_object(f, OBJECT + suffix)
        finally:
            f.daemon.send_signal(signal.SIGCONT)
        f.exchange("local.invalid")
        deadline = time.monotonic() + 3
        while not any(row.startswith("UBus error:") for row in ubus_log_rows(f.daemon_log)):
            assert time.monotonic() < deadline and f.daemon.poll() is None
            f.exchange("local.invalid")
            time.sleep(.005)
        record("retry-disabled" + suffix, ubus_log_rows(f.daemon_log))
        record("retry-healthy" + suffix, f.exchange("local.invalid"))
        other = OBJECT + (".dns" if not suffix else "")
        record("retry-removed-other" + suffix, f.client_call("lookup", other))
        f.stop(holder)
        for _ in range(20):
            f.exchange("local.invalid")
        record("disabled-after-collision" + suffix, f.client_call("lookup", OBJECT))
        record("disabled-after-collision-dns" + suffix, f.client_call("lookup", OBJECT + ".dns"))
        record("disabled-after-collision-logs" + suffix, ubus_log_rows(f.daemon_log))
        f.stop(f.daemon)
    # With port0 and no DHCP service, an explicit SIGHUP provides C's retry
    # caller. Object state must come from the new transport, not a cached ID.
    f.stop(f.bus)
    f.start_product(side, port=0, dhcp=False, upstream=False, wait_bus=False)
    record("no-service-pending", ubus_log_rows(f.daemon_log))
    f.start_bus()
    f.daemon.send_signal(signal.SIGHUP)
    f.wait_registered()
    record("no-service-connected", f.metrics())
    record("no-service-connected-logs", ubus_log_rows(f.daemon_log))
    f.stop(f.daemon)
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--c-binary", type=Path, help="optional exact image runner; native build still supplies ubusd/client")
    parser.add_argument("--c-identity", type=Path, help="strict image ELF/library/runner identity for --c-binary")
    parser.add_argument("--rust-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    parser.add_argument("--suite", choices=("baseline", "extended", "lifecycle", "records", "recovery", "all"), default="baseline")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {"lo"}
    args.reference_build, args.rust_binary = args.reference_build.resolve(), args.rust_binary.resolve()
    assert digest(args.reference_build / "dnsmasq/dnsmasq") == args.c_sha256
    reference = {"kind": "native-glibc", "elf_sha256": args.c_sha256}
    if args.c_binary is not None:
        args.c_binary = args.c_binary.resolve()
        reference = verify_reference(args.c_binary, args.c_identity)
    else:
        assert args.c_identity is None, "--c-identity requires --c-binary"
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "ubus-product", "/run"], check=True)
    Path(BUS).parent.mkdir()
    f = Product(args, out)
    f.authority = {}
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    upstream_answer = f.upstream.answer
    def timed_answer(packet, transport):
        response = bytearray(upstream_answer(packet, transport))
        if packet[12:].startswith(b"\x05stale\x07invalid\0"):
            response[-10:-6] = struct.pack("!I", 2)
        return bytes(response)
    f.upstream.answer = timed_answer
    error, expected, actual = None, {}, {}
    try:
        schedules = {"baseline": run_side, "extended": run_extended, "lifecycle": run_lifecycle,
                     "records": run_records, "recovery": run_recovery}
        selected = list(schedules) if args.suite == "all" else [args.suite]
        for suite in selected:
            f.stop(f.bus)
            f.start_bus()
            if suite == "extended":
                storage_authority(f)
            left = schedules[suite](f, "C")
            if suite == "baseline":
                assert len(left) == 69, "frozen paired service schedule changed"
            (out / (suite + "-c-observations.json")).write_text(json.dumps(left, indent=2) + "\n")
            f.stop(f.bus)
            f.start_bus()
            right = schedules[suite](f, "Rust")
            first_check = len(f.checks)
            compare(f, left, right, args.inject_error)
            for row in f.checks[first_check:]:
                row["suite"] = suite
            if args.suite == "all":
                expected.update({suite + "/" + key: value for key, value in left.items()})
                actual.update({suite + "/" + key: value for key, value in right.items()})
            else:
                expected, actual = left, right
        (out / "c-observations.json").write_text(json.dumps(expected, indent=2) + "\n")
    except Exception as exception:
        error = repr(exception)
        f.check("uncaught-exception", error, None)
    finally:
        f.close()
    report = {"scope": __doc__, "error": error, "checks": f.checks, "raw": f.raw,
              "c": expected, "rust": actual,
              "passed": sum(row["pass"] for row in f.checks), "failed": sum(not row["pass"] for row in f.checks),
              "paired_observations": len(expected),
              "paired_matches": sum(row["pass"] for row in f.checks if row["case"].startswith("paired-") and row["case"] != "paired-observation-keys"),
              "reference_defects": ["C DNS object's type survives bus restart and cannot be resolved",
                                    "Exact image inet_pton rejection writes a partial A destination; Rust retains the original address"],
              "reference": reference,
              "authority": f.authority,
              "identities": {"c": reference["elf_sha256"], "native_client_build_c": args.c_sha256, "rust": digest(args.rust_binary),
                             "ubusd": digest(args.reference_build / "deps/sbin/ubusd"),
                             "client": digest(f.client), "tool": digest(__file__)}}
    (out / "result.json").write_text(json.dumps(report, indent=2, default=lambda value: value.hex()) + "\n")
    print(json.dumps({key: report[key] for key in ("passed", "failed", "error")}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
