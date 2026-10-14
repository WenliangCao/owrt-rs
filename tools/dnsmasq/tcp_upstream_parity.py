#!/usr/bin/env python3
"""Full-daemon TCP upstream selection under mixed IPv4/IPv6 availability.

Run through run_isolated.sh as root. This creates only loopback addresses and,
for DROP cases, one private nftables table inside the dedicated network namespace.
The exact C and Rust daemons run sequentially with the same resolver order and
schedule. --keep-in-foreground preserves C's normal forked TCP implementation.
No physical network is used. Raw wires, kernel connection attempts, timestamps,
configuration, executable identities and daemon logs remain under private/.

The comparisons deliberately keep route differences and elapsed times visible.
A client deadline is an observation bound, not an assertion about daemon timeout.
Use --case to extend a single unresolved timeout rather than rerun the corpus.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, query, read_name, rr, semantics

ENDPOINTS = {
    "v4a": "127.0.0.2", "v4b": "127.0.0.3",
    "v6a": "fd00:53::2", "v6b": "fd00:53::3",
}
TABLE = "dnsmasq_tcp_parity"
DAEMON_PORT = 1053
DROP_RULESET = f'''table inet {TABLE} {{
    chain input {{
        type filter hook input priority 0; policy accept;
        iifname "lo" ip daddr {{ 127.0.0.2, 127.0.0.3 }} tcp dport 53 counter drop;
    }}
}}
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def response(packet):
    _, end = read_name(packet, 12)
    kind = struct.unpack_from("!H", packet, end)[0]
    answer = rr(kind, ipaddress.ip_address("192.0.2.7" if kind == 1 else "2001:db8::7").packed, 0)
    return packet[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + packet[12:end + 4] + answer


class Events:
    def __init__(self):
        self.start = time.monotonic()
        self.lock = threading.Lock()
        self.values = []

    def add(self, kind, **fields):
        with self.lock:
            value = {"seq": len(self.values), "seconds": time.monotonic() - self.start,
                     "kind": kind, **fields}
            self.values.append(value)
            return value

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.values)


def decode_packet(packet):
    """Decode only fixture IPv4/IPv6 TCP/UDP; preserve unrelated packets by omission."""
    if len(packet) < 14:
        return None
    ethertype = struct.unpack_from("!H", packet, 12)[0]
    if ethertype == 0x0800 and len(packet) >= 34:
        offset = 14 + (packet[14] & 15) * 4
        proto = packet[23]
        source = socket.inet_ntop(socket.AF_INET, packet[26:30])
        destination = socket.inet_ntop(socket.AF_INET, packet[30:34])
    elif ethertype == 0x86DD and len(packet) >= 54:
        offset, proto = 54, packet[20]
        source = socket.inet_ntop(socket.AF_INET6, packet[22:38])
        destination = socket.inet_ntop(socket.AF_INET6, packet[38:54])
    else:
        return None
    if proto not in (6, 17) or len(packet) < offset + 8:
        return None
    source_port, destination_port = struct.unpack_from("!HH", packet, offset)
    source_label = next((key for key, value in ENDPOINTS.items() if value == source), None)
    destination_label = next((key for key, value in ENDPOINTS.items() if value == destination), None)
    if not ((destination_label and destination_port == 53) or (source_label and source_port == 53)):
        return None
    fields = {"protocol": "tcp" if proto == 6 else "udp", "source": source,
              "destination": destination, "source_port": source_port,
              "destination_port": destination_port, "upstream": destination_label or source_label,
              "direction": "to-upstream" if destination_label else "from-upstream"}
    if proto == 6 and len(packet) >= offset + 20:
        fields["flags"] = packet[offset + 13]
        fields["sequence"] = struct.unpack_from("!I", packet, offset + 4)[0]
    return fields


class Capture:
    def __init__(self, events):
        self.events, self.stop = events, threading.Event()
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.socket.bind(("lo", 0))
        self.socket.settimeout(.1)
        self.thread = threading.Thread(target=self.run, name="wire-capture", daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                packet, address = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            # Loopback produces two copies. Retain only the outgoing copy.
            if address[2] != socket.PACKET_OUTGOING:
                continue
            fields = decode_packet(packet)
            if fields:
                self.events.add("wire", **fields)

    def close(self):
        self.stop.set()
        self.thread.join(1)
        self.socket.close()
        assert not self.thread.is_alive(), "capture worker leaked"


class Upstreams:
    def __init__(self, events):
        self.events = events
        self.stop = threading.Event()
        self.udp_allowed = set(ENDPOINTS)
        self.sockets, self.threads, self.connections = [], [], []
        self.tcp_labels = set()
        self.errors = []
        self.lock = threading.Lock()
        for label in ENDPOINTS:
            sock = self.bind(label, socket.SOCK_DGRAM)
            self.launch(self.udp, sock, label)
        for label in ("v6a", "v6b"):
            self.enable_tcp(label)

    def bind(self, label, kind):
        family = socket.AF_INET6 if label.startswith("v6") else socket.AF_INET
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ENDPOINTS[label], 53))
        sock.settimeout(.1)
        self.sockets.append(sock)
        return sock

    def launch(self, function, *args):
        worker = threading.Thread(target=function, args=args, daemon=True)
        self.threads.append(worker)
        worker.start()

    def enable_tcp(self, label):
        if label in self.tcp_labels:
            return
        sock = self.bind(label, socket.SOCK_STREAM)
        sock.listen(16)
        self.tcp_labels.add(label)
        self.launch(self.accept, sock, label)
        self.events.add("tcp-enabled", upstream=label)

    def udp(self, sock, label):
        while not self.stop.is_set():
            try:
                packet, peer = sock.recvfrom(65535)
                name, _ = read_name(packet, 12)
                allowed = label in self.udp_allowed
                self.events.add("upstream-query", protocol="udp", upstream=label,
                                name=name, wire=packet.hex(), answered=allowed)
                if allowed:
                    reply = response(packet)
                    sock.sendto(reply, peer)
                    self.events.add("upstream-reply", protocol="udp", upstream=label,
                                    name=name, wire=reply.hex())
            except socket.timeout:
                continue
            except Exception as error:
                if not self.stop.is_set():
                    self.errors.append(repr(error))

    def accept(self, sock, label):
        while not self.stop.is_set():
            try:
                client, _ = sock.accept()
            except socket.timeout:
                continue
            with self.lock:
                connection = len(self.connections)
                self.connections.append(client)
            self.events.add("upstream-open", upstream=label, connection=connection)
            self.launch(self.tcp, client, label, connection)

    def tcp(self, client, label, connection):
        with client:
            client.settimeout(.1)
            while not self.stop.is_set():
                try:
                    # Prefix and body are small fixture frames. Once a prefix
                    # starts, use a bounded full-frame read instead of losing
                    # partial bytes across the idle timeout.
                    first = client.recv(1)
                    if not first:
                        break
                    client.settimeout(2)
                    prefix = first + exact_read(client, 1)
                    packet = exact_read(client, struct.unpack("!H", prefix)[0])
                    name, _ = read_name(packet, 12)
                    self.events.add("upstream-query", protocol="tcp", upstream=label,
                                    connection=connection, name=name, wire=packet.hex(), answered=True)
                    reply = response(packet)
                    client.sendall(struct.pack("!H", len(reply)) + reply)
                    self.events.add("upstream-reply", protocol="tcp", upstream=label,
                                    connection=connection, name=name, wire=reply.hex())
                    client.settimeout(.1)
                except socket.timeout:
                    continue
                except (ConnectionError, OSError) as error:
                    self.events.add("upstream-close-error", upstream=label,
                                    connection=connection, error=type(error).__name__)
                    break
                except Exception as error:
                    self.errors.append(repr(error))
                    break
        self.events.add("upstream-close", upstream=label, connection=connection)

    def close(self):
        self.stop.set()
        for worker in list(self.threads):
            worker.join(3)
        for sock in self.sockets:
            sock.close()
        assert all(not worker.is_alive() for worker in self.threads), "upstream worker leaked"
        assert not self.errors, self.errors


def drop_rule(enabled):
    if enabled:
        result = subprocess.run(["nft", "-f", "-"], input=DROP_RULESET, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(f"nft fixture rejected: {result.stderr.strip()}")
    else:
        counters = subprocess.run(["nft", "-j", "list", "table", "inet", TABLE], capture_output=True, text=True, check=True)
        subprocess.run(["nft", "delete", "table", "inet", TABLE], capture_output=True, check=True)
        return json.loads(counters.stdout)


def plans():
    # UDP warm responses are forced to one server; all UDP responders are then
    # restored. Distinct names and TTL 0 prevent a cached answer hiding routing.
    return {
        "cold-rst": {"fault": "rst", "warm": None},
        "v4-warm-rst": {"fault": "rst", "warm": "v4a"},
        "v6-warm-rst": {"fault": "rst", "warm": "v6a"},
        "v4-warm-reselect-rst": {"fault": "rst", "warm": "v4a", "reselect": "v6a"},
        "v4-warm-drop": {"fault": "drop", "warm": "v4a", "single": True},
        "v6-warm-drop": {"fault": "drop", "warm": "v6a"},
        "v4-warm-drop-session": {"fault": "drop", "warm": "v4a"},
        "v4-warm-drop-restore": {"fault": "drop", "warm": "v4a", "restore_after_first": True},
        "v4-warm-drop-recover": {"fault": "drop", "warm": "v4a", "recover": True},
    }


def exchange(events, sessions, label, transport, name, ident, timeout, kind=1, session=None, udp_retries=()):
    packet = query(name, kind=kind, ident=ident)
    row = {"label": label, "transport": transport, "name": name, "type": kind,
           "request": packet.hex(), "session": session, "timeout_seconds": timeout,
           "scheduled_udp_retries_seconds": list(udp_retries)}
    started = events.add("client-start", **row)
    client = None
    persistent = transport == "tcp" and session is not None
    try:
        if transport == "udp":
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(timeout)
            client.connect(("127.0.0.1", DAEMON_PORT))
            client.send(packet)
            origin = time.monotonic()
            retry_index = 0
            while True:
                elapsed = time.monotonic() - origin
                next_event = udp_retries[retry_index] if retry_index < len(udp_retries) else timeout
                client.settimeout(max(.001, min(timeout, next_event) - elapsed))
                try:
                    reply = client.recv(65535)
                    break
                except socket.timeout:
                    elapsed = time.monotonic() - origin
                    if elapsed >= timeout:
                        raise
                    client.send(packet)
                    events.add("client-udp-retry", label=label, wire=packet.hex(),
                               source_port=client.getsockname()[1], after_seconds=elapsed)
                    retry_index += 1
        else:
            client = sessions.get(session) if persistent else None
            row["reused_connection"] = client is not None
            if client is None:
                client = socket.create_connection(("127.0.0.1", DAEMON_PORT), timeout)
                events.add("client-open", label=label, session=session,
                           source_port=client.getsockname()[1])
                if persistent:
                    sessions[session] = client
            row["client_source_port"] = client.getsockname()[1]
            client.settimeout(timeout)
            client.sendall(struct.pack("!H", len(packet)) + packet)
            reply = exact_read(client, struct.unpack("!H", exact_read(client, 2))[0])
        row.update(status="reply", wire=reply.hex(), reply=semantics(reply))
    except (OSError, ConnectionError, ValueError) as error:
        row.update(status="error", error=type(error).__name__, detail=str(error))
        if persistent and session in sessions:
            sessions.pop(session).close()
    finally:
        if client is not None and not persistent:
            client.close()
    row["elapsed_seconds"] = time.monotonic() - events.start - started["seconds"]
    end = events.add("client-end", label=label, status=row["status"], elapsed_seconds=row["elapsed_seconds"])
    row["start_seconds"], row["end_seconds"] = started["seconds"], end["seconds"]
    time.sleep(.025)  # Let AF_PACKET consumers collect the final packet.
    trace = [entry for entry in events.snapshot() if started["seconds"] <= entry["seconds"] <= end["seconds"] + .025]
    row["upstream_queries"] = [{key: entry[key] for key in ("protocol", "upstream", "name", "wire", "answered")}
                               for entry in trace if entry["kind"] == "upstream-query" and entry["name"] == name]
    row["syn_attempts"] = [{key: entry[key] for key in ("seconds", "upstream", "source_port", "sequence")}
                           for entry in trace if entry["kind"] == "wire" and entry["protocol"] == "tcp"
                           and entry["direction"] == "to-upstream" and entry["flags"] & 0x12 == 0x02]
    # Retain retransmissions in syn_attempts; window_connect_order deduplicates only the
    # exact 4-tuple/initial-sequence connection, never a repeated fresh connect.
    seen = set()
    row["window_connect_order"] = []
    for entry in row["syn_attempts"]:
        key = (entry["upstream"], entry["source_port"], entry["sequence"])
        if key not in seen:
            row["window_connect_order"].append(entry["upstream"])
            seen.add(key)
    row["connect_order_attribution"] = "time-window; no syscall-to-DNS association"
    return row


def prepare_image_root(source, output, reference, rust):
    """Copy the exact image interpreter/dependencies; never use host libraries."""
    root = output / "image-runtime"
    for name in ("lib", "usr/sbin", "etc", "dev", "trial"):
        (root / name).mkdir(parents=True, exist_ok=True)
    libraries = ["libc.so", "libgcc_s.so.1", "libubox.so.20260213", "libubus.so.20251202"]
    libraries += [path.name for path in (source / "lib").glob("ld-musl-*.so.1")]
    identity = {}
    for name in libraries:
        origin, target = source / "lib" / name, root / "lib" / name
        if origin.is_symlink():
            target.symlink_to(os.readlink(origin))
            identity["/lib/" + name] = {"symlink": os.readlink(origin)}
        else:
            shutil.copy2(origin, target)
            identity["/lib/" + name] = {"sha256": sha(origin)}
    for name, binary in (("dnsmasq", reference), ("dnsmasq-rs", rust)):
        shutil.copy2(binary, root / "usr/sbin" / name)
    (root / "etc/passwd").write_text("root:x:0:0:root:/:/bin/false\n")
    (root / "etc/group").write_text("root:x:0:\n")
    for name, minor in (("null", 3), ("random", 8), ("urandom", 9)):
        os.mknod(root / "dev" / name, 0o020666, os.makedev(1, minor))
    dump(output / "image-libraries.json", identity)
    return root


def live_libraries(pid):
    maps = Path(f"/proc/{pid}/maps").read_text()
    values = {}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 6 and "/lib/" in fields[5]:
            path = "/lib/" + fields[5].rsplit("/lib/", 1)[1]
            values[path] = sha(Path(f"/proc/{pid}/root") / path.lstrip("/"))
    return {"maps": maps, "library_sha256": values}


def group_members(group):
    members = []
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                members.append({"pid": int(path.parent.name), "state": fields[0]})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return members


def run_case(binary, output, plan, args, side):
    output.mkdir()
    events, sessions, rows = Events(), {}, []
    workers = Upstreams(events)
    capture = Capture(events)
    dropped = False
    recovery_stop = threading.Event()
    recovery_thread = None
    process = None
    restored = threading.Event()
    result = {"status": "incomplete", "plan": plan, "rows": rows, "binary_sha256": sha(binary)}
    runtime_path = Path("/trial") / output.parent.name / side
    runtime_work = args.runtime_root / runtime_path.relative_to("/") if args.runtime_root else output
    runtime_work.mkdir(parents=True, exist_ok=True)
    resolv = output / "resolv.conf"
    resolv.write_text("".join(f"nameserver {ENDPOINTS[label]}\n" for label in args.resolver_order))
    config = output / "dnsmasq.conf"
    config.write_text(f"""no-hosts
listen-address=127.0.0.1
bind-interfaces
port={DAEMON_PORT}
cache-size={args.cache_size}
resolv-file={runtime_path / "resolv.conf" if args.runtime_root else resolv}
pid-file={runtime_path / "daemon.pid" if args.runtime_root else output / "daemon.pid"}
user=root
group=root
host-record=ready.test,192.0.2.1
log-facility=-
log-queries=extra
""")
    if args.runtime_root:
        shutil.copy2(config, runtime_work / "dnsmasq.conf")
        shutil.copy2(resolv, runtime_work / "resolv.conf")
    result["configuration"] = {"text": config.read_text(), "resolv": resolv.read_text(),
                               "config_sha256": sha(config), "resolv_sha256": sha(resolv)}
    try:
        if plan["fault"] == "drop":
            drop_rule(True)
            dropped = True
            events.add("ipv4-tcp-drop-enabled", rules=DROP_RULESET)
        with (output / "daemon.log").open("w") as log:
            if args.runtime_root:
                argv = ["chroot", str(args.runtime_root), "/usr/sbin/" + ("dnsmasq" if side == "reference" else "dnsmasq-rs"),
                        "--keep-in-foreground", "--conf-file=" + str(runtime_path / "dnsmasq.conf")]
            else:
                argv = [str(binary), "--keep-in-foreground", "--conf-file=" + str(config)]
            process = subprocess.Popen(argv, stdout=log, stderr=log, start_new_session=True)
            result["argv"] = argv
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"daemon exited before readiness: {process.returncode}")
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ready:
                        ready.settimeout(.1)
                        ready.sendto(query("ready.test", ident=0x2700), ("127.0.0.1", DAEMON_PORT))
                        packet, _ = ready.recvfrom(4096)
                        if semantics(packet)["records"][0]["data"] == "192.0.2.1":
                            break
                except (OSError, KeyError, IndexError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("daemon local UDP readiness timeout")
                    time.sleep(.02)
            live = Path(f"/proc/{process.pid}/exe")
            result["live_identity"] = {"pid": process.pid, "exe": os.readlink(live), "sha256": sha(live),
                                       "cmdline": Path(f"/proc/{process.pid}/cmdline").read_bytes().hex()}
            assert result["live_identity"]["sha256"] == result["binary_sha256"], "live executable hash mismatch"
            result["live_identity"].update(live_libraries(process.pid))
            events.add("daemon-ready", **result["live_identity"])
            if plan.get("warm"):
                workers.udp_allowed = {plan["warm"]}
                rows.append(exchange(events, sessions, "warm", "udp", "warm.parity.test", 0x2710, args.udp_timeout))
                workers.udp_allowed = set(ENDPOINTS)
                if rows[-1]["status"] != "reply":
                    raise RuntimeError("UDP warm failed; selected-parent-state precondition not established")
                replied = [entry["upstream"] for entry in rows[-1]["upstream_queries"] if entry["answered"]]
                if replied != [plan["warm"]]:
                    raise RuntimeError(f"UDP warm did not exclusively select requested upstream: {replied}")
            if plan.get("recover"):
                def recover():
                    nonlocal dropped
                    if not recovery_stop.wait(args.recover_after):
                        for label in ("v4a", "v4b"):
                            workers.enable_tcp(label)
                        counters = drop_rule(False)
                        dropped = False
                        events.add("ipv4-tcp-restored", after_seconds=args.recover_after, prior_nft_state=counters)
                        restored.set()
                recovery_thread = threading.Thread(target=recover, name="fault-recovery", daemon=True)
                recovery_thread.start()
            rows.append(exchange(events, sessions, "first", "tcp", "first.parity.test", 0x2720,
                                 args.client_timeout, session="one"))
            first_tcp_completed = rows[-1]["status"] == "reply"
            if plan.get("restore_after_first") and first_tcp_completed:
                for label in ("v4a", "v4b"):
                    workers.enable_tcp(label)
                counters = drop_rule(False)
                dropped = False
                events.add("ipv4-tcp-restored", after_first_reply=True, prior_nft_state=counters)
            if not plan.get("single") and first_tcp_completed:
                rows.append(exchange(events, sessions, "same-session", "tcp", "second.parity.test", 0x2721,
                                     args.client_timeout, kind=28, session="one"))
                rows.append(exchange(events, sessions, "fresh", "tcp", "fresh.parity.test", 0x2722,
                                     args.client_timeout))
            if plan.get("recover"):
                if not restored.wait(args.recover_after + 3):
                    raise RuntimeError("scheduled upstream recovery did not complete")
                if first_tcp_completed:
                    rows.append(exchange(events, sessions, "after-recovery-same", "tcp", "recovery.same.parity.test",
                                     0x2741, args.client_timeout, session="one"))
                    rows.append(exchange(events, sessions, "after-recovery-fresh", "tcp", "recovery.fresh.parity.test",
                                     0x2742, args.client_timeout))
            if not first_tcp_completed:
                result["followup_skipped"] = "first TCP observation ended without reply; no reuse/fresh claims after truncated observation"
            if plan.get("reselect") and first_tcp_completed:
                workers.udp_allowed = {plan["reselect"]}
                rows.append(exchange(events, sessions, "reselect", "udp", "reselect.parity.test", 0x2730,
                                     args.udp_timeout, udp_retries=(.3, .6, 1.2)))
                workers.udp_allowed = set(ENDPOINTS)
                if rows[-1]["status"] != "reply":
                    raise RuntimeError("UDP reselection failed")
                answered = {entry["upstream"] for entry in rows[-1]["upstream_queries"] if entry["answered"]}
                if answered != {plan["reselect"]}:
                    raise RuntimeError(f"UDP reselection precondition failed: {answered}")
                rows.append(exchange(events, sessions, "after-reselect-same", "tcp", "after.same.parity.test",
                                     0x2731, args.client_timeout, session="one"))
                rows.append(exchange(events, sessions, "after-reselect-fresh", "tcp", "after.fresh.parity.test",
                                     0x2732, args.client_timeout))
            result["daemon_alive_after_queries"] = process.poll() is None
            result["status"] = "observed"
    except Exception as error:
        result["harness_error"] = repr(error)
    finally:
        recovery_stop.set()
        if recovery_thread:
            recovery_thread.join(3)
            if recovery_thread.is_alive():
                result["harness_error"] = "fault recovery worker leaked"
        for client in sessions.values():
            client.close()
        if process:
            # Include forked TCP children, even if the parent exited first.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(3)
            result["parent_exit"] = process.returncode
            time.sleep(.1)
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Reap adopted children when Python is namespace PID 1. A zombie
            # awaiting another namespace init is not a running TCP worker and
            # must not be confused with a process surviving SIGKILL.
            until = time.monotonic() + .5
            while True:
                try:
                    while os.waitpid(-1, os.WNOHANG)[0]:
                        pass
                except ChildProcessError:
                    pass
                members = group_members(process.pid)
                active = [member for member in members if member["state"] != "Z"]
                if not active or time.monotonic() >= until:
                    break
                time.sleep(.01)
            result["cleanup_group_members"] = members
            result["cleanup_non_zombie_survivors"] = active
            if active:
                result["harness_error"] = "daemon process group retained live members after cleanup"
        if dropped:
            counters = drop_rule(False)
            events.add("ipv4-tcp-drop-cleanup", prior_nft_state=counters)
        capture.close()
        workers.close()
        result["events"] = events.snapshot()
        dump(output / "result.json", result)
    return result


def compare(reference, rust):
    differences = []
    if reference.get("status") != "observed" or rust.get("status") != "observed" or reference.get("harness_error") or rust.get("harness_error"):
        return [{"field": "harness", "reference": reference.get("harness_error"), "rust": rust.get("harness_error")}]
    if reference.get("daemon_alive_after_queries") is not True or rust.get("daemon_alive_after_queries") is not True:
        return [{"field": "daemon-alive", "reference": reference.get("daemon_alive_after_queries"), "rust": rust.get("daemon_alive_after_queries")}]
    if reference.get("cleanup_non_zombie_survivors") or rust.get("cleanup_non_zombie_survivors"):
        return [{"field": "cleanup-live-members", "reference": reference.get("cleanup_non_zombie_survivors"), "rust": rust.get("cleanup_non_zombie_survivors")}]
    if len(reference["rows"]) != len(rust["rows"]):
        return [{"field": "row-count", "reference": len(reference["rows"]), "rust": len(rust["rows"])}]
    for left, right in zip(reference["rows"], rust["rows"]):
        for field in ("label", "transport", "name", "type", "request", "session", "timeout_seconds",
                      "scheduled_udp_retries_seconds", "status", "wire", "error", "window_connect_order", "reused_connection"):
            if left.get(field) != right.get(field):
                differences.append({"query": left["label"], "field": field,
                                    "reference": left.get(field), "rust": right.get(field)})
        # UDP fanout timing is concurrent; keep its complete actual trace but
        # compare TCP forwarded query order, independent of randomized DNS IDs.
        routes = [[entry["upstream"] for entry in row["upstream_queries"] if entry["protocol"] == "tcp"]
                  for row in (left, right)]
        if routes[0] != routes[1]:
            differences.append({"query": left["label"], "field": "tcp_query_route",
                                "reference": routes[0], "rust": routes[1]})
        if abs(left["elapsed_seconds"] - right["elapsed_seconds"]) > max(.25, .1 * left["elapsed_seconds"]):
            differences.append({"query": left["label"], "field": "latency-over-tolerance",
                                "reference": left["elapsed_seconds"], "rust": right["elapsed_seconds"],
                                "tolerance_seconds": max(.25, .1 * left["elapsed_seconds"])})
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--rust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-root", type=Path, help="exact extracted rootfs supplying C interpreter/dependencies")
    parser.add_argument("--case", action="append", choices=list(plans()))
    parser.add_argument("--client-timeout", type=float, default=25)
    parser.add_argument("--udp-timeout", type=float, default=5)
    # Stay away from the two sequential 5-second connect timeout boundaries.
    parser.add_argument("--recover-after", type=float, default=2)
    parser.add_argument("--cache-size", type=int, default=0)
    parser.add_argument("--resolver-order", nargs=4, choices=list(ENDPOINTS), default=list(ENDPOINTS))
    args = parser.parse_args()
    if os.environ.get("DNSMASQ_TEST_ISOLATED") != "1" or sorted(name for _, name in socket.if_nameindex()) != ["lo"]:
        parser.error("run only in run_isolated.sh's dedicated loopback-only Linux network namespace")
    if set(args.resolver_order) != set(ENDPOINTS):
        parser.error("resolver order must include every endpoint once")
    if args.client_timeout <= 0 or args.udp_timeout <= 0 or args.recover_after < 0:
        parser.error("timeouts must be positive, recovery delay nonnegative")
    out = args.output.resolve()
    if "private" not in out.parts or out.exists():
        parser.error("choose a new output directory under private/")
    out.mkdir(parents=True)
    for label in ("v6a", "v6b"):
        subprocess.run(["ip", "-6", "address", "add", ENDPOINTS[label] + "/128", "dev", "lo"], check=True)
    args.runtime_root = prepare_image_root(args.image_root.resolve(), out, args.reference, args.rust) if args.image_root else None
    summary = {"status": "observed", "identity": {side: sha(getattr(args, side)) for side in ("reference", "rust")},
               "settings": {key: value for key, value in vars(args).items() if key not in ("reference", "rust", "output", "image_root", "runtime_root")},
               "driver_sha256": sha(__file__), "cases": [],
               "scope": "isolated loopback; normal forked TCP; finite client observation deadlines; no physical router"}
    try:
        for name, plan in plans().items():
            if args.case and name not in args.case:
                continue
            work = out / name
            work.mkdir()
            sides = {}
            for side in ("reference", "rust"):
                sides[side] = run_case(getattr(args, side).resolve(), work / side, plan, args, side)
            differences = compare(sides["reference"], sides["rust"])
            summary["cases"].append({"case": name, "differences": differences,
                                     "timings": {side: [{"query": row["label"], "seconds": row["elapsed_seconds"],
                                                          "status": row["status"]} for row in value["rows"]]
                                                 for side, value in sides.items()}})
            print(json.dumps(summary["cases"][-1]), flush=True)
        summary["difference_count"] = sum(len(case["differences"]) for case in summary["cases"])
        summary["status"] = "differences" if summary["difference_count"] else "equal-within-observation"
    except Exception as error:
        summary["status"], summary["harness_error"] = "harness-error", repr(error)
    finally:
        dump(out / "summary.json", summary)
    return int(summary["status"] != "equal-within-observation")


if __name__ == "__main__":
    raise SystemExit(main())
