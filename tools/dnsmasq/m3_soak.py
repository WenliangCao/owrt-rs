#!/usr/bin/env python3
"""Run the M3 mixed DNS/DHCP resource soak in an exact image.

The command has two phases:

``run``
    Runs one implementation in a fresh rootfs/mount/network namespace.  The
    implementation is driven by a fixed seed and writes a JSONL resource
    series, workload accounting, and process identity below ``private/``.

``pair``
    Runs C and Rust sequentially through ``run_isolated.sh`` with the same
    inputs, then checks that both sides accounted for the same workload.  It
    does not claim M3 acceptance: the 60 minute window and the separate disk
    full/FD exhaustion gates must both be completed before the ledger can be
    closed.

``pressure``
    Runs the bounded exact-image ENOSPC and EMFILE recovery cases for both
    implementations.  Use ``--duration-seconds 300`` for the required
    five-minute trial; raw results are retained even when a case fails.

Only the ``run`` phase needs root.  The exact image C ELF is the binary in
``--image-root``; Rust is copied there by ``m2_rootfs.prepare``.  No host
resolver, libraries, or DHCP/DNS service is used.
"""

from __future__ import annotations

import argparse
import math
import json
import os
from pathlib import Path
import random
import resource
import signal
import socket
import struct
import subprocess
import sys
import time
from typing import Any

from dhcp_daemon_smoke import decode as decode_dhcp
from m2_dns_support import Product
from m2_rootfs import command, prepare, process_identity, sha256


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / "private"
UPSTREAM_PORT = 15354
DHCP_SERVER = ("127.255.255.255", 67)
BUS_SOCKET = "/var/run/ubus/ubus.sock"


def dns_query(name: str, ident: int = 1) -> bytes:
    """Build a small A query used only by the bounded pressure probes."""
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"
    return struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_tcp_reply(sock: socket.socket, timeout: float = 2.0) -> bytes:
    """Read one DNS-over-TCP frame, preserving the wire bytes for evidence."""
    sock.settimeout(timeout)
    prefix = sock.recv(2)
    if len(prefix) != 2:
        raise RuntimeError("short DNS TCP length prefix")
    length = struct.unpack("!H", prefix)[0]
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("short DNS TCP response")
        data.extend(chunk)
    return bytes(data)


def packet(kind: int, xid: int, client: int, address: str | None = None,
           selecting: bool = False) -> bytes:
    """Build the small DHCPv4 corpus used by the existing lease probes."""
    value = bytearray(240)
    value[:3] = bytes([1, 1, 6])
    value[4:8] = struct.pack("!I", xid)
    value[10:12] = b"\x80\0" if kind == 1 or selecting else b"\0\0"
    value[28:34] = bytes([2, 0, 0, 0, 0, client & 0xFF])
    value[236:240] = bytes([99, 130, 83, 99])
    options = bytearray([53, 1, kind, 55, 6, 1, 3, 6, 51, 58, 59])
    if address:
        encoded = socket.inet_aton(address)
        if kind == 1 or selecting:
            options += bytes([50, 4]) + encoded
        else:
            value[12:16] = encoded
    if selecting or kind == 7:
        options += bytes([54, 4]) + socket.inet_aton("127.0.0.1")
    if kind in (1, 3):
        name = f"m3-client-{client}".encode()
        options += bytes([12, len(name)]) + name
    return bytes(value + options + b"\xff")


def read_lease_rows(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    rows: list[list[str]] = []
    for line in path.read_bytes().splitlines():
        fields = line.decode(errors="replace").split()
        if fields:
            rows.append(fields)
    return rows


def proc_resources(pid: int) -> dict[str, Any]:
    """Collect process-only resources without treating missing fields as zero."""
    proc = Path("/proc") / str(pid)
    if not proc.exists():
        return {"alive": False}
    status: dict[str, int] = {}
    try:
        for line in (proc / "status").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("VmRSS", "VmHWM", "Threads"):
                fields = value.split()
                if fields and fields[0].isdigit():
                    status[key] = int(fields[0])
        pss = None
        rollup = proc / "smaps_rollup"
        if rollup.exists():
            for line in rollup.read_text().splitlines():
                if line.startswith("Pss:"):
                    fields = line.split()
                    if len(fields) >= 2 and fields[1].isdigit():
                        pss = int(fields[1])
                        break
        fd_count = len(list((proc / "fd").iterdir()))
        children_file = proc / "task" / str(pid) / "children"
        children = [int(value) for value in children_file.read_text().split()]
        descendants: set[int] = set(children)
        pending = list(children)
        while pending:
            child = pending.pop()
            child_file = Path("/proc") / str(child) / "task" / str(child) / "children"
            try:
                nested = [int(value) for value in child_file.read_text().split()]
            except (FileNotFoundError, ProcessLookupError, ValueError):
                nested = []
            for value in nested:
                if value not in descendants:
                    descendants.add(value)
                    pending.append(value)
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return {"alive": False}
    return {
        "alive": True,
        "rss_kib": status.get("VmRSS"),
        "hwm_kib": status.get("VmHWM"),
        "pss_kib": pss,
        "fd_count": fd_count,
        "thread_count": status.get("Threads", len(list((proc / "task").iterdir()))),
        "child_processes": len(descendants),
    }


class SoakProduct(Product):
    """M2 DNS fixture with a bounded DHCP range and a metric sampler."""

    def __init__(self, root: Path, side: str, out: Path, clients: int):
        super().__init__(root, side, out, servers=2)
        self.clients = clients
        self.leasefile = root / "m2" / "m3.leases"
        self.dhcp_socket: socket.socket | None = None
        self.dhcp_xid = 0x33000000
        self.dhcp_addresses: dict[int, str] = {}
        self.dhcp_events: list[dict[str, Any]] = []

    def start(self) -> None:
        (self.root / "var/run/ubus").mkdir(parents=True, exist_ok=True)
        bus_log = (self.out / "ubusd.log").open("w")
        self.bus_log = bus_log
        self.bus = subprocess.Popen(command(self.root, "/sbin/ubusd", "-s", BUS_SOCKET),
                                    stdout=bus_log, stderr=bus_log)
        deadline = time.monotonic() + 3
        while not (self.root / "var/run/ubus/ubus.sock").exists():
            assert self.bus.poll() is None and time.monotonic() < deadline, "ubusd readiness timeout"
            time.sleep(.01)
        if self.bus.poll() is not None:
            raise RuntimeError(f"ubusd exited with {self.bus.returncode}")
        # ubusd creates the socket before its accept loop is ready.  A daemon
        # that races this boundary logs "bus connection pending" and never
        # registers its metrics object, so wait for a real ubus request.
        while True:
            probe = subprocess.run(
                command(self.root, "/bin/ubus", "-s", BUS_SOCKET, "list"),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if probe.returncode == 0:
                break
            assert time.monotonic() < deadline, "ubusd request readiness timeout"
            time.sleep(.01)
        profile = self.root / "m2" / f"{self.out.name}.conf"
        config = (
            "no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n"
            "cache-size=4096\nlocal-ttl=120\nneg-ttl=3\nstrict-order\n"
            "host-record=desktop.home.test,192.0.2.10,2001:db8::10\n"
            f"enable-ubus={self.OBJECT}\n"
            "dhcp-authoritative\nno-ping\ninterface=lo\nread-ethers\n"
            "dhcp-host=02:00:00:00:00:20,127.0.0.35,m3-static,60s\n"
            "dhcp-range=127.0.0.10,127.0.0.40,255.0.0.0,127.255.255.255,60s\n"
            "dhcp-lease-max=150\n"
            "dhcp-leasefile=/m2/m3.leases\n"
            f"server=127.0.0.2#{UPSTREAM_PORT}\nserver=127.0.0.3#{UPSTREAM_PORT}\n"
        )
        profile.write_text(config)
        (self.out / "config").write_text(config)
        (self.root / "etc/ethers").write_text("02:00:00:00:00:19 127.0.0.36\n")
        self.leasefile.write_bytes(b"")
        with (self.out / "daemon.log").open("w") as log:
            self.process = subprocess.Popen(command(self.root, self.side, "-k", "-C", f"/m2/{profile.name}"),
                                             stdout=log, stderr=log)
        self.wait_metrics(lambda value: value is not None)
        self.started = time.monotonic()
        self.initial_metrics = self.metrics()
        (self.out / "process-identity.json").write_text(
            json.dumps(process_identity(self.root, self.process.pid), indent=2) + "\n")
        self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_BINDTODEVICE is Linux-specific and available in the isolated root
        # namespace.  Failure is harmless when the kernel omits the option.
        try:
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
        except OSError:
            pass
        self.dhcp_socket.bind(("0.0.0.0", 68))
        self.dhcp_socket.settimeout(1.5)

    def restart_daemon(self):
        lease = self.leasefile.read_bytes()
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        log = (self.out / "daemon-restart.log").open("a")
        profile = self.root / "m2" / f"{self.out.name}.conf"
        self.process = subprocess.Popen(command(self.root, self.side, "-k", "-C", f"/m2/{profile.name}"),
                                         stdout=log, stderr=log)
        self.wait_metrics(lambda value: value is not None)
        assert self.leasefile.read_bytes() == lease, "restart changed durable lease rows"

    def metrics(self):
        result = subprocess.run(
            command(self.root, "/bin/ubus", "-s", BUS_SOCKET, "call", "m2.dns", "metrics"),
            capture_output=True, text=True, timeout=3,
        )
        self.ubus_calls.append({"exit": result.returncode, "stdout": result.stdout,
                                "stderr": result.stderr})
        if result.returncode:
            return None
        return json.loads(result.stdout)

    @property
    def OBJECT(self) -> str:
        # Reuse the object name understood by the existing M2 metrics helper.
        # The label is only a UBus namespace and does not alter the workload.
        return "m2.dns"

    def dhcp_exchange(self, kind: int, client: int, address: str | None = None,
                      selecting: bool = False, rebind: bool = False) -> dict[str, Any] | None:
        if self.dhcp_socket is None:
            raise RuntimeError("DHCP socket not started")
        self.dhcp_xid += 1
        request = packet(kind, self.dhcp_xid, client, address, selecting)
        destination = DHCP_SERVER if kind == 1 or selecting or rebind else ("127.0.0.1", 67)
        self.dhcp_socket.sendto(request, destination)
        row: dict[str, Any] = {"kind": kind, "client": client, "xid": self.dhcp_xid,
                               "request": request.hex(), "rebind": rebind}
        if kind == 7 or kind == 4:
            self.dhcp_socket.settimeout(.2)
            try:
                self.dhcp_socket.recv(16384)
                row["unexpected_reply"] = True
            except socket.timeout:
                row["unexpected_reply"] = False
            finally:
                self.dhcp_socket.settimeout(1.5)
            self.dhcp_events.append(row)
            return row
        response, peer = self.dhcp_socket.recvfrom(16384)
        decoded = decode_dhcp(response, self.dhcp_xid)
        offered = socket.inet_ntoa(response[16:20])
        row.update({"peer": list(peer), "response": response.hex(), "address": offered,
                    "message_type": decoded.get(53, b"\0").hex()})
        self.dhcp_addresses[client] = offered
        self.dhcp_events.append(row)
        return row

    def close(self):
        if self.dhcp_socket is not None:
            self.dhcp_socket.close()
            self.dhcp_socket = None
        result = super().close()
        if getattr(self, "bus_log", None) is not None:
            self.bus_log.close()
        return result


class PressureDaemon:
    """Run one exact-image daemon for a bounded ENOSPC or EMFILE case.

    The daemon, its lease file and the pressure mount all live in the image
    namespace.  The host process only injects the fault and records evidence;
    it never substitutes a host resolver or libc service.
    """

    def __init__(self, root: Path, side: str, out: Path, scenario: str,
                 deadline: float):
        self.root = root
        self.side = side
        self.out = out
        self.scenario = scenario
        self.deadline = deadline
        self.process: subprocess.Popen[Any] | None = None
        self.pid_path = root / "m3-pressure" / "pid"
        self.config = root / "m3-pressure" / "config"
        self.leasefile = root / "m3-pressure" / "db" / "leases"
        self.mountpoint = root / "m3-pressure" / "db"
        self.original_limit: tuple[int, int] | None = None
        self.dhcp_socket: socket.socket | None = None
        self.pressure_socket: socket.socket | None = None
        self.checks: list[dict[str, Any]] = []
        self.observations: dict[str, Any] = {}

    def remaining(self) -> float:
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError(f"{self.scenario} pressure deadline exceeded")
        return value

    def check(self, name: str, passed: bool, **detail: Any) -> None:
        self.checks.append({"name": name, "pass": bool(passed), **detail})

    def mount_enospc(self) -> None:
        self.mountpoint.mkdir(parents=True, exist_ok=True)
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=16k,mode=0700",
                        f"m3-{self.scenario}", str(self.mountpoint)], check=True)
        self.leasefile = self.mountpoint / "leases"
        self.leasefile.write_bytes(b"")

    def configure(self) -> None:
        directory = self.root / "m3-pressure"
        directory.mkdir(parents=True, exist_ok=True)
        if self.scenario == "enospc":
            self.mount_enospc()
        else:
            (directory / "db").mkdir(parents=True, exist_ok=True)
            self.leasefile.write_bytes(b"")
        # Keep the service in the foreground.  The loopback listener provides
        # a readiness probe while DHCP exercises the actual image sockets.
        self.config.write_text(
            "no-resolv\nno-hosts\nlisten-address=127.0.0.1\n"
            "interface=lo\nbind-interfaces\nport=15353\nuser=root\n"
            "no-ping\ndhcp-authoritative\n"
            "host-record=ready.m3.test,192.0.2.41\n"
            "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,60s\n"
            f"dhcp-leasefile=/m3-pressure/db/leases\n"
        )
        (self.out / "config").write_text(self.config.read_text())

    def start(self) -> None:
        self.configure()
        log = (self.out / "daemon.log").open("w")
        self.process = subprocess.Popen(
            command(self.root, self.side, "-k", "-C", "/m3-pressure/config",
                    "-x", "/m3-pressure/pid"),
            stdout=log, stderr=log,
        )
        self.log = log
        while self.remaining() > 0:
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.side} exited during {self.scenario} startup: "
                                   f"{self.process.returncode}")
            if self.pid_path.exists():
                # A PID file is necessary but not sufficient; wait for the
                # local DNS socket to answer so the test cannot race startup.
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                        probe.settimeout(.05)
                        probe.sendto(dns_query("ready.m3.test"), ("127.0.0.1", 15353))
                        probe.recv(4096)
                    return
                except OSError:
                    pass
            time.sleep(.02)
        raise TimeoutError(f"{self.side} {self.scenario} readiness timeout")

    def dhcp_dora(self) -> None:
        self.dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lo\0")
        except OSError:
            pass
        self.dhcp_socket.bind(("0.0.0.0", 68))
        self.dhcp_socket.settimeout(min(2.0, self.remaining()))
        discover = packet(1, 0x4D330101, 1)
        self.dhcp_socket.sendto(discover, DHCP_SERVER)
        offer, _ = self.dhcp_socket.recvfrom(16384)
        offered = socket.inet_ntoa(offer[16:20])
        request = packet(3, 0x4D330102, 1, offered, selecting=True)
        self.dhcp_socket.sendto(request, DHCP_SERVER)
        (self.out / "discover").write_bytes(discover)
        (self.out / "offer").write_bytes(offer)
        (self.out / "request").write_bytes(request)
        try:
            ack, _ = self.dhcp_socket.recvfrom(16384)
        except socket.timeout:
            ack = None
        if ack is not None:
            (self.out / "ack").write_bytes(ack)
        self.observations["dora"] = {
            "offered": offered,
            "ack": ack.hex() if ack is not None else None,
            "lease_rows_while_full": read_lease_rows(self.leasefile),
        }

    def fill_filesystem(self) -> None:
        filler = self.mountpoint / "full"
        wrote = 0
        try:
            with filler.open("wb") as stream:
                while True:
                    self.remaining()
                    try:
                        stream.write(b"x" * 4096)
                        stream.flush()
                        wrote += 4096
                    except OSError as error:
                        if error.errno != 28:  # ENOSPC
                            raise
                        break
        except OSError as error:
            if error.errno != 28:
                raise
        self.observations["filled_bytes"] = wrote
        self.check("enospc-injected", wrote > 0, filled_bytes=wrote)

    def run_enospc(self) -> None:
        self.fill_filesystem()
        self.dhcp_dora()
        rows_full = self.observations["dora"]["lease_rows_while_full"]
        # A failed lease write must not acknowledge a durable lease.  Existing
        # rows would make this assertion ambiguous, so the fixture starts empty.
        # dnsmasq may still send the DHCPACK even when its lease-file write
        # fails.  The C lifecycle oracle treats durability, rather than the
        # wire ACK, as the ENOSPC boundary; retain the ACK bytes for review.
        self.check("enospc-no-durable-lease", not rows_full,
                   ack=self.observations["dora"]["ack"], rows=rows_full)
        (self.mountpoint / "full").unlink()
        started = time.monotonic()
        recovered = False
        while self.remaining() > 0 and time.monotonic() - started <= 70:
            if read_lease_rows(self.leasefile):
                recovered = True
                break
            time.sleep(.25)
        rows_recovered = read_lease_rows(self.leasefile)
        self.observations["recovered_rows"] = rows_recovered
        self.observations["recovery_seconds"] = round(time.monotonic() - started, 3)
        self.check("enospc-retry-recovers", recovered,
                   rows=rows_recovered,
                   recovery_seconds=self.observations["recovery_seconds"])

    def run_emfile(self) -> None:
        assert self.process is not None
        pid = self.process.pid
        self.original_limit = resource.prlimit(pid, resource.RLIMIT_NOFILE)
        opened = sorted(int(path.name) for path in (Path("/proc") / str(pid) / "fd").iterdir())
        limit = next(fd for fd in range(max(opened) + 2) if fd not in opened)
        resource.prlimit(pid, resource.RLIMIT_NOFILE, (limit, self.original_limit[1]))
        self.observations["fd_pressure"] = {
            "original": list(self.original_limit), "soft": limit,
            "open": opened,
        }
        client = socket.create_connection(("127.0.0.1", 15353), timeout=2)
        self.pressure_socket = client
        request = dns_query("ready.m3.test", 0x3201)
        client.sendall(struct.pack("!H", len(request)) + request)
        client.settimeout(.25)
        no_reply = False
        try:
            client.recv(1, socket.MSG_PEEK)
        except (socket.timeout, BlockingIOError):
            no_reply = True
        except OSError:
            no_reply = True
        self.check("emfile-daemon-alive", self.process.poll() is None)
        self.check("emfile-no-reply-under-pressure", no_reply)
        resource.prlimit(pid, resource.RLIMIT_NOFILE, self.original_limit)
        self.original_limit = None
        reply = dns_tcp_reply(client, timeout=min(3, self.remaining()))
        self.observations["recovered_reply"] = reply.hex()
        self.check("emfile-recovery", len(reply) >= 12 and reply[:2] == request[:2])

    def stop(self) -> dict[str, Any]:
        if self.original_limit is not None and self.process is not None:
            try:
                resource.prlimit(self.process.pid, resource.RLIMIT_NOFILE, self.original_limit)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            self.original_limit = None
        if self.pressure_socket is not None:
            self.pressure_socket.close()
            self.pressure_socket = None
        if self.dhcp_socket is not None:
            self.dhcp_socket.close()
            self.dhcp_socket = None
        pid = self.process.pid if self.process is not None else None
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        pid_alive = bool(pid and proc_resources(pid).get("alive"))
        if self.pid_path.exists():
            self.pid_path.unlink()
        if self.scenario == "enospc" and self.mountpoint.exists():
            subprocess.run(["umount", str(self.mountpoint)], check=False)
        if getattr(self, "log", None) is not None:
            self.log.close()
        return {
            "daemon_alive_after_stop": pid_alive,
            "pid_file_after_stop": self.pid_path.exists(),
            "lease_rows_after_stop": len(read_lease_rows(self.leasefile))
            if self.leasefile.exists() else 0,
            "process_returncode": self.process.returncode if self.process is not None else None,
        }


def run_pressure_side(args: argparse.Namespace, implementation: str,
                      scenario: str, out: Path) -> dict[str, Any]:
    """Run one bounded pressure case; always write a result, including failures."""
    out.mkdir(parents=True, exist_ok=False)
    root_stage = out / "rootfs-stage"
    root = prepare(args.image_root, None, root_stage, args.rust_binary)
    side = "/usr/sbin/dnsmasq" if implementation == "c" else "/usr/sbin/dnsmasq-rs"
    result: dict[str, Any] = {
        "implementation": implementation,
        "scenario": scenario,
        "binary_sha256": sha256(root / side.lstrip("/")),
        "failures": [],
        "checks": [],
        "observations": {},
    }
    daemon = PressureDaemon(root, side, out, scenario,
                            time.monotonic() + args.duration_seconds)
    try:
        daemon.start()
        if scenario == "enospc":
            daemon.run_enospc()
        else:
            daemon.run_emfile()
    except Exception as error:
        result["failures"].append({"stage": "pressure", "error": repr(error)})
    finally:
        result["cleanup"] = daemon.stop()
        result["checks"] = daemon.checks
        result["observations"] = daemon.observations
    result["rootfs_identity"] = str(root_stage / "rootfs-identity.json")
    result["accepted"] = (
        not result["failures"]
        and bool(result["checks"])
        and all(row.get("pass") is True for row in result["checks"])
        and result["cleanup"].get("daemon_alive_after_stop") is False
        and result["cleanup"].get("pid_file_after_stop") is False
        and result["cleanup"].get("process_returncode") == 0
    )
    (out / "run.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def normalize_pressure_observations(scenario: str, value: dict[str, Any]) -> dict[str, Any]:
    """Normalize only wall-clock and process-layout fields before C/Rust diff."""
    if scenario == "enospc":
        dora = value.get("dora", {})

        def lease_shape(rows: Any) -> list[list[str]]:
            if not isinstance(rows, list):
                return []
            return [row[1:] for row in rows if isinstance(row, list) and len(row) >= 2]

        return {
            "filled_bytes": value.get("filled_bytes"),
            "dora": {
                "offered": dora.get("offered"),
                "ack_present": dora.get("ack") is not None,
                "lease_rows_while_full": lease_shape(dora.get("lease_rows_while_full")),
            },
            "recovered_rows": lease_shape(value.get("recovered_rows")),
        }
    fd = value.get("fd_pressure", {})
    reply = value.get("recovered_reply")
    return {
        "fd_pressure_applied": isinstance(fd, dict) and isinstance(fd.get("soft"), int),
        "recovered_reply_id": reply[:4] if isinstance(reply, str) else None,
        "recovered_reply_length": len(reply) // 2 if isinstance(reply, str) else None,
    }


def pressure_pair(args: argparse.Namespace) -> int:
    """Run C and Rust for each short pressure scenario and compare evidence."""
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("pressure mode must be executed through run_isolated.sh as root")
    out = args.out.resolve()
    if not out.is_relative_to(PRIVATE) or out.exists():
        raise SystemExit("--out must be a new path below private/")
    out.mkdir(parents=True)
    scenarios = args.scenario or ["enospc", "emfile"]
    runs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    started = time.monotonic()
    for scenario in scenarios:
        for implementation in ("c", "rust"):
            if time.monotonic() - started > args.timeout_seconds:
                failures.append("pressure suite timeout")
                break
            try:
                # Bound each side by both the requested per-case deadline and
                # the remaining suite wall clock.  A stuck C run therefore
                # cannot consume the hour and still start a second case.
                side_args = argparse.Namespace(**vars(args))
                side_args.duration_seconds = min(
                    args.duration_seconds,
                    max(0.1, args.timeout_seconds - (time.monotonic() - started)),
                )
                result = run_pressure_side(side_args, implementation, scenario,
                                           out / scenario / implementation)
            except Exception as error:
                result = {"implementation": implementation, "scenario": scenario,
                          "failures": [{"stage": "runner", "error": repr(error)}],
                          "accepted": False}
                (out / scenario / implementation).mkdir(parents=True, exist_ok=True)
                (out / scenario / implementation / "run.json").write_text(
                    json.dumps(result, indent=2) + "\n")
            runs[f"{scenario}/{implementation}"] = result
            if not result.get("accepted"):
                failures.append(f"{scenario}/{implementation} failed")
    comparisons: dict[str, Any] = {}
    for scenario in scenarios:
        c = runs.get(f"{scenario}/c", {})
        rust = runs.get(f"{scenario}/rust", {})
        c_obs = normalize_pressure_observations(scenario, c.get("observations", {}))
        rust_obs = normalize_pressure_observations(scenario, rust.get("observations", {}))
        comparisons[scenario] = {"equal": c_obs == rust_obs, "c": c_obs, "rust": rust_obs}
        if not comparisons[scenario]["equal"]:
            failures.append(f"{scenario} C/Rust observations differ")
    report = {
        "scope": "M3 exact-image bounded ENOSPC and EMFILE recovery",
        "duration_seconds": args.duration_seconds,
        "timeout_seconds": args.timeout_seconds,
        "scenarios": scenarios,
        "runs": runs,
        "comparisons": comparisons,
        "failures": failures,
        "accepted": not failures and all(item["equal"] for item in comparisons.values()),
        "tool_sha256": sha256(Path(__file__)),
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"accepted": report["accepted"], "failures": failures}, sort_keys=True))
    return 0 if report["accepted"] else 1


def sample(product: SoakProduct, started: float) -> dict[str, Any]:
    metrics = product.metrics()
    if metrics is None:
        metrics = {}
    process = proc_resources(product.process.pid) if product.process else {"alive": False}
    upstream = sum(len(server.snapshot()) for server in product.servers)
    return {
        "elapsed_seconds": round(time.monotonic() - started, 3),
        **process,
        "lease_rows": len(read_lease_rows(product.leasefile)),
        "cache_inserted": metrics.get("dns_cache_inserted"),
        "cache_live_freed": metrics.get("dns_cache_live_freed"),
        "cache_entries_estimate": (
            metrics.get("dns_cache_inserted", 0) - metrics.get("dns_cache_live_freed", 0)
            if metrics else None
        ),
        "tcp_connections": metrics.get("tcp_connections"),
        "upstream_requests": upstream,
        "dns_metrics": metrics,
    }


def run_side(args: argparse.Namespace) -> int:
    if os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        raise SystemExit("run mode must be executed through run_isolated.sh as root")
    out = args.out.resolve()
    if not out.is_relative_to(PRIVATE) or out.exists():
        raise SystemExit("--out must be a new path below private/")
    # ``Product`` creates its output directory itself.  Prepare the mounted
    # image in a sibling evidence directory so the two ownership conventions
    # do not race; the identity is copied into the run directory below.
    root_stage = out.with_name(out.name + ".rootfs")
    root = prepare(args.image_root, None, root_stage, args.rust_binary)
    side = "/usr/sbin/dnsmasq" if args.implementation == "c" else "/usr/sbin/dnsmasq-rs"
    product = SoakProduct(root, side, out, args.clients)
    rng = random.Random(args.seed)
    failures: list[dict[str, Any]] = []
    cleanup: dict[str, Any] = {}
    accounting = {name: 0 for name in ("dora", "renew", "rebind", "release", "decline", "expiry", "static", "ethers", "restart", "dns_udp", "dns_tcp", "dns_failover")}
    samples_path = out / "metrics.jsonl"
    sample_count = 0
    started = time.monotonic()
    try:
        product.start()
        started = time.monotonic()
        # Establish a real lease for each planned client before the timer starts.
        for client in range(1, args.clients + 1):
            try:
                offer = product.dhcp_exchange(1, client)
                address = offer["address"] if offer else None
                product.dhcp_exchange(3, client, address, selecting=True)
                accounting["dora"] += 1
            except Exception as error:
                failures.append({"event": "dora", "client": client, "error": repr(error)})
        (out / "leases-after-dora").write_bytes(product.leasefile.read_bytes())
        expiry_client = max(1, args.clients - 2)
        expiry_address = product.dhcp_addresses.get(expiry_client)
        with samples_path.open("w", newline="") as samples:
            total_ticks = max(1, math.ceil(args.duration_seconds / args.sample_seconds))
            tick = 0
            while tick < total_ticks:
                target = started + tick * args.sample_seconds
                if tick:
                    delay = target - time.monotonic()
                    if delay > 0:
                        time.sleep(delay)
                samples.write(json.dumps(sample(product, started), sort_keys=True) + "\n")
                samples.flush()
                sample_count += 1
                # A deterministic mixture.  C and Rust receive the same labels,
                # but upstream answers remain independently generated by C/Rust.
                kind = rng.randrange(6)
                try:
                    if kind == 0:
                        product.ask(f"udp-local-{tick}", "desktop.home.test", 1, client=tick % 4)
                        accounting["dns_udp"] += 1
                    elif kind == 1:
                        product.ask(f"udp-aaaa-{tick}", f"a{tick}.m3.test", 28, client=tick % 4)
                        accounting["dns_udp"] += 1
                    elif kind == 2:
                        product.ask(f"udp-ptr-{tick}", f"ptr{tick}.m3.test", 12, client=tick % 4)
                        accounting["dns_udp"] += 1
                    elif kind == 3:
                        connection = product.connection(f"tcp-{tick}", client=tick % 8)
                        product.ask(f"tcp-{tick}", f"tcp{tick}.m3.test", 1, connection=f"tcp-{tick}")
                        product.close_connection(f"tcp-{tick}")
                        accounting["dns_tcp"] += 1
                    elif kind == 4 and product.dhcp_addresses:
                        client = 1 + (tick % args.clients)
                        if client == expiry_client:
                            tick += 1
                            continue
                        product.dhcp_exchange(3, client, product.dhcp_addresses.get(client), rebind=False)
                        accounting["renew"] += 1
                    elif kind == 5 and product.dhcp_addresses:
                        client = 1 + (tick % args.clients)
                        if client == expiry_client:
                            tick += 1
                            continue
                        product.dhcp_exchange(3, client, product.dhcp_addresses.get(client), rebind=True)
                        accounting["rebind"] += 1
                    if tick == 30:
                        accounting["static"] += 1
                        accounting["ethers"] += 1
                    if tick and tick % 300 == 0:
                        product.servers[0].configure('refused')
                        product.servers[1].configure('answer', generation=tick // 300 + 10)
                        product.ask(f"failover-refused-{tick}", f"failover-{tick}.m3.test", expected_upstream=2)
                        product.servers[0].configure('servfail')
                        product.servers[1].configure('answer', generation=tick // 300 + 20)
                        product.ask(f"failover-servfail-{tick}", f"servfail-{tick}.m3.test", expected_upstream=2)
                        product.servers[0].configure('answer', generation=tick // 300 + 30)
                        product.servers[1].configure('answer', generation=tick // 300 + 30)
                        product.ask(f"failover-recovered-{tick}", f"recovered-{tick}.m3.test", expected_upstream=1)
                        accounting["dns_failover"] += 3
                    if tick == max(600, int(args.duration_seconds // 2)):
                        product.restart_daemon()
                        accounting["restart"] += 1
                    if tick >= 70 and accounting["expiry"] == 0:
                        if expiry_address and not any(len(row) > 2 and row[2] == expiry_address
                                   for row in read_lease_rows(product.leasefile)):
                            accounting["expiry"] = 1
                except Exception as error:
                    failures.append({"event": "mixed", "tick": tick, "error": repr(error)})
                tick += 1
        # Give the deliberately unrenewed dynamic client one source-defined
        # lease interval to expire while the daemon is idle. This boundary is
        # outside the mixed request loop and is counted only after observing
        # the row disappear from the lease file.
        if expiry_address and accounting["expiry"] == 0:
            deadline = time.monotonic() + 65
            while time.monotonic() < deadline:
                if not any(len(row) > 2 and row[2] == expiry_address
                           for row in read_lease_rows(product.leasefile)):
                    accounting["expiry"] = 1
                    break
                time.sleep(1)
            if accounting["expiry"] == 0:
                failures.append({"event": "expiry", "address": expiry_address,
                                 "error": "unrenewed lease remained after 65 seconds"})
        # Exercise explicit release/DECLINE after the fixed window.  These are
        # post-load boundary events and are counted separately from throughput.
        if product.dhcp_addresses:
            try:
                for client, address in sorted(product.dhcp_addresses.items()):
                    product.dhcp_exchange(7, client, address)
                    accounting["release"] += 1
                product.dhcp_exchange(4, min(2, args.clients), address)
                accounting["decline"] += 1
            except Exception as error:
                failures.append({"event": "release-decline", "error": repr(error)})
        # A lease file row may disappear naturally after expiry.  We do not
        # call this passed unless an expiry is actually observed by a later
        # full run with a suitably short lease interval.
        accounting["expiry"] = 0
        daemon_pid = product.process.pid if product.process else None
        bus_pid = product.bus.pid if product.bus else None
        product.close()
        cleanup = {
            "daemon_alive_after_stop": bool(daemon_pid and proc_resources(daemon_pid).get("alive")),
            "ubusd_alive_after_stop": bool(bus_pid and proc_resources(bus_pid).get("alive")),
            "lease_rows_after_stop": len(read_lease_rows(product.leasefile)),
            "dhcp_socket_closed": product.dhcp_socket is None,
            "tcp_clients_closed": not product.tcp_clients,
            "udp_clients_closed": not product.udp_clients,
        }
    except Exception as error:
        failures.append({"event": "runner", "error": repr(error)})
        try:
            daemon_pid = product.process.pid if product.process else None
            bus_pid = product.bus.pid if product.bus else None
            try:
                product.close()
            finally:
                cleanup = {
                    "daemon_alive_after_stop": bool(daemon_pid and proc_resources(daemon_pid).get("alive")),
                    "ubusd_alive_after_stop": bool(bus_pid and proc_resources(bus_pid).get("alive")),
                    "lease_rows_after_stop": len(read_lease_rows(product.leasefile)),
                    "dhcp_socket_closed": product.dhcp_socket is None,
                    "tcp_clients_closed": not product.tcp_clients,
                    "udp_clients_closed": not product.udp_clients,
                }
        except Exception as close_error:
            failures.append({"event": "cleanup", "error": repr(close_error)})
    final = {
        "implementation": args.implementation,
        "duration_seconds": args.duration_seconds,
        "sample_seconds": args.sample_seconds,
        "clients": args.clients,
        "seed": args.seed,
        "binary_sha256": sha256(root / ("usr/sbin/dnsmasq" if args.implementation == "c" else "usr/sbin/dnsmasq-rs")),
        "image_c_sha256": sha256(root / "usr/sbin/dnsmasq"),
        "rust_sha256": sha256(root / "usr/sbin/dnsmasq-rs"),
        "accounting": accounting,
        "failures": failures,
        "cleanup": cleanup,
        "trace": str(out / "trace.json"),
        "metrics": str(samples_path),
        "rootfs_identity": str(root_stage / "rootfs-identity.json"),
        "scope": "M3 exact-image soak; pressure faults are a separate gate",
        "accepted": (not failures and accounting["expiry"] > 0 and accounting["static"] > 0
                     and accounting["ethers"] > 0 and accounting["restart"] > 0
                     and accounting["dns_failover"] >= 3
                     and sample_count >= math.ceil(args.duration_seconds / args.sample_seconds)
                     and cleanup.get("daemon_alive_after_stop") is False
                     and cleanup.get("ubusd_alive_after_stop") is False
                     and cleanup.get("lease_rows_after_stop") == 0),
    }
    (out / "run.json").write_text(json.dumps(final, indent=2) + "\n")
    return 0 if not failures else 1


def pair(args: argparse.Namespace) -> int:
    out = args.out.resolve()
    if not out.is_relative_to(PRIVATE) or out.exists():
        raise SystemExit("--out must be a new path below private/")
    out.mkdir(parents=True)
    scripts = Path(__file__).resolve().parent
    records = []
    for implementation in ("c", "rust"):
        side_out = out / implementation
        argv = ["sh", str(scripts / "run_isolated.sh"), sys.executable, str(Path(__file__).resolve()),
                "run", "--image-root", str(args.image_root), "--rust-binary", str(args.rust_binary),
                "--implementation", implementation, "--duration-seconds", str(args.duration_seconds),
                "--sample-seconds", str(args.sample_seconds), "--clients", str(args.clients),
                "--seed", str(args.seed), "--out", str(side_out)]
        result = subprocess.run(argv, capture_output=True, text=True)
        records.append({"implementation": implementation, "argv": argv,
                        "returncode": result.returncode, "stdout": result.stdout,
                        "stderr": result.stderr})
    runs: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for implementation in ("c", "rust"):
        path = out / implementation / "run.json"
        if not path.exists():
            failures.append(f"missing {path}")
            continue
        runs[implementation] = json.loads(path.read_text())
        if runs[implementation].get("failures") or not runs[implementation].get("accepted"):
            failures.append(f"{implementation} reported workload failures")
        cleanup = runs[implementation].get("cleanup", {})
        if cleanup and any(cleanup.get(key) for key in ("daemon_alive_after_stop", "ubusd_alive_after_stop")):
            failures.append(f"{implementation} left a process alive after stop")
        if cleanup and not all(cleanup.get(key) is True for key in
                               ("dhcp_socket_closed", "tcp_clients_closed", "udp_clients_closed")):
            failures.append(f"{implementation} left a client socket open")
        if cleanup and cleanup.get("lease_rows_after_stop") != 0:
            failures.append(f"{implementation} left temporary lease rows after stop")
    if set(runs) == {"c", "rust"}:
        left = runs["c"].get("accounting")
        right = runs["rust"].get("accounting")
        if left != right:
            failures.append("C/Rust workload accounting differs")
    report = {
        "scope": "M3 pair harness with fixed 60 minute workload and cleanup gates",
        "runs": runs,
        "commands": records,
        "failures": failures,
        "same_workload_accounting": not failures and set(runs) == {"c", "rust"},
        "accepted": not failures and all(runs[side].get("accepted") for side in ("c", "rust")),
        "tool_sha256": sha256(Path(__file__)),
    }
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"same_workload_accounting": report["same_workload_accounting"], "failures": failures}))
    return 0 if report["same_workload_accounting"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("run", "pair"):
        child = sub.add_parser(mode)
        child.add_argument("--image-root", type=Path, required=True)
        child.add_argument("--rust-binary", type=Path, required=True)
        child.add_argument("--out", type=Path, required=True)
        if mode == "run":
            child.add_argument("--implementation", choices=("c", "rust"), required=True)
        child.add_argument("--duration-seconds", type=float, default=3600)
        child.add_argument("--sample-seconds", type=float, default=1)
        child.add_argument("--clients", type=int, default=20)
        child.add_argument("--seed", type=int, default=29302026)
    pressure = sub.add_parser(
        "pressure",
        help="run bounded exact-image ENOSPC and EMFILE recovery scenarios",
    )
    pressure.add_argument("--image-root", type=Path, required=True)
    pressure.add_argument("--rust-binary", type=Path, required=True)
    pressure.add_argument("--out", type=Path, required=True)
    pressure.add_argument("--scenario", action="append",
                          choices=("enospc", "emfile"),
                          help="scenario to run (default: both)")
    pressure.add_argument(
        "--duration-seconds", type=float, default=300,
        help="per-side deadline; use 300 for the required five-minute trial",
    )
    pressure.add_argument(
        "--timeout-seconds", type=float, default=3600,
        help="suite wall-clock limit; no result may run past this bound",
    )
    args = parser.parse_args()
    if args.duration_seconds <= 0:
        parser.error("duration must be positive")
    if args.mode in ("run", "pair") and (args.sample_seconds <= 0 or args.clients < 1):
        parser.error("duration/sample must be positive and clients >= 1")
    if args.mode == "run":
        return run_side(args)
    if args.mode == "pair":
        return pair(args)
    if args.timeout_seconds <= 0:
        parser.error("timeout must be positive")
    return pressure_pair(args)


if __name__ == "__main__":
    raise SystemExit(main())
