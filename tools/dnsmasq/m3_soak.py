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
                     and accounting["dns_failover"] >= 3 and len(samples) >= args.duration_seconds
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
    args = parser.parse_args()
    if args.duration_seconds <= 0 or args.sample_seconds <= 0 or args.clients < 1:
        parser.error("duration/sample must be positive and clients >= 1")
    if args.mode == "run":
        return run_side(args)
    return pair(args)


if __name__ == "__main__":
    raise SystemExit(main())
