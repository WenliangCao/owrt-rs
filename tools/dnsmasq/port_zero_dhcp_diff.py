#!/usr/bin/env python3
"""Exact-C DHCP-only port=0 lifecycle and startup exit classes in a private netns.

Readiness is the child's owned DHCP socket in /proc, never a fixed sleep or DNS
connection. Inotify canaries detect opens/reads of private DNS input files.
"""
import argparse
import ctypes
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dhcp_lease_lifecycle import Daemon, rows
from dhcp_host_lifecycle import event, exchange, equivalent, normalized_rows


def sockets(pid):
    owned = set()
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try: target = os.readlink(path)
        except FileNotFoundError: continue
        if target.startswith("socket:["): owned.add(target[8:-1])
    result = []
    for kind in ("udp", "udp6", "tcp", "tcp6"):
        for line in Path(f"/proc/{pid}/net/{kind}").read_text().splitlines()[1:]:
            words = line.split()
            if words[9] in owned:
                result.append({"kind": kind, "port": int(words[1].rsplit(":", 1)[1], 16), "state": words[3]})
    return result


class ZeroDaemon(Daemon):
    def start(self):
        self.starts += 1
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("0.0.0.0", 68))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, 25, b"lo\0")
        self.log = (self.folder / f"daemon-{self.starts}.log").open("wb")
        self.process = subprocess.Popen([str(self.binary), "--no-daemon", "--conf-file=" + str(self.config)], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 5
        while self.process.poll() is None:
            if any(row["kind"] == "udp" and row["port"] == 67 for row in sockets(self.process.pid)):
                return
            if time.monotonic() >= deadline: break
            time.sleep(.01)
        raise AssertionError("DHCP kernel socket did not become ready")


class Canary:
    def __init__(self, paths):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        assert self.fd >= 0
        self.paths = {}
        for path in paths:
            watch = libc.inotify_add_watch(self.fd, os.fsencode(path), 0x01 | 0x20)  # ACCESS | OPEN
            assert watch >= 0
            self.paths[watch] = path.name

    def finish(self):
        events = []
        while True:
            try: data = os.read(self.fd, 16384)
            except BlockingIOError: break
            at = 0
            while at < len(data):
                wd, mask, cookie, size = struct.unpack_from("iIII", data, at)
                events.append({"file": self.paths.get(wd, "unknown"), "mask": mask})
                at += 16 + size
        os.close(self.fd)
        return events


def configuration(folder, leasefile, bank):
    # Resolver reading would be enabled with a nonzero DNS port. The canary is
    # a private file, so other host processes cannot manufacture false hits.
    hosts = folder / "dns.hosts"; hosts.write_text("127.0.0.90 dns-only.test\n")
    resolv = folder / "resolv.conf"; resolv.write_text("nameserver 127.0.0.1\n")
    config = folder / "dnsmasq.conf"
    config.write_text("port=0\nno-hosts\nlisten-address=127.0.0.1\nno-ping\ndhcp-authoritative\n"
                      "dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\ndomain=pool.test\n"
                      f"dhcp-leasefile={leasefile}\ndhcp-hostsfile={bank}\naddn-hosts={hosts}\nresolv-file={resolv}\n")
    return config, [hosts, resolv]


def live(binary, folder, checks, idle=False, control_socket=False):
    folder.mkdir(parents=True)
    leasefile = folder / "leases"
    initial = f"{int(time.time())+4} 02:00:00:00:00:07 127.0.0.13 expiring *\n".encode() if idle else b""
    leasefile.write_bytes(initial); (folder / "initial.leases").write_bytes(initial)
    bank = folder / "dhcp.hosts"; bank.write_text("02:00:00:00:00:2a,127.0.0.14,first,600\n")
    config, watched = configuration(folder, leasefile, bank)
    canary = Canary(watched)
    daemon = ZeroDaemon(binary.resolve(), config, leasefile, folder, checks, folder.name)
    values = []; socket_views = []
    try:
        daemon.start()
        socket_views.append(sockets(daemon.process.pid))
        daemon.check("no-dns-sockets", any(row["port"] == 53 for row in socket_views[-1]), False)
        daemon.check("no-tcp-sockets", sum(row["kind"].startswith("tcp") for row in socket_views[-1]), 0)
        daemon.check("udp-socket-budget", sum(row["kind"].startswith("udp") for row in socket_views[-1]), 1 + int(control_socket))
        if idle:
            daemon.check("restored", len(rows(leasefile)), 1)
            daemon.wait_rows(lambda value: not value, 7)
            daemon.check("expiry-with-no-dhcp", daemon.xid, 0)
            values.append({"label": "idle-expiry", "response": None, "leases": normalized_rows(leasefile, time.time())})
        else:
            for item in [event("offer", client=42), event("ack", 3, client=42, address="127.0.0.14", selecting=True)]:
                value = exchange(daemon, item); values.append(value)
                daemon.check(item["label"] + "-present", value["response"] is not None, True)
                daemon.check(item["label"] + "-no-dns-option", "6" in value["response"]["options"], False)
            original_expiry = rows(leasefile)[0]["expiry"]
            bank.write_text("02:00:00:00:00:2a,127.0.0.14,second,900\n")
            daemon.process.send_signal(signal.SIGHUP)
            daemon.wait_rows(lambda value: len(value) == 1 and value[0]["name"] == "second", 3)
            daemon.check("reload-retains-expiry", rows(leasefile)[0]["expiry"], original_expiry)
            values.append({"label": "reloaded", "response": None, "leases": normalized_rows(leasefile, time.time())})
            values.append(exchange(daemon, event("inform", 8, client=42, address="127.0.0.14")))
            values.append(exchange(daemon, event("release", 7, client=42, address="127.0.0.14")))
            daemon.wait_rows(lambda value: not value, 2)
            daemon.check("release-removes-lease", rows(leasefile), [])
        socket_views.append(sockets(daemon.process.pid))
        daemon.check("still-no-dns-sockets", any(row["port"] == 53 for row in socket_views[-1]), False)
        daemon.check("still-no-tcp-sockets", sum(row["kind"].startswith("tcp") for row in socket_views[-1]), 0)
        daemon.check("stable-udp-socket-budget", sum(row["kind"].startswith("udp") for row in socket_views[-1]), 1 + int(control_socket))
    finally:
        daemon.stop()
        events = canary.finish()
        daemon.check("dns-inputs-unread", events, [])
    (folder / "sockets.json").write_text(json.dumps(socket_views, indent=2) + "\n")
    (folder / "canary.json").write_text(json.dumps(events, indent=2) + "\n")
    return values


def failures(binary, folder):
    folder.mkdir(parents=True)
    expected = {"lease-open": 3, "lease-capacity": 5, "dhcp-bind": 2, "bad-config": 1}
    observed = {}
    for case, code in expected.items():
        path = folder / case; path.mkdir()
        leasefile = path / "leases"
        if case == "lease-capacity":
            leasefile.write_text("0 02:00:00:00:00:01 127.0.0.10 first *\n0 02:00:00:00:00:02 127.0.0.11 second *\n")
        elif case == "lease-open": leasefile = path / "missing-parent" / "leases"
        else: leasefile.write_bytes(b"")
        config = path / "dnsmasq.conf"
        config.write_text("port=0\nno-resolv\nno-hosts\nno-ping\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,600s\n"
                          f"dhcp-leasefile={leasefile}\n" + ("dhcp-lease-max=1\n" if case == "lease-capacity" else "")
                          + ("dhcp-range=invalid\n" if case == "bad-config" else ""))
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if case == "dhcp-bind" else None
        try:
            if blocker: blocker.bind(("0.0.0.0", 67))
            run = subprocess.run([str(binary.resolve()), "--no-daemon", "-C", str(config)], capture_output=True, timeout=5)
            (path / "stdout").write_bytes(run.stdout); (path / "stderr").write_bytes(run.stderr)
            observed[case] = run.returncode
        finally:
            if blocker: blocker.close()
    return observed, expected


def matches(actual, expected):
    if actual["label"] == "inform" and expected["label"] == "inform":
        # rfc2131.c DHCPINFORM reports remaining time, not the configured
        # lifetime. Each daemon samples a whole-second clock independently.
        # Tie each wire TTL to its own file expiry/send time, retain a one-second
        # cross-run bound, and leave every raw value in the saved observation.
        remaining = []
        for value in (actual, expected):
            try:
                wire = int(value["response"]["options"]["51"], 16)
                lease = value["leases"][0]["remaining"]
            except (KeyError, IndexError, TypeError):
                return False
            if abs(wire - lease) > 1: return False
            remaining.append(wire)
        if abs(remaining[0] - remaining[1]) > 1: return False
        actual = copy.deepcopy(actual); expected = copy.deepcopy(expected)
        actual["response"]["options"].pop("51")
        expected["response"]["options"].pop("51")
    return equivalent(actual, expected)


def calibrate_semantics():
    sample = {"label": "inform", "response": {"options": {"51": "00000258"}},
              "leases": [{"remaining": 600, "name": "calibration"}]}
    assert matches(sample, sample)
    earlier = copy.deepcopy(sample)
    earlier["response"]["options"]["51"] = "00000257"
    earlier["leases"][0]["remaining"] = 599
    assert matches(earlier, sample)
    wrong = copy.deepcopy(sample); wrong["response"]["options"]["51"] = "00000001"
    assert not matches(wrong, sample)
    missing = copy.deepcopy(sample); missing["response"]["options"].pop("51")
    assert not matches(missing, sample)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c-reference", type=Path, required=True)
    parser.add_argument("--c-sha256", required=True)
    parser.add_argument("--rust", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    if args.inject_error and not args.rust:
        parser.error("--inject-error requires --rust")
    assert os.uname().sysname == "Linux" and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert not Path("/etc/openwrt_release").exists()
    assert hashlib.sha256(args.c_reference.read_bytes()).hexdigest() == args.c_sha256
    out = args.out.resolve(); assert "private" in out.parts; out.mkdir(parents=True, exist_ok=False)
    calibrate_semantics()
    calibration = out / "canary-calibration"
    calibration.write_bytes(b"private calibration\n")
    watcher = Canary([calibration]); calibration.read_bytes(); detected = watcher.finish()
    masks = 0
    for record in detected: masks |= record["mask"]
    assert masks & 0x01 and masks & 0x20, "canary must detect controlled access/open"
    assert Canary([calibration]).finish() == [], "untouched canary must remain empty"
    (out / "canary-calibration.json").write_text(json.dumps(detected, indent=2) + "\n")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as calibration_socket:
        calibration_socket.bind(("127.0.0.1", 0))
        assert any(row["kind"] == "udp" and row["port"] == calibration_socket.getsockname()[1]
                   for row in sockets(os.getpid())), "owned-socket detector calibration"
    checks = []; observed = {}; error = None
    try:
        for implementation, binary in [("c", args.c_reference)] + ([("rust", args.rust)] if args.rust else []):
            values = live(binary, out / implementation / "live", checks, control_socket=implementation == "rust")
            values += live(binary, out / implementation / "idle", checks, idle=True, control_socket=implementation == "rust")
            assert len(values) == 6
            exits, expected = failures(binary, out / implementation / "startup")
            for case, code in expected.items(): checks.append({"case": implementation + "-" + case, "pass": exits[case] == code, "actual": exits[case], "expected": code})
            observed[implementation] = values
        if args.rust:
            if args.inject_error: observed["rust"][1]["response"]["options"]["51"] = "00000001"
            for c, rust in zip(observed["c"], observed["rust"]):
                checks.append({"case": c["label"], "pass": matches(rust, c), "c": c, "rust": rust})
    except Exception as failure:
        error = repr(failure)
    failed = [check for check in checks if not check["pass"]]
    result = {"passed": sum(check["pass"] for check in checks), "failed": len(failed), "error": error,
              "checks": checks, "observed": observed, "failures": failed,
              "c_sha256": args.c_sha256, "rust_sha256": hashlib.sha256(args.rust.read_bytes()).hexdigest() if args.rust else None,
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "scope": "port=0 DHCP/file/reload/idle expiry, no DNS sockets or input reads, startup exit classes",
              "normalization": "INFORM remaining lease TTL tied to its file expiry/send time and bounded to one second across runs; ACK/OFFER lifetime stays exact"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in ("checks", "observed", "failures")}, indent=2))
    return int(bool(failed) or error is not None)


if __name__ == "__main__":
    raise SystemExit(main())
