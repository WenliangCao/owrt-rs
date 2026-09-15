#!/usr/bin/env python3
"""rpcd reconnect/rollback regression inside an exact-image disposable namespace."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from r92_recovery_probe import Bus, attr, digest, message, write
from r92_compat_probe import Fixture, integer, string, response_data, values


def register_service(client):
    signature = message("event", 2, integer("type", 3) + integer("data", 2))
    code, replies = client.request(6, attr(2, b"service\0") + attr(6, signature))
    assert code == 0
    return struct.unpack(">I", dict(replies[0][2])[3])[0]


class Service:
    def __init__(self, f, fail_first=False):
        self.client = f.connect()
        self.obj = register_service(self.client)
        self.events = []
        self.fail_first = fail_first
        self.reject_package = None
        self.reject_all = False
        self.stall_all = False
        self.attempts = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        self.client.sock.settimeout(0.1)
        while not self.done.is_set():
            try:
                kind, seq, peer, fields = self.client.recv()
            except socket.timeout:
                continue
            except (OSError, EOFError):
                return
            if kind != 5:
                continue
            fields = dict(fields)
            event = values(fields.get(7, b""))
            self.events.append(event)
            self.attempts.append(time.monotonic())
            if self.stall_all:
                continue
            code = 9 if self.fail_first and len(self.events) == 1 else 0
            if self.reject_all or event.get(b"data", {}).get(b"package") == self.reject_package:
                code = 9
            body = attr(3, fields[3]) + attr(1, struct.pack(">I", code))
            self.client.sock.sendall(struct.pack(">BBHII", 0, 1, seq, peer, len(body) + 4) + body)

    def close(self):
        self.done.set()
        self.thread.join(timeout=1)
        self.client.sock.close()


class HalfHeaderProxy:
    """Transparent first connection, then inject a stalled 4-byte ubus header."""
    def __init__(self, frontend, backend):
        self.backend = backend
        self.stop = threading.Event()
        self.inject = threading.Event()
        self.injected = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(frontend))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        count = 0
        while not self.stop.is_set():
            try:
                front, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=self.relay, args=(front, count == 0), daemon=True)
            count += 1
            self.workers.append(worker)
            worker.start()

    def relay(self, front, first):
        with front, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as back:
            back.connect(str(self.backend))
            stalled = False
            while not self.stop.is_set():
                if first and self.inject.is_set() and not stalled:
                    front.sendall(b"\0\0\0\0")
                    stalled = True
                    self.injected.set()
                readable, _, _ = select.select([front] if stalled else [front, back], [], [], 0.02)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (back if source is front else front).sendall(data)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)
        self.listener.close()
        for worker in self.workers:
            worker.join(timeout=1)


def inner(root, fault):
    f = Fixture(root, "candidate", "rpcd")
    service = None
    proxy = None
    checks, observations = {}, {}
    try:
        config = root / "etc/config/r93probe"
        original = "config test 'section'\n option value 'before'\n"
        write(config, original)
        f.start_bus()
        service = Service(f)
        if fault == "half_header":
            proxy = HalfHeaderProxy(root / "tmp/r93-proxy.sock", f.sock)
            f.start_subject("-s", "/tmp/r93-proxy.sock", obj="iwinfo")
        else:
            f.start_subject(obj="iwinfo")
        checks["identity"] = digest(Path(f"/proc/{f.subject.pid}/exe")) == digest(root / "tmp/rpcd-rs")
        client = f.connect()
        session, uci = client.lookup("session"), client.lookup("uci")
        code, replies = client.invoke(session, "create", integer("timeout", 60))
        assert code == 0
        sid = response_data(replies)[0][b"ubus_rpc_session"]
        args = string("ubus_rpc_session", sid)
        pair = message("", 1, string("", "r93probe") + string("", "write"))
        assert client.invoke(session, "grant", args + string("scope", "uci") + message("objects", 1, pair))[0] == 0
        change = args + string("config", "r93probe") + string("section", "section") + message("values", 2, string("value", "after"))
        assert client.invoke(uci, "set", change)[0] == 0
        assert client.invoke(uci, "apply", args + integer("timeout", 2) + message("rollback", 7, b"\x01"))[0] == 0
        checks["applied"] = "after" in config.read_text()
        checks["initial_event"] = f.wait(lambda: len(service.events) == 1)
        # An independently expiring session proves offline timer processing.
        code, replies = client.invoke(session, "create", integer("timeout", 1))
        assert code == 0
        expiring = response_data(replies)[0][b"ubus_rpc_session"]
        # A deferred exec deliberately completes after the new bus is serving.
        deferred = f.connect()
        command = string("command", "/bin/sh") + message("params", 1, string("", "-c") + string("", "touch /tmp/out/worker-started; sleep 5; echo stale-worker; touch /tmp/out/worker-done"))
        deferred.send(5, attr(3, struct.pack(">I", deferred.lookup("file"))) + attr(4, b"exec\0") + attr(7, command))
        assert f.wait(lambda: (f.output / "worker-started").exists())
        started = time.monotonic()
        service.close()
        service = None
        if proxy is not None:
            proxy.inject.set()
            assert proxy.injected.wait(1), "proxy did not inject the half header"
        else:
            f.bus.kill()
            f.bus.wait(timeout=2)
        restored = f.wait(lambda: "before" in config.read_text(), timeout=4)
        checks["offline_file_rollback"] = restored
        observations["rollback_seconds_after_disconnect"] = time.monotonic() - started if restored else None
        checks["same_process_survives"] = f.subject.poll() is None
        assert restored and checks["same_process_survives"], "rpcd lost rollback when ubusd disconnected"
        if proxy is None:
            f.sock.unlink(missing_ok=True)
            f.start_bus()
        service = Service(f)
        assert f.wait(lambda: f.ready("iwinfo")), "rpcd did not re-register every object"
        current = f.connect()
        session, uci = current.lookup("session"), current.lookup("uci")
        checks["session_survives"] = current.invoke(session, "list", args)[0] == 0
        checks["offline_session_expired"] = current.invoke(session, "list", string("ubus_rpc_session", expiring))[0] == 4
        checks["rollback_complete"] = current.invoke(uci, "confirm", args)[0] == 5
        checks["event_replayed"] = f.wait(lambda: len(service.events) == 1)
        checks["correct_replayed_package"] = service.events == [{b"type": b"config.change", b"data": {b"package": b"r93probe"}}]
        assert f.wait(lambda: (f.output / "worker-done").exists(), timeout=5)
        time.sleep(1.2)
        checks["success_event_not_repeated"] = len(service.events) == 1
        checks["serving_after_old_worker"] = current.invoke(session, "list", args)[0] == 0
        # A failed service.event reply on an otherwise live bus must also be
        # retried, while its eventual success must stop further deliveries.
        service.close()
        service = Service(f, fail_first=True)
        change = args + string("config", "r93probe") + string("section", "section") + message("values", 2, string("value", "live-retry"))
        assert current.invoke(uci, "set", change)[0] == 0
        assert current.invoke(uci, "commit", args + string("config", "r93probe"))[0] == 0
        checks["live_failure_retried"] = f.wait(lambda: len(service.events) == 2)
        expected_event = {b"type": b"config.change", b"data": {b"package": b"r93probe"}}
        checks["live_retry_exact_package"] = service.events == [expected_event, expected_event]
        time.sleep(1.2)
        checks["live_success_not_repeated"] = len(service.events) == 2
        # The first package permanently fails; the second still needs its
        # rollback event. Also hold every event reply at the rollback deadline:
        # all disk files must be restored before those replies can delay us.
        service.close()
        service = Service(f)
        for name in ("r93a", "r93b"):
            write(root / "etc/config" / name, original)
            pair = message("", 1, string("", name) + string("", "write"))
            assert current.invoke(session, "grant", args + string("scope", "uci") + message("objects", 1, pair))[0] == 0
            change = args + string("config", name) + string("section", "section") + message("values", 2, string("value", "after"))
            assert current.invoke(uci, "set", change)[0] == 0
        assert current.invoke(uci, "apply", args + integer("timeout", 2) + message("rollback", 7, b"\x01"))[0] == 0
        service.events.clear()
        service.attempts.clear()
        service.stall_all = True
        started = time.monotonic()
        restored = f.wait(lambda: all("before" in (root / "etc/config" / name).read_text() for name in ("r93a", "r93b")), timeout=2.8)
        checks["all_files_restore_before_stalled_events"] = restored
        observations["two_package_restore_seconds"] = time.monotonic() - started
        service.reject_package = b"r93a"
        service.stall_all = False
        checks["later_package_not_starved"] = f.wait(lambda: any(e.get(b"data", {}).get(b"package") == b"r93b" for e in service.events), timeout=5)
        seen_b = sum(e.get(b"data", {}).get(b"package") == b"r93b" for e in service.events)
        time.sleep(1.2)
        checks["later_package_success_not_repeated"] = sum(e.get(b"data", {}).get(b"package") == b"r93b" for e in service.events) == seen_b == 1
        observations["multi_package_attempts"] = [e.get(b"data", {}).get(b"package", b"").decode() for e in service.events]
        service.reject_all = True
        change = args + string("config", "r93b") + string("section", "section") + message("values", 2, string("value", "retry-b"))
        assert current.invoke(uci, "set", change)[0] == 0
        assert current.invoke(uci, "commit", args + string("config", "r93b"))[0] == 0
        service.events.clear()
        service.reject_all = False
        checks["two_failed_packages_retry_fairly"] = f.wait(lambda: any(e.get(b"data", {}).get(b"package") == b"r93b" for e in service.events), timeout=4)
        observations["retry_rotation"] = [e.get(b"data", {}).get(b"package", b"").decode() for e in service.events]
        observations["same_pid"] = f.subject.pid
        observations["live_retry_attempts"] = len(service.events)
        observations["fault"] = fault
        checks["identity_after"] = digest(Path(f"/proc/{f.subject.pid}/exe")) == digest(root / "tmp/rpcd-rs")
    finally:
        if service is not None:
            service.close()
        if proxy is not None:
            proxy.close()
        write(f.output / "result.json", json.dumps({"checks": checks, "observations": observations}, indent=2) + "\n")
        f.close()
    assert all(checks.values()), checks


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("rpcd", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--fault", choices=("disconnect", "half_header"), default="disconnect")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root on the Linux build host")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="r93-rpcd-reconnect-") as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(args.rootfs, root, symlinks=True)
        for directory in ("out", "run/ubus", "lock", "state", "initd", "rcd"):
            (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.rpcd, root / "tmp/rpcd-rs")
        with (args.output / "driver.log").open("wb") as log:
            result = subprocess.run(["timeout", "-k", "3", "40", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root), args.fault], stdout=log, stderr=log)
        shutil.copytree(root / "tmp/out", args.output / "raw")
    data_path = args.output / "raw/result.json"
    data = json.loads(data_path.read_text()) if data_path.exists() else {"checks": {}, "observations": {}}
    summary = {"rpcd_sha256": digest(args.rpcd), "probe_sha256": digest(Path(__file__)), "exit": result.returncode, **data}
    summary["passed"] = result.returncode == 0 and len(data["checks"]) == 20 and all(data["checks"].values())
    write(args.output / "results.json", json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
