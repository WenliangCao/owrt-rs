"""Private exact-image ubusd plus a trigger-free protocol receiver for r1.

The enclosing r92 namespace owns all descendants; this helper also explicitly
stops its two process groups. Never point it at a production root or socket.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

C_UBUSD_SHA256 = "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88"


def raw_events(root: Path) -> list[dict]:
    path = root / "tmp/r1-delivery-raw.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line]


class ProtocolFixture:
    def __init__(self, root: Path, receiver: Path):
        self.root = root
        self.receiver = receiver
        self.processes: list[subprocess.Popen] = []
        self.logs = []

    def start(self, command: list[str], label: str) -> subprocess.Popen:
        log = (self.root / f"tmp/{label}.log").open("wb")
        self.logs.append(log)
        process = subprocess.Popen(["sudo", "-n", "chroot", str(self.root), *command],
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(process)
        return process

    def __enter__(self):
        try:
            observed = hashlib.sha256((self.root / "sbin/ubusd").read_bytes()).hexdigest()
            if observed != C_UBUSD_SHA256:
                raise ValueError("private ubusd differs from the exact image")
            target = self.root / "tmp/reload-fault-receiver"
            shutil.copy2(self.receiver, target)
            target.chmod(0o755)
            (self.root / "var/run/ubus").mkdir(parents=True, exist_ok=True)
            self.start(["/sbin/ubusd", "-s", "/var/run/ubus/ubus.sock"], "r1-bus")
            deadline = time.monotonic() + 5
            socket = self.root / "var/run/ubus/ubus.sock"
            while not socket.exists():
                if any(p.poll() is not None for p in self.processes) or time.monotonic() >= deadline:
                    raise RuntimeError("private C ubusd did not become ready")
                time.sleep(0.01)
            self.start(["/tmp/reload-fault-receiver", "reload-fault-service",
                        "/var/run/ubus/ubus.sock", "/tmp/r1-delivery"], "r1-receiver")
            ready = self.root / "tmp/r1-delivery-ready"
            while not ready.exists():
                if any(p.poll() is not None for p in self.processes) or time.monotonic() >= deadline:
                    raise RuntimeError("private protocol receiver did not register service")
                time.sleep(0.01)
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                subprocess.run(["sudo", "-n", "kill", "-TERM", f"-{process.pid}"],
                               check=False, capture_output=True)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    subprocess.run(["sudo", "-n", "kill", "-KILL", f"-{process.pid}"],
                                   check=False, capture_output=True)
                    process.wait(timeout=3)
        for log in self.logs:
            log.close()

    def __exit__(self, exc_type, exc, traceback):
        failed = [p.returncode for p in self.processes if p.poll() is not None]
        self.close()
        if not exc_type and failed:
            raise RuntimeError(f"private protocol server exited early: {failed}")
