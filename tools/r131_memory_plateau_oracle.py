#!/usr/bin/env python3
"""Oracle-only functional gate for the fixed repeated-event memory diagnostic."""
import argparse
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import tempfile
import time

from r131_latency_report import check, digest, read


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile-plan", type=Path, required=True)
    p.add_argument("--helper", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    check(platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists(), "Oracle only")
    plan = read(a.profile_plan)
    root = Path(plan["rootfs"]["path"])
    for path, sha in plan["rootfs"]["libraries"].items():
        check(digest(root / path.lstrip("/")) == sha, f"library {path}")
    loader = [str(root / "lib/libc.so"), "--library-path", f"{root}/lib:{root}/usr/lib"]
    a.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for label in ("c", "r124", "r131"):
        subject = plan["subjects"][label]
        check(digest(subject["path"]) == subject["sha256"], f"subject {label}")
        daemon = helper = None
        with tempfile.TemporaryDirectory(prefix="r131-memory-plateau-") as tmp, \
                (a.out / f"{label}-daemon.log").open("wb") as log, \
                (a.out / f"{label}-helper.stderr").open("wb") as stderr:
            sock = str(Path(tmp) / "bus.sock")
            cmd = ["/sbin/ubusd", "-s", sock, "-A", tmp]
            executable = subject["path"]
            if subject["kind"] == "dynamic":
                cmd = loader + ["--argv0", "/sbin/ubusd", executable, "-s", sock, "-A", tmp]
                executable = loader[0]
            phases = []
            try:
                daemon = subprocess.Popen(cmd, executable=executable, stdout=log, stderr=subprocess.STDOUT,
                                          preexec_fn=lambda: os.sched_setaffinity(0, {1}))
                deadline = time.monotonic() + 5
                while not Path(sock).exists():
                    check(daemon.poll() is None and time.monotonic() < deadline, "daemon startup")
                    time.sleep(.01)
                subprocess.run(loader + [str(root / "bin/ubus"), "-s", sock, "list"],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                time.sleep(.05)
                base = len(list(Path(f"/proc/{daemon.pid}/fd").iterdir()))
                helper = subprocess.Popen(loader + [str(a.helper), "event-memory-repeat", sock,
                    str(daemon.pid), str(base)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=stderr, text=True)
                for name, count, control in (("READY", 8, "STEP\n"), ("DELIVERED_1", 16, "STEP\n"),
                        ("DELIVERED_1000", 8008, "STEP\n"), ("DELIVERED_10000", 80008, "CLOSE\n"),
                        ("CLOSED", 80008, None)):
                    check(select.select([helper.stdout], [], [], 45)[0], f"{label}: {name} timeout")
                    line = helper.stdout.readline()
                    check(line, f"{label}: {name} absent")
                    row = json.loads(line)
                    check(row["phase"] == name and row["received"] == 8 and row["total_received"] == count,
                          f"{label}: {name} count")
                    check(row["payload_checked"] is True and row["listener_barrier"] is True and
                          row["subject_pid"] == daemon.pid and row["base_fds"] == base and
                          row["subject_cpu"] == 1 and row["client_cpu"] == 0, f"{label}: {name} evidence")
                    phases.append(row)
                    if control:
                        helper.stdin.write(control)
                        helper.stdin.flush()
                check(helper.wait(timeout=5) == 0, f"{label}: helper exit")
                check(not (a.out / f"{label}-helper.stderr").read_bytes(), f"{label}: helper stderr")
                deadline = time.monotonic() + 5
                while len(list(Path(f"/proc/{daemon.pid}/fd").iterdir())) != base:
                    check(daemon.poll() is None and time.monotonic() < deadline, "FD cleanup")
                    time.sleep(.01)
                rows.append({"label": label, "subject_sha256": subject["sha256"], "phases": phases, "passed": True})
            finally:
                (a.out / f"{label}-phases.json").write_text(json.dumps(phases, indent=2) + "\n")
                stop(helper)
                stop(daemon)
    result = {"scope": "Oracle functional validation only; no router memory or performance inference",
              "helper_sha256": digest(a.helper), "runner_sha256": digest(__file__), "passed": True, "cases": rows}
    (a.out / "result.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
