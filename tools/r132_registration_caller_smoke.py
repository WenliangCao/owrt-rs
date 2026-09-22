#!/usr/bin/env python3
"""Oracle functional/ACK check; mock ACKs never establish perf measurements."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import tempfile
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def read_command(fd):
    data = b""
    while not data.endswith(b"\n"):
        require(select.select([fd], [], [], 10)[0], "control command timeout")
        chunk = os.read(fd, 1)
        require(chunk and len(data) < 16, "control pipe closed or invalid command")
        data += chunk
    return data


def validate(data, pid, client, methods):
    expected = {"schema": 1, "fixture": "rust_register_cycle", "n": 100, "successful": 100,
                "errors": 0, "warmup": 20, "methods": methods, "name_bytes": 8,
                "subject_pid": pid, "client_pid": client, "subject_cpu": 1, "client_cpu": 0,
                "perf_controlled": True, "full_signature_checked": True, "warmup_empty": True,
                "final_empty": True, "wire_reply_bytes_checked": False, "latency_sample_count": 100}
    for key, value in expected.items():
        require(type(data[key]) is type(value) and data[key] == value, f"caller field mismatch: {key}")
    require(data["subject_resolution_ns"] == data["client_resolution_ns"] == 1, "clock resolution")
    samples = data["latency_ns"]
    require(len(samples) == 100 and all(type(x) is int and x > 0 for x in samples), "raw samples")
    intervals = {clock: data[f"{clock}_after_ns"] - data[f"{clock}_before_ns"]
                 for clock in ("subject", "client", "wall")}
    require(0 < sum(samples) <= intervals["wall"] and 0 < intervals["subject"] <= intervals["wall"]
            and 0 < intervals["client"] <= intervals["wall"], "clock enclosure")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-host-only", action="store_true", required=True)
    parser.add_argument("--reference-plan", type=Path, required=True)
    parser.add_argument("--caller", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    a = parser.parse_args()
    require(platform.machine() == "aarch64" and not Path("/etc/openwrt_release").exists(), "Oracle only")
    plan = json.loads(a.reference_plan.read_text())
    root = Path(plan["rootfs"]["path"])
    for relative, digest in plan["rootfs"]["libraries"].items():
        require(sha(root / relative.lstrip("/")) == digest, f"library identity: {relative}")
    loader = [str(root / "lib/libc.so"), "--library-path", f"{root}/lib:{root}/usr/lib"]
    a.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for label in ("c", "r124", "r131"):
        subject = plan["subjects"][label]
        require(sha(subject["path"]) == subject["sha256"], f"subject identity: {label}")
        for methods in (1, 16):
            folder = a.out / f"{label}-{methods}"
            folder.mkdir()
            daemon = client = None
            fds = []
            with tempfile.TemporaryDirectory(prefix="r132-caller-") as tmp, \
                    (folder / "daemon.log").open("wb") as daemon_log, \
                    (folder / "caller.json").open("wb") as output, \
                    (folder / "caller.stderr").open("wb") as error:
                sock = str(Path(tmp) / "bus.sock")
                cmd = ["/sbin/ubusd", "-s", sock, "-A", tmp]
                executable = subject["path"]
                if subject["kind"] == "dynamic":
                    cmd = loader + ["--argv0", "/sbin/ubusd", executable, "-s", sock, "-A", tmp]
                    executable = loader[0]
                try:
                    daemon = subprocess.Popen(cmd, executable=executable, stdout=daemon_log, stderr=subprocess.STDOUT,
                                              preexec_fn=lambda: os.sched_setaffinity(0, {1}))
                    deadline = time.monotonic() + 5
                    while not Path(sock).is_socket():
                        require(daemon.poll() is None and time.monotonic() < deadline, "daemon startup")
                        time.sleep(.01)
                    ctl_read, ctl_write = os.pipe()
                    ack_read, ack_write = os.pipe()
                    fds = [ctl_read, ctl_write, ack_read, ack_write]
                    args = [str(a.caller), "register-cycle", sock, str(methods), "8", "100", "20", str(daemon.pid)]
                    env = dict(os.environ, OWRT_PERF_CTL_FD=str(ctl_write), OWRT_PERF_ACK_FD=str(ack_read))
                    client = subprocess.Popen(args, pass_fds=(ctl_write, ack_read), env=env, stdout=output, stderr=error)
                    for fd in (ctl_write, ack_read):
                        os.close(fd)
                        fds.remove(fd)
                    require(read_command(ctl_read) == b"enable\n", "missing enable")
                    require(os.sched_getaffinity(client.pid) == {0} and os.sched_getaffinity(daemon.pid) == {1}, "live affinity")
                    require(sha(f"/proc/{client.pid}/exe") == sha(a.caller), "live caller ELF")
                    # The caller is blocked before the measured loop. An empty
                    # registry here independently checks the warmup boundary.
                    listing = subprocess.run(loader + [str(root / "bin/ubus"), "-s", sock, "list"],
                                             capture_output=True, timeout=5, check=True)
                    require(not listing.stdout.strip(), "object present at enable boundary")
                    os.write(ack_write, b"ack\n\0")
                    require(read_command(ctl_read) == b"disable\n", "missing disable")
                    require(os.sched_getaffinity(client.pid) == {0} and os.sched_getaffinity(daemon.pid) == {1}, "end affinity")
                    os.write(ack_write, b"ack\n\0")
                    require(client.wait(timeout=10) == 0, "caller failed")
                    output.flush()
                    data = json.loads((folder / "caller.json").read_text())
                    validate(data, daemon.pid, client.pid, methods)
                    require(not (folder / "caller.stderr").read_bytes(), "caller stderr")
                    row = {"subject": label, "subject_sha256": subject["sha256"], "methods": methods,
                           "n": 100, "warmup": 20, "commands": ["enable", "disable"],
                           "ack": "ack\\n\\0", "warmup_registry_empty_at_enable": True,
                           "live_affinity_checked": True, "caller_output_sha256": sha(folder / "caller.json"),
                           "passed": True}
                    rows.append(row)
                    (folder / "result.json").write_text(json.dumps(row, indent=2) + "\n")
                finally:
                    stop(client)
                    stop(daemon)
                    for fd in fds:
                        os.close(fd)
    report = {"scope": "Oracle registration fixture and mock-ACK functionality only; no perf or router conclusions",
              "caller_sha256": sha(a.caller), "runner_sha256": sha(__file__), "cases": rows,
              "actual_perf_control_validation": "pending separate low-n perf stat/record smoke", "passed": True}
    (a.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    (a.out / "COMPLETE").touch()


if __name__ == "__main__":
    main()
