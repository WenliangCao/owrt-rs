#!/usr/bin/env python3
"""Compare netifd's logging contract in disposable Linux namespaces.

Use the exact OpenWrt image and a candidate, never a running router. Each case
gets its own mount, network and PID namespace. The PID namespace's init owns
all children, including on failure or timeout. Raw datagrams and stderr stay
in OUTPUT; missing observations and dead daemons fail the gate.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time


ORIGINAL_SHA256 = "8ed0c6bc794fb3c56b8421347173165637d60efdd46782e7a575e67f89b3ba90"
METHODS = {"up", "down", "renew", "status", "prepare", "dump", "add_device",
           "remove_device", "notify_proto", "remove", "set_data"}
CASES = {
    "surface": [],
    "syslog": [],
    "stderr": ["-S"],
    "quiet": ["-l1"],
    "verbose": ["-l99tail"],
    "negative": ["-l", "-1"],
    "invalid": ["-l", "nonnumeric"],
    "reconnect": [],
    "stderr_full": ["-S"],
}
BASE_CHECKS = {"live", "identity", "interface_up", "interface_down", "methods"}
LOG_CHECKS = {"notice_delivery", "notice_priority", "channel_exclusive", "child_identity"}
PROTO = r'''#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_r91_init_config() { :; }
proto_r91_setup() {
    echo $$ > /tmp/out/setup-pid
    echo r91-stdout-notice
    echo r91-stderr-notice >&2
    echo 'r91-format:%s:%n:%%'
    proto_init_update "$2" 1
    proto_add_ipv4_address 10.91.0.1 24
    proto_send_update "$1"
}
proto_r91_teardown() {
    echo $$ > /tmp/out/teardown-pid
    echo r91-teardown-notice
    echo done >> /tmp/out/teardown
}
add_protocol r91
'''
CONFIG = """config interface 'probe'
 option device 'veth1'
 option proto 'r91'
"""
MARKERS = (b"Interface 'probe' is setting up now", b"Interface 'probe' is now up",
           b"r91-stdout-notice", b"r91-stderr-notice", b"r91-teardown-notice",
           b"Interface 'probe' is now down", b"r91-format:%s:%n:%%")


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def write(path, data, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)
    if executable:
        path.chmod(0o755)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inner(root, side, case):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
    run("ip", "link", "set", "veth0", "up")

    output = root / "tmp/out"
    datagrams = []
    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    receiver.bind(str(root / "dev/log"))
    receiver.setblocking(False)
    processes = []
    pipe_fds = []
    checks = {}

    def drain():
        while True:
            try:
                datagrams.append(receiver.recv(65536))
            except BlockingIOError:
                return

    def start(binary, *args, stderr=None):
        with (output / (Path(binary).name + ".stderr")).open("wb") as log:
            process = subprocess.Popen(["chroot", str(root), binary, *args],
                                       stdout=log, stderr=log if stderr is None else stderr)
        processes.append(process)
        return process

    def wait_for(predicate, seconds=8):
        until = time.monotonic() + seconds
        while True:
            drain()
            if any(p.poll() is not None for p in processes):
                raise AssertionError("fixture or subject exited")
            if predicate():
                return
            if time.monotonic() >= until:
                raise AssertionError("precondition or completion timed out")
            time.sleep(0.025)

    def ubus(*args):
        return subprocess.run(["chroot", str(root), "ubus", "-S", "-t", "2", *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)

    def call(method):
        result = ubus("call", "network.interface.probe", method, "{}")
        result.check_returncode()
        return json.loads(result.stdout or "{}")

    try:
        start("/sbin/ubusd")
        wait_for(lambda: (root / "var/run/ubus/ubus.sock").exists())
        binary = "/sbin/netifd" if side == "original" else "/tmp/netifd-rs"
        stderr = None
        if case == "stderr_full":
            rd, wr = os.pipe()
            pipe_fds.extend((rd, wr))
            fcntl.fcntl(wr, fcntl.F_SETFL, fcntl.fcntl(wr, fcntl.F_GETFL) | os.O_NONBLOCK)
            try:
                while True:
                    os.write(wr, b"x" * 4096)
            except BlockingIOError:
                pass
            stderr = wr
        subject = start(binary, *CASES[case], stderr=stderr)
        wait_for(lambda: ubus("list", "network.interface.probe").stdout.strip()
                 == b"network.interface.probe")
        checks["identity"] = sha256(Path(f"/proc/{subject.pid}/exe")) == sha256(root / binary[1:])
        wait_for(lambda: call("status").get("up") is True)
        checks["interface_up"] = True
        write(output / "up.json", json.dumps(call("status"), indent=2) + "\n")

        # ubus's -S suppresses signatures even alongside -v.
        signatures = run("chroot", root, "ubus", "-v", "list", "network.interface.probe",
                         capture_output=True, timeout=4)
        (output / "methods.txt").write_bytes(signatures.stdout)
        found = set(re.findall(rb'^\s+"([^"]+)":', signatures.stdout, re.MULTILINE))
        checks["methods"] = found == {name.encode() for name in METHODS}

        if case == "reconnect":
            # Exercise libc's recovery after logd's socket is replaced. Retain
            # the first receiver's evidence separately from the new channel.
            wait_for(lambda: any(b"r91-stdout-notice" in msg for msg in datagrams))
            write(output / "before-reconnect.json", json.dumps([d.hex() for d in datagrams]) + "\n")
            receiver.close()
            (root / "dev/log").unlink()
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(root / "dev/log"))
            receiver.setblocking(False)
            datagrams.clear()

        call("down")
        wait_for(lambda: call("status").get("up") is False
                 and not call("status").get("pending", False)
                 and (output / "teardown").exists())
        # UP=false can be observed during teardown. Observe its script and
        # the final DOWN log too, rather than treating that boolean as done.
        if case == "reconnect":
            wait_for(lambda: any(b"Interface 'probe' is now down" in msg for msg in datagrams))
            call("up")
            wait_for(lambda: call("status").get("up") is True)
            call("down")
            wait_for(lambda: call("status").get("up") is False)
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            drain()
            time.sleep(0.025)
        checks["interface_down"] = call("status").get("up") is False
        checks["live"] = subject.poll() is None
        stderr_bytes = (output / (Path(binary).name + ".stderr")).read_bytes()
        quiet = case in ("quiet", "negative", "invalid", "stderr_full")
        is_stderr = case in ("stderr", "stderr_full")
        target = stderr_bytes if is_stderr else b"\n".join(datagrams)
        other = b"\n".join(datagrams) if is_stderr else stderr_bytes
        if case != "surface":
            checks["notice_delivery"] = (not any(m in target for m in MARKERS) if quiet
                                         else all(m in target for m in MARKERS))
            checks["notice_priority"] = all(msg.startswith(b"<29>") and b" netifd: " in msg
                                            for msg in datagrams if any(m in msg for m in MARKERS))
            checks["channel_exclusive"] = not any(m in other for m in MARKERS)
            setup_pid = int((output / "setup-pid").read_text())
            teardown_pid = int((output / "teardown-pid").read_text())
            checks["child_identity"] = quiet or all(
                f"probe ({pid}): {marker}".encode() in target
                for pid, marker in ((setup_pid, "r91-stdout-notice"),
                                    (setup_pid, "r91-stderr-notice"),
                                    (teardown_pid, "r91-teardown-notice")))
    finally:
        drain()
        for i, message in enumerate(datagrams):
            (output / f"syslog-{i:04d}.bin").write_bytes(message)
        write(output / "datagrams.json", json.dumps([d.hex() for d in datagrams], indent=2) + "\n")
        write(output / "result.json", json.dumps(checks, indent=2) + "\n")
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        receiver.close()
        for fd in pipe_fds:
            os.close(fd)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--sides", nargs="+", choices=("original", "candidate"),
                        default=["original", "candidate"])
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run as root on the Linux build host")
    args.rootfs = args.rootfs.resolve()
    args.candidate = args.candidate.resolve()
    args.output = args.output.resolve()
    if sha256(args.rootfs / "sbin/netifd") != ORIGINAL_SHA256:
        parser.error("rootfs netifd is not the pinned cbb83a18 image binary")
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "identity.json", json.dumps({
        "original_sha256": ORIGINAL_SHA256,
        "candidate_sha256": sha256(args.candidate),
        "probe_sha256": sha256(Path(__file__)),
        "cases": args.cases,
        "sides": args.sides,
    }, indent=2) + "\n")
    rows = []
    for side in args.sides:
        for case in args.cases:
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="r91-netifd-") as temp:
                root = Path(temp) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state", "resolv.conf.d"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                shutil.copy2(args.candidate, root / "tmp/netifd-rs")
                write(root / "etc/config/network", CONFIG)
                write(root / "etc/config/wireless", "")
                write(root / "lib/netifd/proto/r91.sh", PROTO, True)
                write(root / "sbin/hotplug-call", "#!/bin/sh\nexit 0\n", True)
                with (destination / "driver.log").open("wb") as log:
                    command = ["timeout", "-k", "3", "30", "unshare", "--mount", "--net",
                               "--pid", "--fork", "--kill-child", sys.executable,
                               str(Path(__file__).resolve()), "--inner", str(root), side, case]
                    result = subprocess.run(command, stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            path = destination / "raw/result.json"
            checks = json.loads(path.read_text()) if path.exists() else {}
            required = BASE_CHECKS if case == "surface" else BASE_CHECKS | LOG_CHECKS
            row = {"side": side, "case": case, "exit": result.returncode, "checks": checks,
                   "passed": result.returncode == 0 and checks.keys() == required
                   and all(value is True for value in checks.values())}
            rows.append(row)
            print(json.dumps(row), flush=True)
    write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
    passed = len(rows) == len(args.sides) * len(args.cases) and all(r["passed"] for r in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
