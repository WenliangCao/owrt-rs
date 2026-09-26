#!/usr/bin/env python3
"""R52's real udhcpc identity, stopped-helper and teardown evidence.

Runs on the Linux test host inside each side's PID namespace, never in the
image. A stopped helper is deliberately left for namespace teardown.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def proc_stat(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    return {"state": fields[0], "starttime": int(fields[19])}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def children(pid):
    return Path(f"/proc/{pid}/task/{pid}/children").read_text().split()


def capture(root):
    pid = int((root / "var/run/udhcpc-veth1.pid").read_text())
    require(pid > 1, "invalid helper PID")
    proc = Path(f"/proc/{pid}")
    before = proc_stat(pid)
    require(before["state"] not in ("Z", "X"), "helper has exited")
    require(os.path.samefile(proc / "root", root), "helper has wrong root")
    for namespace in ("pid", "net", "mnt"):
        require(os.path.samefile(proc / "ns" / namespace, f"/proc/self/ns/{namespace}"),
                f"helper has wrong {namespace} namespace")
    argv = (proc / "cmdline").read_bytes()
    args = argv.rstrip(b"\0").split(b"\0")
    require(args[0] == b"udhcpc" and b"-f" in args, "not foreground udhcpc")
    for flag, value in ((b"-p", b"/var/run/udhcpc-veth1.pid"),
                        (b"-s", b"/lib/netifd/dhcp.script"), (b"-i", b"veth1")):
        require(any(args[i:i + 2] == [flag, value] for i in range(len(args) - 1)),
                "wrong udhcpc argument: " + flag.decode())
    exe = sha(proc / "exe")
    require(exe == sha(root / "bin/busybox"), "helper is not the image BusyBox")
    result = {"pid": pid, "starttime": before["starttime"],
              "exe_sha256": exe, "argv_hex": argv.hex(), "argv": [a.decode() for a in args]}
    require(proc_stat(pid)["starttime"] == before["starttime"]
            and (proc / "cmdline").read_bytes() == argv, "helper changed during capture")
    return result


def save(path, data):
    with path.open("x") as output:
        json.dump(data, output, indent=2)
        output.write("\n")


def main():
    action, root_text, evidence_text = sys.argv[1:]
    root, evidence = Path(root_text), Path(evidence_text)
    require(os.environ.get("OWRT_BENCH_NAMESPACE") == "1", "owned namespace required")
    if action == "capture":
        save(evidence, capture(root))
    elif action == "wait-exit":
        original = json.loads(evidence.read_text())
        deadline = time.monotonic() + 10
        while True:
            try:
                current = proc_stat(original["pid"])
            except FileNotFoundError:
                result = "exited"
                break
            if current["starttime"] != original["starttime"]:
                result = "pid-reused"
                break
            require(time.monotonic() < deadline, "original udhcpc survived teardown for 10s")
            time.sleep(0.05)
        save(Path(str(evidence) + ".exit.json"), {**original, "result": result})
        print("udhcpc stopped by the teardown")
    elif action == "stop":
        original = capture(root)
        pid = original["pid"]
        # A pre-existing dhcp.script child could otherwise notify after STOP.
        require(not children(pid), "helper has an active child before STOP")
        fd = os.pidfd_open(pid)
        try:
            require(capture(root) == original, "helper changed before STOP")
            signal.pidfd_send_signal(fd, signal.SIGSTOP)
            deadline = time.monotonic() + 2
            while proc_stat(pid)["state"] != "T":
                require(time.monotonic() < deadline, "helper did not stop")
                time.sleep(0.01)
            require(capture(root) == original, "helper identity changed after STOP")
            require(not children(pid), "helper spawned a child while stopping")
            save(evidence, {**original, "state": "T", "children": []})
        finally:
            os.close(fd)
    elif action == "verify-stopped":
        original = json.loads(evidence.read_text())
        current = capture(root)
        require(current == {key: original[key] for key in current},
                "stopped helper identity changed during notifications")
        require(proc_stat(current["pid"])["state"] == "T" and not children(current["pid"]),
                "helper did not stay stopped and quiescent")
        save(Path(str(evidence) + ".verified.json"), original)
    else:
        raise RuntimeError("unknown action: " + action)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, IndexError) as error:
        print("R52 process evidence FAILED: " + str(error), file=sys.stderr)
        sys.exit(1)
