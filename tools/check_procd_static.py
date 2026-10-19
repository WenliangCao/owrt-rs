#!/usr/bin/env python3
"""Replay procd type-policy/event/timeout cases in disposable Linux namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time


def wait_for(check, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.02)
    raise AssertionError("procd fixture readiness timed out")


def cases(root, call):
    results = {}
    policies = {
        "respawn-string": {"respawn": "bad"},
        "env-array": {"env": ["value"]},
        "limits-array": {"limits": ["0"]},
        "data-array": {"data": ["value"]},
        "netdev-table": {"netdev": {"ignored": "lo"}},
        "file-table": {"file": {"ignored": "/etc/passwd"}},
        "error-table": {"error": {"ignored": "bad"}},
        "netdev-nonstring": {"netdev": ["lo", 7]},
        "file-nonstring": {"file": ["/etc/passwd", 7]},
        "command-control": {"command": ["/bin/sleep", "20"]},
        "invalid-instance-type": "ignored",
    }
    for name, instance in policies.items():
        if isinstance(instance, dict):
            instance = {"command": ["/bin/sleep", "20"], **instance}
        call("set", {"name": name, "autostart": False, "instances": {"main": instance}})
        results[name] = call("list", {"name": name, "verbose": True})
        call("delete", {"name": name})

    # The command only writes inside this disposable chroot. Trigger width is
    # one; wait for each event's observable action before sending the next one.
    call("set", {"name": "observer", "triggers": [["instance.update",
         [["run_script", "/bin/sh", "-c", "echo update >> /tmp/updates"]], 0]]})
    updates = root / "tmp/updates"
    counts = []
    for operation, payload in (
        ("set", {"name": "subject", "autostart": False, "instances": {"one": {}}}),
        ("set", {"name": "subject", "autostart": False, "instances": {"one": {}}}),
        ("set", {"name": "subject", "autostart": False, "instances": {}}),
        ("add", {"name": "subject", "autostart": False, "instances": {"one": {}}}),
        ("add", {"name": "subject", "autostart": False, "instances": {}}),
        ("delete", {"name": "subject", "instance": "one"}),
        ("add", {"name": "subject", "autostart": False, "instances": {"one": {}}}),
        ("update_start", {"name": "subject"}),
        ("update_complete", {"name": "subject"}),
        ("add", {"name": "subject", "autostart": False, "instances": {"one": {}}}),
        ("delete", {"name": "subject"}),
    ):
        call(operation, payload)
        time.sleep(0.5)
        counts.append(len(updates.read_text().splitlines()) if updates.exists() else 0)
    results["instance-update"] = counts

    own_updates = root / "tmp/own-updates"
    call("set", {"name": "own-observer", "autostart": False, "instances": {"one": {}},
         "triggers": [["instance.update", [["run_script", "/bin/sh", "-c",
                       "echo update >> /tmp/own-updates"]], 0]]})
    time.sleep(0.5)
    own_counts = [len(own_updates.read_text().splitlines()) if own_updates.exists() else 0]
    call("delete", {"name": "own-observer"})
    time.sleep(0.5)
    own_counts.append(len(own_updates.read_text().splitlines()) if own_updates.exists() else 0)
    results["own-instance-update"] = own_counts

    call("set", {"name": "negative", "triggers": [["test.negative",
         [["run_script", "/bin/sh", "-c", "echo fired > /tmp/negative"]], -1]]})
    call("event", {"type": "test.negative", "data": {}})
    time.sleep(0.5)
    results["negative-timeout"] = (root / "tmp/negative").exists()
    call("set", {"name": "zero", "triggers": [["test.zero",
         [["run_script", "/bin/sh", "-c", "echo fired > /tmp/zero"]], 0]]})
    call("event", {"type": "test.zero", "data": {}})
    wait_for(lambda: (root / "tmp/zero").exists())
    results["zero-timeout-control"] = True
    return results


def run_side(rootfs, candidate, side, repeat, output):
    with tempfile.TemporaryDirectory(prefix="procd-static-") as temporary:
        root = Path(temporary) / "root"
        subprocess.run(["cp", "-a", str(rootfs), str(root)], check=True)
        (root / "tmp/empty-init").mkdir(parents=True)
        (root / "tmp/run/ubus").mkdir(parents=True, exist_ok=True)
        # The image has an empty /dev; Rust Command's null stdio needs the
        # same device node that devtmpfs supplies at boot.
        (root / "dev").mkdir(exist_ok=True)
        os.mknod(root / "dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
        if side == "rust":
            shutil.copy2(candidate, root / "sbin/procd")
        children = []
        with (output / f"{side}-{repeat}.log").open("w") as log:
            try:
                children.append(subprocess.Popen(["chroot", str(root), "/sbin/ubusd"], stdout=log, stderr=log))
                def invoke(method, data=None, required=True):
                    command = ["chroot", str(root), "/bin/ubus", "call", "service", method]
                    if data is not None:
                        command.append(json.dumps(data, separators=(",", ":")))
                    result = subprocess.run(command, capture_output=True, timeout=5)
                    if required and result.returncode:
                        raise AssertionError((command, result.returncode, result.stderr))
                    if not required:
                        return result.returncode == 0
                    try:
                        return json.loads(result.stdout or b"{}")
                    except json.JSONDecodeError:
                        return {"invalid_json": result.stdout.decode(errors="backslashreplace")}
                wait_for(lambda: (root / "tmp/run/ubus/ubus.sock").exists())
                children.append(subprocess.Popen(["chroot", str(root), "/sbin/procd", "-S",
                                                   "-I", "/tmp/empty-init"], stdout=log, stderr=log))
                wait_for(lambda: invoke("list", required=False))
                result = cases(root, invoke)
                assert all(child.poll() is None for child in children), "fixture daemon exited"
                return result
            finally:
                for child in reversed(children):
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.environ.get("PROCD_STATIC_PRIVATE_NAMESPACE") != "1":
        return subprocess.call(["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                "python3", str(Path(__file__).resolve()), *os.sys.argv[1:]],
                               env={**os.environ, "PROCD_STATIC_PRIVATE_NAMESPACE": "1"})
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    args.output.mkdir(parents=True)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    report = {"artifacts": {"c": sha(args.rootfs / "sbin/procd"), "rust": sha(args.candidate)}, "runs": []}
    for repeat in range(1, 5):
        sides = {side: run_side(args.rootfs, args.candidate, side, repeat, args.output) for side in ("c", "rust")}
        differences = [name for name in sides["c"] if sides["c"][name] != sides["rust"][name]]
        report["runs"].append(dict(repeat=repeat, sides=sides, differences=differences))
        print(json.dumps(dict(repeat=repeat, differences=differences)), flush=True)
    report["passed"] = all(not row["differences"] for row in report["runs"])
    (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
