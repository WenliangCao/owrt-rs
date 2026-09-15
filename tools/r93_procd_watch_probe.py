#!/usr/bin/env python3
"""Normal watch business flow against exact C ubusd in a private Linux namespace."""
import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import threading

from r92_recovery_probe import attr, digest, message, write
from r92_compat_probe import Fixture


def blob(name, value):
    if isinstance(value, str): return message(name, 3, value.encode() + b"\0")
    if isinstance(value, list): return message(name, 1, b"".join(blob("", item) for item in value))
    if isinstance(value, dict): return message(name, 2, b"".join(blob(k, v) for k, v in value.items()))
    raise TypeError(type(value))


def inner(root):
    f = Fixture(root, "candidate", "procd")
    checks, observed = {}, {}
    try:
        f.start_bus()
        f.start_subject("-I", "/tmp/initd", "-R", "/tmp/rcd", obj="service")
        paths = ["r93.watch." + str(n) for n in range(6)]
        trigger = [["r93.changed", [["run_script", "/bin/sh", "-c", "echo received >> /tmp/out/triggered"]]]]
        f.call("service", "set", {"name": "r93watch", "triggers": trigger,
               "instances": {"main": {"command": ["/bin/sleep", "60"], "watch": paths}}})
        provider = f.connect()
        ids = [provider.add(path) for path in paths]

        def subscribed(obj):
            # NOTIFY's immediate STATUS exposes the actual subscriber set.
            # Do not assume set-return or elapsed sleep implies attachment.
            seq = provider.send(10, attr(3, struct.pack(">I", obj)) + attr(4, b"r93.changed\0")
                                + attr(7, message("source", 3, b"probe\0")))
            while True:
                kind, got, _, data = provider.recv()
                if kind == 1 and got == seq:
                    fields = dict(data)
                    assert struct.unpack(">I", fields[1])[0] == 0
                    return bool(fields.get(11))

        started = time.monotonic()
        checks["all_six_subscribed"] = all(f.wait(lambda obj=obj: subscribed(obj)) for obj in ids)
        checks["trigger_executes"] = f.wait(lambda: (f.output / "triggered").exists())
        observed["all_subscribed_seconds"] = time.monotonic() - started
        # Delete/recreate one object while the watched service remains alive.
        assert provider.request(7, attr(3, struct.pack(">I", ids[-1])))[0] == 0
        replacement = provider.add(paths[-1])
        checks["recreated_id_is_new"] = replacement != ids[-1]
        checks["recreated_subscribed"] = f.wait(lambda: subscribed(replacement))
        # R89's stronger return boundary: these objects predate service.set.
        # No process spawn between receiving STATUS and the single notify.
        service = provider.lookup("service")
        trials = []
        for trial in range(12):
            existing = [f"r93.existing.{trial}.{n}" for n in range(6)]
            objects = [provider.add(path) for path in existing]
            assert provider.invoke(service, "list")[0] == 0
            time.sleep(0.02)
            marker = f"/tmp/out/immediate-{trial}"
            kind = f"r93.immediate.{trial}"
            config = {"name": f"immediate{trial}", "triggers": [[kind, [["run_script", "/bin/sh", "-c", f"echo received >> {marker}"]]]],
                      "instances": {"main": {"command": ["/bin/sleep", "60"], "watch": existing}}}
            data = b"".join(blob(key, value) for key, value in config.items())
            method = "set" if trial % 2 == 0 else "add"
            assert provider.invoke(service, method, data)[0] == 0
            returned = time.monotonic()
            seq = provider.send(10, attr(3, struct.pack(">I", objects[-1])) + attr(4, kind.encode() + b"\0") + attr(7, b""))
            sent = time.monotonic()
            while True:
                message_kind, got, _, fields = provider.recv()
                if message_kind == 1 and got == seq:
                    fields = dict(fields)
                    assert struct.unpack(">I", fields[1])[0] == 0
                    attached = bool(fields.get(11))
                    break
            delivered = f.wait(lambda: (root / marker[1:]).exists(), timeout=0.5)
            trials.append({"method": method, "subscribed": attached, "delivered": delivered,
                           "return_to_notify_us": (sent-returned)*1000000})
            assert provider.invoke(service, "delete", blob("name", f"immediate{trial}"))[0] == 0
            for obj in objects:
                assert provider.request(7, attr(3, struct.pack(">I", obj)))[0] == 0
        checks["immediate_set_add_subscribed"] = all(row["subscribed"] for row in trials)
        checks["immediate_set_add_delivered"] = all(row["delivered"] for row in trials)
        observed["immediate_trials"] = trials
        # Completion events must follow subscriptions too: subscribers may
        # react to service.start before the caller receives set STATUS.
        observer = provider.add("r93.service.observer")
        assert provider.request(8, attr(3, struct.pack(">I", observer)) + attr(8, struct.pack(">I", service)))[0] == 0
        caller = f.connect()
        starts = []
        for trial in range(12):
            existing = [f"r93.start.{trial}.{n}" for n in range(6)]
            objects = [provider.add(path) for path in existing]
            assert caller.invoke(service, "list")[0] == 0
            time.sleep(0.02)
            marker = f"/tmp/out/start-{trial}"
            kind = f"r93.start.event.{trial}"
            config = {"name": f"startwatch{trial}", "triggers": [[kind, [["run_script", "/bin/sh", "-c", f"echo received >> {marker}"]]]],
                      "instances": {"main": {"command": ["/bin/sleep", "60"], "watch": existing}}}
            data = b"".join(blob(k, v) for k, v in config.items())
            replies = []
            def set_service():
                replies.append(caller.invoke(service, "set", data)[0])
            worker = threading.Thread(target=set_service)
            worker.start()
            while True:
                message_kind, _, _, fields = provider.recv()
                if message_kind == 5 and dict(fields).get(4) == b"service.start\0":
                    break
            seq = provider.send(10, attr(3, struct.pack(">I", objects[-1])) + attr(4, kind.encode() + b"\0") + attr(7, b""))
            while True:
                message_kind, got, _, fields = provider.recv()
                if message_kind == 1 and got == seq:
                    fields = dict(fields)
                    assert struct.unpack(">I", fields[1])[0] == 0
                    attached = bool(fields.get(11))
                    break
            worker.join(timeout=3)
            assert replies == [0]
            delivered = f.wait(lambda: (root / marker[1:]).exists(), timeout=0.5)
            starts.append({"subscribed": attached, "delivered": delivered})
            assert caller.invoke(service, "delete", blob("name", f"startwatch{trial}"))[0] == 0
            for obj in objects:
                assert provider.request(7, attr(3, struct.pack(">I", obj)))[0] == 0
        checks["service_start_subscribed"] = all(row["subscribed"] for row in starts)
        checks["service_start_delivered"] = all(row["delivered"] for row in starts)
        observed["service_start_trials"] = starts
        missing = {"name": "missing", "instances": {"main": {"command": ["/bin/sleep", "60"],
                   "watch": [f"r93.absent.{n}" for n in range(6)]}}}
        started = time.monotonic()
        code = provider.invoke(service, "set", b"".join(blob(k, v) for k, v in missing.items()))[0]
        observed["missing_set_seconds"] = time.monotonic() - started
        checks["missing_paths_do_not_wait_for_creation"] = code == 0 and observed["missing_set_seconds"] < 1
        checks["same_supervisor"] = f.subject.poll() is None
        checks["identity"] = digest(Path(f"/proc/{f.subject.pid}/exe")) == digest(root / "tmp/procd-rs")
    finally:
        write(f.output / "result.json", json.dumps({"checks": checks, "observations": observed}, indent=2) + "\n")
        f.close()
    assert len(checks) == 11 and all(checks.values()), checks


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("procd", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root on the Linux build host")
    if Path("/etc/openwrt_release").exists():
        parser.error("this probe must not run on a physical router")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="r93-procd-watch-") as temporary:
        root = Path(temporary) / "root"
        shutil.copytree(args.rootfs, root, symlinks=True)
        for directory in ("out", "run/ubus", "lock", "state", "initd", "rcd"):
            (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.procd, root / "tmp/procd-rs")
        with (args.output / "driver.log").open("wb") as log:
            result = subprocess.run(["timeout", "-k", "3", "40", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root)], stdout=log, stderr=log)
        shutil.copytree(root / "tmp/out", args.output / "raw")
    data_path = args.output / "raw/result.json"
    data = json.loads(data_path.read_text()) if data_path.exists() else {"checks": {}, "observations": {}}
    summary = {"procd_sha256": digest(args.procd), "probe_sha256": digest(Path(__file__)), "exit": result.returncode, **data}
    summary["passed"] = result.returncode == 0 and len(data["checks"]) == 11 and all(data["checks"].values())
    write(args.output / "results.json", json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
