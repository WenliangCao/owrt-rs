#!/usr/bin/env python3
"""Protocol exec-failure differential in disposable Linux mount/net/PID namespaces.

Compare the exact image's netifd with a candidate. Each case starts from
the same image and requires a live daemon and a reached precondition. Raw
observations stay in OUTPUT; a missing case or failed fixture is a failure.
Usage: sudo python3 components/netifd/tests/proto_spawn_failure.py ROOTFS BINS OUTPUT
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

CASES = ("healthy_spawn", "fail_spawn")
ORIGINAL_CHECKS = {}
CHECKS = {case: {"recovered", "same_daemon"} for case in CASES}

PROTO = r'''#!/bin/sh
. /lib/functions.sh
. ../netifd-proto.sh
init_proto "$@"
proto_probe_init_config() {
    renew_handler=1
    proto_config_add_string token
}
proto_probe_setup() {
    local cfg="$1" iface="$2" token
    json_get_var token token
    echo "setup:$token" >> /tmp/out/actions
    proto_run_command "$cfg" /bin/sh /tmp/helper.sh
    proto_init_update "$iface" 1
    proto_add_ipv4_address 10.90.0.1 24
    proto_add_data
    json_add_int lease 1
    json_add_string retained yes
    proto_close_data
    proto_send_update "$cfg"
}
proto_probe_teardown() {
    local cfg="$1" token
    json_get_var token token
    echo "teardown:$token" >> /tmp/out/actions
    proto_kill_command "$cfg"
}
proto_probe_renew() { echo renew >> /tmp/out/actions; }
add_protocol probe
'''

HELPER = r'''#!/bin/sh
trap 'kill "$sleeper"; wait "$sleeper"; echo term >> /tmp/out/helper-signals; exit 0' TERM
echo $$ > /tmp/out/helper-pid
sleep 600 &
sleeper=$!
wait "$sleeper"
'''

HOTPLUG = r'''#!/bin/sh
printf '%s:%s:%s\n' "$INTERFACE" "$ACTION" "$IFUPDATE_DATA" >> /tmp/out/hotplug
'''


def run(*cmd, **kwargs):
    return subprocess.run([str(c) for c in cmd], check=True, **kwargs)


def wait_for(fn, seconds=10):
    until = time.monotonic() + seconds
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() >= until:
            raise AssertionError("precondition or completion timed out")
        time.sleep(0.05)


def write(path, text, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


def config(token="old"):
    return ("config interface 'wan'\n option device 'veth1'\n"
            f" option proto 'probe'\n option token '{token}'\n")


def inner(root, side, case):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("mount", "--bind", root / "dev/null", root / "proc/kmsg")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
    run("ip", "link", "set", "veth0", "up")

    output = root / "tmp/out"
    processes = []

    def start(binary, *args):
        log = (output / (Path(binary).name + ".log")).open("wb")
        p = subprocess.Popen(["chroot", str(root), binary, *args], stdout=log, stderr=log)
        log.close()
        processes.append(p)
        return p

    def call(obj, method, data=None):
        p = run("chroot", root, "ubus", "-S", "-t", "3", "call", obj, method,
                json.dumps(data or {}), capture_output=True, timeout=5)
        return json.loads(p.stdout or "{}")

    def ready(obj):
        return subprocess.run(["chroot", str(root), "ubus", "-S", "list", obj],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=5).stdout.strip() == obj.encode()

    def snapshot(label):
        value = call("network.interface.wan", "status")
        write(output / (label + ".json"), json.dumps(value, indent=2) + "\n")
        return value

    start("/sbin/ubusd")
    wait_for(lambda: (root / "tmp/run/ubus/ubus.sock").exists())
    binary = "/sbin/netifd" if side == "original" else "/tmp/netifd-rs"
    daemon = start(binary)
    wait_for(lambda: ready("network.interface.wan"))
    assert daemon.poll() is None
    assert Path(f"/proc/{daemon.pid}/exe").resolve() == root / binary.lstrip("/")
    result = {}
    script = root / "lib/netifd/proto/probe.sh"
    saved = script.read_text()
    if case == "fail_spawn":
        script.unlink()
    call("network.interface.wan", "up")
    time.sleep(0.5)
    snapshot("before-repair")
    if case == "fail_spawn":
        write(script, saved, True)
    time.sleep(3)
    result["recovered"] = snapshot("after-repair").get("up") is True
    result["same_daemon"] = daemon.poll() is None
    assert daemon.poll() is None, "daemon died"
    call("network", "get_proto_handlers")
    write(output / "result.json", json.dumps(result, indent=2) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("bins", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--cases", nargs="+", choices=CASES, default=CASES)
    p.add_argument("--sides", nargs="+", choices=("original", "candidate"), default=("original", "candidate"))
    args = p.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        p.error("run as root on the Linux build host")
    args.output.mkdir(parents=True, exist_ok=False)
    components = ["netifd"]
    identities = {name: hashlib.sha256((args.bins / (name + "-rs")).read_bytes()).hexdigest()
                  for name in components}
    write(args.output / "binaries.json", json.dumps(identities, indent=2) + "\n")
    rows = []
    for side in args.sides:
        for case in args.cases:
            destination = args.output / f"{side}-{case}"
            destination.mkdir()
            with tempfile.TemporaryDirectory(prefix="netifd-exec-recovery-") as temp:
                root = Path(temp) / "root"
                shutil.copytree(args.rootfs, root, symlinks=True)
                for directory in ("out", "run/ubus", "lock", "state", "resolv.conf.d"):
                    (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
                for component in components:
                    shutil.copy2(args.bins / (component + "-rs"), root / "tmp" / (component + "-rs"))
                write(root / "etc/config/network", config() + " option auto '0'\n")
                write(root / "etc/config/wireless", "")
                write(root / "lib/netifd/proto/probe.sh", PROTO, True)
                write(root / "tmp/helper.sh", HELPER, True)
                write(root / "sbin/hotplug-call", HOTPLUG, True)
                with (destination / "driver.log").open("wb") as log:
                    command = ["unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                               sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case]
                    result = subprocess.run(["timeout", "-k", "3", "60", *command], stdout=log, stderr=log)
                shutil.copytree(root / "tmp/out", destination / "raw")
            observations = destination / "raw/result.json"
            values = json.loads(observations.read_text()) if observations.exists() else {}
            expected = ORIGINAL_CHECKS.get(case, {}) if side == "original" else {}
            row = {"side": side, "case": case, "exit": result.returncode, "checks": values,
                   "expected_original_difference": expected,
                   "passed": result.returncode == 0 and values.keys() == CHECKS[case]
                   and all(v is expected.get(k, True) for k, v in values.items())}
            rows.append(row)
            print(json.dumps(row), flush=True)
    write(args.output / "results.json", json.dumps(rows, indent=2) + "\n")
    passed = len(rows) == len(args.cases) * len(args.sides) and all(r["passed"] for r in rows)
    (args.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
