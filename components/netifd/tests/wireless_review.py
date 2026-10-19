#!/usr/bin/env python3
"""Exact-image C/Rust wireless boundary checks; disposable Linux namespaces only."""
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

CHECKS = ("indices", "data", "ifname")
WIRELESS = """config wifi-device 'radio0'
 option type 'mac80211'
config wifi-iface 'ap0'
 option device 'radio0'
 option mode 'ap'
 option ssid 'first'
config wifi-iface 'ap1'
 option device 'radio0'
 option mode 'ap'
 option ssid 'second'
config wifi-vlan 'shared'
 option vid '10'
config wifi-station 'sta0'
 option iface 'ap0'
 option mac '02:00:00:00:00:01'
config wifi-station 'sta1'
 option iface 'ap1'
 option mac '02:00:00:00:00:02'
"""
HANDLER = r'''#!/bin/sh
if [ "${1:-}" = dump ] || [ "${2:-}" = dump ]; then
 echo '{"name":"mac80211","device":[],"iface":[["ssid",3]],"vlan":[["vid",3]],"station":[["mac",3]]}'
 exit 0
fi
printf '%s\n' "$4" > "/tmp/out/$2.json"
if [ "$2" = setup ]; then
 ubus call network.wireless notify '{"device":"radio0","command":0}'
fi
'''


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def wait_for(fn):
    until = time.monotonic() + 10
    while not fn():
        if time.monotonic() >= until:
            raise AssertionError("fixture precondition timed out")
        time.sleep(0.05)


def inner(root, side):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("ip", "link", "set", "lo", "up")
    out = root / "tmp/out"

    def start(binary):
        with (out / (Path(binary).name + ".log")).open("wb") as log:
            return subprocess.Popen(["chroot", str(root), binary], stdout=log, stderr=log)

    def call(method, data=None):
        result = run("chroot", root, "ubus", "-S", "-t", "3", "call", "network.wireless",
                     method, json.dumps(data or {}), capture_output=True, timeout=5)
        return json.loads(result.stdout or "{}")

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    start("/sbin/ubusd")
    wait_for(lambda: (root / "tmp/run/ubus/ubus.sock").exists())
    binary = "/sbin/netifd" if side == "original" else "/tmp/netifd-rs"
    daemon = start(binary)
    wait_for(lambda: (out / "setup.json").exists())
    wait_for(lambda: call("status").get("radio0", {}).get("up"))
    assert Path(f"/proc/{daemon.pid}/exe").resolve() == root / binary.lstrip("/")
    setup = json.loads((out / "setup.json").read_text())
    interfaces = setup["interfaces"]
    assert len(interfaces) == 2
    indices = {key: {kind: list(value[kind]) for kind in ("vlans", "stas")}
               for key, value in interfaces.items()}
    save("indices.json", indices)
    results = {"indices": indices == {key: {"vlans": ["01"], "stas": ["01"]}
                                     for key in ("01", "02")}}
    for key, value in interfaces.items():
        call("notify", {"device": "radio0", "command": 1, "interface": key,
                        "data": {"ifname": "ap-" + key}})
        assert len(value["vlans"]) == 1
        call("notify", {"device": "radio0", "command": 1, "interface": key,
                        "vlan": next(iter(value["vlans"])), "data": {"ifname": "vlan-" + key}})
    status = call("status")
    save("status.json", status)
    rows = status["radio0"]["interfaces"]
    results["ifname"] = all(row.get("ifname") == "ap-" + key
                            and row["vlans"][0].get("ifname") == "vlan-" + key
                            for row, key in zip(rows, ("01", "02")))
    data = {"token": "T1", "counter": 7, "ready": True, "nested": {"a": [1, False, "x"]}}
    call("notify", {"device": "radio0", "command": 1, "data": data})
    call("down", {"device": "radio0"})
    wait_for(lambda: (out / "teardown.json").exists())
    received = json.loads((out / "teardown.json").read_text())["data"]
    results["data"] = all(received.get(key) == value for key, value in data.items())
    assert daemon.poll() is None
    call("status")
    save("result.json", results)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        inner(Path(sys.argv[2]), sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--checks", nargs="+", choices=CHECKS, default=CHECKS)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for side in ("original", "candidate"):
        out = args.output / side
        out.mkdir()
        with tempfile.TemporaryDirectory(prefix="netifd-wireless-review-") as directory:
            root = Path(directory) / "root"
            shutil.copytree(args.rootfs, root, symlinks=True)
            for part in ("out", "run/ubus", "lock", "state", "resolv.conf.d"):
                (root / "tmp" / part).mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.candidate, root / "tmp/netifd-rs")
            (root / "etc/config/network").write_text("config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1/8'\n")
            (root / "etc/config/wireless").write_text(WIRELESS)
            handler = root / "lib/netifd/wireless/mac80211.sh"
            handler.write_text(HANDLER)
            handler.chmod(0o755)
            with (out / "driver.log").open("wb") as log:
                proc = subprocess.run(["timeout", "-k", "3", "45", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                       sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side], stdout=log, stderr=log)
            shutil.copytree(root / "tmp/out", out / "raw")
        result = out / "raw/result.json"
        checks = json.loads(result.read_text()) if result.exists() else {}
        row = {"side": side, "exit": proc.returncode, "checks": checks,
               "passed": proc.returncode == 0 and all(checks.get(key) is True for key in args.checks)}
        rows.append(row)
        print(json.dumps(row), flush=True)
    report = {"candidate_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(), "rows": rows}
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    raise SystemExit(0 if all(row["passed"] for row in rows) else 1)


if __name__ == "__main__":
    main()
