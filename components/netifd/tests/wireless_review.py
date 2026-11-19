#!/usr/bin/env python3
"""Exact-image C/Rust wireless boundary checks; disposable Linux namespaces only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time

CHECKS = ("indices", "data", "ifname")
CASES = ("boundary", "nonfinite", "queue_remove")
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
 list network 'lan'
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
printf '%s\t%s\t%s\n' "$3" "$2" "$4" >> /tmp/out/events
if [ "$2" = setup ]; then
 echo $$ > /tmp/out/pid-$3
 while [ ! -f /tmp/out/setup-release ]; do sleep 0.05; done
 if [ -f /tmp/out/queue-mode ]; then
  ubus call network.wireless notify "{\"device\":\"$3\",\"command\":0}"
 fi
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


def inner(root, side, case):
    run("mount", "--make-rprivate", "/")
    run("mount", "-t", "proc", "proc", "/proc")
    run("mount", "-t", "proc", "proc", root / "proc")
    run("mount", "-t", "sysfs", "sysfs", root / "sys")
    run("mount", "-t", "tmpfs", "tmpfs", root / "dev")
    for name, minor in (("null", 3), ("zero", 5), ("urandom", 9)):
        run("mknod", "-m", "666", root / "dev" / name, "c", "1", minor)
    run("ip", "link", "set", "lo", "up")
    for name in ("vlan-01", "vlan-02"):
        run("ip", "link", "add", name, "type", "dummy")
        run("ip", "link", "set", name, "up")
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
    wait_for(lambda: call("status").get("radio0", {}).get("pending"))
    assert Path(f"/proc/{daemon.pid}/exe").resolve() == root / binary.lstrip("/")
    if case == "queue_remove":
        held = call("status")
        assert all(held[name]["pending"] for name in ("radio0", "radio1", "radio2"))
        assert not (out / "pid-radio1").exists()
        path = root / "etc/config/wireless"
        path.write_text(path.read_text().replace("config wifi-device 'radio1'\n option type 'mac80211'\n", ""))
        run("chroot", root, "ubus", "-S", "call", "network", "reload", "{}", capture_output=True)
        save("held.json", call("status"))
        (out / "setup-release").touch()
        until = time.monotonic() + 5
        while time.monotonic() < until:
            final = call("status")
            if final.get("radio2", {}).get("up"):
                break
            time.sleep(0.05)
        save("status.json", final)
        events = [line.split("\t", 2) for line in (out / "events").read_text().splitlines()]
        results = {
            "old_setup_then_successor": [(e[0], e[1]) for e in events] ==
                [(name, "setup") for name in ("radio0", "radio1", "radio2")],
            "removed_generation_visible": final.get("radio1", {}).get("up") is True
                and final["radio1"]["autostart"] is False,
            "successor_up": final.get("radio2", {}).get("up") is True,
            "same_daemon": daemon.poll() is None,
        }
        if final.get("radio1", {}).get("up"):
            call("up", {"device": "radio1"})
            results["destroyed_radio_not_restarted"] = call("status")["radio1"]["autostart"] is False
            call("down", {"device": "radio1"})
            wait_for(lambda: "radio1" not in call("status"))
            results["destroyed_radio_released"] = True
        save("result.json", results)
        return
    if case == "nonfinite":
        sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
        from r92_recovery_probe import Bus, message
        bus = Bus(root / "tmp/run/ubus/ubus.sock")
        obj = bus.lookup("network.wireless")
        doubles = b"".join(message(key, 8, struct.pack(">d", value)) for key, value in
                           (("nan", float("nan")), ("pos_inf", float("inf")),
                            ("neg_inf", float("-inf"))))
        data = message("token", 3, b"fixture\0") + doubles + message("nested", 2, message("values", 1, doubles))
        request = message("device", 3, b"radio0\0") + message("command", 5, struct.pack(">I", 1)) + message("data", 2, data)
        code, _ = bus.invoke(obj, "notify", request)
        bus.sock.close()
        call("notify", {"device": "radio0", "command": 0})
        (out / "setup-release").touch()
        pid = int((out / "pid-radio0").read_text())
        wait_for(lambda: not Path(f"/proc/{pid}").exists())
        try:
            call("down", {"device": "radio0"})
        except subprocess.CalledProcessError:
            pass  # Preserve the base daemon's abort as a failed observation.
        until = time.monotonic() + 3
        while not (out / "teardown.json").exists() and daemon.poll() is None and time.monotonic() < until:
            time.sleep(0.05)
        text = (out / "teardown.json").read_text() if (out / "teardown.json").exists() else '{"data":{}}'
        received = json.loads(text)["data"]
        tokens = json.loads(text, parse_float=str)["data"]
        save("result.json", {
            "notify_accepted": code == 0,
            "same_daemon": daemon.poll() is None,
            "ucode_values": received.get("nan") == "NaN" and received.get("pos_inf") == float("inf")
                and received.get("neg_inf") == float("-inf")
                and received.get("nested", {}).get("values") == ["NaN", float("inf"), float("-inf")],
            "finite_value_preserved": received.get("token") == "fixture",
            "ucode_number_tokens": tokens.get("pos_inf") == "1e309" and tokens.get("neg_inf") == "-1e309"
                and tokens.get("nested", {}).get("values") == ["NaN", "1e309", "-1e309"],
        })
        (out / "daemon-exit.txt").write_text(str(daemon.poll()))
        return
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
    call("notify", {"device": "radio0", "command": 0})
    (out / "setup-release").touch()
    wait_for(lambda: call("status").get("radio0", {}).get("up"))
    time.sleep(2)
    status = call("status")
    save("status.json", status)
    rows = status["radio0"]["interfaces"]
    results["ifname"] = all(row.get("ifname") == "ap-" + key
                            and row["vlans"][0].get("ifname") == "vlan-" + key
                            for row, key in zip(rows, ("01", "02")))
    links = json.loads(run("ip", "-j", "link", "show", capture_output=True).stdout)
    save("links.json", links)
    results["ifname"] &= all(next(link for link in links if link["ifname"] == name).get("master") == "br-test"
                             for name in ("vlan-01", "vlan-02"))
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
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--checks", nargs="+", choices=CHECKS, default=CHECKS)
    parser.add_argument("--cases", nargs="+", choices=CASES, default=["boundary"])
    parser.add_argument("--sides", nargs="+", choices=("original", "candidate"), default=["original", "candidate"])
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    identities = {str(path.relative_to(args.rootfs)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in [args.rootfs / "sbin/netifd", *(args.rootfs / "lib/netifd" / name
                               for name in ("wireless.uc", "wireless-device.uc", "utils.uc"))]}
    for case, side in ((case, side) for case in args.cases for side in args.sides):
        out = args.output / case / side
        out.mkdir(parents=True)
        with tempfile.TemporaryDirectory(prefix="netifd-wireless-review-") as directory:
            root = Path(directory) / "root"
            shutil.copytree(args.rootfs, root, symlinks=True)
            for part in ("out", "run/ubus", "lock", "state", "resolv.conf.d"):
                (root / "tmp" / part).mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.candidate, root / "tmp/netifd-rs")
            (root / "etc/config/network").write_text("config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1/8'\nconfig device\n option name 'br-test'\n option type 'bridge'\n option bridge_empty '1'\nconfig interface 'lan'\n option device 'br-test'\n option proto 'static'\n option ipaddr '192.168.99.1/24'\n")
            radios = "".join(f"config wifi-device 'radio{index}'\n option type 'mac80211'\n" for index in range(3))
            (root / "etc/config/wireless").write_text(radios if case == "queue_remove" else WIRELESS)
            if case == "queue_remove":
                (root / "tmp/out/queue-mode").touch()
            # Oracle has no nl80211. Only replace unused physical-radio lookup;
            # the image's wireless state machine and ucode JSON stay intact.
            adapter = root / "usr/share/ucode/wifi/utils.uc"
            adapter.parent.mkdir(parents=True, exist_ok=True)
            adapter.write_text("export function find_phy(name, mlo) { return null; };\n")
            handler = root / "lib/netifd/wireless/mac80211.sh"
            handler.write_text(HANDLER)
            handler.chmod(0o755)
            with (out / "driver.log").open("wb") as log:
                proc = subprocess.run(["timeout", "-k", "3", "45", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child",
                                       sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side, case], stdout=log, stderr=log)
            shutil.copytree(root / "tmp/out", out / "raw")
        result = out / "raw/result.json"
        checks = json.loads(result.read_text()) if result.exists() else {}
        required = {"boundary": set(args.checks), "nonfinite": {"notify_accepted", "same_daemon", "ucode_values", "finite_value_preserved", "ucode_number_tokens"},
                    "queue_remove": {"old_setup_then_successor", "removed_generation_visible", "successor_up", "same_daemon", "destroyed_radio_not_restarted", "destroyed_radio_released"}}[case]
        row = {"case": case, "side": side, "exit": proc.returncode, "checks": checks,
               "passed": proc.returncode == 0 and required <= checks.keys() and all(checks[key] is True for key in required)}
        rows.append(row)
        print(json.dumps(row), flush=True)
    report = {"candidate_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(), "image_files": identities, "rows": rows}
    (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    raise SystemExit(0 if all(row["passed"] for row in rows) else 1)


if __name__ == "__main__":
    main()
