#!/usr/bin/env python3
"""Linux-only causal probe: exact C dependencies, one netifd, delayed WAN.

The upstream peer lives in a separate netns, so netifd cannot bring it up by
claiming a same-netns veth parent. No physical interfaces or router are used.
Without --gate outputs are observations, not a success claim. --gate requires
real IPv4 leases/routes and checks delayed carrier, shared ownership, explicit
down/up, auto=0, link loss/recovery and configuration removal/re-addition.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


def command(*args, check=True, timeout=10):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def inside(root, out, kind, delay, gate):
    assert os.environ.get("OWRT_BENCH_NAMESPACE") == "1"
    assert {name for _, name in socket.if_nameindex()} == {"lo"}
    command("mount", "-t", "sysfs", "sysfs", "/sys")
    command("mount", "--bind", "/proc", str(root / "proc"))
    command("mount", "--bind", "/sys", str(root / "sys"))
    command("mount", "-t", "tmpfs", "tmpfs", str(root / "dev"))
    for name, major, minor in [("null", 1, 3), ("zero", 1, 5), ("urandom", 1, 9)]:
        command("mknod", "-m", "666", str(root / "dev" / name), "c", str(major), str(minor))
    command("ip", "link", "set", "lo", "up")
    server = subprocess.Popen(["unshare", "--net", "sleep", "180"])
    for _ in range(100):
        if os.readlink(f"/proc/{server.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
            break
        time.sleep(0.02)
    else:
        raise RuntimeError("upstream netns did not start")
    upstream = ["nsenter", "-t", str(server.pid), "-n"]
    command("ip", "link", "add", "wan", "index", "100", "address", "02:00:00:00:00:01",
            "type", "veth", "peer", "name", "upstream", "index", "200")
    command("ip", "link", "set", "upstream", "netns", str(server.pid))
    command(*upstream, "ip", "address", "add", "198.18.0.1/24", "dev", "upstream")
    assert not any(index == 200 for index, _ in socket.if_nameindex())
    conf = out / "udhcpd.conf"
    conf.write_text(f"""start 198.18.0.100
end 198.18.0.100
interface upstream
max_leases 1
option subnet 255.255.255.0
option router 198.18.0.1
option dns 198.18.0.1
option lease 3600
lease_file {out / 'leases'}
pidfile {out / 'udhcpd.pid'}
""")
    (out / "leases").touch()
    logs = []

    def start(args, name):
        log = (out / name).open("w")
        logs.append(log)
        return subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)

    def enable_upstream():
        command(*upstream, "ip", "link", "set", "upstream", "up")
        return start(upstream + ["busybox", "udhcpd", "-f", str(conf)], "udhcpd.log")

    if delay in ("early", "disabled"):
        enable_upstream()
    command("chroot", str(root), "/bin/sh", "-c",
            "mkdir -p /var/run/ubus /var/lock /var/state /tmp/resolv.conf.d")
    bus = start(["chroot", str(root), "/sbin/ubusd"], "ubusd.log")
    for _ in range(50):
        r = command("chroot", str(root), "/bin/ubus", "-t", "1", "list", check=False)
        if r.returncode == 0:
            break
        assert bus.poll() is None
        time.sleep(0.1)
    else:
        raise RuntimeError("reference bus did not start")
    logd = start(["chroot", str(root), "/sbin/logd", "-S", "128"], "logd.log")
    binary = "/sbin/netifd" if kind == "c" else "/sbin/netifd-candidate"
    started = time.monotonic()
    daemon = start(["chroot", str(root), binary], "netifd-stdio.log")

    def snapshot(label):
        status = command("chroot", str(root), "/bin/ubus", "-S", "-t", "2", "call",
                         "network.interface.wan", "status", check=False)
        status6 = command("chroot", str(root), "/bin/ubus", "-S", "-t", "2", "call",
                          "network.interface.wan6", "status", check=False)
        link = json.loads(command("ip", "-j", "link", "show", "wan").stdout)[0]
        addresses = json.loads(command("ip", "-j", "-4", "addr", "show", "wan").stdout)
        routes = json.loads(command("ip", "-j", "-4", "route", "show").stdout)
        helpers = []
        for p in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                cmdline = p.read_bytes().split(b"\0")
            except (OSError, ProcessLookupError):
                continue
            if cmdline and Path(os.fsdecode(cmdline[0])).name in ["udhcpc", "odhcp6c"]:
                helpers.append([os.fsdecode(a) for a in cmdline if a])
        result = {"label": label, "elapsed_s": time.monotonic() - started,
                  "wan_status": json.loads(status.stdout) if status.returncode == 0 else None,
                  "wan6_status": json.loads(status6.stdout) if status6.returncode == 0 else None,
                  "status_returncode": status.returncode, "kernel_link": link,
                  "ipv4": addresses, "routes": routes, "helpers": helpers}
        write_json(out / (label + ".json"), result)
        return result

    time.sleep(3)
    before = snapshot("before-upstream")
    assert before["wan_status"] is not None, "missing interface, invalid experiment"
    if delay in ("late", "late-single"):
        enable_upstream()
    plugged = time.monotonic()
    attempts = []
    while delay != "disabled" and time.monotonic() - plugged < 12:
        time.sleep(1)
        attempts.append(snapshot("poll"))
        if attempts[-1]["wan_status"]["up"]:
            break
        assert daemon.poll() is None and logd.poll() is None
    final = snapshot("after-upstream")
    (out / "logread.txt").write_text(command("chroot", str(root), "/sbin/logread", check=False).stdout)
    result = {"side": kind, "upstream": delay,
              "before_wan_admin_up": "UP" in before["kernel_link"]["flags"],
              "before_protocol_up": before["wan_status"]["up"],
              "after_wan_admin_up": "UP" in final["kernel_link"]["flags"],
              "after_protocol_up": final["wan_status"]["up"],
              "after_DHCP_helper_count": len(final["helpers"]),
              "after_default_route": any(r.get("dst") == "default" for r in final["routes"]),
              "post_plug_observation_s": time.monotonic() - plugged,
              "binary_sha256": hashlib.sha256((root / binary.lstrip("/")).read_bytes()).hexdigest(),
              "original_C_bus_sha256": hashlib.sha256((root / "sbin/ubusd").read_bytes()).hexdigest()}
    write_json(out / "observations.json", attempts)
    write_json(out / "result.json", result)
    print(json.dumps(result), flush=True)
    if not gate:
        return

    def admin_up(s):
        return "UP" in s["kernel_link"]["flags"]

    def helper_names(s):
        return sorted(Path(p[0]).name for p in s["helpers"])

    def has_address(s):
        return any(a.get("local") == "198.18.0.100" for dev in s["ipv4"]
                   for a in dev.get("addr_info", []))

    def has_default(s):
        return any(r.get("dst") == "default" and r.get("dev") == "wan"
                   and r.get("gateway") == "198.18.0.1" for r in s["routes"])

    shared = delay != "late-single"
    expected_helpers = ["odhcp6c", "udhcpc"] if shared else ["udhcpc"]

    def leased(s):
        return (admin_up(s) and (s["wan_status"] or {}).get("up") is True
                and has_address(s) and has_default(s)
                and helper_names(s) == expected_helpers)

    def waiting(s):
        return (admin_up(s) and (s["wan_status"] or {}).get("up") is False
                and (s["wan_status"] or {}).get("pending") is False
                and not s["helpers"] and not has_address(s) and not has_default(s))

    def released(s):
        return (not admin_up(s) and not s["helpers"]
                and not has_address(s) and not has_default(s))

    phases = []

    def require(label, observation, condition):
        passed = bool(condition(observation))
        phases.append({"phase": label, "passed": passed,
                       "elapsed_s": observation["elapsed_s"]})
        write_json(out / "gate.json", phases)
        if not passed:
            raise RuntimeError(f"{kind}/{delay}: {label} failed; see {out}")

    def wait_for(label, condition):
        deadline = time.monotonic() + 12
        observations = []
        while True:
            s = snapshot(label)
            observations.append(s)
            if condition(s) or time.monotonic() >= deadline:
                break
            if daemon.poll() is not None or logd.poll() is not None:
                raise RuntimeError("daemon exited during lifecycle gate")
            time.sleep(0.2)
        write_json(out / (label + "-observations.json"), observations)
        require(label, s, condition)
        return s

    def call(obj, method):
        command("chroot", str(root), "/bin/ubus", "-t", "3", "call", obj, method)

    if delay == "disabled":
        require("auto-disabled", final, lambda s: released(s)
                and s["wan_status"]["autostart"] is False
                and s["wan6_status"]["autostart"] is False)
        call("network.interface.wan", "up")
        call("network.interface.wan6", "up")
        wait_for("manual-up", leased)
    else:
        require("startup-port-enabled", before, admin_up)
        if delay.startswith("late"):
            require("startup-waiting-for-carrier", before, waiting)
        require("obtained-lease-and-default-route", final, leased)

    if delay != "late":
        return
    command(*upstream, "ip", "link", "set", "upstream", "down")
    wait_for("link-lost-device-still-held", waiting)
    command(*upstream, "ip", "link", "set", "upstream", "up")
    wait_for("link-restored", leased)
    call("network.interface.wan6", "down")
    wait_for("one-shared-owner-remains", lambda s: admin_up(s)
             and s["wan_status"]["up"] and has_default(s)
             and helper_names(s) == ["udhcpc"])
    call("network.interface.wan", "down")
    wait_for("last-owner-releases-device", released)
    command(*upstream, "ip", "link", "set", "upstream", "down")
    call("network.interface.wan", "up")
    call("network.interface.wan6", "up")
    wait_for("manual-up-waits-for-carrier", waiting)
    call("network", "reload")
    # Give asynchronous reload work a turn before observing preserved claims.
    time.sleep(1)
    wait_for("unchanged-reload-preserves-waiting-device", waiting)
    command(*upstream, "ip", "link", "set", "upstream", "up")
    wait_for("link-restored-after-reload", leased)
    config = root / "etc/config/network"
    original = config.read_text()
    config.write_text(original.split("config interface 'wan'")[0])
    call("network", "reload")
    wait_for("removed-config-releases-device", released)
    command(*upstream, "ip", "link", "set", "upstream", "down")
    config.write_text(original)
    call("network", "reload")
    wait_for("readded-config-waits-for-carrier", waiting)
    command(*upstream, "ip", "link", "set", "upstream", "up")
    wait_for("readded-config-obtains-lease", leased)
    (out / "logread-final.txt").write_text(
        command("chroot", str(root), "/sbin/logread", check=False).stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("ns_exec", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--inside", nargs=2, metavar=("SIDE", "EARLY_OR_LATE"))
    p.add_argument("--gate", action="store_true", help="require connectivity and lifecycle checks")
    args = p.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists(), "build host only"
    rootfs, candidate, ns_exec, output = (p.resolve() for p in
                                        [args.rootfs, args.candidate, args.ns_exec, args.output])
    if args.inside:
        inside(rootfs, output, *args.inside, args.gate)
        return
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for delay in (["early", "late", "late-single", "disabled"] if args.gate else ["early", "late"]):
        for kind in ["c", "rust"]:
            out = output / (kind + "-" + delay)
            out.mkdir()
            with tempfile.TemporaryDirectory(prefix="netifd-delayed-wan-") as tmp:
                root = Path(tmp) / "root"
                command("cp", "-a", str(rootfs), str(root), timeout=60)
                for old in (root / "etc/config").iterdir():
                    if old.is_file() or old.is_symlink():
                        old.unlink()
                config = """config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1/8'
config interface 'wan'
    option device 'wan'
    option proto 'dhcp'
config interface 'wan6'
    option device 'wan'
    option proto 'dhcpv6'
"""
                if delay == "late-single":
                    config = config.split("config interface 'wan6'")[0]
                if delay == "disabled":
                    config = config.replace("option device 'wan'", "option device 'wan'\n    option auto '0'")
                (root / "etc/config/network").write_text(config)
                (root / "sbin/hotplug-call").write_text("#!/bin/sh\nexit 0\n")
                (root / "sbin/hotplug-call").chmod(0o755)
                shutil.copy2(candidate, root / "sbin/netifd-candidate")
                (root / "sbin/netifd-candidate").chmod(0o755)
                child = [str(ns_exec), sys.executable, str(Path(__file__).resolve()),
                         str(root), str(candidate), str(ns_exec), str(out), "--inside", kind, delay]
                if args.gate:
                    child.append("--gate")
                subprocess.run(child, check=True, timeout=170)
                results.append(json.loads((out / "result.json").read_text()))
    write_json(output / "results.json", results)
    if args.gate:
        write_json(output / "gate.json", {"passed": True, "cases": len(results)})


if __name__ == "__main__":
    main()
