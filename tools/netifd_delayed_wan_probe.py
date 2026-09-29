#!/usr/bin/env python3
"""Linux-only causal probe: exact C dependencies, one netifd, delayed WAN.

The upstream peer lives in a separate netns, so netifd cannot bring it up by
claiming a same-netns veth parent. No physical interfaces or router are used.
Outputs are observations, not a success claim for a candidate with no lease.
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


def inside(root, out, kind, delay):
    assert os.environ.get("OWRT_BENCH_NAMESPACE") == "1"
    assert {name for _, name in socket.if_nameindex()} == {"lo"}
    command("mount", "-t", "sysfs", "sysfs", "/sys")
    command("mount", "--bind", "/proc", str(root / "proc"))
    command("mount", "--bind", "/sys", str(root / "sys"))
    command("mount", "-t", "tmpfs", "tmpfs", str(root / "dev"))
    for name, major, minor in [("null", 1, 3), ("zero", 1, 5), ("urandom", 1, 9)]:
        command("mknod", "-m", "666", str(root / "dev" / name), "c", str(major), str(minor))
    command("ip", "link", "set", "lo", "up")
    server = subprocess.Popen(["unshare", "--net", "sleep", "120"])
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

    if delay == "early":
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
                  "status_returncode": status.returncode, "kernel_link": link,
                  "ipv4": addresses, "routes": routes, "helpers": helpers}
        write_json(out / (label + ".json"), result)
        return result

    time.sleep(3)
    before = snapshot("before-upstream")
    assert before["wan_status"] is not None, "missing interface, invalid experiment"
    if delay == "late":
        enable_upstream()
    plugged = time.monotonic()
    attempts = []
    while time.monotonic() - plugged < 12:
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("ns_exec", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--inside", nargs=2, metavar=("SIDE", "EARLY_OR_LATE"))
    args = p.parse_args()
    assert sys.platform == "linux" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists(), "build host only"
    rootfs, candidate, ns_exec, output = (p.resolve() for p in
                                        [args.rootfs, args.candidate, args.ns_exec, args.output])
    if args.inside:
        inside(rootfs, output, *args.inside)
        return
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for delay in ["early", "late"]:
        for kind in ["c", "rust"]:
            out = output / (kind + "-" + delay)
            out.mkdir()
            with tempfile.TemporaryDirectory(prefix="netifd-delayed-wan-") as tmp:
                root = Path(tmp) / "root"
                command("cp", "-a", str(rootfs), str(root), timeout=60)
                for old in (root / "etc/config").iterdir():
                    if old.is_file() or old.is_symlink():
                        old.unlink()
                (root / "etc/config/network").write_text("""config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1/8'
config interface 'wan'
    option device 'wan'
    option proto 'dhcp'
config interface 'wan6'
    option device 'wan'
    option proto 'dhcpv6'
""")
                (root / "sbin/hotplug-call").write_text("#!/bin/sh\nexit 0\n")
                (root / "sbin/hotplug-call").chmod(0o755)
                shutil.copy2(candidate, root / "sbin/netifd-candidate")
                (root / "sbin/netifd-candidate").chmod(0o755)
                args = [str(ns_exec), sys.executable, str(Path(__file__).resolve()),
                        str(root), str(candidate), str(ns_exec), str(out), "--inside", kind, delay]
                subprocess.run(args, check=True, timeout=70)
                results.append(json.loads((out / "result.json").read_text()))
    write_json(output / "results.json", results)


if __name__ == "__main__":
    main()
