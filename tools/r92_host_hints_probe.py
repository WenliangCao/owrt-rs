#!/usr/bin/env python3
"""Exercise host-hint IPv6 membership on exact binaries in private namespaces.

All addresses and MACs below are synthetic. Only a disposable Linux rootfs and
its network namespace are changed; this probe is never run on the router.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from r92_compat_probe import Fixture
from r92_recovery_probe import digest, run, write

MAC = "02:00:00:00:92:02"
V4 = "203.0.113.2"
LINK = "fe80::92:2"
GLOBAL = "2001:db8:92::2"
PHASES = (
    ("link_local_only", None, [LINK]),
    ("global_added", "permanent", [GLOBAL, LINK]),
    ("global_removed", None, [LINK]),
    ("global_noarp", "noarp", [LINK]),
    ("global_stale", "stale", [GLOBAL, LINK]),
    ("global_removed_again", None, [LINK]),
)


def exercise(f):
    write(f.root / "etc/config/dhcp", "config dnsmasq\n\toption leasefile '/tmp/dhcp.leases'\n")
    write(f.root / "tmp/dhcp.leases", "")
    write(f.root / "etc/ethers", "")
    write(f.root / "etc/resolv.conf", "nameserver 127.0.0.1\n")
    run("ip", "link", "add", "r92hint", "type", "dummy")
    run("ip", "link", "set", "r92hint", "up")
    run("ip", "neigh", "replace", V4, "lladdr", MAC, "nud", "permanent", "dev", "r92hint")
    run("ip", "-6", "neigh", "replace", LINK, "lladdr", MAC, "nud", "permanent", "dev", "r92hint")
    f.start_bus()
    f.start_subject(obj="luci-rpc")
    snapshots = []
    for index, (label, state, expected) in enumerate(PHASES):
        if state is None:
            if index:
                run("ip", "-6", "neigh", "del", GLOBAL, "dev", "r92hint")
        else:
            run("ip", "-6", "neigh", "replace", GLOBAL, "lladdr", MAC,
                "nud", state, "dev", "r92hint")
        before = run("ip", "-6", "neigh", "show", "dev", "r92hint", capture_output=True).stdout
        for repeat in (1, 2):
            value = f.call("luci-rpc", "getHostHints").get(MAC.upper())
            f.check(f"{label}_{repeat}", value, {"ipaddrs": [V4], "ip6addrs": expected})
        after = run("ip", "-6", "neigh", "show", "dev", "r92hint", capture_output=True).stdout
        f.check(label + "_input_unchanged", after, before)
        # Bytes are decoded only for the synthetic neighbor snapshots.
        f.checks[label + "_input_unchanged"]["actual"] = after.decode()
        f.checks[label + "_input_unchanged"]["expected"] = before.decode()
        snapshots.append({"phase": label, "neighbors": before.decode()})
    f.observations["inputs"] = snapshots
    f.check("serving", f.subject.poll() is None and f.ready("luci-rpc"))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        f = Fixture(Path(sys.argv[2]), sys.argv[3], "rpcd")
        try:
            exercise(f)
        finally:
            write(f.output / "result.json", json.dumps({"checks": f.checks,
                  "observations": f.observations}, indent=2) + "\n")
            f.close()
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("rootfs", type=Path)
    p.add_argument("binary", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux" or Path("/etc/openwrt_release").exists():
        p.error("run as root on the Linux build host, never on OpenWrt")
    a.output.mkdir(parents=True, exist_ok=False)
    rows = []
    required = {"identity", "serving"} | {
        label + suffix for label, _, _ in PHASES for suffix in ("_1", "_2", "_input_unchanged")}
    for side in ("original", "candidate"):
        destination = a.output / side
        destination.mkdir()
        with tempfile.TemporaryDirectory(prefix="r92-hints-") as temporary:
            root = Path(temporary) / "root"
            shutil.copytree(a.rootfs, root, symlinks=True)
            for directory in ("out", "run/ubus", "lock", "state", "initd", "rcd"):
                (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
            shutil.copy2(a.binary, root / "tmp/rpcd-rs")
            with (destination / "driver.log").open("xb") as log:
                result = subprocess.run(["timeout", "-k", "3", "60", "unshare", "--mount",
                    "--net", "--pid", "--fork", "--kill-child", sys.executable,
                    str(Path(__file__).resolve()), "--inner", str(root), side], stdout=log, stderr=log)
            shutil.copytree(root / "tmp/out", destination / "raw")
        path = destination / "raw/result.json"
        data = json.loads(path.read_text()) if path.exists() else {"checks": {}, "observations": {}}
        passed = result.returncode == 0 and required == data["checks"].keys() and all(
            c["passed"] for c in data["checks"].values())
        rows.append({"side": side, "exit": result.returncode, "passed": passed, **data})
        write(a.output / "results.json", json.dumps(rows, indent=2) + "\n")
        print(json.dumps({"side": side, "passed": passed, "exit": result.returncode}), flush=True)
    passed = len(rows) == 2 and all(r["passed"] for r in rows)
    write(a.output / "identities.json", json.dumps({"driver_sha256": digest(Path(__file__)),
        "candidate_sha256": digest(a.binary), "original_sha256": digest(a.rootfs / "sbin/rpcd")}, indent=2) + "\n")
    (a.output / ("COMPLETE" if passed else "FAILED")).touch()
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
