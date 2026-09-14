#!/usr/bin/env python3
"""Observe both radios and rpcd plugin methods during an accepted router boot.

Responses contain private network data: output belongs outside Git. The normal
probe reads state only. --scan explicitly exercises one scan per AP; scans may
temporarily change radio state and require the deployment recovery gate.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from r84_device_probe import probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stock", "rust"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--scan", action="store_true")
    parser.add_argument("--recovery-gate", type=Path)
    args = parser.parse_args()
    if args.scan:
        if args.recovery_gate is None:
            parser.error("scan requires the verified deployment recovery gate")
        gate = json.loads(args.recovery_gate.read_text())
        assert gate["offline_backup_verified"] and gate["configuration_matches_backup"]
        assert gate["automatic_rollback_seconds"] == 900
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", args.host]

    def remote(command):
        return subprocess.check_output(ssh + [command], timeout=30)

    health_args = dict(host=args.host, mode=args.mode, interface=args.interface)
    before = probe(**health_args)
    config = remote("sha256sum /etc/config/*")
    identity = remote("/bin/sh /root/r84/stack-switch.sh verify " + args.mode)
    calls = [("iwinfo", "devices", {})]
    for device in sorted(before["ap_bridges"]):
        calls += [("iwinfo", method, {"device": device}) for method in
                  ("info", "assoclist", "freqlist", "txpowerlist", "countrylist", "survey")]
    calls += [("iwinfo", "phyname", {"section": radio}) for radio in ("radio0", "radio1")]
    calls += [("luci-rpc", method, {}) for method in ("getNetworkDevices", "getWirelessDevices",
              "getHostHints", "getDUIDHints", "getBoardJSON", "getDHCPLeases")]
    calls += [("luci-rpc", "getDHCPLeases", {"family": family}) for family in (4, 6)]
    calls += [("luci", "getFeatures", {}), ("luci", "getVersion", {}),
              ("network.rrdns", "lookup", {"addrs": ["192.168.1.1"], "timeout": 500})]
    rows = []

    def invoke(round_number, obj, method, data):
        command = " ".join(shlex.quote(word) for word in
                           ["ubus", "-S", "-t", "35", "call", obj, method, json.dumps(data)])
        result = subprocess.run(ssh + [command], capture_output=True, timeout=60)
        rows.append({"round": round_number, "object": obj, "method": method, "arguments": data,
                     "exit": result.returncode, "stdout": result.stdout.decode("utf-8", "replace"),
                     "stderr": result.stderr.decode("utf-8", "replace")})
        (args.output / "calls.json").write_text(json.dumps(rows, indent=2) + "\n")
        assert result.returncode == 0, f"{obj}.{method} failed"
        json.loads(result.stdout)

    for round_number in (1, 2):
        for obj, method, data in calls:
            invoke(round_number, obj, method, data)
    scans = []
    if args.scan:
        for device in sorted(before["ap_bridges"]):
            invoke("scan", "iwinfo", "scan", {"device": device})
            scans.append(probe(**health_args))
    after = probe(**health_args)
    assert before["boot_id"] == after["boot_id"]
    assert remote("sha256sum /etc/config/*") == config
    assert remote("/bin/sh /root/r84/stack-switch.sh verify " + args.mode) == identity
    (args.output / "observations.json").write_text(json.dumps({
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "mode": args.mode,
        "before": before, "after": after, "scan_health": scans, "calls": len(rows),
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "configuration_unchanged": True, "running_identities_unchanged": True,
        "scope": "two observation rounds; optional one active scan per AP",
    }, indent=2) + "\n")
    (args.output / "running-hashes.txt").write_bytes(identity)
    (args.output / "COMPLETE").touch()
    print(json.dumps({"mode": args.mode, "calls": len(rows), "radios": len(before["ap_bridges"]),
                      "scan_calls": len(scans), "client_health": "passed"}), flush=True)


if __name__ == "__main__":
    main()
