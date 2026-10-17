#!/usr/bin/env python3
"""Exact-image fw4 reload differential in disposable Linux namespaces.

Prediction: after flowtable warmup, unchanged WAN6 address updates cause zero
candidate nft applies (stock: one each). Changed rules, unsafe includes, failed
applies and external kernel edits still cause an apply. Counts and real kernel
handles test this directly; host timings are not router performance claims.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from r92_compat_probe import Fixture
from r92_recovery_probe import attr, message, write


def blob(name, value):
    if isinstance(value, bool):
        return message(name, 7, bytes([value]))
    if isinstance(value, int):
        return message(name, 5, struct.pack(">I", value))
    if isinstance(value, str):
        return message(name, 3, value.encode() + b"\0")
    if isinstance(value, list):
        return message(name, 1, b"".join(blob("", item) for item in value))
    if isinstance(value, dict):
        return message(name, 2, b"".join(blob(k, v) for k, v in value.items()))
    raise TypeError(type(value))

CONFIG = """config defaults
 option input 'DROP'
 option output 'ACCEPT'
 option forward 'DROP'
 option auto_includes '0'
 option flow_offloading '1'
config zone
 option name 'wan'
 list network 'wan6'
 option input 'DROP'
 option output 'ACCEPT'
 option forward 'DROP'
"""

NFT_WRAPPER = """#!/bin/sh
printf '%s\\n' "$*" >> /tmp/out/nft-args
case " $* " in
 *' -f '*)
  cat > /tmp/out/last-apply
  [ ! -e /tmp/fail-apply ] || exit 1
  if [ -e /tmp/race-include-inplace ]; then
   cp /etc/nftables.d/10-comments.nft /tmp/saved-include
   printf 'chain input { counter drop comment "race include"; }\\n' > /etc/nftables.d/10-comments.nft
  elif [ -e /tmp/race-include-atomic ]; then
   mv /etc/nftables.d/10-comments.nft /tmp/saved-include
   printf 'chain input { counter drop comment "race include"; }\\n' > /etc/nftables.d/10-comments.nft
  elif [ -e /tmp/race-include-wildcard ]; then
   printf 'chain input { counter drop comment "race include"; }\\n' > /etc/nftables.d/20-added.nft
  fi
  /usr/sbin/nft.real "$@" < /tmp/out/last-apply || exit $?
  if [ -e /tmp/race-include-inplace ]; then
   cat /tmp/saved-include > /etc/nftables.d/10-comments.nft
  elif [ -e /tmp/race-include-atomic ]; then
   mv /tmp/saved-include /etc/nftables.d/10-comments.nft
  elif [ -e /tmp/race-include-wildcard ]; then
   rm /etc/nftables.d/20-added.nft
  fi
  if [ -e /tmp/race-apply ]; then
   /usr/sbin/nft.real add rule inet fw4 input counter drop
  fi
  exit 0;;
 *' -s '*)
  [ ! -e /tmp/fail-list ] || exit 1
  /usr/sbin/nft.real "$@" || exit $?
  if [ -e /tmp/race-list ]; then
   /usr/sbin/nft.real add rule inet fw4 input counter drop
  fi
  exit 0;;
esac
exec /usr/sbin/nft.real "$@"
"""


def inner(root, side):
    f = Fixture(root, side, "fw4")
    stop = threading.Event()
    provider_thread = None
    observations = []
    try:
        subprocess.run(["ip", "link", "add", "wan0", "type", "dummy"], check=True)
        subprocess.run(["ip", "link", "set", "wan0", "up"], check=True)
        subprocess.run(["ip", "addr", "add", "192.0.2.1/24", "dev", "wan0"], check=True)
        subprocess.run(["ip", "neigh", "replace", "192.0.2.2", "lladdr", "02:00:00:00:00:02", "dev", "wan0"], check=True)
        write(root / "etc/config/firewall", CONFIG)
        write(root / "etc/nftables.d/10-comments.nft", "# empty include\n")
        nft = root / "usr/sbin/nft"
        nft.rename(nft.with_name("nft.real"))
        write(nft, NFT_WRAPPER)
        nft.chmod(0o755)
        f.start_bus()
        provider = f.connect()
        for path, method in (("network.interface", "dump"), ("service", "get_data")):
            code, _ = provider.request(6, attr(2, path.encode() + b"\0") + attr(6, message(method, 2, b"")))
            assert code == 0
        state = {"interface": [{"interface": "wan6", "up": True, "l3_device": "wan0",
                               "device": "wan0", "ipv6-address": [{"address": "2001:db8::1", "mask": 64}]}]}

        def serve():
            while not stop.is_set():
                try:
                    kind, seq, peer, data = provider.recv()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if kind != 5:
                    continue
                fields = dict(data)
                reply = state if fields[4] == b"dump\0" else {}
                payload = attr(3, fields[3]) + attr(7, b"".join(blob(k, v) for k, v in reply.items()))
                provider.sock.sendall(struct.pack(">BBHII", 0, 2, seq, peer, len(payload) + 4) + payload)
                payload = attr(1, struct.pack(">I", 0)) + attr(3, fields[3])
                provider.sock.sendall(struct.pack(">BBHII", 0, 1, seq, peer, len(payload) + 4) + payload)

        provider_thread = threading.Thread(target=serve, daemon=True)
        provider_thread.start()

        def command(*args):
            return subprocess.run(["chroot", str(root), *args], capture_output=True, timeout=10)

        def table():
            result = command("/usr/sbin/nft.real", "-a", "list", "table", "inet", "fw4")
            assert result.returncode == 0, result.stderr
            return result.stdout

        def count():
            path = f.output / "nft-args"
            return sum(" -f " in " " + line + " " for line in path.read_text().splitlines()) if path.exists() else 0

        def snapshot_count():
            path = f.output / "nft-args"
            return path.read_text().splitlines().count("-s list table inet fw4") if path.exists() else 0

        def check(name, expected, action="reload", snapshots=None):
            before = count()
            before_snapshots = snapshot_count()
            result = command(f.binary, action)
            delta = count() - before
            reads = snapshot_count() - before_snapshots
            observations.append({"name": name, "applies": delta, "expected": expected, "exit": result.returncode,
                                 "snapshots": reads, "expected_snapshots": snapshots})
            with (f.output / "commands.log").open("ab") as log:
                log.write(name.encode() + b"\n" + result.stdout + result.stderr)
            assert result.returncode == 0 and delta == expected, observations[-1]
            assert snapshots is None or reads == snapshots, observations[-1]

        check("start", 1, "start", snapshots=0)
        assert not (root / "var/run/fw4.reload-state").exists()
        certify_reads = 1 if side == "candidate" else 0
        check("flowtable_warmup", 1, snapshots=certify_reads)
        if side == "candidate":
            assert (root / "var/run/fw4.reload-state").exists()
        stable = 0 if side == "candidate" else 1
        original = table()
        assert b"flowtable ft" in original, original
        check("unchanged", stable, snapshots=certify_reads)
        assert (table() == original) == (side == "candidate")
        for i in range(3):
            state["interface"][0]["ipv6-address"][0]["address"] = f"2001:db8:{i + 1}::1"
            check(f"wan6_address_{i}", stable)
        before = count()
        children = [subprocess.Popen(["chroot", str(root), f.binary, "reload"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
        for child in children:
            child.communicate(timeout=10)
            assert child.returncode == 0
        assert count() - before == 4 * stable
        observations.append({"name": "concurrent_reload_4", "applies": count() - before, "expected": 4 * stable, "exit": 0})
        subprocess.run(["ping", "-c", "1", "-W", "1", "192.0.2.2"], capture_output=True)
        before = table()
        assert b"counter packets 1 " in before, before
        check("live_counters", stable)
        if side == "candidate":
            assert table() == before, "skip must retain counters and handles"
        changed = CONFIG + "config rule\n option name 'changed'\n option src 'wan'\n option proto 'tcp'\n option dest_port '12345'\n option target 'ACCEPT'\n"
        write(root / "etc/config/firewall", changed)
        check("real_rule_change", 1, snapshots=certify_reads)
        assert b"12345" in table()
        # Changed reload still certifies its successful apply. Its next
        # unchanged event must skip immediately, without a deferred rebuild.
        check("unchanged_after_rule_change", stable, snapshots=certify_reads)
        assert command("/usr/sbin/nft.real", "add", "rule", "inet", "fw4", "input", "counter", "drop").returncode == 0
        check("external_rule_change", 1)
        assert command("/usr/sbin/nft.real", "delete", "table", "inet", "fw4").returncode == 0
        check("external_table_delete", 1)
        check("rewarm_after_delete", 1)
        script = "config include\n option path '/tmp/user.sh'\n option fw4_compatible '1'\n"
        write(root / "tmp/user.sh", "echo called >> /tmp/out/include-calls\n")
        write(root / "etc/config/firewall", changed + script)
        check("user_script_1", 1)
        check("user_script_2", 1)
        assert (f.output / "include-calls").read_text().splitlines() == ["called", "called"]
        write(root / "etc/config/firewall", changed)
        write(root / "etc/nftables.d/10-comments.nft", "chain custom { }\n")
        check("nft_include_1", 1)
        check("nft_include_2", 1)
        write(root / "etc/nftables.d/10-comments.nft", "# comments again\n")
        check("restore_eligible", 1)
        (root / "tmp/fail-list").touch()
        check("snapshot_failure", 1)
        (root / "tmp/fail-list").unlink()
        check("snapshot_retry", 1)
        (root / "tmp/race-list").touch()
        check("snapshot_generation_race", 1)
        assert not (root / "var/run/fw4.reload-state").exists()
        (root / "tmp/race-list").unlink()
        check("snapshot_race_repair", 1)
        # Force an apply without changing the desired candidate, then inject
        # a second successful kernel transaction before nft returns.
        (root / "var/run/fw4.reload-state").unlink(missing_ok=True)
        (root / "tmp/race-apply").touch()
        check("apply_snapshot_race", 1)
        assert not (root / "var/run/fw4.reload-state").exists()
        (root / "tmp/race-apply").unlink()
        check("race_repair", 1)
        for kind in ("inplace", "atomic", "wildcard"):
            (root / "var/run/fw4.reload-state").unlink(missing_ok=True)
            marker = root / f"tmp/race-include-{kind}"
            marker.touch()
            check(f"include_race_{kind}", 1)
            assert b"race include" in table()
            assert not (root / "var/run/fw4.reload-state").exists()
            marker.unlink()
            check(f"include_race_repair_{kind}", 1)
            assert b"race include" not in table()
        (root / "tmp/fail-apply").touch()
        write(root / "etc/config/firewall", CONFIG)
        check("failed_apply", 1)
        assert not (root / "var/run/fw4.reload-state").exists()
        (root / "tmp/fail-apply").unlink()
        write(root / "etc/config/firewall", changed)
        check("failed_apply_retry_old_candidate", 1)
        check("reload_sets", 1, "reload-sets")
        check("after_reload_sets", 1)
        write(root / "etc/config/firewall", changed + "config ipset\n option name 'external'\n list match 'src_ip'\n")
        check("named_set_1", 1)
        check("named_set_2", 1)
        write(root / "etc/config/firewall", changed)
        check("restart", 2, "restart", snapshots=0)
        assert not (root / "var/run/fw4.reload-state").exists()
        check("after_restart_warmup", 1)
        check("stop", 0, "stop")
        assert not (root / "var/run/fw4.reload-state").exists()
        check("start_after_stop", 1, "start", snapshots=0)
        check("flush", 0, "flush")
        assert not (root / "var/run/fw4.reload-state").exists()
        write(f.output / "result.json", json.dumps(observations, indent=2) + "\n")
    finally:
        stop.set()
        f.close()
        if provider_thread:
            provider_thread.join(timeout=4)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inner":
        return inner(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        parser.error("run as root on Linux")
    args.output.mkdir(parents=True, exist_ok=False)
    for side in ("original", "candidate"):
        with tempfile.TemporaryDirectory(prefix="fw4-reload-") as temporary:
            root = Path(temporary) / "root"
            shutil.copytree(args.rootfs, root, symlinks=True)
            for directory in ("out", "run/ubus", "lock", "state"):
                (root / "tmp" / directory).mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.candidate, root / "tmp/fw4-rs")
            result = subprocess.run(["timeout", "-k", "2", "90", "unshare", "--mount", "--net", "--pid", "--fork", "--kill-child", sys.executable, str(Path(__file__).resolve()), "--inner", str(root), side], capture_output=True)
            shutil.copytree(root / "tmp/out", args.output / side)
            (args.output / f"{side}.log").write_bytes(result.stdout + result.stderr)
            print(json.dumps({"side": side, "passed": result.returncode == 0}), flush=True)
            if result.returncode:
                raise SystemExit(result.stderr.decode())


if __name__ == "__main__":
    main()
