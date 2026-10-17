#!/usr/bin/env python3
"""Read-only, bounded post-deployment observation on the real router.

Writes private snapshots; never reloads, renews, restarts or changes a service.
Run alongside the existing deployment controller, which owns health/rollback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


SNAPSHOT = r'''set -eu
field() { printf '\034'; "$@"; }
cat /proc/sys/kernel/random/boot_id
field cat /proc/uptime
field cat /usr/share/owrt-control-plane/release.json
field ubus -S -t 3 call network.interface.wan status
field ubus -S -t 3 call network.interface.wan6 status
field nft -s -a -j list table inet fw4
field sh -c 'stat -c "%i %Y %s" /var/run/fw4.reload-state 2>/dev/null || true'
field sh -c 'sha256sum /var/run/fw4.reload-state 2>/dev/null || true'
field cat /proc/sys/kernel/random/boot_id
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--previous-boot", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--seconds", type=int, default=300)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 600:
        parser.error("observation must be 30..600 seconds")
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ["ssh", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
           "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=1", args.host]
    began = None
    boot = None
    wait_deadline = time.monotonic() + 850
    samples = []
    with (args.output / "events.jsonl").open("x", buffering=1) as events:
        while began is None or time.monotonic() - began < args.seconds:
            if began is None and time.monotonic() > wait_deadline:
                raise RuntimeError("candidate boot was not observed; no device action taken")
            start = time.monotonic()
            try:
                response = subprocess.run(ssh + [SNAPSHOT], capture_output=True, timeout=20)
                if response.returncode:
                    raise RuntimeError(f"snapshot SSH returned {response.returncode}")
                fields = response.stdout.decode().split("\x1c")
                if len(fields) != 9:
                    raise RuntimeError("incomplete snapshot")
                current = fields[0].strip()
                if current == args.previous_boot:
                    time.sleep(5)
                    continue
                release = json.loads(fields[2])
                if release.get("source_commit") != args.source_commit:
                    raise RuntimeError("unexpected release; observer does not confirm it")
                if fields[8].strip() != current or (boot is not None and boot != current):
                    raise RuntimeError("boot changed during observation")
                wan, wan6, rules = map(json.loads, fields[3:6])
                if began is None:
                    began, boot = time.monotonic(), current
                    log = subprocess.run(ssh + ["logread -t"], capture_output=True, timeout=15)
                    (args.output / "logread-first.txt").write_bytes(log.stdout)
                number = len(samples)
                (args.output / f"snapshot-{number:03d}.txt").write_bytes(response.stdout)
                # Address strings stay in the private original. The fingerprints
                # detect changes without publishing client/network identifiers.
                addresses = sorted((item["address"], item["mask"]) for item in wan6.get("ipv6-address", []))
                canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                sample = dict(unix=time.time(), elapsed_s=time.monotonic()-began,
                              uptime_s=float(fields[1].split()[0]), duration_s=time.monotonic()-start,
                              wan_up=wan.get("up"), wan6_up=wan6.get("up"),
                              wan6_address_count=len(addresses), wan6_addresses_sha256=hashlib.sha256(canonical(addresses)).hexdigest(),
                              stateless_rules_with_handles_sha256=hashlib.sha256(canonical(rules)).hexdigest(),
                              cache_stat=fields[6].strip(), cache_sha256=fields[7].split()[0] if fields[7].strip() else None)
                samples.append(sample)
                events.write(json.dumps(dict(event="sample", **sample)) + "\n")
                if number % 6 == 0:
                    print(json.dumps(dict(samples=len(samples), uptime_s=sample["uptime_s"],
                                          wan_up=sample["wan_up"], wan6_up=sample["wan6_up"])), flush=True)
            except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
                events.write(json.dumps(dict(event="snapshot_failed", unix=time.time(), error=str(error))) + "\n")
            time.sleep(max(0, 5 - (time.monotonic() - start)))
    log = subprocess.run(ssh + ["logread -t"], capture_output=True, timeout=15)
    (args.output / "logread-last.txt").write_bytes(log.stdout)
    result = dict(samples=len(samples), all_interfaces_up=all(s["wan_up"] and s["wan6_up"] for s in samples),
                  distinct_wan6_address_sets=len({s["wan6_addresses_sha256"] for s in samples}),
                  distinct_rule_handle_states=len({s["stateless_rules_with_handles_sha256"] for s in samples}),
                  cache_present_samples=sum(s["cache_sha256"] is not None for s in samples),
                  distinct_cache_inodes=len({s["cache_stat"].split()[0] for s in samples if s["cache_stat"]}),
                  source_commit=args.source_commit, seconds=args.seconds,
                  qualification="Sampled rules/handles and interface state; not netifd syscall tracing or a latency benchmark")
    (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
