#!/usr/bin/env python3
"""Bounded iperf TCP measurements with read-only router snapshots.

Raw output can contain IP/MAC addresses; --output must be inside private/.
Does not change router configuration, install services or start an iperf server.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import time


SNAPSHOT = r'''
printf '@@stat\n'; cat /proc/stat
printf '@@netdev\n'; cat /proc/net/dev
printf '@@softirqs\n'; cat /proc/softirqs
printf '@@uptime\n'; cat /proc/uptime
printf '@@wifi\n'
for dev in $(iw dev | awk '$1 == "Interface" {print $2}'); do
 printf 'INTERFACE %s\n' "$dev"
 iw dev "$dev" station dump
done
printf '@@flow_counts\n'
if [ -r /proc/net/nf_conntrack ]; then
 awk '{n++} /\[OFFLOAD\]/{s++} /\[HW_OFFLOAD\]/{h++} END {print n+0,s+0,h+0}' /proc/net/nf_conntrack
fi
'''


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def snapshot(router):
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", router, "sh"],
        input=SNAPSHOT, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError("router snapshot failed: " + result.stderr)
    return result.stdout


def cpu(snapshot_text):
    result = {}
    for line in snapshot_text.split("@@stat\n", 1)[1].split("@@netdev\n", 1)[0].splitlines():
        fields = line.split()
        if fields and (fields[0] == "cpu" or fields[0][3:].isdigit() and fields[0].startswith("cpu")):
            # guest/guest_nice are already included in user/nice.
            result[fields[0]] = list(map(int, fields[1:9]))
    return result


def cpu_delta(before, after):
    first, last = cpu(before), cpu(after)
    result = {}
    for name, values in first.items():
        delta = [b-a for a, b in zip(values, last[name])]
        total = sum(delta)
        if total <= 0 or min(delta) < 0:
            raise ValueError("CPU counters did not advance monotonically")
        result[name] = {"busy_pct": 100*(total-delta[3]-delta[4])/total,
                        "softirq_pct": 100*delta[6]/total,
                        "iowait_pct": 100*delta[4]/total}
    return result


def probes(host, duration, stop=None):
    start = time.monotonic()
    records = []
    deadline = start + duration
    while time.monotonic() < deadline and (stop is None or not stop.is_set()):
        attempt = time.monotonic()
        try:
            with socket.create_connection((host, 80), timeout=1):
                elapsed = (time.monotonic()-attempt)*1000
            records.append({"at_s": attempt-start, "ms": elapsed})
        except OSError as error:
            records.append({"at_s": attempt-start, "error": str(error)})
        time.sleep(max(0, min(0.5-(time.monotonic()-attempt), deadline-time.monotonic())))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iperf", type=Path, required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--router", default="openwrt")
    parser.add_argument("--probe-host", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--streams", type=int, default=4)
    args = parser.parse_args()
    private = Path(__file__).resolve().parent.parent / "private"
    assert args.output.resolve().is_relative_to(private)
    assert 1 <= args.rounds <= 3 and 3 <= args.seconds <= 20 and 1 <= args.streams <= 4
    args.output.mkdir(parents=True, exist_ok=False)
    iperf = args.iperf.resolve()
    write(args.output / "plan.json", {
        "server": args.server, "port": args.port, "rounds": args.rounds,
        "seconds": args.seconds, "omit_seconds": 2, "streams": args.streams,
        "iperf_sha256": hashlib.sha256(iperf.read_bytes()).hexdigest(),
        "version": subprocess.check_output([str(iperf), "--version"], text=True),
        "probe": "TCP connect to router port 80 every 0.5 seconds"})
    write(args.output / "idle-probes.json", probes(args.probe_host, 10))
    summary = []
    for trial in range(1, args.rounds+1):
        for direction in ("upload", "download"):
            name = f"{trial:02}-{direction}"
            before = snapshot(args.router)
            (args.output / (name+"-before.txt")).write_text(before)
            command = [str(iperf), "-c", args.server, "-p", str(args.port), "-4",
                       "-J", "-t", str(args.seconds), "-O", "2", "-P", str(args.streams),
                       "--connect-timeout", "3000", "--get-server-output"]
            if direction == "download":
                command.append("-R")
            print("START", name, flush=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(probes, args.probe_host, args.seconds+2)
                try:
                    result = subprocess.run(command, text=True, capture_output=True, timeout=args.seconds+15)
                except subprocess.TimeoutExpired as error:
                    (args.output / (name+"-timeout.txt")).write_text(str(error))
                    raise
                (args.output / (name+".json")).write_text(result.stdout)
                (args.output / (name+".stderr")).write_text(result.stderr)
                write(args.output / (name+"-probes.json"), future.result())
            after = snapshot(args.router)
            (args.output / (name+"-after.txt")).write_text(after)
            data = json.loads(result.stdout)
            if result.returncode or "error" in data:
                raise RuntimeError(f"failed {name}: {data.get('error', result.stderr)}")
            end = data["end"]
            row = {"trial": trial, "direction": direction,
                   "receiver_mbps": end["sum_received"]["bits_per_second"]/1e6,
                   "sender_retransmits": end["sum_sent"].get("retransmits"),
                   "endpoint_cpu": end.get("cpu_utilization_percent"),
                   "router_cpu": cpu_delta(before, after)}
            summary.append(row)
            write(args.output / "summary.json", summary)
            print("DONE", json.dumps(row), flush=True)
            time.sleep(3)


if __name__ == "__main__":
    main()
