#!/usr/bin/env python3
"""Capture a read-only native probe over one SSH session, or summarize its JSONL.

The caller owns probe upload, artifact identity and router cleanup. This command
never signals the measured daemon or changes its configuration. Raw goes private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import statistics
import subprocess
import time


def distribution(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


def counters(process):
    return (process["user_ticks"] + process["system_ticks"],
            process["waited_child_user_ticks"] + process["waited_child_system_ticks"])


def summarize(rows, seconds=600, interval=5):
    errors = []
    if not rows:
        raise ValueError("no samples")
    expected = seconds // interval + 1
    if len(rows) != expected:
        errors.append(f"expected {expected} samples, got {len(rows)}")
    if [row["index"] for row in rows] != list(range(len(rows))):
        errors.append("sample index gap")
    roots = [row["processes"][0] for row in rows]
    if len({(p["pid"], p["starttime_ticks"]) for p in roots}) != 1:
        errors.append("target identity changed")
    ticks = {row["clock_ticks_per_second"] for row in rows}
    if len(ticks) != 1 or min(ticks) <= 0:
        raise ValueError("clock tick frequency changed or invalid")
    hz = next(iter(ticks))
    times = [row["monotonic_ns"] / 1e9 for row in rows]
    elapsed = times[-1] - times[0]
    if len(rows) < 2 or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError("insufficient or nonmonotonic samples")
    if abs(elapsed - seconds) > 1:
        errors.append("duration differs by more than one second")
    if any(abs(b - a - interval) > 1 for a, b in zip(times, times[1:])):
        errors.append("sample interval differs by more than one second")
    if any(row["proc_parent_map_scans"] != 1 for row in rows):
        errors.append("unexpected process map scan count")
    cpu = [counters(p) for p in roots]
    if any(b[i] < a[i] for a, b in zip(cpu, cpu[1:]) for i in range(2)):
        errors.append("target CPU counter decreased")
    root_ticks = cpu[-1][0] - cpu[0][0]
    waited_ticks = cpu[-1][1] - cpu[0][1]
    observers = [row["observer"] for row in rows]
    if len({(p["pid"], p["starttime_ticks"]) for p in observers}) != 1:
        errors.append("observer identity changed")
    observer_ticks = counters(observers[-1])[0] - counters(observers[0])[0]
    child_free = all(len(row["processes"]) == 1 and row["children_disappeared"] == 0
                     for row in (rows[0], rows[-1]))
    memory = {key: distribution([p[key] for p in roots]) for key in
              ("rss_kib", "rss_anon_kib", "fd_count", "thread_count")}
    tree = {key: distribution([sum(p[key] for p in row["processes"]) for row in rows])
            for key in ("rss_kib", "rss_anon_kib", "fd_count", "thread_count")}
    interval_cpu = [(b[0] - a[0]) / hz / (end - begin) * 100
                    for a, b, begin, end in zip(cpu, cpu[1:], times, times[1:])]
    leases = [row["lease_count"] for row in rows if row["lease_count"] is not None]
    return {
        "valid_observation_window": not errors, "errors": errors,
        "samples": len(rows), "duration_seconds": elapsed,
        "clock_ticks_per_second": hz,
        "main_cpu_seconds": root_ticks / hz,
        "main_average_one_core_percent": root_ticks / hz / elapsed * 100,
        "main_interval_one_core_percent": distribution(interval_cpu),
        "waited_children_cpu_seconds": waited_ticks / hz,
        "main_plus_waited_cpu_seconds": (root_ticks + waited_ticks) / hz,
        "main_plus_waited_average_one_core_percent": (root_ticks + waited_ticks) / hz / elapsed * 100,
        "child_free_endpoints_observed": child_free,
        "tree_cpu_qualification": ("main plus waited children at child-free sampled endpoints; "
                                   "proc reads are not atomic" if child_free else
                                   "not complete service-tree CPU: a sampled endpoint has live/missing children"),
        "main": memory, "tree_shared_pages_recounted": tree,
        "process_count": distribution([len(row["processes"]) for row in rows]),
        "children_disappeared_total": sum(row["children_disappeared"] for row in rows),
        "lease_count": distribution(leases) if leases else None,
        "lease_count_missing_samples": len(rows) - len(leases),
        "observer_cpu_seconds": observer_ticks / hz,
        "observer_average_one_core_percent": observer_ticks / hz / elapsed * 100,
        "sample_duration_ms": distribution([row["sample_duration_ns"] / 1e6 for row in rows]),
        "limitations": ["Daily usage, not controlled workload or performance ranking.",
                        "RSS and RssAnon are not PSS or USS; tree memory recounts shared pages.",
                        "Short-lived children may only appear in waited-child CPU counters.",
                        "Observer CPU excludes SSH, network probes and local analysis.",
                        "No query logging or per-client/name/address collection."]}


def collect(args):
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    raw = args.output / "usage.jsonl"
    command = [args.probe, str(args.pid), str(args.starttime), str(args.seconds), str(args.interval)]
    if args.lease_file:
        command.append(args.lease_file)
    invocation = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                  "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
                  args.ssh, shlex.join(command)]
    before = time.time_ns()
    with raw.open("xb") as output, (args.output / "stderr.txt").open("xb") as error:
        raw.chmod(0o600)
        (args.output / "stderr.txt").chmod(0o600)
        result = subprocess.run(invocation, stdout=output, stderr=error, check=False)
    receipt = {"ssh_returncode": result.returncode, "started_unix_ns": before,
               "finished_unix_ns": time.time_ns(), "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
               "seconds": args.seconds, "interval_seconds": args.interval,
               "pid": args.pid, "starttime_ticks": args.starttime}
    (args.output / "collection.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    capture = sub.add_parser("collect")
    capture.add_argument("--ssh", default="openwrt")
    capture.add_argument("--probe", required=True)
    capture.add_argument("--pid", type=int, required=True)
    capture.add_argument("--starttime", type=int, required=True)
    capture.add_argument("--lease-file")
    capture.add_argument("--output", type=Path, required=True)
    summary = sub.add_parser("summarize")
    summary.add_argument("input", type=Path)
    summary.add_argument("--output", type=Path)
    for command in (capture, summary):
        command.add_argument("--seconds", type=int, default=600)
        command.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()
    if not (0 < args.seconds <= 3600 and 0 < args.interval <= 60 and args.seconds % args.interval == 0):
        parser.error("seconds must be a multiple of interval, in probe bounds")
    if args.action == "collect":
        raise SystemExit(collect(args))
    rows = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    result = summarize(rows, args.seconds, args.interval)
    result["raw_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    raise SystemExit(0 if result["valid_observation_window"] else 1)


if __name__ == "__main__":
    main()
