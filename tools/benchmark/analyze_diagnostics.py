#!/usr/bin/env python3
"""Derive HTTP parking and repeated-close diagnostics without publishing PIDs.

Input contains settings.json, runs.json and one raw directory per named run.
Tracing rows publish syscall counts only; their latency is intentionally absent.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics

from analyze import stats


def read(path):
    return json.loads(path.read_text())


def syscalls(path):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) not in (5, 6) or fields[-1] == "total":
            continue
        try:
            result[fields[-1]] = {"calls": int(fields[3]),
                                  "errors": int(fields[4]) if len(fields) == 6 else 0,
                                  "blocked_wall_seconds": float(fields[1])}
        except ValueError:
            continue
    assert result, "empty syscall trace"
    return result


def series(values):
    count = len(values)
    assert count >= 10
    # Skip the first five completed cycles when quantifying subsequent drift.
    tail = values[5:]
    xmean = (len(tail) - 1) / 2
    ymean = statistics.mean(tail)
    denominator = sum((i - xmean) ** 2 for i in range(len(tail)))
    slope = sum((i - xmean) * (v - ymean) for i, v in enumerate(tail)) / denominator
    return {"first": values[0], "last": values[-1], "all": stats(values),
            "last_half": stats(values[count//2:]), "slope_per_cycle_after_five": slope,
            "last_ten_minus_first_ten_median": statistics.median(values[-10:]) - statistics.median(values[:10])}


def derive(root):
    assert (root / "COMPLETE").exists(), "collector did not complete"
    settings = read(root / "settings.json")
    rows = []
    for run in read(root / "runs.json"):
        assert run["exit"] == 0
        raw = root / run["name"]
        assert (raw / "COMPLETE").exists()
        meta = read(raw / "meta.json")
        assert meta["component"] == "httpd" and meta["dependencies"] == "original OpenWrt"
        for name in ("binary-sha256.txt", "subject-sha256.txt"):
            assert (raw / name).read_text().split()[0] == settings["subject_sha256"][run["side"]]
        assert (raw / "harness-sha256.txt").read_text().split()[0] == settings["harness_sha256"]
        assert (raw / "diagnostic-sha256.txt").read_text().split()[0] == settings["diagnostic_sha256"]
        row = {k: run[k] for k in ("name", "side", "kind", "value", "repeat")}
        row["kernel"] = (raw / "kernel.txt").read_text().strip()
        traced = (raw / "TRACE_DIAGNOSTIC").exists()
        assert traced == run["kind"].startswith("trace-")
        if run["kind"] == "memory":
            files = sorted(raw.glob("memory-*.json"), key=lambda p: int(p.stem.split("-")[1]))
            assert len(files) == run["value"]
            cycles = [read(path) for path in files]
            initial = cycles[0]["before"]
            for cycle in cycles:
                assert cycle["connections"] == 64 and cycle["requests_per_connection"] == 2
                assert cycle["response_bytes"] == 16384
                for phase in ("before", "held", "after_close"):
                    sample = cycle[phase]
                    assert sample["pid"] == meta["subject_pid"]
                    assert sample["start_ticks"] == initial["start_ticks"]
                assert cycle["held"]["fds"] == initial["fds"] + 64
                assert cycle["after_close"]["fds"] == initial["fds"]
                assert cycle["after_close"]["Threads"] == initial["Threads"]
            row.update(cycles=len(cycles), successful=len(cycles) * 128,
                       initial={key: initial[key] for key in ("VmRSS", "RssAnon", "RssFile", "fds", "Threads")},
                       post_close={key: series([c["after_close"][key] for c in cycles])
                                   for key in ("VmRSS", "RssAnon", "RssFile")},
                       post_close_samples=[{key: c["after_close"][key] for key in
                                            ("VmRSS", "RssAnon", "RssFile", "fds", "Threads")} for c in cycles],
                       max_held_rss_kib=max(c["held"]["VmRSS"] for c in cycles),
                       descriptors_and_threads_returned=True)
        else:
            data = read(raw / "paced.json")
            assert data["diagnostic_only"] and data["errors"] == 0
            count = data["successful"]
            assert count == len(data["latency_ns"]) == meta["iterations"]
            assert data["before"]["pid"] == data["after"]["pid"] == meta["subject_pid"]
            assert data["before"]["start_ticks"] == data["after"]["start_ticks"]
            row.update(successful=count, clients=data["clients"], gap_ms=data["gap_ms"])
            if traced:
                assert (raw / "strace-sha256.txt").read_text().split()[0] == settings["strace_sha256"]
                row["syscalls"] = syscalls(raw / "syscalls.txt")
            else:
                ticks = data["after"]["cpu_ticks"] - data["before"]["cpu_ticks"]
                assert ticks >= 0
                latency = sorted(data["latency_ns"])
                assert all(math.isfinite(v) and v > 0 for v in latency)
                row.update(mean_us=statistics.mean(latency) / 1000,
                           p50_us=latency[math.ceil(count * .50)-1] / 1000,
                           p95_us=latency[math.ceil(count * .95)-1] / 1000,
                           p99_us=latency[math.ceil(count * .99)-1] / 1000,
                           subject_cpu_us_per_op=ticks / data["ticks_per_second"] * 1e6 / count,
                           cpu_ticks=ticks, ticks_per_second=data["ticks_per_second"],
                           wall_seconds=data["wall_ns"] / 1e9,
                           sampled_thread_births_lower_bound=data["thread_births_observed_lower_bound"])
            if run["kind"] == "netem":
                assert "netem" in (raw / "netem.txt").read_text()
                row["configured_one_way_delay_ms"] = run["value"]
        row["evidence_sha256"] = hashlib.sha256(b"".join(
            path.read_bytes() for path in sorted(raw.glob("*.json")))).hexdigest()
        rows.append(row)
    return {"schema": 1, "environment": settings["environment"],
            "subject_sha256": settings["subject_sha256"],
            "harness_sha256": settings["harness_sha256"],
            "diagnostic_sha256": settings["diagnostic_sha256"],
            "rows": rows,
            "limitations": ["Diagnostic client differs from the frozen performance client.",
                "CPU tick quantization is retained; these are not throughput benchmarks.",
                "Request gaps are not network RTT; netem rows identify actual private-namespace delay.",
                "Thread births sampled every 2 ms are lower bounds; traced clone counts are separate.",
                "Stable RSS over these finite cycles does not prove the absence of every leak.",
                "RSS and file-page residency are not PSS, USS or exclusive physical memory."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = derive(args.private)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"runs": len(result["rows"]), "validated": True}))


if __name__ == "__main__":
    main()
