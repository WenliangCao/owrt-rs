#!/usr/bin/env python3
"""Independently recompute completed baseline traffic windows and planning floors.

Read-only. It does not import the primary analyzer or assess a candidate.
The frozen final comparison still needs fresh paired B/N windows and their W.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import struct

parser = argparse.ArgumentParser()
parser.add_argument("summary", type=Path)
parser.add_argument("raw", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
snapshot = args.summary.read_bytes()
summary = json.loads(snapshot)
expected = summary["identity"]["comparison"]
records = []
verified = 0
for published in summary["windows"]:
    folder = args.raw / "runs" / published["label"]
    if not (folder / "client.json").is_file():
        continue
    manifest = json.loads((args.raw / (published["label"] + ".archive.json")).read_text())
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((folder / name).read_bytes()).hexdigest() == digest
        verified += 1
    assert (folder / "elf.sha256").read_text().split()[0] == expected[published["side"]]
    assert (folder / "live.sha256").read_text().split()[0] == expected[published["side"]]
    client = json.loads((folder / "client.json").read_text())
    assert published["valid"], "do not silently select a subset of failed windows"
    for phase, seconds in (("warmup", 5), ("measurement", 20)):
        counts = client[phase]
        assert all(counts[k] == client["rate"] * seconds for k in ("scheduled", "sent", "correct"))
        assert all(counts[k] == 0 for k in ("timeout", "wrong", "transport_error", "scheduled_skipped"))
    samples = list(struct.iter_unpack("<QQQHHBBBB", (folder / "client.latencies.bin").read_bytes()))
    assert len(samples) == client["measurement"]["correct"]
    assert len({row[0] for row in samples}) == len(samples)
    assert all(row[5] == 0 and row[6] == 1 and row[8] == 0 for row in samples)
    times = sorted(row[1] for row in samples)
    p50 = times[(len(times) + 1) // 2 - 1] / 1e6
    p95 = times[(len(times) * 95 + 99) // 100 - 1] / 1e6
    endpoints = []
    for name in ("before.jsonl", "after.jsonl"):
        endpoints.append(json.loads((folder / name).read_text().splitlines()[0]))
    before, after = endpoints
    assert len(before["processes"]) == len(after["processes"]) == 1
    old, new = before["processes"][0], after["processes"][0]
    assert (old["pid"], old["starttime_ticks"]) == (new["pid"], new["starttime_ticks"])
    keys = ("user_ticks", "system_ticks", "waited_child_user_ticks", "waited_child_system_ticks")
    assert all(new[key] >= old[key] for key in keys)
    ticks = sum(new[key] - old[key] for key in keys)
    operations = client["warmup"]["correct"] + client["measurement"]["correct"]
    hz = before["clock_ticks_per_second"]
    assert hz == after["clock_ticks_per_second"] == 100
    cpu = ticks * 1e6 / hz / operations
    assert abs(p50 - published["latency_ms"]["p50"]) < 1e-12
    assert abs(p95 - published["latency_ms"]["p95"]) < 1e-12
    assert ticks == published["cpu_ticks"] and operations == published["cpu_operations"]
    assert abs(cpu - published["cpu_us_per_operation"]) < 1e-12
    records.append({"scene": published["scene"], "round": published["round"], "side": published["side"],
                    "p50_ms": p50, "p95_ms": p95, "cpu_ticks": ticks, "cpu_us": cpu, "operations": operations})

def spread(values):
    median = statistics.median(values)
    return {"median": median, "min": min(values), "max": max(values),
            "relative_full_range_pct": 100 * (max(values) - min(values)) / median,
            "rounds": values}

scenes = []
incomplete = []
for scene in sorted({row["scene"] for row in records}):
    sides = {side: sorted((r for r in records if r["scene"] == scene and r["side"] == side), key=lambda r: r["round"])
             for side in ("c", "rust")}
    if any([r["round"] for r in side] != [1, 2, 3, 4, 5] for side in sides.values()):
        incomplete.append({"scene": scene, "windows": {side: len(rows) for side, rows in sides.items()}})
        continue
    row = {"scene": scene}
    for side, values in sides.items():
        row[side] = {metric: spread([r[metric] for r in values]) for metric in ("p50_ms", "p95_ms", "cpu_us", "cpu_ticks")}
    baseline = row["rust"]
    operations = {r["operations"] for r in sides["rust"]}
    assert len(operations) == 1
    quantum = 1e6 / 100 / operations.pop()
    tick_range = baseline["cpu_ticks"]["max"] - baseline["cpu_ticks"]["min"]
    required_ticks = max(8, tick_range) + 1  # Strictly greater, odd five-round medians are integral.
    row["planning_only_floors"] = {
        "p50_baseline_full_range_us": 1000 * (baseline["p50_ms"]["max"] - baseline["p50_ms"]["min"]),
        "p95_baseline_full_range_us": 1000 * (baseline["p95_ms"]["max"] - baseline["p95_ms"]["min"]),
        "cpu_one_tick_us_per_operation": quantum,
        "cpu_precision_requires_more_than_us_per_operation": 8 * quantum,
        "cpu_observed_baseline_and_precision_minimum_integral_tick_gap": required_ticks,
        "cpu_minimum_integral_gap_us_per_operation": required_ticks * quantum,
        "cpu_minimum_integral_gap_pct": 100 * required_ticks * quantum / baseline["cpu_us"]["median"],
    }
    scenes.append(row)

report = {"status": "partial-baseline-independent-audit", "summary_sha256": hashlib.sha256(snapshot).hexdigest(),
          "scope": "Recomputed original C/deployed baseline only; no research candidate is evaluated.",
          "deployed_sha256": expected["rust"], "reference_sha256": expected["c"],
          "traffic_windows_verified": len(records), "archived_member_hashes_verified": verified,
          "all_recomputed_latency_and_cpu_values_match_primary_analyzer": True,
          "completed_five_pair_scenes": scenes, "incomplete_scenes_not_ranked": incomplete,
          "limitations": ["These are planning floors from this baseline series, not new acceptance thresholds.",
                          "Final W uses both fresh baseline and candidate ranges; candidate variation can raise the floor.",
                          "At least four of five fresh pairs must agree and every CPU window must have at least ten ticks.",
                          "Current data cannot prove remaining cost is irreducible or establish a candidate stopping point."]}
args.output.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"windows": len(records), "verified_members": verified, "complete_scenes": [r["scene"] for r in scenes]}))
