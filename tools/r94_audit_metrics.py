#!/usr/bin/env python3
"""Recheck R94's saved device results; does not contact or modify a device."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


RESULTS = {
    "logd": "device-r94-01-derived/logd",
    "httpd": "device-r94-03-derived/httpd",
    "rpcd": "device-rpcd-01/report",
    "procd": "device-procd-02/report",
    "ubusd": "device-ubusd-01/report",
    "netifd": "device-netifd-02/report",
    "fw4": "device-fw4-02/report",
    "uci": "device-uci-01/report",
    "reload-config": "device-rc-01/report",
}
METRICS = ("subject_cpu_us_per_op", "mean_us", "p50_us", "p95_us", "p99_us")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="ignored private/r94 directory")
    parser.add_argument("output", type=Path, help="derived, shareable JSON")
    args = parser.parse_args()
    output = {
        "schema_version": 1,
        "scope": "74 workload lanes, separately built R94 device candidates; not final HEAD or integrated deployment",
        "method": "Median of four per-run metrics, independently recomputed from runs. Range overlap is descriptive, not a statistical equivalence test. Positive deltas mean worse.",
        "components": {},
    }
    for component, relative in RESULTS.items():
        path = args.root / relative / "results.json"
        raw = path.read_bytes()
        data = json.loads(raw)
        result = {
            "source": path.as_posix(),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "subjects": data["subjects"],
            "workloads": len(data["summary"]),
            "observations": len(data["runs"]),
            "comparison_counts": {},
            "not_strictly_lower": [],
            "resident_kib_or_count": {},
        }
        for baseline in ("stock", "r89"):
            counts = {metric: {"lower": 0, "equal": 0, "higher": 0,
                               "higher_disjoint_ranges": 0} for metric in METRICS}
            for lane, sides in data["summary"].items():
                for metric in METRICS:
                    stats = {}
                    for side in ("candidate", baseline):
                        samples = [r[metric] for r in data["runs"]
                                   if r["side"] == side and r["workload"] == lane]
                        assert len(samples) == 4, (component, lane, side, len(samples))
                        stats[side] = {"median": statistics.median(samples),
                                       "min": min(samples), "max": max(samples)}
                        for key, value in stats[side].items():
                            assert math.isclose(value, sides[side][metric][key], rel_tol=1e-10), (
                                component, lane, side, metric, key)
                    candidate, reference = stats["candidate"], stats[baseline]
                    delta = (candidate["median"] / reference["median"] - 1) * 100
                    overlap = (candidate["min"] <= reference["max"]
                               and reference["min"] <= candidate["max"])
                    status = "equal" if abs(delta) < 1e-9 else "higher" if delta > 0 else "lower"
                    counts[metric][status] += 1
                    if status == "higher" and not overlap:
                        counts[metric]["higher_disjoint_ranges"] += 1
                    if status != "lower":
                        result["not_strictly_lower"].append({
                            "baseline": baseline, "workload": lane, "metric": metric,
                            "delta_pct": delta, "ranges_overlap": overlap, **stats,
                        })
            result["comparison_counts"][baseline] = counts
        if data["resident"]:
            for metric in ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "Threads", "fds"):
                result["resident_kib_or_count"][metric] = {}
                for side in ("stock", "r89", "candidate"):
                    samples = [r[metric] for r in data["resident"] if r["side"] == side]
                    result["resident_kib_or_count"][metric][side] = {
                        "median": statistics.median(samples), "min": min(samples), "max": max(samples)}
        output["components"][component] = result
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"components": len(RESULTS), "workloads": sum(
        c["workloads"] for c in output["components"].values()), "output": str(args.output)}))


if __name__ == "__main__":
    main()
