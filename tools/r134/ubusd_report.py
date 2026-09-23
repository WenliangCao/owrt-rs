#!/usr/bin/env python3
"""Apply the frozen R134 sign rule to a complete analyze_candidate JSON.

Usage: ubusd_report.py DERIVED/results.json --output NEW_REPORT.json
Reads local derived evidence only; it does not collect or reverify raw archives.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import statistics


ORDER = ["stock", "candidate", "candidate", "stock"] * 4
RUNS = [f"{i:02d}-{side}" for i, side in enumerate(ORDER, 1)]
PAIRS = [(RUNS[i], RUNS[i + 1]) if ORDER[i] == "stock"
         else (RUNS[i + 1], RUNS[i]) for i in range(0, len(RUNS), 2)]
LANES = ("lookup", "lookup_all_64", "invoke", "lookup_c4", "lookup_all_64_c4",
         "invoke_c4", "lookup_prefix_64", "lookup_prefix_64_c4", "lookup_all_128",
         "lookup_all_128_c4", "register_1", "register_16", "event_1", "event_8",
         "event_nomatch")
LATENCY = ("mean_us", "p50_us", "p95_us", "p99_us")
CLOCK = "subject_own_cpu_clock_us_per_op"
TICKS = "subject_cpu_us_per_op"


def check(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def delta_pct(candidate, stock):
    return (candidate / stock - 1) * 100 if stock else None


def compare(values, classify=True):
    """Decision uses side medians and signs, not the median paired ratio."""
    pairs = [{"stock_run": stock, "candidate_run": candidate,
              "stock": values[stock], "candidate": values[candidate],
              "delta": values[candidate] - values[stock],
              "delta_pct": delta_pct(values[candidate], values[stock])}
             for stock, candidate in PAIRS]
    lower = sum(p["candidate"] < p["stock"] for p in pairs)
    higher = sum(p["candidate"] > p["stock"] for p in pairs)
    medians = {side: statistics.median(values[run] for run in RUNS if run.endswith("-" + side))
               for side in ("stock", "candidate")}
    decision = ("win" if medians["candidate"] < medians["stock"] and lower >= 7 else
                "loss" if medians["candidate"] > medians["stock"] and higher >= 7 else "tie")
    percentages = [p["delta_pct"] for p in pairs]
    result = {"pairs": pairs, "lower_pairs": lower, "higher_pairs": higher,
              "equal_pairs": 8 - lower - higher, "side_median": medians,
              "side_median_delta": medians["candidate"] - medians["stock"],
              "ratio_of_side_medians_delta_pct": delta_pct(medians["candidate"], medians["stock"]),
              "median_paired_delta_pct": statistics.median(percentages) if None not in percentages else None}
    if classify:
        result["decision"] = decision
    return result


def derive(data):
    check(data.get("schema_version") == 1 and data.get("component") == "ubusd"
          and data.get("matrix") is True, "expected ubusd matrix from analyze_candidate.py")
    check(data.get("host_gates_passed") is True and data.get("acceptance_eligible") is True
          and data.get("limitations") == [], "input is incomplete or ineligible")
    check(data.get("order") == ORDER and data.get("measured_sides") == ["stock", "candidate"],
          "expected exactly ABBA x4: stock/candidate, eight windows per side")
    for side in ("stock", "candidate"):
        check(digest(data["subjects"].get(side)), f"invalid {side} ELF hash")
    for key in ("benchmark_sha256", "namespace_sha256", "harness_sha256"):
        check(digest(data.get(key)), f"missing/invalid {key}")

    sources = data.get("sources", [])
    check(len(sources) == 16 and [s["run"] for s in sources] == RUNS,
          "expected sixteen ordered source archives")
    for source, side in zip(sources, ORDER):
        check(digest(source.get("archive_sha256")) and source.get("subject_sha256") == data["subjects"][side],
              f"invalid source identity: {source['run']}")

    rows = data.get("runs", [])
    check(len(rows) == 16 * len(LANES), "expected 240 rows: 16 windows x 15 lanes")
    indexed = {}
    for row in rows:
        run, lane = row["run"], row["workload"]
        check(run in RUNS and lane in LANES and row["side"] == ORDER[RUNS.index(run)],
              f"unexpected run/lane/side: {run}/{lane}")
        check((run, lane) not in indexed, f"duplicate row: {run}/{lane}")
        check(type(row.get("successful")) is int and row["successful"] == 10000
              and type(row.get("warmup")) is int and row["warmup"] == (80 if lane.endswith("_c4") else 20),
              f"unexpected operation counts: {run}/{lane}")
        for metric in LATENCY:
            check(number(row.get(metric)) and row[metric] > 0, f"invalid {metric}: {run}/{lane}")
        indexed[run, lane] = row
    check(set(indexed) == {(run, lane) for run in RUNS for lane in LANES}, "missing run/lane")
    have_clocks = [CLOCK in row for row in rows]
    check(all(have_clocks) or not any(have_clocks), "mixed process-clock availability; do not mix CPU instruments")
    cpu_field = CLOCK if all(have_clocks) else TICKS
    for row in rows:
        check(number(row.get(cpu_field)), f"invalid {cpu_field}: {row['run']}/{row['workload']}")
    metrics = {**{name: name for name in LATENCY}, "daemon_cpu_us_per_op": cpu_field}
    lanes = {lane: {name: compare({run: indexed[run, lane][field] for run in RUNS})
                    for name, field in metrics.items()} for lane in LANES}
    counts = Counter(result["decision"] for lane in lanes.values() for result in lane.values())

    residents = data.get("resident", [])
    check(len(residents) == 16, "expected sixteen resident snapshots")
    resident_rows = {}
    for row in residents:
        run = row["run"]
        check(run in RUNS and row["side"] == ORDER[RUNS.index(run)] and run not in resident_rows,
              f"invalid/duplicate resident row: {run}")
        for metric in ("RssAnon", "VmRSS"):
            check(number(row.get(metric)), f"invalid resident {metric}: {run}")
        resident_rows[run] = row
    resident = {metric: compare({run: resident_rows[run][metric] for run in RUNS}, classify=False)
                for metric in ("RssAnon", "VmRSS")}
    return {
        "schema_version": 1, "label": "R134 ubusd paired sign report", "component": "ubusd",
        "subjects": {side: data["subjects"][side] for side in ("stock", "candidate")},
        "tools": {key: data[key] for key in ("benchmark_sha256", "namespace_sha256", "harness_sha256")},
        "sources": sources, "order": ORDER,
        "pairing": [{"stock": stock, "candidate": candidate} for stock, candidate in PAIRS],
        "rule": "Lower side median and at least 7/8 lower pairs: win; higher side median and at least 7/8 higher pairs: loss; otherwise tie. No effect-size band.",
        "cpu_source_field": cpu_field,
        "cpu_clock_available": all(have_clocks),
        "lanes": lanes, "metric_decisions": {key: counts[key] for key in ("win", "loss", "tie")},
        "resident": {"unit": "KiB", "phase": "Immediately after the matrix; provider still holds 128 objects. Not an empty-bus idle baseline.",
                     "metrics": resident},
        "limitations": [
            "Uses complete analyze_candidate.py derived rows; raw archives are not reopened or independently verified here. Source archive hashes are preserved, not revalidated.",
            "Each adjacent AB/BA pair uses distinct windows; operation samples are not independent repetitions. The 75 metric decisions are reported individually, without a global pass or multiplicity-adjusted significance claim.",
            "A tie is the frozen decision rule's unresolved result, not statistical equivalence. Exact equal pairs do not count as lower or higher.",
            "event_1/event_8/event_nomatch measure ADD/REMOVE with object-event listeners, not user SEND events. No monitor/slow-reader/user-event acceptance is inferred.",
            "CPU uses process clocks when present in every row; otherwise explicit tick CPU fallback. analyze_candidate summary and Markdown use tick CPU even when its runs contain process clocks.",
            "Serial CPU covers timed operations; c4 daemon CPU uses the outer interval divided by timed plus warm-up operations. Latency quantiles are computed within each window, never pooled across windows.",
            "Resident deltas are descriptive; the frozen timing sign rule does not define a memory acceptance threshold. Correctness gates remain separate.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("derived", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.derived.read_bytes()
    data = json.loads(source, object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"nonfinite JSON: {value}")))
    result = derive(data)
    result["derived_json_sha256"] = hashlib.sha256(source).hexdigest()
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"windows": 16, "pairs": 8, "lanes": len(LANES),
                      "cpu_source_field": result["cpu_source_field"], **result["metric_decisions"]}))


if __name__ == "__main__":
    main()
