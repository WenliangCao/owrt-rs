#!/usr/bin/env python3
"""Verify the separately frozen R131 router latency supplement."""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("c", "r124", "r131")
LANES = ("user_1_1", "user_8_1", "user_1_0")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "wall_us_op",
           "daemon_cpu_us_op", "caller_cpu_us_op")
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config",
          "same_production_identity", "same_host_mounts")
CMDLINE = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"


def check(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def hashes(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        sha, name = line.split(maxsplit=1)
        check(len(sha) == 64 and name not in result, f"invalid hash row: {path}")
        result[name] = sha
    return result


def load_plan(path):
    plan = read(path)
    check(plan["schema_version"] == 1 and plan["component"] == "ubusd", "schema")
    check(plan["iterations"] == 5000 and plan["warmup"] == 200, "frozen counts")
    check(set(plan["subjects"]) == set(LABELS), "frozen subjects")
    expected = list(itertools.permutations(LABELS))
    check(plan["permutations"] == [list(row) for row in expected], "frozen permutations")
    check(plan["runs"] == [{"index": i, "label": label}
          for i, label in enumerate(itertools.chain.from_iterable(expected), 1)], "schedule")
    for group in (plan["subjects"], plan["files"]):
        for name, entry in group.items():
            check(digest(ROOT / entry["path"]) == entry["sha256"], f"input hash: {name}")
    check(digest(__file__) == plan["reporter_sha256"], "reporter hash")
    check(digest(ROOT / "tools/r131_latency_runner.py") == plan["orchestrator_sha256"], "runner hash")
    prerequisite = plan["prerequisites"]["oracle_helper_functional_smoke"]
    check(digest(ROOT / prerequisite["path"]) == prerequisite["sha256"], "Oracle smoke hash")
    smoke = read(ROOT / prerequisite["path"])
    check(smoke["passed"] is True and smoke["helper_sha256"] == plan["files"]["event_benchmark"]["sha256"] and
          len(smoke["rows"]) == 9, "Oracle helper validation")
    check(plan["acceptance"] == {
        "primary": "user_8_1 sample mean: six paired R131/R124 blocks lower and median <= -3%",
        "reject_tail_cpu": "user_8_1 p95, p99, or daemon CPU/op paired median > +5% is not accepted",
        "guards": "user_1_1 and user_1_0: any wall/daemon/caller metric six positive pairs and median > +5% is not accepted",
        "practical_tie_band_pct": 1,
        "no_extensions": True,
    }, "acceptance changed")
    return plan


def sample_metrics(data, n, warmup, lane, subject_pid):
    _, listeners, matched = lane.split("_")
    listeners, matched = int(listeners), bool(int(matched))
    check(data["n"] == n and data["warmup"] == warmup, f"{lane}: counts")
    check(data["listeners"] == listeners and data["matched"] is matched, f"{lane}: fixture")
    check(data["subject_pid"] == subject_pid != data["client_pid"], f"{lane}: pid")
    check(data["subject_cpu"] == 1 and data["client_cpu"] == 0, f"{lane}: affinity")
    check(data["payload_checked"] is True and data["handlers_removed"] is True, f"{lane}: validation")
    check(data["received"] == n * listeners * matched and
          data["warmup_received"] == warmup * listeners * matched, f"{lane}: callbacks")
    check(data["held_clients"] == 0 and data["held_fds"] == data["base_fds"] > 0, f"{lane}: fds")
    check(data["latency_clock"] == "CLOCK_MONOTONIC" and
          data["latency_scope"] == "send_through_all_callbacks_or_unmatched_drain" and
          data["latency_overhead_unsubtracted"] is True, f"{lane}: sample definition")
    check(data["subject_resolution_ns"] == data["client_resolution_ns"] ==
          data["latency_resolution_ns"] == 1, f"{lane}: clock resolution")
    values = data["latency_ns"]
    check(data["latency_sample_count"] == len(values) == n, f"{lane}: sample count")
    check(all(type(value) is int and value > 0 for value in values), f"{lane}: sample value")
    elapsed = {clock: data[f"{clock}_after_ns"] - data[f"{clock}_before_ns"]
               for clock in ("wall", "subject", "client")}
    check(all(type(value) is int and value > 0 for value in elapsed.values()), f"{lane}: clocks")
    check(sum(values) <= elapsed["wall"], f"{lane}: samples exceed enclosing wall clock")
    check(elapsed["subject"] <= elapsed["wall"] and elapsed["client"] <= elapsed["wall"], f"{lane}: CPU clock")
    ordered = sorted(values)
    result = {"mean_us": statistics.mean(values) / 1000,
              "wall_us_op": elapsed["wall"] / n / 1000,
              "daemon_cpu_us_op": elapsed["subject"] / n / 1000,
              "caller_cpu_us_op": elapsed["client"] / n / 1000}
    for name, q in (("p50_us", .5), ("p95_us", .95), ("p99_us", .99)):
        result[name] = ordered[math.floor((n - 1) * q + .5)] / 1000
    return result


def verify_window(root, plan, run):
    label, index = run["label"], run["index"]
    window = Path(root) / f"{index:02d}-{label}"
    raw = window / "raw"
    result, meta = read(window / "result.json"), read(raw / "meta.json")
    check(all(result.get(key) is True for key in HEALTH), f"{window.name}: health")
    check(result["exit"] == 0 and result["component"] == "ubusd" and
          result["production_mode"] == "stock" and result["installed"] is False and
          result["pilot_only"] is True and result["matrix"] is False and
          result["correctness_smoke_only"] is False and result["iterations"] == 5000,
          f"{window.name}: collection mode")
    implementation = "c" if label == "c" else "rs"
    sha = plan["subjects"][label]["sha256"]
    check(result["implementation"] == implementation and result["candidate_sha256"] == sha,
          f"{window.name}: candidate")
    for key in ("driver", "workload", "guard", "recovery_gate", "benchmark", "event_benchmark"):
        check(result[f"{key}_sha256"] == plan["files"][key]["sha256"], f"{window.name}: {key}")
    expected_meta = {"subject_pid": meta["subject_pid"], "subject_cpu": 1, "client_cpu": 0,
                     "implementation": implementation, "iterations": 5000, "warmup": 200,
                     "scenarios": list(LANES), "exact_image_caller": True,
                     "daemon_argv0": "/sbin/ubusd", "per_operation_latency": True,
                     "latency_clock": "CLOCK_MONOTONIC"}
    check(meta == expected_meta, f"{window.name}: metadata")
    starttimes = []
    for phase in ("before", "after"):
        check(read(window / f"health-{phase}.json")["boot_id"] == plan["boot_id"], f"{window.name}: boot")
        check((raw / f"daemon-{phase}.cmdline").read_bytes() == CMDLINE, f"{window.name}: argv")
        check(hashes(raw / f"daemon-{phase}.exe-sha256") == {f'/proc/{meta["subject_pid"]}/exe': sha},
              f"{window.name}: executable")
        status = dict(line.split(":", 1) for line in (raw / f"daemon-{phase}.status").read_text().splitlines() if ":" in line)
        check(int(status["Pid"]) == meta["subject_pid"] and int(status["Threads"]) == 1 and
              status["Cpus_allowed_list"].strip() == "1", f"{window.name}: live daemon status")
        starttimes.append((raw / f"daemon-{phase}.starttime").read_text().strip())
    check(len(set(starttimes)) == 1 and starttimes[0].isdigit(), f"{window.name}: daemon replaced")
    for prefix, expected in (
        ("binary", {"/sbin/ubusd" if label == "c" else "/tmp/bin/ubusd-rs": sha}),
        ("benchmark", {"/tmp/bin/owrt-benchmark": plan["files"]["benchmark"]["sha256"],
                       "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"]}),
        ("event-benchmark", {"/tmp/bin/event-benchmark": plan["files"]["event_benchmark"]["sha256"]}),
    ):
        for suffix in ("-sha256.txt", "-after-sha256.txt"):
            check(hashes(raw / f"{prefix}{suffix}") == expected, f"{window.name}: {prefix} identity")
    check(hashes(raw / "harness-sha256.txt") == {"/tmp/workload.sh": plan["files"]["workload"]["sha256"]}, f"{window.name}: harness")
    check(not (raw / "objects-before.txt").read_text().strip() and
          not (raw / "objects-after.txt").read_text().strip(), f"{window.name}: leaked objects")
    check(read(raw / "summary.json") == {"daemon_pid": meta["subject_pid"], "iterations": 5000,
          "warmup": 200, "scenarios": 3, "serial_client": True, "event_payload_validated": True,
          "per_operation_latency": True}, f"{window.name}: summary")
    check((raw / "COMPLETE").is_file(), f"{window.name}: incomplete")
    return {"index": index, "label": label, "block": (index - 1) // 3 + 1,
            "metrics": {lane: sample_metrics(read(raw / f"{lane}.json"), 5000, 200, lane,
                                             meta["subject_pid"]) for lane in LANES},
            "raw_sha256": digest(window / "raw.tar.gz"), "result_sha256": digest(window / "result.json")}


def paired(windows, lane, metric, baseline):
    values = []
    for block in range(1, 7):
        rows = {row["label"]: row for row in windows if row["block"] == block}
        values.append((rows["r131"]["metrics"][lane][metric] /
                       rows[baseline]["metrics"][lane][metric] - 1) * 100)
    return {"paired_delta_pct": values, "median_delta_pct": statistics.median(values),
            "all_lower": all(value < 0 for value in values), "all_higher": all(value > 0 for value in values),
            "range_delta_pct": [min(values), max(values)]}


def verdict(comparison):
    primary = comparison["user_8_1"]
    mean_pass = primary["mean_us"]["all_lower"] and primary["mean_us"]["median_delta_pct"] <= -3
    tail_cpu_fail = any(primary[key]["median_delta_pct"] > 5 for key in ("p95_us", "p99_us", "daemon_cpu_us_op"))
    guard_fail = any(comparison[lane][metric]["all_higher"] and comparison[lane][metric]["median_delta_pct"] > 5
                     for lane in ("user_1_1", "user_1_0")
                     for metric in ("wall_us_op", "daemon_cpu_us_op", "caller_cpu_us_op"))
    return {"primary_mean_pass": mean_pass, "tail_cpu_fail": tail_cpu_fail, "guard_fail": guard_fail,
            "verdict": "pass_latency_supplement" if mean_pass and not tail_cpu_fail and not guard_fail else "not_accepted"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    plan = load_plan(args.plan)
    check((args.root / "COMPLETE").is_file(), "series incomplete")
    expected = {f'{row["index"]:02d}-{row["label"]}' for row in plan["runs"]}
    actual = {path.name for path in args.root.iterdir() if path.is_dir() and path.name[:2].isdigit()}
    check(actual == expected, "window set differs")
    windows = [verify_window(args.root, plan, run) for run in plan["runs"]]
    comparisons = {baseline: {lane: {metric: paired(windows, lane, metric, baseline) for metric in METRICS}
                              for lane in LANES} for baseline in ("r124", "c")}
    report = {"schema_version": 1, "scope": "R131 exact caller router latency supplement",
              "plan_sha256": digest(args.plan), "reporter_sha256": digest(__file__),
              "windows": windows, "comparisons": comparisons, "decision": verdict(comparisons["r124"]),
              "all_windows_cleaned_and_stock": True,
              "limitations": ["Six paired blocks are an engineering gate, not an equivalence proof.",
                              "Samples include two monotonic clock calls and callback validation; no overhead is subtracted.",
                              "Each p99 is a within-window percentile; samples are not independent router windows.",
                              "This supplement does not cover other fanout layouts, memory, or nine-component integration."]}
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
