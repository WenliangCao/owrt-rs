#!/usr/bin/env python3
"""Verify and summarize the frozen R131 router event-fanout series.

The exact event caller reports aggregate CPU clocks and wall time.  It does
not retain per-operation latency samples, so this report never invents p95 or
p99 values; those gates are recorded as unassessed.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUBJECTS = ("c", "r124", "r131")
LANES = ("user_1_1", "user_8_1", "user_1_0")
METRICS = ("wall_us_op", "daemon_cpu_us_op", "caller_cpu_us_op")
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config",
          "same_production_identity", "same_host_mounts")
SOCKET_CMDLINE = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"


def check(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def hash_rows(path: Path) -> dict[str, str]:
    rows = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        check(len(parts) == 2 and len(parts[0]) == 64, f"invalid hash row: {path}")
        check(parts[1] not in rows, f"duplicate hash row: {path}")
        rows[parts[1]] = parts[0]
    return rows


def proc_identity(path: Path) -> tuple[int, int]:
    text = path.read_text().strip()
    left, right = text.split(") ", 1)
    pid = int(left.split(" (")[0])
    fields = right.split()
    check(len(fields) >= 20 and fields[0] in {"R", "S", "D", "I"},
          f"invalid live process stat: {path}")
    return pid, int(fields[19])


def verify_plan(plan: dict) -> None:
    check(plan["schema_version"] == 1 and plan["component"] == "ubusd", "invalid plan")
    check(plan["iterations"] == 5000 and plan["warmup"] == 20, "counts changed")
    check(set(plan["subjects"]) == set(SUBJECTS), "subject set changed")
    expected = [label for permutation in plan["permutations"] for label in permutation]
    check([row["label"] for row in plan["runs"]] == expected, "schedule changed")
    for label, subject in plan["subjects"].items():
        path = ROOT / subject["path"]
        check(path.is_file() and digest(path) == subject["sha256"], f"subject hash: {label}")
    for name, entry in plan["files"].items():
        path = ROOT / entry["path"]
        check(path.is_file() and digest(path) == entry["sha256"], f"input hash: {name}")


def metrics(raw: Path, lane: str, plan: dict, subject: str) -> dict:
    data = read_json(raw / f"{lane}.json")
    check(data["n"] == plan["iterations"] and data["warmup"] == plan["warmup"], f"{lane}: counts")
    check(data["subject_cpu"] == 1 and data["client_cpu"] == 0, f"{lane}: affinity")
    check(data["payload_checked"] is True and data["handlers_removed"] is True, f"{lane}: payload gate")
    expected_received = plan["iterations"] * (8 if lane == "user_8_1" else 1 if lane == "user_1_1" else 0)
    check(data["received"] == expected_received, f"{lane}: receive count")
    check(data["subject_pid"] == read_json(raw / "meta.json")["subject_pid"], f"{lane}: subject PID")
    n = data["n"]
    values = {
        "wall_us_op": (data["wall_after_ns"] - data["wall_before_ns"]) / n / 1000,
        "daemon_cpu_us_op": (data["subject_after_ns"] - data["subject_before_ns"]) / n / 1000,
        "caller_cpu_us_op": (data["client_after_ns"] - data["client_before_ns"]) / n / 1000,
    }
    check(all(math.isfinite(value) and value > 0 for value in values.values()), f"{lane}: metrics")
    return values


def verify_window(root: Path, plan: dict, run: dict) -> dict:
    label = run["label"]
    name = f"{run['index']:02d}-{label}"
    window = root / name
    result = read_json(window / "result.json")
    check(all(result.get(key) is True for key in HEALTH), f"{name}: health/cleanup")
    check(result["exit"] == 0 and result["component"] == "ubusd" and result["pilot_only"] is True,
          f"{name}: driver mode")
    implementation = "c" if label == "c" else "rs"
    check(result["implementation"] == implementation, f"{name}: implementation")
    check(result["candidate_sha256"] == plan["subjects"][label]["sha256"], f"{name}: candidate")
    for key, entry in plan["files"].items():
        if key in {"namespace_helper", "harness"}:
            continue
        if key == "event_benchmark":
            check(result["event_benchmark_sha256"] == entry["sha256"], f"{name}: event helper")
        else:
            check(result.get(f"{key}_sha256") == entry["sha256"], f"{name}: {key}")
    for phase in ("before", "after"):
        health = read_json(window / f"health-{phase}.json")
        check(health["boot_id"] == plan["boot_id"], f"{name}: boot")
        check((window / f"raw/daemon-{phase}.cmdline").read_bytes() == SOCKET_CMDLINE,
              f"{name}: daemon argv")
        check(hash_rows(window / f"raw/daemon-{phase}.exe-sha256") == {
            f"/proc/{read_json(window / 'raw/meta.json')['subject_pid']}/exe": plan["subjects"][label]["sha256"]
        }, f"{name}: daemon ELF")
    raw = window / "raw"
    check(hash_rows(raw / "binary-sha256.txt") == {
        "/sbin/ubusd" if label == "c" else "/tmp/bin/ubusd-rs": plan["subjects"][label]["sha256"]
    }, f"{name}: binary")
    check(hash_rows(raw / "benchmark-sha256.txt") == {
        "/tmp/bin/owrt-benchmark": plan["files"]["benchmark"]["sha256"],
        "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"],
    }, f"{name}: daemon helper")
    for filename in ("benchmark-after-sha256.txt",):
        check(hash_rows(raw / filename) == {
            "/tmp/bin/owrt-benchmark": plan["files"]["benchmark"]["sha256"],
            "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"],
        }, f"{name}: after helper")
    for filename in ("event-benchmark-sha256.txt", "event-benchmark-after-sha256.txt"):
        check(hash_rows(raw / filename) == {
            "/tmp/bin/event-benchmark": plan["files"]["event_benchmark"]["sha256"]
        }, f"{name}: event helper evidence")
    check(hash_rows(raw / "harness-sha256.txt") == {
        "/tmp/workload.sh": plan["files"]["workload"]["sha256"]
    }, f"{name}: harness")
    meta = read_json(raw / "meta.json")
    check(meta["subject_cpu"] == 1 and meta["client_cpu"] == 0 and meta["daemon_argv0"] == "/sbin/ubusd",
          f"{name}: workload metadata")
    lane_metrics = {lane: metrics(raw, lane, plan, label) for lane in LANES}
    return {"index": run["index"], "label": label, "block": (run["index"] - 1) // 3 + 1,
            "metrics": lane_metrics}


def paired(windows: list[dict], lane: str, metric: str, baseline: str) -> dict:
    values = []
    for block in range(1, 7):
        rows = {row["label"]: row for row in windows if row["block"] == block}
        values.append((rows["r131"]["metrics"][lane][metric] /
                       rows[baseline]["metrics"][lane][metric] - 1) * 100)
    return {"paired_delta_pct": values, "median_delta_pct": statistics.median(values),
            "all_lower": all(value < 0 for value in values),
            "all_higher": all(value > 0 for value in values),
            "range_delta_pct": [min(values), max(values)]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    plan = read_json(args.plan)
    verify_plan(plan)
    expected = {f"{row['index']:02d}-{row['label']}" for row in plan["runs"]}
    actual = {path.name for path in args.root.iterdir() if path.is_dir() and path.name[:2].isdigit()}
    check(actual == expected, "window set differs from frozen schedule")
    windows = [verify_window(args.root, plan, row) for row in plan["runs"]]
    comparison = {
        f"r131_vs_{baseline}/{lane}/{metric}": paired(windows, lane, metric, baseline)
        for baseline in ("r124", "c") for lane in LANES for metric in METRICS
    }
    primary = {
        metric: comparison[f"r131_vs_r124/user_8_1/{metric}"]
        for metric in METRICS
    }
    guards = {
        lane: {metric: comparison[f"r131_vs_r124/{lane}/{metric}"] for metric in METRICS}
        for lane in ("user_1_1", "user_1_0")
    }
    decision = {
        "primary_mean_gate": all(item["all_lower"] and item["median_delta_pct"] <= -3 for item in primary.values()),
        "primary_metrics": list(primary),
        "daemon_cpu_regression_gate": primary["daemon_cpu_us_op"]["median_delta_pct"] > 5,
        "guard_clear_regression": any(
            any(item["all_higher"] and item["median_delta_pct"] > 5 for item in lane.values())
            for lane in guards.values()
        ),
        "p95_p99": "unassessed: exact event caller records aggregate clocks, not per-operation samples",
    }
    decision["verdict"] = "accept_mean_cpu_wall_experiment" if (
        decision["primary_mean_gate"] and not decision["daemon_cpu_regression_gate"] and
        not decision["guard_clear_regression"]
    ) else "reject_or_defer"
    report = {
        "schema_version": 1,
        "scope": "Physical router R131/R124/C event fanout; router-04 only",
        "plan_sha256": digest(args.plan),
        "reporter_sha256": digest(Path(__file__)),
        "windows": windows,
        "comparison_r131_vs_r124": {key: value for key, value in comparison.items() if key.startswith("r131_vs_r124/")},
        "comparison_r131_vs_c": {key: value for key, value in comparison.items() if key.startswith("r131_vs_c/")},
        "decision": decision,
        "limitations": [
            "Six paired blocks are an engineering gate, not a statistical equivalence claim.",
            "The exact event caller reports aggregate wall and process CPU clocks only; p95/p99 are unavailable.",
            "The primary workload is one listener connection with eight handlers.",
            "This report does not establish memory or nine-component integration behavior.",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
