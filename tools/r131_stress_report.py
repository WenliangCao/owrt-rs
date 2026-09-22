#!/usr/bin/env python3
"""Verify the separately frozen R131 owner/monitor/backpressure supplement."""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path
import statistics
from r124_event_memory_report import verify_archive

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("c", "r124", "r131")
LANES = ("grouped", "interleaved", "monitor")
METRICS = ("mean_us", "wall_us_op", "p50_us", "p95_us", "p99_us", "daemon_cpu_us_op", "caller_cpu_us_op")
GUARDS = ("mean_us", "wall_us_op", "p95_us", "p99_us", "daemon_cpu_us_op")
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config", "same_production_identity", "same_host_mounts")
CMDLINE = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"


def check(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def hashes(path):
    rows = {}
    for line in Path(path).read_text().splitlines():
        sha, name = line.split(maxsplit=1)
        check(len(sha) == 64 and name not in rows, f"invalid hash row: {path}")
        rows[name] = sha
    return rows


def load_plan(path):
    plan = read(path)
    check(plan["schema_version"] == 1 and plan["component"] == "ubusd", "schema")
    check(plan["iterations"] == 2000 and plan["warmup"] == 20 and plan["slow_iterations"] == 192, "counts")
    check(set(plan["subjects"]) == set(LABELS), "subjects")
    perms = [list(row) for row in itertools.permutations(LABELS)]
    check(plan["permutations"] == perms, "permutations")
    check(plan["runs"] == [{"index": i, "label": label} for i, label in
                          enumerate(itertools.chain.from_iterable(perms), 1)], "schedule")
    for group in (plan["subjects"], plan["files"]):
        for name, entry in group.items():
            check(digest(ROOT / entry["path"]) == entry["sha256"], f"input hash: {name}")
    for name in ("reporter", "runner"):
        check(digest(ROOT / plan[name]["path"]) == plan[name]["sha256"], f"{name} hash")
    check(digest(ROOT / plan["helper_source"]["path"]) == plan["helper_source"]["sha256"], "helper source hash")
    smoke = plan["oracle_helper_validation"]
    check(digest(ROOT / smoke["path"]) == smoke["sha256"], "Oracle result hash")
    result = read(ROOT / smoke["path"])
    check(result["passed"] is True and result["helper_sha256"] == plan["files"]["event_benchmark"]["sha256"]
          and len(result["cases"]) == 12 and all(x["exit"] == 0 for x in result["cases"]), "Oracle cases")
    check({(r["label"], r["mode"]) for r in result["cases"]} == set(itertools.product(LABELS, (*LANES, "slow")))
          and all(r["sha256"] == plan["subjects"][r["label"]]["sha256"] for r in result["cases"]), "Oracle identities")
    check(plan["guard"] == {"metrics": list(GUARDS), "lanes": list(LANES),
                           "flag": "six R131/R124 paired deltas positive and median > 5%",
                           "functionality": "all cases mandatory", "no_extensions": True}, "guard changed")
    return plan


def verify_case(raw, lane, plan, sha):
    case = raw / lane
    check((case / "COMPLETE").is_file() and not (case / "helper.log").read_bytes(), f"{case}: incomplete/error")
    rows = [json.loads(line) for line in (case / "helper.jsonl").read_text().splitlines()]
    phases = ["empty", "registered", "flooded", "drained", "closed", "RESULT"] if lane == "slow" else ["empty", "registered", "delivered", "closed", "RESULT"]
    check([row["phase"] for row in rows] == phases, f"{case}: phases")
    result = rows[-1]
    slow = lane == "slow"
    n, warmup = (192, 0) if slow else (2000, 20)
    owners = 1 if lane in ("slow", "monitor") else 2
    pid = result["subject_pid"]
    check(result["mode"] == lane and result["n"] == n and result["warmup"] == warmup and
          result["handlers"] == 8 and result["owners"] == owners and
          result["subject_cpu"] == 1 and result["client_cpu"] == 0, f"{case}: fixture")
    for field in ("payload_target_order_sequence_checked", "handlers_removed", "fd_baseline_restored"):
        check(result[field] is True, f"{case}: {field}")
    check(result["c_txq_limit_bytes"] == 1048576 and result["payload_bytes"] == (2048 if slow else 0), f"{case}: bounds")
    if slow:
        check(0 < result["flooded_received"] < n * 8 and
              result["received"] == result["flooded_received"] + 8 and result["mirrored"] == 0,
              f"{case}: cap/recovery")
    else:
        check(result["received"] == n * 8 and result["mirrored"] == (n * 8 if lane == "monitor" else 0)
              and result["flooded_received"] == 0, f"{case}: event count")
    baseline = rows[0]["fds"]
    check(baseline > 0 and rows[-2]["fds"] == baseline, f"{case}: fd restoration")
    for row in rows[:-1]:
        check(row["subject_pid"] == pid and all(type(row[x]) is int and row[x] >= 0
              for x in ("rss_kib", "rssanon_kib", "vmdata_kib", "fds")), f"{case}: memory sample")
    for row in rows[1:-2]:
        check(row["fds"] == baseline + owners + 1 + (lane == "monitor"), f"{case}: live connections")
    starts = []
    for phase in ("before", "after"):
        check((case / f"{phase}.cmdline").read_bytes() == CMDLINE, f"{case}: argv")
        check(hashes(case / f"{phase}.exe-sha256") == {f"/proc/{pid}/exe": sha}, f"{case}: executable")
        status = dict(line.split(":", 1) for line in (case / f"{phase}.status").read_text().splitlines() if ":" in line)
        check(int(status["Pid"]) == pid and int(status["Threads"]) == 1 and status["Cpus_allowed_list"].strip() == "1", f"{case}: status")
        starts.append((case / f"{phase}.starttime").read_text().strip())
    check(starts[0].isdigit() and starts[0] == starts[1], f"{case}: process replacement")
    check(not (case / "objects-after.txt").read_text().strip(), f"{case}: objects leaked")
    samples = result["latency_ns"]
    check(len(samples) == n and all(type(v) is int and v > 0 for v in samples), f"{case}: samples")
    check(0 < sum(samples) <= result["wall_ns"] and
          all(0 < result[x] <= result["wall_ns"] for x in ("daemon_cpu_ns", "caller_cpu_ns")), f"{case}: clocks")
    ordered = sorted(samples)
    metrics = {"mean_us": statistics.mean(samples) / 1000, "wall_us_op": result["wall_ns"] / n / 1000,
               "daemon_cpu_us_op": result["daemon_cpu_ns"] / n / 1000, "caller_cpu_us_op": result["caller_cpu_ns"] / n / 1000}
    for name, q in (("p50_us", .5), ("p95_us", .95), ("p99_us", .99)):
        metrics[name] = ordered[math.floor((n - 1) * q + .5)] / 1000
    return {"metrics": metrics, "memory_diagnostic": rows[:-1], "flooded_received": result["flooded_received"],
            "received": result["received"], "mirrored": result["mirrored"], "functional_pass": True}


def verify_window(root, plan, run):
    label, index = run["label"], run["index"]
    window = Path(root) / f"{index:02d}-{label}"
    raw = window / "raw"
    result = read(window / "result.json")
    check(all(result.get(k) is True for k in HEALTH) and result["exit"] == 0, f"{window.name}: health")
    impl = "c" if label == "c" else "rs"
    sha = plan["subjects"][label]["sha256"]
    check(result["component"] == "ubusd" and result["implementation"] == impl and
          result["candidate_sha256"] == sha and result["iterations"] == 2000 and
          result["pilot_only"] is True and result["matrix"] is False and result["installed"] is False and
          result["production_mode"] == "stock", f"{window.name}: driver mode")
    for key in ("driver", "workload", "guard", "recovery_gate", "benchmark", "event_benchmark"):
        check(result[f"{key}_sha256"] == plan["files"][key]["sha256"], f"{window.name}: {key}")
    for phase in ("before", "after"):
        check(read(window / f"health-{phase}.json")["boot_id"] == plan["boot_id"], f"{window.name}: boot")
    check(read(raw / "meta.json") == {"implementation": impl, "iterations": 2000, "slow_iterations": 192,
          "subject_cpu": 1, "client_cpu": 0, "daemon_argv0": "/sbin/ubusd", "cases": list(LANES) + ["slow"]}, f"{window.name}: metadata")
    check(hashes(raw / "binary-sha256.txt") == {"/sbin/ubusd" if label == "c" else "/tmp/bin/ubusd-rs": sha}, f"{window.name}: binary")
    check(hashes(raw / "benchmark-sha256.txt") == {"/tmp/bin/owrt-benchmark": plan["files"]["benchmark"]["sha256"],
          "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"]}, f"{window.name}: helpers")
    for filename in ("event-benchmark-sha256.txt", "event-benchmark-after-sha256.txt"):
        check(hashes(raw / filename) == {"/tmp/bin/event-benchmark": plan["files"]["event_benchmark"]["sha256"]}, f"{window.name}: event helper")
    check(hashes(raw / "workload-sha256.txt") == {"/tmp/workload.sh": plan["files"]["workload"]["sha256"]}, f"{window.name}: workload")
    check(hashes(raw / "libraries.sha256") == plan["runtime_libraries"], f"{window.name}: libraries")
    check((raw / "COMPLETE").is_file(), f"{window.name}: incomplete")
    verify_archive(window)
    cases = {lane: verify_case(raw, lane, plan, sha) for lane in (*LANES, "slow")}
    return {"index": index, "label": label, "block": (index - 1) // 3 + 1, "cases": cases,
            "raw_sha256": digest(window / "raw.tar.gz"), "result_sha256": digest(window / "result.json")}


def paired(windows, lane, metric, baseline):
    values = []
    for block in range(1, 7):
        rows = {row["label"]: row for row in windows if row["block"] == block}
        values.append((rows["r131"]["cases"][lane]["metrics"][metric] / rows[baseline]["cases"][lane]["metrics"][metric] - 1) * 100)
    return {"paired_delta_pct": values, "median_delta_pct": statistics.median(values),
            "all_lower": all(x < 0 for x in values), "all_higher": all(x > 0 for x in values)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path); parser.add_argument("root", type=Path); parser.add_argument("output", type=Path)
    args = parser.parse_args(); plan = load_plan(args.plan)
    check((args.root / "COMPLETE").is_file(), "series incomplete")
    expected = {f'{r["index"]:02d}-{r["label"]}' for r in plan["runs"]}
    check({p.name for p in args.root.iterdir() if p.is_dir() and p.name[:2].isdigit()} == expected, "window set")
    windows = [verify_window(args.root, plan, run) for run in plan["runs"]]
    comparison = {baseline: {lane: {metric: paired(windows, lane, metric, baseline) for metric in METRICS}
                             for lane in LANES} for baseline in ("r124", "c")}
    flags = [f"{lane}/{metric}" for lane in LANES for metric in GUARDS
             if comparison["r124"][lane][metric]["all_higher"] and comparison["r124"][lane][metric]["median_delta_pct"] > 5]
    report = {"schema_version": 1, "scope": "R131 physical owner/monitor/slow-reader supplement",
              "plan_sha256": digest(args.plan), "reporter_sha256": digest(__file__), "windows": windows,
              "comparisons": comparison, "decision": {"all_functional_pass": True, "regression_flags": flags,
              "verdict": "flag_for_review" if flags else "pass_supplement"},
              "limitations": ["Six paired blocks are an engineering regression gate, not equivalence proof.",
                              "Immediate memory snapshots are diagnostic; settled memory is measured separately.",
                              "Slow sender-ack latency is not normal event delivery latency; no performance gate uses it.",
                              "Monitor checks order and sequence within each stream; it does not establish cross-socket mirror/delivery wall-clock order.",
                              "Per-owner poll and payload validation are inside latency; the caller's latency array is not prefaulted. All subjects use this identical instrument.",
                              "Oracle flooded survivors: C/R124 542 versus R131 574. Kernel packing is a plausible explanation, not a demonstrated mechanism; all surviving frames and recovery passed."]}
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(json.dumps(report["decision"], sort_keys=True))


if __name__ == "__main__":
    main()
