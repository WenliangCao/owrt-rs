#!/usr/bin/env python3
"""Verify local R136 completion evidence and report every frozen metric.

Reuses R134 timing/SEND and R131 memory/stress verification. This program never
collects evidence, retries windows, or accesses the router.
"""
import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
for path in (ROOT / "tools", ROOT / "tools/benchmark", ROOT / "tools/r134"):
    sys.path.insert(0, str(path))
import analyze_candidate
import ubusd_report as matrix_report
import ubusd_latency_report as send_report
import r131_memory_audit as memory_audit
import r131_memory_supplement as memory_collection
import r124_event_memory_report as memory_raw
import r131_stress_report as stress_report
from r130_registration_report import archive_hashes, check, digest, hashes, read
from make_completion_plan import CANDIDATE_SHA, C_SHA, HEALTH, RULES

COMPONENTS = {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"}
FLAGS = {"--guard": "guard", "--recovery-gate": "recovery_gate",
         "--benchmark": "benchmark", "--workload-script": "workload",
         "--event-benchmark": "event_benchmark"}


def argument(step, flag, default=None):
    argv = step["argv"]
    return argv[argv.index(flag) + 1] if flag in argv else default


def identity(plan, path):
    return {"path": path, "sha256": plan["input_sha256"][path]}


def step_tools(plan, step):
    result = {"driver": identity(plan, step["argv"][0])}
    result.update({key: identity(plan, argument(step, flag)) for flag, key in FLAGS.items()
                   if flag in step["argv"]})
    result["namespace_helper"] = {"sha256": plan["namespace_sha256"]}
    return result


def verify_health(window, plan):
    before, after = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
    check(before == after and before["mode"] == "stock" and before["boot_id"] == plan["boot_id"],
          f"{window}: unchanged production/boot health")
    check(set(before["verified_components"]) == COMPONENTS, f"{window}: nine production identities")
    return {phase: digest(window / f"health-{phase}.json") for phase in ("before", "after")}


def verify_guarded(root, plan, step):
    window = root / Path(step["driver_result"]).relative_to(plan["output"]).parent
    check(not any((window / name).exists() for name in ("FAILED", "FAILED.json", "failure.json")),
          f"{window}: failed attempt")
    result = read(window / "result.json")
    expected = {"component": "ubusd", "exit": 0, "installed": False,
                "production_mode": "stock", "implementation": argument(step, "--implementation", "rs"),
                "iterations": int(argument(step, "--iterations")),
                "candidate_sha256": plan["input_sha256"][step["argv"][2]],
                "pilot_only": "--pilot" in step["argv"], "matrix": False}
    check(all(result.get(key) is True for key in HEALTH), f"{window}: health/cleanup gate")
    check(all(type(result.get(key)) is type(value) and result[key] == value
              for key, value in expected.items()), f"{window}: collection mode/subject")
    for key, value in step_tools(plan, step).items():
        if key != "namespace_helper":
            check(result.get(key + "_sha256") == value["sha256"], f"{window}: {key} identity")
    check((window / "raw/COMPLETE").is_file(), f"{window}: incomplete raw evidence")
    verify_health(window, plan)
    return window


def primary_comparison(historical):
    """Keep the R134 descriptive calculation, replacing only the named decision."""
    check(historical["median_paired_delta_pct"] is not None and len(historical["pairs"]) == 8,
          "eight finite percentage pairs required")
    deltas = [(Fraction(str(pair["candidate"])) / Fraction(str(pair["stock"])) - 1) * 100
              for pair in historical["pairs"]]
    delta = statistics.median(deltas)
    decision = ("win" if delta < -1 and historical["lower_pairs"] >= 7 else
                "loss" if delta > 1 and historical["higher_pairs"] >= 7 else "tie")
    return {**historical, "historical_r134_decision": historical["decision"],
            "historical_r134_median_paired_delta_pct": historical["median_paired_delta_pct"],
            "median_paired_delta_pct": float(delta),
            "pairs": [{**pair, "delta_pct": float(change)} for pair, change in zip(historical["pairs"], deltas)],
            "decision": decision}


def timing_summary(lanes):
    converted = {lane: {metric: primary_comparison(value) for metric, value in metrics.items()}
                 for lane, metrics in lanes.items()}
    counts = {rule: Counter(value[field] for metrics in converted.values() for value in metrics.values())
              for rule, field in (("r136_primary", "decision"), ("r134_historical", "historical_r134_decision"))}
    higher = [{"lane": lane, "metric": metric, **value}
              for lane, metrics in converted.items() for metric, value in metrics.items()
              if value["median_paired_delta_pct"] > 0 or value["ratio_of_side_medians_delta_pct"] > 0]
    return {"lanes": converted,
            "decision_counts": {rule: {key: count[key] for key in ("win", "loss", "tie")}
                                for rule, count in counts.items()},
            "all_higher_medians": higher}


def analyze_matrix(root, plan):
    folder = root / "matrix"
    check((folder / "COMPLETE").is_file() and not (folder / "FAILED").exists(), "matrix incomplete")
    check({p.name for p in folder.iterdir() if p.is_dir()} == set(matrix_report.RUNS), "matrix window set")
    verify_health(folder, plan)
    settings = read(folder / "settings.json")
    check(settings["iterations"] == 10000 and settings["matrix"] is True and
          settings["extended"] is True and settings["schedule"] == "two-side-balanced" and
          settings["management_access"] == "wifi", "matrix frozen settings")
    archives, host_checks, production_identity = {}, [], None
    for run, side in zip(matrix_report.RUNS, matrix_report.ORDER):
        window = folder / run
        archives[run] = archive_hashes(window)
        snapshots = [read(window / f"host-{phase}.json") for phase in ("before", "after")]
        identities = [{(process["pid"], process["start_ticks"]) for process in snap["processes"]}
                      for snap in snapshots]
        check(identities[0] and identities[0] == identities[1] and
              all(len(identity) == len(snap["processes"]) for identity, snap in zip(identities, snapshots)),
              f"{run}: production process replaced/missing")
        check(production_identity is None or production_identity == identities[0],
              f"{run}: production processes changed between windows")
        production_identity = identities[0]
        check(snapshots[1]["uptime_s"] > snapshots[0]["uptime_s"], f"{run}: host clock regressed")
        raw = window / "raw"
        meta = read(raw / "meta.json")
        check(meta["implementation"] == ("c" if side == "stock" else "rs") and meta["iterations"] == 10000,
              f"{run}: matrix implementation/count")
        check((raw / "kernel.txt").read_text().strip() == "6.12.94", f"{run}: kernel identity")
        starts = set()
        for lane in matrix_report.LANES:
            if lane.endswith("_c4"):
                phases = [read(raw / lane / f"{phase}.json")["processes"] for phase in ("before", "after")]
                for processes in phases:
                    starts.add(next(p["start_ticks"] for p in processes if p["pid"] == meta["subject_pid"]))
            else:
                daemon = next(p for p in read(raw / f"{lane}.json")["daemon_cpu"] if p["pid"] == meta["subject_pid"])
                starts.update(daemon[phase]["start_ticks"] for phase in ("before", "after"))
        check(len(starts) == 1, f"{run}: measured daemon changed between lanes")
        host_checks.append({"run": run, "stable_process_count": len(production_identity),
                            **{f"host_{phase}_sha256": digest(window / f"host-{phase}.json")
                               for phase in ("before", "after")}})
    data = analyze_candidate.derive(folder, "R136 completion matrix")
    data["measured_sides"] = list(data["measured_sides"])
    check({side: data["subjects"][side] for side in ("stock", "candidate")} ==
          {side: value["sha256"] for side, value in plan["subjects"].items()}, "matrix subject identities")
    step = next(step for step in plan["steps"] if step["name"] == "matrix")
    check(data["benchmark_sha256"] == plan["input_sha256"][argument(step, "--bench")] and
          data["namespace_sha256"] == plan["namespace_sha256"] and
          data["harness_sha256"] == plan["input_sha256"]["tools/benchmark/isolated.sh"], "matrix tool identities")
    report = matrix_report.derive(data)
    check(report["cpu_clock_available"] and report["cpu_source_field"] == matrix_report.CLOCK,
          "matrix process CPU clocks required; tick fallback forbidden")
    return {**timing_summary(report["lanes"]), "windows_verified": 16,
            "sources": report["sources"], "tools": report["tools"], "order": report["order"],
            "records": data["runs"], "resident": report["resident"],
            "raw_files_verified": {run: len(values) for run, values in archives.items()},
            "production_process_verification": host_checks,
            "cpu_source_field": report["cpu_source_field"],
            "limits": [line for line in report["limitations"]
                       if not line.startswith(("Uses complete", "CPU uses process clocks"))] +
                      ["Every daemon CPU value uses its process clock; missing or mixed clocks are rejected. No tick fallback.",
                       "Daemon CPU1/normalized argv are enforced by the frozen harness; this matrix does not archive separate live argv/affinity snapshots."],
            "archive_verification": "Every expanded matrix file was reconciled against its raw archive."}


def analyze_send(root, plan):
    folder = root / "latency"
    steps = [step for step in plan["steps"] if step["name"].startswith("latency-")]
    check(len(steps) == 16, "SEND window count")
    for step in steps:
        verify_guarded(root, plan, step)
    # These immutable specifications were constants in R134. Rebind them only
    # inside this offline process; all raw verification and math stay identical.
    send_report.BOOT = plan["boot_id"]
    send_report.SUBJECTS = {side: value["sha256"] for side, value in plan["subjects"].items()}
    send_report.TOOLS = {key: value["sha256"] for key, value in step_tools(plan, steps[0]).items()}
    report = send_report.derive(folder)
    return {**timing_summary(report["lanes"]), "windows_verified": 16,
            "windows": report["windows"], "tools": report["tools"],
            "iterations": report["iterations"], "warmup": report["warmup"],
            "cpu_source": report["cpu_source"], "limits": report["limitations"]}


def memory_summary(windows):
    groups = defaultdict(lambda: {"stock": [], "candidate": []})
    def add(kind, fixture, measure, metric, window, value):
        if value != "NA":
            groups[kind, fixture, measure, metric][window["side"]].append(
                {"run": window["name"], "value": int(value)})
    for window in windows:
        kind = window["kind"]
        rows = window["memory"]
        if kind == "idle":
            for row in rows:
                for metric in ("rssanon", "vmrss", "vmdata", "pss"):
                    before, after = row[f"{metric}_before_kb"], row[f"{metric}_after_kb"]
                    for phase, value in (("before", before), ("after", after)):
                        add(kind, f"clients_{row['clients']}", phase, metric, window, value)
                    if before != "NA" and after != "NA":
                        add(kind, f"clients_{row['clients']}", "after_minus_before", metric,
                            window, int(after) - int(before))
        else:
            indexed = {(row["payload_bytes"], row["phase"], row["delay_seconds"]): row for row in rows}
            for row in rows:
                size, phase, delay = row["payload_bytes"], row["phase"], row["delay_seconds"]
                for metric in ("rssanon", "vmrss", "vmdata", "pss"):
                    value = row[metric + "_kb"]
                    add(kind, f"bytes_{size}", f"{phase}_{delay}s", metric, window, value)
                    if phase != "empty":
                        origin = indexed[size, "connected", delay] if phase == "held" else indexed[size, "empty", "0"]
                        if value != "NA" and origin[metric + "_kb"] != "NA":
                            add(kind, f"bytes_{size}", f"{phase}_{delay}s_minus_{origin['phase']}",
                                metric, window, int(value) - int(origin[metric + "_kb"]))
    result = []
    for (kind, fixture, measure, metric), sides in sorted(groups.items()):
        check(all(len(rows) == 2 for rows in sides.values()), "memory observation count/availability differs")
        medians = {side: statistics.median(row["value"] for row in rows) for side, rows in sides.items()}
        result.append({"kind": kind, "fixture": fixture, "measure": measure, "metric": metric,
                       "unit": "KiB", "observations": sides, "side_median": medians,
                       "candidate_minus_stock": medians["candidate"] - medians["stock"]})
    return {"measurements": result, "all_candidate_increases": [row for row in result if row["candidate_minus_stock"] > 0]}


def analyze_memory(root, plan):
    folder = root / "memory"
    check((folder / "COMPLETE").is_file(), "memory incomplete")
    check({p.name for p in folder.iterdir() if p.is_dir()} == {"idle", "large", "fanout"}, "memory fixture set")
    windows = []
    libraries = read(ROOT / "docs/reviews/r124-memory-plan-v2.json")["libraries"]
    for kind in ("idle", "large", "fanout"):
        check({p.name for p in (folder / kind).iterdir() if p.is_dir()} == set(matrix_report.RUNS[:4]), "memory window set")
        for index, (name, side) in enumerate(zip(matrix_report.RUNS[:4], matrix_report.ORDER[:4])):
            step = next(step for step in plan["steps"] if step["name"] == f"memory-{kind}-{name}")
            window = verify_guarded(root, plan, step)
            files = step_tools(plan, step)
            files[kind + "_helper"], files[kind + "_workload"] = files["benchmark"], files["workload"]
            spec = {"name": f"{kind}/{name}", "kind": kind, "subject": "c" if side == "stock" else side,
                    "order": 1 if index < 2 else 2}
            inputs = {"boot_id": plan["boot_id"], "subjects": {spec["subject"]: plan["subjects"][side]}, "files": files}
            base = memory_collection.verify_window(folder, spec, inputs)
            raw, archived = window / "raw", archive_hashes(window)
            executable = "/sbin/ubusd" if side == "stock" else "/tmp/bin/ubusd-rs"
            check(hashes(raw / "binary-sha256.txt") == {executable: plan["subjects"][side]["sha256"]}, "memory executable")
            helpers = {"/tmp/bin/owrt-benchmark": files["benchmark"]["sha256"],
                       "/tmp/bin/ns-exec": plan["namespace_sha256"]}
            if kind != "idle":
                helpers["/tmp/bin/guard"] = files["guard"]["sha256"]
                check(hashes(raw / "workload-sha256.txt") == {"/tmp/workload.sh": files["workload"]["sha256"]}, "memory workload")
                check(hashes(raw / "libraries.sha256") == libraries and
                      set((raw / "libraries-verified.txt").read_text().splitlines()) == {name + ": OK" for name in libraries}, "memory libraries")
                check((raw / "boot-id.txt").read_text().strip() == plan["boot_id"], "memory boot")
            check(hashes(raw / "benchmark-sha256.txt") == helpers, "memory helpers")
            metrics = memory_audit.audit_idle(window) if kind == "idle" else memory_audit.audit_event(window, spec, inputs)
            windows.append({**base, "side": side, "raw_files_verified": len(archived),
                            "proc_snapshot_verified": True, "memory": metrics})
    return {"windows_verified": len(windows), "windows": windows, **memory_summary(windows),
            "limits": ["Two windows per side/fixture; descriptive snapshots, not peaks, confidence intervals or equivalence tests.",
                       "VmRSS includes shared pages and is not system-wide savings; unavailable PSS stays NA.",
                       "Idle fixture has no archived live exe/cmdline/starttime/FD listing; it enforces CPU/FD transitions during collection.",
                       "Event fixtures reconcile live executable, PID/starttime, argv, FD transitions and requested settling delays."]}


def analyze_stress(root, plan):
    windows = []
    expected_libraries = read(ROOT / "docs/reviews/r124-memory-plan-v2.json")["libraries"]
    expected_libraries = {key: value for key, value in expected_libraries.items()
                          if "libblobmsg_json" not in key and "libjson-c" not in key}
    for side in ("stock", "candidate"):
        step = next(step for step in plan["steps"] if step["name"] == "correctness-stress-" + side)
        window = verify_guarded(root, plan, step)
        raw, files = window / "raw", step_tools(plan, step)
        archived = archive_hashes(window)
        check(read(raw / "meta.json") == {"implementation": "c" if side == "stock" else "rs",
              "iterations": 2000, "slow_iterations": 192, "subject_cpu": 1, "client_cpu": 0,
              "daemon_argv0": "/sbin/ubusd", "cases": ["grouped", "interleaved", "monitor", "slow"]}, "stress metadata")
        check(hashes(raw / "binary-sha256.txt") == {
            "/sbin/ubusd" if side == "stock" else "/tmp/bin/ubusd-rs": plan["subjects"][side]["sha256"]}, "stress executable")
        check(hashes(raw / "benchmark-sha256.txt") == {"/tmp/bin/owrt-benchmark": files["benchmark"]["sha256"],
              "/tmp/bin/ns-exec": plan["namespace_sha256"]}, "stress benchmark")
        for name in ("event-benchmark-sha256.txt", "event-benchmark-after-sha256.txt"):
            check(hashes(raw / name) == {"/tmp/bin/event-benchmark": files["event_benchmark"]["sha256"]}, "stress helper")
        check(hashes(raw / "workload-sha256.txt") == {"/tmp/workload.sh": files["workload"]["sha256"]}, "stress workload")
        check(hashes(raw / "libraries.sha256") == expected_libraries, "stress libraries")
        check(set((raw / "libraries-verified.txt").read_text().splitlines()) == {name + ": OK" for name in expected_libraries}, "stress library checks")
        cases = {lane: stress_report.verify_case(raw, lane, {}, plan["subjects"][side]["sha256"])
                 for lane in (*stress_report.LANES, "slow")}
        windows.append({"side": side, "cases": cases, "raw_archive_sha256": digest(window / "raw.tar.gz"),
                        "raw_files_verified": len(archived), "driver_result_sha256": digest(window / "result.json")})
    return {"windows_verified": 2, "functional_pass": True, "windows": windows,
            "limit": "One window per side is a functional check, not a performance comparison; slow sender ACK is not event-delivery latency."}


def analyze(root, plan_path):
    check(__debug__, "do not run with Python -O: reused auditors require assertions")
    plan = read(plan_path)
    check(plan["schema_version"] == 1 and plan["rules"] == RULES, "frozen completion rules differ")
    check(plan["candidate_sha256"] == CANDIDATE_SHA and
          {side: item["sha256"] for side, item in plan["subjects"].items()} ==
          {"stock": C_SHA, "candidate": CANDIDATE_SHA}, "exact completion subjects required")
    check(root.resolve() == (ROOT / plan["output"]).resolve(), "completion output location differs")
    check((root / "COMPLETE").is_file() and not any((root / name).exists() for name in
          ("FAILED", "FAILED.json", "failure.json")), "completion incomplete/failed")
    check(digest(root / "plan.json") == digest(plan_path), "captured plan differs")
    for path, expected in plan["input_sha256"].items():
        check(digest(ROOT / path) == expected, f"frozen input changed: {path}")
    check(read(root / "steps.json") == [{"name": step["name"], "exit": 0} for step in plan["steps"]], "completed step set differs")
    for path in plan["prerequisites"]:
        result = read(ROOT / path)
        check(result["candidate_sha256"] == CANDIDATE_SHA and all(result.get(key) is True for key in HEALTH), "correctness prerequisite")
    matrix, send, memory, stress = (analyze_matrix(root, plan), analyze_send(root, plan),
                                    analyze_memory(root, plan), analyze_stress(root, plan))
    return {"schema_version": 1, "scope": "R136 frozen physical completion coverage; no deployment",
            "verified": True, "physical_windows_verified": 46, "all_windows_cleaned_and_stock": True,
            "subjects": plan["subjects"], "plan_sha256": digest(plan_path),
            "reporter_sha256": digest(Path(__file__)), "frozen_input_sha256": plan["input_sha256"],
            "rules": plan["rules"], "matrix": matrix, "direct_send": send, "memory": memory, "stress": stress,
            "limits": ["Prior R134/R135/R136 targeted and Oracle samples are not pooled into this independent completion series.",
                       "Primary decision uses the paired-percentage median ±1% band and 7/8 signs. Historical R134 side-median decisions remain separately named.",
                       "No global performance/adoption verdict, equivalence proof, multiplicity-adjusted significance, long-term stability or nine-Rust-component integration claim.",
                       "Every timing metric and resident increase is retained, including unresolved higher medians; previous negative findings are not erased."]}


def public_report(report):
    """Allowlist derived measurements; never copy raw IDs, paths or health bodies."""
    def pick(row, keys):
        return {key: row[key] for key in keys}
    result = pick(report, ("schema_version", "scope", "verified", "physical_windows_verified",
                           "all_windows_cleaned_and_stock", "plan_sha256", "reporter_sha256", "rules", "limits"))
    result["subjects"] = {side: item["sha256"] for side, item in report["subjects"].items()}
    result["support_sha256"] = {path: value for path, value in report["frozen_input_sha256"].items()
                                if path.startswith(("tools/", "docs/"))}
    timing = ("lanes", "decision_counts", "all_higher_medians", "windows_verified", "tools", "limits")
    result["matrix"] = pick(report["matrix"], (*timing, "sources", "order", "records", "resident",
                                                "raw_files_verified", "production_process_verification",
                                                "cpu_source_field", "archive_verification"))
    result["direct_send"] = pick(report["direct_send"], (*timing, "iterations", "warmup", "cpu_source"))
    result["direct_send"]["windows"] = [pick(window, ("run", "side", "metrics", "raw_archive_sha256",
                                                        "driver_result_sha256", "health_sha256"))
                                          for window in report["direct_send"]["windows"]]
    result["memory"] = pick(report["memory"], ("windows_verified", "measurements", "all_candidate_increases", "limits"))
    result["memory"]["windows"] = []
    idle_columns = ["clients", *(f"{metric}_{phase}_kb" for metric in ("vmrss", "rssanon", "vmdata", "pss")
                                  for phase in ("before", "after"))]
    event_columns = ["payload_bytes", "phase", "delay_seconds", "vmrss_kb", "rssanon_kb", "vmdata_kb", "pss_kb", "fds"]
    for window in report["memory"]["windows"]:
        safe = pick(window, ("name", "kind", "side", "order", "raw_archive_sha256", "result_sha256",
                             "raw_files_verified", "proc_snapshot_verified"))
        safe["memory"] = [pick(row, idle_columns if window["kind"] == "idle" else event_columns)
                          for row in window["memory"]]
        result["memory"]["windows"].append(safe)
    result["stress"] = pick(report["stress"], ("windows_verified", "functional_pass", "limit"))
    result["stress"]["windows"] = []
    for window in report["stress"]["windows"]:
        safe = pick(window, ("side", "raw_archive_sha256", "raw_files_verified", "driver_result_sha256"))
        safe["cases"] = {}
        for lane, case in window["cases"].items():
            safe["cases"][lane] = pick(case, ("metrics", "flooded_received", "received", "mirrored", "functional_pass"))
            safe["cases"][lane]["memory_diagnostic"] = [pick(row, ("phase", "rss_kib", "rssanon_kib", "vmdata_kib", "fds"))
                                                         for row in case["memory_diagnostic"]]
        result["stress"]["windows"].append(safe)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, help="optional redacted derived JSON, created exclusively")
    args = parser.parse_args()
    result = analyze(args.root, args.plan)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    if args.public_output:
        with args.public_output.open("x") as stream:
            json.dump(public_report(result), stream, indent=2, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"verified_windows": result["physical_windows_verified"],
                      "matrix": result["matrix"]["decision_counts"],
                      "direct_send": result["direct_send"]["decision_counts"],
                      "memory_increases": len(result["memory"]["all_candidate_increases"])}))


if __name__ == "__main__":
    main()
