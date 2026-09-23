#!/usr/bin/env python3
"""Verify all four frozen R139 windows and describe caller-placement effects.

Local evidence only. No collection, excluded cases, adoption decision, or
inference of a kernel mechanism. Existing R136 formal conclusions stay intact.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from r130_registration_report import archive_hashes, argv, check, digest, hashes, proc_identity, proc_status, read
from r139.make_affinity_plan import BENCHMARK_SHA, C_SHA, CANDIDATE_SHA, HEALTH, NAMESPACE_SHA, ORDERS

PLACEMENTS = ("allowed", "split", "colocated")
SIDES = ("c", "candidate")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "daemon_cpu_us_per_op", "caller_cpu_us_per_op")
SUBJECTS = {"c": C_SHA, "candidate": CANDIDATE_SHA}
BENCH, SOCKET = "/tmp/bin/owrt-benchmark", "/var/run/ubus/ubus.sock"
COMMAND = ["/sbin/ubusd", "-s", SOCKET]
CTX = ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")
IDENTITIES = {"/sbin/ubusd": C_SHA, "/tmp/bin/ubusd-rs": CANDIDATE_SHA,
              BENCH: BENCHMARK_SHA, "/tmp/bin/ns-exec": NAMESPACE_SHA}


def integer(value, label, minimum=0):
    check(type(value) is int and value >= minimum, f"{label}: invalid integer")
    return value


def load_plan(path):
    plan = read(path)
    check(plan["schema_version"] == 1 and plan["orders"] == ORDERS
          and plan["window_count"] == 4 and plan["case_count"] == 24
          and len(plan["steps"]) == 4, "expected four frozen six-case windows")
    check(plan["iterations"] == 10000 and plan["warmup"] == 20
          and plan["lane"] == {"name": "register_1", "command": "register-cycle", "parameters": [1, 8]},
          "workload/counts differ")
    check(plan["runtime"] == {"daemon_cpu": 1, "socket": SOCKET, "daemon_argv0": "/sbin/ubusd",
          "default_acl": True, "fresh_daemon_per_case": True,
          "caller_allowed_cpus": {"allowed": [0, 1], "split": [0], "colocated": [1]}},
          "runtime contract differs")
    check({key: value["sha256"] for key, value in plan["subjects"].items()} == SUBJECTS
          and plan["candidate_sha256"] == CANDIDATE_SHA
          and plan["benchmark"]["sha256"] == BENCHMARK_SHA
          and plan["namespace_sha256"] == NAMESPACE_SHA, "exact ELF identities differ")
    rules = plan["decision_rules"]
    check(rules["primary_metric"] == "p95_us" and rules["required_metrics"] == list(METRICS)
          and rules["replication"] == "median(g[w,allowed]) > 5 and g[w,allowed] > 0 in at least 3/4 windows"
          and rules["placement_sensitivity"] == "abs(median(d[w,p])) >= 10 percentage points and at least 3/4 d[w,p] strictly share its sign",
          "frozen diagnostic rules differ")
    inputs = plan["input_sha256"]
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        check(not relative.is_absolute() and ".." not in relative.parts
              and re.fullmatch("[0-9a-f]{64}", expected), "invalid frozen input")
        check(digest(ROOT / name) == expected, f"frozen input changed: {name}")
    settings = []
    for index, step in enumerate(plan["steps"]):
        args = step["argv"]
        check(step["name"] == f"window-{index}" and len(args) == 15
              and args[:2] == ["tools/r95_device_smoke.py", "ubusd"]
              and args[2] == plan["subjects"]["candidate"]["path"]
              and args[3] == f'{plan["output"]}/window-{index}'
              and step["driver_result"] == f'{args[3]}/result.json'
              and args[-1] == "--pilot", "driver/window contract differs")
        flags = dict(zip(args[4:-1:2], args[5:-1:2]))
        check(set(flags) == {"--guard", "--recovery-gate", "--benchmark", "--workload-script", "--iterations"}
              and flags["--iterations"] == "10000" and flags["--benchmark"] == plan["benchmark"]["path"],
              "driver flags differ")
        files = {"driver": args[0], "candidate": args[2], "guard": flags["--guard"],
                 "recovery_gate": flags["--recovery-gate"], "benchmark": flags["--benchmark"],
                 "workload": flags["--workload-script"]}
        settings.append({key: inputs[value] for key, value in files.items()})
    common = {key: value for key, value in settings[0].items() if key != "workload"}
    check(all({key: value for key, value in row.items() if key != "workload"} == common for row in settings),
          "subjects/tools changed between windows")
    gate = read(ROOT / flags["--recovery-gate"])
    check(gate["offline_backup_verified"] is True and gate["configuration_matches_backup"] is True,
          "recovery gate invalid")
    for name in plan["prerequisites"]:
        check(name in inputs, "prerequisite not frozen")
        result = read(ROOT / name)
        check(result.get("candidate_sha256") == CANDIDATE_SHA
              and all(result.get(key) is True for key in HEALTH), "exact-ELF prerequisite failed")
    return plan, settings, gate["boot_id"]


def status(path, cpus, pid=None):
    fields = dict(line.split(":", 1) for line in path.read_text().splitlines() if ":" in line)
    observed = int(fields["Pid"].strip())
    check(pid is None or observed == pid, f"{path.name}: PID differs")
    result = proc_status(path, observed, "0-1" if cpus == (0, 1) else cpus[0])
    check(int(result["Cpus_allowed"].replace(",", ""), 16) == sum(1 << cpu for cpu in cpus),
          f"{path.name}: hex mask differs")
    return observed, result


def measurement(data, daemon_id):
    check(data["schema"] == 1 and data["successful"] == 10000
          and data["warmup"] == 20 and data["errors"] == 0, "caller count/status differs")
    samples = data["latency_ns"]
    check(len(samples) == 10000 and all(type(x) is int and x > 0 for x in samples), "invalid raw latencies")
    ordered = sorted(samples)
    metrics = {"mean_us": Fraction(sum(samples), 10000 * 1000)}
    for name, q in (("p50_us", .50), ("p95_us", .95), ("p99_us", .99)):
        metrics[name] = Fraction(ordered[math.floor(9999 * q + .5)], 1000)
    for name, value in metrics.items():
        check(math.isclose(data[name], float(value), rel_tol=1e-10, abs_tol=1e-9), f"{name}: raw arithmetic differs")
    check(data["wall_s"] > 0 and math.isclose(data["ops_per_s"], 10000 / data["wall_s"], rel_tol=1e-10),
          "wall/throughput arithmetic differs")
    check(len(data["daemon_cpu"]) == 1, "one monitored daemon required")
    daemon = data["daemon_cpu"][0]
    before, after = daemon["before"], daemon["after"]
    check((daemon["pid"], before["start_ticks"]) == daemon_id
          and (before["pid"], before["start_ticks"]) == (after["pid"], after["start_ticks"]) == daemon_id,
          "measured daemon identity differs")
    hz = data["clock_ticks_per_second"]
    check(hz > 0 and before["Threads"] == after["Threads"] == 1, "invalid tick rate/threads")
    check(integer(before["process_cpu_resolution_ns"], "CPU resolution", 1)
          == after["process_cpu_resolution_ns"], "CPU resolution changed")
    for point in (before, after):
        for key in ("process_cpu_ns", "cpu_ticks", "child_cpu_ticks", *CTX):
            integer(point[key], key)
    delta = after["process_cpu_ns"] - before["process_cpu_ns"]
    check(integer(daemon["cpu_clock_ns"], "daemon CPU", 1) == delta, "daemon process-clock delta differs")
    for seconds, ticks in (("cpu_s", "cpu_ticks"), ("child_cpu_s", "child_cpu_ticks")):
        check(after[ticks] >= before[ticks]
              and math.isclose(daemon[seconds], (after[ticks] - before[ticks]) / hz, abs_tol=1e-9),
              f"{seconds}: tick arithmetic differs")
    context = {key: after[key] - before[key] for key in CTX}
    check(all(value >= 0 for value in context.values()), "context counter regressed")
    metrics["daemon_cpu_us_per_op"] = Fraction(delta, 10000 * 1000)
    metrics["caller_cpu_us_per_op"] = Fraction(integer(data["client_cpu_clock_ns"], "caller CPU", 1), 10000 * 1000)
    check("client_before" not in data and "client_after" not in data, "unexpected original-caller schema")
    return metrics, context


def series(values):
    median = statistics.median(values)
    return {"by_window": list(map(float, values)), "median": float(median),
            "positive_windows": sum(value > 0 for value in values),
            "negative_windows": sum(value < 0 for value in values),
            "zero_windows": sum(value == 0 for value in values)}


def comparisons(indexed):
    gaps, interactions, within_side = {}, {}, {}
    for placement in PLACEMENTS:
        gaps[placement] = {metric: [100 * (indexed[w, "candidate", placement][metric]
                                        / indexed[w, "c", placement][metric] - 1)
                                     for w in range(4)] for metric in METRICS}
    for placement in ("split", "colocated"):
        interactions[placement] = {metric: [value - baseline for value, baseline in
                                           zip(gaps[placement][metric], gaps["allowed"][metric])]
                                   for metric in METRICS}
    for side in SIDES:
        within_side[side] = {}
        for placement in ("split", "colocated"):
            within_side[side][placement] = {}
            for metric in METRICS:
                baseline = [indexed[w, side, "allowed"][metric] for w in range(4)]
                values = [indexed[w, side, placement][metric] for w in range(4)]
                within_side[side][placement][metric] = {
                    "allowed_by_window_us": list(map(float, baseline)),
                    "placement_by_window_us": list(map(float, values)),
                    "absolute_delta_us": series([a - b for a, b in zip(values, baseline)]),
                    "delta_pct": series([100 * (a / b - 1) for a, b in zip(values, baseline)])}
    baseline = gaps["allowed"]["p95_us"]
    replication = statistics.median(baseline) > 5 and sum(value > 0 for value in baseline) >= 3
    signals = {}
    for placement, metrics in interactions.items():
        values = metrics["p95_us"]
        median = statistics.median(values)
        same_sign = sum(value * median > 0 for value in values)
        threshold = abs(median) >= 10 and same_sign >= 3
        signals[placement] = {"interaction_threshold_met": threshold,
                              "same_sign_windows": same_sign,
                              "replicated_tail_placement_sensitive": replication and threshold}
    return {"candidate_vs_c_gap_pct": {p: {m: series(v) for m, v in metrics.items()} for p, metrics in gaps.items()},
            "gap_shift_vs_allowed_pp": {p: {m: series(v) for m, v in metrics.items()} for p, metrics in interactions.items()},
            "within_side_placement_vs_allowed": within_side,
            "primary_p95_diagnostic": {"original_allowance_tail_replicated": replication,
                                      "placements": signals},
            "interpretation": "Descriptive four-window gates only. Without baseline replication, placement effects do not explain the original tail. No kernel cause or candidate adoption is assigned."}


def analyze(root, plan_path):
    plan, settings, boot = load_plan(plan_path)
    check((root / "COMPLETE").is_file() and digest(root / "plan.json") == digest(plan_path),
          "series incomplete or captured plan differs")
    check({p.name for p in root.glob("window-*") if p.is_dir()} == {f"window-{i}" for i in range(4)},
          "exactly four windows required")
    check(read(root / "steps.json") == [{"name": f"window-{i}", "exit": 0} for i in range(4)],
          "outer runner steps differ")
    records, windows, indexed, series_health = [], [], {}, None
    for w, expected in enumerate(settings):
        window, raw = root / f"window-{w}", root / f"window-{w}" / "raw"
        check((raw / "COMPLETE").is_file() and not any((base / marker).exists()
              for base in (root, window) for marker in ("FAILED", "FAILED.json", "failure.json")), "failed/incomplete evidence")
        raw_hashes = archive_hashes(window)
        result = read(window / "result.json")
        check(all(result.get(key) is True for key in HEALTH), "driver health/cleanup failed")
        mode = {"exit": 0, "component": "ubusd", "implementation": "rs", "iterations": 10000,
                "installed": False, "matrix": False, "production_mode": "stock",
                "pilot_only": True, "correctness_smoke_only": False}
        check(all(type(result.get(key)) is type(value) and result[key] == value for key, value in mode.items()), "collection mode differs")
        check(all(result.get(key + "_sha256") == value for key, value in expected.items()), "driver/tool identities differ")
        health = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
        check(health[0] == health[1] and health[0]["boot_id"] == boot and health[0]["mode"] == "stock"
              and (series_health is None or series_health == health[0]), "health/boot identity changed")
        series_health = health[0]
        check(set(health[0]["verified_components"]) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"}, "production identity coverage differs")
        check((raw / "boot-id.txt").read_text().strip() == boot
              and (raw / "kernel.txt").read_text().strip() == "6.12.94"
              and (raw / "cpus-online.txt").read_text().strip() == "0-1", "raw target differs")
        for name in ("expected-identities.txt", "identities-before.txt", "identities-after.txt"):
            check(hashes(raw / name) == IDENTITIES, "raw artifact identities differ")
        check(hashes(raw / "binary-sha256.txt") == {"/tmp/bin/ubusd-rs": CANDIDATE_SHA}, "driver subject differs")
        check(sorted((raw / "identity-check.log").read_text().splitlines()) == sorted(f"{name}: OK" for name in IDENTITIES), "ELF identity check differs")
        check((raw / "order.txt").read_text().split() == ORDERS[w]
              and {p.name for p in raw.iterdir() if p.is_dir()} == set(ORDERS[w]), "recorded case set/order differs")
        parent = status(raw / "parent-before.status", (0, 1))[0]
        status(raw / "parent-after.status", (0, 1), parent)
        for cpu in (0, 1):
            status(raw / f"helper-cpu-{cpu}.status", (cpu,))
        seen = set()
        for condition in ORDERS[w]:
            side, placement = condition.split("-")
            folder = raw / condition
            check((folder / "COMPLETE").is_file() and {p.name for p in folder.glob("*.json")} == {"register_1.json"}, "case incomplete/extra records")
            check(all(not (folder / name).read_bytes() for name in ("caller.log", "daemon.log", "objects-after.txt")), "case logs/objects nonempty")
            check((folder / "caller-exit.txt").read_text().strip() == "0"
                  and (folder / "daemon-exit.txt").read_text().strip() in ("0", "143"), "case exit differs")
            daemon_id = proc_identity(folder / "before.stat")
            check(daemon_id not in seen and proc_identity(folder / "after.stat") == daemon_id, "daemon reused/replaced")
            seen.add(daemon_id)
            status(folder / "parent-before.status", (0, 1), parent)
            check(argv(folder / "expected.cmdline") == COMMAND, "expected daemon argv differs")
            boundary = {}
            for phase in ("before", "after"):
                boundary[phase] = status(folder / f"{phase}.status", (1,), daemon_id[0])[1]
                check(argv(folder / f"{phase}.cmdline") == COMMAND
                      and hashes(folder / f"{phase}-exe.sha256") == {f"/proc/{daemon_id[0]}/exe": SUBJECTS[side]}, "live daemon argv/ELF differs")
            caller = [BENCH, "register-cycle", SOCKET, "1", "8", "10000", "20", str(daemon_id[0])]
            if placement != "allowed":
                caller = [BENCH, "exec-cpu", "0" if placement == "split" else "1", *caller]
            check(argv(folder / "caller-command.argv") == caller, "original caller launch argv differs")
            data = read(folder / "register_1.json")
            metrics, context = measurement(data, daemon_id)
            for key in CTX:
                proc = data["daemon_cpu"][0]
                check(int(boundary["before"][key]) <= proc["before"][key] <= proc["after"][key]
                      <= int(boundary["after"][key]), "context snapshots outside launch boundaries")
            indexed[w, side, placement] = metrics
            records.append({"window": w, "side": side, "placement": placement,
                            "raw_sha256": raw_hashes[f"{condition}/register_1.json"],
                            "metrics": {key: float(value) for key, value in metrics.items()},
                            "daemon_context_switch_deltas": context})
        windows.append({"window": w, "order": ORDERS[w], "raw_sha256": raw_hashes,
                        "archive_sha256": digest(window / "raw.tar.gz"), "result_sha256": digest(window / "result.json"),
                        "health_sha256": {p: digest(window / f"health-{p}.json") for p in ("before", "after")}})
    check(len(records) == len(indexed) == 24, "expected all 24 cases")
    return {"schema_version": 1, "scope": "Four-window exact-caller R139 placement diagnostic; no adoption",
            "verified": True, "windows_verified": 4, "case_count": 24, "subjects": SUBJECTS,
            "benchmark_sha256": BENCHMARK_SHA, "plan_sha256": digest(plan_path),
            "analyzer_sha256": digest(Path(__file__)), "support_sha256": {
                name: digest(ROOT / name) for name in ("tools/r130_registration_report.py", "tools/r139/make_affinity_plan.py")},
            "decision_rules": plan["decision_rules"], "windows": windows, "records": records,
            "comparisons": comparisons(indexed),
            "limitations": [
                "All 24 cases and all four same-boot stock-production windows are retained; no new formal performance ranking or adoption.",
                "Same-window C/R136 ratios stay separate for each placement. Interactions are differences of these percentage gaps, in percentage points.",
                "Fresh daemon per case and balanced order do not eliminate temporal variation. Four descriptive windows are not a mechanism proof.",
                "Exact exec-cpu helper masks were exercised before timing; parent mask, launch argv, successful exit and daemon live identity are checked. No live caller mask or per-cycle migration evidence exists.",
                "Daemon CPU delta is recomputed from process-clock snapshots. Original caller CPU provides a positive clock delta only, so no independent caller before/after reconstruction is possible; no tick fallback.",
                "Daemon context switches are window-boundary counts, not per-operation traces or waiting durations. CPU and wall are not subtracted.",
                "Guard assertions cover configuration/mount/production identity within each window; health/boot and exact input identities agree across windows. Raw host process identities are not separately archived.",
                "Only one-method ADD/REMOVE is exercised; event_1, event_nomatch, user events, memory and integration remain outside this diagnostic.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root, args.plan)
    with args.output.open("x") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"verified_windows": 4, "cases": 24,
                      **report["comparisons"]["primary_p95_diagnostic"]}))


if __name__ == "__main__":
    main()
