#!/usr/bin/env python3
"""Verify eight complete R135 router windows and apply the frozen paired rules.

Usage: analyze_formal.py RAW_ROOT --plan PLAN.json --output NEW_SUMMARY.json
The output contains derived measurements and artifact hashes, not device IDs.
"""

import argparse
from fractions import Fraction
import itertools
import json
from pathlib import Path, PurePosixPath
import statistics

from analyze_router import CMDLINE, HEALTH, NAMESPACE_SHA, REPO, archive_hashes, hashes, proc_status
from analyze_screen import METRICS as CORE_METRICS, REFERENCE_HASHES, measurements, read, require, sha, summary, valid_hash
from make_formal_plan import LANES as WORKLOADS, ORDERS
from r130_registration_report import proc_identity


SIDES = ("c", "r134", "candidate")
LANES = tuple(lane for lane, _, _ in WORKLOADS)
METRICS = (*CORE_METRICS, "caller_cpu_us_per_op")
BINARIES = {"c": "/sbin/ubusd", "r134": "/tmp/bin/before-rs", "candidate": "/tmp/bin/ubusd-rs"}
N = 10000
WARMUP = 20


def compare(values, baseline, band=1):
    require(len(values) == len(baseline) == 8 and all(v > 0 for v in baseline), "eight positive paired controls required")
    # Exact decimal ratios keep observations exactly at a frozen boundary in
    # the tie band, rather than changing the rule through float roundoff.
    deltas = [(Fraction(str(value)) / Fraction(str(control)) - 1) * 100
              for value, control in zip(values, baseline)]
    median = statistics.median(deltas)
    lower, higher = sum(value < 0 for value in deltas), sum(value > 0 for value in deltas)
    decision = "win" if median < -band and lower >= 7 else "loss" if median > band and higher >= 7 else "tie"
    return {"by_window_delta_pct": list(map(float, deltas)), "median_delta_pct": float(median),
            "min_delta_pct": float(min(deltas)), "max_delta_pct": float(max(deltas)),
            "lower_windows": lower, "higher_windows": higher, "equal_windows": 8 - lower - higher,
            "decision": decision}


def load_plan(path):
    plan = read(path)
    require(plan["schema_version"] == 1 and plan["window_count"] == len(plan["steps"]) == 8
            and plan["orders"] == [list(order) for order in ORDERS], "eight frozen subject-order windows required")
    require(plan["iterations"] == N and plan["warmup"] == WARMUP and plan["lanes"] ==
            [{"name": lane, "command": command, "parameters": parameters, "iterations": N, "warmup": WARMUP}
             for lane, command, parameters in WORKLOADS], "workload/counts differ")
    require(plan["runtime"] == {"daemon_cpu": 1, "caller_allowed_cpus": [0, 1], "socket": "/var/run/ubus/ubus.sock",
                               "default_acl": True, "daemon_argv0": "/sbin/ubusd", "event_benchmark_slot": False,
                               "lane_order": list(LANES)}, "runtime contract differs")
    rules = plan["decision_rules"]
    require(rules["required_metrics"] == list(METRICS) and rules["lower_is_better"] is True
            and rules["comparisons"] == ["candidate_vs_r134", "candidate_vs_c"]
            and rules["effect"] == "median of eight (candidate / baseline - 1) * 100 paired changes"
            and rules["descriptive"]["win"] == "median_delta_pct < -1 and lower_windows >= 7"
            and rules["descriptive"]["loss"] == "median_delta_pct > 1 and higher_windows >= 7"
            and rules["primary"] == {"lane": "register_1", "metric": "p95_us", "baseline": "r134",
                                     "pass": "median_delta_pct < -5 and lower_windows >= 7"}, "frozen decision rules differ")
    inputs = plan["input_sha256"]
    require(set(plan["subjects"]) == set(SIDES), "planned subject set differs")
    subjects = {side: plan["subjects"][side]["sha256"] for side in SIDES}
    require(all(valid_hash(value) for value in subjects.values())
            and subjects["c"] == REFERENCE_HASHES["c"] and subjects["r134"] == REFERENCE_HASHES["s1b1k1"],
            "invalid subject/reference SHA256")
    require(plan["candidate_sha256"] == subjects["candidate"] and plan["namespace_sha256"] == NAMESPACE_SHA
            and all(inputs.get(plan["subjects"][side]["path"]) == subjects[side] for side in SIDES)
            and inputs.get(plan["benchmark"]["path"]) == plan["benchmark"]["sha256"], "subject/helper plan identities differ")
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and valid_hash(expected), "invalid plan input")
        require(sha(REPO / name) == expected, f"frozen input hash changed: {name}")
    settings = []
    for index, step in enumerate(plan["steps"]):
        argv = step["argv"]
        require(step["name"] == f"window-{index}" and argv[:2] == ["tools/r95_device_smoke.py", "ubusd"], "driver/window mismatch")
        require(argv.count("--pilot") == 1, "custom measurement workload requires driver pilot mode")
        flags = {}
        pos = 4
        while pos < len(argv):
            if argv[pos] == "--pilot":
                pos += 1
                continue
            require(argv[pos] not in flags and pos + 1 < len(argv), "duplicate/incomplete driver option")
            flags[argv[pos]] = argv[pos + 1]
            pos += 2
        require(set(flags) == {"--recovery-gate", "--guard", "--benchmark", "--before-candidate",
                               "--workload-script", "--iterations"} and flags["--iterations"] == str(N),
                "unexpected driver options")
        require(argv[3] == f'{plan["output"]}/window-{index}'
                and step["driver_result"] == f'{argv[3]}/result.json', "planned output differs")
        require(argv[2] == plan["subjects"]["candidate"]["path"]
                and flags["--before-candidate"] == plan["subjects"]["r134"]["path"]
                and flags["--benchmark"] == plan["benchmark"]["path"], "planned driver subject/helper paths differ")
        files = {"driver": argv[0], "candidate": argv[2], "recovery_gate": flags["--recovery-gate"],
                 "guard": flags["--guard"], "benchmark": flags["--benchmark"],
                 "before_candidate": flags["--before-candidate"], "workload": flags["--workload-script"]}
        require(all(value in inputs for value in files.values()), "driver input not frozen")
        settings.append({key: inputs[value] for key, value in files.items()})
    common = {key: value for key, value in settings[0].items() if key != "workload"}
    require(all({key: value for key, value in row.items() if key != "workload"} == common for row in settings),
            "window tools/subjects changed")
    require(common["candidate"] == subjects["candidate"] and common["before_candidate"] == subjects["r134"], "subject ELF differs")
    gate = read(REPO / files["recovery_gate"])
    require(gate["offline_backup_verified"] is True and gate["configuration_matches_backup"] is True, "invalid recovery gate")
    return plan, settings, subjects, gate["boot_id"]


def verify_window(window, expected, subjects, boot, order):
    raw = window / "raw"
    require((raw / "COMPLETE").is_file() and not any((window / name).exists() for name in ("FAILED", "FAILED.json", "failure.json")),
            "window incomplete/failed")
    raw_hashes = archive_hashes(window)
    result = read(window / "result.json")
    require(all(result.get(key) is True for key in HEALTH), f"{window.name}: failed health/cleanup")
    mode = {"exit": 0, "component": "ubusd", "implementation": "rs", "iterations": N,
            "installed": False, "matrix": False, "production_mode": "stock", "pilot_only": True,
            "correctness_smoke_only": False}
    require(all(type(result.get(key)) is type(value) and result[key] == value for key, value in mode.items()), "collection mode differs")
    require(all(result.get(f"{key}_sha256") == value for key, value in expected.items())
            and "event_benchmark_sha256" not in result, "driver/tool/subject identity differs")
    health = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
    require(health[0] == health[1] and health[0]["boot_id"] == boot and health[0]["mode"] == "stock", "production boot/health differs")
    require(set(health[0]["verified_components"]) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"},
            "production identity coverage")
    require((raw / "boot-id.txt").read_text().strip() == boot
            and (raw / "kernel.txt").read_text().strip() == "6.12.94", "raw target boot/kernel differs")
    require(hashes(raw / "binary-sha256.txt") == {BINARIES["candidate"]: subjects["candidate"]}, "driver candidate identity")
    identities = {BINARIES[side]: subjects[side] for side in SIDES}
    identities.update({"/tmp/bin/owrt-benchmark": expected["benchmark"], "/tmp/bin/ns-exec": NAMESPACE_SHA})
    require(hashes(raw / "identities.txt") == hashes(raw / "expected-identities.txt") == identities, "raw ELF/helper identities differ")
    checks = (raw / "identity-check.log").read_text().splitlines()
    require(len(checks) == len(identities) and set(checks) == {f"{name}: OK" for name in identities}, "live identity checks differ")
    require((raw / "order.txt").read_text().split() == order, "recorded subject order differs")
    require({p.name for p in raw.iterdir() if p.is_dir()} == set(SIDES), "raw subject folders differ")
    return raw_hashes


def analyze(root, plan_path):
    require((root / "COMPLETE").is_file() and not any((root / name).exists() for name in ("FAILED", "FAILED.json", "failure.json")),
            "formal series incomplete/failed")
    require({p.name for p in root.glob("window-*") if p.is_dir()} == {f"window-{i}" for i in range(8)}, "exactly eight windows required")
    require(sha(root / "plan.json") == sha(plan_path), "captured plan differs from frozen plan")
    plan, settings, subjects, boot = load_plan(plan_path)
    windows, records, indexed = [], [], {}
    for index, expected in enumerate(settings):
        window = root / f"window-{index}"
        raw_hashes = verify_window(window, expected, subjects, boot, plan["orders"][index])
        for side in plan["orders"][index]:
            folder = window / "raw" / side
            require((folder / "COMPLETE").is_file() and not (folder / "objects-after.txt").read_bytes(), "subject incomplete/leaked objects")
            require(not (folder / "daemon.log").read_bytes(), "daemon output nonempty")
            require((folder / "expected.cmdline").read_bytes() == CMDLINE
                    and (folder / "before.cmdline").read_bytes() == (folder / "after.cmdline").read_bytes() == CMDLINE,
                    "daemon launch argv differs")
            require((folder / "daemon-exit.txt").read_text().strip() in ("0", "143"), "unclean daemon exit")
            require({p.name for p in folder.glob("*.json")} == {f"{lane}.json" for lane in LANES}, "unexpected/missing case JSON")
            identity = None
            for lane in LANES:
                require(not (folder / f"{lane}.log").read_bytes(), "caller stderr nonempty")
                metrics, diagnostics = measurements(read(folder / f"{lane}.json"), N, WARMUP, (0, 1), "pair_allowed")
                metrics["caller_cpu_us_per_op"] = diagnostics["caller_cpu_us_per_op"]
                current = diagnostics["daemon"]["pid"], diagnostics["daemon"]["start_ticks"]
                require(identity is None or current == identity, "daemon identity changed across lanes")
                identity = current
                indexed[index, side, lane] = metrics
                records.append({"window": index, "side": side, "lane": lane,
                                "sample_sha256": raw_hashes[f"{side}/{lane}.json"], "metrics": metrics})
            for phase in ("before", "after"):
                require(proc_identity(folder / f"{phase}.stat") == identity, "archived live daemon PID/starttime differs")
                status = proc_status(folder / f"{phase}.status", identity[0], 1)
                require(int(status["Cpus_allowed"].replace(",", ""), 16) == 2, "daemon hex CPU mask differs")
                require(hashes(folder / f"{phase}-exe.sha256") == {f"/proc/{identity[0]}/exe": subjects[side]}, "live daemon ELF differs")
        windows.append({"window": index, "order": plan["orders"][index], "raw_archive_sha256": sha(window / "raw.tar.gz"),
                        "raw_file_count": len(raw_hashes), "driver_result_sha256": sha(window / "result.json"),
                        "health_sha256": {phase: sha(window / f"health-{phase}.json") for phase in ("before", "after")}})
    require(len(indexed) == len(records) == 120, "incomplete case matrix")
    groups = []
    for side, lane in itertools.product(SIDES, LANES):
        values = {metric: [indexed[index, side, lane][metric] for index in range(8)] for metric in METRICS}
        comparisons = {control: {metric: compare(series, [indexed[index, control, lane][metric] for index in range(8)])
                                 for metric, series in values.items()} for control in ("c", "r134")}
        groups.append({"side": side, "lane": lane, "metrics": {metric: summary(series) for metric, series in values.items()},
                       "vs": comparisons})
    primary = compare([indexed[i, "candidate", "register_1"]["p95_us"] for i in range(8)],
                      [indexed[i, "r134", "register_1"]["p95_us"] for i in range(8)], band=5)
    counts = {control: {decision: sum(g["vs"][control][metric]["decision"] == decision for g in groups if g["side"] == "candidate" for metric in METRICS)
                        for decision in ("win", "loss", "tie")} for control in ("c", "r134")}
    higher = [{"control": control, "lane": g["lane"], "metric": metric, **g["vs"][control][metric]}
              for g in groups if g["side"] == "candidate" for control in ("c", "r134") for metric in METRICS
              if g["vs"][control][metric]["median_delta_pct"] > 0]
    return {"schema_version": 1, "scope": "R135 preregistered targeted confirmation on the physical router",
            "verified": True, "physical_router_windows_verified": 8, "all_windows_cleaned_and_stock": True,
            "plan_sha256": sha(plan_path), "reporter_sha256": sha(Path(__file__)),
            "support_sha256": {name: sha(REPO / "tools" / name) for name in ("r130_registration_report.py", "r135/analyze_screen.py", "r135/analyze_router.py", "r135/make_formal_plan.py")},
            "subjects": subjects, "benchmark_sha256": settings[0]["benchmark"], "iterations": N, "warmup": WARMUP,
            "metric_units": {metric: "microseconds per operation" for metric in METRICS},
            "affinity": {"daemon": [1], "caller": [0, 1]}, "windows": windows, "groups": groups, "records": records,
            "candidate_decision_counts": counts, "candidate_higher_medians": higher,
            "primary_validation": {"lane": "register_1", "metric": "p95_us", "control": "r134",
                                   "passed": primary["decision"] == "win", **primary},
            "rules": {"paired": "Same window and lane; eight non-reused subject/control pairs.",
                      "metric": "Win: paired percentage median < -1% and >= 7/8 lower; loss: median > +1% and >= 7/8 higher; otherwise tie.",
                      "primary": "Candidate/R134 register_1 p95: paired percentage median < -5% and >= 7/8 lower."},
            "limitations": [
                "Every planned lane and metric is reported, including all candidate higher medians. The primary result alone does not accept the candidate or imply global superiority.",
                "These are frozen engineering decision rules, not familywise-adjusted significance or equivalence tests. Each lane shares a daemon with the other lanes within a subject/window.",
                "Process CPU clocks bracket the measurement interval; daemon CPU is distinct from caller CPU. Latencies are recomputed from all 10000 raw operation samples.",
                "Events here are generated by object ADD/REMOVE, not general user SEND. This confirmation does not cover other ubusd lanes, resident memory or nine-component integration.",
                "Archive and expanded evidence hashes agree. Driver assertions establish cleanup and unchanged production configuration/mounts; the report contains no raw device identity or process identifiers.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.root, args.plan)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"verified_windows": 8, "cases": len(result["records"]), "groups": len(result["groups"]),
                      "primary_validation_passed": result["primary_validation"]["passed"],
                      "candidate_decisions": result["candidate_decision_counts"]}))


if __name__ == "__main__":
    main()
