#!/usr/bin/env python3
"""Verify four R135 router diagnostic windows; do not promote a candidate.

Usage: analyze_router.py RAW_ROOT --plan PLAN.json --output NEW_SUMMARY.json
Keeps caller affinities separate and pairs subjects within the same window.
"""

import argparse
import itertools
import json
from pathlib import Path, PurePosixPath
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r130_registration_report import archive_hashes, hashes, proc_status
from analyze_screen import (
    AFFINITIES, LANES, METRICS, REFERENCE_HASHES, contrast, measurements,
    read, require, sha, summary, valid_hash,
)


REPO = Path(__file__).resolve().parents[2]
SIDES = ("c", "r134", "drain", "split")
ORDERS = [["c", "r134", "split", "drain"], ["r134", "drain", "c", "split"],
          ["drain", "split", "r134", "c"], ["split", "c", "drain", "r134"]]
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config", "same_production_identity", "same_host_mounts")
BINARIES = {"c": "/sbin/ubusd", "r134": "/tmp/bin/before-rs", "drain": "/tmp/bin/ubusd-rs", "split": "/tmp/bin/event-benchmark"}
NAMESPACE_SHA = "fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2"
CMDLINE = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"
CTX_FIELDS = {f"{role}_{kind}_ctxt_per_op": (role, f"{kind}_ctxt_switches")
              for role in ("daemon", "caller") for kind in ("voluntary", "nonvoluntary")}
ALL_METRICS = (*METRICS, *CTX_FIELDS)


def paired(values, baseline):
    """Do not omit zero-context-switch windows or invent their percentages."""
    absolute = [value - control for value, control in zip(values, baseline)]
    if all(control > 0 for control in baseline):
        result = contrast(values, baseline)
    else:
        result = {"by_block_delta_pct": [(value / control - 1) * 100 if control else None
                                         for value, control in zip(values, baseline)],
                  "median_delta_pct": None, "min_delta_pct": None, "max_delta_pct": None,
                  "lower_blocks": sum(value < 0 for value in absolute),
                  "higher_blocks": sum(value > 0 for value in absolute),
                  "equal_blocks": sum(value == 0 for value in absolute),
                  "exploratory_direction": "undefined_zero_baseline"}
    return {**result, "by_block_delta": absolute, "median_delta": statistics.median(absolute)}


def load_plan(path):
    plan = read(path)
    require(plan["orders"] == ORDERS and len(plan["steps"]) == 4, "four frozen Latin-order windows required")
    inputs = plan["input_sha256"]
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts and valid_hash(expected), "invalid plan input")
        require(sha(REPO / name) == expected, f"frozen input hash changed: {name}")
    settings = []
    for index, step in enumerate(plan["steps"]):
        argv = step["argv"]
        require(step["name"] == f"window-{index}" and argv[:2] == ["tools/r95_device_smoke.py", "ubusd"], "driver/window mismatch")
        require(argv.count("--pilot") == 1 and "--matrix" not in argv and "--implementation" not in argv,
                "unexpected collection mode")
        flags = {}
        pos = 4
        while pos < len(argv):
            if argv[pos] == "--pilot":
                pos += 1
                continue
            require(argv[pos] not in flags and pos + 1 < len(argv), "duplicate/incomplete driver flag")
            flags[argv[pos]] = argv[pos + 1]
            pos += 2
        require(set(flags) == {"--recovery-gate", "--guard", "--benchmark", "--before-candidate",
                               "--event-benchmark", "--workload-script", "--iterations"}
                and flags["--iterations"] == "10000", "driver options differ from frozen diagnostic")
        require(argv[3] == f'{plan["output"]}/window-{index}'
                and step["driver_result"] == f'{argv[3]}/result.json', "planned output differs")
        files = {"driver": argv[0], "candidate": argv[2], "recovery_gate": flags["--recovery-gate"],
                 "guard": flags["--guard"], "benchmark": flags["--benchmark"],
                 "before_candidate": flags["--before-candidate"], "event_benchmark": flags["--event-benchmark"],
                 "workload": flags["--workload-script"]}
        require(all(value in inputs for value in files.values()), "driver input not frozen")
        settings.append({key: inputs[value] for key, value in files.items()})
    common = {key: value for key, value in settings[0].items() if key != "workload"}
    require(all({key: value for key, value in row.items() if key != "workload"} == common for row in settings), "window subjects/tools changed")
    subjects = {"c": REFERENCE_HASHES["c"], "r134": common["before_candidate"],
                "drain": common["candidate"], "split": common["event_benchmark"]}
    require(subjects["r134"] == REFERENCE_HASHES["s1b1k1"], "R134 reference changed")
    gate = read(REPO / plan["steps"][0]["argv"][plan["steps"][0]["argv"].index("--recovery-gate") + 1])
    require(gate["offline_backup_verified"] is True and gate["configuration_matches_backup"] is True, "invalid recovery gate")
    return plan, settings, subjects, gate["boot_id"]


def analyze(root, plan_path):
    require(not (root / "FAILED").exists() and not (root / "failure.json").exists(), "diagnostic failed")
    require({p.name for p in root.glob("window-*") if p.is_dir()} == {f"window-{i}" for i in range(4)}, "exactly four windows required")
    plan, settings, subjects, boot = load_plan(plan_path)
    windows, records, indexed = [], [], {}
    for index, expected in enumerate(settings):
        window, raw = root / f"window-{index}", root / f"window-{index}" / "raw"
        require((raw / "COMPLETE").is_file() and not (window / "FAILED.json").exists(), "window incomplete")
        raw_hashes = archive_hashes(window)
        result = read(window / "result.json")
        require(all(result.get(key) is True for key in HEALTH), f"{window.name}: failed health/cleanup")
        mode = {"exit": 0, "component": "ubusd", "implementation": "rs", "iterations": 10000,
                "installed": False, "matrix": False, "production_mode": "stock", "pilot_only": True,
                "correctness_smoke_only": False}
        require(all(type(result.get(key)) is type(value) and result[key] == value for key, value in mode.items()), "collection mode differs")
        require(all(result.get(f"{key}_sha256") == value for key, value in expected.items()), "driver/tool/subject hash differs")
        health = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
        require(health[0] == health[1] and health[0]["boot_id"] == boot and health[0]["mode"] == "stock", "production boot/health differs")
        require(set(health[0]["verified_components"]) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"}, "production identity coverage")
        require((raw / "boot-id.txt").read_text().strip() == boot
                and (raw / "kernel.txt").read_text().strip() == "6.12.94", "raw target boot/kernel differs")
        require(hashes(raw / "binary-sha256.txt") == {BINARIES["drain"]: subjects["drain"]}, "driver candidate identity")
        identities = {BINARIES[side]: subjects[side] for side in SIDES}
        identities.update({"/tmp/bin/owrt-benchmark": expected["benchmark"], "/tmp/bin/ns-exec": NAMESPACE_SHA})
        require(hashes(raw / "identities.txt") == identities, "raw ELF/helper identities differ")
        for side in ORDERS[index]:
            folder = raw / side
            require((folder / "COMPLETE").is_file() and not (folder / "objects-after.txt").read_bytes(), f"{side}: incomplete/leaked objects")
            require(not (folder / "daemon.log").read_bytes(), "daemon output nonempty")
            require((folder / "expected.cmdline").read_bytes() == CMDLINE
                    and (folder / "before.cmdline").read_bytes() == CMDLINE, "daemon launch argv differs")
            require({p.name for p in folder.glob("*.json")} ==
                    {f"{affinity}-{lane}.json" for affinity, lane in itertools.product(AFFINITIES, LANES)},
                    "unexpected/missing case JSON")
            samples = {affinity: {lane: read(folder / f"{affinity}-{lane}.json") for lane in LANES} for affinity in AFFINITIES}
            pid = samples["split"]["register_1"]["daemon_cpu"][0]["pid"]
            for phase in ("before", "after"):
                status = proc_status(folder / f"{phase}.status", pid, 1)
                require(int(status["Cpus_allowed"].replace(",", ""), 16) == 2, "daemon hex CPU mask differs")
                require(hashes(folder / f"{phase}-exe.sha256") == {f"/proc/{pid}/exe": subjects[side]}, "live daemon ELF differs")
            starts = set()
            for affinity, lane in itertools.product(AFFINITIES, LANES):
                require(not (folder / f"{affinity}-{lane}.log").read_bytes(), "caller stderr nonempty")
                metrics, diagnostics = measurements(samples[affinity][lane], 10000, 20, (0, 1), affinity)
                require(diagnostics["daemon"]["pid"] == pid, "monitored daemon PID changed")
                starts.add(diagnostics["daemon"]["start_ticks"])
                for metric, (role, field) in CTX_FIELDS.items():
                    metrics[metric] = diagnostics[role]["context_switch_deltas"][field] / 10000
                indexed[index, side, affinity, lane] = metrics
                name = f"{side}/{affinity}-{lane}.json"
                records.append({"window": index, "side": side, "affinity": affinity, "lane": lane,
                                "file": f"window-{index}/raw/{name}", "sha256": raw_hashes[name],
                                "metrics": metrics, **diagnostics})
            require(len(starts) == 1, "daemon start time changed across lanes/affinities")
        windows.append({"window": index, "order": ORDERS[index], "raw_archive_sha256": sha(window / "raw.tar.gz"),
                        "raw_file_count": len(raw_hashes), "driver_result_sha256": sha(window / "result.json"),
                        "health_sha256": {phase: sha(window / f"health-{phase}.json") for phase in ("before", "after")}})
    require(len(indexed) == len(records) == 96, "incomplete case matrix")
    groups = []
    for side, affinity, lane in itertools.product(SIDES, AFFINITIES, LANES):
        values = {metric: [indexed[index, side, affinity, lane][metric] for index in range(4)] for metric in ALL_METRICS}
        comparisons = {control: {metric: paired(series, [indexed[index, control, affinity, lane][metric] for index in range(4)])
                                 for metric, series in values.items()} for control in ("c", "r134")}
        groups.append({"side": side, "affinity": affinity, "lane": lane,
                       "metrics": {metric: summary(series) for metric, series in values.items()}, "vs": comparisons})
    return {"schema_version": 1, "scope": "R135 four-window physical-router targeted diagnostic; not formal promotion",
            "verified": True, "physical_router_windows_verified": 4, "all_windows_cleaned_and_stock": True,
            "boot_id": boot, "plan_sha256": sha(plan_path), "reporter_sha256": sha(Path(__file__)),
            "support_sha256": {name: sha(REPO / "tools" / name) for name in ("r130_registration_report.py", "r135/analyze_screen.py")},
            "subjects": subjects, "benchmark_sha256": settings[0]["benchmark"], "iterations": 10000, "warmup": 20,
            "windows": windows, "groups": groups, "records": records,
            "metric_units": {metric: "context switches per operation" if metric in CTX_FIELDS else "microseconds per operation" for metric in ALL_METRICS},
            "limitations": [
                "All 96 cases and four cleaned physical windows are required. Caller split and pair_allowed conditions are never pooled.",
                "Each comparison pairs the same window, affinity and lane. Four descriptive pairs cannot satisfy or replace R134's frozen 7/8 rule, and no formal win or candidate promotion is assigned.",
                "Absolute median paired change <= 1% is exploratory unresolved; larger changes describe direction only, not statistical significance or a cause.",
                "Context-switch percentages are undefined when a control count is zero; all windows and absolute deltas are retained. Boundary last_processor snapshots are not migration counts or per-operation traces.",
                "Affinities and lanes share a daemon within each side/window. Latin side orders and reversed affinity order balance some ordering effects but do not create independent repeated daemons for each lane.",
                "The workload includes ADD/REMOVE and registration-generated object events, not general user SEND, monitor, memory or nine-component integration coverage.",
                "Raw archives and expanded files are reconciled. Driver assertions establish stable configuration/mounts/production and uploaded workload identity; their raw before/after strings are not archived.",
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
    print(json.dumps({"verified_windows": 4, "cases": len(result["records"]), "groups": len(result["groups"]), "formal_promotion": False}))


if __name__ == "__main__":
    main()
