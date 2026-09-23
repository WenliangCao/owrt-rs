#!/usr/bin/env python3
"""Validate and summarize the separate R137 registration phase diagnostic.

Reads local evidence only. Default: two guarded router windows, all 24 cases.
--oracle-smoke: the existing flat 12-case Oracle correctness fixture (100/20).
Usage: analyze_phase.py ROOT --plan FROZEN_PLAN.json --output NEW_SUMMARY.json
CPU intervals include instrumentation and can overlap across processes. This
tool never subtracts process CPU from wall time or estimates scheduler wait.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r130_registration_report import archive_hashes, check, digest, hashes, proc_identity, proc_status, read
from r137.make_phase_plan import C, CANDIDATE, CALLER, NAMESPACE


MODES = ("cycle-wall", "phase-wall", "phase-cpu")
METHODS = (1, 16)
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us")
REPO = Path(__file__).resolve().parents[2]
ORDERS = [{"sides": ["c", "candidate"], "modes": list(MODES), "methods": list(METHODS)},
          {"sides": ["candidate", "c"], "modes": list(reversed(MODES)), "methods": list(reversed(METHODS))}]
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config", "same_production_identity", "same_host_mounts")


def integer(value, name, minimum=0):
    check(type(value) is int and value >= minimum, f"{name}: invalid integer")
    return value


def vector(value, size, name):
    check(isinstance(value, list) and len(value) == size, f"{name}: wrong vector size")
    for item in value:
        integer(item, name)
    return value


def percentile(values, q):
    ordered = sorted(values)
    return ordered[math.floor((len(ordered) - 1) * q + .5)]


def stats(values):
    check(bool(values), "empty statistics input")
    return {"count": len(values), "mean_us": sum(values) / len(values) / 1000,
            "p50_us": percentile(values, .50) / 1000,
            "p95_us": percentile(values, .95) / 1000,
            "p99_us": percentile(values, .99) / 1000,
            "min_us": min(values) / 1000, "max_us": max(values) / 1000}


def check_process(data, role, allowed):
    before, after = data[f"{role}_before"], data[f"{role}_after"]
    for key in ("pid", "start_ticks", "process_cpu_resolution_ns"):
        integer(before[key], f"{role}/{key}", 1)
        check(before[key] == after[key], f"{role}: {key} changed")
    mask = sum(1 << cpu for cpu in allowed)
    cpulist = "0-1" if allowed == (0, 1) else str(allowed[0])
    for proc in (before, after):
        check(proc["Threads"] == 1, f"{role}: subject is not single threaded")
        check(proc["Cpus_allowed_list"] == cpulist
              and int(proc["Cpus_allowed"].replace(",", ""), 16) == mask,
              f"{role}: CPU affinity differs from frozen condition")
        check(proc["last_processor"] in allowed, f"{role}: snapshot CPU outside allowed set")
    for key in ("process_cpu_ns", "cpu_ticks", "child_cpu_ticks",
                "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
        integer(before[key], f"{role}/{key}")
        integer(after[key], f"{role}/{key}")
        check(after[key] >= before[key], f"{role}: {key} decreased")
    return {"pid": before["pid"], "start_ticks": before["start_ticks"],
            "allowed_cpus": list(allowed),
            "context_switches_setup_and_validation_included": {
                name: after[name] - before[name]
                for name in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")}}


def check_stamp(value, name):
    vector(value, 4, name)
    check(value[0] <= value[3], f"{name}: reversed wall bracket")


def check_next_stamp(before, after, name):
    check(before[3] <= after[0] and before[1] <= after[1] and before[2] <= after[2],
          f"{name}: nonmonotonic wall/CPU stamp")


def tail_summary(series, selected):
    if not selected:
        return {"count": 0}
    result = {"count": len(selected),
              "metrics": {name: stats([values[i] for i in selected]) for name, values in series.items()}}
    total = sum(series["cycle_wall"][i] for i in selected)
    result["wall_component_share_of_total_cycle"] = {
        name: sum(series[name][i] for i in selected) / total
        for name in ("add_wall", "middle_probe_wall", "remove_wall") if name in series}
    return result


def analyze_record(path, mode, methods, n, warmup, caller_cpus):
    data = read(path)
    check(data["schema"] == 1 and data["fixture"] == "rust_register_phase_diagnostic",
          f"{path}: diagnostic fixture mismatch")
    check(data["mode"] == mode and data["methods"] == methods and data["name_bytes"] == 8,
          f"{path}: workload differs")
    check(data["n"] == data["successful"] == n and data["errors"] == 0
          and data["warmup"] == warmup and data["full_signature_checked"] is True
          and data["final_empty"] is True, f"{path}: counts/correctness checks failed")
    subjects = {role: check_process(data, role, cpus)
                for role, cpus in (("caller", caller_cpus), ("daemon", (1,)))}
    check(subjects["caller"]["pid"] != subjects["daemon"]["pid"], f"{path}: PID alias")
    resolution = vector(data["clock_resolution_ns"], 3, "clock resolutions")
    check(all(value > 0 for value in resolution), "nonpositive clock resolution")
    for index, role in ((1, "caller"), (2, "daemon")):
        check(resolution[index] == data[f"{role}_before"]["process_cpu_resolution_ns"],
              f"{role}: CPU clock resolution mismatch")
    check(data["perf_capability"]["available"] is (data["perf_capability"]["errno"] == 0),
          f"{path}: inconsistent perf capability")
    probes = data["clock_probes_ns"]
    check(len(probes) == 256, f"{path}: expected all 256 clock probes")
    for probe in probes:
        vector(probe, 4, "clock probe")
    samples, cpu = data["wall_samples_ns"], data["cpu_stamps"]
    check(len(samples) == n and len(cpu) == (n if mode == "phase-cpu" else 0),
          f"{path}: missing/extra samples")
    loop_before, loop_after = data["loop_before"], data["loop_after"]
    for name, stamp in (("loop_before", loop_before), ("loop_after", loop_after)):
        check_stamp(stamp, name)
    check_next_stamp(loop_before, loop_after, "loop")
    for index, role in ((1, "caller"), (2, "daemon")):
        check(data[f"{role}_before"]["process_cpu_ns"] <= loop_before[index]
              <= loop_after[index] <= data[f"{role}_after"]["process_cpu_ns"],
              f"{role}: loop CPU clocks outside process snapshots")

    series = {"cycle_wall": []}
    if mode != "cycle-wall":
        series.update({name: [] for name in ("add_wall", "middle_probe_wall", "remove_wall")})
    if mode == "phase-cpu":
        series.update({f"{role}_{phase}_cpu": [] for role in ("caller", "daemon")
                       for phase in ("add", "remove", "cycle")})
    widths = {name: [] for name in ("before_add", "between_phases", "after_remove")}
    previous_end, previous_cpu = loop_before[3], loop_before
    for index, sample in enumerate(samples):
        start, add_end, remove_start, end = vector(sample, 4, f"wall[{index}]")
        check(previous_end <= start < end <= loop_after[0], f"wall[{index}]: invalid ordering")
        previous_end = end
        series["cycle_wall"].append(end - start)
        if mode == "cycle-wall":
            check(add_end == remove_start == 0, "cycle-wall has nonzero phase fields")
        else:
            check(start < add_end <= remove_start < end, f"wall[{index}]: invalid phase ordering")
            check(mode != "phase-wall" or add_end == remove_start, "phase-wall has a CPU probe gap")
            series["add_wall"].append(add_end - start)
            series["middle_probe_wall"].append(remove_start - add_end)
            series["remove_wall"].append(end - remove_start)
        if mode == "phase-cpu":
            check(isinstance(cpu[index], list) and len(cpu[index]) == 3, "expected three CPU stamps")
            first, middle, last = cpu[index]
            for stamp, location in zip(cpu[index], widths):
                check_stamp(stamp, f"CPU[{index}]/{location}")
                check_next_stamp(previous_cpu, stamp, f"CPU[{index}]/{location}")
                previous_cpu = stamp
                widths[location].append(stamp[3] - stamp[0])
            check([first[3], middle[0], middle[3], last[0]] == sample,
                  f"CPU[{index}]: wall phase boundaries do not match CPU brackets")
            for column, role in ((1, "caller"), (2, "daemon")):
                for phase, before, after in (("add", first, middle), ("remove", middle, last),
                                             ("cycle", first, last)):
                    series[f"{role}_{phase}_cpu"].append(after[column] - before[column])
    check_next_stamp(previous_cpu, loop_after, "final CPU to loop_after")
    threshold = percentile(series["cycle_wall"], .95)
    tail = [i for i, value in enumerate(series["cycle_wall"]) if value >= threshold]
    rest = [i for i, value in enumerate(series["cycle_wall"]) if value < threshold]
    return {"path": str(path), "sha256": digest(path), "mode": mode, "methods": methods,
            "n": n, "warmup": warmup, "subjects": subjects,
            "measurement_interval_monotonic_ns": [loop_before[0], loop_after[3]],
            "clock_resolution_ns": resolution, "perf_capability": data["perf_capability"],
            "metrics": {name: stats(values) for name, values in series.items()},
            "loop_cpu_us_per_cycle_including_instrumentation": {
                role: (loop_after[column] - loop_before[column]) / n / 1000
                for column, role in ((1, "caller"), (2, "daemon"))},
            "clock_probe_brackets": {name: stats([row[index] for row in probes])
                for index, name in enumerate(("wall_read", "caller_cpu_read", "daemon_cpu_read", "combined_stamp"))},
            "cpu_stamp_brackets": {name: stats(values) for name, values in widths.items() if values},
            "tail_selection": {"rule": "cycle_wall >= this record's p95 at sorted index floor((n-1)*0.95+0.5); include all ties",
                               "threshold_ns": threshold, "tail": tail_summary(series, tail),
                               "rest": tail_summary(series, rest)}}


def comparisons(records):
    indexed = {(r["window"], r["subject"], r["methods"], r["mode"]): r for r in records}
    calibrations, subjects = [], []
    for window in sorted({r["window"] for r in records}):
        for methods in METHODS:
            for subject in ("c", "candidate"):
                for newer, baseline in (("phase-wall", "cycle-wall"), ("phase-cpu", "phase-wall")):
                    a, b = (indexed[(window, subject, methods, mode)]["metrics"]["cycle_wall"]
                            for mode in (newer, baseline))
                    calibrations.append({"window": window, "subject": subject, "methods": methods,
                        "ratio": f"{newer}/{baseline}",
                        "cycle_delta_pct": {key: (a[key] / b[key] - 1) * 100 for key in METRICS}})
            for mode in MODES:
                a, b = (indexed[(window, subject, methods, mode)]["metrics"]
                        for subject in ("candidate", "c"))
                subjects.append({"window": window, "methods": methods, "mode": mode,
                    "ratio": "candidate/c", "delta_pct": {
                        name: {key: (a[name][key] / b[name][key] - 1) * 100 if b[name][key] else None
                               for key in METRICS} for name in a}})
    return {"mode_calibration": calibrations, "subject_comparisons": subjects,
            "interpretation": "Descriptive whole-case comparisons only, kept separate by window. No acceptance gate, pooled inference, or CPU/wall subtraction."}


def load_plan(path):
    plan = read(path)
    check(plan["schema_version"] == 1 and plan["orders"] == ORDERS and len(plan["steps"]) == 2,
          "expected two frozen opposite-order windows")
    check(plan["iterations"] == 2000 and plan["warmup"] == 200 and plan["probe_count"] == 256
          and plan["affinity"] == {"daemon": [1], "caller": [0, 1]}, "frozen counts/affinity differ")
    check(plan["rules"]["repeat_or_exclude"] is False and plan["rules"]["performance_acceptance"] is False,
          "diagnostic cannot become a selective performance acceptance test")
    check(set(plan["subjects"]) == {"c", "candidate"}
          and plan["subjects"]["c"]["sha256"] == C
          and plan["subjects"]["candidate"]["sha256"] == plan["candidate_sha256"] == CANDIDATE
          and plan["caller"]["sha256"] == CALLER and plan["namespace_sha256"] == NAMESPACE,
          "frozen artifact identities differ")
    inputs = plan["input_sha256"]
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        check(not relative.is_absolute() and ".." not in relative.parts
              and re.fullmatch(r"[0-9a-f]{64}", expected), "invalid frozen input")
        check(digest(REPO / name) == expected, f"frozen input changed: {name}")
    settings = []
    for index, step in enumerate(plan["steps"]):
        args = step["argv"]
        check(step["name"] == f"window-{index}" and args[:2] == ["tools/r95_device_smoke.py", "ubusd"]
              and args[2] == plan["subjects"]["candidate"]["path"]
              and args[3] == f'{plan["output"]}/window-{index}'
              and step["driver_result"] == f'{args[3]}/result.json', "driver/window contract differs")
        check(args[-1] == "--pilot" and len(args) == 15, "unexpected driver flags")
        flags = dict(zip(args[4:-1:2], args[5:-1:2]))
        check(set(flags) == {"--guard", "--recovery-gate", "--benchmark", "--workload-script", "--iterations"}
              and flags["--iterations"] == "2000" and flags["--benchmark"] == plan["caller"]["path"],
              "driver workload/caller flags differ")
        files = {"driver": args[0], "candidate": args[2], "guard": flags["--guard"],
                 "recovery_gate": flags["--recovery-gate"], "benchmark": flags["--benchmark"],
                 "workload": flags["--workload-script"]}
        settings.append({key: inputs[value] for key, value in files.items()})
    gate = read(REPO / flags["--recovery-gate"])
    check(gate["offline_backup_verified"] is True and gate["configuration_matches_backup"] is True,
          "recovery gate invalid")
    return plan, settings, gate["boot_id"]


def router_report(root, plan_path):
    plan, settings, boot = load_plan(plan_path)
    check((root / "COMPLETE").is_file() and digest(root / "plan.json") == digest(plan_path),
          "series incomplete or captured plan differs")
    check({p.name for p in root.glob("window-*")} == {"window-0", "window-1"},
          "exactly two windows required; no excluded/replacement windows")
    records, windows = [], []
    for index, expected in enumerate(settings):
        window = root / f"window-{index}"
        raw = window / "raw"
        check((raw / "COMPLETE").is_file() and not any((base / marker).exists()
              for base in (root, window) for marker in ("FAILED", "FAILED.json", "failure.json")),
              "incomplete/failed evidence")
        raw_hashes = archive_hashes(window)
        result = read(window / "result.json")
        check(all(result.get(key) is True for key in HEALTH), "driver health/cleanup failed")
        collection = {"exit": 0, "component": "ubusd", "implementation": "rs", "iterations": 2000,
                      "installed": False, "matrix": False, "production_mode": "stock",
                      "pilot_only": True, "correctness_smoke_only": False}
        check(all(type(result.get(key)) is type(value) and result[key] == value
                  for key, value in collection.items()), "collection mode differs")
        check(all(result.get(f"{key}_sha256") == value for key, value in expected.items()),
              "driver/tool identities differ")
        health = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
        check(health[0] == health[1] and health[0]["boot_id"] == boot and health[0]["mode"] == "stock",
              "health/boot/stock production identity changed")
        check(set(health[0]["verified_components"]) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"},
              "production identity coverage differs")
        check((raw / "boot-id.txt").read_text().strip() == boot
              and (raw / "kernel.txt").read_text().strip() == "6.12.94", "raw boot/kernel differs")
        identities = {"/sbin/ubusd": C, "/tmp/bin/ubusd-rs": CANDIDATE,
                      "/tmp/bin/owrt-benchmark": CALLER, "/tmp/bin/ns-exec": NAMESPACE}
        check(hashes(raw / "identities.txt") == hashes(raw / "expected-identities.txt") == identities
              and hashes(raw / "binary-sha256.txt") == {"/tmp/bin/ubusd-rs": CANDIDATE}, "raw ELF identities differ")
        identity_checks = (raw / "identity-check.log").read_text().splitlines()
        check(len(identity_checks) == 4 and set(identity_checks) == {f"{name}: OK" for name in identities},
              "live ELF identity check differs")
        order = plan["orders"][index]
        for filename, key in (("side-order.txt", "sides"), ("mode-order.txt", "modes"), ("method-order.txt", "methods")):
            check((raw / filename).read_text().split() == list(map(str, order[key])), "recorded case order differs")
        check({p.name for p in raw.iterdir() if p.is_dir()} == {"c", "candidate"}, "raw subject set differs")
        previous_end, callers = 0, set()
        for subject in order["sides"]:
            folder = raw / subject
            check((folder / "COMPLETE").is_file() and not (folder / "objects-after.txt").read_bytes()
                  and not (folder / "daemon.log").read_bytes(), "subject incomplete/logs/objects remain")
            check((folder / "daemon-exit.txt").read_text().strip() in ("0", "143"), "unclean daemon exit")
            expected_cases = {f"{mode}-{methods}.json" for mode in MODES for methods in METHODS}
            check({p.name for p in folder.glob("*.json")} == expected_cases, "missing/unexpected phase records")
            daemon_id = None
            for mode in order["modes"]:
                for methods in order["methods"]:
                    stem = f"{mode}-{methods}"
                    check(not (folder / f"{stem}.log").read_bytes(), "caller stderr nonempty")
                    record = analyze_record(folder / f"{stem}.json", mode, methods, 2000, 200, (0, 1))
                    current = tuple(record["subjects"]["daemon"][key] for key in ("pid", "start_ticks"))
                    check(daemon_id is None or current == daemon_id, "daemon changed between cases")
                    daemon_id = current
                    caller = tuple(record["subjects"]["caller"][key] for key in ("pid", "start_ticks"))
                    check(caller not in callers, "caller process reused between cases")
                    callers.add(caller)
                    interval = record["measurement_interval_monotonic_ns"]
                    check(previous_end <= interval[0], "cases not in frozen chronological order")
                    previous_end = interval[1]
                    record.update({"window": index, "subject": subject})
                    records.append(record)
            command = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"
            check((folder / "expected.cmdline").read_bytes() == command, "expected daemon argv differs")
            for phase in ("before", "after"):
                check((folder / f"{phase}.cmdline").read_bytes() == command, "live daemon argv differs")
                check(proc_identity(folder / f"{phase}.stat") == daemon_id, "live daemon PID/starttime differs")
                status = proc_status(folder / f"{phase}.status", daemon_id[0], 1)
                check(int(status["Cpus_allowed"].replace(",", ""), 16) == 2, "live daemon CPU mask differs")
                check(hashes(folder / f"{phase}-exe.sha256") == {f"/proc/{daemon_id[0]}/exe": plan["subjects"][subject]["sha256"]},
                      "live daemon executable differs")
        windows.append({"window": index, "order": order, "raw_sha256": raw_hashes,
                        "raw_archive_sha256": digest(window / "raw.tar.gz"),
                        "driver_result_sha256": digest(window / "result.json"),
                        "health_sha256": {phase: digest(window / f"health-{phase}.json") for phase in ("before", "after")}})
    check(len(records) == 24, "expected all 24 diagnostic records")
    return {"scope": "Two guarded router diagnostic windows; observer calibration only, no performance acceptance",
            "plan_sha256": digest(plan_path), "record_count": 24, "windows": windows, "records": records,
            "comparisons": comparisons(records),
            "assertions": {"all_24_records": True, "archive_matches_expanded_raw": True,
                           "health_cleanup_stock_identity": True, "PID_starttime_affinity": True,
                           "full_wall_CPU_bracket_ordering": True},
            "limitations": ["CPU intervals include instrumentation and may overlap across processes. No wall-minus-CPU or scheduler-wait inference is made.",
                            "Middle CPU sampling delays REMOVE; mode comparisons are observer calibration, never corrections subtracted from requests.",
                            "Each tail is selected by its own cycle p95 with ties; samples are not independent experimental repeats.",
                            "Two windows remain separate. No original formal benchmark observations are pooled into this diagnostic."]}


def oracle_report(root):
    manifest = read(root / "result.json")
    check(manifest["passed"] is True and len(manifest["cases"]) == 12, "Oracle smoke incomplete")
    expected = {f"{subject}-{methods}-{mode}" for subject in ("c", "combined")
                for methods in METHODS for mode in MODES}
    check({case["case"] for case in manifest["cases"]} == expected, "Oracle case set differs")
    by_case = {case["case"]: case for case in manifest["cases"]}
    records = []
    for subject in ("c", "combined"):
        for methods in METHODS:
            for mode in MODES:
                stem = f"{subject}-{methods}-{mode}"
                path = root / f"{stem}.json"
                check(digest(path) == by_case[stem]["file_sha256"]
                      and by_case[stem]["passed"] is True, f"{stem}: smoke identity differs")
                check((root / f"{stem}.stderr").read_bytes() == b"", f"{stem}: nonempty stderr")
                record = analyze_record(path, mode, methods, 100, 20, (0,))
                record.update({"window": "oracle-smoke", "subject": "candidate" if subject == "combined" else "c"})
                records.append(record)
    return {"scope": "Oracle correctness smoke; not router evidence or a performance comparison",
            "records": records, "record_count": len(records)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan", type=Path, help="frozen router plan; required without --oracle-smoke")
    parser.add_argument("--oracle-smoke", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite analysis output")
    if args.oracle_smoke:
        result = oracle_report(args.root.resolve())
    else:
        if args.plan is None:
            parser.error("--plan is required for router analysis")
        result = router_report(args.root.resolve(), args.plan.resolve())
    result.update({"schema": 1, "passed": True, "analyzer_sha256": digest(Path(__file__))})
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"passed": True, "records": result["record_count"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
