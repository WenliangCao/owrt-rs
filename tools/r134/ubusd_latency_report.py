#!/usr/bin/env python3
"""Verify all sixteen R134 physical-router user-event latency windows.

Usage: ubusd_latency_report.py RAW_ROOT --output NEW_REPORT.json
Expected window names: 01-stock, 02-candidate, 03-candidate, 04-stock,
repeated through 16-stock. No partial-series or alternate-subject mode.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r130_registration_report import archive_hashes, check, digest, hashes, proc_status, read
from r131_latency_report import CMDLINE, HEALTH, LANES, sample_metrics
from ubusd_report import ORDER, PAIRS, RUNS, compare


BOOT = "75a17130-62f9-43f8-bd28-7bbbb44ad5c8"
SUBJECTS = {
    "stock": "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88",
    "candidate": "98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0",
}
TOOLS = {
    "driver": "f2ba002279ac538966d1a5df3688cfc8e0c8252266921247a33a2e8a87ad5e6d",
    "workload": "66ac6bbfdf74119fd8de503d3b30450bd781f0a6d080ada57335e31fd2f3b2cd",
    "guard": "58b96cc6307dc7d3810003fcc557f361901630227ae32100575b0da342a65d6d",
    "recovery_gate": "08b3009b8e3464c895ec60092b19e304b88b4c960ca7d6870570415bce94f536",
    "benchmark": "0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693",
    "event_benchmark": "aef917bf15119f5108e963e6b2e1745b3aee74fc71b2fcf2f6a7ccf65de859f3",
    "namespace_helper": "fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2",
}
METRICS = {name: name for name in ("mean_us", "p50_us", "p95_us", "p99_us")}
METRICS["daemon_cpu_us_per_op"] = "daemon_cpu_us_op"


def verify_window(root, name, side):
    window, sha = root / name, SUBJECTS[side]
    raw = window / "raw"
    check((raw / "COMPLETE").is_file() and not (window / "FAILED.json").exists(), f"{name}: incomplete")
    raw_hashes = archive_hashes(window)
    result = read(window / "result.json")
    check(all(result.get(key) is True for key in HEALTH), f"{name}: driver health/cleanup")
    implementation = "c" if side == "stock" else "rs"
    expected = {"exit": 0, "component": "ubusd", "production_mode": "stock", "installed": False,
                "pilot_only": True, "matrix": False, "correctness_smoke_only": False,
                "iterations": 5000, "implementation": implementation, "candidate_sha256": sha}
    check(all(type(result.get(key)) is type(value) and result[key] == value for key, value in expected.items()),
          f"{name}: collection mode/subject")
    for key, value in TOOLS.items():
        if key != "namespace_helper":
            check(result.get(f"{key}_sha256") == value, f"{name}: {key} hash")
    health = [read(window / f"health-{phase}.json") for phase in ("before", "after")]
    check(health[0] == health[1] and health[0]["boot_id"] == BOOT and health[0]["mode"] == "stock",
          f"{name}: physical-router boot/health differs")
    check(set(health[0]["verified_components"]) == {"procd", "ubusd", "netifd", "rpcd", "logd", "httpd", "uci", "fw4", "reload-config"},
          f"{name}: production component identities")
    check((raw / "kernel.txt").read_text().strip() == "6.12.94"
          and (raw / "cpus-online.txt").read_text().strip() == "0-1", f"{name}: target kernel/CPU topology")

    meta = read(raw / "meta.json")
    pid = meta["subject_pid"]
    check(type(pid) is int and pid > 0, f"{name}: daemon pid")
    expected_meta = {"subject_pid": pid, "subject_cpu": 1, "client_cpu": 0,
                     "implementation": implementation, "iterations": 5000, "warmup": 200,
                     "scenarios": list(LANES), "exact_image_caller": True, "daemon_argv0": "/sbin/ubusd",
                     "per_operation_latency": True, "latency_clock": "CLOCK_MONOTONIC"}
    check(meta == expected_meta, f"{name}: workload metadata")
    executable = "/sbin/ubusd" if side == "stock" else "/tmp/bin/ubusd-rs"
    starts = []
    for phase in ("before", "after"):
        prefix = raw / f"daemon-{phase}"
        proc_status(Path(str(prefix) + ".status"), pid, 1)
        check(Path(str(prefix) + ".cmdline").read_bytes() == CMDLINE, f"{name}: argv")
        check(Path(str(prefix) + ".exe").read_text().strip() == executable, f"{name}: executable path")
        check(hashes(Path(str(prefix) + ".exe-sha256")) == {f"/proc/{pid}/exe": sha}, f"{name}: live ELF")
        starts.append(Path(str(prefix) + ".starttime").read_text().strip())
    check(starts[0] == starts[1] and starts[0].isdigit() and int(starts[0]) > 0, f"{name}: daemon replaced")
    check((raw / "daemon-expected.cmdline").read_bytes() == CMDLINE, f"{name}: expected argv")
    identities = {
        "binary": {executable: sha},
        "benchmark": {"/tmp/bin/owrt-benchmark": TOOLS["benchmark"], "/tmp/bin/ns-exec": TOOLS["namespace_helper"]},
        "event-benchmark": {"/tmp/bin/event-benchmark": TOOLS["event_benchmark"]},
    }
    for prefix, values in identities.items():
        for suffix in ("-sha256.txt", "-after-sha256.txt"):
            check(hashes(raw / f"{prefix}{suffix}") == values, f"{name}: {prefix} identity")
    check(hashes(raw / "harness-sha256.txt") == {"/tmp/workload.sh": TOOLS["workload"]}, f"{name}: workload identity")
    check(all(not (raw / f"objects-{phase}.txt").read_bytes() for phase in ("before", "after")), f"{name}: leaked objects")
    check(read(raw / "summary.json") == {"daemon_pid": pid, "iterations": 5000, "warmup": 200,
          "scenarios": 3, "serial_client": True, "event_payload_validated": True,
          "per_operation_latency": True}, f"{name}: summary")
    metrics = {lane: sample_metrics(read(raw / f"{lane}.json"), 5000, 200, lane, pid) for lane in LANES}
    return {"run": name, "side": side, "daemon_pid": pid, "daemon_start_ticks": int(starts[0]),
            "metrics": metrics, "raw_archive_sha256": digest(window / "raw.tar.gz"),
            "raw_files_sha256": raw_hashes, "driver_result_sha256": digest(window / "result.json"),
            "health_sha256": {phase: digest(window / f"health-{phase}.json") for phase in ("before", "after")}}


def derive(root):
    check((root / "COMPLETE").is_file() and not (root / "FAILED").exists(), "series incomplete")
    actual = {path.name for path in root.iterdir() if path.is_dir() and re.match(r"^\d+-", path.name)}
    check(actual == set(RUNS), "expected exactly sixteen ABBA window directories")
    windows = [verify_window(root, run, side) for run, side in zip(RUNS, ORDER)]
    lanes = {lane: {metric: compare({window["run"]: window["metrics"][lane][source] for window in windows})
                    for metric, source in METRICS.items()} for lane in LANES}
    counts = Counter(result["decision"] for lane in lanes.values() for result in lane.values())
    table = [{"lane": lane, "metrics": {metric: {
        "stock_median": values["side_median"]["stock"], "candidate_median": values["side_median"]["candidate"],
        "delta_pct": values["ratio_of_side_medians_delta_pct"], "lower_pairs": values["lower_pairs"],
        "higher_pairs": values["higher_pairs"], "decision": values["decision"]}
        for metric, values in lanes[lane].items()}} for lane in LANES]
    return {"schema_version": 1, "scope": "R134 exact-image caller user-event latency on the physical AX3000T",
            "physical_router_windows_verified": 16, "all_windows_cleaned_and_stock": True,
            "boot_id": BOOT, "subjects": SUBJECTS, "tools": TOOLS, "iterations": 5000, "warmup": 200,
            "reporter_sha256": digest(Path(__file__)),
            "support_sha256": {name: digest(Path(__file__).resolve().parents[1] / name) for name in
                               ("r130_registration_report.py", "r131_latency_report.py", "r134/ubusd_report.py")},
            "order": ORDER, "pairing": [{"stock": stock, "candidate": candidate} for stock, candidate in PAIRS],
            "rule": "Lower side median and at least 7/8 lower pairs: win; higher side median and at least 7/8 higher pairs: loss; otherwise tie. No effect-size band.",
            "cpu_source": "daemon CLOCK_PROCESS_CPUTIME interval divided by 5000 timed operations; no tick fallback",
            "metric_decisions": {key: counts[key] for key in ("win", "loss", "tie")},
            "table": table, "lanes": lanes, "windows": windows,
            "limitations": [
                "A complete sixteen-window physical series is required. Per-operation samples are not independent router windows; tail percentiles are computed within each window.",
                "Caller samples cover SEND through all callbacks, or the unmatched drain barrier. Two monotonic reads and payload validation remain included; no overhead is subtracted.",
                "These are user SEND events, unlike the main matrix's registration-generated object events. Eight handlers share one listener connection.",
                "Reports fifteen separate sign decisions, not a global ubusd pass or multiplicity-adjusted statistical claim. Tie does not prove equivalence.",
                "Raw archive contents, expanded files and recorded identities are reconciled. Configuration, production process and mount stability rely on the frozen driver's assertions; its raw before/after strings are not archived.",
                "Monitor, grouped/interleaved owners, slow readers, memory and nine-component integration are outside this supplement.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = derive(args.root)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"physical_router_windows_verified": 16, **result["metric_decisions"]}))


if __name__ == "__main__":
    main()
