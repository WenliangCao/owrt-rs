#!/usr/bin/env python3
"""Reuse frozen R135 per-request syscall attribution on exact R138 subjects."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--oracle-host-only", action="store_true", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    tools = Path(__file__).resolve().parents[1]
    runner = load("r136_runner", tools / "r136/oracle_batch.py")
    trace = load("r135_syscalls", tools / "r135/syscalls.py")
    runner.require(platform.system() == "Linux" and platform.machine() == "aarch64"
                   and os.geteuid() == 0 and not Path("/etc/openwrt_release").exists(),
                   "requires root on Oracle aarch64 Linux")
    manifest, subjects = runner.load_manifest(args.manifest.resolve())
    runner.require(set(subjects) == {"c", "r136", "remove"}, "expected C/R136/REMOVE")
    runner.require(subjects["r136"]["sha256"] ==
                   "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330", "R136 differs")
    runner.require({0, 1} <= os.sched_getaffinity(0), "CPUs 0/1 unavailable")
    trace.ROOTFS = Path(manifest["rootfs"]["loader"]).parent.parent
    trace.LIBRARIES = {str(Path(path).relative_to(trace.ROOTFS)): digest
                       for path, digest in manifest["libraries"].items()}
    trace.BENCHMARK = Path(manifest["benchmark"]["path"])
    trace.BENCHMARK_SHA = manifest["benchmark"]["sha256"]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    plan = {"scope": "R138 syscall mechanism only; traced latency and CPU excluded",
            "manifest": manifest, "runner_sha256": trace.sha(__file__),
            "attribution_runner_sha256": trace.sha(tools / "r135/syscalls.py"),
            "n": trace.N, "warmup": trace.WARMUP, "attribution": trace.ATTRIBUTION,
            "runs": [{"methods": methods, "label": label} for methods, labels in
                     ((1, ("c", "r136", "remove")), (16, ("remove", "r136", "c"))) for label in labels]}
    trace.write_json(out / "plan.json", plan)
    records = []
    try:
        for item in plan["runs"]:
            label, methods = item["label"], item["methods"]
            subject = subjects[label]
            case = out / f"{label}-{methods}"
            try:
                record = trace.run_case(case, label, Path(subject["path"]), subject["sha256"], methods)
                data = json.loads((case / "caller.json").read_text())
                runner.require(data["successful"] == trace.N and data["errors"] == 0
                               and data["warmup"] == trace.WARMUP, "caller did not complete exact cycles")
                records.append(record)
                print(f"COMPLETE {label} methods={methods}", flush=True)
            finally:
                (case / "bus.sock").unlink(missing_ok=True)
        indexed = {(item["subject"], item["methods"]): item for item in records}
        mechanism = {str(methods): {
            "r136_sendmsg_per_cycle": indexed["r136", methods]["measured_calls_per_cycle"]["sendmsg"],
            "remove_sendmsg_per_cycle": indexed["remove", methods]["measured_calls_per_cycle"]["sendmsg"]}
            for methods in (1, 16)}
        confirmed = all(item["r136_sendmsg_per_cycle"] == 3 and item["remove_sendmsg_per_cycle"] == 2
                        for item in mechanism.values())
        trace.write_json(out / "results.json", {"passed": True, "mechanism_confirmed": confirmed,
                                               "mechanism": mechanism, "records": records})
        (out / "COMPLETE").touch()
    except BaseException as error:
        trace.write_json(out / "failure.json", {"error": f"{type(error).__name__}: {error}"})
        (out / "FAILED").touch()
        raise


if __name__ == "__main__":
    main()
