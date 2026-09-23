#!/usr/bin/env python3
"""Freeze six independent memory windows after the failed completion series.

Original evidence and its failed status are immutable. This only writes a new
local plan; the coordinating main thread runs the existing guarded collector.
"""
import argparse
import json
from pathlib import Path

from make_completion_plan import ROOT, CANDIDATE_SHA, HEALTH, relative, read, sha

SOURCE = "private/r136/completion-plan-01.json"
ORIGINAL = "private/r136/completion-01"
OLD_GOOD = [f"memory/idle/{name}" for name in ("01-stock", "02-candidate", "03-candidate", "04-stock")]
OLD_GOOD += ["memory/large/01-stock", "memory/large/02-candidate"]
FAILED = "memory/large/03-candidate"


def make_plan(output, health_audit):
    source = read(SOURCE)
    if not (ROOT / ORIGINAL / "FAILED").is_file() or (ROOT / ORIGINAL / "COMPLETE").exists():
        raise ValueError("original collection must remain failed and incomplete")
    failed = read(f"{ORIGINAL}/{FAILED}/result.json")
    if failed.get("passed") is not False or failed.get("cleanup_verified") is not False or failed.get("exit") != 0:
        raise ValueError("original failed-health window differs")
    audit = read(health_audit)
    if not all(audit.get(key) is True for key in ("read_only_post_failure_check", "health_equals_failed_window_before",
               "same_production_identity", "same_config", "no_owned_test_directories_or_mounts", "original_failure_unchanged")):
        raise ValueError("post-failure read-only audit failed")
    audit_files = {str(Path(health_audit).parent / name): expected for name, expected in audit["evidence_sha256"].items()}
    if any(sha(path) != expected for path, expected in audit_files.items()):
        raise ValueError("post-failure audit evidence changed")
    health = read(str(Path(health_audit).parent / "health.json"))
    if health.get("mode") != "stock" or health.get("boot_id") != source["boot_id"] or len(health.get("verified_components", [])) != 9:
        raise ValueError("post-failure audit must contain exact-stock, same-boot nine-component health")
    names = {"memory-large-03-candidate", "memory-large-04-stock",
             *(f"memory-fanout-{name}" for name in ("01-stock", "02-candidate", "03-candidate", "04-stock"))}
    def relocate(value):
        if isinstance(value, str):
            return value.replace(ORIGINAL, output)
        if isinstance(value, list):
            return [relocate(item) for item in value]
        if isinstance(value, dict):
            return {key: relocate(item) for key, item in value.items()}
        return value
    steps = [relocate(step) for step in source["steps"] if step["name"] in names]
    if len(steps) != 6:
        raise ValueError("expected exactly six supplemental windows")
    inputs = {SOURCE, health_audit, "tools/r136/make_memory_supplement_plan.py",
              "tools/r136/make_completion_plan.py", "tools/r136/make_formal_plan.py",
              "tools/r134/ubusd_router_finish.py", "tools/r84_device_probe.py", "tools/benchmark/isolated.sh",
              f"{ORIGINAL}/FAILED", f"{ORIGINAL}/steps.json", f"{ORIGINAL}/{FAILED}/result.json",
              f"{ORIGINAL}/{FAILED}/raw.tar.gz"}
    inputs.update(audit_files)
    for step in steps:
        inputs.update(item for item in step["argv"] if (ROOT / item).is_file())
    for name in OLD_GOOD:
        window = f"{ORIGINAL}/{name}"
        result = read(window + "/result.json")
        side = "stock" if name.endswith("stock") else "candidate"
        if not all(result.get(key) is True for key in HEALTH) or result["candidate_sha256"] != source["subjects"][side]["sha256"]:
            raise ValueError(f"named previous passed window invalid: {name}")
        inputs.update(f"{window}/{file}" for file in ("result.json", "raw.tar.gz", "health-before.json", "health-after.json"))
    for path in inputs:
        if path in source["input_sha256"] and sha(path) != source["input_sha256"][path]:
            raise ValueError(f"frozen collection artifact changed: {path}")
    return {"schema_version": 1, "scope": "Independent six-window R136 memory supplement after an explicitly retained failed collection",
            "output": output, "candidate_sha256": CANDIDATE_SHA, "subjects": source["subjects"],
            "boot_id": source["boot_id"], "namespace_sha256": source["namespace_sha256"],
            "source_plan": {"path": SOURCE, "sha256": sha(SOURCE)},
            "post_failure_health_audit": {"path": health_audit, "sha256": sha(health_audit)},
            "prior_passed_windows": OLD_GOOD, "excluded_failed_window": f"{ORIGINAL}/{FAILED}",
            "steps": steps, "input_sha256": {path: sha(path) for path in sorted(inputs)},
            "rules": {"collection": "Exactly six new windows; first failure stops. Do not alter or repair the old FAILED marker, result, health or raw evidence.",
                      "memory": "Describe the six named previously passed windows plus six independent new windows, retaining source labels. No continuous-original-ABBA or original-46-window-success claim.",
                      "failed_window": "Exclude original large/03-candidate from qualified summaries; separately publish its raw memory diagnostics and failed final-health status, including increases.",
                      "performance": "Original completed matrix and SEND comparisons retain their frozen samples/rules; no timing is collected or pooled by this supplement.",
                      "reporting": "All memory metrics and increases remain visible; descriptive snapshots only, not allocator peaks, equivalence, statistical memory superiority or nine-component integration."}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health-audit", type=Path, required=True)
    parser.add_argument("--plan", type=Path, default=Path("private/r136/memory-supplement-plan-01.json"))
    parser.add_argument("--results", type=Path, default=Path("private/r136/memory-supplement-01"))
    args = parser.parse_args()
    plan_path, output = ROOT / relative(args.plan), relative(args.results)
    if plan_path.exists() or (ROOT / output).exists():
        parser.error("supplement plan and result paths must be new")
    plan = make_plan(output, relative(args.health_audit))
    with plan_path.open("x") as stream:
        json.dump(plan, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"plan": relative(plan_path), "plan_sha256": sha(relative(plan_path)), "new_windows": 6}))


if __name__ == "__main__":
    main()
