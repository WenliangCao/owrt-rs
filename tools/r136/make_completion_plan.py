#!/usr/bin/env python3
"""Freeze the R136 completion coverage using the completed R134 collection recipe.

This only reads local identities and writes a plan. The guarded R134 runner owns
all later physical-router collection; production remains the exact image C.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from make_formal_plan import C_SHA, CANDIDATE_SHA, NAMESPACE_SHA, ROOT, relative

SOURCE = "private/r134/router-finish-03/plan.json"
CANDIDATE = "private/r136/build-01/combined/ubusd-rs"
STOCK = "private/r95/ubusd-pilot/stock"
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config",
          "same_production_identity", "same_host_mounts")
RULES = {
    "matrix": "15 workloads, ABBA x4, n10000, daemon CPU1; identical uploaded Rust owrt_ubus::Connection benchmark on both sides.",
    "direct_events": "3 exact-image libubus SEND workloads, ABBA x4, n5000/warmup200, daemon CPU1/client CPU0.",
    "decision": "Primary R136 rule: median of eight disjoint adjacent candidate/stock paired percentage changes < -1% and >=7/8 lower pairs: win; median > +1% and >=7/8 higher pairs: loss; otherwise unresolved. Report mean/p50/p95/p99 and daemon process-clock CPU; no tick fallback.",
    "historical_rule": "Also disclose the R134 side-median/sign rule in a separately named field: lower candidate side median and >=7/8 lower pairs wins; higher and >=7/8 higher loses; otherwise unresolved. Never mix these counts with primary R136 decisions.",
    "memory": "ABBA x1 per idle/large/fanout fixture; report every RssAnon/VmRSS/VmData/Pss sample and same-process phase increment, including increases. Descriptive snapshots only; no peak or statistical memory superiority claim.",
    "correctness": "R136 same-ELF wire/FD prerequisites plus C and candidate grouped/interleaved/monitor/slow-reader stress; every health/identity/archive/cleanup gate required. First failure stops collection.",
    "scope": "Independent C/combined completion coverage. Do not pool prior R136 targeted, R134, R135 or Oracle samples; no new R134 comparison or replacement of their conclusions.",
    "reporting": "Report every lane/metric, all descriptive losses and every higher median. No global superiority/adoption pass inferred from counts; retain registration-tail and memory negative findings.",
    "execution": "Exactly frozen windows; no retries, result-driven exclusions or added windows. Only the coordinating main thread may run the physical router; never deploy.",
}
SUPPORT = (
    "tools/r136/make_completion_plan.py", "tools/r136/make_formal_plan.py",
    "tools/benchmark/analyze.py", "tools/benchmark/analyze_candidate.py",
    "tools/r134/ubusd_report.py", "tools/r134/ubusd_latency_report.py",
    "tools/r130_registration_report.py", "tools/r131_latency_report.py",
    "tools/r131_memory_supplement.py", "tools/r131_memory_audit.py",
    "tools/r124_event_memory_report.py", "tools/r131_stress_report.py",
    "docs/reviews/r124-memory-plan-v2.json",
    "docs/reviews/R136_COMPLETION_PLAN.md",
)


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def make_plan(output):
    source = read(SOURCE)
    if sha(CANDIDATE) != CANDIDATE_SHA or sha(STOCK) != C_SHA:
        raise ValueError("the frozen R136 candidate or image C identity differs")
    prerequisites = [f"private/r136/router-correctness-01/{kind}/result.json"
                     for kind in ("events", "fd")]
    boots = set()
    for path in prerequisites:
        result = read(path)
        if result.get("candidate_sha256") != CANDIDATE_SHA or not all(
                result.get(key) is True for key in HEALTH):
            raise ValueError(f"invalid same-candidate correctness prerequisite: {path}")
        health = [read(str(Path(path).parent / f"health-{phase}.json"))
                  for phase in ("before", "after")]
        if health[0] != health[1] or health[0]["mode"] != "stock":
            raise ValueError(f"prerequisite health differs: {path}")
        boots.add(health[0]["boot_id"])
    if len(boots) != 1:
        raise ValueError("correctness prerequisites span different boots")

    before = "private/r134/bins-ubusd/ubusd-rs"
    def replace(value):
        if isinstance(value, str):
            return value.replace(source["output"], output).replace(before, CANDIDATE)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value
    steps = [replace(copy.deepcopy(step)) for step in source["steps"]
             if step["name"] != "correctness-fd"]
    if len(steps) != 31 or sum(s["name"].startswith("latency-") for s in steps) != 16:
        raise ValueError("R134 completion recipe has changed shape")
    # Freeze only artifacts actually used by the selected steps, plus analysis
    # dependencies. Do not make the old R134 candidate or correctness a new gate.
    inputs = {SOURCE, *SUPPORT, *prerequisites,
              "tools/r134/ubusd_router_finish.py", "tools/r84_device_probe.py",
              "tools/benchmark/isolated.sh", CANDIDATE, STOCK}
    for step in steps:
        for item in step["argv"]:
            if (ROOT / item).is_file():
                inputs.add(item)
    for path in list(inputs):
        expected = source["input_sha256"].get(path)
        if expected is not None and sha(path) != expected:
            raise ValueError(f"mature R134 input changed: {path}")
    return {
        "schema_version": 1,
        "scope": "R136 independent physical completion coverage; exact C/combined; no deployment",
        "output": output, "candidate_sha256": CANDIDATE_SHA,
        "subjects": {"stock": {"path": STOCK, "sha256": C_SHA},
                     "candidate": {"path": CANDIDATE, "sha256": CANDIDATE_SHA}},
        "namespace_sha256": NAMESPACE_SHA, "boot_id": boots.pop(),
        "source_recipe": {"path": SOURCE, "sha256": sha(SOURCE)},
        "physical_windows": {"stress": 2, "matrix": 16, "direct_send": 16,
                             "memory": 12, "total": 46},
        "prerequisites": prerequisites, "rules": RULES, "steps": steps,
        "input_sha256": {path: sha(path) for path in sorted(inputs)},
        "analysis_note": "The completion reporter reuses the frozen analysis modules above. Its final source hash is recorded with derived results; decision rules are frozen here before collection.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=Path("private/r136/completion-plan-01.json"))
    parser.add_argument("--results", type=Path, default=Path("private/r136/completion-01"))
    args = parser.parse_args()
    plan_path, result_path = ROOT / relative(args.plan), ROOT / relative(args.results)
    if plan_path.exists() or result_path.exists() or result_path in plan_path.parents:
        parser.error("plan and results paths must be new and disjoint")
    plan = make_plan(relative(args.results))
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    with plan_path.open("x") as stream:
        json.dump(plan, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"plan": relative(plan_path), "steps": len(plan["steps"]),
                      "physical_windows": plan["physical_windows"],
                      "plan_sha256": sha(relative(plan_path))}))


if __name__ == "__main__":
    main()
