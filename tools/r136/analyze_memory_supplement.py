#!/usr/bin/env python3
"""Combine named passed evidence with an independent six-window memory supplement.

The original collection must remain FAILED. Its failed memory window is
published separately as raw diagnostics, never promoted into qualified data.
"""
import argparse
import json
from pathlib import Path

import analyze_completion as base
from make_memory_supplement_plan import make_plan, ORIGINAL, OLD_GOOD, FAILED


def failed_diagnostic(root, source, memory):
    window = root / FAILED
    result = base.read(window / "result.json")
    base.check(result["passed"] is False and result["cleanup_verified"] is False and result["exit"] == 0,
               "failed window was promoted or altered")
    base.check(result["cleanup_error"] == {"type": "RuntimeError", "message": "ssh exited 255"}, "original health failure differs")
    archived = base.archive_hashes(window)
    spec = {"name": "large/03-candidate", "kind": "large", "subject": "candidate", "order": 2}
    rows = base.memory_audit.audit_event(window, spec, {"subjects": source["subjects"]})
    comparisons = []
    values = {(row["fixture"], row["measure"], row["metric"]): row
              for row in memory["measurements"] if row["kind"] == "large"}
    for row in rows:
        for metric in ("rssanon", "vmrss", "vmdata", "pss"):
            if row[metric + "_kb"] == "NA":
                continue
            key = (f"bytes_{row['payload_bytes']}", f"{row['phase']}_{row['delay_seconds']}s", metric)
            stock = values[key]["side_median"]["stock"]
            comparisons.append({"payload_bytes": int(row["payload_bytes"]), "phase": row["phase"],
                                "delay_seconds": int(row["delay_seconds"]), "metric": metric, "unit": "KiB",
                                "failed_candidate_observation": int(row[metric + "_kb"]),
                                "qualified_stock_median": stock,
                                "difference": int(row[metric + "_kb"]) - stock})
    return {"qualified": False, "included_in_summary": False,
            "reason": "Workload exited 0; the final production watchdog health probe lost SSH (255). The original passed/cleanup_verified flags remain false.",
            "collector_step_exit": 1, "measurement_exit": result["exit"],
            "passed": result["passed"], "cleanup_verified": result["cleanup_verified"],
            "candidate_sha256": result["candidate_sha256"], "raw_archive_sha256": base.digest(window / "raw.tar.gz"),
            "result_sha256": base.digest(window / "result.json"), "raw_files_verified": len(archived),
            "raw_proc_reconciled": True, "memory": rows, "diagnostic_comparisons": comparisons,
            "all_diagnostic_increases": [row for row in comparisons if row["difference"] > 0],
            "limitation": "Unqualified single-window diagnostics only; a later healthy observation does not replace the failed immediate health gate."}


def analyze(root, plan_path):
    base.check(__debug__, "Python -O disables reused evidence assertions")
    plan = base.read(plan_path)
    base.check(plan == make_plan(plan["output"], plan["post_failure_health_audit"]["path"]),
               "supplement differs from its frozen six-window recipe or inputs")
    base.check(root.resolve() == (base.ROOT / plan["output"]).resolve(), "supplement location differs")
    base.check((root / "COMPLETE").is_file() and not (root / "FAILED").exists(), "independent supplement incomplete/failed")
    base.check(base.digest(root / "plan.json") == base.digest(plan_path), "captured supplement plan differs")
    base.check(base.read(root / "steps.json") == [{"name": step["name"], "exit": 0} for step in plan["steps"]],
               "supplement did not pass exactly six steps")
    source_path = base.ROOT / plan["source_plan"]["path"]
    source = base.read(source_path)
    original = base.ROOT / ORIGINAL
    for path, expected in source["input_sha256"].items():
        base.check(base.digest(base.ROOT / path) == expected, f"original frozen input changed: {path}")
    base.check(base.digest(original / "plan.json") == base.digest(source_path), "original captured plan differs")
    steps = base.read(original / "steps.json")
    expected_steps = [{"name": step["name"], "exit": 0} for step in source["steps"][:26]]
    expected_steps[-1]["exit"] = 1
    base.check(steps == expected_steps and steps[-1]["name"] == "memory-large-03-candidate", "original failure boundary differs")
    recovery = base.verify_transport_recovery(original, source, base.digest(source_path), stopped_after=len(steps))
    windows = []
    for kind in ("idle", "large", "fanout"):
        for name in base.matrix_report.RUNS[:4]:
            prior = f"memory/{kind}/{name}" in OLD_GOOD
            row = base.verify_memory_window(original if prior else root, source if prior else plan, kind, name)
            row["source_collection"] = "original_passed_prefix" if prior else "independent_memory_supplement"
            windows.append(row)
    base.check(sum(row["source_collection"] == "original_passed_prefix" for row in windows) == 6, "prior/new window selection differs")
    memory = {"windows_verified": 12, "windows": windows, **base.memory_summary(windows),
              "limits": [
                  "Six named originally passed windows plus six separately frozen supplemental windows; this is not an uninterrupted original ABBA series.",
                  "The failed original large/03-candidate window is excluded from qualified statistics and separately disclosed with raw memory diagnostics.",
                  "Two qualified observations per subject/fixture are descriptive snapshots, not peaks, statistical superiority or equivalence.",
                  "PSS remains NA when unavailable; VmRSS includes shared mappings and is not a system-wide memory saving.",
                  "Idle metadata has the previously documented live-identity limitations; event phase snapshots are reconciled with proc evidence."]}
    matrix, send, stress = base.analyze_matrix(original, source), base.analyze_send(original, source), base.analyze_stress(original, source)
    report = {"schema_version": 2, "scope": "R136 completed timing plus independent memory supplement; original completion collection remains failed",
              "verified": True, "physical_windows_verified": 46, "all_windows_cleaned_and_stock": True,
              "subjects": source["subjects"], "plan_sha256": base.digest(source_path),
              "reporter_sha256": base.digest(Path(__file__)),
              "frozen_input_sha256": {**source["input_sha256"], **plan["input_sha256"]},
              "rules": source["rules"], "transport_recovery": recovery,
              "matrix": matrix, "direct_send": send, "memory": memory, "stress": stress,
              "limits": ["Original FAILED/result/health files are unchanged. Qualified observations span two explicitly named collections; no original 46-window completion claim.",
                         "The original timing/SEND samples and ±1% plus 7/8 rule are unchanged; no old R134/R135/Oracle samples are pooled.",
                         "No blanket ubusd superiority, absence-of-bugs, nine-component integration or language-limit conclusion.", *memory["limits"], *recovery["limitations"]]}
    public = base.public_report(report)
    source_by_name = {row["name"]: row["source_collection"] for row in windows}
    for row in public["memory"]["windows"]:
        row["source_collection"] = source_by_name[row["name"]]
    diagnostic = failed_diagnostic(original, source, memory)
    health_audit = base.read(base.ROOT / plan["post_failure_health_audit"]["path"])
    for output in (report, public):
        output["qualified_windows_verified"] = output.pop("physical_windows_verified")
        output["all_qualified_windows_passed_health_and_cleanup"] = output.pop("all_windows_cleaned_and_stock")
        output["original_collection"] = {"complete": False, "failed": True, "observed_windows": 41,
                                         "qualified_windows": 40, "excluded_failed_windows": 1,
                                         "failed_marker_sha256": base.digest(original / "FAILED"),
                                         "step_results_sha256": base.digest(original / "steps.json")}
        output["independent_memory_supplement"] = {"complete": True, "new_windows": 6,
             "plan_sha256": base.digest(plan_path), "rules": plan["rules"],
             "prior_passed_windows": plan["prior_passed_windows"], "post_failure_health_audit": health_audit,
             "post_failure_health_audit_sha256": plan["post_failure_health_audit"]["sha256"]}
        output["analysis_support_sha256"] = {"tools/r136/analyze_completion.py": base.digest(Path(base.__file__))}
    report["failed_window_diagnostic"] = diagnostic
    public["failed_window_diagnostic"] = {**diagnostic,
        "memory": [{key: value for key, value in row.items() if key != "daemon_pid"} for row in diagnostic["memory"]]}
    return report, public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    args = parser.parse_args()
    result, public = analyze(args.root, args.plan)
    for path, value in ((args.output, result), (args.public_output, public)):
        with path.open("x") as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write("\n")
    print(json.dumps({"original_collection_failed": True, "independent_memory_supplement_complete": True,
                      "qualified_windows": result["qualified_windows_verified"],
                      "matrix": result["matrix"]["decision_counts"]["r136_primary"],
                      "send": result["direct_send"]["decision_counts"]["r136_primary"],
                      "memory_increases": len(result["memory"]["all_candidate_increases"])}))


if __name__ == "__main__":
    main()
