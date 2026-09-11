#!/usr/bin/env python3
"""Preserve R27's exact existing deviations while checking a new HTTPD.

Run on the Linux build host. Normalized responses and logs stay private; the
printed summary contains only case names and counts. No assertions or masks
in the original R27 harness are changed.
"""
import argparse
import json
from pathlib import Path

import r27_httpd_fuzz as fuzz


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--port", type=int, default=18880)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for offset, (side, binary, impl) in enumerate([
        ("stock", args.baseline, "original"),
        ("r84", args.baseline, "candidate"),
        ("candidate", args.candidate, "candidate"),
    ]):
        data, log = fuzz.run_side(args.rootfs.resolve(), binary.resolve(), impl, args.port + offset * 4)
        (args.output / (side + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        (args.output / (side + ".log")).write_text(log)
        results[side] = data
        print(f"{side}: {len(data)} cases collected", flush=True)
    names = {case["id"] for case in fuzz.cases()}
    assert all(set(data) == names for data in results.values()), "missing cases"
    survival = [(side, name) for side, data in results.items() for name, value in data.items()
                if value.get("alive_after") is not True]
    baseline_differences = sorted(name for name in names if results["stock"][name] != results["r84"][name])
    changed = sorted(name for name in names if results["r84"][name] != results["candidate"][name])
    summary = {"cases": len(names), "baseline_differences": baseline_differences,
               "candidate_changes": changed, "survival_failures": survival,
               "passed": len(names) == 133 and len(baseline_differences) == 22 and not changed and not survival}
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    if not summary["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
