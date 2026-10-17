#!/usr/bin/env python3
"""Review every R27 deviation against the explicit R92 contract.

The default r89-transition mode permits only the two explicit R92 changes.
current-release mode requires full equality with a released baseline which
already includes both changes. Both modes compare complete normalized
responses against independent exact-image and Rust controls. R85's historical
gate and R27's parser/masks remain unchanged.
"""
import argparse
import hashlib
import json
from pathlib import Path

import r27_httpd_fuzz as fuzz


BASELINE_MODES = ("r89-transition", "current-release")


def evaluate(stock, baseline, candidate, contract, baseline_mode="r89-transition"):
    """Apply the same comparator to live runs or preserved raw JSON results."""
    if baseline_mode not in BASELINE_MODES:
        raise ValueError("unknown baseline mode: " + baseline_mode)
    names = {case["id"] for case in fuzz.cases()}
    baseline_side = "r89" if baseline_mode == "r89-transition" else "baseline"
    results = {"stock": stock, baseline_side: baseline, "candidate": candidate}
    assert len(names) == 133 and all(set(data) == names for data in results.values()), "missing cases"
    differences = {name for name in names if stock[name] != baseline[name]}
    candidate_differences = {name for name in names if stock[name] != candidate[name]}
    changes = {name for name in names if baseline[name] != candidate[name]}
    match_cases = {name: row["match_case"] for name, row in contract.items() if "match_case" in row}
    checks = {}
    for name in sorted(names):
        reference = match_cases.get(name) if baseline_mode == "r89-transition" else None
        expected = candidate[reference] if reference else baseline[name]
        checks[name] = candidate[name] == expected
    survival = [(side, name) for side, data in results.items() for name, value in data.items()
                if value.get("alive_after") is not True]
    summary = {
        "cases": len(names), "baseline_mode": baseline_mode,
        "baseline_differences": sorted(differences), "candidate_changes": sorted(changes),
        "checks": checks, "survival_failures": survival,
        "passed": differences == set(contract) and all(checks.values()) and not survival,
    }
    if baseline_mode == "r89-transition":
        summary["passed"] &= changes == set(match_cases)
    else:
        match_checks = {side: {name: data[name] == data[reference]
                              for name, reference in match_cases.items()}
                        for side, data in (("baseline", baseline), ("candidate", candidate))}
        summary["candidate_differences"] = sorted(candidate_differences)
        summary["match_case_checks"] = match_checks
        summary["passed"] &= (not changes and candidate_differences == set(contract)
                              and all(all(checks.values()) for checks in match_checks.values()))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--port", type=int, default=18880)
    parser.add_argument("--baseline-mode", choices=BASELINE_MODES, default="r89-transition")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    contract_path = Path(__file__).resolve().parents[1] / "tests/reference/httpd/r92-deviations.json"
    contract = json.loads(contract_path.read_text())
    results = {}
    baseline_side = "r89" if args.baseline_mode == "r89-transition" else "baseline"
    for offset, (side, binary, impl) in enumerate([
        ("stock", args.baseline, "original"),
        (baseline_side, args.baseline, "candidate"),
        ("candidate", args.candidate, "candidate"),
    ]):
        data, log = fuzz.run_side(args.rootfs.resolve(), binary.resolve(), impl, args.port + offset * 4)
        (args.output / (side + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        (args.output / (side + ".log")).write_text(log)
        results[side] = data
        print(f"{side}: {len(data)} cases collected", flush=True)
    summary = evaluate(results["stock"], results[baseline_side], results["candidate"], contract,
                       args.baseline_mode)
    summary.update({
        "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "baseline_sha256": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        "candidate_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
    })
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "checks"}), flush=True)
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
