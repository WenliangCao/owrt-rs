#!/usr/bin/env python3
"""Review every R27 deviation and permit only the two explicit R92 changes.

Uses the exact-image original and the formal R89 binary as independent
controls. Complete normalized responses compare, not only HTTP status codes.
R85's historical gate and R27's parser/masks remain unchanged.
"""
import argparse
import hashlib
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
    contract_path = Path(__file__).resolve().parents[1] / "tests/reference/httpd/r92-deviations.json"
    contract = json.loads(contract_path.read_text())
    results = {}
    for offset, (side, binary, impl) in enumerate([
        ("stock", args.baseline, "original"),
        ("r89", args.baseline, "candidate"),
        ("candidate", args.candidate, "candidate"),
    ]):
        data, log = fuzz.run_side(args.rootfs.resolve(), binary.resolve(), impl, args.port + offset * 4)
        (args.output / (side + ".json")).write_text(json.dumps(data, indent=2) + "\n")
        (args.output / (side + ".log")).write_text(log)
        results[side] = data
        print(f"{side}: {len(data)} cases collected", flush=True)
    names = {case["id"] for case in fuzz.cases()}
    assert len(names) == 133 and all(set(data) == names for data in results.values()), "missing cases"
    differences = {name for name in names if results["stock"][name] != results["r89"][name]}
    checks = {}
    for name in names:
        reference = contract.get(name, {}).get("match_case")
        expected = results["candidate"][reference] if reference else results["r89"][name]
        checks[name] = results["candidate"][name] == expected
    survival = [(side, name) for side, data in results.items() for name, value in data.items() if value.get("alive_after") is not True]
    approved_changes = {name for name, row in contract.items() if "match_case" in row}
    changes = {name for name in names if results["r89"][name] != results["candidate"][name]}
    summary = {
        "cases": len(names), "contract_sha256": hashlib.sha256(contract_path.read_bytes()).hexdigest(),
        "baseline_sha256": hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
        "candidate_sha256": hashlib.sha256(args.candidate.read_bytes()).hexdigest(),
        "baseline_differences": sorted(differences), "candidate_changes": sorted(changes),
        "checks": checks, "survival_failures": survival,
        "passed": differences == set(contract) and changes == approved_changes and all(checks.values()) and not survival,
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "checks"}), flush=True)
    raise SystemExit(0 if summary["passed"] else 1)


if __name__ == "__main__":
    main()
