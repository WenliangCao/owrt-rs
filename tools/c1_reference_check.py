#!/usr/bin/env python3
"""Reference model and case runner for contract C1-01 (config change dispatch).

The model implements the algorithm the contract describes, at the level of
normalised-content tokens rather than real md5 sums, so it runs without a uci
binary.  It is the oracle an R1 implementation must agree with on these cases.

It proves the algorithm: scan set, precedence, the dotted-name rule, and the
new/changed/deleted asymmetry.  It deliberately does NOT prove the
normalisation itself; byte equivalence with `uci show` is a V1 differential
test against the real device.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

EMPTY = "<EMPTY>"
EVIDENCE_LEVELS = {"DEP", "SRC", "RUN"}


def normalise(name: str, content: str, uci_lookups: dict[str, str]) -> str:
    """Model `uci show <name>` for one directory entry.

    A name containing a dot is parsed by uci as package.section.option.  The
    seven dotted names observed on the device do not resolve and therefore
    leave an empty file behind, but a tuple naming an existing section or
    option produces that element's output instead.
    """
    return uci_lookups.get(name, EMPTY) if "." in name else content


def reload_config(
    etc_config: dict[str, str],
    var_run_uci: dict[str, str],
    baseline: dict[str, str] | None,
    uci_lookups: dict[str, str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Return (events, new_baseline) for one run."""
    check: dict[str, str] = {}
    lookups = uci_lookups or {}
    # glob order puts /var/run/uci first, and the first entry for a name wins
    for source in (var_run_uci, etc_config):
        for name in sorted(source):
            if name in check:
                continue
            check[name] = normalise(name, source[name], lookups)

    events: list[str] = []
    if baseline is not None:
        # md5sum -c walks the baseline file, which was written in glob order
        for name in sorted(baseline):
            if check.get(name) != baseline[name]:
                events.append(name)
    return events, check


def run_cases(case_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    results, problems = [], []
    paths = sorted(case_dir.glob("*.json"))
    if not paths:
        return [], [f"no reference cases found in {case_dir}"]
    for path in paths:
        case = json.loads(path.read_text())
        for field in ("id", "contract", "evidence", "evidence_ref", "description", "given", "expect"):
            if field not in case:
                problems.append(f"{path.name}: missing field {field}")
        if case.get("evidence") not in EVIDENCE_LEVELS:
            problems.append(f"{path.name}: evidence must be one of {sorted(EVIDENCE_LEVELS)}")
            continue
        given = case["given"]
        events, baseline = reload_config(
            given["etc_config"],
            given["var_run_uci"],
            given["baseline"],
            given.get("uci_lookups"),
        )
        expected = case["expect"]
        ok_events = events == expected["events"]
        ok_baseline = baseline == expected["baseline"]
        if not ok_events:
            problems.append(f"{case['id']}: events {events} != expected {expected['events']}")
        if not ok_baseline:
            problems.append(f"{case['id']}: baseline {baseline} != expected {expected['baseline']}")
        results.append(
            {
                "id": case["id"],
                "contract": case["contract"],
                "evidence": case["evidence"],
                "passed": ok_events and ok_baseline,
            }
        )
    return results, problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    args = parser.parse_args()

    results, problems = run_cases(args.cases.resolve())
    by_evidence: dict[str, int] = {}
    for item in results:
        by_evidence[item["evidence"]] = by_evidence.get(item["evidence"], 0) + 1

    print(json.dumps({
        "cases": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "by_evidence": by_evidence,
        "src_only_cases": [r["id"] for r in results if r["evidence"] == "SRC"],
    }, indent=2, sort_keys=True))

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        raise SystemExit(f"{len(problems)} case failure(s)")


if __name__ == "__main__":
    main()
