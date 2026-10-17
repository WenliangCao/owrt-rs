#!/usr/bin/env python3
"""Replay the pre-frozen single-batch gate, preserving every paired difference."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

ELF = {
    "fw4": {"A": "ee5a9c5685f7363be3fc2bd5039546b2f01327633afc24031b446fc0fb7f5b55",
            "B": "2a077d0d268fca821463919219ee339b629c37cab2f47b2584b382074a83a72c"},
    "netifd": {"A": "0131ce3feeec074bfa6f5046ff3732ec235495442956407e7ea17559ce747a93",
               "B": "cd02d474cfc557fb43231c947c29b442a0178efdaea6902e9b4bf2a0d03310ef"},
}


def gate(calibration, formal, resolution):
    noise = max(*(max(values) - min(values) for values in calibration.values()),
                2 * resolution)
    differences = [b - a for a, b in formal]
    a = statistics.median(pair[0] for pair in formal)
    b = statistics.median(pair[1] for pair in formal)
    return {
        "unit": "ns", "calibration": calibration, "noise": noise,
        "formal_pairs_A_B": formal, "pair_differences_B_minus_A": differences,
        "A_median": a, "B_median": b, "median_change_percent": (b / a - 1) * 100,
        "largest_pair_regression": max(differences),
        "regression_pairs": [i + 1 for i, delta in enumerate(differences) if delta > noise],
        "regression": any(delta > noise for delta in differences),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.output
    assert (root / "COMPLETE").is_file() and not (root / "TIMEOUT").exists()
    assert (root / "boot-before").read_bytes() == (root / "boot-after").read_bytes()
    results = {}
    for scene in ("unchanged", "changed", "start", "check", "print"):
        rows = []
        for number, side in enumerate("ABBAABABBABAAB", 1):
            phase = "cal" if number <= 6 else "formal"
            sample = root / "fw4" / f"{scene}-{phase}-{number}-{side}"
            assert (sample / "COMPLETE").is_file()
            assert (sample / "request").read_text().strip() == f"{scene} {side}"
            assert (sample / "elf.sha256").read_text().split()[0] == ELF["fw4"][side]
            assert (sample / "quiet-seconds").read_text().strip() == "1"
            row = json.loads((sample / "measurement.json").read_text())
            assert row["exit"] == 0 and row["cpu_us"] == row["user_us"] + row["system_us"]
            rows.append((side, row))
        for name, key, scale, res in (("wall", "wall_ns", 1, "wall_resolution_ns"),
                                      ("cpu", "cpu_us", 1000, "cpu_resolution_us")):
            calibration = {side: [r[key] * scale for s, r in rows[:6] if s == side]
                           for side in "AB"}
            pairs = []
            for offset in range(6, 14, 2):
                pair = {side: row[key] * scale for side, row in rows[offset:offset + 2]}
                pairs.append([pair["A"], pair["B"]])
            results[f"fw4_{scene}_{name}"] = gate(
                calibration, pairs, max(row[res] * scale for _, row in rows))

    subjects = {}
    for side in "AB":
        directory = root / f"netifd-{side}"
        assert (directory / "COMPLETE").is_file()
        assert (directory / "identities.sha256").read_text().split()[0] == ELF["netifd"][side]
        rows = [json.loads(line) for line in (directory / "samples.jsonl").read_text().splitlines()]
        assert len(rows) == 8
        for index, row in enumerate(rows):
            assert row["side"] == side and row["round"] == index
            assert row["successful"] == 1 and row["errors"] == 0 and row["identity_and_state_checked"]
            assert row["settle_wall_ns"] >= 1_000_000
        assert len({(r["subject_pid"], r["subject_start_ticks"]) for r in rows}) == 1
        subjects[side] = rows
    assert len({r["t0_ns"] for rows in subjects.values() for r in rows}) == 1
    for index in range(8):
        a, b = subjects["A"][index], subjects["B"][index]
        assert b["scheduled_ns"] - a["scheduled_ns"] == (2_000_000_000 if index % 2 == 0 else -2_000_000_000)
    results["netifd_renewal_cpu"] = gate(
        {s: [r["subject_cpu_ns"] for r in rows[:3]] for s, rows in subjects.items()},
        [[subjects[s][i]["subject_cpu_ns"] for s in "AB"] for i in range(3, 8)],
        max(r["subject_resolution_ns"] for rows in subjects.values() for r in rows))
    floor = [json.loads((root / "floor" / f"{i}.json").read_text()) for i in range(1, 7)]
    assert all(row["exit"] == 0 for row in floor)
    inputs = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(root.rglob("*")) if p.is_file()}
    report = {
        "schema": 1, "plan": "docs/reviews/V023_DEVICE_AB_PLAN_20261017.md",
        "decision": "STOP" if any(r["regression"] for r in results.values()) else "PASS",
        "metrics": results, "netifd_samples": subjects, "exec_floor": floor,
        "input_sha256": inputs,
        "elapsed_seconds": float((root / "uptime-after").read_text().split()[0])
                           - float((root / "uptime-before").read_text().split()[0]),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
