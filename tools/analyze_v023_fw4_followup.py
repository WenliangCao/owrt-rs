#!/usr/bin/env python3
"""Only the user's authorized start/changed follow-up, with the original noise rule."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from analyze_v023_device_ab import ELF, gate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("candidate_sha256")
    args = parser.parse_args()
    assert re.fullmatch(r"[0-9a-f]{64}", args.candidate_sha256)
    expected = {"A": ELF["fw4"]["A"], "B": args.candidate_sha256}
    root = args.output
    assert (root / "COMPLETE").is_file() and not (root / "TIMEOUT").exists()
    assert (root / "boot-before").read_bytes() == (root / "boot-after").read_bytes()
    assert not (root / "netifd-A").exists() and not (root / "netifd-B").exists()
    results = {}
    for scene in ("start", "changed"):
        rows = []
        for number, side in enumerate("ABBAABABBABAAB", 1):
            phase = "cal" if number <= 6 else "formal"
            sample = root / "fw4" / f"{scene}-{phase}-{number}-{side}"
            assert (sample / "COMPLETE").is_file()
            assert (sample / "request").read_text().strip() == f"{scene} {side}"
            assert (sample / "elf.sha256").read_text().split()[0] == expected[side]
            assert (sample / "quiet-seconds").read_text().strip() == "1"
            row = json.loads((sample / "measurement.json").read_text())
            assert row["exit"] == 0 and row["cpu_us"] == row["user_us"] + row["system_us"]
            rows.append((side, row))
        for name, key, scale, res in (("wall", "wall_ns", 1, "wall_resolution_ns"),
                                      ("cpu", "cpu_us", 1000, "cpu_resolution_us")):
            calibration = {s: [r[key] * scale for side, r in rows[:6] if side == s] for s in "AB"}
            pairs = []
            for offset in range(6, 14, 2):
                pair = {s: r[key] * scale for s, r in rows[offset:offset + 2]}
                pairs.append([pair["A"], pair["B"]])
            results[f"{scene}_{name}"] = gate(calibration, pairs, max(r[res] * scale for _, r in rows))
    assert len(list((root / "fw4").glob("*/measurement.json"))) == 28
    floors = [json.loads((root / "floor" / f"{i}.json").read_text()) for i in range(1, 7)]
    assert all(row["exit"] == 0 for row in floors)
    stop = any(r["regression"] for name, r in results.items() if name.startswith("start_"))
    accepted = [name for name, r in results.items() if name.startswith("changed_") and r["regression"]]
    print(json.dumps({
        "schema": 1, "plan": "docs/reviews/V023_FW4_FOLLOWUP_PLAN_20261017.md",
        "decision": "STOP" if stop else "START_PASS_CHANGED_ACCEPTED" if accepted else "PASS",
        "accepted_necessary_snapshot_regressions": accepted, "subjects_sha256": expected,
        "metrics": results, "exec_floor": floors,
        "elapsed_seconds": float((root / "uptime-after").read_text().split()[0])
                           - float((root / "uptime-before").read_text().split()[0]),
        "input_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(root.rglob("*")) if p.is_file()},
    }, indent=2))


if __name__ == "__main__":
    main()
