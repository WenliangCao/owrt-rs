#!/usr/bin/env python3
"""Recompute the frozen R95 lookup pilot. Never issue a superiority verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).parent / "benchmark"))
from analyze_candidate import serial  # noqa: E402


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--plan", type=Path, default=Path("docs/reviews/r95-ubusd-pilot-plan.json"))
    a = p.parse_args()
    assert (a.root / "COMPLETE").is_file(), "collection incomplete"
    plan = read(a.plan)
    rows = []
    boots, clients, recoveries = set(), set(), set()
    for block in plan["blocks"]:
        assert set(block["order"]) == set(plan["subjects"])
        for position, side in enumerate(block["order"], 1):
            root = a.root / f"{block['block']:02d}-{side}"
            result = read(root / "result.json")
            assert result["pilot_only"] and not result["installed"]
            assert result["exit"] == 0 and result["production_mode"] == "stock"
            for key in ("passed", "cleanup_verified", "same_boot", "same_config",
                        "same_production_identity", "same_host_mounts"):
                assert result[key], (root, key)
            assert result["candidate_sha256"] == plan["subjects"][side]
            assert result["driver_sha256"] == plan["source_scripts"]["tools/r95_device_smoke.py"]
            assert result["workload_sha256"] == plan["source_scripts"]["tools/r95_ubusd_pilot.sh"]
            assert result["iterations"] == plan["iterations"]
            assert result["implementation"] == ("c" if side == "stock" else "rs")
            before = read(root / "health-before.json")
            after = read(root / "health-after.json")
            assert before["boot_id"] == after["boot_id"]
            boots.add(before["boot_id"])
            recoveries.add((result["recovery_gate_sha256"], result["guard_sha256"]))
            raw = root / "raw"
            assert (raw / "COMPLETE").is_file()
            assert (raw / "binary-sha256.txt").read_text().split()[0] == plan["subjects"][side]
            clients.add(tuple(line.split()[0] for line in (raw / "benchmark-sha256.txt").read_text().splitlines()))
            meta = read(raw / "meta.json")
            assert meta["pilot_only"] and meta["iterations"] == plan["iterations"]
            assert (raw / "objects-before.txt").read_bytes() == (raw / "objects-after.txt").read_bytes()
            expected = [f"bench.filler{i:04d}" for i in range(1, 128)] + ["bench.target"]
            assert (raw / "objects-before.txt").read_text().splitlines() == expected
            metrics = serial(raw / "lookup_all_128.json", meta["subject_pid"])
            assert metrics["successful"] == plan["iterations"] and metrics["warmup"] == plan["warmup"]
            hz = read(raw / "before.json")["clock_ticks_per_second"]
            assert hz == read(raw / "after.json")["clock_ticks_per_second"] and hz > 0
            rows.append({"block": block["block"], "side": side, "position": position,
                         "result_sha256": digest(root / "result.json"),
                         "raw_archive_sha256": digest(root / "raw.tar.gz"),
                         "kernel": (raw / "kernel.txt").read_text().strip(),
                         "cpu_tick_us_per_op": 1e6 / hz / plan["iterations"], **metrics})
    assert len(boots) == len(clients) == len(recoveries) == 1, "collection identities changed"
    summary = {}
    for metric in plan["planned_metrics"]:
        sides = {}
        for side in plan["subjects"]:
            values = [r[metric] for r in rows if r["side"] == side]
            sides[side] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        pairs = {}
        for baseline in ("stock", "r89"):
            deltas = []
            for block in plan["blocks"]:
                values = {r["side"]: r[metric] for r in rows if r["block"] == block["block"]}
                # Zero CPU counters remain missing ratios, never made into wins.
                deltas.append(100 * (values["candidate"] / values[baseline] - 1)
                              if values[baseline] > 0 else None)
            pairs[baseline] = {"per_block_delta_pct": deltas,
                               "median_delta_pct": statistics.median(deltas) if None not in deltas else None}
        summary[metric] = {"sides": sides, "paired_exploration": pairs}
    result = {"schema_version": 1, "plan_sha256": digest(a.plan), "plan": plan,
              "method": "Six paired exploratory blocks; full per-run values; no confidence or equivalence claim",
              "superiority_verdict": None, "scope": "single component, private router namespace, 128 objects",
              "all_windows_cleaned_and_production_stock": True, "runs": rows, "summary": summary}
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"runs": len(rows), "superiority_verdict": None}))


if __name__ == "__main__":
    main()
