#!/usr/bin/env python3
"""Recompute the frozen R95 lookup pilot. Never issue a superiority verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).parent / "benchmark"))
from analyze_candidate import parallel, serial  # noqa: E402


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(rows, plan):
    summary = {}
    for metric in plan["planned_metrics"]:
        sides = {}
        for side in plan["subjects"]:
            values = [r[metric] for r in rows if r["side"] == side]
            assert len(values) == len(plan["blocks"])
            sides[side] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        pairs = {}
        for baseline in (side for side in plan["subjects"] if side != "candidate"):
            deltas = []
            for block in plan["blocks"]:
                values = {r["side"]: r[metric] for r in rows if r["block"] == block["block"]}
                # Zero CPU counters remain missing ratios, never made into wins.
                deltas.append(100 * (values["candidate"] / values[baseline] - 1)
                              if values[baseline] > 0 else None)
            pairs[baseline] = {"per_block_delta_pct": deltas,
                               "median_delta_pct": statistics.median(deltas) if None not in deltas else None}
        summary[metric] = {"sides": sides, "paired_exploration": pairs}
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--plan", type=Path, default=Path("docs/reviews/r95-ubusd-pilot-plan.json"))
    p.add_argument("--workload-script", help="custom collector script; SHA must match the frozen plan")
    p.add_argument("--object-count", type=int, help="complete object set for a custom workload")
    a = p.parse_args()
    assert (a.root / "COMPLETE").is_file(), "collection incomplete"
    plan = read(a.plan)
    matrix = plan.get("matrix", False)
    workload_script = a.workload_script or ("tools/benchmark/isolated.sh" if matrix else "tools/r95_ubusd_pilot.sh")
    lanes = plan.get("workloads", ("lookup_all_128",))
    multiple = len(lanes) > 1
    counts = (a.object_count,) if a.object_count is not None else ((64, 128) if matrix else (128,))
    assert all(count > 0 for count in counts)
    rows = []
    residents = []
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
            if "benchmark_sha256" in plan:
                assert result["benchmark_sha256"] == plan["benchmark_sha256"]
            assert result["driver_sha256"] == plan["source_scripts"]["tools/r95_device_smoke.py"]
            assert result["workload_sha256"] == plan["source_scripts"][workload_script]
            assert result.get("matrix", False) == matrix
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
            if "benchmark_sha256" in plan:
                assert (raw / "benchmark-sha256.txt").read_text().split()[0] == plan["benchmark_sha256"]
            meta = read(raw / "meta.json")
            assert meta["iterations"] == plan["iterations"]
            if matrix:
                assert meta["component"] == "ubusd" and meta["implementation"] == result["implementation"]
            else:
                assert meta["pilot_only"]
            for count in counts:
                prefix = f"objects-{count}" if matrix else "objects"
                assert (raw / f"{prefix}-before.txt").read_bytes() == (raw / f"{prefix}-after.txt").read_bytes()
                expected = [f"bench.filler{i:04d}" for i in range(1, count)] + ["bench.target"]
                assert (raw / f"{prefix}-before.txt").read_text().splitlines() == expected
            common = {"block": block["block"], "side": side, "position": position,
                      "result_sha256": digest(root / "result.json"),
                      "raw_archive_sha256": digest(root / "raw.tar.gz"),
                      "kernel": (raw / "kernel.txt").read_text().strip()}
            for lane in lanes:
                concurrent = lane.endswith("_c4")
                if concurrent:
                    metrics = parallel(raw / lane, meta["subject_pid"])
                    hz = read(raw / lane / "before.json")["clock_ticks_per_second"]
                else:
                    metrics = serial(raw / (lane + ".json"), meta["subject_pid"])
                    hz = read(raw / (lane + ".json"))["clock_ticks_per_second"]
                assert metrics["successful"] == plan["iterations"]
                assert metrics["warmup"] == plan["warmup"] * (4 if concurrent else 1)
                assert hz > 0
                denominator = metrics["successful"] + (metrics["warmup"] if concurrent else 0)
                rows.append({**common, **({"workload": lane} if multiple else {}),
                             "cpu_tick_us_per_op": 1e6 / hz / denominator, **metrics})
            if matrix:
                memory = read(raw / "resident.json")
                subject = next(p for p in memory["processes"] if p["pid"] == meta["subject_pid"])
                residents.append({"block": block["block"], "side": side, **{k: subject[k] for k in
                    ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "Threads", "fds")}})
    assert len(boots) == len(clients) == len(recoveries) == 1, "collection identities changed"
    summary = ({lane: summarize([r for r in rows if r["workload"] == lane], plan) for lane in lanes}
               if multiple else summarize(rows, plan))
    result = {"schema_version": 1, "plan_sha256": digest(a.plan), "plan": plan,
              "method": "Paired exploratory blocks; full per-run values; no confidence or equivalence claim",
              "superiority_verdict": None, "scope": f"ubusd only, private router namespace, {len(lanes)} lanes; object counts {counts}",
              "analysis_workload_script": workload_script,
              "analysis_object_counts": counts,
              "all_windows_cleaned_and_production_stock": True, "runs": rows, "summary": summary}
    if matrix:
        result["resident_diagnostics"] = residents
        result["memory_note"] = "End-of-matrix proc counters; not PSS, precise RSS, per-lane peak or whole-system memory"
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"runs": len(rows), "superiority_verdict": None}))


if __name__ == "__main__":
    main()
