#!/usr/bin/env python3
"""Verify every R136 batch record and emit paired, CPU-pair-separated deltas.

Reuses R135's raw-sample and process-clock validation and descriptive contrasts.
No p-value, significance, equivalence, or router acceptance is inferred.
"""
import argparse
import importlib.util
import itertools
from pathlib import Path

R135 = Path(__file__).resolve().parents[1] / "r135/analyze_screen.py"
spec = importlib.util.spec_from_file_location("r135_analyze", R135)
r135 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r135)


def analyze(root):
    require, read = r135.require, r135.read
    require((root / "COMPLETE").is_file() and not (root / "FAILED").exists(), "incomplete batch")
    hashes = r135.verify_hashes(root)
    require({"COMPLETE", "plan.json", "results.json", "manifest-identity.json"} <= hashes.keys(),
            "batch root evidence missing from hash manifest")
    plan, result = read(root / "plan.json"), read(root / "results.json")
    require(plan["schema"] == result["schema"] == 1 and result["passed"] is True, "wrong result schema")
    pairs = [tuple(pair) for pair in plan["pairs"]]
    labels = list(plan["subjects"])
    lanes, affinities = list(plan["lanes"]), plan["affinities"]
    repeats, n, warmup = plan["repeats"], plan["iterations"], plan["warmup"]
    require(repeats > 0 and len(set(labels)) == len(labels), "invalid repeats/subjects")
    c = [label for label in labels if plan["subjects"][label]["kind"] == "c"]
    require(len(c) == 1, "expected one C control")
    controls = c + (["r134"] if "r134" in labels else [])
    indexed, records = {}, []
    for record in result["records"]:
        pair = tuple(record["pair"])
        key = pair, record["affinity"], record["lane"], record["label"], record["block"]
        require(pair in pairs and record["affinity"] in affinities and record["lane"] in lanes
                and record["label"] in labels and record["block"] in range(repeats), "unknown measurement dimension")
        require(key not in indexed, "duplicate measurement")
        original = Path(record["file"])
        # Downloaded evidence retains its original absolute Oracle path.
        relative = Path(*original.parts[-3:])
        require(str(relative) in hashes, "measurement missing from hashes")
        folder = root / relative.parent
        required = ("COMPLETE", "cleanup.json", "daemon.log", "daemon-start.json",
                    "daemon-end.json", "daemon-cmdline.json", "daemon-command.json", "subject.json",
                    "daemon-maps.txt", relative.name.replace(".json", "-command.json"),
                    relative.name.replace(".json", ".log"))
        require(all(str(relative.parent / name) in hashes for name in required),
                "subject evidence missing from hashes")
        require((folder / "COMPLETE").is_file(), "subject did not finish")
        cleanup = read(folder / "cleanup.json")
        require(cleanup["daemon_exited"] and cleanup["caller_exited"] and cleanup["socket_absent"]
                and cleanup["daemon_returncode"] in (0, -15), "unclean subject cleanup")
        require(not (folder / "daemon.log").read_bytes()
                and not (root / relative.with_suffix(".log")).read_bytes(), "nonempty process log")
        data = read(root / relative)
        metrics, diagnostics = r135.measurements(data, n, warmup, pair, record["affinity"])
        metrics["caller_cpu_us_per_op"] = diagnostics["caller_cpu_us_per_op"]
        require(all(r135.close(record["metrics"][metric], value) for metric, value in metrics.items()),
                "runner metric differs from archived raw data")
        subject = plan["subjects"][record["label"]]
        require(record["subject_sha256"] == subject["sha256"]
                and record["benchmark_sha256"] == plan["benchmark"]["sha256"], "record identity mismatch")
        start = read(folder / "daemon-start.json")
        require((start["pid"], start["start_ticks"]) ==
                (diagnostics["daemon"]["pid"], diagnostics["daemon"]["start_ticks"]), "daemon identity mismatch")
        indexed[key] = metrics
        records.append({**record, "file": str(relative), "sha256": hashes[str(relative)], **diagnostics})
    expected = set(itertools.product(pairs, affinities, lanes, labels, range(repeats)))
    require(set(indexed) == expected, "missing or unexpected measurements")
    groups = []
    metric_names = (*r135.METRICS, "caller_cpu_us_per_op")
    for pair, affinity, lane, label in itertools.product(pairs, affinities, lanes, labels):
        values = {metric: [indexed[pair, affinity, lane, label, block][metric]
                           for block in range(repeats)] for metric in metric_names}
        contrasts = {control: {metric: r135.contrast(series, [indexed[pair, affinity, lane, control, block][metric]
                                                              for block in range(repeats)])
                               for metric, series in values.items()} for control in controls}
        groups.append({"pair": pair, "affinity": affinity, "lane": lane, "label": label,
                       "metrics": {metric: r135.summary(series) for metric, series in values.items()},
                       "vs": contrasts})
    return {"schema": 1, "verified": True, "router_conclusion": False,
            "scope": "R136 Oracle exploratory batch; paired block/CPU/affinity/lane comparisons",
            "plan": plan, "hash_manifest_sha256": r135.sha(root / "hashes.json"),
            "verified_file_count": len(hashes), "records": records, "groups": groups,
            "limitations": [
                "CPU pairs are reported separately; concurrent workers share host caches and scheduler resources.",
                "Each subject keeps one daemon for all lanes and affinity conditions within a block.",
                "Absolute paired median <= 1% is unresolved; larger changes are descriptive directions only.",
                "Register and event lanes use real socket protocol but Oracle rankings do not predict router acceptance.",
                "All raw latency samples, CPU snapshots, subject results, and failed executions remain archived.",
            ]}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root.resolve())
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"verified": True, "measurements": len(report["records"]),
                      "groups": len(report["groups"]), "router_conclusion": False}))


if __name__ == "__main__":
    main()
