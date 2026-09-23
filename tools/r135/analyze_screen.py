#!/usr/bin/env python3
"""Verify a downloaded R135 Oracle screen and summarize each CPU pair separately.

Usage: analyze_screen.py LOCAL_CAPTURE_ROOT --output NEW_SUMMARY.json
This is exploratory analysis, not significance, causality or router acceptance.
"""

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics


VARIANTS = tuple(f"s{s}b{b}k{k}" for s, b, k in itertools.product((0, 1), repeat=3))
LABELS = ("c", "r131", *VARIANTS)
LANES = {"register_1": ("register-cycle", "1", "8"),
         "register_16": ("register-cycle", "16", "8"),
         "event_1": ("register-watch", "1", "1")}
AFFINITIES = ("split", "pair_allowed")
METRICS = ("mean_us", "p50_us", "p95_us", "p99_us", "daemon_cpu_us_per_op")
REFERENCE_HASHES = {
    "c": "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88",
    "r131": "c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a",
    "s1b1k1": "98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0",
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"nonfinite JSON: {value}")))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None


def natural(value, positive=False):
    return type(value) is int and value >= (1 if positive else 0)


def close(a, b):
    return type(a) in (int, float) and math.isfinite(a) and math.isclose(a, b, rel_tol=1e-8, abs_tol=1e-6)


def verify_hashes(root):
    manifest = read(root / "hashes.json")
    require(isinstance(manifest, dict) and manifest, "empty hash manifest")
    for name, expected in manifest.items():
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and str(relative) == name and valid_hash(expected), f"invalid manifest entry: {name}")
        path = root / name
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
                f"missing/unsafe manifest file: {name}")
        require(sha(path) == expected, f"hash mismatch: {name}")
    return manifest


def process(before, after, allowed):
    pid, start = before["pid"], before["start_ticks"]
    require(natural(pid, True) and natural(start, True) and after["pid"] == pid
            and after["start_ticks"] == start, "PID/starttime changed")
    text = str(min(allowed)) if len(allowed) == 1 else f"{min(allowed)}-{max(allowed)}"
    mask = sum(1 << cpu for cpu in allowed)
    for sample in (before, after):
        require(sample["Threads"] == 1 and sample["Cpus_allowed_list"] == text
                and int(sample["Cpus_allowed"].replace(",", ""), 16) == mask, "CPU affinity/threads mismatch")
        require(natural(sample["last_processor"]) and sample["last_processor"] in allowed,
                "last CPU outside allowed mask")
        require(natural(sample["process_cpu_ns"]) and natural(sample["process_cpu_resolution_ns"], True),
                "invalid process clock")
    require(before["process_cpu_resolution_ns"] == after["process_cpu_resolution_ns"], "clock resolution changed")
    elapsed = after["process_cpu_ns"] - before["process_cpu_ns"]
    require(elapsed > 0, "nonpositive CPU interval")
    switches = {}
    for key in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches"):
        require(natural(before[key]) and natural(after[key]) and after[key] >= before[key], "context-switch counter regressed")
        switches[key] = after[key] - before[key]
    return {"pid": pid, "start_ticks": start, "cpu_clock_ns": elapsed, "cpu_allowed": sorted(allowed),
            "last_processor_before": before["last_processor"], "last_processor_after": after["last_processor"],
            "context_switch_deltas": switches}


def measurements(data, n, warmup, pair, affinity):
    require(data["schema"] == 1 and type(data["successful"]) is int and data["successful"] == n
            and data["errors"] == 0 and data["warmup"] == warmup, "operation counts/errors mismatch")
    samples = data["latency_ns"]
    require(len(samples) == n and all(natural(value, True) for value in samples), "invalid latency samples")
    ordered = sorted(samples)
    metrics = {"mean_us": sum(samples) / n / 1000}
    for key, quantile in (("p50_us", .5), ("p95_us", .95), ("p99_us", .99)):
        metrics[key] = ordered[math.floor((n - 1) * quantile + .5)] / 1000
    require(all(close(data[key], value) for key, value in metrics.items()), "reported latency differs from samples")
    wall = data["wall_s"]
    require(type(wall) in (int, float) and math.isfinite(wall) and wall > 0
            and close(data["ops_per_s"], n / wall), "invalid wall/throughput")
    require(len(data["daemon_cpu"]) == 1, "expected exactly one daemon")
    daemon_data = data["daemon_cpu"][0]
    daemon = process(daemon_data["before"], daemon_data["after"], {pair[1]})
    caller = process(data["client_before"], data["client_after"], {pair[0]} if affinity == "split" else set(pair))
    require(daemon_data["pid"] == daemon["pid"] != caller["pid"], "daemon/caller PID mismatch")
    require(natural(daemon_data["cpu_clock_ns"], True) and daemon_data["cpu_clock_ns"] == daemon["cpu_clock_ns"]
            and natural(data["client_cpu_clock_ns"], True) and data["client_cpu_clock_ns"] == caller["cpu_clock_ns"],
            "CPU clock delta mismatch")
    metrics["daemon_cpu_us_per_op"] = daemon["cpu_clock_ns"] / n / 1000
    return metrics, {"daemon": daemon, "caller": caller, "caller_cpu_us_per_op": caller["cpu_clock_ns"] / n / 1000}


def summary(values):
    return {"by_block": values, "median": statistics.median(values), "min": min(values), "max": max(values)}


def contrast(values, baseline):
    deltas = [(value / control - 1) * 100 for value, control in zip(values, baseline)]
    median = statistics.median(deltas)
    return {"by_block_delta_pct": deltas, "median_delta_pct": median, "min_delta_pct": min(deltas),
            "max_delta_pct": max(deltas), "lower_blocks": sum(v < 0 for v in deltas),
            "higher_blocks": sum(v > 0 for v in deltas), "equal_blocks": sum(v == 0 for v in deltas),
            "exploratory_direction": "unresolved_within_1pct" if abs(median) <= 1 else "lower" if median < 0 else "higher"}


def analyze(root, allow_subset=False):
    require((root / "COMPLETE").is_file() and not (root / "FAILED").exists()
            and not (root / "failure.json").exists(), "screen incomplete/failed")
    manifest = verify_hashes(root)
    require({"plan.json", "results.json"} <= manifest.keys(), "plan/results not covered by hashes")
    plan, result = read(root / "plan.json"), read(root / "results.json")
    require(result["passed"] is True, "screen did not pass")
    selected = set(plan["subjects"])
    if allow_subset:
        require({"c", "s1b1k1"} <= selected <= set(LABELS), "subset requires C and R134 controls and known labels")
    else:
        require(selected == set(LABELS), "full eight variants plus C/R131 required (or explicitly use --subset)")
    labels = tuple(label for label in LABELS if label in selected)
    require(valid_hash(plan["runner_sha256"]) and valid_hash(plan["benchmark_sha256"]), "invalid tool hash")
    for label, subject in plan["subjects"].items():
        require(valid_hash(subject["sha256"]) and PurePosixPath(subject["path"]).is_absolute(), f"invalid subject: {label}")
    require(all(label not in selected or plan["subjects"][label]["sha256"] == value
                for label, value in REFERENCE_HASHES.items()), "reference ELF changed")
    pairs = [tuple(pair) for pair in plan["pairs"]]
    require(pairs in ([(0, 1)], [(0, 1), (2, 3)]), "unexpected CPU pairs")
    require(len(plan["schedules"]) == len(pairs), "schedule/pair count mismatch")
    expected_jobs = {(block, label) for block in range(4) for label in labels}
    for schedule in plan["schedules"]:
        require(len(schedule) == 4 * len(labels) and {tuple(job) for job in schedule} == expected_jobs, "four complete blocks required")
    n, warmup = plan["iterations"], plan["warmup"]
    require(natural(n, True) and warmup == 20, "invalid iteration/warmup counts")
    normalized = "output_label_width" in plan
    if normalized:
        require(plan["output_label_width"] == max(map(len, labels)) and plan["output_block_width"] == 1,
                "unexpected normalized directory widths")

    verified_subjects, live_identities, records, indexed = {}, {}, [], {}
    for record in result["records"]:
        pair, block, label, affinity, lane = tuple(record["pair"]), record["block"], record["label"], record["affinity"], record["lane"]
        require(pair in pairs and type(block) is int and block in range(4) and label in labels
                and affinity in AFFINITIES and lane in LANES, "unexpected record dimensions")
        key = (pair, affinity, lane, label, block)
        require(key not in indexed, f"duplicate measurement: {key}")
        require(record["subject_sha256"] == plan["subjects"][label]["sha256"]
                and record["benchmark_sha256"] == plan["benchmark_sha256"], "record identities differ from plan")
        folder_label = label.ljust(plan["output_label_width"], "_") if normalized else label
        directory = f"p{pair[0]}-{block}-{folder_label}"
        original = PurePosixPath(record["file"])
        relative = PurePosixPath(*original.parts[-2:]) if original.is_absolute() else original
        expected_file = f"{directory}/{affinity}-{lane}.json"
        require(str(relative) == expected_file and expected_file in manifest, "unexpected/unhashed measurement path")
        folder = root / directory
        if directory not in verified_subjects:
            names = ("COMPLETE", "cleanup.json", "results.json", "daemon-command.json", "daemon-maps.txt",
                     "daemon.log", "system-before.json", "system-after.json")
            require(all(f"{directory}/{name}" in manifest for name in names), "subject evidence absent from hashes")
            cleanup = read(folder / "cleanup.json")
            require(cleanup["daemon_exited"] is True and cleanup["socket_absent"] is True
                    and cleanup["returncode"] in (0, -15), f"unclean daemon exit: {directory}")
            command = read(folder / "daemon-command.json")
            if normalized and label != "c":
                require(PurePosixPath(command[0]).name == "owrt-benchmark" and command[1:5] ==
                        ["exec-cpu-as", str(pair[1]), plan["subjects"][label]["path"], "/sbin/ubusd"],
                        "normalized daemon command identity/affinity")
            else:
                require(command[:3] == ["taskset", "-c", str(pair[1])]
                        and plan["subjects"][label]["path"] in command, "daemon command identity/affinity")
            if normalized:
                require(all(f"{directory}/{name}" in manifest for name in ("daemon-stat.txt", "daemon-cmdline.bin")),
                        "normalized live process evidence unhashed")
                require(cleanup.get("caller_exited") is True and cleanup.get("caller_returncode") == 0,
                        "caller not reaped cleanly")
                expected_cmdline = command[3:] if label == "c" else command[4:]
                require((folder / "daemon-cmdline.bin").read_bytes() == b"\0".join(v.encode() for v in expected_cmdline) + b"\0",
                        "live daemon argv differs from launcher")
                stat = (folder / "daemon-stat.txt").read_text()
                live_identities[directory] = (int(stat.split(" ", 1)[0]), int(stat.rsplit(") ", 1)[1].split()[19]))
            require(plan["subjects"][label]["path"] in (folder / "daemon-maps.txt").read_text(), "subject missing from maps")
            local_records = read(folder / "results.json")
            require(len(local_records) == 6 and len({r["file"] for r in local_records}) == 6, "incomplete subject results")
            verified_subjects[directory] = local_records
        require(record in verified_subjects[directory], "outer record differs from subject results")
        stem = f"{affinity}-{lane}"
        require(all(f"{directory}/{stem}{suffix}" in manifest for suffix in ("-command.json", ".log")), "caller metadata unhashed")
        require(not (folder / f"{stem}.log").read_bytes(), "caller stderr is nonempty")
        data = read(root / expected_file)
        metrics, diagnostics = measurements(data, n, warmup, pair, affinity)
        if normalized:
            require((diagnostics["daemon"]["pid"], diagnostics["daemon"]["start_ticks"]) == live_identities[directory],
                    "measured daemon identity differs from archived live stat")
        cmd = read(folder / f"{stem}-command.json")
        mask = str(pair[0]) if affinity == "split" else f"{pair[0]},{pair[1]}"
        require(cmd[:3] == ["taskset", "-c", mask] and PurePosixPath(cmd[3]).name == "owrt-benchmark"
                and cmd[4:] == [LANES[lane][0], str(original.parent / "bus.sock"), *LANES[lane][1:],
                              str(n), str(warmup), str(diagnostics["daemon"]["pid"])], "caller command differs from planned workload")
        indexed[key] = metrics
        records.append({"pair": list(pair), "block": block, "label": label, "affinity": affinity, "lane": lane,
                        "file": expected_file, "sha256": manifest[expected_file], "metrics": metrics, **diagnostics})
    expected = set(itertools.product(pairs, AFFINITIES, LANES, labels, range(4)))
    require(set(indexed) == expected, "missing/unexpected measurements")
    for pair in pairs:
        for block in range(4):
            for label in labels:
                group = [r for r in records if r["pair"] == list(pair) and r["block"] == block and r["label"] == label]
                require(len({(r["daemon"]["pid"], r["daemon"]["start_ticks"]) for r in group}) == 1, "daemon replaced between lanes")

    groups = []
    for pair, affinity, lane, label in itertools.product(pairs, AFFINITIES, LANES, labels):
        values = {metric: [indexed[pair, affinity, lane, label, block][metric] for block in range(4)] for metric in METRICS}
        comparisons = {control: {metric: contrast(series, [indexed[pair, affinity, lane, control, block][metric] for block in range(4)])
                                for metric, series in values.items()} for control in ("s1b1k1", "c")}
        groups.append({"pair": list(pair), "affinity": affinity, "lane": lane, "label": label,
                       "metrics": {metric: summary(series) for metric, series in values.items()}, "vs": comparisons})
    return {"schema_version": 1, "scope": "R135 complete Oracle exploratory screen; CPU pairs kept separate",
            "verified": True, "router_conclusion": False, "plan_sha256": sha(root / "plan.json"),
            "results_sha256": sha(root / "results.json"), "hash_manifest_sha256": sha(root / "hashes.json"),
            "verified_file_count": len(manifest), "reporter_sha256": sha(Path(__file__)), "plan": plan,
            "blocks": [0, 1, 2, 3], "metrics": list(METRICS), "groups": groups, "records": records,
            "limitations": [
                "No router performance, statistical significance, equivalence or causal attribution is claimed. Oracle ranking is a screen only.",
                "All four per-block observations are retained. Contrasts match the same block, CPU pair, affinity and lane; two CPU pairs are not pooled into eight independent same-core observations.",
                "Absolute median paired change <= 1% is exploratory unresolved. Larger changes are descriptive lower/higher directions, not acceptance or rejection decisions; sign counts are reported separately.",
                "Two workers, when present, run concurrently and share host resources. Affinity conditions and lanes share a subject daemon within a block; they are not independent daemon repetitions.",
                "Boundary last_processor observations do not count migrations. Context-switch deltas cover the snapshot bracket, including measurement bookkeeping; they do not locate individual slow operations.",
                "register_1/register_16 include ADD plus REMOVE; event_1 includes registration-generated object events, not a user SEND event workload.",
                "Hash consistency is checked against the captured manifest; runner assertions establish live binary/library identities and cleanup. This report does not independently rehash Oracle binaries or recreate that environment.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--subset", action="store_true",
                        help="analyze all subjects of a frozen subset plan; C and s1b1k1 are still mandatory")
    args = parser.parse_args()
    report = analyze(args.root, allow_subset=args.subset)
    with args.output.open("x") as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write("\n")
    print(json.dumps({"verified_files": report["verified_file_count"], "measurements": len(report["records"]),
                      "groups": len(report["groups"]), "cpu_pairs": report["plan"]["pairs"], "router_conclusion": False}))


if __name__ == "__main__":
    main()
