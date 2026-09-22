#!/usr/bin/env python3
"""Independently verify and summarize local R132 registration perf-stat data.

This tool never contacts Oracle or a router.  It recomputes counts and timings
from perf.csv and client.json rather than trusting collection metadata totals.
"""
import argparse
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import statistics
import tarfile

ROOT = Path(__file__).resolve().parents[1]
COUNTERS = ("instructions:u", "branches:u", "branch-misses:u", "cycles:u", "context-switches", "cpu-migrations")
EVENT_GROUPS = ["{instructions:u,branches:u,branch-misses:u,cycles:u}", "context-switches", "cpu-migrations"]
COUNTER_METRICS = dict(zip(COUNTERS, ("user_instructions_op", "user_branches_op", "user_branch_misses_op",
                                    "user_cycles_op", "context_switches_op", "cpu_migrations_op")))


def check(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def verify_archive(archive, root):
    files = {}
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            path = Path(member.name)
            check(path.parts[0] == root.name and not path.is_absolute() and ".." not in path.parts,
                  "unexpected archive path")
            if member.isdir():
                continue
            check(member.isfile(), "non-regular archive member")
            relative = str(path.relative_to(root.name))
            check(relative not in files, "duplicate archive member")
            content = stream.extractfile(member).read()
            check((root / relative).read_bytes() == content, f"archive differs: {relative}")
            files[relative] = hashlib.sha256(content).hexdigest()
    check(files and all(any(name.startswith(f"{i:03d}-") for name in files) for i in range(1, 13)),
          "archive lacks formal windows")
    return {"sha256": sha(archive), "all_members_match_local_bytes": True,
            "regular_file_count": len(files), "files_sha256": files}


def parse_csv(path):
    counts = {}
    for parts in csv.reader(Path(path).read_text().splitlines(), delimiter=";"):
        if not parts or not parts[0].strip() or parts[0].startswith("#"):
            continue
        check(len(parts) >= 5, f"short perf CSV row: {parts}")
        event = parts[2].strip()
        check(event in COUNTERS and event not in counts, f"unknown/duplicate event: {event}")
        check(re.fullmatch(r"[0-9]+", parts[0]) is not None, f"non-integer/unavailable count: {parts[0]}")
        check(parts[1].strip() == "", "unexpected unit for count event")
        runtime, percent = Decimal(parts[3]), Decimal(parts[4])
        check(runtime.is_finite() and runtime > 0 and runtime == runtime.to_integral_value(), "invalid counter runtime")
        check(percent.is_finite() and percent == Decimal(100), f"multiplexed event: {event}")
        counts[event] = {"count": int(parts[0]), "runtime_ns": int(runtime), "running_percent": float(percent)}
    check(set(counts) == set(COUNTERS), "missing counter")
    check(all(counts[event]["count"] > 0 for event in COUNTERS[:4]), "zero hardware counter")
    check(counts["cpu-migrations"]["count"] == 0, "pinned daemon migrated")
    return counts


def process_identity(path):
    text = Path(path).read_text().strip()
    match = re.fullmatch(r"([0-9]+) \(.*\) (.+)", text)
    check(match is not None, "invalid proc stat")
    fields = match[2].split()
    check(len(fields) >= 20 and fields[0] in ("R", "S", "D", "I"), "invalid live process stat")
    return int(match[1]), int(fields[19])


def mapped_files(path):
    files = {}
    for line in Path(path).read_text().splitlines():
        words = line.split(None, 5)
        check(len(words) >= 5, f"invalid map: {line}")
        if len(words) != 6 or not words[5].startswith("/"):
            continue
        name = words[5]
        check(not name.endswith(" (deleted)"), "deleted mapped file")
        identity = (words[3], int(words[4]))
        check(name not in files or files[name] == identity, "one path maps multiple file identities")
        files[name] = identity
    return files


def client_metrics(data, item, meta):
    expected = {key: item[key] for key in ("n", "warmup", "methods", "name_bytes")}
    expected.update(schema=1, fixture="rust_register_cycle", subject_pid=meta["daemon_pid"],
                    client_pid=meta["client_pid"], subject_cpu=1, client_cpu=0,
                    successful=item["n"], errors=0, latency_sample_count=item["n"],
                    perf_controlled=True, full_signature_checked=True, warmup_empty=True,
                    final_empty=True, wire_reply_bytes_checked=False, latency_clock="CLOCK_MONOTONIC")
    for key, value in expected.items():
        check(type(data[key]) is type(value) and data[key] == value, f"caller field: {key}")
    check(data["subject_resolution_ns"] == data["client_resolution_ns"] == 1, "clock resolution changed")
    values = data["latency_ns"]
    check(len(values) == item["n"] and all(type(x) is int and x > 0 for x in values), "invalid raw latency")
    elapsed = {clock: data[f"{clock}_after_ns"] - data[f"{clock}_before_ns"] for clock in ("wall", "subject", "client")}
    check(all(type(x) is int and x > 0 for x in elapsed.values()), "invalid clock interval")
    check(sum(values) <= elapsed["wall"] and elapsed["subject"] <= elapsed["wall"] and
          elapsed["client"] <= elapsed["wall"], "timing enclosure")
    check(meta["elapsed_ns"] == elapsed, "metadata clocks differ from raw caller")
    n = item["n"]
    ordered = sorted(values)
    result = {"daemon_cpu_us_op": elapsed["subject"] / n / 1000,
              "caller_cpu_us_op": elapsed["client"] / n / 1000,
              "wall_us_op": elapsed["wall"] / n / 1000,
              "sample_mean_us": sum(values) / n / 1000}
    for name, q in (("p50_us", 50), ("p95_us", 95), ("p99_us", 99)):
        result[name] = ordered[(2 * (n - 1) * q + 100) // 200] / 1000
    return result, elapsed


def verify_window(root, index, item, plan):
    label = item["subject"]
    folder = root / f"{index:03d}-{label}-{item['methods']}"
    check((folder / "COMPLETE").is_file() and not (folder / "FAILED").exists(), f"{folder.name}: incomplete")
    meta = load(folder / "meta.json")
    check(meta["status"] == "complete" and meta["mode"] == "stat" and meta["run"] == item, "collection metadata")
    check(meta["returncodes"]["client"] == 0 and meta["returncodes"]["perf"] in (0, -2) and
          meta["returncodes"]["daemon"] in (0, -15), "child return codes")
    check(not (folder / "client.stderr").read_bytes(), "caller stderr")
    subject_sha = plan["subjects"][label]["sha256"]
    subject_path = plan["launch_directory"] + "/ubusd"
    socket_path = plan["launch_directory"] + "/ubus.sock"
    loader = plan["rootfs"]["path"] + "/lib/libc.so"
    check(meta["subject_sha256"] == subject_sha and meta["normalized_subject_path"] == subject_path and
          meta["normalized_socket_path"] == socket_path and meta["program_argv0"] == "/sbin/ubusd", "normalized subject identity")
    daemon_command = ([loader, "--library-path", plan["rootfs"]["path"] + "/lib:" + plan["rootfs"]["path"] + "/usr/lib",
                      "--argv0", "/sbin/ubusd", subject_path, "-s", socket_path] if label == "c" else ["/sbin/ubusd", "-s", socket_path])
    check(meta["daemon_command"] == daemon_command, "daemon command changed")
    expected_maps = {plan["rootfs"]["path"] + name: sha for name, sha in plan["rootfs"]["libraries"].items()}
    expected_maps[subject_path] = subject_sha
    observations = []
    for phase in ("before", "after"):
        identity = load(folder / f"identity-{phase}.json")
        check(identity["pid"] == meta["daemon_pid"] and identity["affinity"] == [1], "daemon pid/affinity")
        check(identity["exe"] == (loader if label == "c" else subject_path), "daemon executable")
        check(identity["exe_sha256"] == expected_maps[identity["exe"]], "daemon executable SHA")
        files = mapped_files(folder / f"maps-{phase}.txt")
        check(set(files) == set(identity["mapped_sha256"]) and subject_path in files, "daemon mappings")
        check(all(expected_maps.get(path) == value for path, value in identity["mapped_sha256"].items()), "unplanned/changed daemon library")
        if label != "c":
            check(set(files) == {subject_path}, "static daemon maps another file")
        pid_start = process_identity(folder / f"stat-{phase}.txt")
        check(pid_start[0] == meta["daemon_pid"], "proc stat PID")
        check((folder / f"cmdline-{phase}.bin").read_bytes() == b"\0".join(x.encode() for x in daemon_command) + b"\0", "daemon actual argv")
        observations.append((identity, files, pid_start))
    check(observations[0] == observations[1], "daemon identity/mapped inodes/starttime changed")
    caller = load(folder / "client-identity.json")
    check(caller["pid"] == meta["client_pid"] and caller["affinity"] == [0] and int(caller["start_ticks"]) > 0,
          "caller live identity")
    check(caller["mapped_sha256"] == {plan["client"]["path"]: plan["client"]["sha256"]}, "caller mapped ELF hash")
    check(set(mapped_files(folder / "client-maps.txt")) == {plan["client"]["path"]}, "caller maps another file")
    status = dict(line.split(":", 1) for line in (folder / "client-status.txt").read_text().splitlines() if ":" in line)
    check(int(status["Pid"]) == int(status["Tgid"]) == meta["client_pid"] and int(status["Threads"]) == 1
          and status["Cpus_allowed_list"].strip() == "0", "caller live status")
    caller_command = [plan["client"]["path"], "register-cycle", socket_path, str(item["methods"]),
                      str(item["name_bytes"]), str(item["n"]), str(item["warmup"]), str(meta["daemon_pid"])]
    check(meta["client_command"] == caller_command and (folder / "client-cmdline.bin").read_bytes() ==
          b"\0".join(x.encode() for x in caller_command) + b"\0", "caller argv")
    command = meta["perf_command"]
    check(command[1:5] == ["stat", "-D", "-1", "--control"] and re.fullmatch(r"fd:[0-9]+,[0-9]+", command[5]), "perf ACK setup")
    check(command[6:11] == ["-p", str(meta["daemon_pid"]), "-x", ";", "-o"] and command[12:] ==
          [value for event in EVENT_GROUPS for value in ("-e", event)], "perf attachment/events")
    check([line for line in (folder / "perf.stderr").read_text().splitlines() if line.startswith("Events ")] ==
          ["Events disabled", "Events enabled", "Events disabled"], "perf control boundaries")
    counts = parse_csv(folder / "perf.csv")
    for event, record in counts.items():
        stated = meta["counters"][event]
        check(stated["value"] == record["count"] and stated["enabled_ns"] == record["runtime_ns"] and
              stated["running_percent"] == 100, "metadata counter differs from CSV")
    metrics, elapsed = client_metrics(load(folder / "client.json"), item, meta)
    metrics.update({COUNTER_METRICS[event]: record["count"] / item["n"] for event, record in counts.items()})
    metrics["user_instructions_per_cycle"] = counts["instructions:u"]["count"] / counts["cycles:u"]["count"]
    metrics["user_branch_miss_pct"] = 100 * counts["branch-misses:u"]["count"] / counts["branches:u"]["count"]
    return {"index": index, **item, "within_method_block": (index - 1) % 6 // 3 + 1,
            "daemon_pid": meta["daemon_pid"], "daemon_start_ticks": observations[0][2][1],
            "counts": counts, "elapsed_ns": elapsed, "metrics": metrics,
            "raw_sha256": {path.name: sha(path) for path in sorted(folder.iterdir()) if path.is_file()}}


def paired(windows, methods, numerator, denominator, metric):
    pairs = []
    for block in (1, 2):
        selected = {row["subject"]: row for row in windows if row["methods"] == methods and row["within_method_block"] == block}
        a, b = selected[numerator]["metrics"][metric], selected[denominator]["metrics"][metric]
        pairs.append({"block": block, "numerator_window": selected[numerator]["index"],
                      "denominator_window": selected[denominator]["index"], "numerator": a, "denominator": b,
                      "absolute_delta": a - b, "delta_pct": 100 * (a / b - 1) if b else None})
    deltas = [row["delta_pct"] for row in pairs]
    return {"pairs": pairs, "median_delta_pct": statistics.median(deltas) if all(x is not None for x in deltas) else None,
            "all_lower": all(x is not None and x < 0 for x in deltas),
            "all_higher": all(x is not None and x > 0 for x in deltas)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("plan", type=Path); p.add_argument("root", type=Path); p.add_argument("output", type=Path)
    p.add_argument("--collector-tools", type=Path, default=ROOT / "tools",
                   help="directory containing the exact frozen collector and support sources")
    p.add_argument("--archive", type=Path, required=True, help="untouched downloaded stat archive")
    a = p.parse_args(); plan = load(a.plan)
    check(plan["schema_version"] == 1 and plan["mode"] == "stat", "formal stat plan required")
    expected = [{"subject": label, "methods": methods, "name_bytes": 8, "n": 100000, "warmup": 5000}
                for methods in (1, 16) for label in ("c", "r124", "r131", "r131", "r124", "c")]
    check(plan["runs"] == expected, "formal schedule changed")
    check(plan["stat"] == {"events": EVENT_GROUPS, "counter_names": list(COUNTERS), "running_percent_required": 100.0}, "counter specification")
    collector_sources = {"r132_registration_profile.py": plan["runner_sha256"], **plan["support_sha256"]}
    check(all(sha(a.collector_tools / name) == value for name, value in collector_sources.items()), "frozen collector source identity")
    check((a.root / "COMPLETE").is_file() and not (a.root / "FAILED").exists(), "series incomplete")
    check((a.root / "plan.json").read_bytes() == a.plan.read_bytes(), "retained plan differs")
    host = load(a.root / "host.json")
    check(host["machine"] == "aarch64" and host["plan_sha256"] == sha(a.plan) and host["runner_sha256"] == plan["runner_sha256"]
          and host["perf_sha256"] == plan["perf"]["sha256"], "host identities")
    names = {f"{i:03d}-{item['subject']}-{item['methods']}" for i, item in enumerate(expected, 1)}
    check({path.name for path in a.root.iterdir() if path.is_dir() and path.name[:3].isdigit()} == names, "window set differs")
    windows = [verify_window(a.root, i, item, plan) for i, item in enumerate(expected, 1)]
    archive = verify_archive(a.archive, a.root)
    check(all(archive["files_sha256"].get(f"{row['index']:03d}-{row['subject']}-{row['methods']}/{name}") == digest
              for row in windows for name, digest in row["raw_sha256"].items()), "window file absent from archive")
    comparisons = {f"{num}_vs_{den}": {str(methods): {metric: paired(windows, methods, num, den, metric)
                   for metric in windows[0]["metrics"]} for methods in (1, 16)}
                   for num, den in (("r131", "r124"), ("r131", "c"), ("r124", "c"))}
    report = {"schema_version": 1, "scope": "Independent R132 Oracle ACK-bracketed perf-stat verification",
              "plan_sha256": sha(a.plan), "reporter_sha256": sha(__file__), "host": host, "windows": windows,
              "collector_source_sha256": collector_sources,
              "source_archive": archive,
              "comparisons": comparisons, "verification_passed": True,
              "limitations": ["Two mirrored paired blocks per method count; no equivalence, significance, or acceptance verdict.",
                              "Hardware counters use :u and exclude kernel instructions/cycles; process CPU clocks include kernel work.",
                              "Perf stat and perf record substantially perturb timing differently; CPU clocks and latency here are descriptive within stat mode only.",
                              "Do not merge stat CPU clocks with profile or historical router timing, or infer production kernel cost from their ratios.",
                              "All positive and negative directions are retained; per-operation samples are not independent windows.",
                              "This independent instrumented caller and Oracle host are not the frozen router experiment.",
                              "Counter or CPU differences do not by themselves identify the cause of router p95 regression."]}
    a.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("VERIFIED", len(windows), "windows; 1200000 raw latency samples")


if __name__ == "__main__":
    main()
