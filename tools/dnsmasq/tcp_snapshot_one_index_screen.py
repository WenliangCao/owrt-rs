#!/usr/bin/env python3
"""Independent frozen shared_one_index cache screen; no product-source mutations.

Reuse a previously calibrated exact-C primitive oracle. Gate every operation
while a cache image is retained, then separately measure allocations and cost.
Timing requires an explicitly coordinated quiet-window label.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import time
from datetime import datetime, timezone

import dns_cache_diff as reference
import tcp_snapshot_screen as shared_base

ROOT = Path(__file__).resolve().parents[2]
LABELS = ("deep", "shared_one_index")
PROFILES = ((150, 0), (150, 150), (1000, 1000), (10000, 10000))
ORDERS = (LABELS, ("shared_one_index", "deep"), LABELS)
FLAGS = ["--edition=2021", "-A", "dead_code", "-A", "unused_imports",
         "-Copt-level=3", "-Clto", "-Ccodegen-units=1", "-Cpanic=abort"]
NORMALIZATION = "Only cross-type Generic RR grouping; within-type order, data, TTL, expiry, negative and stale flags exact."
LAYOUTS = {"deep": [168, 160, 120, 56, 24], "shared_one_index": [168, 32, 120, 56, 24]}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def replace(text, before, after, count=1):
    assert text.count(before) == count, ("source contract changed", before, text.count(before), count)
    return text.replace(before, after)


def variant(source, label):
    """Keep V1 shared entries and change only the private name-index value."""
    source = shared_base.variant(source, "shared" if label == "shared_one_index" else "deep")
    for name, visibility in (("Slot", ""), ("Cache", "pub ")):
        source = replace(source, f"#[derive(Clone)]\n{visibility}struct {name} {{", f"#[derive(Debug, Clone)]\n{visibility}struct {name} {{")
    index_type = "Vec<usize>"
    insert = "value.splice(at..at, extra.iter().copied());"
    if label == "shared_one_index":
        source = replace(source, "names: HashMap<Vec<u8>, Vec<usize>>", "names: HashMap<Vec<u8>, NameSlots>")
        source = replace(source, "self.names.get(&key).cloned()", "self.names.get(&key).map(NameSlots::to_vec)", 2)
        source = replace(source, "self.names.get(&victim_key).cloned()", "self.names.get(&victim_key).map(NameSlots::to_vec)")
        source = replace(source, "entries.splice(at..at, found[1..].iter().copied());", "entries.insert_before(at, &found[1..]);")
        source += "\n" + Path(__file__).with_suffix(".index.rs").read_text()
        index_type = "NameSlots"
        insert = "value.insert_before(at, extra);"
    source = replace(source, "pub fn screen_layout() -> [usize; 4]", "pub fn screen_layout() -> [usize; 5]")
    source = replace(source, "std::mem::size_of::<Record>()]", f"std::mem::size_of::<Record>(), std::mem::size_of::<{index_type}>()]")
    checks = Path(__file__).with_suffix(".checks.rs").read_text()
    source += "\n" + replace(replace(checks, "/* INDEX_TYPE */", index_type), "/* INSERT_BEFORE */", insert)
    return source


def run(command, stem, stdin=None, check=True):
    assert not stem.with_suffix(".command.json").exists(), "fresh evidence path required"
    started = time.time_ns()
    result = subprocess.run(list(map(str, command)), input=stdin, capture_output=True)
    stem.with_suffix(".stdout").write_bytes(result.stdout)
    stem.with_suffix(".stderr").write_bytes(result.stderr)
    write_json(stem.with_suffix(".command.json"), {"command": list(map(str, command)), "exit": result.returncode,
        "started_unix_ns": started, "finished_unix_ns": time.time_ns(), "runner_sha256": sha(Path(__file__))})
    if check:
        result.check_returncode()
    return result


def compiler(rustc):
    path = Path(shutil.which(rustc)).resolve()
    version = subprocess.run([str(path), "--version", "--verbose"], capture_output=True, text=True, check=True).stdout
    assert version.startswith("rustc 1.98.1 "), "compiler is pinned before any result"
    assert "host: aarch64-unknown-linux-gnu\n" in version, "native aarch64 compiler required"
    return {"path": str(path), "sha256": sha(path), "version": version}


def prepare(args):
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    for name in ("sources", "oracle", "build", "gate", "allocation", "timing"):
        (out / name).mkdir()
    source_root = args.source_root.resolve()
    source = source_root / "components/dnsmasq/src/dns"
    assert args.source_revision == "e77d966d0bf92e5296f73ee3e54fdaf960ed7781"
    assert args.cache_sha256 == "8c73672d4ebe3959d8172cecf5b951afef61f23ec568c52b27f6b00ae081e9a5"
    assert sha(source / "cache.rs") == args.cache_sha256, "baseline must be named explicitly"
    original = {name: sha(source / name) for name in ("cache.rs", "wire.rs", "lease_names.rs")}
    summary = json.loads((args.oracle / "summary.json").read_text())
    assert summary["source_sha256"] == reference.EXPECTED_SOURCE
    assert {name: sha(args.c_source / name) for name in reference.EXPECTED_SOURCE} == reference.EXPECTED_SOURCE
    assert summary["mismatches"] == 0 and summary["commands"] == 22571 and len(summary["scenarios"]) == 21
    corpus = []
    for name, config, commands in reference.scenarios():
        expected_input = ("\n".join(commands) + "\n").encode()
        assert (args.oracle / f"{name}.input").read_bytes() == expected_input
        for suffix in ("input", "oracle.stdout", "oracle.stderr"):
            shutil.copyfile(args.oracle / f"{name}.{suffix}", out / "oracle" / f"{name}.{suffix}")
        answer = out / "oracle" / f"{name}.oracle.stdout"
        assert len(answer.read_text().splitlines()) == len(commands)
        corpus.append({"name": name, "config": config, "operations": len(commands),
            "input_sha256": sha(out / "oracle" / f"{name}.input"), "expected_sha256": sha(answer)})
    assert sum(row["operations"] for row in corpus) == 22571
    calibration = (out / "oracle/calibration.oracle.stdout").read_text().splitlines()
    assert calibration == ['B','I 1','C 1','Q 1:7:0:102:2:0','Q','B','I 0','C 0','B','I 1','L 0','C 1','Q']
    for name in ("summary.json", "oracle.c", "driver.rs"):
        shutil.copyfile(args.oracle / name, out / "oracle" / name)
    builds = {}
    template = Path(__file__).with_suffix(".rs").read_text()
    allocator = (ROOT / "tools/dnsmasq/cache_expiry_screen.rs").read_text()
    allocator = allocator[allocator.index("#[cfg(allocation_tracking)]"):allocator.index("\nstruct Operation {")]
    original_driver = (out / "oracle/driver.rs").read_text()
    marker = "use std::io::{self,BufRead}; use cache::*;"
    assert original_driver.count(marker) == 1
    gate_body = original_driver[original_driver.index(marker):]
    gate_body = replace(gate_body, "fn main() {", 'fn main() {\n if std::env::args().nth(1).as_deref()==Some("--layout") {println!("{:?}",cache::screen_layout());return;}')
    gate_body = replace(gate_body, "data:vec![n(4) as u8]", "data:screen_data(&[n(4) as u8])")
    gate_body = replace(gate_body, "let mut cache=Cache::new(a[0] as usize,policy);", "let mut image=image(Cache::new(a[0] as usize,policy));")
    gate_body = replace(gate_body, " match w[0] {", ' let hold=image.clone(); let retained_before=format!("{:?}",hold); let cache=mutable(&mut image);\n match w[0] {')
    gate_body = replace(gate_body, '_=>panic!()}\n }\n}', '_=>panic!()}\n assert_eq!(retained_before,format!("{:?}",hold),"retained image mutated"); std::hint::black_box(hold);\n }\n}')
    image_api = template[template.index("type Image = Cache;"):template.index("\nfn stats()")]
    for label in LABELS:
        root = out / "sources" / label
        dest = root / "components/dnsmasq/src/dns"; dest.mkdir(parents=True)
        for name in ("wire.rs", "lease_names.rs"):
            shutil.copyfile(source / name, dest / name)
        (dest / "cache.rs").write_text(variant((source / "cache.rs").read_text(), label))
        modules = reference.rust_modules(root)
        driver = replace(replace(template, "/* CACHE_MODULES */", modules), "/* ALLOCATION_AND_CLOCK */", allocator)
        (out / "build" / f"{label}.rs").write_text(driver)
        (out / "build" / f"{label}-gate.rs").write_text(modules + "\nuse std::sync::Arc;\n" + image_api + "\n" + gate_body)
        payload = Path(__file__).with_suffix(".payload.rs").read_text()
        payload = replace(replace(replace(payload, "/* CACHE_MODULES */", modules),
                                  "/* ALLOCATION_AND_CLOCK */", allocator), "/* IMAGE_API */", image_api)
        (out / "build" / f"{label}-payload.rs").write_text(payload)
        builds[label] = {"root": str(root), "source_sha256": {name: sha(dest / name) for name in original},
            "driver_sha256": sha(out / "build" / f"{label}.rs"), "gate_sha256": sha(out / "build" / f"{label}-gate.rs"),
            "payload_sha256": sha(out / "build" / f"{label}-payload.rs"),
            "cfg": []}
    manifest = {"status": "prepared", "baseline_revision": args.source_revision, "baseline_source_root": str(source_root), "baseline_sha256": original,
        "compiler": compiler(args.rustc), "flags": FLAGS, "variants": builds, "corpus": corpus,
        "oracle_origin": str(args.oracle.resolve()), "oracle_summary_sha256": sha(out / "oracle/summary.json"),
        "oracle_source_sha256": sha(out / "oracle/oracle.c"), "c_source_sha256": reference.EXPECTED_SOURCE,
        "profiles": PROFILES, "orders": ORDERS, "warm_groups": 5, "measured_groups": 25, "snapshots_per_group": 20,
        "normalization": NORMALIZATION, "tool_sha256": sha(Path(__file__)),
        "driver_sha256": sha(Path(__file__).with_suffix(".rs")),
        "index_value_sha256": sha(Path(__file__).with_suffix(".index.rs")),
        "payload_template_sha256": sha(Path(__file__).with_suffix(".payload.rs")),
        "shared_variant_tool_sha256": sha(Path(shared_base.__file__)), "expected_layouts": LAYOUTS,
        "index_checks_sha256": sha(Path(__file__).with_suffix(".checks.rs")),
        "freeze_sha256": sha(ROOT / "docs/dnsmasq/TCP_SNAPSHOT_ONE_INDEX_V1.md"),
        "reference_tool_sha256": sha(ROOT / "tools/dnsmasq/dns_cache_diff.py"),
        "platform": subprocess.run(["uname", "-a"], capture_output=True, text=True, check=True).stdout,
        "gates": {"primary_combined_cpu_gain": .20, "primary_snapshot_live_heap_gain": .20,
            "capacity150_p95_max_regression": .05, "population_cpu_max_regression": .05, "steady_heap_max_regression": .05}}
    write_json(out / "manifest.json", manifest)
    print(json.dumps({"status": "prepared", "corpus_operations": 22571, "variants": list(builds)}))


def load(args):
    out = args.output.resolve(); manifest = json.loads((out / "manifest.json").read_text())
    for label, row in manifest["variants"].items():
        dest = Path(row["root"]) / "components/dnsmasq/src/dns"
        assert {name: sha(dest / name) for name in row["source_sha256"]} == row["source_sha256"]
        assert sha(out / "build" / f"{label}.rs") == row["driver_sha256"]
        assert sha(out / "build" / f"{label}-gate.rs") == row["gate_sha256"]
        assert sha(out / "build" / f"{label}-payload.rs") == row["payload_sha256"]
    for row in manifest["corpus"]:
        assert sha(out / "oracle" / (row["name"] + ".input")) == row["input_sha256"]
        assert sha(out / "oracle" / (row["name"] + ".oracle.stdout")) == row["expected_sha256"]
    assert sha(ROOT / "docs/dnsmasq/TCP_SNAPSHOT_ONE_INDEX_V1.md") == manifest["freeze_sha256"]
    assert sha(Path(__file__).with_suffix(".rs")) == manifest["driver_sha256"]
    assert sha(Path(__file__).with_suffix(".index.rs")) == manifest["index_value_sha256"]
    assert sha(Path(__file__).with_suffix(".checks.rs")) == manifest["index_checks_sha256"]
    assert sha(Path(__file__).with_suffix(".payload.rs")) == manifest["payload_template_sha256"]
    assert sha(Path(shared_base.__file__)) == manifest["shared_variant_tool_sha256"]
    assert sha(ROOT / "tools/dnsmasq/dns_cache_diff.py") == manifest["reference_tool_sha256"]
    assert sha(Path(__file__)) == manifest["tool_sha256"]
    assert compiler(manifest["compiler"]["path"]) == manifest["compiler"]
    return out, manifest


def compare(commands, expected, observed):
    if not len(commands) == len(expected) == len(observed):
        raise ValueError("missing or extra observation")
    failures, variations = [], []
    for line, (command, c, rust) in enumerate(zip(commands, expected, observed)):
        if c == rust:
            continue
        row = {"line": line, "command": command, "c": c, "rust": rust}
        generic = command.startswith("Q ") and int(command.split()[2]) not in (1, 28, 5, 65536)
        group = lambda value: sorted(value.split()[1:], key=lambda item: int(item.split(":")[0]))
        if generic and group(c) == group(rust):
            variations.append(row)
        else:
            failures.append(row)
    return failures, variations


def gate(args):
    out, manifest = load(args)
    binaries = {}
    for label in LABELS:
        for suffix in ("-gate", "-payload", "", "-alloc"):
            source = out / "build" / (label + (suffix if suffix in ("-gate", "-payload") else "") + ".rs")
            binary = out / "build" / (label + suffix)
            command = [manifest["compiler"]["path"], *FLAGS, *manifest["variants"][label]["cfg"], str(source), "-o", str(binary)]
            if suffix in ("-alloc", "-payload"): command += ["--cfg", "allocation_tracking"]
            run(command, out / "build" / ("compile-" + label + (suffix or "-timing")))
            binaries[binary.name] = sha(binary)
    rows = []
    for label in LABELS:
        layout = run([out / "build" / (label + "-gate"), "--layout"], out / "gate" / (label + "-layout"))
        actual_layout = json.loads(layout.stdout)
        assert actual_layout == manifest["expected_layouts"][label], (label, "layout gate", actual_layout)
        payload = run([out / "build" / (label + "-payload")], out / "gate" / (label + "-payload"))
        payload_result = json.loads(payload.stdout)
        assert payload_result == {"drop_orders": 2, "adapter_checks": True,
                                  "retained_independence": True, "balanced": True}
        failures, variations = [], []
        completed = 0
        for case in manifest["corpus"]:
            name = case["name"]; inputs = (out / "oracle" / f"{name}.input").read_bytes()
            observed = run([out / "build" / (label + "-gate"), *case["config"]], out / "gate" / f"{label}-{name}", inputs)
            expected = (out / "oracle" / f"{name}.oracle.stdout").read_text().splitlines()
            errors, order = compare(inputs.decode().splitlines(), expected, observed.stdout.decode().splitlines())
            failures += [{"scenario": name, **row} for row in errors]
            variations += [{"scenario": name, **row} for row in order]
            completed += len(expected)
        write_json(out / "gate" / f"{label}-failures.json", failures)
        write_json(out / "gate" / f"{label}-cross-type-order.json", variations)
        rows.append({"variant": label, "scenarios": len(manifest["corpus"]), "operations": completed,
                     "failures": len(failures), "cross_type_order_variations": len(variations),
                     "layout": actual_layout, "index_checks": payload_result})
    # A real comparison with one changed Rust row must fail exactly once.
    commands = (out / "oracle/calibration.input").read_text().splitlines()
    expected = (out / "oracle/calibration.oracle.stdout").read_text().splitlines()
    observed = (out / "gate/deep-calibration.stdout").read_text().splitlines()
    observed[3] = "Q 1:7:0:102:3:0"
    failures, variations = compare(commands, expected, observed)
    assert len(failures) == 1 and failures[0]["line"] == 3 and not variations
    try:
        compare(commands, expected, observed[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing observation was accepted")
    write_json(out / "gate/calibration-negative.json", {"operations": len(commands), "matches": len(commands)-1, "failures": failures})
    # Exercise the command-level failure exit rather than only the comparator.
    negative = run(["python3", __file__, "negative", "--output", str(out)], out / "gate/calibration-negative-command", check=False)
    assert negative.returncode == 1
    report = {"status": "passed" if all(row["failures"] == 0 for row in rows) else "failed",
        "results": rows, "binaries": binaries, "negative_control": {"matches": 12, "failures": 1, "exit": 1, "missing_observation_rejected": True},
        "oracle": "reused exact C; no Rust-generated expectation", "normalization": NORMALIZATION, "retained_state_checks_per_variant": 22571}
    write_json(out / "gate.json", report); print(json.dumps(report, indent=2))
    return int(report["status"] != "passed")


def measure(args, allocation):
    out, manifest = load(args); gate_result = json.loads((out / "gate.json").read_text())
    assert gate_result["status"] == "passed", "correctness precedes costs"
    rows = []; phase = "allocation" if allocation else "timing"
    assert not (out / (phase + ".json")).exists(), "retain every run; no overwrite"
    window = None
    if not allocation:
        validate_allocations(json.loads((out / "allocation.json").read_text()))
        allocation_result = json.loads((out / "allocation-result.json").read_text())
        assert allocation_result["allocation_sha256"] == sha(out / "allocation.json")
        assert allocation_result["gate_sha256"] == sha(out / "gate.json")
        assert [row["variant"] for row in allocation_result["results"]] == list(LABELS)
        assert all(all(row["allocation_gates"].values()) for row in allocation_result["results"] if row["variant"] != "deep"), "deterministic allocation gates precede timing"
        assert args.quiet_window, "parent must coordinate this host window before timing"
        assert args.cpu in os.sched_getaffinity(0)
        window = {"label": args.quiet_window, "cpu": args.cpu, "started_utc": datetime.now(timezone.utc).isoformat(),
            "load_before": Path("/proc/loadavg").read_text(), "declared_runs": 24,
            "runner_sha256": sha(Path(__file__)), "affinity": sorted(os.sched_getaffinity(0))}
        write_json(out / "quiet-window.json", window)
    for round_index, order in enumerate((LABELS,) if allocation else ORDERS, 1):
        for capacity, filled in PROFILES:
            for label in order:
                name = label + ("-alloc" if allocation else "")
                binary = out / "build" / name
                assert sha(binary) == gate_result["binaries"][name]
                command = [str(binary), str(capacity), str(filled), phase]
                if not allocation: command = ["taskset", "-c", str(args.cpu), *command]
                result = run(command, out / phase / f"round{round_index}-{capacity}-{filled}-{label}", check=False)
                row = {"round": round_index, "variant": label, "exit": result.returncode, **json.loads(result.stdout)}
                row["correct"] = row["exit"] == 0 and row["errors"] == 0 and row["completed"] == (20 if allocation else 500)
                rows.append(row); write_json(out / (phase + ".json"), rows)
                assert row["correct"], "remaining cost runs stopped on functional failure"
    if window:
        window.update(finished_utc=datetime.now(timezone.utc).isoformat(), completed_runs=len(rows),
                      load_after=Path("/proc/loadavg").read_text())
        write_json(out / "quiet-window.json", window)
    print(json.dumps({"phase": phase, "runs": len(rows), "completed": sum(row["completed"] for row in rows), "errors": sum(row["errors"] for row in rows)}))


def validate_allocations(rows):
    expected = {(label, capacity, filled) for label in LABELS for capacity, filled in PROFILES}
    actual = {(row["variant"], row["capacity"], row["filled"]) for row in rows}
    assert len(rows) == len(expected) and actual == expected, "complete allocation matrix required"
    for row in rows:
        assert row["round"] == 1 and row["correct"] and row["exit"] == 0 and row["errors"] == 0
        assert row["completed"] == 20 and row["hits"] == (20 if row["filled"] else 0)
        assert row["layout"] == LAYOUTS[row["variant"]]


def summarize(args):
    out, _ = load(args)
    allocations = json.loads((out / "allocation.json").read_text())
    validate_allocations(allocations)
    timing_path = out / "timing.json"
    timings = json.loads(timing_path.read_text()) if timing_path.exists() else []
    assert not timings or len(timings) == 24
    results = []
    for label in LABELS:
        profiles = []
        for capacity, filled in PROFILES:
            memory = {row["variant"]: row for row in allocations if (row["capacity"], row["filled"]) == (capacity, filled)}
            current = memory[label]; base = memory["deep"]
            steady_ratio = current["population_allocation"][3] / base["population_allocation"][3]
            # Include first mutable lookup: top COW must not win on cheap Arc::clone alone.
            snapshot_live = current["clone_allocation"][3] + current["lookup_allocation"][3]
            base_live = base["clone_allocation"][3] + base["lookup_allocation"][3]
            row = {"capacity": capacity, "filled": filled, "steady_requested_heap": current["population_allocation"][3],
                "steady_heap_ratio": steady_ratio, "snapshot_live_requested_heap": snapshot_live,
                "snapshot_live_heap_gain": 1 - snapshot_live / base_live, "peak_extra_requested": current["peak_extra_requested"],
                "population_allocations": current["population_allocation"][:2],
                "no_extra_population_allocations": all(a <= b for a, b in zip(current["population_allocation"][:2], base["population_allocation"][:2])),
                "snapshot_allocations": current["clone_allocation"][:2], "lookup_allocations": current["lookup_allocation"][:2],
                "layout": current["layout"], "image_layout": current["image_layout"],
                "balanced": current["final_allocation"][3] == 0 and current["population_drop"] == -current["population_allocation"][3]}
            if timings:
                cpu, population, p95 = [], [], []
                for round_index in (1, 2, 3):
                    pair = {value["variant"]: value for value in timings if value["round"] == round_index and (value["capacity"], value["filled"]) == (capacity, filled)}
                    a, b = pair[label], pair["deep"]
                    cpu.append((a["clone_cpu_ns"] + a["lookup_cpu_ns"]) / (b["clone_cpu_ns"] + b["lookup_cpu_ns"]))
                    population.append(a["population_cpu_ns"] / b["population_cpu_ns"])
                    p95.append(a["combined_p95_ns"] / b["combined_p95_ns"])
                row.update(combined_cpu_ratios=cpu, median_combined_cpu_gain=1-statistics.median(cpu),
                    paired_cpu_ratio_spread=max(cpu)-min(cpu), population_cpu_ratios=population, combined_p95_ratios=p95)
            profiles.append(row)
        balanced = all(row["balanced"] for row in profiles)
        steady = all(row["steady_heap_ratio"] <= 1.05 for row in profiles)
        live = all(row["snapshot_live_heap_gain"] >= .20 for row in profiles if row["capacity"] >= 1000)
        counts = all(row["no_extra_population_allocations"] for row in profiles)
        passed = False
        if timings:
            cpu = all(row["median_combined_cpu_gain"] >= .20 and row["median_combined_cpu_gain"] > row["paired_cpu_ratio_spread"] for row in profiles if row["capacity"] >= 1000)
            population = all(max(row["population_cpu_ratios"]) <= 1.05 for row in profiles)
            tail = all(max(row["combined_p95_ratios"]) <= 1.05 for row in profiles if row["capacity"] == 150)
            passed = balanced and steady and live and counts and cpu and population and tail
        results.append({"variant": label, "profiles": profiles, "allocation_gates": {"balanced": balanced, "steady_heap": steady, "snapshot_live_heap": live, "no_extra_population_allocations": counts},
            "status": "reference" if label == "deep" else ("candidate-pass" if passed else "candidate-fail" if timings else "timing-pending")})
    report = {"status": "measured" if timings else "allocation-only-timing-pending", "results": results,
        "allocation_sha256": sha(out / "allocation.json"), "gate_sha256": sha(out / "gate.json"),
        "scope": "private host primitive screen; no C-versus-Rust, component or router performance claim", "extra_rounds": 0}
    write_json(out / ("result.json" if timings else "allocation-result.json"), report)
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "gate", "allocation", "timing", "summarize", "negative"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-root", type=Path); parser.add_argument("--cache-sha256"); parser.add_argument("--source-revision")
    parser.add_argument("--oracle", type=Path); parser.add_argument("--c-source", type=Path)
    parser.add_argument("--rustc"); parser.add_argument("--cpu", type=int, default=0)
    parser.add_argument("--quiet-window")
    args = parser.parse_args()
    assert args.output.resolve().is_relative_to(ROOT / "private"), "artifacts belong in private"
    if args.phase == "negative":
        commands = (args.output / "oracle/calibration.input").read_text().splitlines()
        expected = (args.output / "oracle/calibration.oracle.stdout").read_text().splitlines()
        observed = (args.output / "gate/deep-calibration.stdout").read_text().splitlines()
        observed[3] = "Q 1:7:0:102:3:0"
        failures, variations = compare(commands, expected, observed)
        assert not variations
        report = {"operations": len(commands), "matches": len(commands)-len(failures), "failures": failures}
        print(json.dumps(report)); return int(bool(report["failures"]))
    assert os.uname().sysname == "Linux" and os.uname().machine == "aarch64", "native aarch64 Linux mechanism screen only"
    if args.phase == "prepare": return prepare(args)
    if args.phase == "gate": return gate(args)
    if args.phase in ("allocation", "timing"): return measure(args, args.phase == "allocation")
    return summarize(args)


if __name__ == "__main__":
    raise SystemExit(main())
