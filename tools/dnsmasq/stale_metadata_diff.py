#!/usr/bin/env python3
"""Replay the frozen actual C stale metadata trace through a Rust test driver.

No C baseline is regenerated and no expected response comes from Rust. Compare
stale/filtered even for NONE, and DNS semantics without sorting RR order or
discarding TTLs/flags. Count or execution failures invalidate a whole profile.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from local_answer_diff import dns_semantics
from stale_metadata_oracle import SOURCE_HASHES
import rust_lib_probe

ROOT = Path(__file__).resolve().parents[2]
TEST = "dns::daemon::stale_tests::exact_c_stale_driver"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def semantics(command, output):
    op = command.split()[0]
    if op in ("RESET", "P"):
        if output != op:
            raise ValueError(f"invalid {op} output")
        return output
    if op == "M":
        words = output.split()
        if len(words) != 3 or words[0] != "M":
            raise ValueError("invalid metrics output")
        values = list(map(int, words[1:]))
        if any(value < 0 or value > 2**32-1 for value in values):
            raise ValueError("metric is not u32")
        return ["M", *values]
    if op == "T":
        words = output.split(" ", 3)
        if len(words) != 4 or words[0] != "T" or any(value not in ("0", "1") for value in words[1:3]):
            raise ValueError("invalid stale metadata output")
        return {"stale": int(words[1]), "filtered": int(words[2]), "reply": dns_semantics(words[3])}
    if op == "Q":
        return dns_semantics(output)
    raise ValueError("unexpected command")


def compare(rows, expected, actual):
    if len(rows) != len(expected) or len(expected) != len(actual):
        raise ValueError(f"output count differs: commands={len(rows)} C={len(expected)} Rust={len(actual)}")
    failures = []
    for index, (row, c, rust) in enumerate(zip(rows, expected, actual)):
        c_semantics = semantics(row["command"], c)
        try:
            rust_semantics = semantics(row["command"], rust)
        except Exception as error:
            # Malformed returned DNS data is a counted functional failure,
            # not a reason to drop the profile or its remaining comparisons.
            failures.append({"index": index, "case": row["case"], "command": row["command"],
                             "c": c, "rust": rust, "c_semantics": c_semantics,
                             "rust_parse_error": repr(error)})
            continue
        if c_semantics != rust_semantics:
            failures.append({"index": index, "case": row["case"], "command": row["command"],
                             "c": c, "rust": rust, "c_semantics": c_semantics, "rust_semantics": rust_semantics})
    return failures


def source_hashes(root):
    files = [*sorted((root / "components/dnsmasq/src").rglob("*.rs")),
             *sorted((root / "components/ubus/src").rglob("*.rs")),
             root / "components/dnsmasq/Cargo.toml", root / "components/dnsmasq/Cargo.lock"]
    assert files and (root / "components/dnsmasq/src/dns/daemon_stale_tests.rs").is_file()
    return {str(path.relative_to(root)): digest(path) for path in files}


def calibrate(rows, c):
    assert compare(rows, c, c) == []
    for changed in [c[:-1], c + [c[-1]]]:
        try:
            compare(rows, c, changed)
        except ValueError:
            pass
        else:
            raise AssertionError("count calibration accepted missing/extra output")
    index = next(i for i, row in enumerate(rows) if row["command"].startswith("T "))
    for position in [1, 2]:
        changed = list(c); words = changed[index].split(" ", 3)
        words[position] = str(1-int(words[position])); changed[index] = " ".join(words)
        assert [row["index"] for row in compare(rows, c, changed)] == [index]
    index = next(i for i, line in enumerate(c) if line.startswith("T ") and not line.endswith(" NONE"))
    changed = list(c); words = changed[index].split(" ", 3); packet = bytearray.fromhex(words[3])
    packet[3] ^= 1; words[3] = packet.hex(); changed[index] = " ".join(words)
    assert [row["index"] for row in compare(rows, c, changed)] == [index]
    return {"equal_trace": 1, "short_output_rejected": 1, "extra_output_rejected": 1,
            "stale_mutation_rejected": 1, "filtered_mutation_rejected": 1, "rcode_mutation_rejected": 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=ROOT / "private/dnsmasq-rewrite/stale-metadata-20261001/baseline-01")
    parser.add_argument("--rust-driver", type=Path, help="optional prebuilt driver; must match the fresh source build")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    rust_lib_probe.add_arguments(parser)
    args = parser.parse_args()
    if not args.rust_source_root:
        parser.error('--rust-source-root is required')
    # Retain legacy local invocation; Oracle always requires a copied probe.
    if not (args.rust_test_binary or args.rust_build_receipt):
        args.local_native = True
    out = args.out.resolve()
    try:
        probe, source_root, binding = rust_lib_probe.selection(args, ROOT, out)
    except ValueError as error:
        parser.error(str(error))
    if probe and args.rust_driver:
        parser.error('--rust-driver belongs to legacy local builds, not a copied probe')
    baseline = args.baseline.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    base = json.loads((baseline / "result.json").read_text())
    identity = json.loads((baseline / "identity.json").read_text())
    assert base["identity"] == identity and identity["source_sha256"] == SOURCE_HASHES
    assert base["passed"] == 1131 and base["failed"] == 0 and not base["inject_error"]
    assert digest(baseline / Path(identity["binary"]).name) == identity["binary_sha256"]
    assert identity["driver_sha256"] == digest(Path(__file__).with_name("cache_answer_driver.c"))
    before = source_hashes(source_root)
    driver = probe
    if probe is None:
        # Legacy local drivers remain bound to a fresh source build.
        build_command = [args.cargo, "+1.98.1", "test", "--manifest-path",
                         str(source_root / "components/dnsmasq/Cargo.toml"),
                         "--lib", "--no-run", "--message-format=json"]
        build = subprocess.run(build_command, text=True, capture_output=True, cwd=source_root)
        (out / "build.stdout").write_text(build.stdout); (out / "build.stderr").write_text(build.stderr)
        (out / "build-command.json").write_text(json.dumps(build_command, indent=2) + "\n")
        build.check_returncode()
        assert before == source_hashes(source_root), "source changed during build"
        executables = [Path(row["executable"]) for line in build.stdout.splitlines() if line.startswith("{")
                       for row in [json.loads(line)] if row.get("executable") and row.get("profile", {}).get("test")]
        assert len(executables) == 1
        if args.rust_driver:
            assert digest(args.rust_driver.resolve()) == digest(executables[0]), "prebuilt driver does not match the source build"
        driver = out / "rust-driver"
        shutil.copy2(executables[0], driver)
    report = {"scope": "frozen-clock cached-answer caller metadata/semantics; max-reply profile is library-only",
              "baseline_result_sha256": digest(baseline / "result.json"), "c_identity": identity,
              "rust_driver_sha256": digest(driver), "rust_source_root": str(source_root), "source_sha256": before,
              "rust_probe": binding,
              "tool_sha256": digest(Path(__file__)), "profiles": [], "execution_errors": [], "inject_error": args.inject_error}
    injected = False
    for profile in base["profiles"]:
        rust_lib_probe.recheck(binding)
        folder = baseline / profile["folder"]
        for filename, key in [("config.conf", "config_sha256"), ("commands.txt", "commands_sha256"), ("c.stdout", "trace_sha256")]:
            assert digest(folder / filename) == profile[key], (profile["label"], filename, "baseline identity changed")
        rows = json.loads((folder / "cases.json").read_text())
        assert "\n".join(row["command"] for row in rows)+"\n" == (folder / "commands.txt").read_text()
        c = (folder / "c.stdout").read_text().splitlines()
        assert len(rows) == len(c) == profile["commands"]
        calibration = calibrate(rows, c)
        target = out / profile["label"]; target.mkdir()
        command = rust_lib_probe.argv(driver, TEST)
        env = {**os.environ, "DNSMASQ_STALE_CONFIG": str(folder / "config.conf"), "DNSMASQ_STALE_INPUT": str(folder / "commands.txt")}
        detail = {"profile": profile["label"], "profile_scope": profile["scope"], "command": command,
                  "planned": len(rows), "compared": 0, "failures": [], "exit": None, "calibration": calibration}
        try:
            run = subprocess.run(command, env=env, cwd=source_root, text=True, capture_output=True, timeout=30)
        except (subprocess.TimeoutExpired, OSError) as error:
            def captured(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            (target / "rust.stdout").write_text(captured(getattr(error, "stdout", None)))
            (target / "rust.stderr").write_text(captured(getattr(error, "stderr", None)))
            detail["execution_error"] = repr(error)
            report["execution_errors"].append({"profile": profile["label"], "error": repr(error)})
            (target / "comparison.json").write_text(json.dumps(detail, indent=2)+"\n")
            report["profiles"].append(detail)
            continue
        (target / "rust.stdout").write_text(run.stdout); (target / "rust.stderr").write_text(run.stderr)
        actual = [line.removeprefix("STALE_ORACLE ")
                  for line in rust_lib_probe.records(run.stdout, TEST, "STALE_ORACLE ")]
        detail["exit"] = run.returncode
        try:
            if run.returncode:
                raise ValueError(f"Rust driver exited {run.returncode}")
            rust_lib_probe.require_one_test(run.stdout, TEST)
            if args.inject_error and not injected:
                index = next(i for i, row in enumerate(rows) if row["command"].startswith("T "))
                if len(actual) != len(c):
                    raise ValueError("cannot inject before complete output validation")
                words = actual[index].split(" ", 3); words[1] = str(1-int(words[1])); actual[index] = " ".join(words)
                (target / "injected-rust.rows").write_text("\n".join(actual)+"\n"); injected = True
            detail["failures"] = compare(rows, c, actual)
            detail["compared"] = len(rows)
        except ValueError as error:
            detail["execution_error"] = str(error)
            report["execution_errors"].append({"profile": profile["label"], "error": str(error)})
        (target / "comparison.json").write_text(json.dumps(detail, indent=2)+"\n")
        report["profiles"].append(detail)
    rust_lib_probe.recheck(binding)
    after = source_hashes(source_root)
    if before != after or digest(driver) != report["rust_driver_sha256"]:
        report["execution_errors"].append({"error": "Rust source/driver identity changed during the gate"})
    report["planned"] = sum(row["planned"] for row in report["profiles"])
    report["compared"] = sum(row["compared"] for row in report["profiles"])
    report["not_compared"] = report["planned"]-report["compared"]
    report["mismatches"] = sum(len(row["failures"]) for row in report["profiles"])
    report["passed"] = report["compared"]-report["mismatches"]
    (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({key: report[key] for key in ["scope", "planned", "compared", "not_compared", "passed", "mismatches", "execution_errors"]}))
    return bool(report["mismatches"] or report["execution_errors"] or report["not_compared"])


if __name__ == "__main__":
    raise SystemExit(main())
