#!/usr/bin/env python3
"""Independent 27-row same-name reverse expiry addon; original gates unchanged."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess

import reverse_cache_c_gate as reference
from reverse_cache_rust_gate import annotate, compare, files

ROOT = Path(__file__).resolve().parents[2]
TARGET = "MiXeD.Target.Test"
ADDRESS = "192.0.2.7"
FORWARD = "192.0.2.99"


def corpus():
    owner = reference.reverse(ADDRESS)
    cases = []
    for suffix, flags in (("rd1", 0x100), ("rd0", 0)):
        case = reference.Case("lookup-" + suffix)
        case.ptr("seed-expiring-ptr", owner, TARGET, ttl=1)
        case.query("forward-lookup-after-expiry", TARGET.lower(), 1, now=102, flags=flags)
        case.state("expired-reverse-removed", [])
        case.query("rollback-ptr-miss", owner, now=100)
        case.metrics(1)
        cases.append(case)
    case = reference.Case("forward-insert")
    case.ptr("seed-expiring-ptr", owner, TARGET, ttl=1)
    case.address("same-name-forward-insert", TARGET.lower(), FORWARD, now=102)
    case.state("only-forward-survives", [reference.entry(TARGET.lower(), FORWARD, expires=222)])
    case.query("rollback-ptr-miss", owner, now=100)
    case.query("forward-hit", TARGET.lower(), 1, ipaddress.ip_address(FORWARD).packed, now=102)
    case.metrics(2)
    cases.append(case)
    case = reference.Case("contains-control")
    case.ptr("seed-expiring-ptr", owner, TARGET, ttl=1)
    case.exists("read-only-forward-existence", TARGET.lower(), False, now=102)
    case.state("expired-reverse-retained", [reference.rentry(TARGET, ADDRESS, 101)])
    case.query("rollback-ptr-hit", owner, data=reference.name(TARGET.lower()), now=100)
    case.actions[-1]["expected"]["ptr_case"] = [TARGET]
    case.metrics(1)
    cases.append(case)
    case = reference.Case("live-coexist-control")
    case.ptr("seed-live-ptr", owner, TARGET)
    case.address("same-name-forward-insert", TARGET.lower(), FORWARD, now=102)
    case.query("forward-hit", TARGET.lower(), 1, ipaddress.ip_address(FORWARD).packed, now=102)
    case.query("rollback-ptr-hit", owner, data=reference.name(TARGET.lower()), now=100)
    case.actions[-1]["expected"]["ptr_case"] = [TARGET]
    case.state("both-directions-live", [reference.rentry(TARGET, ADDRESS),
                                       reference.entry(TARGET.lower(), FORWARD, expires=222)])
    case.metrics(2)
    cases.append(case)
    assert len(cases) == 5 and sum(len(case.actions) for case in cases) == 27
    return cases


def isolated():
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(label for _, label in socket.if_nameindex()) == ["lo"]


def output(path):
    path = path.resolve()
    assert path.is_relative_to(ROOT / "private") and not path.exists()
    path.mkdir(parents=True)
    shutil.copy2(__file__, path / Path(__file__).name)
    return path


def check(row, expected):
    errors = reference.check_row(row, expected)
    if "entries" in expected:
        actual = [{key: value for key, value in entry.items() if key != "bucket"}
                  for entry in row["entries"]]
        if actual != expected["entries"]:
            errors.append({"field": "ordered_entries", "expected": expected["entries"], "actual": actual})
    return errors


def calibrate_comparator(rows):
    assert not compare(rows, copy.deepcopy(rows))
    changed = copy.deepcopy(rows)
    index = next(i for i, row in enumerate(changed) if row["op"] == "M")
    changed[index]["inserted"] += 1
    assert compare(rows, changed) == [index]
    try:
        compare(rows, rows[:-1])
    except ValueError:
        pass
    else:
        raise AssertionError("missing row was accepted")


def execute(binary, config, actions, out):
    commands = "\n".join(row["command"] for row in actions) + "\n"
    (out / "commands.txt").write_text(commands)
    result = subprocess.run([str(binary), "-C", str(config)], input=commands,
                            capture_output=True, text=True, timeout=15)
    (out / "stdout.txt").write_text(result.stdout)
    (out / "stderr.txt").write_text(result.stderr)
    assert result.returncode == 0, f"driver exit {result.returncode}"
    raw = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(raw) == len(actions), "missing or extra rows"
    rows = [annotate(row, action["label"]) for row, action in zip(raw, actions)]
    reference.save(out / "observations.json", rows)
    return rows


def c_run(args):
    isolated()
    out = output(args.out)
    args.reference_build = args.reference_build.resolve()
    cases = corpus()
    reference.save(out / "matrix.json", [vars(case) for case in cases])
    binary, identity = reference.build(args, out)
    shutil.copy2(reference.DRIVER, out / reference.DRIVER.name)
    report = {"scope": "exact native source primitive; same-name expiry addon only",
              "tool_sha256": reference.digest(__file__), "identity": identity,
              "profiles": [], "failures": []}
    for case in cases:
        work = out / case.label
        work.mkdir()
        config = work / "dnsmasq.conf"
        config.write_text(f"no-hosts\nno-resolv\ncache-size={case.capacity}\nneg-ttl=120\nno-round-robin\n")
        rows, errors = [], []
        try:
            rows = execute(binary, config, case.actions, work)
            for action, row in zip(case.actions, rows):
                errors.extend({"label": action["label"], **error} for error in check(row, action["expected"]))
            calibrate_comparator(rows)
        except Exception as error:
            errors.append({"error": repr(error)})
        profile = {"label": case.label, "expected_rows": len(case.actions),
                   "observed_rows": len(rows), "failures": errors}
        report["profiles"].append(profile)
        report["failures"].extend({"profile": case.label, **error} for error in errors)
        reference.save(out / "result.json", report)
    report["observed"] = sum(case["observed_rows"] for case in report["profiles"])
    reference.save(out / "result.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("identity", "profiles")}))
    return int(bool(report["failures"]))


def rust_run(args):
    isolated()
    out = output(args.out)
    baseline = args.c_baseline.resolve()
    matrix = json.loads((baseline / "matrix.json").read_text())
    assert matrix == json.loads(json.dumps([vars(case) for case in corpus()])), "frozen addon matrix changed"
    c_result = json.loads((baseline / "result.json").read_text())
    assert c_result["observed"] == 27 and not c_result["failures"]
    assert c_result["tool_sha256"] == reference.digest(__file__)
    identity = json.loads((args.build / "identity.json").read_text())
    assert identity["source_commit"] == args.expect_source
    assert identity["build_exit"] == 0 and reference.digest(identity["binary"]) == identity["binary_sha256"]
    assert files(args.build / "source") == identity["instrumented_sources"]
    report = {"scope": "same-name expiry addon only; original 125 and cohort untouched",
              "tool_sha256": reference.digest(__file__), "build_identity": identity,
              "c_matrix_sha256": reference.digest(baseline / "matrix.json"),
              "c_result_sha256": reference.digest(baseline / "result.json"),
              "profiles": [], "failures": []}
    for case in matrix:
        work = out / case["label"]
        work.mkdir()
        config = work / "dnsmasq.conf"
        shutil.copy2(baseline / case["label"] / "dnsmasq.conf", config)
        expected = json.loads((baseline / case["label"] / "observations.json").read_text())
        calibrate_comparator(expected)
        actual, differences, failures = [], [], []
        try:
            actual = execute(identity["binary"], config, case["actions"], work)
            differences = [{"label": case["actions"][index]["label"], "c": expected[index], "rust": actual[index]}
                           for index in compare(expected, actual)]
        except Exception as error:
            failures.append(repr(error))
        reference.save(work / "differences.json", differences)
        profile = {"label": case["label"], "expected_rows": len(expected), "observed_rows": len(actual),
                   "mismatches": len(differences), "failures": failures}
        report["profiles"].append(profile)
        report["failures"].extend({"profile": case["label"], "error": error} for error in failures)
        reference.save(out / "result.json", report)
    report["observed"] = sum(case["observed_rows"] for case in report["profiles"])
    report["mismatches"] = sum(case["mismatches"] for case in report["profiles"])
    reference.save(out / "result.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("build_identity", "profiles")}))
    return int(bool(report["failures"] or report["mismatches"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    phases = parser.add_subparsers(dest="phase", required=True)
    c = phases.add_parser("c")
    c.add_argument("--reference-build", type=Path, required=True)
    rust = phases.add_parser("rust")
    rust.add_argument("--build", type=Path, required=True)
    rust.add_argument("--expect-source", required=True)
    rust.add_argument("--c-baseline", type=Path, required=True)
    for phase in (c, rust):
        phase.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return c_run(args) if args.phase == "c" else rust_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
