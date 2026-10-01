#!/usr/bin/env python3
"""Observe the unchanged private whole-frame Receiver against frozen C EOF.

Eight semantic cutpoints use prefixes of valid actual typed encodings. Native
partial sentinel has no typed equivalent and is explicitly reported C-only.
An observed behavior mismatch makes this runner exit nonzero; no repair occurs.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

from cache_transfer_diff import save, sha

ROOT = Path(__file__).resolve().parents[2]
PLAN_SHA = "9bbf0d1f2d373f8a780f77fbbbd60c74dc5f39ad6ec809c16865ff8a279f68d5"
RESULT_SHA = "aaf68255bd667494e694e55e5d36a5d27a917a40103716933580d6c56806c727"
TEST = "dns::tcp_transfer::partial_eof_tests::exact_c_partial_eof_probe"


def command(out, label, argv, env=None):
    run = subprocess.run(list(map(str, argv)), env=env, text=True, capture_output=True)
    (out / f"{label}.stdout").write_text(run.stdout)
    (out / f"{label}.stderr").write_text(run.stderr)
    save(out / f"{label}.command.json", {"argv": list(map(str, argv)), "exit": run.returncode})
    assert run.returncode == 0, (label, run.returncode)
    return run.stdout


def plan_text(case):
    lines = [f"case {case['case']}", f"capacity {case['capacity']}", f"seed-now {case['seed_now']}",
             f"receive-now {case['receive_now']}", f"cut {case['cut_stage']}"]
    for seed in case["seed"]:
        op = seed["operation"]
        if op == "insert":
            record = seed["record"]
            lines.append(f"seed insert {record['name']} {record['type']} {record['expiry']} {record.get('address', '-')}")
        elif op == "link":
            lines.append(f"seed link {seed['alias']} {seed['target']}")
        else:
            assert op in ("start", "commit")
            lines.append("seed " + op)
    for record in case["intended_records"]:
        assert record["type"] == "A" and record["class"] == 1
        lines.append(f"record {record['name']} A {record['expiry']} {record['address']}")
    lines += [f"lookup {lookup['name']} {lookup['type']}" for lookup in case["lookup_order"]]
    return "\n".join(lines) + "\n"


def compare(expected, actual):
    assert len(expected) == len(actual) == 3, "observation count mismatch"
    assert [row["stage"] for row in expected] == [row["stage"] for row in actual], "stage mismatch"
    return [{"stage": left["stage"], "c": left, "rust": right}
            for left, right in zip(expected, actual) if left != right]


def source_hashes():
    return {str(path.relative_to(ROOT)): sha(path)
            for component in ("dnsmasq", "ubus")
            for path in (ROOT / "components" / component).rglob("*")
            if path.is_file() and "target" not in path.parts
            and (path.suffix == ".rs" or path.name in ("Cargo.toml", "Cargo.lock"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [name for _, name in socket.if_nameindex()] == ["lo"]
    baseline, out = args.baseline.resolve(), args.out.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    assert sha(baseline / "plan.json") == PLAN_SHA
    assert sha(baseline / "result.json") == RESULT_SHA
    c_result = json.loads((baseline / "result.json").read_text())
    assert c_result["passed"] == 171 and c_result["failed"] == 0
    for case in c_result["cases"]:
        assert sha(baseline / case["case"] / "trace.json") == case["trace_sha256"]
    schedule = json.loads((baseline / "plan.json").read_text())
    out.mkdir(parents=True)
    sources = source_hashes()
    report = {"scope": __doc__, "baseline_result_sha256": RESULT_SHA, "plan_sha256": PLAN_SHA,
              "source_files": sources, "tool_sha256": sha(Path(__file__)), "cases": [], "differences": [],
              "failures": [], "c_only_not_representable": [], "compared": 0, "matched": 0}
    try:
        output = command(out, "build", [args.cargo, "+1.98.1", "test", "--locked", "--manifest-path",
            ROOT / "components/dnsmasq/Cargo.toml", "--lib", "--no-run", "--message-format=json", "--target-dir", out / "target"])
        executables = [Path(row["executable"]) for row in map(json.loads, output.splitlines())
                       if row.get("reason") == "compiler-artifact" and row.get("executable") and row.get("profile", {}).get("test")]
        assert len(executables) == 1
        probe = executables[0]
        report["probe_sha256"] = sha(probe)
        command(out, "compiler", [args.cargo, "+1.98.1", "--version"])
        for case in schedule:
            label = case["case"]
            c_trace = json.loads((baseline / label / "trace.json").read_text())
            if case["typed_correspondence"].startswith("not-representable"):
                report["c_only_not_representable"].append({"case": label, "observations": len(c_trace) - 1,
                    "reason": "native partial ssize_t end sentinel has no typed length/count counterpart"})
                continue
            folder = out / label
            folder.mkdir()
            (folder / "plan.txt").write_text(plan_text(case))
            env = dict(os.environ, DNSMASQ_PARTIAL_EOF_CASE=str(folder))
            command(folder, "probe", [probe, TEST, "--ignored", "--exact", "--nocapture", "--test-threads=1"], env=env)
            actual = [json.loads(line) for line in (folder / "rust-states.jsonl").read_text().splitlines()]
            expected = c_trace[1:]
            differences = compare(expected, actual)
            report["differences"] += [{"case": label, **row} for row in differences]
            report["compared"] += len(actual)
            report["matched"] += len(actual) - len(differences)
            report["cases"].append({"case": label, "observations": len(actual), "differences": len(differences),
                "native_metadata": c_trace[0], "typed_metadata": json.loads((folder / "typed-metadata.json").read_text()),
                "typed_states_sha256": sha(folder / "rust-states.jsonl"), "typed_wire_sha256": sha(folder / "typed-complete-wire.bin")})
            assert not compare(expected, expected)
            changed = json.loads(json.dumps(expected))
            changed[1]["pending_before_lookup"] += 1
            assert len(compare(expected, changed)) == 1
            changed = json.loads(json.dumps(expected))
            changed[1]["inserted"] += 1
            assert len(compare(expected, changed)) == 1
            try:
                compare(expected, actual[:-1])
            except AssertionError:
                pass
            else:
                raise AssertionError("missing observation accepted")
        assert sources == source_hashes(), "source changed during qualification"
        assert report["compared"] == 24 and len(report["c_only_not_representable"]) == 1
        report["comparison_calibrations"] = ["equal trace accepted", "pending mismatch rejected", "counter mismatch rejected", "missing state rejected"]
    except Exception as error:
        report["failures"].append(repr(error))
    report["failed"] = len(report["differences"]) + len(report["failures"])
    save(out / "result.json", report)
    print(json.dumps({key: report[key] for key in ("compared", "matched", "failed", "failures", "c_only_not_representable")}))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
