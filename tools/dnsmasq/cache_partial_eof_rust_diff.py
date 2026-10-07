#!/usr/bin/env python3
"""Compare the actual private Receiver against frozen C partial-pipe EOF.

Original whole-frame mode maps eight semantic cutpoints and reports native
partial sentinel C-only. --stream-format maps all nine using explicit Begin,
length-prefixed records and an End marker. Mismatches always exit nonzero.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

from cache_transfer_diff import save, sha
import rust_lib_probe

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


def source_hashes(source=ROOT):
    return {str(path.relative_to(source)): sha(path)
            for component in ("dnsmasq", "ubus")
            for path in (source / "components" / component).rglob("*")
            if path.is_file() and "target" not in path.parts
            and (path.suffix == ".rs" or path.name in ("Cargo.toml", "Cargo.lock"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--stream-format", action="store_true")
    parser.add_argument("--fresh-c-receipt", type=Path, help='explicit newly executed C primitive receipt; historical result pin otherwise')
    rust_lib_probe.add_arguments(parser)
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and [name for _, name in socket.if_nameindex()] == ["lo"]
    baseline, out = args.baseline.resolve(), args.out.resolve()
    try:
        probe, source_root, binding = rust_lib_probe.selection(args, ROOT, out)
    except ValueError as error:
        parser.error(str(error))
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    assert sha(baseline / "plan.json") == PLAN_SHA
    fresh_c = None
    if args.fresh_c_receipt:
        from c_primitive_receipt import validate_fresh
        fresh_c = validate_fresh(baseline, args.fresh_c_receipt.resolve(), 'cache-partial-eof')
    else:
        assert sha(baseline / "result.json") == RESULT_SHA
    c_result = json.loads((baseline / "result.json").read_text())
    assert c_result["failed"] == 0 and (fresh_c is not None or c_result["passed"] == 171)
    for case in c_result["cases"]:
        assert sha(baseline / case["case"] / "trace.json") == case["trace_sha256"]
    schedule = json.loads((baseline / "plan.json").read_text())
    assert len(c_result['cases']) == len(schedule) == 9
    assert {case['case'] for case in c_result['cases']} == {case['case'] for case in schedule}
    out.mkdir(parents=True)
    sources = source_hashes(source_root)
    report = {"scope": __doc__, "baseline_result_sha256": sha(baseline / 'result.json'), "plan_sha256": PLAN_SHA,
              "typed_format": "stream-v1" if args.stream_format else "whole-frame-v1",
              "source_files": sources, "tool_sha256": sha(Path(__file__)), "cases": [], "differences": [],
              "rust_probe": binding, "rust_test": TEST,
              "fresh_c_receipt": fresh_c,
              "c_reference_scope": ("fresh exact-source C partial-pipe primitive on unchanged corpus; not stock image 097a9e21 ELF" if fresh_c else
                                    "historical pinned C partial-pipe transcripts; additional regression, not fresh A service"),
              "failures": [], "c_only_not_representable": [], "compared": 0, "matched": 0}
    try:
        if probe is None:
            output = command(out, "build", [args.cargo, "+1.98.1", "test", "--locked", "--manifest-path",
                source_root / "components/dnsmasq/Cargo.toml", "--lib", "--no-run", "--message-format=json", "--target-dir", out / "target"])
            executables = [Path(row["executable"]) for row in map(json.loads, output.splitlines())
                           if row.get("reason") == "compiler-artifact" and row.get("executable") and row.get("profile", {}).get("test")]
            assert len(executables) == 1
            probe = executables[0]
            command(out, "compiler", [args.cargo, "+1.98.1", "--version"])
        report["probe_sha256"] = sha(probe)
        for case in schedule:
            rust_lib_probe.recheck(binding)
            if fresh_c is not None:
                if validate_fresh(baseline, args.fresh_c_receipt.resolve(), 'cache-partial-eof') != fresh_c:
                    raise ValueError('fresh C receipt/baseline changed during comparison')
            label = case["case"]
            c_trace = json.loads((baseline / label / "trace.json").read_text())
            if case["typed_correspondence"].startswith("not-representable") and not args.stream_format:
                report["c_only_not_representable"].append({"case": label, "observations": len(c_trace) - 1,
                    "reason": "native partial ssize_t end sentinel has no typed length/count counterpart"})
                continue
            folder = out / label
            folder.mkdir()
            (folder / "plan.txt").write_text(plan_text(case))
            env = dict(os.environ, DNSMASQ_PARTIAL_EOF_CASE=str(folder))
            command(folder, "probe", rust_lib_probe.argv(probe, TEST), env=env)
            actual = [json.loads(line) for line in (folder / "rust-states.jsonl").read_text().splitlines()]
            typed_metadata = json.loads((folder / "typed-metadata.json").read_text())
            assert typed_metadata.get("format", "whole-frame-v1") == report["typed_format"], "runner/adapter format mismatch"
            expected = c_trace[1:]
            differences = compare(expected, actual)
            report["differences"] += [{"case": label, **row} for row in differences]
            report["compared"] += len(actual)
            report["matched"] += len(actual) - len(differences)
            report["cases"].append({"case": label, "observations": len(actual), "differences": len(differences),
                "native_metadata": c_trace[0], "typed_metadata": typed_metadata,
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
            rust_lib_probe.recheck(binding)
        assert sources == source_hashes(source_root), "source changed during qualification"
        if fresh_c is not None and validate_fresh(baseline, args.fresh_c_receipt.resolve(), 'cache-partial-eof') != fresh_c:
            raise ValueError('fresh C receipt/baseline changed after comparison')
        assert report["compared"] == (27 if args.stream_format else 24)
        assert len(report["c_only_not_representable"]) == (0 if args.stream_format else 1)
        report["comparison_calibrations"] = ["equal trace accepted", "pending mismatch rejected", "counter mismatch rejected", "missing state rejected"]
    except Exception as error:
        report["failures"].append(repr(error))
    report["failed"] = len(report["differences"]) + len(report["failures"])
    save(out / "result.json", report)
    print(json.dumps({key: report[key] for key in ("compared", "matched", "failed", "failures", "c_only_not_representable")}))
    return int(bool(report["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
