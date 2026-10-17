#!/usr/bin/env python3
"""Compare a frozen Rust source copy with the saved 125-row reverse C baseline."""
import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tarfile

from dns_cache_rr_diff import decode
from reverse_cache_c_gate import digest, ptr_case, read_case_name, save

ROOT = Path(__file__).resolve().parents[2]
C_MATRIX_SHA = "dd8c3201822afde8b480e39fe7631ddf6d109bc72948c4a21e16e63040d9a6b5"
C_RESULT_SHA = "63e97d2c01e391036f9b71de7ea3bff47030816043b2aaecdcf308c406ae396f"


def private_path(path):
    path = path.resolve()
    assert path.is_relative_to(ROOT / "private")
    return path


def files(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob("*")) if path.is_file()}


def build(args):
    out = private_path(args.out)
    assert not out.exists()
    out.mkdir(parents=True)
    source = out / "source"
    source.mkdir()
    archive = args.source_archive.resolve()
    with tarfile.open(archive) as package:
        assert package.pax_headers.get("comment") == args.source_commit, package.pax_headers
        for member in package.getmembers():
            assert not member.name.startswith("/") and ".." not in Path(member.name).parts
            assert member.name == "components" or member.name.startswith(("components/dnsmasq", "components/ubus", "components/platform"))
            assert member.isfile() or member.isdir()
        package.extractall(source, filter="data")
    original = files(source)
    state_path = Path(__file__).with_name("reverse_cache_state_probe.rs")
    entry_path = Path(__file__).with_name("reverse_cache_probe.rs")
    state = state_path.read_text()
    entry = entry_path.read_text()
    if args.projection == "before":
        arms = ""
        lookup = 'println!("{{\\\"op\\\":\\\"A\\\",\\\"unsupported\\\":\\\"no reverse lookup API\\\"}}");'
    else:
        arms = "Kind::ReverseIpv4 => (1, true), Kind::ReverseIpv6 => (28, true),"
        lookup = '''let now: i64 = words[1].parse().unwrap();
                let address: std::net::IpAddr = words[2].parse().unwrap();
                let entries: Vec<_> = cache.lookup_reverse(address, now).into_iter()
                    .map(|id| cache.reverse_gate_entry_json(id)).collect();
                println!("{{\\\"op\\\":\\\"A\\\",\\\"entries\\\":[{}]}}", entries.join(","));'''
    state = state.replace("/* REVERSE_MATCH_ARMS */", arms)
    entry = entry.replace("/* REVERSE_LOOKUP */", lookup)
    modified = {}
    for relative, text in [("components/dnsmasq/src/dns/cache.rs", state), ("components/dnsmasq/src/dns/daemon.rs", entry)]:
        path = source / relative
        before = path.read_bytes()
        path.write_bytes(before + b"\n" + text.encode())
        assert path.read_bytes().startswith(before)
        modified[relative] = {"original_sha256": original[relative], "original_bytes": len(before), "instrumented_sha256": digest(path)}
    binary_source = source / "components/dnsmasq/src/bin/reverse-cache-probe.rs"
    binary_source.parent.mkdir(exist_ok=True)
    binary_source.write_text("fn main() { dnsmasq_rs::dns::daemon::reverse_cache_probe_main(); }\n")
    instrumented = files(source)
    allowed = set(modified) | {str(binary_source.relative_to(source))}
    assert {path for path in set(original) | set(instrumented) if original.get(path) != instrumented.get(path)} == allowed
    identity = {"source_commit": args.source_commit, "source_archive_sha256": digest(archive),
                "projection": args.projection, "original_sources": original,
                "instrumented_sources": instrumented, "append_only": modified,
                "entry_probe_sha256": digest(entry_path), "state_probe_sha256": digest(state_path),
                "tool_sha256": digest(__file__)}
    save(out / "identity.json", identity)
    command = [args.cargo, "+1.98.1", "build", "--frozen", "--release", "--manifest-path",
               str(source / "components/dnsmasq/Cargo.toml"), "--bin", "reverse-cache-probe", "--target-dir", str(out / "target")]
    with (out / "build.log").open("w") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    identity["build_command"] = command
    identity["build_exit"] = result.returncode
    if result.returncode == 0:
        identity["binary"] = str(out / "target/release/reverse-cache-probe")
        identity["binary_sha256"] = digest(identity["binary"])
    save(out / "identity.json", identity)
    print(json.dumps({key: value for key, value in identity.items() if key not in ("original_sources", "instrumented_sources", "append_only", "build_command")}))
    return int(result.returncode != 0)


def annotate(row, label):
    row = copy.deepcopy(row)
    row["label"] = label
    if row.get("packet") is not None:
        wire = bytes.fromhex(row["packet"])
        row["decoded"] = decode(wire)
        row["ptr_case"] = ptr_case(wire)
        count, position, questions = struct.unpack_from("!H", wire, 4)[0], 12, []
        for _ in range(count):
            owner, position = read_case_name(wire, position)
            kind, cls = struct.unpack_from("!HH", wire, position)
            questions.append([owner, kind, cls])
            position += 4
        row["question_case"] = questions
    return row


def semantic(row):
    row = copy.deepcopy(row)
    if row.get("packet") is not None:
        # The complete decoded packet and original-case question/PTR names
        # remain. Only compression bytes are excluded from equivalence.
        del row["packet"]
    for entry in row.get("entries", []):
        entry.pop("bucket", None)
    return row


def compare(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("missing or extra rows")
    return [index for index, (left, right) in enumerate(zip(expected, actual)) if semantic(left) != semantic(right)]


def run(args):
    assert os.geteuid() == 0 and os.environ.get("DNSMASQ_TEST_ISOLATED") == "1"
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    out = private_path(args.out)
    assert not out.exists()
    out.mkdir(parents=True)
    baseline = args.c_baseline.resolve()
    assert digest(baseline / "matrix.json") == C_MATRIX_SHA
    assert digest(baseline / "result.json") == C_RESULT_SHA
    c_result = json.loads((baseline / "result.json").read_text())
    assert not c_result["failures"] and c_result["main_complete"] == 125 and c_result["cohort_complete"] == 44
    matrix = json.loads((baseline / "matrix.json").read_text())
    cases = [case for case in matrix if not case["cohort"]]
    assert len(cases) == 14 and sum(len(case["actions"]) for case in cases) == 125
    build_root = args.build.resolve()
    identity = json.loads((build_root / "identity.json").read_text())
    assert identity["build_exit"] == 0 and digest(identity["binary"]) == identity["binary_sha256"]
    assert files(build_root / "source") == identity["instrumented_sources"]
    report = {"build_identity": identity, "c_result_sha256": C_RESULT_SHA, "c_matrix_sha256": C_MATRIX_SHA,
              "cohort": "C-only; not replayed or normalized", "profiles": [], "failures": [],
              "tool_sha256": digest(__file__)}
    calibration = []
    for case in cases:
        label = case["label"]
        work = out / label
        work.mkdir()
        config = work / "dnsmasq.conf"
        shutil.copy2(baseline / label / "dnsmasq.conf", config)
        commands = (baseline / label / "commands.txt").read_text()
        assert commands == "\n".join(action["command"] for action in case["actions"]) + "\n"
        (work / "commands.txt").write_text(commands)
        expected_saved = json.loads((baseline / label / "observations.json").read_text())
        expected = [annotate(row, action["label"]) for row, action in zip(expected_saved, case["actions"])]
        assert len(expected) == len(case["actions"])
        assert not compare(expected, copy.deepcopy(expected))
        changed = copy.deepcopy(expected)
        changed_at = next(i for i, row in enumerate(changed) if row.get("decoded", {}).get("records"))
        changed[changed_at]["decoded"]["records"][0]["ttl"] += 1
        assert compare(expected, changed) == [changed_at]
        try:
            compare(expected, expected[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("missing row was accepted")
        calibration.append({"profile": label, "one_changed_ttl_detected": True, "missing_row_rejected": True})
        result = subprocess.run([identity["binary"], "-C", str(config)], input=commands, capture_output=True, text=True, timeout=15)
        (work / "stdout.txt").write_text(result.stdout)
        (work / "stderr.txt").write_text(result.stderr)
        actual, differences, failures = [], [], []
        try:
            assert result.returncode == 0, f"probe exit {result.returncode}"
            raw = [json.loads(line) for line in result.stdout.splitlines()]
            assert len(raw) == len(case["actions"]), "missing or extra command rows"
            actual = [annotate(row, action["label"]) for row, action in zip(raw, case["actions"])]
            for index in compare(expected, actual):
                differences.append({"label": case["actions"][index]["label"], "c": expected[index], "rust": actual[index]})
        except Exception as error:
            failures.append(repr(error))
        save(work / "observations.json", actual)
        save(work / "differences.json", differences)
        profile = {"label": label, "expected_rows": len(expected), "observed_rows": len(actual),
                   "mismatches": len(differences), "unsupported_rows": sum("unsupported" in row for row in actual),
                   "probe_exit": result.returncode, "failures": failures,
                   "c_observations_sha256": digest(baseline / label / "observations.json")}
        report["profiles"].append(profile)
        report["failures"].extend({"profile": label, "failure": failure} for failure in failures)
        save(out / "result.json", report)
    report["observed"] = sum(row["observed_rows"] for row in report["profiles"])
    report["mismatches"] = sum(row["mismatches"] for row in report["profiles"])
    report["unsupported_rows"] = sum(row["unsupported_rows"] for row in report["profiles"])
    save(out / "calibration.json", calibration)
    save(out / "result.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("profiles", "build_identity")}))
    return int(bool(report["failures"] or report["mismatches"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    prepare = sub.add_parser("build")
    prepare.add_argument("--source-archive", type=Path, required=True)
    prepare.add_argument("--source-commit", required=True)
    prepare.add_argument("--projection", choices=("before", "reverse"), required=True)
    prepare.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    execute = sub.add_parser("run")
    execute.add_argument("--build", type=Path, required=True)
    execute.add_argument("--c-baseline", type=Path, required=True)
    for phase in (prepare, execute):
        phase.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return build(args) if args.phase == "build" else run(args)


if __name__ == "__main__":
    raise SystemExit(main())
