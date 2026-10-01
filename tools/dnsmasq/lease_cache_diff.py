#!/usr/bin/env python3
"""Exact C cache_add_dhcp_entry versus Rust selective forward invalidation.

Local blocker placement is a state-machine fixture through real cache_hash;
the oracle includes unchanged cache.c and links the remaining exact objects.
No listeners, router state, Rust-derived expectations or order normalization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
CACHE_SHA = "51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(args, out):
    obj = args.reference_build / "dnsmasq"
    local_answer_diff.validate_reference_variant(obj)
    assert digest(obj / "cache.c") == CACHE_SHA
    renamed = local_answer_diff.rename_main(obj, out)
    objects = sorted(p for p in obj.glob("*.o") if p.name not in {"cache.o", "dnsmasq.o"})
    deps = args.reference_build / "deps/lib"
    c = out / "oracle"
    subprocess.run(["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror",
                    f"-I{obj}", f"-I{args.reference_build / 'deps/include'}",
                    str(Path(__file__).with_name("lease_cache_driver.c")), *map(str, objects), str(renamed),
                    f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", str(c)], check=True)
    with (out / "rust-build.log").open("w") as log:
        subprocess.run([args.cargo, "build", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"),
                        "--lib", "--release", "--target-dir", str(out / "target")], stdout=log, stderr=log, check=True)
    rust = out / "rust"
    subprocess.run([str(Path(args.cargo).with_name("rustc")), "--edition=2021", "-O", "-Cpanic=abort", "-Clto",
                    str(Path(__file__).with_name("lease_cache_probe.rs")), "--extern",
                    f"dnsmasq_rs={out / 'target/release/libdnsmasq_rs.rlib'}", "-L",
                    f"dependency={out / 'target/release/deps'}", "-o", str(rust)], check=True)
    return c, rust


def corpus():
    questions = [f"Q lease.test {kind} 100" for kind in [1, 28, 5, 16, 65536]] + ["Q other.test 1 100", "Q target.test 1 100"]
    blockers = [[], [(1, 1, 1, 1)], [(1, 0, 1, 1)], [(28, 1, 1, 1)], [(28, 0, 1, 1)],
                [(5, 0, 1, 1)], [(1, 1, 0, 0)], [(1, 0, 0, 0)], [(1, 0, 1, 0)],
                [(28, 1, 1, 1), (1, 0, 0, 0)], [(1, 0, 0, 0), (1, 0, 0, 0)]]
    for cname_at in [None, 0, 2]:
        records = [("lease.test", 1, 1, 0), ("lease.test", 1, 2, 1),
                   ("lease.test", 28, 3, 0), ("lease.test", 16, 4, 0),
                   ("lease.test", 65536, 5, 1), ("other.test", 1, 6, 0), ("target.test", 1, 7, 0)]
        if cname_at is not None:
            records.insert(cname_at, ("lease.test", 5, 0, 0))
        prefix = ["B"] + [f"I {name} {kind} 90 {value} {negative} 100" for name, kind, value, negative in records]
        if cname_at is not None:
            prefix += [f"L {cname_at} {len(records)-1}"]
        prefix += ["C"]
        for index, blocked in enumerate(blockers):
            lines = prefix + questions + [f"H lease.test {kind} {reverse} {immortal} {local}" for kind, reverse, immortal, local in blocked]
            lines += ["D LEASE.test"] + questions
            yield f"trigger-{cname_at}-blockers-{index}", 16, lines
    # The dynamic target is removed without preserving its generation. Its
    # external CNAME must become invalid, including after slot reuse.
    lines = ["B", "I alias.test 5 90 0 0 100", "I lease.test 1 90 9 0 100", "L 0 1", "C",
             "Q alias.test 5 100", "D lease.test", "Q alias.test 5 100", "Q lease.test 1 100"]
    for i in range(12):
        lines += ["B", f"I reuse{i}.test 1 90 {i} 0 100", "C", "Q alias.test 5 100"]
    yield "cname-target-reuse", 3, lines
    # Expiry uses time zero during publication, including an expired-at-zero
    # entry; it must not apply the caller's current wall clock.
    yield "time-zero", 8, ["B", "I lease.test 1 1 1 0 -1", "I lease.test 28 1 2 0 -1",
                           "I lease.test 16 1 3 0 100", "C", "D lease.test",
                           "Q lease.test 1 0", "Q lease.test 28 0", "Q lease.test 16 100"]


def mismatches(expected, actual):
    if len(expected) != len(actual):
        raise ValueError("result count mismatch")
    return [i for i, (left, right) in enumerate(zip(expected, actual)) if left != right]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default=shutil.which("cargo"))
    args = parser.parse_args(); out = args.output.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists()
    args.reference_build = args.reference_build.resolve(); out.mkdir(parents=True)
    assert not mismatches(["Q 1:7:0:190"], ["Q 1:7:0:190"])
    assert mismatches(["Q 1:7:0:190"], ["Q 1:7:0:191"]) == [0]
    try: mismatches(["Q"], [])
    except ValueError: pass
    else: raise AssertionError("count calibration")
    c, rust = build(args, out)
    report = {"reference_cache_sha256": CACHE_SHA, "c_sha256": digest(c), "rust_sha256": digest(rust),
              "calibration": {"equal": 1, "negative_ttl_and_count": 2, "c_insert_hit_selective_delete": 1}, "cases": [], "failures": [],
              "scope": "actual cache_add_dhcp_entry/cache_find_by_name effects on dynamic entries; synthetic local blockers via actual cache_hash; no reverse cache or full daemon/answer_request equivalence"}
    for no_round in [False, True]:
        for index, (label, capacity, lines) in enumerate(corpus()):
            prefix = out / f"{int(no_round)}-{index:02}"
            conf = prefix.with_suffix(".conf")
            conf.write_text(f"no-hosts\nno-resolv\ncache-size={capacity}\n" + ("no-round-robin\n" if no_round else ""))
            wire = "\n".join(lines) + "\n"; prefix.with_suffix(".input").write_text(wire)
            results = []
            for side, command in [("c", [str(c), "-C", str(conf)]), ("rust", [str(rust), str(capacity), str(int(no_round))])]:
                run = subprocess.run(command, input=wire, text=True, capture_output=True)
                prefix.with_suffix(f".{side}.stdout").write_text(run.stdout)
                prefix.with_suffix(f".{side}.stderr").write_text(run.stderr)
                if run.returncode: raise RuntimeError(f"{label} {side} exited {run.returncode}")
                result = run.stdout.splitlines(); assert len(result) == len(lines), (label, side, "incomplete")
                results.append(result)
            if index == 0:
                before = lines.index("Q lease.test 1 100")
                after = lines.index("D LEASE.test") + 1
                assert results[0][before] == "Q 1:1:0:190 1:2:1:190", "C insert/hit calibration"
                assert results[0][after] == "Q", "C publication must remove A/NODATA"
                assert results[0][after + 1] == "Q 28:3:0:190", "C publication must retain AAAA"
                assert results[0][after + 4] == "Q 65536:5:1:190", "C publication must retain NXDOMAIN"
            failure = mismatches(*results)
            row = {"label": label, "no_round_robin": no_round, "commands": len(lines), "mismatches": failure}
            report["cases"].append(row)
            if failure: report["failures"].append(row)
    report["planned"] = report["compared"] = sum(row["commands"] for row in report["cases"])
    report["mismatches"] = sum(len(row["mismatches"]) for row in report["cases"])
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
