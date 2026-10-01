#!/usr/bin/env python3
"""Ordered cache-counter snapshots against full exact C objects, no sockets.

The C cache translation unit is unchanged and supplies the expected snapshots.
Each C scenario runs three times before Rust to detect unstable reference order.
The Rust fixture also compares counted versus the preserved ordinary API.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
CACHE_SHA = "51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def scenarios():
    yield "calibration", 1, 0, ["B", "I a.test 1 60 7 0 100", "C", "Q a.test 1 100", "B", "I b.test 1 60 8 0 100", "C", "S"]
    yield "pending-abort", 4, 0, ["B", "I a.test 1 60 1 0 100", "I b.test 28 60 2 0 100", "B", "C", "Q a.test 1 100", "S"]
    yield "failed-transaction", 4, 0, ["B", "I a.test 1 60 1 0 100", "I b.test 1 0 2 0 100", "C", "B", "C", "Q a.test 1 100", "S"]
    yield "replace-no-pressure", 4, 0, ["B", "I a.test 1 60 1 0 100", "C", "B", "I a.test 1 60 2 0 101", "C", "Q a.test 1 101", "S"]
    yield "rrset-spill-once", 2, 0, ["B", "I a.test 1 60 1 0 100", "I a.test 1 60 2 0 100", "C", "B", "I b.test 1 60 3 0 101", "C", "Q a.test 1 101", "Q b.test 1 101"]
    long_name = "a" * 60 + "." + "b" * 16
    yield "spill-before-long-name-failure", 1, 0, ["B", "I a.test 1 60 1 0 100", "C", "B", f"I {long_name} 1 60 2 0 101", "C", "Q a.test 1 101", "B", "C", "S"]
    yield "commit-drops-dangling-cname", 8, 0, ["B", "I dangling.test 5 60 0 0 100", "I ordinary.test 1 60 3 0 100", "C", "Q dangling.test 5 100", "Q ordinary.test 1 100"]
    yield "valid-cname-chain", 8, 0, ["B", "I alias.test 5 60 0 0 100", "I target.test 1 60 9 0 100", "L 0 1", "C", "Q alias.test 5 100", "Q target.test 1 100", "S"]
    yield "u32-wrap", 1, 0, ["B", "I a.test 1 60 1 0 100", "C", "T 4294967295 4294967295", "B", "I b.test 1 60 2 0 101", "C", "S"]
    yield "negative-records", 4, 0, ["B", "I nx.test 65536 60 0 1 100", "I nodata.test 1 60 0 1 100", "I txt.test 16 60 4 0 100", "C", "Q nx.test 65536 100", "Q nodata.test 1 100", "S"]
    for stale in [0, 5, -1]:
        for now in [109, 110, 111, 115]:
            yield f"pressure-expiry-{stale}-{now}", 1, stale, ["B", "I a.test 1 10 1 0 100", "C", "B", f"I b.test 1 10 2 0 {now}", "C", f"Q a.test 1 {now}", f"Q b.test 1 {now}", "S"]
        yield f"lookup-expiry-{stale}", 4, stale, ["B", "I a.test 1 10 1 0 100", "C", "Q a.test 1 110", "Q a.test 1 115", "B", "I b.test 1 10 2 0 116", "C", "S"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    out = args.output.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    objects = args.reference_build / "dnsmasq"
    local_answer_diff.validate_reference_variant(objects)
    assert digest(objects / "cache.c") == CACHE_SHA
    renamed = local_answer_diff.rename_main(objects, out)
    deps = args.reference_build / "deps/lib"
    oracle = out / "oracle"
    command = ["cc", *local_answer_diff.REFERENCE_COPTS, "-O2", "-Wall", "-Wextra", "-Werror", f"-I{objects}",
               f"-I{args.reference_build / 'deps/include'}", str(Path(__file__).with_name("cache_metrics_driver.c")),
               *map(str, sorted(p for p in objects.glob("*.o") if p.name not in {"cache.o", "dnsmasq.o", "dnsmasq-renamed.o"})),
               str(renamed), f"-L{deps}", f"-Wl,-rpath,{deps}", "-lubus", "-lubox", "-o", str(oracle)]
    with (out / "build.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=log, check=True)
        subprocess.run([args.cargo, "+1.98.1", "build", "--manifest-path", str(ROOT / "components/dnsmasq/Cargo.toml"),
                        "--lib", "--target-dir", str(out / "target")], stdout=log, stderr=log, check=True)
        probe = out / "probe"
        subprocess.run([str(Path(args.cargo).with_name("rustc")), "+1.98.1", "--edition=2021", str(Path(__file__).with_name("cache_metrics_probe.rs")),
                        "--extern", f"dnsmasq_rs={out / 'target/debug/libdnsmasq_rs.rlib'}", "-L", f"dependency={out / 'target/debug/deps'}",
                        "-o", str(probe)], stdout=log, stderr=log, check=True)
    sizes = list(map(int, subprocess.check_output([str(probe), "--sizes"], text=True).split()))
    report = {"scope": "cache primitive real event counters and ordered snapshots; product owner integration pending",
              "source_cache_sha256": CACHE_SHA, "oracle_sha256": digest(oracle), "probe_sha256": digest(probe),
              "rust_cache_bytes": sizes[0], "caller_counters_bytes": sizes[1], "cases": [], "failures": []}
    for label, capacity, stale, lines in scenarios():
        folder = out / label
        folder.mkdir()
        config = folder / "config"
        config.write_text(f"no-hosts\nno-resolv\ncache-size={capacity}\n" + ("use-stale-cache=0\n" if stale == -1 else f"use-stale-cache={stale}\n" if stale else ""))
        data = "\n".join(lines) + "\n"
        (folder / "input").write_text(data)
        observed = []
        for side, command in [(f"c-{i}", [str(oracle), "-C", str(config)]) for i in range(3)] + [("rust", [str(probe), str(capacity), str(stale)])]:
            run = subprocess.run(command, input=data, text=True, capture_output=True)
            (folder / f"{side}.stdout").write_text(run.stdout)
            (folder / f"{side}.stderr").write_text(run.stderr)
            assert run.returncode == 0, (label, side, run.returncode)
            value = run.stdout.splitlines()
            assert len(value) == len(lines), (label, side, "snapshot count")
            observed.append(value)
        assert observed[0] == observed[1] == observed[2], (label, "C/C instability")
        if label == "calibration":
            wanted = ["B | 0 0", "I 1 | 0 0", "C 1 | 1 0", "Q 7:160 | 1 0", "B | 1 0", "I 1 | 1 1", "C 1 | 2 1", "S | 0 0"]
            assert observed[0] == wanted, "C behavior calibration"
            if args.inject_error:
                observed[0][2] = "C 1 | 2 0"
        failures = [{"line": index, "input": lines[index], "c": c, "rust": rust}
                    for index, (c, rust) in enumerate(zip(observed[0], observed[-1])) if c != rust]
        row = {"case": label, "snapshots": len(lines), "failures": failures}
        report["cases"].append(row)
        if failures:
            report["failures"].append(row)
    report["planned"] = report["compared"] = sum(row["snapshots"] for row in report["cases"])
    report["failed"] = sum(len(row["failures"]) for row in report["cases"])
    report["passed"] = report["compared"] - report["failed"]
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["scope", "compared", "passed", "failed", "rust_cache_bytes", "caller_counters_bytes"]}))
    return bool(report["failed"])


if __name__ == "__main__":
    raise SystemExit(main())
