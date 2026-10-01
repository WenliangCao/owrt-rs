#!/usr/bin/env python3
"""Directed same/different-C-bucket review of DHCP cache blockers.

The live C oracle chooses and confirms a name for its current ASLR hash seed;
both implementations then receive identical concrete cache operations. Metadata
selection performs no cache mutation and is not a response normalization.
"""
import argparse
import json
from pathlib import Path
import subprocess

import lease_cache_diff


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--reference-build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cargo", required=True)
    args = p.parse_args(); out = args.output.resolve()
    assert out.is_relative_to(lease_cache_diff.ROOT / "private") and not out.exists()
    args.reference_build = args.reference_build.resolve(); out.mkdir(parents=True)
    c, rust = lease_cache_diff.build(args, out)
    rows = []
    for no_round in [False, True]:
        for same in [False, True]:
            base = out / f"{int(no_round)}-{int(same)}"
            config = base.with_suffix(".conf")
            config.write_text("no-hosts\nno-resolv\ncache-size=16\n" + ("no-round-robin\n" if no_round else ""))
            with base.with_suffix(".c.stderr").open("w") as log:
                oracle = subprocess.Popen([str(c), "-C", str(config)], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=log, text=True)
                selection = f"X lease.test {int(same)}\n"
                oracle.stdin.write(selection); oracle.stdin.flush()
                chosen = oracle.stdout.readline().strip(); assert chosen.startswith("X collision")
                other = chosen.split()[1]
                verification = f"V lease.test {other}\n"
                oracle.stdin.write(verification); oracle.stdin.flush()
                verified = oracle.stdout.readline().strip(); assert verified == f"V {int(same)}"
                commands = ["B", "I lease.test 1 90 1 0 100", "I lease.test 1 90 2 0 100", "C",
                            "B", f"I {other} 1 90 9 0 100", "C", "H lease.test 1 0 0 0",
                            "D lease.test", "Q lease.test 1 100", f"Q {other} 1 100"]
                wire = "\n".join(commands) + "\n"
                actual_c, _ = oracle.communicate(wire, timeout=10)
                assert oracle.returncode == 0
            run = subprocess.run([str(rust), "16", str(int(no_round))], input=wire, text=True, capture_output=True)
            assert run.returncode == 0
            expected, actual = actual_c.splitlines(), run.stdout.splitlines()
            assert len(expected) == len(actual) == len(commands)
            base.with_suffix(".c.input").write_text(selection + verification + wire)
            base.with_suffix(".rust.input").write_text(wire)
            base.with_suffix(".c.stdout").write_text(chosen + "\n" + verified + "\n" + actual_c)
            base.with_suffix(".rust.stdout").write_text(run.stdout)
            base.with_suffix(".rust.stderr").write_text(run.stderr)
            rows.append({"no_round_robin": no_round, "same_c_bucket": same, "other_name": other,
                         "commands": len(commands), "mismatches": lease_cache_diff.mismatches(expected, actual),
                         "c_lease_records": expected[-2], "rust_lease_records": actual[-2]})
    report = {"c_sha256": lease_cache_diff.digest(c), "rust_sha256": lease_cache_diff.digest(rust),
              "scope": "directed cache state; synthetic prior DHCP blocker inserted after an existing dynamic group; no normal-publication reachability claim",
              "rows": rows, "failures": [row for row in rows if row["mismatches"]]}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
