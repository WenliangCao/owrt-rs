#!/usr/bin/env python3
"""Run only within a root-issued quiet reservation. No product/device claims."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--private", type=Path, required=True)
parser.add_argument("--cpu", type=int, required=True)
parser.add_argument("--reservation", required=True)
parser.add_argument("--operations", type=int, default=500000)
parser.add_argument("--variants", nargs="+", default=["baseline", "dns1", "dns2"])
parser.add_argument("--scenes", nargs="+", default=["hit", "hit-upper", "hit-leases", "miss", "miss-leases", "host", "rrset"])
parser.add_argument("--probe-suffix", default="-probe")
parser.add_argument("--output", default="timing-dns1-dns2.json")
args = parser.parse_args()
out = args.private / args.output
assert not out.exists(), "fresh evidence required"
variants = args.variants
scenes = args.scenes
report = {
    "reservation": args.reservation,
    "cpu": args.cpu,
    "scope": "Native diagnostic whole-process CPU/wall including fixture setup and priming; not device timing. Uninstrumented System allocator; no perf process in timed windows.",
    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "artifacts": {v: hashlib.sha256((args.private / (v + args.probe_suffix)).read_bytes()).hexdigest() for v in variants},
    "rows": [],
}
for scene in scenes:
    for round_index in range(1, 6):
        order = variants if round_index % 2 else list(reversed(variants))
        for variant in order:
            command = ["taskset", "-c", str(args.cpu), str(args.private / (variant + args.probe_suffix)), scene, str(args.operations)]
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            start = time.monotonic_ns()
            result = subprocess.run(command, capture_output=True, check=True, text=True)
            elapsed = time.monotonic_ns() - start
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            row = json.loads(result.stdout)
            row.update(variant=variant, round=round_index, wall_ns=elapsed,
                       user_ns=round((after.ru_utime-before.ru_utime)*1e9),
                       system_ns=round((after.ru_stime-before.ru_stime)*1e9))
            row["cpu_ns"] = row["user_ns"] + row["system_ns"]
            assert row["operations"] == args.operations
            report["rows"].append(row)
            out.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"output": str(out), "rows": len(report["rows"])}))
