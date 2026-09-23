#!/usr/bin/env python3
"""Run the frozen R134 router checks serially; production remains C.

The plan holds exact argv and input hashes. Existing guarded drivers own
namespace cleanup. No retries, changed candidates, or extra windows are added.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HEALTH = ("passed", "cleanup_verified", "same_boot", "same_config",
          "same_production_identity", "same_host_mounts")


def read(path):
    return json.loads(path.read_text())


def verify(plan):
    for path, expected in plan["input_sha256"].items():
        actual = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"input changed: {path}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("plan", type=Path)
    p.add_argument("--wait-for", type=Path, help="existing collection must finish before using router")
    a = p.parse_args()
    plan = read(a.plan)
    verify(plan)
    for path in plan.get("prerequisites", []):
        result = read(ROOT / path)
        if not all(result.get(k) is True for k in HEALTH) or result.get("candidate_sha256") != plan["candidate_sha256"]:
            raise ValueError(f"prior correctness gate invalid: {path}")
    out = ROOT / plan["output"]
    out.mkdir(parents=True, exist_ok=False)
    (out / "plan.json").write_bytes(a.plan.read_bytes())
    if a.wait_for:
        deadline = time.monotonic() + 3600
        print(f"Waiting for existing collection: {a.wait_for}", flush=True)
        while not (a.wait_for / "COMPLETE").is_file():
            if (a.wait_for / "FAILED").exists() or time.monotonic() > deadline:
                raise RuntimeError("preceding collection did not finish cleanly")
            time.sleep(10)
        if not (a.wait_for / "health-after.json").is_file():
            raise RuntimeError("preceding collection lacks final health check")
    results = []
    for step in plan["steps"]:
        verify(plan)
        print("START", step["name"], flush=True)
        with (out / (step["name"] + ".log")).open("xb") as log:
            code = subprocess.run([sys.executable, *step["argv"]], cwd=ROOT,
                                  stdout=log, stderr=subprocess.STDOUT).returncode
        row = {"name": step["name"], "exit": code}
        if code == 0 and step.get("driver_result"):
            result = read(ROOT / step["driver_result"])
            if not all(result.get(k) is True for k in HEALTH):
                row["exit"] = 1
                row["error"] = "driver health or cleanup gate failed"
        results.append(row)
        (out / "steps.json").write_text(json.dumps(results, indent=2) + "\n")
        if row["exit"]:
            (out / "FAILED").touch()
            raise SystemExit(row["exit"])
        print("PASS", step["name"], flush=True)
        if step.get("completed_group"):
            (ROOT / step["completed_group"] / "COMPLETE").touch()
    (out / "COMPLETE").touch()
    print("R134 router collection COMPLETE", flush=True)


if __name__ == "__main__":
    main()
