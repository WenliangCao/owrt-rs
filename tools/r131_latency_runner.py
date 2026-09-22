#!/usr/bin/env python3
"""Run the frozen R131 latency supplement; production remains stock C."""
import argparse
import subprocess
import sys
from pathlib import Path

from r131_latency_report import ROOT, check, load_plan, verify_window


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=ROOT / "docs/reviews/r131-latency-plan.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = load_plan(args.plan)
    check(not args.output.exists(), f"refusing existing output: {args.output}")
    args.output.mkdir(parents=True, mode=0o700)
    (args.output / "plan.json").write_bytes(args.plan.read_bytes())
    files = plan["files"]
    for run in plan["runs"]:
        name = f'{run["index"]:02d}-{run["label"]}'
        command = [sys.executable, str(ROOT / files["driver"]["path"]), "ubusd",
                   str(ROOT / plan["subjects"][run["label"]]["path"]), str(args.output / name),
                   "--pilot", "--iterations", "5000", "--implementation", "c" if run["label"] == "c" else "rs"]
        for flag, key in (("--recovery-gate", "recovery_gate"), ("--guard", "guard"),
                          ("--benchmark", "benchmark"), ("--event-benchmark", "event_benchmark"),
                          ("--workload-script", "workload")):
            command += [flag, str(ROOT / files[key]["path"])]
        print(f"START {name}", flush=True)
        with (args.output / f"{name}.log").open("xb") as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        verify_window(args.output, plan, run)
        print(f"VERIFIED {name}", flush=True)
    (args.output / "COMPLETE").touch()
    subprocess.run([sys.executable, str(ROOT / "tools/r131_latency_report.py"), str(args.plan),
                    str(args.output), str(args.output / "report.json")], cwd=ROOT, check=True)
    print("COMPLETE 18 windows; report.json includes every frozen gate", flush=True)


if __name__ == "__main__":
    main()
