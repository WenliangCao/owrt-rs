#!/usr/bin/env python3
"""Run the frozen R131 event-fanout series on a disposable router namespace.

The physical router stays in the stock C configuration.  Each window invokes
the existing recovery-gated device driver, which copies one candidate into a
private namespace, runs the exact-image event workload, archives raw evidence,
and removes only its UUID-owned processes and files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "docs/reviews/r131-ubusd-event-plan.json"
DEFAULT_OUTPUT = ROOT / "private/r131-event-batch/router-01"
SOCKET_CMDLINE = b"/sbin/ubusd\0-s\0/var/run/ubus/ubus.sock\0"
HEALTH_KEYS = (
    "passed",
    "cleanup_verified",
    "same_boot",
    "same_config",
    "same_production_identity",
    "same_host_mounts",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def hash_rows(path: Path) -> dict[str, str]:
    rows = {}
    for line in path.read_text().splitlines():
        digest_value, name = line.split(maxsplit=1)
        check(len(digest_value) == 64 and name not in rows,
              f"{path}: invalid or duplicate hash row")
        rows[name] = digest_value
    return rows


def load_plan(path: Path) -> dict:
    plan = json.loads(path.read_text())
    check(plan.get("schema_version") == 1, "unsupported R131 plan schema")
    check(plan.get("component") == "ubusd", "R131 plan is not for ubusd")
    check(plan.get("iterations") == 5000 and plan.get("warmup") == 20,
          "R131 counts must remain 5000/20")
    check(plan.get("boot_id"), "R131 plan must pin the recovery-gate boot")
    subjects = plan.get("subjects")
    check(set(subjects or {}) == {"c", "r124", "r131"}, "R131 subjects differ")
    for label, subject in subjects.items():
        check((ROOT / subject["path"]).is_file(), f"missing {label} candidate: {subject['path']}")
        check(digest(ROOT / subject["path"]) == subject["sha256"],
              f"{label} candidate hash differs from plan")
    files = plan["files"]
    for name, value in files.items():
        path = ROOT / value["path"]
        check(path.is_file(), f"missing R131 input {name}: {value['path']}")
        check(digest(path) == value["sha256"], f"R131 input hash differs: {name}")
    check(len(plan["runs"]) == 18, "R131 requires 18 windows")
    expected = [label for permutation in plan["permutations"] for label in permutation]
    actual = [run["label"] for run in plan["runs"]]
    check(actual == expected, "R131 schedule differs from six frozen permutations")
    for index, run in enumerate(plan["runs"], 1):
        check(run == {"index": index, "label": expected[index - 1]},
              f"R131 run {index} differs from frozen schedule")
    orchestrator_sha = plan.get("orchestrator_sha256")
    if orchestrator_sha:
        check(digest(ROOT / "tools/r131_router_runner.py") == orchestrator_sha,
              "R131 orchestrator differs from frozen plan")
    return plan


def verify_window(window: Path, plan: dict, run: dict) -> None:
    label = run["label"]
    result_path = window / "result.json"
    check(result_path.is_file(), f"{window.name}: missing result.json")
    result = json.loads(result_path.read_text())
    check(all(result.get(key) is True for key in HEALTH_KEYS),
          f"{window.name}: health or cleanup gate failed")
    check(result.get("exit") == 0 and result.get("component") == "ubusd",
          f"{window.name}: driver result is not a successful ubusd pilot")
    check(result.get("pilot_only") is True and result.get("matrix") is False,
          f"{window.name}: collection mode changed")
    expected_impl = "c" if label == "c" else "rs"
    check(result.get("implementation") == expected_impl,
          f"{window.name}: implementation mode differs")
    check(result.get("candidate_sha256") == plan["subjects"][label]["sha256"],
          f"{window.name}: candidate identity differs")
    files = plan["files"]
    for key in ("driver", "workload", "guard", "recovery_gate"):
        check(result.get(f"{key}_sha256") == files[key]["sha256"],
              f"{window.name}: {key} identity differs")
    check(result.get("benchmark_sha256") == files["benchmark"]["sha256"],
          f"{window.name}: benchmark identity differs")
    for phase in ("before", "after"):
        health = json.loads((window / f"health-{phase}.json").read_text())
        check(health.get("boot_id") == plan["boot_id"],
              f"{window.name}: {phase} boot differs from recovery gate")
        check((window / f"raw/daemon-{phase}.cmdline").read_bytes() == SOCKET_CMDLINE,
              f"{window.name}: {phase} daemon argv differs")
    executable = "/sbin/ubusd" if label == "c" else "/tmp/bin/ubusd-rs"
    expected_binary = {executable: plan["subjects"][label]["sha256"]}
    for filename in ("binary-sha256.txt", "binary-after-sha256.txt"):
        check(hash_rows(window / f"raw/{filename}") == expected_binary,
              f"{window.name}: executable hash differs")
    expected_tools = {
        "/tmp/bin/owrt-benchmark": plan["files"]["benchmark"]["sha256"],
        "/tmp/bin/ns-exec": plan["files"]["namespace_helper"]["sha256"],
    }
    for filename in ("benchmark-sha256.txt", "benchmark-after-sha256.txt"):
        check(hash_rows(window / f"raw/{filename}") == expected_tools,
              f"{window.name}: benchmark/helper hash differs")
    check(hash_rows(window / "raw/harness-sha256.txt") == {
        "/tmp/workload.sh": plan["files"]["workload"]["sha256"]
    }, f"{window.name}: workload hash differs")
    meta = json.loads((window / "raw/meta.json").read_text())
    check(meta == {
        "subject_pid": meta["subject_pid"],
        "subject_cpu": 1,
        "client_cpu": 0,
        "implementation": expected_impl,
        "iterations": plan["iterations"],
        "warmup": plan["warmup"],
        "scenarios": ["user_1_1", "user_8_1", "user_1_0"],
        "exact_image_caller": True,
        "daemon_argv0": "/sbin/ubusd",
    }, f"{window.name}: workload metadata differs")
    summary = json.loads((window / "raw/summary.json").read_text())
    check(summary == {
        "daemon_pid": summary["daemon_pid"],
        "iterations": plan["iterations"],
        "warmup": plan["warmup"],
        "scenarios": 3,
        "serial_client": True,
        "event_payload_validated": True,
    }, f"{window.name}: workload summary differs")
    check((window / "raw/COMPLETE").is_file(), f"{window.name}: raw workload incomplete")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    plan = load_plan(args.plan)
    check(not args.output.exists(), f"refusing to overwrite existing output: {args.output}")
    args.output.mkdir(parents=True, mode=0o700)
    (args.output / "plan.json").write_bytes(args.plan.read_bytes())
    files = plan["files"]
    paths = {label: ROOT / subject["path"] for label, subject in plan["subjects"].items()}
    driver = ROOT / files["driver"]["path"]
    workload = ROOT / files["workload"]["path"]
    benchmark = ROOT / files["benchmark"]["path"]
    guard = ROOT / files["guard"]["path"]
    recovery_gate = ROOT / files["recovery_gate"]["path"]
    for run in plan["runs"]:
        name = f"{run['index']:02d}-{run['label']}"
        window = args.output / name
        command = [
            sys.executable,
            str(driver),
            "ubusd",
            str(paths[run["label"]]),
            str(window),
            "--pilot",
            "--iterations",
            str(plan["iterations"]),
            "--implementation",
            "c" if run["label"] == "c" else "rs",
            "--recovery-gate",
            str(recovery_gate),
            "--guard",
            str(guard),
            "--benchmark",
            str(benchmark),
            "--workload-script",
            str(workload),
        ]
        print(f"START {name}", flush=True)
        with (args.output / f"{name}.log").open("xb") as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        verify_window(window, plan, run)
        print(f"VERIFIED {name}", flush=True)
    (args.output / "COMPLETE").touch()
    print("COMPLETE 18 windows; analysis remains separate", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
