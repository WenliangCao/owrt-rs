#!/usr/bin/env python3
"""Explicit one-shot CI ELF smoke, then frozen training; no build commands."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys


SMOKE_PLAN_SHA256 = "1091bf90aa46bc19c0e8b6a93da2f76a4fb2beaac985b166c0744041fd1dad9c"


def run(request_path):
    request = json.loads(request_path.read_text())
    runner = Path(request["runner"]["path"])
    assert hashlib.sha256(runner.read_bytes()).hexdigest() == request["runner"]["sha256"]
    spec = importlib.util.spec_from_file_location("pgo_training_only", runner)
    training = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(training)
    assert __debug__ and sys.platform == "linux" and os.uname().machine == "aarch64"
    assert os.uname().nodename.startswith("instance-") and request["schema"] == 1
    base = Path(request["attempt"])
    training.empty_directory(base, fresh=True)
    shutil.copy2(request_path, base / "request.json")
    state = {"status": "preflight", "request_sha256": training.sha(request_path),
             "controller_sha256": training.sha(__file__), "commands": [], "release_qualified": False}
    state_path = base / "state.json"
    training.save(state_path, state)
    try:
        training_attempt = Path(request["training_attempt"])
        training_runtime = Path(request["runtime_directory"])
        assert training_attempt.is_absolute() and not training_attempt.exists() and not training_attempt.is_symlink()
        assert training_runtime.parent == Path("/tmp") and training_runtime.name.startswith("dnsmasq-")
        assert not training_runtime.exists() and not training_runtime.is_symlink()
        reference_path = training.checked_file(request["reference_plan"])
        assert training.sha(reference_path) == training.REFERENCE_PLAN_SHA256
        reference = json.loads(reference_path.read_text())
        smoke_reference_path = training.checked_file(request["smoke_reference_plan"])
        assert training.sha(smoke_reference_path) == SMOKE_PLAN_SHA256
        smoke_reference = json.loads(smoke_reference_path.read_text())
        ci_path = training.checked_file(request["ci_build"])
        original_elf = training.checked_file(request["generate_elf"])
        baseline = json.loads(training.checked_file(reference["baseline_receipt"]).read_text())
        default = training.validate_ci(json.loads(ci_path.read_text()), reference, baseline, original_elf)
        training.empty_directory(default)
        profdata = training.checked_file(reference["profdata"])
        isolator = training.checked_file(smoke_reference["isolator"])
        runtime = base / "smoke-runtime"
        inputs = base / "inputs"
        inputs.mkdir()
        original = reference_path.parent / "pgo_sdk_smoke.py"
        assert training.sha(original) == reference["input_sha256"][original.name]
        shutil.copy2(original, inputs / original.name)
        smoke_spec = importlib.util.spec_from_file_location("original_pgo_sdk_smoke", inputs / original.name)
        smoke_tool = importlib.util.module_from_spec(smoke_spec)
        smoke_spec.loader.exec_module(smoke_tool)
        adapter = base / "generate-adapter"
        adapter.mkdir()
        elf = adapter / "dnsmasq-rs"
        shutil.copy2(original_elf, elf)
        elf.chmod(0o755)
        elf_item = {"path": str(elf), "sha256": training.sha(elf), "bytes": elf.stat().st_size}
        assert elf_item["sha256"] == request["generate_elf"]["sha256"]
        training.save(adapter / "build.json", {
            "status": "runtime-adapter-only-not-build", "release_qualified": False,
            "ci_build": request["ci_build"], "original_elf": request["generate_elf"],
            "artifacts": [{"path": elf.name, "sha256": elf_item["sha256"], "bytes": elf_item["bytes"]}]})
        smoke = {"outputs": {"generate": str(adapter)}, "default_profile_directory": str(default),
                 "runtime": dict(smoke_reference["runtime"])}
        smoke["runtime"].update(directory=str(runtime), llvm_profile_file=str(runtime / "%p.profraw"),
                                 daemon_argv=[str(elf), "-k", "-C", str(runtime / "config")])
        smoke_plan = inputs / "smoke-plan.json"
        training.save(smoke_plan, smoke)
        state.update(ci_build=request["ci_build"], generate_elf=elf_item, adapter_sha256=training.sha(adapter / "build.json"),
                     smoke_plan_sha256=training.sha(smoke_plan), status="smoke")
        os.sched_setaffinity(0, {reference["cpu"]})

        def command(label, argv, timeout):
            row = {"label": label, "argv": list(map(str, argv))}
            process = None
            try:
                with (base / (label + ".stdout")).open("xb") as stdout, (base / (label + ".stderr")).open("xb") as stderr:
                    process = subprocess.Popen(row["argv"], stdin=subprocess.DEVNULL, stdout=stdout,
                                               stderr=stderr, start_new_session=True)
                    state["active"] = {"label": label, "pid": process.pid}
                    training.save(state_path, state)
                    row["returncode"] = process.wait(timeout=timeout)
                    assert row["returncode"] == 0, label
            finally:
                try:
                    if process is not None:
                        row["cleanup"] = smoke_tool.stop_group(process)
                finally:
                    state["commands"].append(row)
                    if process is None or not smoke_tool.group_exists(process.pid):
                        state["active"] = None
                    training.save(state_path, state)
            return (base / (label + ".stdout")).read_text()

        command("isolated-smoke", ["sudo", "-n", "sh", isolator, "python3", "-B", inputs / original.name,
                smoke_plan, "--runtime", "--parent-netns", os.readlink("/proc/self/ns/net"),
                "--parent-mntns", os.readlink("/proc/self/ns/mnt")], 60)
        smoke_receipt = runtime / "runtime.json"
        result = json.loads(smoke_receipt.read_text())
        raw = training.validate_smoke(result, elf_item["sha256"])
        smoke_merged = base / "excluded-smoke.profdata"
        command("smoke-profile-merge", [profdata, "merge", "-o", smoke_merged, raw], 60)
        shown = command("smoke-profile-show", [profdata, "show", "--all-functions", "--counts", smoke_merged], 60)
        for key in ("Total functions", "Maximum function count"):
            match = re.search(r"^\s*" + key + r":\s*(\d+)\s*$", shown, re.M)
            assert match and int(match[1]) > 0, key
        for label in ("smoke-profile-merge", "smoke-profile-show"):
            assert not (base / (label + ".stderr")).read_text().strip(), label
        for item in (request["ci_build"], request["generate_elf"], request["runner"], elf_item,
                     reference["profdata"], smoke_reference["isolator"]):
            training.checked_file(item)
        assert training.sha(inputs / original.name) == reference["input_sha256"][original.name]
        training_request = {"schema": 1, "attempt": request["training_attempt"],
                            "runtime_directory": request["runtime_directory"], "reference_plan": request["reference_plan"],
                            "ci_build": request["ci_build"], "generate_elf": elf_item,
                            "smoke_runtime": {"path": str(smoke_receipt), "sha256": training.sha(smoke_receipt)}}
        training_request_path = base / "training-request.json"
        training.save(training_request_path, training_request)
        state.update(status="training", excluded_smoke_profile=result["profile"],
                     training_request_sha256=training.sha(training_request_path))
        command("training-only", [sys.executable, "-B", runner, training_request_path], 1800)
        trained = Path(request["training_attempt"]) / "training-profile.json"
        receipt = json.loads(trained.read_text())
        assert receipt["status"] == "training-complete-unqualified" and receipt["profile_count"] == 50
        assert receipt["scene_count"] == 11 and receipt["generate_elf"] == elf_item
        state.update(status="smoke-and-training-complete-unqualified", training_receipt_sha256=training.sha(trained),
                     merged_profile=receipt["merged_profile"], scene_count=11, profile_count=50)
    except BaseException as error:
        state.update(status="failed", error=repr(error))
        raise
    finally:
        training.save(state_path, state)


def interrupted(signum, _frame):
    raise InterruptedError(f"interrupted by signal {signum}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("--execute", action="store_true", help="run once on Oracle after the artifact/request is frozen")
    args = parser.parse_args()
    if not args.execute:
        parser.error("--execute is required; no commands were run")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    run(args.request.resolve())
