#!/usr/bin/env python3
"""Run the frozen a97 training pass on a canonical CI instrumented ELF.

Request JSON (schema 1): attempt and runtime_directory are fresh absolute paths;
reference_plan, ci_build, generate_elf and smoke_runtime each contain path/sha256.
reference_plan is the original Oracle train-stage/inputs/plan.json. ci_build is
the CI manifest.json. smoke_runtime is the completed, excluded runtime.json from
the original pgo_sdk_smoke.runtime, bound to this instrumented ELF. The existing
training C helper is reused only after source/compiler/ELF verification.

This program invokes the original collect function through its unchanged CLI.
It neither builds Rust nor consumes a profile. Every attempt is kept; rerunning
requires a new attempt/runtime directory. The output profile remains unqualified.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys


REFERENCE_PLAN_SHA256 = "dcb13b5d341a946e86704772ce1802687564ee2fbee58e3030d832f7abc17b66"
HELPER_SHA256 = "bdf39f4d42d601f0141360f4bdd2ab8b11ba540cb4ceed47ab4f319a5b7d1d6a"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def checked_file(item):
    path = Path(item["path"])
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "expected regular absolute input")
    require(sha(path) == item["sha256"], "input identity differs: " + str(path))
    if "bytes" in item:
        require(path.stat().st_size == item["bytes"], "input size differs: " + str(path))
    return path


def empty_directory(path, *, fresh=False):
    require(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
            "output path must be absolute without symlinks")
    if fresh:
        require(not path.exists(), "attempt already exists; preserve it and use a new path")
    path.mkdir(exist_ok=not fresh)
    require(not any(path.iterdir()), "profile directory is not empty")


def validate_ci(built, reference, baseline, elf):
    require(built["status"] == "built-instrumented-training-only"
            and built["artifact_purpose"] == "instrumented-training-only"
            and built["release_qualified"] is False and built["pgo_stage"] == "generate",
            "CI artifact is not an unqualified instrumented training build")
    for key in ("source_commit", "source_digest", "source_date_epoch"):
        require(built[key] == reference[key], "CI source identity differs: " + key)
    require(built["source_files"] == baseline["source_files"]
            and len(built["source_files"]) == reference["source_file_count"] == 193,
            "CI source input set differs")
    require(built["sdk"]["archive_sha256"] == baseline["sdk"]["archive_sha256"], "CI SDK archive differs")
    require(built["elf"]["sha256"] == sha(elf) and built["elf"]["size"] == elf.stat().st_size,
            "CI ELF identity differs")
    header = elf.read_bytes()[:20]
    require(header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\xb7\x00", "expected AArch64 ELF")
    rustc = built["toolchain"]["rustc"]
    require("release: 1.98.1\n" in rustc + "\n" and "host: x86_64-unknown-linux-gnu\n" in rustc + "\n"
            and "LLVM version: 22.1.8" in rustc, "CI compiler must be canonical x86 Rust 1.98.1/LLVM 22.1.8")
    require(built["compiler_warnings"]["strict_compiler_warnings_zero"], "CI compiler warnings remain")
    pgo, invocation = built["pgo"], built["pgo"]["invocation"]
    default = Path(pgo["profile_output_dir"])
    require(default.is_absolute() and default.parent == Path("/tmp")
            and default.name.startswith("dnsmasq-") and pgo["mode"] == invocation["mode"] == "generate",
            "unexpected default profile directory or PGO mode")
    added = "-Cprofile-generate=" + str(default)
    require(invocation["added_rustflags"] == added
            and invocation["effective_rustflags"] == invocation["recipe_rustflags"] + " " + added
            and "profile-use" not in invocation["effective_rustflags"]
            and invocation["static_pie_linker_sha256"] == reference["static_pie_linker_sha256"],
            "CI instrumentation flags or static PIE linker differ")
    return default


def validate_smoke(smoke, elf_sha256):
    require(smoke["status"] == "complete" and smoke["live_elf_sha256"] == elf_sha256
            and smoke["exit_status"] == 0 and smoke["forced_cleanup"] is False
            and len(smoke["queries"]) == 2, "excluded smoke did not complete for this ELF")
    for key in ("relro_read_only", "no_writable_executable_mapping", "stack_nx"):
        require(smoke["protections"][key] is True, "smoke protection failed: " + key)
    raw = checked_file(smoke["profile"])
    require(raw.stat().st_size > 0, "excluded smoke profile is empty")
    return raw


def load_original(inputs, hashes):
    for name, digest in hashes.items():
        require(Path(name).name == name and sha(inputs / name) == digest, "frozen input differs: " + name)
    sys.path.insert(0, str(inputs))
    sys.dont_write_bytecode = True
    original = importlib.import_module("pgo_train")
    for name in ("pgo_train", "pgo_sdk_smoke", "perf_opt_device_run", "perf_opt_oracle_run"):
        require(Path(sys.modules[name].__file__).resolve() == inputs / (name + ".py"), "wrong imported tool: " + name)
    return original


def prepare(request, base):
    require(request["schema"] == 1, "unknown request schema")
    reference_path = checked_file(request["reference_plan"])
    require(sha(reference_path) == REFERENCE_PLAN_SHA256, "original training plan is not frozen a97 plan")
    reference = json.loads(reference_path.read_text())
    baseline = json.loads(checked_file(reference["baseline_receipt"]).read_text())
    ci_path = checked_file(request["ci_build"])
    elf = checked_file(request["generate_elf"])
    require(os.access(elf, os.X_OK), "instrumented ELF must be executable after artifact extraction")
    built = json.loads(ci_path.read_text())
    default = validate_ci(built, reference, baseline, elf)
    smoke_path = checked_file(request["smoke_runtime"])
    smoke = json.loads(smoke_path.read_text())
    validate_smoke(smoke, sha(elf))
    runtime = Path(request["runtime_directory"])
    require(runtime.is_absolute() and runtime.parent == Path("/tmp") and runtime.name.startswith("dnsmasq-")
            and not runtime.exists() and not runtime.is_symlink(), "runtime directory must be fresh")
    require(reference["training_seed"] == 539365398 and reference["evaluation_seed"] == 2699265
            and reference["expected_profile_count"] == 50, "frozen training parameters differ")
    inputs = base / "inputs"
    inputs.mkdir()
    for name, digest in reference["input_sha256"].items():
        source = checked_file({"path": str(reference_path.parent / name), "sha256": digest})
        shutil.copy2(source, inputs / name)
    original = load_original(inputs, reference["input_sha256"])
    require(reference["scenes"] == [list(scene) for scene in original.SCENES], "original scenes differ")
    for item in reference["workload_tools"].values():
        checked_file(item)
    checked_file(reference["profdata"])
    helper_base = Path(reference["attempt"])
    helper = helper_base / "device_perf_lifecycle"
    helper_build = json.loads((helper_base / "helper-build.json").read_text())
    source = original.lifecycle_source((inputs / "device_perf_lifecycle.c").read_text(),
                                       (inputs / "pgo_lifecycle_exit.c").read_text())
    require(helper_build["source_sha256"] == reference["training_lifecycle_source_sha256"]
            == hashlib.sha256(source.encode()).hexdigest(), "reused helper source differs")
    require(helper_build["compiler_sha256"] == sha(reference["sdk_cc"])
            and helper_build["elf_sha256"] == sha(helper) == HELPER_SHA256
            and helper_build["argv"] == reference["helper_build_argv"], "reused helper compiler/ELF differs")
    shutil.copy2(helper, base / "device_perf_lifecycle")
    shutil.copy2(helper_base / "helper-build.json", base / "helper-build.json")
    for name, path in (("reference-plan.json", reference_path), ("ci-build.json", ci_path),
                       ("smoke-runtime.json", smoke_path)):
        shutil.copy2(path, base / name)
    keys = ("source_commit", "source_digest", "source_file_count", "source_date_epoch", "training_seed", "evaluation_seed",
            "cpu", "scenes", "workload_tools", "input_sha256", "profdata", "expected_profile_count")
    plan = {key: reference[key] for key in keys}
    plan.update(attempt=str(base), training_directory=str(base / "training"), runtime_directory=str(runtime),
                generate_elf=request["generate_elf"], generate_default_profile_directory=str(default),
                merged_profile=str(base / "training.profdata"), smoke_profile=smoke["profile"],
                ci_build=request["ci_build"], smoke_runtime=request["smoke_runtime"],
                helper_reused=True, product_training_reused=False, release_qualified=False)
    case = original.training_case((inputs / "perf_opt_device_case.sh").read_text(),
                                  Path(plan["training_directory"]), runtime, plan["training_seed"])
    plan["training_case_sha256"] = hashlib.sha256(case.encode()).hexdigest()
    save(inputs / "plan.json", plan)
    empty_directory(default)
    return plan, original


def training_profiles(plan, collection):
    require(collection["status"] == "complete" and len(collection["scenes"]) == 11
            and [row["scene"] for row in collection["scenes"]] == plan["scenes"]
            and all(row["valid"] and not row["errors"] for row in collection["scenes"]), "training collection failed")
    profiles = [p for row in collection["scenes"] for p in row["profiles"]]
    require(len(profiles) == len({p["path"] for p in profiles}) == 50, "training must produce 50 unique profiles")
    root = Path(plan["training_directory"]) / "profiles"
    for item in profiles:
        path = checked_file(item)
        require(path.is_relative_to(root) and path.stat().st_size > 0
                and path.resolve() != Path(plan["smoke_profile"]["path"]).resolve(), "foreign or smoke profile in training")
    require({str(p) for p in root.rglob("*.profraw")} == {p["path"] for p in profiles}, "unaccounted raw profiles")
    return profiles


def execute(request_path):
    require(__debug__, "original collector requires Python assertions enabled")
    require(sys.platform == "linux" and os.uname().machine == "aarch64"
            and os.uname().nodename.startswith("instance-"), "training is Oracle-only")
    request = json.loads(request_path.read_text())
    base = Path(request["attempt"])
    empty_directory(base, fresh=True)
    shutil.copy2(request_path, base / "request.json")
    state = {"status": "preflight", "commands": [], "request_sha256": sha(request_path),
             "runner_sha256": sha(__file__), "release_qualified": False}
    state_path = base / "state.json"
    save(state_path, state)
    try:
        plan, original = prepare(request, base)
        os.sched_setaffinity(0, {plan["cpu"]})

        def run(label, argv, timeout=120):
            row = {"label": label, "argv": list(map(str, argv))}
            process = None
            try:
                with (base / (label + ".stdout")).open("xb") as stdout, (base / (label + ".stderr")).open("xb") as stderr:
                    process = subprocess.Popen(row["argv"], stdin=subprocess.DEVNULL, stdout=stdout,
                                               stderr=stderr, start_new_session=True)
                    state["active"] = {"label": label, "pid": process.pid}
                    save(state_path, state)
                    row["returncode"] = process.wait(timeout=timeout)
                    require(row["returncode"] == 0, label + " failed")
            finally:
                try:
                    if process is not None:
                        row["cleanup"] = original.stop_group(process)
                finally:
                    state["commands"].append(row)
                    if process is None or not original.group_exists(process.pid):
                        state["active"] = None
                    save(state_path, state)
            return (base / (label + ".stdout")).read_text()

        version = run("profdata-version", [plan["profdata"]["path"], "--version"])
        require("22.1.8-rust-1.98.1-stable" in version, "Oracle llvm-profdata version differs")
        state["status"] = "training"
        inputs = base / "inputs"
        run("collect", ["sudo", "-n", "python3", "-B", inputs / "pgo_train.py", inputs / "plan.json", "--collect"], 1500)
        collection_path = Path(plan["training_directory"]) / "collection.json"
        collection = json.loads(collection_path.read_text())
        require(collection["plan_sha256"] == sha(inputs / "plan.json"), "collection plan differs")
        profiles = training_profiles(plan, collection)
        checked_file(plan["profdata"])
        run("profile-merge", [plan["profdata"]["path"], "merge", "-o", plan["merged_profile"], *[p["path"] for p in profiles]])
        shown = run("profile-show", [plan["profdata"]["path"], "show", "--all-functions", "--counts", plan["merged_profile"]])
        for key in ("Total functions", "Maximum function count"):
            match = re.search(r"^\s*" + key + r":\s*(\d+)\s*$", shown, re.M)
            require(match is not None and int(match[1]) > 0, "empty merged profile: " + key)
        for label in ("profile-merge", "profile-show"):
            require(not (base / (label + ".stderr")).read_text().strip(), label + " diagnostics present")
        for item in (request["generate_elf"], request["ci_build"], request["smoke_runtime"], plan["smoke_profile"],
                     *plan["workload_tools"].values()):
            checked_file(item)
        load_original(inputs, plan["input_sha256"])
        require(not any(Path(plan["generate_default_profile_directory"]).iterdir()), "profiles escaped training directory")
        merged = Path(plan["merged_profile"])
        receipt = {"status": "training-complete-unqualified", "release_qualified": False,
                   "source_commit": plan["source_commit"], "source_digest": plan["source_digest"],
                   "source_file_count": plan["source_file_count"], "source_date_epoch": plan["source_date_epoch"],
                   "plan_sha256": sha(inputs / "plan.json"), "generate_elf": plan["generate_elf"],
                   "ci_build": plan["ci_build"], "training_seed": plan["training_seed"],
                   "profdata": plan["profdata"], "smoke_runtime": plan["smoke_runtime"],
                   "scene_count": 11, "profile_count": 50, "profiles": profiles,
                   "excluded_smoke_profile": plan["smoke_profile"], "helper_reused": True,
                   "product_training_reused": False, "collection_sha256": sha(collection_path),
                   "merged_profile": {"path": str(merged), "sha256": sha(merged), "bytes": merged.stat().st_size}}
        save(base / "training-profile.json", receipt)
        state.update(status="training-complete-unqualified", profile_receipt_sha256=sha(base / "training-profile.json"))
    except BaseException as error:
        state.update(status="failed", error=repr(error))
        raise
    finally:
        save(state_path, state)


def interrupted(signum, _frame):
    raise InterruptedError(f"interrupted by signal {signum}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    execute(args.request.resolve())
