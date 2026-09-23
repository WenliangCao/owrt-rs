#!/usr/bin/env python3
"""Build Oracle candidates at one fixed Cargo source path in private namespaces.

Input: {"schema": 1, "variants": [{"label": "control-a", "components":
"/path/to/components", "expected_sha256": "<optional expected ELF sha256>"}]}
--output must be a new run directory. No daemon or router is accessed.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import time


CANONICAL = Path("/tmp/owrt-build/r135/r136-combined-01")
BUILDER_SHA256 = "da5692bb202c7ee10ce7d1f56966dfc06262101e8e96ef4e133c745db90c3bc5"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError(f"source must contain only directories and regular files: {path}")
        if path.is_file():
            result[str(path.relative_to(root))] = sha256(path)
    for required in ("ubusd/Cargo.toml", "ubusd/Cargo.lock", "ubus/Cargo.toml"):
        if required not in result:
            raise ValueError(f"missing source input: {root / required}")
    if any("target" in Path(name).parts for name in result):
        raise ValueError(f"source must be a clean snapshot without target directories: {root}")
    return result


def outside_mount(path: Path) -> Path:
    path = path.resolve()
    mount_parent = CANONICAL.parent.resolve()
    if path == mount_parent or mount_parent in path.parents:
        raise ValueError(f"path would be hidden by the private mount: {path}")
    return path


def freeze_plan(manifest: Path, output: Path, builder: Path, runner: Path, jobs: int) -> dict:
    if sha256(builder) != BUILDER_SHA256:
        raise ValueError("builder differs from the frozen R136 artifact recipe")
    value = json.loads(manifest.read_text())
    if value.get("schema") != 1 or not isinstance(value.get("variants"), list) or not value["variants"]:
        raise ValueError("manifest requires schema=1 and a nonempty variants array")
    variants = []
    labels = set()
    for item in value["variants"]:
        label = item.get("label")
        if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", label) or label in labels:
            raise ValueError(f"invalid or duplicate label: {label!r}")
        labels.add(label)
        components = outside_mount(Path(item["components"]))
        if not components.is_dir():
            raise ValueError(f"missing components directory: {components}")
        if components == output or components in output.parents:
            raise ValueError("output must be outside every source snapshot")
        expected = item.get("expected_sha256")
        if expected is not None and not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError(f"invalid expected SHA-256: {label}")
        variants.append({"label": label, "components": str(components),
                         "source_sha256": source_hashes(components),
                         "expected_sha256": expected,
                         "output": str(output / label / "ubusd-rs")})
    return {"schema": 1, "scope": "Oracle build identity only; no performance or router execution",
            "input_manifest_sha256": sha256(manifest), "canonical_source_root": str(CANONICAL),
            "cwd": "/home/ubuntu", "cargo_user": "ubuntu", "jobs": jobs,
            "builder": str(builder), "builder_sha256": sha256(builder),
            "namespace_runner_sha256": sha256(runner),
            "batch_wrapper_sha256": sha256(Path(__file__)), "variants": variants}


def write_json(path: Path, value: dict) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def build_one(item: dict, output: Path, builder: Path, runner: Path) -> dict:
    label = item["label"]
    binary = Path(item["output"])
    sources = Path(item["components"])
    started = time.time_ns()
    record = {"label": label, "started_ns": started, "status": "failed"}
    log = output / f"{label}.log"
    try:
        if source_hashes(sources) != item["source_sha256"]:
            raise ValueError("source changed after plan freeze")
        # The private parent starts empty. The unchanged builder creates its
        # canonical child within this bind mount, never in the host directory.
        with tempfile.TemporaryDirectory(prefix=f".{label}-mount-", dir=output) as private:
            command = ["sudo", "-n", "unshare", "--mount", "--pid", "--fork",
                       "--kill-child", "--propagation", "private", "bash", str(runner),
                       str(builder), str(sources), str(binary.parent), str(CANONICAL), private,
                       os.readlink("/proc/self/ns/mnt")]
            with log.open("xb") as stream:
                subprocess.run(command, cwd="/home/ubuntu", stdout=stream,
                               stderr=subprocess.STDOUT, check=True)
        if source_hashes(sources) != item["source_sha256"]:
            raise ValueError("source changed during build")
        if not binary.is_file() or binary.is_symlink():
            raise ValueError("builder did not produce a regular ELF")
        actual = sha256(binary)
        record.update({"sha256": actual, "size": binary.stat().st_size,
                       "namespace": json.loads((binary.parent / "namespace.json").read_text()),
                       "source_unchanged": True})
        if item["expected_sha256"] is not None and actual != item["expected_sha256"]:
            raise ValueError(f"ELF identity mismatch: {actual}")
        record["status"] = "built"
    except Exception as error:
        record["error"] = str(error)
    record.update({"finished_ns": time.time_ns(), "log_sha256": sha256(log) if log.exists() else None})
    write_json(output / f"{label}-result.json", record)
    print(f"{record['status'].upper()} {label} {record.get('sha256', record.get('error'))}", flush=True)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--build-script", type=Path,
                        default=Path(__file__).resolve().parents[1] / "r135/build_variant.sh")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True, help="new run directory")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be between 1 and 32")
    if pwd.getpwuid(os.geteuid()).pw_name != "ubuntu":
        parser.error("run as ubuntu; only namespace setup uses sudo")
    builder = outside_mount(args.build_script)
    runner = outside_mount(Path(__file__).with_name("namespace_build.sh"))
    output = outside_mount(args.output)
    if output.exists():
        parser.error(f"refusing pre-existing output: {output}")
    if not CANONICAL.parent.is_dir():
        parser.error(f"host mount point must already exist: {CANONICAL.parent}")
    subprocess.run(["sudo", "-n", "true"], check=True)
    plan = freeze_plan(args.manifest.resolve(), output, builder, runner, args.jobs)
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "frozen-plan.json", plan)
    parent_namespace = os.readlink("/proc/self/ns/mnt")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(build_one, item, output, builder, runner) for item in plan["variants"]]
        records = [future.result() for future in futures]
    namespaces = [item.get("namespace", {}).get("mount_namespace") for item in records]
    passed = (all(item["status"] == "built" for item in records)
              and parent_namespace not in namespaces
              and sha256(builder) == plan["builder_sha256"]
              and sha256(runner) == plan["namespace_runner_sha256"])
    result = {"schema": 1, "passed": passed, "frozen_plan_sha256": sha256(output / "frozen-plan.json"),
              "parent_mount_namespace": parent_namespace, "variants": records}
    write_json(output / "results.json", result)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
