#!/usr/bin/env python3
"""Build a declared set of isolated ubusd candidates on the Oracle host.

This is a build stage only.  It never starts ubusd, touches the router, or
accepts an existing output/work directory.  The input manifest is intentionally
small so that a new experiment can add a candidate (including a sendmmsg
candidate) without changing the timing runner.

Manifest input::

    {"schema": 1, "variants": [{
      "label": "sendmmsg-a",
      "components": "/home/ubuntu/r136/variants/sendmmsg-a/components",
      "output": "/home/ubuntu/r136/build/sendmmsg-a/ubusd-rs",
      "work_root": "/tmp/owrt-build/r135/r136-sendmmsg-a",
      "expected_sha256": null
    }]}

The canonical R135 build script is reused.  Its own flag and source-root
guards remain authoritative; this wrapper only supplies distinct output and
work roots and records the resulting identity.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import NoReturn


LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_manifest(path: Path) -> list[dict]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read manifest {path}: {error}")
    if value.get("schema") != 1 or not isinstance(value.get("variants"), list):
        fail("input manifest requires schema=1 and a variants array")
    if not value["variants"]:
        fail("input manifest must declare at least one variant")
    labels = set()
    outputs = set()
    works = set()
    variants = []
    for item in value["variants"]:
        if not isinstance(item, dict):
            fail("each variant must be an object")
        label = item.get("label")
        if not isinstance(label, str) or not LABEL.fullmatch(label) or label in labels:
            fail(f"invalid or duplicate variant label: {label!r}")
        labels.add(label)
        components_value = item.get("components")
        output_value = item.get("output")
        if not isinstance(components_value, str) or not isinstance(output_value, str):
            fail(f"variant {label} requires string components and output paths")
        components = Path(components_value)
        output = Path(output_value)
        if output.name != "ubusd-rs":
            fail(f"canonical builder output must be named ubusd-rs: {output}")
        if not components.is_dir():
            fail(f"components directory does not exist: {components}")
        if output.parent.exists():
            fail(f"refusing pre-existing output directory: {output.parent}")
        work = Path(item.get("work_root", f"/tmp/owrt-build/r135/r136-{label}"))
        if output.parent.resolve() in outputs or work.resolve() in works:
            fail(f"duplicate output/work root: {label}")
        outputs.add(output.parent.resolve())
        works.add(work.resolve())
        if work.exists():
            fail(f"refusing pre-existing build root: {work}")
        expected = item.get("expected_sha256")
        if expected is not None and (not isinstance(expected, str) or not HEX64.fullmatch(expected)):
            fail(f"expected_sha256 must be lowercase hexadecimal or null: {label}")
        variants.append({"label": label, "components": components, "output": output,
                         "work_root": work, "expected_sha256": expected})
    return variants


def build_one(item: dict, script: Path) -> dict:
    label = item["label"]
    output = item["output"].resolve()
    work = item["work_root"].resolve()
    output.parent.parent.mkdir(parents=True, exist_ok=True)
    log = output.parent.parent / f"{output.parent.name}-build.log"
    if log.exists():
        fail(f"refusing pre-existing build log: {log}")
    command = ["bash", str(script), str(item["components"].resolve()), str(output.parent), str(work)]
    source_hashes = {str(path.relative_to(item["components"])): sha256(path)
                     for path in sorted(item["components"].rglob("*")) if path.is_file()}
    try:
        with log.open("wb") as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        binary = output
        if not binary.is_file() or binary.is_symlink():
            fail(f"build did not produce a regular ELF path: {binary}")
        actual = sha256(binary)
        expected = item["expected_sha256"]
        if expected is not None and actual != expected:
            fail(f"{label}: expected {expected}, got {actual}")
        after = {str(path.relative_to(item["components"])): sha256(path)
                 for path in sorted(item["components"].rglob("*")) if path.is_file()}
        if after != source_hashes:
            fail(f"{label}: source changed during build")
        return {"label": label, "path": str(binary), "sha256": actual,
                "components": str(item["components"].resolve()), "work_root": str(work),
                "source_sha256": source_hashes,
                "command": command, "log": str(log), "status": "built"}
    except Exception:
        # Keep the log for diagnosis, but make the failed result unmistakable.
        output.parent.mkdir(parents=True, exist_ok=True)
        (output.parent / "FAILED").touch()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="schema-1 input manifest")
    parser.add_argument("--build-script", type=Path,
                        default=Path(__file__).resolve().parents[1] / "r135/build_variant.sh")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True,
                        help="new JSON result manifest; its parent may already exist")
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 32:
        parser.error("--jobs must be between 1 and 32")
    script = args.build_script.resolve()
    if not script.is_file():
        parser.error(f"build script does not exist: {script}")
    if args.output.exists():
        parser.error(f"refusing pre-existing result: {args.output}")
    variants = read_manifest(args.manifest.resolve())
    records: list[dict] = []
    errors: list[str] = []
    # Build roots are independent, so this is safe to parallelize.  The
    # canonical build script itself constrains Cargo jobs to one per variant.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.jobs, len(variants))) as pool:
        future_map = {pool.submit(build_one, item, script): item["label"] for item in variants}
        for future in concurrent.futures.as_completed(future_map):
            label = future_map[future]
            try:
                record = future.result()
            except Exception as error:
                errors.append(f"{label}: {error}")
            else:
                records.append(record)
                print(f"BUILT {label} {record['sha256']}", flush=True)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    records.sort(key=lambda item: item["label"])
    result = {
        "schema": 1,
        "scope": "Oracle build stage only; no daemon or router execution",
        "input_manifest": str(args.manifest.resolve()),
        "input_manifest_sha256": sha256(args.manifest.resolve()),
        "build_script": str(script),
        "build_script_sha256": sha256(script),
        "jobs": args.jobs,
        "variants": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, args.output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
