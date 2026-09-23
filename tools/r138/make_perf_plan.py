#!/usr/bin/env python3
"""Freeze the bounded R138 PMU diagnostic using the existing R132 caller."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r132_registration_profile as base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    subjects = {item["label"]: item for item in manifest["subjects"]}
    base.require(set(subjects) == {"c", "r136", "remove"}, "expected C/R136/REMOVE")
    base.require(subjects["r136"]["sha256"] ==
                 "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330", "R136 differs")
    plan = base.template("stat")
    rootfs = Path(manifest["rootfs"]["loader"]).parent.parent
    plan.update({"purpose": "R138 bounded instruction diagnostic; all observed latency excluded",
                 "rootfs": {"path": str(rootfs), "libraries": {
                     "/" + str(Path(path).relative_to(rootfs)): digest for path, digest in manifest["libraries"].items()}},
                 "r138_wrapper_sha256": base.sha(Path(__file__).with_name("perf_stat.py")),
                 "screen_manifest_sha256": base.sha(args.manifest),
                 "subjects": {label: {"path": item["path"], "sha256": item["sha256"],
                                      "kind": "dynamic" if item["kind"] == "c" else "static"}
                              for label, item in subjects.items()},
                 "launch_directory": "/tmp/r132-registration-r138-01",
                 "runs": [{"subject": label, "methods": methods, "name_bytes": 8, "n": 10000, "warmup": 200}
                          for methods in (1, 16) for label in ("c", "r136", "remove", "remove", "r136", "c")]})
    with args.output.open("x") as stream:
        json.dump(plan, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
