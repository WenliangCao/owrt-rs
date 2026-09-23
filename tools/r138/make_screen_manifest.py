#!/usr/bin/env python3
"""Make a three-subject screen manifest from verified fixed-path build results."""
import argparse
import hashlib
import json
from pathlib import Path


R136 = "ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330"
BENCHMARK = "85dd537a070e39373a4a21a6bf982da9359bc70e61e53cdf93516b9c34684b1d"
C = "cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path, help="completed R137 fixed-path build directory")
    parser.add_argument("--reference", type=Path, required=True, help="frozen R136 screen manifest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads((args.build / "frozen-plan.json").read_text())
    result = json.loads((args.build / "results.json").read_text())
    if result.get("passed") is not True or result["frozen_plan_sha256"] != sha(args.build / "frozen-plan.json"):
        raise ValueError("fixed-path build did not pass or its frozen plan changed")
    if plan["canonical_source_root"] != "/tmp/owrt-build/r135/r136-combined-01":
        raise ValueError("source path differs from the R136 canonical path")
    builds = {item["label"]: item for item in result["variants"]}
    paths = {item["label"]: item["output"] for item in plan["variants"]}
    if set(builds) != {"r136", "remove"} or set(paths) != set(builds):
        raise ValueError("expected exactly r136 and remove builds")
    if builds["r136"]["sha256"] != R136:
        raise ValueError("rebuilt R136 control differs from the measured ELF")
    reference = json.loads(args.reference.read_text())
    subjects = [item for item in reference["subjects"] if item["kind"] == "c"]
    if len(subjects) != 1 or subjects[0]["sha256"] != C or reference["benchmark"]["sha256"] != BENCHMARK:
        raise ValueError("C or benchmark differs from the frozen R136 screen")
    subjects[0] = {**subjects[0], "label": "c"}
    for label in ("r136", "remove"):
        item = builds[label]
        if item["status"] != "built" or sha(paths[label]) != item["sha256"]:
            raise ValueError(f"build artifact identity mismatch: {label}")
        subjects.append({"label": label, "kind": "rust", "path": paths[label], "sha256": item["sha256"]})
    manifest = {"schema": 1, **{key: reference[key] for key in ("benchmark", "rootfs", "libraries")},
                "subjects": subjects,
                "r138_policy": json.loads(Path(__file__).with_name("screen-policy.json").read_text()),
                "provenance": {"build_plan_sha256": sha(args.build / "frozen-plan.json"),
                               "build_results_sha256": sha(args.build / "results.json"),
                               "reference_manifest_sha256": sha(args.reference),
                               "policy_sha256": sha(Path(__file__).with_name("screen-policy.json"))}}
    with args.output.open("x") as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
