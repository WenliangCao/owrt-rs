#!/usr/bin/env python3
"""Build canonical PGO stages from an explicit integrated-source freeze."""
import argparse
import hashlib
import json
from pathlib import Path
import re

import ci_check_dnsmasq_target as target


BUILD_SLOT = "/home/ubuntu/owrt-unified-v022-20261017/private/dnsmasq-sdk-build-slot"
PROFILE_OUTPUT = "/tmp/dnsmasq-unified-v022-ci-pgo"
INSTRUMENTATION_BUDGET = {"elf_max_bytes": 6_000_000, "apk_max_bytes": 3_500_000}


def frozen_hash(value, length=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value)


def load_spec(path, expected_stage):
    spec = json.loads(path.read_text())
    require = target.builder.audit.require
    require(frozen_hash(spec.get("source_commit"), 40), "full source commit required")
    require(type(spec.get("source_date_epoch")) is int and spec["source_date_epoch"] > 0,
            "source timestamp must be frozen")
    files = spec.get("source_files", {})
    require(isinstance(files, dict) and files and all(
        isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts
        and frozen_hash(digest) for name, digest in files.items()), "complete source input map required")
    require({"components/platform/Cargo.toml", "components/dnsmasq/platform/Cargo.toml"} <= files.keys(),
            "integrated shared platform source is required")
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(spec.get("source_digest") == digest and spec.get("source_file_count") == len(files),
            "source input digest/count differs from frozen map")
    require(spec.get("elf_max_bytes") == 2_500_000 and spec.get("apk_max_bytes") == 1_400_000
            and spec.get("package_release") == "4", "final package budgets/release differ")
    stage = spec.get("pgo_stage")
    require(stage in target.builder.PGO_STAGES and stage == expected_stage,
            "explicit dispatch stage must match frozen spec")
    pgo = spec.get("pgo", {})
    require(pgo.get("build_slot") == BUILD_SLOT and pgo.get("retain_link_map") is True,
            "canonical build slot and same-build linker map required")
    if stage == "generate":
        require(spec.get("instrumentation_budget") == INSTRUMENTATION_BUDGET,
                "training-only instrumentation budget differs")
        require(pgo == {"build_slot": BUILD_SLOT, "profile_output_dir": PROFILE_OUTPUT,
                        "retain_link_map": True}, "generation must not consume an input profile")
    else:
        require("instrumentation_budget" not in spec and "profile_output_dir" not in pgo,
                "use artifacts cannot use instrumentation settings/budgets")
        require(frozen_hash(pgo.get("profile_sha256")) and type(pgo.get("profile_bytes")) is int
                and pgo["profile_bytes"] > 0, "profile hash/size must be frozen")
        repo, tag, name = target.builder.profile_asset(pgo.get("profile_url", ""))
        require(repo == "WenliangCao/owrt-control-plane-rs" and tag == "dnsmasq-k-pgo-inputs-20261017"
                and name == f"dnsmasq-{spec['source_commit'][:8]}-{pgo['profile_sha256']}.profdata",
                "profile must name its unique source/hash build-input asset")
        provenance = pgo.get("training", {})
        require(all(frozen_hash(provenance.get(key)) for key in (
            "generator_manifest_sha256", "generator_elf_sha256", "training_receipt_sha256")),
            "canonical generator/training provenance must be frozen")
    if stage == "frozen-use":
        require(frozen_hash(spec.get("reference_elf_sha256"))
                and type(spec.get("reference_elf_bytes")) is int
                and 0 < spec["reference_elf_bytes"] <= spec["elf_max_bytes"],
                "accepted reference ELF hash/size must be frozen")
    else:
        require(not any(key in spec for key in ("reference_elf_sha256", "reference_elf_bytes")),
                "diagnostic stages cannot bypass a frozen reference ELF")
    return spec


def run(work, spec_path, stage):
    spec = load_spec(spec_path, stage)
    target.run(work, spec=spec, pgo_stage=stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--stage", choices=target.builder.PGO_STAGES, required=True)
    args = parser.parse_args()
    run(target.builder.audit.safe_path(args.work.resolve()), args.spec, args.stage)


if __name__ == "__main__":
    main()
