#!/usr/bin/env python3
"""Reproduce one frozen PGO candidate on x86, without changing accepted releases."""
import argparse
import json
from pathlib import Path
import re

import ci_check_dnsmasq_target as target


SPEC = target.builder.REPO / "manifests/dnsmasq-pgo-candidate-a97edbc1.json"
SOURCE_COMMIT = "a97edbc1382fc92b83110ed0822284aafeee7461"
SOURCE_DIGEST = "c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671"
SOURCE_DATE_EPOCH = 1792244626
BUILD_SLOT = "/home/ubuntu/dnsmasq-safe-v022-20261017/private/sdk-build-slot"


def validate_source(spec):
    require = target.builder.audit.require
    require((spec.get("source_commit"), spec.get("source_digest"), spec.get("source_file_count")) ==
            (SOURCE_COMMIT, SOURCE_DIGEST, 193), "candidate source freeze changed")
    require(spec.get("source_date_epoch") == SOURCE_DATE_EPOCH, "candidate source timestamp changed")
    require(spec.get("elf_max_bytes") == 2_500_000 and spec.get("apk_max_bytes") == 1_400_000
            and spec.get("package_release") == "4", "candidate package budgets changed")
    pgo = spec.get("pgo", {})
    require(pgo.get("build_slot") == BUILD_SLOT, "candidate PGO build slot changed")


def validate_reference(spec):
    require = target.builder.audit.require
    value = spec.get("reference_elf_sha256")
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "candidate ELF identity is not frozen")
    value = spec.get("reference_elf_bytes")
    require(type(value) is int and 0 < value <= spec["elf_max_bytes"], "candidate ELF size is not frozen or exceeds budget")


def validate_profile(spec):
    require = target.builder.audit.require
    pgo = spec["pgo"]
    value = pgo.get("profile_sha256")
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "candidate profile identity is not frozen")
    value = pgo.get("profile_bytes")
    require(type(value) is int and value > 0, "candidate profile size is not frozen")
    require(isinstance(pgo.get("profile_url"), str), "candidate profile URL is not frozen")
    repo, tag, name = target.builder.profile_asset(pgo["profile_url"])
    require(repo == "WenliangCao/owrt-control-plane-rs" and tag == "dnsmasq-k-pgo-inputs-20261017"
            and SOURCE_COMMIT[:8] in name and pgo["profile_sha256"][:16] in name
            and name.endswith(".profdata"), "candidate profile must use its unique source/hash release asset")


def load_spec(path=SPEC):
    spec = json.loads(path.read_text())
    validate_source(spec)
    validate_reference(spec)
    validate_profile(spec)
    return spec


def run(work, spec_path=SPEC):
    # Validate before SDK download, compiler invocation or profile access.
    spec = load_spec(spec_path)
    target.run(work, spec=spec)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    args = parser.parse_args()
    run(target.builder.audit.safe_path(args.work.resolve()))


if __name__ == "__main__":
    main()
