#!/usr/bin/env python3
"""Reproduce one frozen PGO candidate on x86, without changing accepted releases."""
import argparse
import json
from pathlib import Path
import re

import ci_check_dnsmasq_target as target


SPEC = target.builder.REPO / "manifests/dnsmasq-pgo-candidate-8adcdeaf.json"
SOURCE_COMMIT = "8adcdeafddb7cfd8bc5d059e396d898c0447cb70"
SOURCE_DIGEST = "a6f9f1e7a7aca739842c6695e9c94945b80339cdbce11c88e8c4b950cfa987ae"
SOURCE_DATE_EPOCH = 1792237751
BUILD_SLOT = "/home/ubuntu/dnsmasq-safe-v022-20261017/private/sdk-build-slot"


def load_spec(path=SPEC):
    spec = json.loads(path.read_text())
    require = target.builder.audit.require
    require((spec.get("source_commit"), spec.get("source_digest"), spec.get("source_file_count")) ==
            (SOURCE_COMMIT, SOURCE_DIGEST, 193), "candidate source freeze changed")
    require(spec.get("source_date_epoch") == SOURCE_DATE_EPOCH, "candidate source timestamp changed")
    require(spec.get("elf_max_bytes") == 2_500_000 and spec.get("apk_max_bytes") == 1_400_000
            and spec.get("package_release") == "4", "candidate package budgets changed")
    pgo = spec.get("pgo", {})
    require(pgo.get("build_slot") == BUILD_SLOT, "candidate PGO build slot changed")
    for value in (spec.get("reference_elf_sha256"), pgo.get("profile_sha256")):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
                "candidate profile/Oracle ELF identity is not frozen")
    for value in (spec.get("reference_elf_bytes"), pgo.get("profile_bytes")):
        require(type(value) is int and value > 0, "candidate profile/Oracle ELF size is not frozen")
    require(spec["reference_elf_bytes"] <= spec["elf_max_bytes"], "Oracle ELF exceeds candidate budget")
    require(isinstance(pgo.get("profile_url"), str), "candidate profile URL is not frozen")
    repo, tag, name = target.builder.profile_asset(pgo["profile_url"])
    require(repo == "WenliangCao/owrt-control-plane-rs" and tag == "dnsmasq-k-pgo-inputs-20261017"
            and SOURCE_COMMIT[:8] in name and pgo["profile_sha256"][:16] in name
            and name.endswith(".profdata"), "candidate profile must use its unique source/hash release asset")
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
