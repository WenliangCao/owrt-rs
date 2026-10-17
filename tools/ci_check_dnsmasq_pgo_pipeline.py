#!/usr/bin/env python3
"""Build canonical instrumentation or an explicitly unqualified PGO candidate.

The same x86 SDK builder produces generation and use artifacts. Oracle only
executes the frozen training workload between these builds. A first-use ELF
must be frozen in a separate spec before reference reproduction is possible;
neither step grants runtime, performance or deployment acceptance.
"""
import argparse
import json
from pathlib import Path
import re

import ci_check_dnsmasq_pgo_candidate as candidate


SPEC = candidate.target.builder.REPO / "manifests/dnsmasq-pgo-generate-a97edbc1.json"
PROFILE_OUTPUT = "/tmp/dnsmasq-a97edbc1-ci-pgo"
INSTRUMENTATION_BUDGET = {"elf_max_bytes": 6_000_000, "apk_max_bytes": 3_500_000}


def load_spec(path=SPEC, expected_stage=None):
    spec = json.loads(path.read_text())
    # Keep the existing dispatch default and its immutable Oracle-host spec.
    if expected_stage == "frozen-use" and "pgo_stage" not in spec:
        return candidate.load_spec(path)
    candidate.validate_source(spec)
    require = candidate.target.builder.audit.require
    stage = spec.get("pgo_stage")
    require(stage in candidate.target.builder.PGO_STAGES, "explicit PGO pipeline stage required")
    require(expected_stage is None or expected_stage == stage, "dispatch stage differs from frozen spec")
    require(spec["pgo"].get("retain_link_map") is True, "canonical pipeline requires a same-build linker map")
    if stage == "generate":
        require(spec.get("instrumentation_budget") == INSTRUMENTATION_BUDGET,
                "training-only instrumentation budget changed")
        require(spec["pgo"] == {"build_slot": candidate.BUILD_SLOT, "profile_output_dir": PROFILE_OUTPUT,
                                "retain_link_map": True},
                "instrumentation must have only a build slot and output directory, no input profile")
    else:
        require("instrumentation_budget" not in spec and "profile_output_dir" not in spec["pgo"],
                "use artifacts cannot use instrumentation settings or budgets")
        candidate.validate_profile(spec)
        provenance = spec["pgo"].get("training", {})
        for key in ("generator_manifest_sha256", "generator_elf_sha256", "training_receipt_sha256"):
            value = provenance.get(key)
            require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
                    "canonical training provenance is not frozen: " + key)
    if stage == "frozen-use":
        candidate.validate_reference(spec)
    else:
        require(not any(key in spec for key in ("reference_elf_sha256", "reference_elf_bytes")),
                "diagnostic stages cannot bypass a frozen ELF identity")
    return spec


def run(work, spec_path=SPEC, expected_stage=None):
    spec = load_spec(spec_path, expected_stage)
    candidate.target.run(work, spec=spec, pgo_stage=spec.get("pgo_stage", expected_stage))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--spec", type=Path, default=SPEC)
    parser.add_argument("--stage", choices=candidate.target.builder.PGO_STAGES)
    args = parser.parse_args()
    run(candidate.target.builder.audit.safe_path(args.work.resolve()), args.spec, args.stage)


if __name__ == "__main__":
    main()
