"""Check integrated PGO stage boundaries without Rust or SDK builds."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ci_check_dnsmasq_pgo_pipeline as pipeline


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = {"components/platform/Cargo.toml": "a" * 64,
                 "components/dnsmasq/platform/Cargo.toml": "b" * 64}
        self.spec = {"source_commit": "c" * 40, "source_date_epoch": 1792244626,
                     "source_files": files, "source_file_count": len(files),
                     "source_digest": hashlib.sha256(json.dumps(files, sort_keys=True,
                         separators=(",", ":")).encode()).hexdigest(),
                     "elf_max_bytes": 2_500_000, "apk_max_bytes": 1_400_000, "package_release": "4",
                     "pgo_stage": "generate", "instrumentation_budget": pipeline.INSTRUMENTATION_BUDGET,
                     "pgo": {"build_slot": pipeline.BUILD_SLOT, "profile_output_dir": pipeline.PROFILE_OUTPUT,
                             "retain_link_map": True}}
        self.path = self.root / "spec.json"

    def save(self, spec):
        self.path.write_text(json.dumps(spec))
        return self.path

    def use_spec(self):
        spec = copy.deepcopy(self.spec)
        spec.pop("instrumentation_budget")
        spec["pgo_stage"] = "candidate-use"
        spec["pgo"] = {"build_slot": pipeline.BUILD_SLOT, "retain_link_map": True,
                       "profile_sha256": "f" * 64, "profile_bytes": 12345,
                       "profile_url": "https://github.com/WenliangCao/owrt-control-plane-rs/releases/download/"
                                      "dnsmasq-k-pgo-inputs-20261017/dnsmasq-cccccccc-" + "f" * 64 + ".profdata",
                       "training": {key: "a" * 64 for key in (
                           "generator_manifest_sha256", "generator_elf_sha256", "training_receipt_sha256")}}
        return spec

    def test_generation_requires_integrated_source_freeze_without_profile(self):
        self.assertEqual(pipeline.load_spec(self.save(self.spec), "generate"), self.spec)
        for mutate in (
            lambda spec: spec["pgo"].update(profile_sha256="e" * 64),
            lambda spec: spec.update(reference_elf_sha256="e" * 64),
            lambda spec: spec.update(elf_max_bytes=6_000_000),
            lambda spec: spec["instrumentation_budget"].update(elf_max_bytes=7_000_000),
            lambda spec: spec["source_files"].pop("components/platform/Cargo.toml"),
            lambda spec: spec["source_files"].update({"../outside": "a" * 64}),
            lambda spec: spec.update(source_file_count=193),
            lambda spec: spec.update(source_digest="e" * 64),
        ):
            spec = copy.deepcopy(self.spec)
            mutate(spec)
            with self.assertRaises(ValueError):
                pipeline.load_spec(self.save(spec), "generate")

    def test_first_use_requires_unique_profile_and_generator_provenance(self):
        spec = self.use_spec()
        with patch.object(pipeline.target, "run") as build:
            pipeline.run(self.root, self.save(spec), "candidate-use")
        build.assert_called_once_with(self.root, spec=spec, pgo_stage="candidate-use")
        for mutate in (
            lambda spec: spec["pgo"].update(profile_bytes=None),
            lambda spec: spec["pgo"]["training"].pop("generator_manifest_sha256"),
            lambda spec: spec["pgo"].update(profile_url=spec["pgo"]["profile_url"].replace("cccccccc", "a97edbc1")),
            lambda spec: spec.update(reference_elf_sha256="e" * 64),
            lambda spec: spec.update(instrumentation_budget=pipeline.INSTRUMENTATION_BUDGET),
        ):
            bad = copy.deepcopy(spec)
            mutate(bad)
            with self.assertRaises(ValueError):
                pipeline.load_spec(self.save(bad), "candidate-use")

    def test_reference_reproduction_still_requires_actual_accepted_identity(self):
        spec = self.use_spec()
        spec["pgo_stage"] = "frozen-use"
        with self.assertRaisesRegex(ValueError, "reference ELF"):
            pipeline.load_spec(self.save(spec), "frozen-use")
        spec.update(reference_elf_sha256="b" * 64, reference_elf_bytes=2_300_000)
        self.assertEqual(pipeline.load_spec(self.save(spec), "frozen-use"), spec)

    def test_stage_must_be_explicit_and_match_spec(self):
        for stage in (None, "candidate-use", "frozen-use"):
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, "dispatch stage"):
                pipeline.load_spec(self.save(self.spec), stage)

    def test_input_map_is_checked_against_actual_archived_files(self):
        builder = pipeline.target.builder
        with patch.object(builder.audit, "inputs", return_value=self.spec["source_files"]):
            self.assertEqual(builder.source_identity(self.spec, self.root)[0], self.spec["source_files"])
            changed = {**self.spec, "source_file_count": 999}
            with self.assertRaisesRegex(ValueError, "complete frozen input map"):
                builder.source_identity(changed, self.root)

    def test_created_artifacts_do_not_claim_release_acceptance(self):
        target = pipeline.target
        def fake_build(work, spec, report, **kwargs):
            out = work / "out/dnsmasq"
            (out / "compile.log").write_text("Compiling dnsmasq-platform\nCompiling dnsmasq-rs\n")
            report.update(elf={"sha256": "e" * 64, "size": 2_300_000}, artifact={},
                          pgo_stage=kwargs["pgo_stage"], release_qualified=False)
        for stage, status in [("generate", "built-instrumented-training-only"),
                              ("candidate-use", "created-unqualified-pgo-candidate")]:
            work = self.root / stage
            spec = self.spec if stage == "generate" else self.use_spec()
            with patch.object(target.platform, "system", return_value="Linux"), \
                 patch.object(target.platform, "machine", return_value="x86_64"), \
                 patch.object(target, "freeze_source", return_value=self.root), \
                 patch.object(target, "prepare_sdk"), \
                 patch.object(target.builder, "build", side_effect=fake_build):
                pipeline.run(work, self.save(spec), stage)
            report = json.loads((work / "out/dnsmasq/manifest.json").read_text())
            self.assertEqual(report["status"], status)
            self.assertFalse(report["release_qualified"])


if __name__ == "__main__":
    unittest.main()
