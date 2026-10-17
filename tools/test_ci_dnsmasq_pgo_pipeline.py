"""Exercise stage and qualification boundaries without Rust or SDK builds."""
import copy
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
        self.spec = json.loads(pipeline.SPEC.read_text())
        self.path = self.root / "spec.json"

    def save(self, spec):
        self.path.write_text(json.dumps(spec))
        return self.path

    def use_spec(self):
        spec = copy.deepcopy(self.spec)
        spec.pop("instrumentation_budget")
        spec["pgo_stage"] = "candidate-use"
        spec["pgo"] = {
            "build_slot": pipeline.candidate.BUILD_SLOT,
            "retain_link_map": True,
            "profile_sha256": "f" * 64, "profile_bytes": 12345,
            "profile_url": "https://github.com/WenliangCao/owrt-control-plane-rs/releases/download/"
                           "dnsmasq-k-pgo-inputs-20261017/dnsmasq-a97edbc1-ffffffffffffffff.profdata",
            "training": {key: "a" * 64 for key in (
                "generator_manifest_sha256", "generator_elf_sha256", "training_receipt_sha256")}}
        return spec

    def test_instrumented_generation_never_downloads_an_existing_profile(self):
        self.assertEqual(pipeline.load_spec(self.save(self.spec)), self.spec)
        for mutate in (
            lambda spec: spec["pgo"].update(profile_sha256="e" * 64),
            lambda spec: spec.update(reference_elf_sha256="e" * 64),
            lambda spec: spec.update(elf_max_bytes=6_000_000),
            lambda spec: spec["instrumentation_budget"].update(elf_max_bytes=7_000_000),
        ):
            spec = copy.deepcopy(self.spec)
            mutate(spec)
            with self.assertRaises(ValueError):
                pipeline.load_spec(self.save(spec))

    def test_first_use_requires_profile_and_training_provenance_but_no_reference(self):
        spec = self.use_spec()
        with patch.object(pipeline.candidate.target, "run") as build:
            pipeline.run(self.root, self.save(spec))
        build.assert_called_once_with(self.root, spec=spec, pgo_stage="candidate-use")
        for mutate in (
            lambda spec: spec["pgo"].update(profile_bytes=None),
            lambda spec: spec["pgo"]["training"].pop("generator_manifest_sha256"),
            lambda spec: spec.update(reference_elf_sha256="e" * 64),
            lambda spec: spec.update(instrumentation_budget=pipeline.INSTRUMENTATION_BUDGET),
        ):
            bad = copy.deepcopy(spec)
            mutate(bad)
            with self.assertRaises(ValueError):
                pipeline.load_spec(self.save(bad))

    def test_reference_reproduction_remains_fail_closed(self):
        spec = self.use_spec()
        spec["pgo_stage"] = "frozen-use"
        with self.assertRaisesRegex(ValueError, "identity is not frozen"):
            pipeline.load_spec(self.save(spec))
        spec.update(reference_elf_sha256="b" * 64, reference_elf_bytes=2_300_000)
        self.assertEqual(pipeline.load_spec(self.save(spec)), spec)
        with self.assertRaisesRegex(ValueError, "identity is not frozen"):
            pipeline.candidate.load_spec(self.save(self.use_spec()))

    def test_dispatch_defaults_keep_the_original_frozen_spec(self):
        original = json.loads(pipeline.candidate.SPEC.read_text())
        self.assertEqual(pipeline.load_spec(pipeline.candidate.SPEC, "frozen-use"), original)
        with self.assertRaisesRegex(ValueError, "explicit PGO pipeline stage"):
            pipeline.load_spec(pipeline.candidate.SPEC, "candidate-use")
        with self.assertRaisesRegex(ValueError, "dispatch stage differs"):
            pipeline.load_spec(self.save(self.spec), "candidate-use")

    def test_target_reports_creation_without_claiming_reference_acceptance(self):
        target = pipeline.candidate.target
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
                pipeline.run(work, self.save(spec))
            report = json.loads((work / "out/dnsmasq/manifest.json").read_text())
            self.assertEqual(report["status"], status)
            self.assertFalse(report["release_qualified"])


if __name__ == "__main__":
    unittest.main()
