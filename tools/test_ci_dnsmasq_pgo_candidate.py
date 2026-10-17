"""Candidate freeze and failure preservation, without building a product."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ci_check_dnsmasq_pgo_candidate as candidate


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.spec = json.loads(candidate.SPEC.read_text())
        self.spec.update(reference_elf_sha256="e" * 64, reference_elf_bytes=2_300_000)
        self.spec["pgo"].update(
            profile_sha256="f" * 64, profile_bytes=12345,
            profile_url="https://github.com/WenliangCao/owrt-control-plane-rs/releases/download/"
                        "dnsmasq-k-pgo-inputs-20261017/dnsmasq-a97edbc1-ffffffffffffffff.profdata")
        self.path = self.root / "candidate.json"

    def save(self, spec):
        self.path.write_text(json.dumps(spec))
        return self.path

    def test_unfrozen_identity_stops_before_any_build(self):
        for field in ("reference_elf_sha256", "reference_elf_bytes"):
            spec = copy.deepcopy(self.spec)
            spec[field] = None
            with self.subTest(field=field), patch.object(candidate.target, "run") as build:
                with self.assertRaisesRegex(ValueError, "not frozen"):
                    candidate.run(self.root, self.save(spec))
                build.assert_not_called()
        for field in ("profile_url", "profile_sha256", "profile_bytes"):
            spec = copy.deepcopy(self.spec)
            spec["pgo"][field] = None
            with self.subTest(field=field), patch.object(candidate.target, "run") as build:
                with self.assertRaisesRegex(ValueError, "not frozen"):
                    candidate.run(self.root, self.save(spec))
                build.assert_not_called()

    def test_frozen_candidate_uses_only_new_slot_and_unique_profile(self):
        self.assertEqual(candidate.load_spec(self.save(self.spec)), self.spec)
        old_slot = "/home/ubuntu/dnsmasq-perf-20261015/root/private/sdk-build-slot"
        self.assertEqual(str(candidate.target.builder.PGO_BUILD_SLOT), old_slot)
        changes = [("source_commit", "0" * 40), ("source_digest", "0" * 64),
                   ("source_file_count", 192), ("source_date_epoch", 1792237750),
                   ("elf_max_bytes", 3_000_000)]
        for field, value in changes:
            spec = copy.deepcopy(self.spec)
            spec[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate.load_spec(self.save(spec))
        for field, value in [("build_slot", old_slot), ("profile_bytes", True),
                             ("profile_url", self.spec["pgo"]["profile_url"].replace(
                                 "dnsmasq-a97edbc1-ffffffffffffffff.profdata", "dnsmasq-k.profdata"))]:
            spec = copy.deepcopy(self.spec)
            spec["pgo"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                candidate.load_spec(self.save(spec))

    def test_git_archive_freezes_product_source_not_tooling_head(self):
        frozen = candidate.target.freeze_source(self.root, self.spec)
        files, digest = candidate.target.builder.source_identity(self.spec, frozen)
        self.assertEqual(len(files), 193)
        self.assertEqual(digest, candidate.SOURCE_DIGEST)
        self.assertIn("components/dnsmasq/platform/src/process_fork.rs", files)
        epoch = subprocess.check_output(["git", "-C", str(candidate.target.builder.REPO),
                                         "show", "-s", "--format=%ct", candidate.SOURCE_COMMIT], text=True)
        self.assertEqual(int(epoch), candidate.SOURCE_DATE_EPOCH)
        manifest = json.loads((self.root / "source-manifest.json").read_text())
        self.assertEqual(manifest["commit"], candidate.SOURCE_COMMIT)

    def test_elf_mismatch_preserves_actual_profile_prestrip_and_package(self):
        def mismatched_build(work, spec, report, **kwargs):
            out = work / "out/dnsmasq"
            (out / "compile.log").write_text("actual compilation output\n")
            for name, contents in {"pgo/candidate.profdata": b"actual profile",
                                   "pgo-compilation/dnsmasq-prestrip": b"actual prestrip",
                                   "payload/usr/sbin/dnsmasq": b"different actual ELF",
                                   "dnsmasq-2.93-r4.apk": b"actual package"}.items():
                path = out / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            report.update(accepted_product_commit=spec["source_commit"], pgo=spec["pgo"])
            raise ValueError("fresh CI PGO ELF differs from frozen reference")

        target = candidate.target
        with patch.object(target.platform, "system", return_value="Linux"), \
             patch.object(target.platform, "machine", return_value="x86_64"), \
             patch.object(target, "freeze_source", return_value=self.root), \
             patch.object(target, "prepare_sdk"), \
             patch.object(target.builder, "build", side_effect=mismatched_build), \
             self.assertRaisesRegex(ValueError, "differs from frozen reference"):
            candidate.run(self.root, self.save(self.spec))
        out = self.root / "out/dnsmasq"
        report = json.loads((out / "manifest.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["checked_product_commit"], candidate.SOURCE_COMMIT)
        self.assertNotIn("accepted_product_commit", report)
        self.assertEqual((out / "dnsmasq-rs").read_bytes(), b"different actual ELF")
        for name in ("pgo/candidate.profdata", "pgo-compilation/dnsmasq-prestrip", "dnsmasq-2.93-r4.apk"):
            self.assertIn(name, report["retained"])
        self.assertEqual(json.loads((out / "build-spec.json").read_text()), self.spec)


if __name__ == "__main__":
    unittest.main()
