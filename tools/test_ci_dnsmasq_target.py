"""Warning denial and failed-build evidence, without compiling a product."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ci_check_dnsmasq_target as target
from dnsmasq.compiler_warnings import scan


class TargetCheckTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_all_rust_cargo_and_unknown_warning_forms_fail(self):
        log = self.root / "compile.log"
        for text in ["warning: linker stderr: ERROR: ld.so: runas.so cannot be preloaded",
                     "warning: `dnsmasq-rs` (bin) generated 1 warning",
                     "warning[unused_variables]: unused variable",
                     "\x1b[1m\x1b[33mwarning\x1b[0m: dead code",
                     "src/main.rs:3:4: warning: unused variable",
                     "warning: unfamiliar diagnostic"]:
            with self.subTest(text=text):
                log.write_text(text + "\n")
                result = scan([log])
                self.assertFalse(result["strict_compiler_warnings_zero"])
                self.assertEqual(len(result["compiler_or_unclassified"]), 1)

    def test_sdk_kconfig_warnings_are_retained_separately(self):
        log = self.root / "prepare.log"
        log.write_text("WARNING: Makefile 'package/kernel/linux/Makefile' has a dependency on 'firmware', which does not exist\n"
                       "tmp/.config-package.in:7:warning: ignoring type redefinition\n"
                       "Config-build.in:2691:warning: defaults for choice values not supported\n"
                       "Makefile:798: WARNING: skipping libgomp -- package has no install section\n"
                       "    Finished `release` profile [optimized]\n")
        result = scan([log])
        self.assertTrue(result["strict_compiler_warnings_zero"])
        self.assertEqual([entry["line"] for entry in result["sdk_metadata"]], [1, 2, 3, 4])

    def test_only_exact_sdk_openssl_configuration_message_is_exempt(self):
        log = self.root / "compile.log"
        text = "WARNING: can't open config file: /builder/shared-workdir/build/staging_dir/host/etc/ssl/openssl.cnf"
        log.write_text(text + "\n")
        result = scan([log])
        self.assertTrue(result["strict_compiler_warnings_zero"])
        self.assertEqual(result["sdk_metadata"][0]["text"], text)
        for changed in [text.replace("WARNING:", "warning:"),
                        text.replace("/builder/shared-workdir/build/staging_dir/host/etc/ssl/", "/tmp/"),
                        "warning: linker stderr: " + text]:
            with self.subTest(text=changed):
                log.write_text(changed + "\n")
                self.assertFalse(scan([log])["strict_compiler_warnings_zero"])

    def test_frozen_source_archive_matches_current_revision(self):
        spec = target.source_spec()
        frozen = target.freeze_source(self.root, spec)
        files, digest = target.builder.source_identity(spec, frozen)
        self.assertEqual(files, target.builder.audit.inputs(target.builder.REPO))
        self.assertEqual(digest, spec["source_digest"])
        self.assertIn("components/dnsmasq/platform/src/lib.rs", files)
        (frozen / "components/dnsmasq/platform/src/lib.rs").write_text("changed")
        with self.assertRaisesRegex(ValueError, "differs"):
            target.builder.source_identity(spec, frozen)

    def test_successful_build_with_linker_warning_fails_and_retains_outputs(self):
        def successful_build(work, spec, report, **kwargs):
            out = work / "out/dnsmasq"
            (out / "compile.log").write_text("Compiling dnsmasq-platform\nCompiling dnsmasq-rs\n"
                                             "warning: linker stderr: host loader failed\n")
            (out / "payload/usr/sbin").mkdir(parents=True)
            (out / "payload/usr/sbin/dnsmasq").write_bytes(b"actual elf")
            (out / "dnsmasq-2.93-r4.apk").write_bytes(b"actual apk")
            report["accepted_product_commit"] = spec["source_commit"]
            report["accepted_product_git_commit"] = target.builder.resolve_commit(
                target.builder.REPO, spec["source_commit"])

        with patch.object(target.platform, "system", return_value="Linux"), \
             patch.object(target.platform, "machine", return_value="x86_64"), \
             patch.object(target, "freeze_source", return_value=self.root), \
             patch.object(target, "prepare_sdk"), \
             patch.object(target.builder, "build", side_effect=successful_build), \
             self.assertRaisesRegex(ValueError, "compiler warning"):
            target.run(self.root)
        out = self.root / "out/dnsmasq"
        report = json.loads((out / "manifest.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["checked_product_git_commit"], target.builder.resolve_commit(
            target.builder.REPO, report["checked_product_commit"]))
        self.assertFalse(report["warnings"]["strict_compiler_warnings_zero"])
        self.assertEqual((out / "dnsmasq-rs").read_bytes(), b"actual elf")
        self.assertIn("dnsmasq-2.93-r4.apk", report["retained"])
        self.assertTrue((out / "warnings.json").is_file())

    def test_compile_failure_keeps_partial_package_and_original_error(self):
        def failed_build(work, spec, report, **kwargs):
            out = work / "out/dnsmasq"
            (out / "compile.log").write_text("error: could not compile dnsmasq-rs\n")
            (out / "sdk-output").mkdir()
            (out / "sdk-output/dnsmasq-2.93-r4.apk").write_bytes(b"partial actual package")
            raise subprocess.CalledProcessError(2, ["make", "compile"])

        with patch.object(target.platform, "system", return_value="Linux"), \
             patch.object(target.platform, "machine", return_value="x86_64"), \
             patch.object(target, "freeze_source", return_value=self.root), \
             patch.object(target, "prepare_sdk"), \
             patch.object(target.builder, "build", side_effect=failed_build), \
             self.assertRaises(subprocess.CalledProcessError):
            target.run(self.root)
        out = self.root / "out/dnsmasq"
        report = json.loads((out / "manifest.json").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertIn("non-zero exit status 2", report["error"])
        self.assertEqual((out / "dnsmasq-2.93-r4.apk").read_bytes(), b"partial actual package")


if __name__ == "__main__":
    unittest.main()
