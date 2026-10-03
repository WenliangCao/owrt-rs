#!/usr/bin/env python3
"""Local failure-boundary checks; no SDK commands or network access."""
from pathlib import Path
import copy
import json
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

import build_package as package
import m4_package_lifecycle as lifecycle


class PackageBuildTests(unittest.TestCase):
    def test_failed_build_restores_existing_recipe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root / "sdk"
            active = sdk / "package/owrt-dnsmasq"
            active.mkdir(parents=True)
            (active / "old").write_text("preserve")
            source = root / "source"
            source.mkdir()
            (source / "Makefile").write_text("current")
            report = {}
            with self.assertRaisesRegex(ValueError, "deliberate build failure"):
                with package.package_recipe(sdk, source, root / "output", report):
                    self.assertEqual((active / "Makefile").read_text(), "current")
                    self.assertEqual((sdk / ".dnsmasq-backup-output/old").read_text(), "preserve")
                    self.assertEqual([p.name for p in (sdk / "package").iterdir()], ["owrt-dnsmasq"])
                    raise ValueError("deliberate build failure")
            self.assertEqual([p.name for p in active.iterdir()], ["old"])
            self.assertEqual((active / "old").read_text(), "preserve")
            self.assertTrue(report["sdk_recipe_restored"])

    def test_failed_copy_restores_existing_recipe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            active = root / "sdk/package/owrt-dnsmasq"
            active.mkdir(parents=True)
            (active / "old").write_text("preserve")
            with patch.object(package.shutil, "copytree", side_effect=OSError("copy failure")):
                with self.assertRaises(OSError):
                    with package.package_recipe(root / "sdk", root / "source", root / "output", {}):
                        self.fail("failed copy entered the build")
            self.assertEqual((active / "old").read_text(), "preserve")

    def test_payload_rejects_extra_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in package.REPLACEMENT_FILES | {
                "lib/apk/packages/dnsmasq.conffiles",
                "lib/apk/packages/dnsmasq.conffiles_static",
                "lib/apk/packages/dnsmasq.list",
                "lib/apk/packages/dnsmasq.rusers",
                "lib/upgrade/keep.d/dnsmasq",
            }:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"fixture")
            listing = root / "lib/apk/packages/dnsmasq.list"
            listing.write_text("\n".join(package.OWNERSHIP_LIST) + "\n")
            self.assertEqual(len(package.audit_payload(root)), len(package.PAYLOAD_FILES))
            extra = root / "usr/libexec/extra"
            extra.parent.mkdir(parents=True)
            extra.write_text("unexpected")
            with self.assertRaises(ValueError):
                package.audit_payload(root)
            extra.unlink()
            extra.symlink_to("dnsmasq-rs")
            with self.assertRaises(ValueError):
                package.audit_payload(root)

    def test_make_path_rejects_shell_and_make_metacharacters(self):
        for path in ("/tmp/a b", "/tmp/a;id", "/tmp/$(id)", "/tmp/a\nb", "/tmp/a#b"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                package.safe_path(Path(path))

    def test_exceeded_size_targets_keep_both_measurements(self):
        report = {"artifact": {"size": 801_000}, "elf": {"size": 1_200_000},
                  "budget": {"apk_max_bytes": 800_000, "elf_max_bytes": 700_000}}
        with self.assertRaisesRegex(ValueError, "APK size 801000.*ELF size 1200000"):
            package.audit_sizes(report)
        self.assertEqual(report["budget_checks"], {"apk": False, "elf": False})
        self.assertEqual(report["elf"]["size"], 1_200_000)

    def test_candidate_metadata_requires_actual_lifecycle_scripts(self):
        metadata = """info:
  name: dnsmasq
  version: 2.93-r2
  arch: aarch64_cortex-a53
  depends: # 2 items
    - libc
    - libubus20251202
  provides: # 1 items
    - dnsmasq-any
scripts:
  post-install: |
  pre-deinstall: |
  post-upgrade: |
"""
        self.assertEqual(package.audit_metadata(metadata)["version"], "2.93-r2")
        for script in ("post-install", "pre-deinstall", "post-upgrade"):
            with self.subTest(script=script), self.assertRaisesRegex(ValueError, script):
                package.audit_metadata(metadata.replace(f"  {script}: |\n", ""))


class PackageLifecycleTests(unittest.TestCase):
    def test_database_rejects_duplicate_package_and_escaping_path(self):
        base = "P:dnsmasq\nV:2.93-r1\nF:usr/sbin\nR:dnsmasq\n"
        with self.assertRaisesRegex(RuntimeError, "duplicate package"):
            lifecycle.installed_packages(base + "\n" + base)
        with self.assertRaisesRegex(RuntimeError, "unsafe path"):
            lifecycle.installed_packages(base.replace("R:dnsmasq", "R:../../../outside"))

    def test_upgrade_requires_new_version_and_exclusive_ownership(self):
        baseline = {
            "dnsmasq": {"version": "2.93-r1", "files": sorted(package.PAYLOAD_FILES)},
            "libc": {"version": "1", "files": ["lib/libc.so"]},
        }
        with self.assertRaisesRegex(RuntimeError, "wrong dnsmasq version"):
            lifecycle.assert_database(baseline, "2.93-r2", baseline)
        current = copy.deepcopy(baseline)
        current["dnsmasq"]["version"] = "2.93-r2"
        lifecycle.assert_database(current, "2.93-r2", baseline)
        current["libc"]["version"] = "2"
        with self.assertRaisesRegex(RuntimeError, "another installed package"):
            lifecycle.assert_database(current, "2.93-r2", baseline)
        baseline["libc"]["files"].append("usr/sbin/dnsmasq")
        current = copy.deepcopy(baseline)
        current["dnsmasq"]["version"] = "2.93-r2"
        with self.assertRaisesRegex(RuntimeError, "duplicate file owner"):
            lifecycle.assert_database(current, "2.93-r2", baseline)

    def test_missing_variant_dependency_is_not_conflict_evidence(self):
        result = {"returncode": 1, "stdout": "", "stderr":
                  "dnsmasq-full-2.93-r1: conflicts: dnsmasq-2.93-r2\n"}
        lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] += "libnettle (no such package)\n"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            lifecycle.assert_variant_rejected(result, "dnsmasq-full")
        result["stderr"] = "APK archive is corrupt\n"
        with self.assertRaisesRegex(RuntimeError, "without evidence"):
            lifecycle.assert_variant_rejected(result, "dnsmasq-full")

    def test_timed_out_script_is_forcibly_reaped_and_failure_logged(self):
        with tempfile.TemporaryDirectory() as temp:
            root, log = Path(temp), Path(temp) / "timeout.json"
            argv = [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]
            with patch.object(lifecycle, "command", return_value=argv):
                with self.assertRaisesRegex(RuntimeError, "timed out"):
                    lifecycle.invoke(root, ["unused"], log, timeout=.5)
            result = json.loads(log.read_text())
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["returncode"], -signal.SIGKILL)

    def test_failure_record_does_not_suppress_apk_scripts(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "failed.json"
            process = unittest.mock.Mock()
            process.communicate.return_value = ("", "post-install failed")
            process.returncode = 1
            with patch.object(lifecycle.subprocess, "Popen", return_value=process) as popen:
                with self.assertRaisesRegex(RuntimeError, "command failed"):
                    lifecycle.invoke(Path(temp), ["/usr/bin/apk", "add", "candidate.apk"], log)
            environment = popen.call_args.kwargs["env"]
            self.assertNotIn("IPKG_INSTROOT", environment)
            self.assertNotIn("IPKG_NO_SCRIPT", environment)
            self.assertEqual(json.loads(log.read_text())["returncode"], 1)


if __name__ == "__main__":
    unittest.main()
