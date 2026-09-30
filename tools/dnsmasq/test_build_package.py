#!/usr/bin/env python3
"""Local failure-boundary checks; no SDK commands or network access."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_package as package


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
            (root / "usr/libexec").mkdir(parents=True)
            (root / "usr/libexec/dnsmasq-rs").write_bytes(b"ELF fixture")
            (root / "lib/apk/packages").mkdir(parents=True)
            (root / "lib/apk/packages/owrt-dnsmasq.list").write_text("/usr/libexec/dnsmasq-rs\n")
            self.assertEqual(len(package.audit_payload(root)), 2)
            extra = root / "usr/libexec/extra"
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


if __name__ == "__main__":
    unittest.main()
