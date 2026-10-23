#!/usr/bin/env python3
"""CLI failure boundaries for the versioned offline FIT check."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).resolve().with_name("check_ax3000t_fit.py")


class FitCheckArguments(unittest.TestCase):
    def reject(self, *arguments):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "output"
            result = subprocess.run(
                [sys.executable, "-B", str(CHECKER), "--imagebuilder", str(root),
                 "--output", str(output), *arguments],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(output.exists(), "invalid inputs must not create an evidence run")
            return result.stderr

    def test_unreviewed_version_is_rejected_before_tools_or_output(self):
        self.assertIn("no reviewed AX3000T FIT inputs",
                      self.reject("--openwrt-version", "unreviewed"))

    def test_both_reviewed_versions_require_an_executable_mkimage(self):
        for version in ("25.12.5", "25.12.6"):
            with self.subTest(version=version):
                self.assertIn("mkimage is not executable",
                              self.reject("--openwrt-version", version))


if __name__ == "__main__":
    unittest.main()
