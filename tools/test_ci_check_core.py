"""An ImageBuilder metadata diagnostic must never exempt compiler warnings."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from ci_check_core import warnings


class WarningBoundaryTests(unittest.TestCase):
    INDEX = ("WARNING: opening /work/openwrt-imagebuilder-25.12.5-mediatek-filogic.Linux-x86_64/"
             "packages/packages.adb: No such file or directory")

    def classify(self, name, text):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / name
            log.write_text(text + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                return warnings(root / "warnings.json", [log])

    def test_initial_local_index_is_metadata_only_in_the_image_log(self):
        accepted = self.classify("image.log", self.INDEX)
        self.assertTrue(accepted["strict_compiler_warnings_zero"])
        self.assertEqual(len(accepted["sdk_metadata"]), 1)
        rejected = self.classify("compile.log", self.INDEX)
        self.assertFalse(rejected["strict_compiler_warnings_zero"])
        self.assertEqual(len(rejected["compiler_or_unclassified"]), 1)

    def test_other_missing_paths_and_compiler_warnings_still_fail(self):
        for text in [self.INDEX.replace("packages.adb", "other.adb"),
                     self.INDEX.replace("openwrt-imagebuilder-", "openwrt-sdk-"),
                     "warning: linker stderr: " + self.INDEX,
                     self.INDEX + "\nwarning: an actual compiler diagnostic"]:
            with self.subTest(text=text):
                self.assertFalse(self.classify("image.log", text)["strict_compiler_warnings_zero"])


if __name__ == "__main__":
    unittest.main()
