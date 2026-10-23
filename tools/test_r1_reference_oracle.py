"""Exact-release identity and private root-copy boundaries; no router or SDK."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import r1_reference_oracle as oracle


class RootCopyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        (self.source / "etc").mkdir(parents=True)
        self.release = self.source / "etc/openwrt_release"
        self.release.write_text("DISTRIB_RELEASE='25.12.6'\n")

    def test_release_maps_keep_the_original_pins_and_isolate_new_busybox(self):
        self.assertEqual(oracle.EXPECTED_ARTIFACTS["bin/busybox"], "54d4139265132254e5601cb65d8617a928d5d5867c044ef701d53b973daafe09")
        self.assertEqual(oracle.EXPECTED_RELEASE_ARTIFACTS["25.12.5"], oracle.EXPECTED_ARTIFACTS)
        new = oracle.EXPECTED_RELEASE_ARTIFACTS["25.12.6"]
        self.assertEqual(new["bin/busybox"], "aeeda86015e809106a5d247fd8504ac45e01bde0711f4d80af60fc2885ee923a")
        self.assertEqual({key: value for key, value in new.items() if key != "bin/busybox"},
                         {key: value for key, value in oracle.EXPECTED_ARTIFACTS.items() if key != "bin/busybox"})

    def test_unknown_release_and_wrong_artifact_hash_fail_before_copy(self):
        with patch.object(oracle.subprocess, "run") as copy:
            self.release.write_text("DISTRIB_RELEASE='25.12.7'\n")
            with self.assertRaisesRegex(SystemExit, "unsupported rootfs release"):
                oracle.prepare_rootfs(self.source, self.root / "copy")
            self.release.write_text("DISTRIB_RELEASE='25.12.6'\n")
            with patch.object(oracle, "sha256_file", return_value="0" * 64), \
                    self.assertRaisesRegex(SystemExit, "identity gate failed"):
                oracle.prepare_rootfs(self.source, self.root / "copy")
            copy.assert_not_called()

    def test_private_copy_preserves_fifo_and_refuses_existing_destination(self):
        expected = {}
        for relative in oracle.EXPECTED_ARTIFACTS:
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture:" + relative)
            expected[relative] = oracle.sha256_file(path)
        os.mkfifo(self.source / "fifo", 0o600)
        destination = self.root / "copy"
        with patch.dict(oracle.EXPECTED_RELEASE_ARTIFACTS, {"25.12.6": expected}):
            self.assertEqual(oracle.prepare_rootfs(self.source, destination, delivery_adapter=False), expected)
            self.assertTrue(stat.S_ISFIFO((destination / "fifo").stat().st_mode))
            self.assertEqual((destination / "fifo").stat().st_mode & 0o777, 0o600)
            self.assertEqual((destination / "bin/ubus").read_bytes(), (self.source / "bin/ubus").read_bytes())
            with self.assertRaises(FileExistsError):
                oracle.prepare_rootfs(self.source, destination, delivery_adapter=False)


if __name__ == "__main__":
    unittest.main()
