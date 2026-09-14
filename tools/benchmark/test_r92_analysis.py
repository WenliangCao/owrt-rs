#!/usr/bin/env python3
"""Negative controls for the final evidence download and archive gates."""
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest

from analyze_r92 import verified_archive, verified_files


class DownloadEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.raw = self.base / "raw"
        self.raw.mkdir()
        (self.raw / "sample").write_bytes(b"measured evidence")
        self.manifest = self.base / "download.sha256"
        self.line = hashlib.sha256(b"measured evidence").hexdigest() + "  ./sample\n"
        self.manifest.write_text(self.line)

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_then_modified_download(self):
        self.assertEqual(verified_files(self.raw, self.manifest)["verified_files"], 1)
        (self.raw / "sample").write_bytes(b"silently replaced result")
        with self.assertRaises(AssertionError):
            verified_files(self.raw, self.manifest)

    def test_extra_result_is_not_hidden_by_hash_manifest(self):
        (self.raw / "unlisted").write_bytes(b"another run")
        with self.assertRaises(AssertionError):
            verified_files(self.raw, self.manifest)

    def test_duplicate_and_escaping_names_are_rejected(self):
        for text in (self.line * 2, self.line.replace("./sample", "../raw/sample"),
                     self.line.replace("./sample", str(self.raw / "sample"))):
            self.manifest.write_text(text)
            with self.assertRaises(AssertionError):
                verified_files(self.raw, self.manifest)

    def test_symlink_is_not_accepted_as_downloaded_bytes(self):
        (self.raw / "sample").rename(self.base / "outside")
        (self.raw / "sample").symlink_to(self.base / "outside")
        with self.assertRaises(AssertionError):
            verified_files(self.raw, self.manifest)

    def test_archive_detects_changed_or_extra_extracted_data(self):
        archive = self.base / "raw.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(self.raw, arcname="raw")
        self.assertEqual(verified_archive(archive, self.raw)["verified_files"], 1)
        (self.raw / "extra").touch()
        with self.assertRaises(AssertionError):
            verified_archive(archive, self.raw)
        (self.raw / "extra").unlink()
        (self.raw / "sample").write_bytes(b"incorrect extraction")
        with self.assertRaises(AssertionError):
            verified_archive(archive, self.raw)


if __name__ == "__main__":
    unittest.main()
