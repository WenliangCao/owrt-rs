"""The exact-image container allowlist never relaxes file or runner checks."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns_udp_refusal_diff as reference


OLD_IMAGE = "144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720"
NEW_IMAGE = "286dbbaf16588c22daeaf6dbc8ca02573a1c30fbeb8592e3ba58b865c8726043"


class ExactReferenceIdentity(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.files = {}
        for name in reference.TARGET_FILES:
            data = name.encode()
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            self.files[name] = hashlib.sha256(data).hexdigest()
        self.runner = self.root / "dnsmasq-image-runner"
        self.runner.write_text(
            f'#!/bin/sh\nexec {self.root}/lib/libc.so --library-path {self.root}/lib '
            f'{self.root}/usr/sbin/dnsmasq "$@"\n')
        self.identity = self.root / "image-identity.json"
        # Small test payloads replace expected file hashes, while the actual
        # production image allowlist remains in force in every test below.
        changed = patch.dict(reference.TARGET_FILES, self.files, clear=True)
        changed.start()
        self.addCleanup(changed.stop)

    def describe(self, image):
        self.identity.write_text(json.dumps({
            "canonical_image_sha256": image,
            "files": {name: {"sha256": value} for name, value in self.files.items()},
            "runner_sha256": hashlib.sha256(self.runner.read_bytes()).hexdigest(),
        }))

    def test_both_reviewed_images_keep_all_file_checks(self):
        for image in (OLD_IMAGE, NEW_IMAGE):
            with self.subTest(image=image):
                self.describe(image)
                self.assertEqual(reference.verify_reference(self.runner, self.identity)["kind"],
                                 "image-aarch64-musl")

    def test_unknown_container_is_rejected_even_with_matching_files(self):
        self.describe("0" * 64)
        with self.assertRaisesRegex(AssertionError, "unreviewed exact reference image"):
            reference.verify_reference(self.runner, self.identity)

    def test_new_container_rejects_modified_loader_and_runner(self):
        self.describe(NEW_IMAGE)
        loader = self.root / "lib/libc.so"
        old = loader.read_bytes()
        loader.write_bytes(old + b"changed")
        with self.assertRaises(AssertionError):
            reference.verify_reference(self.runner, self.identity)
        loader.write_bytes(old)
        self.runner.write_text('#!/bin/sh\nexec /usr/sbin/dnsmasq "$@"\n')
        self.describe(NEW_IMAGE)
        with self.assertRaisesRegex(AssertionError, "unexpected target runner"):
            reference.verify_reference(self.runner, self.identity)


if __name__ == "__main__":
    unittest.main()
