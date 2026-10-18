"""Preparation rejects mismatched identities before creating trial material."""
import io
import json
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest import mock

import odhcpd_trial_prepare as trial


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "tools").mkdir()
        shutil.copy2(trial.REPO / "tools/odhcpd_trial.sh", self.root / "tools/odhcpd_trial.sh")
        self.rootfs = self.root / "rootfs"
        for name, contents in (("usr/sbin/odhcpd", b"synthetic C reference"),
                               ("etc/init.d/odhcpd", b"synthetic init reference"),
                               ("usr/sbin/odhcpd-update", b"synthetic trigger reference")):
            path = self.rootfs / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        self.candidate = self.root / "candidate"
        self.helper = self.root / "helper"
        self.candidate.write_bytes(self.elf() + b"candidate")
        self.helper.write_bytes(self.elf() + b"helper")
        self.backup = self.root / "backup.tar.gz"
        self.backup_config()
        for field, value in (("REPO", self.root), ("C_SHA", trial.sha(self.rootfs / "usr/sbin/odhcpd")),
                             ("INIT_SHA", trial.sha(self.rootfs / "etc/init.d/odhcpd")),
                             ("TRIGGER_SHA", trial.sha(self.rootfs / "usr/sbin/odhcpd-update"))):
            patch = mock.patch.object(trial, field, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.output = self.root / "private/trial"

    @staticmethod
    def elf(interpreter=False):
        data = bytearray(120)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", data, 16, 2, 183)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<I", data, 64, 3 if interpreter else 1)
        return bytes(data)

    def backup_config(self, names=("dhcp", "network", "system")):
        with tarfile.open(self.backup, "w:gz") as archive:
            for name in names:
                data = b"config fixture\n"
                member = tarfile.TarInfo("etc/config/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def prepare(self, **changes):
        args = dict(candidate=self.candidate, candidate_sha=trial.sha(self.candidate), rootfs=self.rootfs,
                    backup=self.backup, backup_sha=trial.sha(self.backup), helper=self.helper,
                    helper_sha=trial.sha(self.helper), boot="11111111-2222-3333-4444-555555555555",
                    output=self.output)
        args.update(changes)
        return trial.prepare(**args)

    def test_bundle_is_private_bound_and_not_deployed(self):
        before = self.backup.read_bytes()
        receipt = self.prepare()
        self.assertEqual(receipt["status"], "prepared_not_deployed")
        self.assertTrue(receipt["confirmation_restores_C"])
        self.assertEqual(receipt["config_files"], 3)
        self.assertEqual(self.backup.read_bytes(), before)
        self.assertEqual((self.output / "config-backup.tar.gz").read_bytes(), before)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(trial.sha(self.output / "bundle.sha256"), receipt["bundle_manifest_sha256"])
        for line in (self.output / "bundle.sha256").read_text().splitlines():
            digest, name = line.split()
            self.assertEqual(trial.sha(self.output / name), digest)
        self.assertEqual(json.loads((self.output / "receipt.json").read_text()), receipt)

    def test_mismatch_or_wrong_boot_never_creates_output(self):
        for changes in ({"candidate_sha": "0" * 64}, {"backup_sha": "0" * 64},
                        {"helper_sha": "0" * 64}, {"boot": "not-a-boot"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.prepare(**changes)
            self.assertFalse(self.output.exists())

    def test_dynamic_candidate_missing_backup_and_public_output_are_refused(self):
        self.candidate.write_bytes(self.elf(interpreter=True))
        with self.assertRaisesRegex(ValueError, "dynamic loader"):
            self.prepare()
        self.candidate.write_bytes(self.elf())
        self.backup_config(names=("dhcp",))
        with self.assertRaisesRegex(ValueError, "lacks"):
            self.prepare()
        with self.assertRaisesRegex(ValueError, "ignored private"):
            self.prepare(output=self.root / "public-output")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
