import tempfile
from pathlib import Path
import unittest

from r93_regressions import freeze_binaries, verify_binaries


class FrozenBinaries(unittest.TestCase):
    def test_shared_input_overwrite_cannot_change_active_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            binary = source / "ubusd-rs"
            binary.write_bytes(b"control")
            binary.chmod(0o755)
            frozen = root / "frozen"
            expected = freeze_binaries(source, frozen)
            binary.write_bytes(b"experiment")
            self.assertEqual((frozen / binary.name).read_bytes(), b"control")
            self.assertNotEqual(binary.stat().st_ino, (frozen / binary.name).stat().st_ino)
            self.assertEqual((frozen / binary.name).stat().st_mode & 0o222, 0)
            verify_binaries(frozen, expected)

    def test_changed_run_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "logd-rs").write_bytes(b"control")
            frozen = root / "frozen"
            expected = freeze_binaries(source, frozen)
            (frozen / "logd-rs").chmod(0o600)
            (frozen / "logd-rs").write_bytes(b"other")
            with self.assertRaisesRegex(RuntimeError, "identities changed"):
                verify_binaries(frozen, expected)


if __name__ == "__main__":
    unittest.main()
