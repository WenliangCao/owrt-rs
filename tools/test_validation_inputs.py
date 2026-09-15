"""The historical gate must reject missing fixtures before a partial run."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from r92_validate import example_inputs


class ValidationInputs(unittest.TestCase):
    def test_recovery_requires_output_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "output_lifecycle"):
                example_inputs({"r92-recovery"}, Path(directory))

    def test_partial_selection_records_only_used_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            examples = Path(directory)
            notifier = examples / "notifier"
            notifier.write_bytes(b"fixture")
            notifier.chmod(0o700)
            self.assertEqual(example_inputs({"httpd-extended", "procd-r65"}, examples),
                             {"notifier": hashlib.sha256(b"fixture").hexdigest()})
            notifier.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "non-executable"):
                example_inputs({"httpd-extended"}, examples)

    def test_unit_selection_needs_no_runtime_examples(self):
        self.assertEqual(example_inputs({"procd-unit", "procd-clippy"}, Path("/absent")), {})


if __name__ == "__main__":
    unittest.main()
