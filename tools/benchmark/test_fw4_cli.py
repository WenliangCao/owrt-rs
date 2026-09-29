#!/usr/bin/env python3
"""Linux CLI checks for normalized fw4 validation and retained failure bytes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BENCH = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).parent / "target/debug/owrt-benchmark"
C = b"define lan_subnets = { 2001:db8::/64, fd00::/60 }\naccept\ndrop\n"
RUST = b"define lan_subnets = { fd00::/60, 2001:db8::/64 }\naccept\ndrop\n"


class Fw4CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reference = self.root / "c.stdout"
        self.actual = self.root / "rust.stdout"
        self.reference.write_bytes(C)
        self.actual.write_bytes(RUST)
        (self.root / "samples").mkdir()

    def measure(self, journal=True, program=None):
        env = {k: v for k, v in os.environ.items() if k not in ("OWRT_BENCH_EXEC_JOURNAL", "OWRT_BENCH_EXEC_ARTIFACTS")}
        if journal:
            env.update(OWRT_BENCH_EXEC_JOURNAL=str(self.root / "samples.jsonl"),
                       OWRT_BENCH_EXEC_ARTIFACTS=str(self.root / "samples"))
        return subprocess.run([str(BENCH), "exec-fw4", "2", "1", str(self.reference), "-", "--",
                               *(program or ["/bin/cat", str(self.actual)])], env=env, capture_output=True)

    def test_permutation_succeeds_and_every_sample_keeps_original_bytes(self):
        result = self.measure()
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual((data["successful"], data["warmup"], data["errors"]), (2, 1, 0))
        for i in range(3):
            self.assertEqual((self.root / f"samples/iteration-{i:06}/exec.stdout").read_bytes(), RUST)
        entries = [json.loads(line) for line in (self.root / "samples.jsonl").read_text().splitlines()]
        self.assertEqual([e["event"] for e in entries], ["started", "completed"] * 3)

    def test_wrong_membership_fails_against_c_and_keeps_failing_warmup(self):
        wrong = RUST.replace(b", 2001:db8::/64", b"")
        self.actual.write_bytes(wrong)
        result = self.measure()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual((self.root / "samples/iteration-000000/exec.stdout").read_bytes(), wrong)
        entries = [json.loads(line) for line in (self.root / "samples.jsonl").read_text().splitlines()]
        self.assertEqual((entries[-1]["event"], entries[-1]["phase"]), ("failed", "warmup"))

    def test_nonzero_exit_and_missing_evidence_are_rejected(self):
        result = self.measure(program=["/bin/sh", "-c", "echo diagnostic >&2; exit 9"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "samples/iteration-000000/exec.stderr").read_bytes(), b"diagnostic\n")
        result = self.measure(journal=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"requires a journal", result.stderr)

    def test_reference_comparison_accepts_order_but_rejects_environment_change(self):
        command = [str(BENCH), "fw4-compare", str(self.reference), str(self.actual)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.actual.write_bytes(RUST.replace(b"2001:db8::/64", b"2001:db8:1::/64"))
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.actual.write_bytes(RUST.replace(b"accept\ndrop", b"drop\naccept"))
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
