#!/usr/bin/env python3
"""Exercise the actual shell gate with a proc tree lacking task/children."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class ChildReapingGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        script = Path(__file__).with_name("isolated.sh").read_text()
        self.function = re.search(r"    netifd_children_reaped\(\) \{.*?^    \}",
                                  script, flags=re.S | re.M).group()

    def process(self, pid, parent, state="S"):
        path = self.proc / str(pid)
        path.mkdir(exist_ok=True)
        (path / "status").write_text(f"Name:\tfixture with spaces\nState:\t{state}\nPPid:\t{parent}\n")

    def check(self):
        return subprocess.run(["sh", "-c", self.function + '\nsubject=42\nnetifd_children_reaped "$1"',
                               "gate", str(self.proc)], capture_output=True).returncode

    def test_live_and_zombie_children_must_be_reaped(self):
        self.process(42, 1)
        self.process(43, 42)
        self.assertNotEqual(self.check(), 0)
        self.process(43, 42, "Z")
        self.assertNotEqual(self.check(), 0)
        (self.proc / "43/status").unlink()
        self.assertEqual(self.check(), 0)

    def test_exact_parent_id_and_unrelated_processes(self):
        self.process(42, 1)
        self.process(43, 420)
        self.assertEqual(self.check(), 0)

    def test_unreadable_proc_tree_is_not_an_empty_child_list(self):
        self.assertNotEqual(self.check(), 0)


if __name__ == "__main__":
    unittest.main()
