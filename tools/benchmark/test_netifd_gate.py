#!/usr/bin/env python3
"""Exercise the actual shell gate with a proc tree lacking task/children."""
from pathlib import Path
import json
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


class ScaleFixtureTests(unittest.TestCase):
    def test_full_fixture_order_crosses_one_hundred_interfaces(self):
        script = Path(__file__).with_name("isolated.sh").read_text()
        function = re.search(r"    netifd_expect\(\).*?^    \}", script, flags=re.S | re.M).group()
        for count in (2, 32, 64, 128):
            digits = 3 if count == 128 else 2
            output = subprocess.check_output(["sh", "-c", function +
                '\nnetifd_digits=$1\nnetifd_expect "$2"', "fixture", str(digits), str(count)])
            interfaces = json.loads(output)["interface"]
            names = [i["interface"] for i in interfaces]
            self.assertEqual(len(names), count)
            self.assertEqual(names, sorted(set(names)))
            self.assertEqual(names[-2:], ["lan", "loopback"])
            for index, iface in enumerate(interfaces[:-2]):
                self.assertEqual(iface["ipv4-address"][0]["address"], f"198.18.{index}.1")


if __name__ == "__main__":
    unittest.main()
