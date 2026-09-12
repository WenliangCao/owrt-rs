#!/usr/bin/env python3
"""Reject setup work masquerading as read-only netifd query performance."""
import json
from pathlib import Path
import tempfile
import unittest

from analyze_candidate import check_netifd_hotplug


class HotplugCompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.events = self.root / "hotplug-settled-2.txt"
        self.events.write_text("lan ifup 0\nloopback ifup 0\n")
        self.before = {"processes": [{"pid": 42, "start_ticks": 10, "child_cpu_ticks": 99}]}
        self.after = {"processes": [{"pid": 42, "start_ticks": 10, "child_cpu_ticks": 99}]}

    def check(self):
        for phase, data in (("before", self.before), ("after", self.after)):
            (self.root / f"hotplug-settled-2-{phase}.json").write_text(json.dumps(data))
        check_netifd_hotplug(self.root, 42, 2, ["lan", "loopback"])

    def test_all_callbacks_finished_and_reaped(self):
        self.check()

    def test_missing_or_duplicate_completion_is_rejected(self):
        for text in ("lan ifup 0\n", "lan ifup 0\nlan ifup 0\nloopback ifup 0\n"):
            with self.subTest(text=text):
                self.events.write_text(text)
                with self.assertRaisesRegex(AssertionError, "incomplete or duplicate"):
                    self.check()

    def test_failed_callback_is_not_completion(self):
        self.events.write_text("lan ifup 0\nloopback ifup 1\n")
        with self.assertRaisesRegex(AssertionError, "callback failed"):
            self.check()

    def test_running_setup_cpu_is_rejected(self):
        self.after["processes"][0]["child_cpu_ticks"] += 1
        with self.assertRaisesRegex(AssertionError, "children still running"):
            self.check()

    def test_restarted_daemon_is_rejected(self):
        self.after["processes"][0]["start_ticks"] += 1
        with self.assertRaisesRegex(AssertionError, "restarted"):
            self.check()


if __name__ == "__main__":
    unittest.main()
