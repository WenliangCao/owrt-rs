#!/usr/bin/env python3
"""Reject invalid registration diagnostics before interpreting them."""
import copy
from pathlib import Path
import tempfile
import unittest

import r132_registration_profile as subject


class RegistrationProfileValidation(unittest.TestCase):
    def counter_file(self, directory):
        path = Path(directory) / "perf.csv"
        path.write_text("\n".join(f"100;;{event};100000;100.00;;" for event in subject.COUNTERS[:-1]) +
                        "\n0;;cpu-migrations;100000;100.00;;\n")
        return path

    def test_complete_unscaled_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.counter_file(directory)
            self.assertEqual(set(subject.stat_counts(path, subject.COUNTERS)), set(subject.COUNTERS))

    def test_multiplex_unavailable_duplicate_and_migration_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.counter_file(directory)
            original = path.read_text()
            corruptions = [original.replace("100.00", "99.90", 1),
                           original.replace("100;", "<not supported>;", 1),
                           original + original.splitlines()[0] + "\n",
                           original.replace("0;;cpu-migrations", "1;;cpu-migrations")]
            for text in corruptions:
                with self.subTest(text=text[:50]):
                    path.write_text(text)
                    with self.assertRaises(RuntimeError):
                        subject.stat_counts(path, subject.COUNTERS)

    def client_result(self):
        item = {"n": 2, "warmup": 20, "methods": 1, "name_bytes": 8}
        data = {**item, "subject_pid": 123, "client_pid": 456, "subject_cpu": 1, "client_cpu": 0,
                "fixture": "rust_register_cycle", "successful": 2, "errors": 0, "latency_sample_count": 2,
                "latency_ns": [100, 120], "subject_before_ns": 1000, "subject_after_ns": 1100,
                "client_before_ns": 2000, "client_after_ns": 2080, "wall_before_ns": 3000, "wall_after_ns": 3300,
                "subject_resolution_ns": 1, "client_resolution_ns": 1, "perf_controlled": True,
                "full_signature_checked": True, "warmup_empty": True, "final_empty": True,
                "wire_reply_bytes_checked": False}
        return item, data

    def test_valid_client_clocks(self):
        item, data = self.client_result()
        self.assertEqual(subject.validate_client(data, item, 123, 456), {"subject": 100, "client": 80, "wall": 300})

    def test_identity_or_clock_failures_rejected(self):
        item, original = self.client_result()
        for key, value in (("client_pid", 789), ("final_empty", False), ("perf_controlled", False),
                           ("subject_after_ns", 1400), ("client_after_ns", 2400),
                           ("latency_ns", [100, 201]), ("wire_reply_bytes_checked", True)):
            with self.subTest(key=key):
                data = copy.deepcopy(original); data[key] = value
                with self.assertRaises(RuntimeError):
                    subject.validate_client(data, item, 123, 456)

    def test_templates_keep_profile_and_counts_separate(self):
        for mode, count in (("profile", 300000), ("stat", 100000)):
            plan = subject.template(mode)
            self.assertEqual(len(plan["runs"]), 12)
            self.assertEqual({run["n"] for run in plan["runs"]}, {count})
            self.assertEqual({run["warmup"] for run in plan["runs"]}, {5000})
            self.assertNotIn("stat" if mode == "profile" else "profile", plan)


if __name__ == "__main__":
    unittest.main()
