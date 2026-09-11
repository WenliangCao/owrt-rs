#!/usr/bin/env python3
"""Guard the shared CPU interval and failed-run checks in HTTPD aggregation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import analyze_candidate as analyze_httpd


class ParallelIntervalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put("group.json", {"clients": 4, "iterations_per_client": 25, "warmup_per_client": 5})
        self.before = {"uptime_s": 100, "clock_ticks_per_second": 100, "processes": [
            {"pid": 42, "start_ticks": 10, "cpu_ticks": 100, "child_cpu_ticks": 10}]}
        self.after = {"uptime_s": 101, "clock_ticks_per_second": 100, "processes": [
            {"pid": 42, "start_ticks": 10, "cpu_ticks": 110, "child_cpu_ticks": 12}]}
        self.put("before.json", self.before)
        self.put("after.json", self.after)
        self.clients = [{"successful": 25, "warmup": 5,
                         "latency_ns": [n * 1000 for n in range(i * 25, (i + 1) * 25)],
                         "client_cpu_s": .002,
                         # These overlap. A sum of them is deliberately very
                         # different from the one outer 0.12-second interval.
                         "daemon_cpu": [{"pid": 42, "cpu_s": 100, "child_cpu_s": 100}]}
                        for i in range(4)]

    def put(self, name, data):
        (self.root / name).write_text(json.dumps(data))

    def test_shared_cpu_is_counted_once_and_warmup_has_a_denominator(self):
        with patch.object(analyze_httpd, "native", side_effect=self.clients):
            result = analyze_httpd.parallel(self.root, 42)
        self.assertEqual(result["successful"], 100)
        self.assertEqual(result["warmup"], 20)
        self.assertEqual(result["subject_cpu_us_per_op"], 1000)
        self.assertEqual(result["ops_per_s"], 100)
        self.assertEqual(result["mean_us"], 49.5)
        self.assertEqual(result["p95_us"], 94)
        self.assertEqual(result["p99_us"], 98)

    def test_replaced_server_invalidates_the_group(self):
        self.after["processes"][0]["start_ticks"] = 99
        self.put("after.json", self.after)
        with patch.object(analyze_httpd, "native", side_effect=self.clients), self.assertRaises(AssertionError):
            analyze_httpd.parallel(self.root, 42)

    def test_missing_operations_in_one_client_invalidate_the_group(self):
        self.clients[2]["successful"] = 24
        with patch.object(analyze_httpd, "native", side_effect=self.clients), self.assertRaises(AssertionError):
            analyze_httpd.parallel(self.root, 42)

    def test_client_diagnostic_cannot_be_published_as_the_regular_matrix(self):
        (self.root / "COMPLETE").touch()
        self.put("order.json", ["stock", "candidate"])
        self.put("subjects.json", {})
        self.put("settings.json", {"component": "rpcd", "rpc_client_diagnostic": True})
        with self.assertRaisesRegex(AssertionError, "diagnostics cannot be published"):
            analyze_httpd.derive(self.root, "not-a-performance-result")


if __name__ == "__main__":
    unittest.main()
