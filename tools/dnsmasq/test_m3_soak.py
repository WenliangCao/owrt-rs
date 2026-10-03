#!/usr/bin/env python3
"""Regression checks for resource-window accounting and bounded runner cleanup."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from m3_soak import resource_summary, run_accepted, run_parallel, sample, stop_process_group


class CollectionAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.cleanup = {"daemon_alive_after_stop": False, "ubusd_alive_after_stop": False,
                        "lease_rows_after_stop": 0, "dhcp_socket_closed": True,
                        "tcp_clients_closed": True, "udp_clients_closed": True}

    def test_resource_window_does_not_require_m2_functional_coverage(self):
        # A 12-hour lease cannot expire inside a five-minute smoke or hour soak.
        self.assertTrue(run_accepted([], self.cleanup, 300, 300, 300.01, 300))
        self.assertTrue(run_accepted([], self.cleanup, 3600, 3600, 3600.01, 3600))

    def test_counts_alone_cannot_replace_wall_clock_duration(self):
        self.assertFalse(run_accepted([], self.cleanup, 3600, 3600, 3599.0, 3600))
        self.assertFalse(run_accepted([], self.cleanup, 3599, 3600, 3600.1, 3600))

    def test_missing_samples_errors_and_unclean_exit_fail(self):
        self.assertFalse(run_accepted(["query failed"], self.cleanup, 300, 300, 300, 300))
        for key, value in (("daemon_alive_after_stop", True), ("ubusd_alive_after_stop", True),
                           ("lease_rows_after_stop", 1), ("dhcp_socket_closed", False),
                           ("tcp_clients_closed", False), ("udp_clients_closed", False)):
            with self.subTest(key=key):
                self.assertFalse(run_accepted([], dict(self.cleanup, **{key: value}),
                                              300, 300, 300, 300))

    def test_summary_separates_warmup_from_second_half(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.jsonl"
            path.write_text("".join(json.dumps({"rss_kib": value}) + "\n"
                                    for value in (100, 120, 160, 190, 200, 200, 200, 200)))
            summary = resource_summary(path)
        self.assertEqual(summary["rss_kib"]["third_quarter_median"], 200)
        self.assertEqual(summary["rss_kib"]["fourth_quarter_median"], 200)
        self.assertEqual(summary["fd_count"], {"missing_samples": 8})

    def test_missing_resource_or_cache_fields_fail_sampling(self):
        resources = {"alive": True, "rss_kib": 100, "pss_kib": 90,
                     "fd_count": 5, "thread_count": 1, "child_processes": 0}
        metrics = {"dns_cache_inserted": 10, "dns_cache_live_freed": 0}
        product = SimpleNamespace(process=SimpleNamespace(pid=123))
        for source, keys in (("resources", tuple(resources)[1:]), ("metrics", tuple(metrics))):
            for key in keys:
                for missing in (None, "unknown"):
                    with self.subTest(source=source, key=key, missing=missing):
                        values = dict(resources)
                        counters = dict(metrics)
                        (values if source == "resources" else counters)[key] = missing
                        product.metrics = lambda: counters
                        with patch("m3_soak.proc_resources", return_value=values):
                            with self.assertRaisesRegex(RuntimeError, key):
                                sample(product, 0)


@unittest.skipUnless(os.name == "posix", "process groups require POSIX")
class ParallelCleanupTests(unittest.TestCase):
    def test_pair_starts_both_sides_before_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            script = (
                "import pathlib,sys,time\n"
                "p=pathlib.Path(sys.argv[1]);p.touch();deadline=time.monotonic()+3\n"
                "while not pathlib.Path(sys.argv[2]).exists():\n"
                " if time.monotonic()>deadline: raise SystemExit(3)\n"
                " time.sleep(.01)\n"
            )
            records = [{"implementation": side,
                        "argv": [sys.executable, "-c", script, str(out / side), str(out / peer)]}
                       for side, peer in (("c", "rust"), ("rust", "c"))]
            run_parallel(records, out, 5)
        self.assertEqual([record["returncode"] for record in records], [0, 0])
        self.assertFalse(any(record["timed_out"] for record in records))

    def test_timeout_and_force_kill_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            records = [{"implementation": "stuck", "argv": [sys.executable, "-c", "import time;time.sleep(30)"]}]
            run_parallel(records, Path(directory), .1)
        self.assertTrue(records[0]["timed_out"])
        self.assertNotEqual(records[0]["returncode"], 0)
        with self.assertRaises(ProcessLookupError):
            os.killpg(records[0]["pid"], 0)

    def test_term_ignoring_runner_is_killed_and_reaped(self):
        process = subprocess.Popen([
            sys.executable, "-c",
            'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(30)',
        ], stdout=subprocess.PIPE, text=True, start_new_session=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            stop_process_group(process, grace_seconds=.05)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            with self.assertRaises(ProcessLookupError):
                os.killpg(process.pid, 0)
        finally:
            stop_process_group(process, grace_seconds=.05)
            process.stdout.close()

    def test_launch_failure_cleans_already_started_side(self):
        with tempfile.TemporaryDirectory() as directory:
            records = [{"implementation": "c", "argv": [sys.executable, "-c", "import time;time.sleep(30)"]},
                       {"implementation": "rust", "argv": ["/missing-m3-runner-regression"]}]
            with self.assertRaises(FileNotFoundError):
                run_parallel(records, Path(directory), 5)
            with self.assertRaises(ProcessLookupError):
                os.killpg(records[0]["pid"], 0)


if __name__ == "__main__":
    unittest.main()
