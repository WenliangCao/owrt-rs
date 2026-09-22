#!/usr/bin/env python3
"""Critical validity checks for the R131 supplement, using synthetic inputs."""
import copy
import unittest
from r131_latency_report import LANES, METRICS, sample_metrics, verdict


class LatencyReportTest(unittest.TestCase):
    def setUp(self):
        self.data = {"n": 100, "warmup": 20, "listeners": 8, "matched": True,
                     "subject_pid": 10, "client_pid": 11, "subject_cpu": 1, "client_cpu": 0,
                     "payload_checked": True, "handlers_removed": True, "received": 800,
                     "warmup_received": 160, "held_clients": 0, "held_fds": 5, "base_fds": 5,
                     "latency_clock": "CLOCK_MONOTONIC", "latency_sample_count": 100,
                     "latency_scope": "send_through_all_callbacks_or_unmatched_drain",
                     "latency_overhead_unsubtracted": True, "subject_resolution_ns": 1,
                     "client_resolution_ns": 1, "latency_resolution_ns": 1,
                     "latency_ns": list(range(1000, 101000, 1000)),
                     "wall_before_ns": 1, "wall_after_ns": 10000001,
                     "subject_before_ns": 1, "subject_after_ns": 1000001,
                     "client_before_ns": 1, "client_after_ns": 1000001}

    def test_percentiles_use_raw_samples(self):
        metrics = sample_metrics(self.data, 100, 20, "user_8_1", 10)
        self.assertEqual(metrics["mean_us"], 50.5)
        self.assertEqual(metrics["p50_us"], 51)
        self.assertEqual(metrics["p95_us"], 95)
        self.assertEqual(metrics["p99_us"], 99)

    def test_missing_or_invalid_samples_are_rejected(self):
        for value in ([], [-1] * 100, [1.] * 100, [True] * 100):
            data = copy.deepcopy(self.data)
            data["latency_ns"] = value
            with self.assertRaises(ValueError):
                sample_metrics(data, 100, 20, "user_8_1", 10)

    def test_tail_regression_prevents_acceptance_despite_mean_gain(self):
        comparisons = {lane: {metric: {"all_lower": True, "all_higher": False, "median_delta_pct": -20}
                              for metric in METRICS} for lane in LANES}
        self.assertEqual(verdict(comparisons)["verdict"], "pass_latency_supplement")
        comparisons["user_8_1"]["p99_us"]["median_delta_pct"] = 5.1
        self.assertEqual(verdict(comparisons)["verdict"], "not_accepted")


if __name__ == "__main__":
    unittest.main()
