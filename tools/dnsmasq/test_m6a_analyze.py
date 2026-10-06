#!/usr/bin/env python3
"""Independent arithmetic/evidence guards using small hand-counted streams."""
import json
from pathlib import Path
import struct
import tempfile
import unittest

import m6a_analyze as analyze
from dns_service_probe import query, rr


def save(path, value):
    path.write_text(json.dumps(value))


def fixture(directory):
    directory.mkdir(parents=True)
    start, middle, end = 1_000_000_000, 91_000_000_000, 121_000_000_000
    base = 1 << 32
    # Three steady successes: the last crosses into saturation. Two saturation
    # successes: the last completes after the entire window. Wrong/timeout
    # records never contribute to QPS or successful latency percentiles.
    rows = [(1, 10_000_000, start + 1_000_000_000, 0, 1, 0, 1, 0, 0),
            (2, 100_000_000, start + 2_000_000_000, 0, 1, 0, 1, 0, 0),
            (3, 200_000_000, middle - 100_000_000, 0, 1, 0, 1, 0, 0),
            (4, 50_000_000, middle + 100_000_000, 0, 1, 0, 2, 0, 0),
            (5, 200_000_000, end - 100_000_000, 0, 1, 0, 2, 0, 0),
            (6, 1_000_000_000, start + 3_000_000_000, 0, 1, 1, 1, 0, 0),
            (7, 1, start + 4_000_000_000, 0, 1, 2, 1, 0, 0)]
    (directory / "load.latencies.bin").write_bytes(b"".join(analyze.LATENCY.pack(base + row[0], *row[1:]) for row in rows))
    (directory / "load.send-lag.bin").write_bytes(b"".join(analyze.LAG.pack(base + row[0], 1000) for row in rows))
    zero = {"sent": 0, "correct": 0, "timeout": 0, "wrong": 0, "transport_error": 0}
    load = {"measurement": {"sent": 7, "correct": 5, "timeout": 1, "wrong": 1, "transport_error": 0,
                            "correct_in_window": 3, "send_lag_sum_ns": 7000, "send_lag_max_ns": 1000},
            "warmup": zero, "steady": {**zero, "sent": 5, "correct": 3, "timeout": 1, "wrong": 1},
            "saturation": {**zero, "sent": 2, "correct": 2}, "interrupted": False, "output_failed": False}
    epoch = {"measurement_start_ns": start, "measurement_end_ns": end, "saturation_start_ns": middle}
    points = {}
    for label, when, usage in (("measurement-start", start, 0), ("saturation-start", middle, 9_000_000),
                               ("measurement-end", end, 12_000_000)):
        points[label] = {"cgroup_cpu": {"monotonic_ns": when + 1000, "usage_usec": usage},
                         "capture_lag_ns": 1000, "scheduled_monotonic_ns": when}
    identity = {"scenario": "hit", "implementation": "c", "round": 1, "seed": 1,
                "clients": 20, "saturation_seconds": 30, "duration_seconds": 120,
                "excluded_preflight": False}
    result = {"identity": identity, "accepted": True, "measurement_valid": True,
              "measurement": {"load": load, "epoch": epoch, "cpu_points": points,
                              "cpu_segments": {"measurement-start..saturation-start": {"cpu_seconds": 9},
                                               "saturation-start..measurement-end": {"cpu_seconds": 3}},
                              "measurement_cpu_seconds": 12}}
    resources = [{"monotonic_ns": start + (i * 1000 + 500) * 1_000_000,
                  "tree": {"rss_kib": 1000 + i, "pss_kib": 800 + i, "fd_count": 3,
                           "thread_count": 1, "child_processes": 0},
                  "parent": {"hwm_kib": 1120}, "clock_ticks_per_second": 100,
                  "loadgen": {"pid": 1, "starttime_ticks": 42, "user_ticks": i * 10, "system_ticks": 0},
                  "upstream": {"pid": 2, "starttime_ticks": 43, "user_ticks": i, "system_ticks": 0}}
                 for i in range(120)]
    for name, value in (("load.json", load), ("epoch.json", epoch), ("resources.json", resources), ("result.json", result)):
        save(directory / name, value)
    q = query("q0001.m6a.test", ident=1)
    reply = q[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0) + q[12:] + rr(1, bytes((192, 0, 2, 1)), 3600)
    (directory / "load.wire-samples.jsonl").write_text(json.dumps({"query_hex": q.hex(), "reply_hex": reply.hex(),
                                                                  "correct": True, "phase": 1}) + "\n")
    return rows


class FrozenArithmetic(unittest.TestCase):
    def test_nearest_rank_and_p99_sample_gate(self):
        result = analyze.quantiles(range(1, 10001))
        self.assertEqual((result["p50"], result["p95"], result["p99"]), (5000, 9500, 9900))
        self.assertIsNone(analyze.quantiles(range(9999))["p99"])

    def test_thresholds_variability_and_direction(self):
        self.assertEqual(analyze.classify([100] * 5, [110] * 5, "qps")["classification"], "有收益")
        self.assertEqual(analyze.classify([100] * 5, [95] * 5, "qps")["classification"], "变差")
        self.assertEqual(analyze.classify([100] * 5, [110] * 5, "cpu_us_per_correct")["classification"], "变差")
        self.assertEqual(analyze.classify([100] * 5, [110, 110, 110, 90, 90], "qps")["classification"], "无显著差异")
        self.assertEqual(analyze.classify([80, 100, 100, 100, 120], [110] * 5, "qps")["classification"], "无显著差异")
        self.assertEqual(analyze.classify([600] * 5, [660] * 5, "pss_kib")["classification"], "无显著差异")
        self.assertEqual(analyze.classify([640] * 5, [704] * 5, "pss_kib")["classification"], "变差")
        self.assertEqual(analyze.classify([100] * 5, [120] * 5, "qps", True)["classification"], "受限")

    def test_hand_counted_phases_crossing_and_late_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "formal"
            fixture(root)
            result = analyze.analyze_window(root)
            steady, saturated = result["phases"]
            self.assertTrue(result["methodology_valid"])
            self.assertEqual(steady["completion_counts"], {"correct": 2, "timeout": 1, "wrong": 1, "transport_error": 0})
            self.assertEqual(saturated["completion_counts"]["correct"], 2)
            self.assertEqual(saturated["cross_phase_completions"]["correct"], 1)
            self.assertEqual(result["measurement"]["completion_counts"]["correct"], 4)
            self.assertEqual(result["late_completion_counts"]["correct"], 1)
            self.assertEqual(result["load_aggregate_in_window_difference"], 1)
            self.assertAlmostEqual(steady["qps"], 2 / 90)
            self.assertEqual(steady["cpu_us_per_correct"], 4_500_000)
            self.assertEqual(steady["latency_ns"]["p95"], 200_000_000)
            self.assertEqual(steady["completion_latency_ns"]["p95"], 100_000_000)
            self.assertEqual(saturated["latency_ns"]["p95"], 200_000_000)
            self.assertIsNone(steady["latency_ns"]["p99"])

    def test_truncated_duplicate_and_mismatched_lag_streams_rejected(self):
        for mutation in ("truncated", "duplicate", "lag"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "formal"
                fixture(root)
                path = root / "load.latencies.bin"
                if mutation == "truncated":
                    path.write_bytes(path.read_bytes()[:-1])
                elif mutation == "duplicate":
                    rows = path.read_bytes()
                    path.write_bytes(rows[:32] + rows[:32] + rows[64:])
                    lag = root / "load.send-lag.bin"
                    stream = lag.read_bytes()
                    lag.write_bytes(stream[:16] + stream[:16] + stream[32:])
                else:
                    lag = root / "load.send-lag.bin"
                    lag.write_bytes(lag.read_bytes()[:-1])
                with self.assertRaises(analyze.EvidenceError):
                    analyze.analyze_window(root)

    def test_state_selects_declared_attempt_not_any_faster_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = "r01-udp-hit-C"
            fixture(root / "runs" / job / "attempt-1" / "formal")
            fixture(root / "archives" / job / "attempt-2" / "plain" / "formal")
            save(root / "state.json", {"windows": {job: {"valid_attempt": 2, "round": 1,
                  "profile": "udp-hit", "group": "C", "attempts": [{"attempt": 1, "methodology_valid": False},
                                                                         {"attempt": 2, "methodology_valid": True}]}}})
            result = analyze.analyze(root)
            self.assertEqual(len(result["windows"]), 1)
            self.assertEqual(result["windows"][0]["attempt"], 2)
            self.assertEqual(result["valid_counts"]["udp-hit"]["C"], 1)
            self.assertFalse(result["formal_complete"])
            (root / "state.json").unlink()
            result = analyze.analyze(root)
            self.assertFalse(result["authoritative_state"])
            self.assertEqual(result["comparisons"], [])

    def test_raw_correct_sample_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "formal"
            fixture(root)
            path = root / "load.wire-samples.jsonl"
            sample = json.loads(path.read_text())
            sample["reply_hex"] = sample["reply_hex"][:-2] + "02"
            path.write_text(json.dumps(sample) + "\n")
            with self.assertRaisesRegex(analyze.EvidenceError, "raw sample"):
                analyze.analyze_window(root)

    def test_generator_cpu_limit_retains_data_and_tags_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "formal"
            fixture(root)
            resources = json.loads((root / "resources.json").read_text())
            for index, row in enumerate(resources):
                row["loadgen"]["user_ticks"] = index * 95
            save(root / "resources.json", resources)
            result = analyze.analyze_window(root)
            self.assertTrue(result["methodology_valid"])
            self.assertTrue(result["phases"][0]["generator_limited"])
            self.assertEqual(result["record_count"], 7)

    def test_fault_origin_timeout_is_not_assigned_to_recovery_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "formal"
            fixture(root)
            result = json.loads((root / "result.json").read_text())
            result["identity"].update(scenario="fault", saturation_seconds=0)
            start = result["measurement"]["epoch"]["measurement_start_ns"]
            for label, seconds, usage in (("fault-start", 30, 3_000_000), ("fault-end", 60, 6_000_000)):
                when = start + seconds * 1_000_000_000
                result["measurement"]["cpu_points"][label] = {
                    "cgroup_cpu": {"usage_usec": usage, "monotonic_ns": when + 1000},
                    "scheduled_monotonic_ns": when, "capture_lag_ns": 1000}
            result["measurement"]["cpu_segments"] = {
                "measurement-start..fault-start": {"cpu_seconds": 3},
                "fault-start..fault-end": {"cpu_seconds": 3},
                "fault-end..measurement-end": {"cpu_seconds": 6}}
            # Move the timeout to fault t59.5, completing in recovery t60.5.
            path = root / "load.latencies.bin"
            rows = list(analyze.LATENCY.iter_unpack(path.read_bytes()))
            rows[5] = (*rows[5][:2], start + 59_500_000_000, *rows[5][3:])
            rows = [(*row[:6], 1, *row[7:]) for row in rows]
            path.write_bytes(b"".join(analyze.LATENCY.pack(*row) for row in rows))
            load = result["measurement"]["load"]
            load["steady"] = dict(load["measurement"])
            load["saturation"] = dict(load["warmup"])
            save(root / "load.json", load)
            save(root / "result.json", result)
            value = analyze.analyze_window(root)
            pre, fault, recovery = value["phases"]
            self.assertEqual(fault["origin_counts"]["timeout"], 1)
            self.assertEqual(recovery["origin_counts"]["timeout"], 0)
            self.assertEqual(recovery["completion_counts"]["timeout"], 1)
            self.assertEqual(recovery["cross_phase_completions"]["timeout"], 1)


if __name__ == "__main__":
    unittest.main()
