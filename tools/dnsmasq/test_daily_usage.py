#!/usr/bin/env python3
"""Offline counter-accounting/invalid-window tests; no router is contacted."""
import copy
import unittest

from daily_usage import summarize


def samples():
    rows = []
    for i in range(121):
        process = {"pid": 664, "ppid": 1, "starttime_ticks": 1234,
                   "user_ticks": 100 + i, "system_ticks": 50 + i,
                   "waited_child_user_ticks": 10 + i, "waited_child_system_ticks": 5,
                   "rss_kib": 1200 + i, "rss_anon_kib": 200, "thread_count": 1, "fd_count": 11}
        observer = dict(process, pid=700, starttime_ticks=2000, user_ticks=10 + i // 30,
                        system_ticks=0, waited_child_user_ticks=0, waited_child_system_ticks=0)
        rows.append({"index": i, "monotonic_ns": (1000 + i * 5) * 1_000_000_000,
                     "clock_ticks_per_second": 100, "processes": [process],
                     "observer": observer, "proc_parent_map_scans": 1,
                     "children_disappeared": 0, "lease_count": 6, "sample_duration_ns": 2_000_000})
    return rows


class DailyUsageTests(unittest.TestCase):
    def test_cpu_counter_scope_and_one_core_percent(self):
        report = summarize(samples())
        self.assertTrue(report["valid_observation_window"])
        self.assertEqual(report["main_cpu_seconds"], 2.4)
        self.assertAlmostEqual(report["main_average_one_core_percent"], .4)
        self.assertEqual(report["waited_children_cpu_seconds"], 1.2)
        self.assertEqual(report["main_plus_waited_cpu_seconds"], 3.6)
        self.assertEqual(report["observer_cpu_seconds"], .04)
        self.assertTrue(report["child_free_endpoints_observed"])
        self.assertEqual(report["main"]["rss_kib"], {"min": 1200, "median": 1260, "max": 1320})

    def test_live_endpoint_child_is_not_added_to_waited_cpu(self):
        rows = samples()
        child = copy.deepcopy(rows[-1]["processes"][0])
        child.update(pid=900, ppid=664, user_ticks=10000)
        rows[-1]["processes"].append(child)
        report = summarize(rows)
        self.assertFalse(report["child_free_endpoints_observed"])
        self.assertEqual(report["main_plus_waited_cpu_seconds"], 3.6)
        self.assertIn("not complete", report["tree_cpu_qualification"])
        self.assertEqual(report["tree_shared_pages_recounted"]["rss_kib"]["max"], 2640)

    def test_disappeared_endpoint_child_disqualifies_tree_cpu(self):
        rows = samples()
        rows[0]["children_disappeared"] = 1
        self.assertFalse(summarize(rows)["child_free_endpoints_observed"])

    def test_missing_sample_invalidates_window(self):
        rows = samples()
        del rows[20]
        report = summarize(rows)
        self.assertFalse(report["valid_observation_window"])
        self.assertIn("sample index gap", report["errors"])

    def test_pid_reuse_invalidates_window(self):
        rows = samples()
        rows[-1]["processes"][0]["starttime_ticks"] += 100
        self.assertFalse(summarize(rows)["valid_observation_window"])

    def test_cpu_reset_invalidates_window(self):
        rows = samples()
        rows[-1]["processes"][0]["user_ticks"] = 0
        self.assertIn("target CPU counter decreased", summarize(rows)["errors"])

    def test_late_sample_invalidates_window(self):
        rows = samples()
        rows[-1]["monotonic_ns"] += 2_000_000_000
        self.assertFalse(summarize(rows)["valid_observation_window"])

    def test_unknown_lease_count_is_not_zero(self):
        rows = samples()
        for row in rows:
            row["lease_count"] = None
        report = summarize(rows)
        self.assertIsNone(report["lease_count"])
        self.assertEqual(report["lease_count_missing_samples"], 121)


if __name__ == "__main__":
    unittest.main()
