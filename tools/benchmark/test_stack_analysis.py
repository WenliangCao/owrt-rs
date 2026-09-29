import copy
import unittest

from analyze_stack_trial import memory_accounting, native, normalize_recorded_fw4, system_cost, timing, tls_tail


def sample(pid, cpu, user=0, system=0):
    return {"pid": pid, "start_ticks": 7, "process_cpu_ns": cpu,
            "rusage_children_user_us": user, "rusage_children_system_us": system}


def fixture():
    return {"successful": 1, "errors": 0, "latency_ns": [1000000], "wall_s": 0.001,
            "mean_us": 1000, "p50_us": 1000, "p95_us": 1000, "p99_us": 1000,
            "ops_per_s": 1000, "daemon_cpu": [{"pid": 12, "cpu_clock_ns": 5000,
                "child_cpu_s": 0, "before": sample(12, 100), "after": sample(12, 5100)}],
            "client_before": sample(22, 200, 100, 100),
            "client_after": sample(22, 10200, 250, 150), "client_cpu_clock_ns": 10000}


class StackAnalysisTests(unittest.TestCase):
    def test_file_cache_growth_can_lower_available_without_growing_other_usage(self):
        memory = {"MemTotal": 239024, "MemFree": 144180, "MemAvailable": 133876,
                  "Active(file)": 7076, "Inactive(file)": 14764, "SReclaimable": 6704}
        before = memory_accounting(memory)
        memory["MemFree"] -= 1024
        memory["Inactive(file)"] += 1024
        memory["MemAvailable"] -= 512
        after = memory_accounting(memory)
        self.assertEqual(before["available_model_error_kib"], 0)
        self.assertEqual(after["available_model_error_kib"], 0)
        self.assertEqual(before["used_excluding_free_file_LRU_reclaimable_slab"],
                         after["used_excluding_free_file_LRU_reclaimable_slab"])
        # An odd count of 4 KiB pages rounds the retained half down.
        memory["Inactive(file)"] += 4
        memory["SReclaimable"] += 4
        memory["MemAvailable"] += 8
        self.assertEqual(memory_accounting(memory)["available_model_error_kib"], 0)

    def test_tail_review_pools_requests_without_replacing_recorded_round_p99(self):
        row = {"successful": 2, "errors": 0, "latency_ns": [1000000, 13000000],
               "mean_ms": 7, "p50_ms": 1, "p95_ms": 13, "p99_ms": 13,
               "ops_per_s": 2, "wall_s": 1, "tls_ciphers": ["AES"]}
        result = tls_tail([row, row, row])
        self.assertEqual(result["requests"], 6)
        self.assertEqual(result["over_12ms"], 3)
        self.assertEqual(result["pooled_median_us"], 7000)
        self.assertEqual(result["round_p99_us"], [13000, 13000, 13000])

    def test_retrospective_fw4_comparison_retains_membership_and_rule_order(self):
        before = "define lan_subnets = { fd00::/64, 2001:db8::/64 }\naccept\ndrop\n"
        reordered = before.replace("fd00::/64, 2001:db8::/64", "2001:db8::/64, fd00::/64")
        self.assertEqual(normalize_recorded_fw4(before), normalize_recorded_fw4(reordered))
        for changed in (before.replace(", 2001:db8::/64", ""), before.replace("accept\ndrop", "drop\naccept")):
            self.assertNotEqual(normalize_recorded_fw4(before), normalize_recorded_fw4(changed))

    def test_native_and_lan_even_sample_rank_definitions_are_preserved(self):
        native_data = {"successful": 10, "errors": 0, "latency_ns": list(range(1000, 11000, 1000)),
                       "wall_s": 1, "ops_per_s": 10, "mean_us": 5.5,
                       "p50_us": 6, "p95_us": 10, "p99_us": 10}
        self.assertEqual(timing(native_data)["p50_us"], 6)
        lan = {key: value for key, value in native_data.items() if not key.endswith("_us")}
        lan.update(mean_ms=0.0055, p50_ms=0.005, p95_ms=0.01, p99_ms=0.01)
        self.assertEqual(timing(lan)["p50_us"], 5)

    def test_rejects_corrupted_latency_summary_and_count(self):
        for field, value in [("mean_us", 999), ("successful", 2), ("errors", 1)]:
            d = fixture()
            d[field] = value
            with self.assertRaises(AssertionError): timing(d)

    def test_exec_target_cpu_and_mixed_driver_cpu_are_not_confused(self):
        command = native(fixture(), {12: "procd"}, command=True)
        self.assertEqual(command["control_accounted_cpu_us"], 205)
        mixed = native(fixture(), {12: "procd"}, mixed=4)
        self.assertEqual(mixed["control_accounted_cpu_us"], 1.25)
        self.assertEqual(mixed["driver_cpu_us"], 52.5)
        self.assertNotIn("p99_us", mixed)

    def test_rejects_pid_reuse_and_inconsistent_fine_clock(self):
        for key, value in [("start_ticks", 8), ("process_cpu_ns", 0), ("process_cpu_ns", 9999)]:
            d = fixture()
            d["daemon_cpu"][0]["after"][key] = value
            with self.assertRaises(AssertionError): native(d, {12: "procd"})

    def test_whole_cpu_does_not_double_count_guest_or_iowait(self):
        before = {"clock_ticks_per_second": 100, "system_cpu_ticks": [0] * 10, "uptime_s": 1}
        after = copy.deepcopy(before)
        after.update(system_cpu_ticks=[10, 0, 20, 50, 10, 2, 3, 5, 8, 0], uptime_s=2)
        d = system_cost(before, after, 10)
        self.assertEqual(d["system_busy_pct"], 40)
        self.assertEqual(d["system_busy_cpu_us"], 40000)


if __name__ == "__main__":
    unittest.main()
