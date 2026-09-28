#!/usr/bin/env python3
"""Negative evidence gates for publishable benchmark summaries."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from analyze import logd_idle, native, summarize, timing


class AnalysisGates(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "sample.json"
        self.valid = {"successful": 2, "errors": 0, "latency_ns": [1000, 3000],
                      "wall_s": .001, "ops_per_s": 2000, "mean_us": 2,
                      "p50_us": 3, "p95_us": 3, "p99_us": 3,
                      "daemon_cpu": [{"before": {"start_ticks": 17}, "after": {"start_ticks": 17},
                                      "cpu_s": .01, "child_cpu_s": 0}]}

    def tearDown(self):
        self.directory.cleanup()

    def test_invalid_counts_errors_and_latency_are_rejected(self):
        for patch in ({"successful": 3}, {"errors": 1}, {"mean_us": 99}, {"wall_s": 0}):
            data = {**self.valid, **patch}
            self.path.write_text(json.dumps(data))
            with self.assertRaises(AssertionError):
                native(self.path)

    def test_replaced_process_is_rejected(self):
        data = copy.deepcopy(self.valid)
        data["daemon_cpu"][0]["after"]["start_ticks"] += 1
        self.path.write_text(json.dumps(data))
        with self.assertRaises(AssertionError):
            native(self.path)

    def test_derived_percentiles_and_rate_must_match_raw_samples(self):
        for key in ("p50_us", "p95_us", "p99_us", "ops_per_s"):
            with self.subTest(key=key):
                self.path.write_text(json.dumps({**self.valid, key: 123456789}))
                with self.assertRaises(AssertionError):
                    native(self.path)

    def test_invalid_raw_samples_and_nonfinite_wall_are_rejected(self):
        for patch in ({"latency_ns": [-1000, 5000]},
                      {"latency_ns": [1000.0, 3000.0]},
                      {"wall_s": float("inf")}, {"wall_s": float("nan")}):
            self.path.write_text(json.dumps({**self.valid, **patch}))
            with self.assertRaises(AssertionError):
                native(self.path)

    def test_even_sample_median_uses_native_half_up_index(self):
        self.path.write_text(json.dumps(self.valid))
        self.assertEqual(native(self.path)["p50_us"], 3)
        self.path.write_text(json.dumps({**self.valid, "p50_us": 1}))
        with self.assertRaises(AssertionError):
            native(self.path)

    def test_timing_fields_do_not_export_unrelated_payloads(self):
        self.path.write_text(json.dumps({**self.valid, "private_response": "must remain private"}))
        result = timing(native(self.path))
        self.assertNotIn("private_response", result)
        self.assertNotIn("latency_ns", result)
        self.assertEqual(result["mean_us"], 2)

    def test_run_summary_retains_dispersion(self):
        rows = [{"side": "stock", "mean_us": value} for value in (1, 3, 20)]
        result = summarize(rows, ("side",))[0]
        self.assertEqual(result["runs"], 3)
        self.assertEqual(result["metrics"]["mean_us"]["median"], 3)
        self.assertEqual(result["metrics"]["mean_us"]["max"], 20)

    def test_candidate_distinguishes_child_program_cpu_from_daemon_cpu(self):
        from analyze_candidate import serial
        data = copy.deepcopy(self.valid)
        data.update(warmup=5, child_cpu_s=.004, client_cpu_s=.002)
        data["daemon_cpu"][0]["pid"] = 7
        self.path.write_text(json.dumps(data))
        self.assertEqual(serial(self.path, None)["subject_cpu_us_per_op"], 2000)
        self.assertEqual(serial(self.path, 7)["subject_cpu_us_per_op"], 5000)
        with self.assertRaises(AssertionError):
            serial(self.path, 99)

    def command_sample(self):
        data = {**self.valid, "warmup": 5, "child_cpu_s": 0, "client_cpu_s": .002,
                "clock_ticks_per_second": 100, "daemon_cpu": [], "client_cpu_clock_ns": 2000}
        data["client_before"] = {"pid": 23, "start_ticks": 17, "child_cpu_ticks": 0,
                                 "process_cpu_ns": 1000, "process_cpu_resolution_ns": 1,
                                 "rusage_children_user_us": 100000,
                                 "rusage_children_system_us": 50000,
                                 "rusage_children_counter_source": "getrusage(RUSAGE_CHILDREN)"}
        data["client_after"] = {**data["client_before"], "process_cpu_ns": 3000,
                                "rusage_children_user_us": 101100,
                                "rusage_children_system_us": 50300}
        return data

    def test_one_shot_command_cpu_uses_measured_delta_and_count(self):
        from analyze_candidate import serial
        data = self.command_sample()
        for warmup in (5, 65):
            data["warmup"] = warmup
            self.path.write_text(json.dumps(data))
            result = serial(self.path, None)
            self.assertEqual(result["command_tree_cpu_us_per_op"], 700)
            self.assertEqual(result["subject_cpu_us_per_op"], 0)  # retained legacy ticks
            self.assertEqual(result["client_reaped_child_cpu_us_per_op"], 0)

    def test_one_shot_command_cpu_rejects_partial_regressed_or_wrong_source(self):
        from analyze_candidate import serial
        for patch in ({"rusage_children_user_us": 99999},
                      {"rusage_children_counter_source": "wrong"},
                      {"start_ticks": 99}):
            data = self.command_sample()
            data["client_after"].update(patch)
            self.path.write_text(json.dumps(data))
            with self.assertRaises(AssertionError):
                serial(self.path, None)
        data = self.command_sample()
        del data["client_after"]["rusage_children_system_us"]
        self.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(AssertionError, "partial"):
            serial(self.path, None)
        for snapshot in (data["client_before"], data["client_after"]):
            for field in list(snapshot):
                if field.startswith("rusage_children_"):
                    del snapshot[field]
        self.path.write_text(json.dumps(data))
        self.assertNotIn("command_tree_cpu_us_per_op", serial(self.path, None))

    def test_one_shot_collection_does_not_require_a_resident_process_hash(self):
        from analyze_candidate import derive
        root = Path(self.directory.name)

        def save(name, value):
            (root / name).write_text(json.dumps(value))

        (root / "COMPLETE").touch()
        save("order.json", ["stock", "candidate"])
        save("subjects.json", {"stock": "a" * 64, "candidate": "b" * 64})
        save("settings.json", {"component": "uci", "matrix": False})
        for phase in ("before", "after"):
            save(f"health-{phase}.json", {"boot_id": "same-boot"})
            (root / f"config-{phase}.sha256").write_text("same-config\n")
        data = {**self.valid, "warmup": 5, "child_cpu_s": .004, "client_cpu_s": .002,
                "daemon_cpu": []}
        for index, side in enumerate(("stock", "candidate"), 1):
            run = root / f"{index:02d}-{side}"
            raw = run / "raw"
            raw.mkdir(parents=True)
            (run / "COMPLETE").touch()
            (raw / "COMPLETE").touch()
            (run / "raw.tar.gz").write_bytes(b"fixture archive identity")
            meta = {"component": "uci", "dependencies": "original OpenWrt",
                    "subject_pid": None, "iterations": 40}
            (raw / "meta.json").write_text(json.dumps(meta))
            (raw / "boot-id.txt").write_text("same-boot\n")
            (raw / "kernel.txt").write_text("fixture-kernel\n")
            (raw / "binary-sha256.txt").write_text(("a" if side == "stock" else "b") * 64 + "  uci\n")
            (raw / "benchmark-sha256.txt").write_text("client  benchmark\nnamespace  ns-exec\n")
            (raw / "harness-sha256.txt").write_text("harness  isolated.sh\n")
            for workload in ("export_network", "export_64", "set_commit_get"):
                (raw / (workload + ".json")).write_text(json.dumps(data))
        result = derive(root, "one-shot fixture")
        self.assertEqual(result["resident"], [])
        self.assertEqual(len(result["runs"]), 6)
        self.assertTrue(all(r["subject_cpu_us_per_op"] == 2000 for r in result["runs"]))
        self.assertFalse(result["acceptance_eligible"])
        self.assertTrue(any("short-lived" in reason for reason in result["limitations"]))

        # Fine command-tree CPU is aggregated when all short-lived runs have it.
        for path in root.glob("*/raw/*.json"):
            if path.stem in ("export_network", "export_64", "set_commit_get"):
                path.write_text(json.dumps(self.command_sample()))
        result = derive(root, "one-shot fine CPU fixture")
        self.assertTrue(result["acceptance_eligible"])
        for workload in ("export_network", "export_64", "set_commit_get"):
            self.assertEqual(result["summary"][workload]["candidate"]["command_tree_cpu_us_per_op"]["median"], 700)

        # A valid command counter cannot replace the caller's own CPU clock.
        for path in root.glob("*/raw/*.json"):
            if path.stem in ("export_network", "export_64", "set_commit_get"):
                data = self.command_sample()
                del data["client_cpu_clock_ns"]
                path.write_text(json.dumps(data))
        self.assertFalse(derive(root, "missing caller CPU")["acceptance_eligible"])
        # A caller clock cannot turn legacy command ticks into fine evidence.
        for path in root.glob("*/raw/*.json"):
            if path.stem in ("export_network", "export_64", "set_commit_get"):
                data = self.command_sample()
                for snapshot in (data["client_before"], data["client_after"]):
                    for field in list(snapshot):
                        if field.startswith("rusage_children_"):
                            del snapshot[field]
                path.write_text(json.dumps(data))
        self.assertFalse(derive(root, "missing getrusage")["acceptance_eligible"])

        # Declaring a daemon to have no PID must not bypass its live identity check.
        save("settings.json", {"component": "rpcd", "matrix": False})
        for path in root.glob("*/raw/meta.json"):
            meta = json.loads(path.read_text())
            meta["component"] = "rpcd"
            path.write_text(json.dumps(meta))
        with self.assertRaisesRegex(AssertionError, "invalid subject process kind"):
            derive(root, "invalid daemon fixture")

    def test_logd_perpetually_readable_kernel_log_is_rejected(self):
        samples = [{"uptime_s": i, "clock_ticks_per_second": 100,
                    "processes": [{"pid": 7, "start_ticks": 17, "cpu_ticks": i * 100}]}
                   for i in range(4)]
        self.path.write_text("\n".join(json.dumps(s) for s in samples))
        with self.assertRaises(AssertionError):
            logd_idle(self.path, 7)
        for sample in samples:
            sample["processes"][0]["cpu_ticks"] = 1
        self.path.write_text("\n".join(json.dumps(s) for s in samples))
        self.assertEqual(logd_idle(self.path, 7)["cpu_s"], 0)


if __name__ == "__main__":
    unittest.main()
