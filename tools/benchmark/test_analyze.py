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
