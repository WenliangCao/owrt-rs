#!/usr/bin/env python3
"""Offline boundary/rejection tests and replay of retained R134 evidence."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent / "r136"))
import analyze_completion as report


class DecisionTests(unittest.TestCase):
    def comparison(self, candidate, higher=8):
        values = {}
        for index, (stock, run) in enumerate(report.matrix_report.PAIRS):
            values[stock] = 100
            values[run] = candidate if index < higher else 100
        return report.primary_comparison(report.matrix_report.compare(values))

    def test_exact_one_percent_is_unresolved(self):
        for value in (99, 101):
            result = self.comparison(value)
            self.assertEqual(result["decision"], "tie")
            self.assertEqual(abs(result["median_paired_delta_pct"]), 1)
            self.assertNotEqual(result["historical_r134_decision"], "tie")

    def test_seven_signs_and_effect_size_are_both_required(self):
        self.assertEqual(self.comparison(101.001, 7)["decision"], "loss")
        self.assertEqual(self.comparison(98.999, 7)["decision"], "win")
        self.assertEqual(self.comparison(102, 6)["decision"], "tie")
        self.assertEqual(self.comparison(100.999, 8)["decision"], "tie")


@unittest.skipUnless((report.ROOT / "private/r134/router-finish-03/COMPLETE").exists(),
                     "requires retained local R134 raw evidence; never contacts router")
class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = report.ROOT / "private/r134/router-finish-03"
        cls.plan = json.loads((cls.root / "plan.json").read_text())
        cls.plan["subjects"] = {
            "stock": {"path": "private/r95/ubusd-pilot/stock", "sha256": report.C_SHA},
            "candidate": {"path": "private/r134/bins-ubusd/ubusd-rs", "sha256": cls.plan["candidate_sha256"]},
        }
        cls.plan["namespace_sha256"] = "fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2"

    def test_replay_46_old_windows_and_redact(self):
        matrix = report.analyze_matrix(self.root, self.plan)
        send = report.analyze_send(self.root, self.plan)
        memory = report.analyze_memory(self.root, self.plan)
        stress = report.analyze_stress(self.root, self.plan)
        self.assertEqual(matrix["decision_counts"]["r134_historical"], {"win": 62, "loss": 5, "tie": 8})
        self.assertEqual(send["decision_counts"]["r134_historical"], {"win": 12, "loss": 0, "tie": 3})
        self.assertEqual(memory["windows_verified"], 12)
        self.assertEqual(stress["windows_verified"], 2)
        fixture = {"schema_version": 1, "scope": "offline R134 replay only", "verified": True,
                   "physical_windows_verified": 46, "all_windows_cleaned_and_stock": True,
                   "plan_sha256": "0" * 64, "reporter_sha256": "0" * 64, "rules": report.RULES,
                   "limits": [], "subjects": self.plan["subjects"], "frozen_input_sha256": self.plan["input_sha256"],
                   "matrix": matrix, "direct_send": send, "memory": memory, "stress": stress,
                   "boot_id": "sensitive-canary", "raw_address": "sensitive-canary"}
        public = report.public_report(fixture)
        encoded = json.dumps(public)
        for forbidden in ("sensitive-canary", "private/", '"boot_id"', '"daemon_pid"', '"subject_pid"',
                          '"daemon_start_ticks"', '"raw_files_sha256"'):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(public["memory"]["all_candidate_increases"], memory["all_candidate_increases"])
        self.assertEqual(public["matrix"]["all_higher_medians"], matrix["all_higher_medians"])

    def test_mixed_candidate_identity_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan["subjects"]["candidate"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "subject identities"):
            report.analyze_matrix(self.root, plan)

    def test_changed_helper_identity_rejected(self):
        plan = copy.deepcopy(self.plan)
        step = next(step for step in plan["steps"] if step["name"] == "latency-01-stock")
        plan["input_sha256"][report.argument(step, "--event-benchmark")] = "0" * 64
        with self.assertRaisesRegex(ValueError, "event_benchmark identity"):
            report.verify_guarded(self.root, plan, step)

    def test_archive_expansion_drift_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "window"
            shutil.copytree(self.root / "memory/idle/01-stock", target)
            (target / "raw/COMPLETE").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "archive differs"):
                report.archive_hashes(target)


if __name__ == "__main__":
    unittest.main()
