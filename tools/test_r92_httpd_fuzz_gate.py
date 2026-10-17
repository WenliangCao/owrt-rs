#!/usr/bin/env python3
"""A released baseline never excuses response drift or extra C differences."""
import copy
import json
from pathlib import Path
import unittest

from r92_httpd_fuzz_gate import evaluate, fuzz


class ReleasedBaseline(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads((Path(__file__).resolve().parents[1]
                                   / "tests/reference/httpd/r92-deviations.json").read_text())
        self.baseline = {case["id"]: {"status": "HTTP/1.1 200 OK", "headers": [],
                                      "body": case["id"], "closed": True, "alive_after": True}
                         for case in fuzz.cases()}
        for name, row in self.contract.items():
            if "match_case" in row:
                self.baseline[name] = copy.deepcopy(self.baseline[row["match_case"]])
        self.candidate = copy.deepcopy(self.baseline)
        self.stock = copy.deepcopy(self.baseline)
        for name in self.contract:
            self.stock[name]["body"] = "stock: " + name

    def current(self):
        return evaluate(self.stock, self.baseline, self.candidate, self.contract, "current-release")

    def test_modes_keep_distinct_transition_requirements(self):
        self.assertTrue(self.current()["passed"])
        self.assertFalse(evaluate(self.stock, self.baseline, self.candidate, self.contract)["passed"])
        for name, row in self.contract.items():
            if "match_case" in row:
                self.baseline[name]["body"] = "historical: " + name
        self.assertTrue(evaluate(self.stock, self.baseline, self.candidate, self.contract)["passed"])

    def test_same_status_does_not_hide_candidate_body_drift(self):
        self.candidate["http09"]["body"] += " changed"
        result = self.current()
        self.assertEqual(set(result["candidate_differences"]), set(self.contract))
        self.assertFalse(result["checks"]["http09"])
        self.assertFalse(result["passed"])

    def test_equal_versions_still_require_match_cases_and_exact_c_differences(self):
        for name in ("chunked-huge-size", "plain"):
            with self.subTest(name=name):
                baseline = copy.deepcopy(self.baseline)
                baseline[name]["body"] += " changed in both versions"
                result = evaluate(self.stock, baseline, baseline, self.contract, "current-release")
                self.assertTrue(all(result["checks"].values()))
                self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
