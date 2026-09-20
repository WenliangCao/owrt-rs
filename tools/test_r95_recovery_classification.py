import unittest

from r92_recovery_probe import CHECKS, ORIGINAL_DIFFERENCES, classify_checks


class RecoveryClassification(unittest.TestCase):
    def test_both_observed_original_halfclose_outcomes_are_explicit(self):
        checks = dict.fromkeys(CHECKS["ubusd_halfclose"], True)
        healthy = classify_checks("ubusd_halfclose", "original", 0, checks)
        self.assertTrue(healthy["passed"])
        self.assertEqual(healthy["original_failure_not_reproduced"], ["complete_reply"])
        checks["complete_reply"] = False
        truncated = classify_checks("ubusd_halfclose", "original", 0, checks)
        self.assertTrue(truncated["passed"])
        self.assertEqual(truncated["original_failure_not_reproduced"], [])

    def test_no_candidate_invariant_can_be_waived(self):
        for case, keys in CHECKS.items():
            checks = dict.fromkeys(keys, True)
            self.assertTrue(classify_checks(case, "candidate", 0, checks)["passed"])
            for key in keys:
                with self.subTest(case=case, key=key):
                    bad = dict(checks, **{key: False})
                    self.assertFalse(classify_checks(case, "candidate", 0, bad)["passed"])
            self.assertFalse(classify_checks(case, "candidate", 1, checks)["passed"])
            self.assertFalse(classify_checks(case, "candidate", 0, {})["passed"])

    def test_other_controls_and_unexpected_failures_stay_strict(self):
        for case, keys in CHECKS.items():
            expected = dict.fromkeys(keys, True) | ORIGINAL_DIFFERENCES.get(case, {})
            self.assertTrue(classify_checks(case, "original", 0, expected)["passed"])
            for key in keys:
                if (case, key) == ("ubusd_halfclose", "complete_reply"):
                    continue
                with self.subTest(case=case, key=key):
                    changed = dict(expected, **{key: not expected[key]})
                    self.assertFalse(classify_checks(case, "original", 0, changed)["passed"])
        checks = dict.fromkeys(CHECKS["ubusd_halfclose"], True)
        self.assertFalse(classify_checks("ubusd_halfclose", "original", 0, checks | {"extra": True})["passed"])


if __name__ == "__main__":
    unittest.main()
