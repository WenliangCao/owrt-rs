"""Reject stale or weakened acceptance rules for the exact logd history corpus."""
import unittest

from r92_compat_probe import backlog_admission_matches


class BacklogGateTests(unittest.TestCase):
    def test_valid_bounded_and_original_transcripts(self):
        self.assertTrue(backlog_admission_matches([0, 0, 0, 8], True))
        self.assertTrue(backlog_admission_matches([0, 0, 8, 8], True))
        self.assertTrue(backlog_admission_matches([0, 0, 0, 0], False))

    def test_unbounded_candidate_is_a_red_control(self):
        self.assertFalse(backlog_admission_matches([0, 0, 0, 0], True))

    def test_retired_low_limit_is_a_red_control(self):
        for statuses in ([8, 8, 8, 8], [0, 8, 8, 8]):
            with self.subTest(statuses=statuses):
                self.assertFalse(backlog_admission_matches(statuses, True))

    def test_incomplete_or_failed_requests_never_pass(self):
        for statuses in ([], [0, 0, 8], [0, 0, 0, 8, 8], [0, 0, 2, 8], [0, 0, 8, 0]):
            with self.subTest(statuses=statuses):
                self.assertFalse(backlog_admission_matches(statuses, True))
        self.assertFalse(backlog_admission_matches([0, 0, 8, 8], False))


if __name__ == "__main__":
    unittest.main()
