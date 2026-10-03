#!/usr/bin/env python3
"""Checks for the outcome comparator used by exact-image DNS regressions."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from m2_dns_diff import compare, comparison_controls


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.trace = {'profile': 'udp-cache', 'rows': [{
            'label': 'fill', 'semantic': [{'flags': 0x8180, 'records': []}],
            'transport': 'udp', 'client': 0, 'upstream': [{'server': 'one'}],
            'expect_reply': True, 'expected_upstream': 1, 'ttl_checks': [],
        }]}

    def test_missing_and_additional_outcomes_cannot_pass(self):
        empty = dict(self.trace, rows=[])
        self.assertEqual(compare(self.trace, empty)['unexecuted'], 1)
        self.assertEqual(compare(empty, self.trace)['unexecuted'], 1)

    def test_false_cache_hit_cannot_hide_a_missing_upstream(self):
        candidate = copy.deepcopy(self.trace)
        candidate['rows'][0]['upstream'].clear()
        self.assertEqual(len(compare(self.trace, candidate)['differences']), 1)

    def test_live_comparison_controls_detect_every_mutation(self):
        unchanged = copy.deepcopy(self.trace)
        checks = comparison_controls(self.trace)
        self.assertEqual(len(checks), 3)
        self.assertTrue(all(check['detected'] for check in checks))
        self.assertEqual(self.trace, unchanged)


if __name__ == '__main__':
    unittest.main()
