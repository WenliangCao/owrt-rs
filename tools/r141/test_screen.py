#!/usr/bin/env python3
"""Guard PGO eligibility boundaries and prohibit pooling away a failed CPU pair."""
from fractions import Fraction as F
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r141.analyze_screen import contrast, decisions, METRICS

POLICY = json.loads(Path(__file__).with_name('screen-policy.json').read_text())


def fixture(ratio=F(97, 100)):
    return {(tuple(pair), affinity, lane, label, block):
            {metric: F(100) * (ratio if label == 'pgo' else 1) for metric in METRICS}
            for pair in POLICY['pairs'] for affinity in POLICY['affinities'] for lane in POLICY['lanes']
            for label in ('c', 'r136', 'pgo') for block in range(4)}


class ScreenRules(unittest.TestCase):
    def test_inclusive_one_percent_band_is_unresolved(self):
        for value in (F(99), F(100), F(101)):
            self.assertEqual(contrast([value] * 4, [F(100)] * 4)['direction'], 'unresolved_within_1pct')

    def test_strict_primary_boundary(self):
        self.assertFalse(decisions(fixture(F(99, 100)), POLICY)['screen_passed'])
        self.assertTrue(decisions(fixture(F(989, 1000)), POLICY)['screen_passed'])

    def test_both_cpu_pairs_must_pass(self):
        data = fixture()
        for lane in POLICY['lanes']:
            for block in range(4):
                data[(2, 3), 'split', lane, 'pgo', block]['mean_us'] = F(999, 10)
        result = decisions(data, POLICY)
        self.assertEqual([p['passed'] for p in result['primary']], [True, False])
        self.assertFalse(result['screen_passed'])

    def test_three_of_four_primary_sign_gate(self):
        data = fixture()
        for block in (2, 3):
            for lane in POLICY['lanes']:
                data[(0, 1), 'split', lane, 'pgo', block]['mean_us'] = F(1001, 10)
        self.assertFalse(decisions(data, POLICY)['screen_passed'])

    def test_nonprimary_placement_tail_can_veto(self):
        data = fixture()
        for block in range(4):
            data[(2, 3), 'pair_allowed', 'event_8', 'pgo', block]['p99_us'] = F(1031, 10)
        result = decisions(data, POLICY)
        self.assertTrue(all(p['passed'] for p in result['primary']))
        self.assertEqual(len(result['latency_vetoes']), 1)
        self.assertEqual(result['latency_checks'], 60)
        self.assertFalse(result['screen_passed'])

    def test_exact_veto_boundary_and_four_sign_requirement(self):
        data = fixture()
        for block in range(4):
            data[(0, 1), 'split', 'register_16', 'pgo', block]['p95_us'] = F(103)
        self.assertTrue(decisions(data, POLICY)['screen_passed'])
        for block in range(3):
            data[(0, 1), 'split', 'register_16', 'pgo', block]['p95_us'] = F(110)
        data[(0, 1), 'split', 'register_16', 'pgo', 3]['p95_us'] = F(99)
        self.assertTrue(decisions(data, POLICY)['screen_passed'])

    def test_cpu_is_not_a_hidden_veto(self):
        data = fixture()
        for block in range(4):
            data[(0, 1), 'split', 'event_1', 'pgo', block]['daemon_cpu_us_per_op'] = F(10000)
        self.assertTrue(decisions(data, POLICY)['screen_passed'])


if __name__ == '__main__':
    unittest.main()
