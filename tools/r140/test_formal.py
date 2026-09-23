#!/usr/bin/env python3
"""Boundary and counterexample tests for the preregistered R140 decisions."""
from fractions import Fraction as F
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r140.analyze_formal import decisions, LANES, METRICS


def fixture(ratio):
    return {(w, side, lane): {m: F(100) * (ratio if side == 'candidate' else 1) for m in METRICS}
            for w in range(8) for side in ('c', 'r136', 'candidate') for lane in LANES}


class FrozenDecisions(unittest.TestCase):
    def test_strict_primary_boundary(self):
        self.assertFalse(decisions(fixture(F(98, 100)))['primary']['passed'])
        self.assertTrue(decisions(fixture(F(979, 1000)))['performance_rule_passed'])

    def test_primary_sign_gate(self):
        values = fixture(F(97, 100))
        for w in (6, 7):
            for lane in LANES:
                values[w, 'candidate', lane]['mean_us'] = F(101)
        self.assertFalse(decisions(values)['primary']['passed'])

    def test_one_tail_can_veto_broad_mean_improvement(self):
        values = fixture(F(97, 100))
        for w in range(7):
            values[w, 'candidate', 'event_8']['p95_us'] = F(1031, 10)
        result = decisions(values)
        self.assertTrue(result['primary']['passed'])
        self.assertFalse(result['performance_rule_passed'])
        self.assertEqual([(r['lane'], r['metric']) for r in result['latency_vetoes']], [('event_8', 'p95_us')])

    def test_exact_veto_boundary_and_sign_count(self):
        values = fixture(F(97, 100))
        for w in range(7):
            values[w, 'candidate', 'event_8']['p95_us'] = F(103)
        self.assertTrue(decisions(values)['performance_rule_passed'])
        for w in range(6):
            values[w, 'candidate', 'event_8']['p95_us'] = F(110)
        values[6, 'candidate', 'event_8']['p95_us'] = F(99)
        self.assertTrue(decisions(values)['performance_rule_passed'])

    def test_cpu_is_report_only(self):
        values = fixture(F(97, 100))
        for w in range(8):
            values[w, 'candidate', 'event_8']['daemon_cpu_us_per_op'] = F(10000)
        result = decisions(values)
        self.assertTrue(result['performance_rule_passed'])
        self.assertTrue(any(r['metric'] == 'daemon_cpu_us_per_op' for r in result['higher_medians']))

    def test_equal_lane_weights_and_c_does_not_control_adoption(self):
        values = fixture(F(97, 100))
        original = decisions(values)['primary']
        for w in range(8):
            for i, lane in enumerate(LANES, 1):
                for side in ('candidate', 'r136'):
                    values[w, side, lane]['mean_us'] *= 10 ** i
                for metric in METRICS:
                    values[w, 'c', lane][metric] = F(1)
        result = decisions(values)
        self.assertEqual(result['primary'], original)
        self.assertTrue(result['performance_rule_passed'])


if __name__ == '__main__':
    unittest.main()
