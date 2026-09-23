#!/usr/bin/env python3
"""Strict decision-boundary tests; no workload execution."""
from fractions import Fraction as F
import unittest
import monitor_screen as screen


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.policy = screen.read(screen.POLICY)
        self.data = {(block, label, mode): {m: F(100) for m in screen.METRICS}
                     for block, label, mode in screen.schedule(self.policy)}
        for block in range(1, 7):
            self.data[block, 'candidate', 'monitor']['mean_us'] = F(96)

    def result(self):
        return screen.comparisons(self.data, self.policy)

    def test_full_permutations(self):
        schedule = screen.schedule(self.policy)
        self.assertEqual(len(schedule), 54)
        self.assertEqual(len(set(schedule)), 54)
        self.assertTrue(self.result()['screen_passed'])

    def test_strict_primary_boundary(self):
        for block in range(1, 7):
            self.data[block, 'candidate', 'monitor']['mean_us'] = F(97)
        self.assertFalse(self.result()['primary_passed'])

    def test_five_direction_requirement(self):
        self.data[5, 'candidate', 'monitor']['mean_us'] = F(100)
        self.assertTrue(self.result()['primary_passed'])
        self.data[6, 'candidate', 'monitor']['mean_us'] = F(100)
        self.assertFalse(self.result()['primary_passed'])

    def test_guard_threshold_and_direction(self):
        for block in range(1, 7):
            self.data[block, 'candidate', 'grouped']['p99_us'] = F(103)
        self.assertEqual(self.result()['latency_vetoes'], [])
        for block in range(1, 5):
            self.data[block, 'candidate', 'grouped']['p99_us'] = F(104)
        self.data[5, 'candidate', 'grouped']['p99_us'] = F(100)
        self.data[6, 'candidate', 'grouped']['p99_us'] = F(100)
        self.assertEqual(self.result()['latency_vetoes'], [])
        self.data[5, 'candidate', 'grouped']['p99_us'] = F(101)
        self.assertEqual(len(self.result()['latency_vetoes']), 1)
        self.assertFalse(self.result()['screen_passed'])

    def test_cpu_and_c_not_hard_gates(self):
        for block in range(1, 7):
            for mode in self.policy['modes']:
                self.data[block, 'c', mode] = {m: F(1) for m in screen.METRICS}
                self.data[block, 'candidate', mode]['daemon_cpu_us_op'] = F(200)
        self.assertTrue(self.result()['screen_passed'])


if __name__ == '__main__':
    unittest.main()
