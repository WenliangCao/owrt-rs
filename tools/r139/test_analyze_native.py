#!/usr/bin/env python3
"""Guard evidence rejection and the strictly bounded descriptive decision."""
import copy
from fractions import Fraction
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r139 import analyze_native as report


def fixture():
    return {'n': 4, 'successful': 4, 'latency_sample_count': 4, 'warmup': 20, 'errors': 0,
            'subject_pid': 10, 'client_pid': 20, 'subject_cpu': 1, 'client_cpu': 0,
            'full_signature_checked': True, 'last_type_reset_checked_each_cycle': True,
            'final_empty': True, 'final_signature_checked': True, 'latency_overhead_unsubtracted': True,
            'latency_clock': 'CLOCK_MONOTONIC', 'latency_quantile': 'ordered[round((n-1)*q)]',
            'subject_resolution_ns': 1, 'client_resolution_ns': 1, 'latency_resolution_ns': 1,
            'latency_ns': [10, 40, 20, 30], 'mean_us': .025, 'p50_us': .030,
            'p95_us': .040, 'p99_us': .040, 'subject_before_ns': 1000, 'subject_after_ns': 1050,
            'client_before_ns': 1000, 'client_after_ns': 1060, 'wall_before_ns': 1000, 'wall_after_ns': 1120}


class NativeEvidence(unittest.TestCase):
    def test_raw_reconstruction(self):
        data = fixture()
        measured = report.measurement(data, (10, 99), n=4)
        self.assertEqual(measured['p50_us'], Fraction(30, 1000))
        self.assertEqual(measured['daemon_cpu_us_per_op'], Fraction(50, 4000))
        self.assertEqual(measured['caller_cpu_us_per_op'], Fraction(60, 4000))
        self.assertEqual(measured['outer_wall_us_per_op'], Fraction(120, 4000))
        self.assertEqual(data['latency_ns'], [10, 40, 20, 30])

    def test_corrupt_evidence_rejected(self):
        mutations = {'n': 5, 'n_bool': True, 'latency_ns': [10, 40, 20, 31], 'mean_us': .026,
                     'p50_us': .020, 'p95_us': float('nan'), 'subject_after_ns': 999,
                     'client_after_ns': 1000, 'wall_after_ns': 1099, 'client_pid': 10,
                     'subject_pid': 11, 'client_cpu': 1, 'final_signature_checked': False,
                     'last_type_reset_checked_each_cycle': 1, 'latency_resolution_ns': 0}
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                data = copy.deepcopy(fixture())
                data['n' if key == 'n_bool' else key] = value
                report.measurement(data, (10, 99), n=4)

    def test_strict_threshold_and_direction_count(self):
        for gaps, expected in [([-5] * 4, 'unresolved'), ([5] * 4, 'unresolved'),
                               ([-6, -6, -6, 20], 'lower'), ([-20, 6, 6, 6], 'higher'),
                               ([-30, -10, 1, 1], 'unresolved')]:
            with self.subTest(gaps=gaps):
                indexed = {}
                for window, delta in enumerate(gaps):
                    indexed[window, 'c'] = {m: Fraction(100) for m in report.ALL_METRICS}
                    indexed[window, 'candidate'] = {m: Fraction(100 + delta) for m in report.ALL_METRICS}
                result = report.comparisons(indexed)
                self.assertEqual(result['primary_p95_diagnostic'], expected)
                self.assertEqual(result['paired_candidate_vs_c']['p95_us']['delta_pct']['by_window'], gaps)


if __name__ == '__main__':
    unittest.main()
