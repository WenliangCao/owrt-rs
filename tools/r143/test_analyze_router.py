#!/usr/bin/env python3
"""Decision, pairing and raw-memory boundaries; no router or timing execution."""
import copy
from fractions import Fraction as F
import unittest
import analyze_router as report


class InferenceTests(unittest.TestCase):
    def data(self):
        return {(w, s): {m: F(100) for m in report.METRICS} for w in range(10) for s in report.SUBJECTS}

    def test_exact_binomial_tails(self):
        self.assertEqual(report.binomial_tail(10), F(1, 1024))
        self.assertEqual(report.binomial_tail(9), F(11, 1024))
        self.assertEqual(report.binomial_tail(8), F(56, 1024))
        self.assertEqual(report.binomial_tail(0), 1)

    def test_complete_family_penalty_and_holm_stepdown(self):
        data = self.data()
        for w in range(9):
            data[w, 'candidate']['mean_us'] = F(98)
        result = report.performance_comparisons(data)
        self.assertEqual(result['primary_mean_direction'], 'unresolved')
        lower = result['hypotheses'][0]
        self.assertEqual(lower['holm_p']['value'], float(F(66, 1024)))
        for w in range(10):
            data[w, 'candidate']['p95_us'] = data[w, 'candidate']['p99_us'] = F(102)
        result = report.performance_comparisons(data)
        self.assertEqual(result['primary_mean_direction'], 'lower_beyond_1pct')
        self.assertEqual(result['hypotheses'][0]['holm_p']['value'], float(F(44, 1024)))
        self.assertEqual(result['confirmed_negative_metrics'], ['p95_us', 'p99_us'])

    def test_threshold_ties_are_nonsupporting_trials(self):
        data = self.data()
        for w in range(10):
            data[w, 'candidate']['mean_us'] = F(99)
            data[w, 'candidate']['p95_us'] = F(101)
        result = report.performance_comparisons(data)
        self.assertTrue(all(row['n'] == 10 and row['supporting_windows'] == 0 for row in result['hypotheses']))
        self.assertTrue(result['paired_r136_vs_c']['mean_us']['median_within_1pct'])
        self.assertEqual(result['primary_mean_direction'], 'unresolved')

    def test_magnitude_alone_not_confirmation_and_cpu_excluded(self):
        data = self.data()
        for w in range(10):
            data[w, 'candidate']['mean_us'] = F(98 if w < 6 else 101)
            data[w, 'candidate']['daemon_cpu_us_per_op'] = F(200)
        result = report.performance_comparisons(data)
        self.assertFalse(result['paired_r136_vs_c']['mean_us']['median_within_1pct'])
        self.assertEqual(result['primary_mean_direction'], 'unresolved')
        self.assertEqual(result['family_size'], 6)

    def test_missing_window_rejected(self):
        data = self.data()
        del data[9, 'c']
        with self.assertRaises(ValueError):
            report.performance_comparisons(data)

    def test_holm_monotone_equal_p_values_and_alpha_boundary(self):
        self.assertEqual(report.holm([F(1, 120)] * 6), [F(1, 20)] * 6)
        self.assertEqual(report.holm([F(1), F(1, 100), F(1, 1000)]), [F(1), F(1, 50), F(3, 1000)])


class MemoryTests(unittest.TestCase):
    def rows(self):
        rows = []
        for i, (phase, size) in enumerate(report.PHASES):
            for delay in (1000, 5000):
                rows.append({'phase': phase, 'payload_bytes': size, 'delay_ms': delay,
                             'elapsed_ms': i * 5000 + delay, 'subject_pid': 7, 'start_ticks': '123',
                             'fds': 4 if phase in ('empty', 'disconnected') else 6,
                             **{m: 100 + i * 4 for m in report.MEMORY}})
        return rows + [{'phase': 'COMPLETE', 'full_mirror_bytes_checked': True,
                        'mirror_frames': 10, 'subject_pid': 7, 'smoke': False}]

    def test_retained_growth_preserved(self):
        rows = report.memory(self.rows(), (7, 123))
        self.assertEqual(len(rows), 16)
        self.assertEqual(rows[-1]['growth_from_empty_kib']['rss_kib'], 28)
        self.assertEqual(rows[-1]['fds'], 4)

    def test_smoke_missing_wait_fd_or_pid_rejected(self):
        mutations = [(16, 'smoke', True), (15, 'elapsed_ms', 39999),
                     (15, 'fds', 6), (3, 'subject_pid', 8), (4, 'delay_ms', 0)]
        for index, key, value in mutations:
            rows = copy.deepcopy(self.rows())
            rows[index][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                report.memory(rows, (7, 123))


class PerformanceReaderTests(unittest.TestCase):
    def test_native_5000_quantiles_and_process_clocks(self):
        rows = [{'phase': phase, 'subject_pid': 7, 'fds': fds, 'rss_kib': 100,
                 'rssanon_kib': 40, 'vmdata_kib': 300}
                for phase, fds in zip(('empty', 'registered', 'delivered', 'closed'), (4, 7, 7, 4))]
        rows.append({'phase': 'RESULT', 'mode': 'monitor', 'n': 5000, 'warmup': 20, 'handlers': 8,
                     'owners': 1, 'subject_pid': 7, 'subject_cpu': 1, 'client_cpu': 0,
                     'payload_bytes': 0, 'c_txq_limit_bytes': 1048576, 'received': 40000, 'mirrored': 40000,
                     'flooded_received': 0, 'payload_target_order_sequence_checked': True,
                     'handlers_removed': True, 'fd_baseline_restored': True, 'wall_ns': 20000000,
                     'daemon_cpu_ns': 15000000, 'caller_cpu_ns': 10000000, 'latency_ns': list(range(1, 5001))})
        metrics, _ = report.performance(rows, (7, 123))
        self.assertEqual(metrics['mean_us'], F(5001, 2000))
        self.assertEqual(metrics['p50_us'], F(2501, 1000))
        self.assertEqual(metrics['p95_us'], F(19, 4))
        self.assertEqual(metrics['p99_us'], F(99, 20))
        self.assertEqual(metrics['daemon_cpu_us_per_op'], 3)
        rows[-1]['n'] = 2000
        with self.assertRaises(ValueError):
            report.performance(rows, (7, 123))


if __name__ == '__main__':
    unittest.main()
