"""Exhaustive sign-pattern coverage check, not a Monte Carlo demonstration."""
import itertools
import math
import unittest
from r99_registration_cpu_report import median_interval


class RankIntervalTests(unittest.TestCase):
    def test_exact_coverage_and_maximal_rank(self):
        for n in range(1, 13):
            for comparisons in [1, 2, 10]:
                interval = median_interval(list(range(n)), comparisons)
                if interval is None:
                    self.assertGreater(2 / 2**n, 0.05 / comparisons)
                    continue
                k = interval['rank']
                covered = 0
                for signs in itertools.product([-1, 1], repeat=n):
                    ordered = sorted(sign * (i + 1) for i, sign in enumerate(signs))
                    covered += ordered[k - 1] <= 0 <= ordered[n - k]
                expected = 1 - 2 * sum(math.comb(n, j) for j in range(k)) / 2**n
                self.assertEqual(covered / 2**n, expected)
                self.assertEqual(interval['marginal_coverage_lower_bound'], expected)
                self.assertGreaterEqual(expected, 1 - 0.05 / comparisons)
                self.assertGreater(sum(math.comb(n, j) for j in range(k + 1)) / 2**n,
                                   0.05 / (2 * comparisons))

    def test_eight_pairs_two_metrics_use_extremes(self):
        r = median_interval([1.04, 0.96, 1.03, 0.97, 1.02, 0.98, 1.01, 0.99], 2)
        self.assertEqual((r['lower'], r['upper'], r['rank']), (0.96, 1.04, 1))


if __name__ == '__main__':
    unittest.main()
