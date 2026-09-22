#!/usr/bin/env python3
"""Counter eligibility must fail closed for unusable diagnostic evidence."""
from pathlib import Path
import tempfile
import unittest

import r132_registration_report as report


class PerfCsvTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "perf.csv"
        self.rows = [f"{0 if event == 'cpu-migrations' else 123};;{event};1000000;100.00;;"
                     for event in report.COUNTERS]

    def parse(self, rows):
        self.path.write_text("\n".join(rows) + "\n")
        return report.parse_csv(self.path)

    def test_exact_integer_counts(self):
        self.rows[0] = self.rows[0].replace("123;", "9007199254740993;", 1)
        self.assertEqual(self.parse(self.rows)["instructions:u"]["count"], 9007199254740993)

    def test_ineligible_counter_sets(self):
        cases = {
            "missing": self.rows[:-1],
            "duplicate": self.rows + self.rows[:1],
            "multiplexed": [self.rows[0].replace("100.00", "99.99"), *self.rows[1:]],
            "unsupported": [self.rows[0].replace("123", "<not supported>"), *self.rows[1:]],
            "migration": [*self.rows[:-1], self.rows[-1].replace("0;;", "1;;", 1)],
            "unknown": [self.rows[0].replace("instructions:u", "instructions"), *self.rows[1:]],
            "fractional": [self.rows[0].replace("123", "123.5"), *self.rows[1:]],
            "nonfinite_runtime": [self.rows[0].replace("1000000", "NaN"), *self.rows[1:]],
        }
        for name, rows in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.parse(rows)


if __name__ == "__main__":
    unittest.main()
