import unittest
from analyze_candidate import process_clock_delta


class CpuClockAccounting(unittest.TestCase):
    def test_delta_uses_nanoseconds_not_ticks_or_children(self):
        before = dict(pid=7, start_ticks=100, process_cpu_ns=1_000_010,
                      process_cpu_resolution_ns=1, cpu_ticks=9, child_cpu_ticks=200)
        after = dict(before, process_cpu_ns=1_000_133, cpu_ticks=9, child_cpu_ticks=300)
        self.assertEqual(process_clock_delta(before, after), 123)
        for change in ({'pid': 8}, {'start_ticks': 101}, {'process_cpu_ns': 1_000_000},
                       {'process_cpu_resolution_ns': 1000}):
            with self.subTest(change=change), self.assertRaises(AssertionError):
                process_clock_delta(before, dict(after, **change))
        with self.assertRaises(KeyError):
            process_clock_delta({'pid': 7, 'start_ticks': 100}, after)


if __name__ == '__main__':
    unittest.main()
