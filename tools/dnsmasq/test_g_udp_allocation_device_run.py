import json
import unittest

import g_udp_allocation_device_run as diagnostic
import udp_allocation_device_run as original
from test_udp_allocation_device_run import MeterReportTests


class GAllocationTests(unittest.TestCase):
    def test_original_parser_is_reused_without_a_zero_target(self):
        self.assertIs(diagnostic.meter_report, original.meter_report)
        folder, _ = MeterReportTests.fixture(self)
        result = diagnostic.meter_report(folder)
        self.assertEqual(result['cached_step_per_query']['alloc'], 5)
        self.assertEqual(result['raw']['queries'][3], 5200)

    def test_zero_counts_are_allowed_using_actual_cached_query_denominator(self):
        folder, meter = MeterReportTests.fixture(self)
        meter['totals'][3] = [0] * 5
        meter['cached_allocation_histogram_64_is_overflow'] = [5200] + [0] * 64
        meter['whole_owner_turns'][1] = [5200, 5200] + [0] * 5
        (folder / 'udp-alloc.json').write_text(json.dumps(meter))
        result = diagnostic.meter_report(folder)
        self.assertEqual(result['cached_step_per_query']['alloc'], 0)
        self.assertEqual(result['conditional_cached_only_turn_per_query']['alloc'], 0)
        self.assertEqual(result['raw']['queries'][3], 5200)
        meter['cached_allocation_histogram_64_is_overflow'][0] = 5000
        (folder / 'udp-alloc.json').write_text(json.dumps(meter))
        with self.assertRaises(AssertionError):
            diagnostic.meter_report(folder)


if __name__ == '__main__':
    unittest.main()
