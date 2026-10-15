import json
from pathlib import Path
import tempfile
import unittest

from udp_allocation_device_run import meter_report


class MeterReportTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        counts = dict(scheduled=1000, sent=1000, correct=1000, timeout=0, wrong=0,
                      transport_error=0, scheduled_skipped=0)
        (folder / 'prewarm.json').write_text(json.dumps({'measurement': counts, 'interrupted': False, 'output_failed': False}))
        (folder / 'client.json').write_text(json.dumps({'warmup': counts, 'measurement': {'correct': 4000}}))
        sample = {'processes': [{'thread_count': 1}], 'tree_truncated': False}
        for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl'):
            (folder / name).write_text(json.dumps(sample) + '\n')
        histogram = [0] * 65
        histogram[5] = 5200
        meter = {'kinds': ['no_packet_or_error', 'other_packet', 'local', 'cached', 'stale'],
                 'columns': ['alloc', 'dealloc', 'realloc', 'requested_bytes', 'released_bytes'],
                 'turn_kinds': ['no_packet', 'cached_only', 'mixed_or_other'],
                 'turn_columns': ['turns', 'cached_queries', 'alloc', 'dealloc', 'realloc', 'requested_bytes', 'released_bytes'],
                 'queries': [6000, 800, 0, 5200, 0], 'nested_steps': 0, 'unscoped_classifications': 0,
                 'totals': [[0] * 5 for _ in range(3)] + [[26000, 26000, 0, 1404000, 1404000], [0] * 5],
                 'cached_allocation_histogram_64_is_overflow': histogram,
                 'whole_owner_turns': [[6000, 0, 1, 1, 0, 8, 8], [5200, 5200, 26000, 26000, 0, 1404000, 1404000], [800, 0, 0, 0, 0, 0, 0]]}
        (folder / 'udp-alloc.json').write_text(json.dumps(meter))
        return folder, meter

    def test_actual_cached_denominator_includes_prewarm_and_turns_stay_distinct(self):
        folder, _ = self.fixture()
        result = meter_report(folder)
        self.assertEqual(result['consumed_packet_steps'], 6000)
        self.assertEqual(result['cached_step_per_query']['alloc'], 5)
        self.assertEqual(result['conditional_cached_only_turn_per_query']['alloc'], 5)
        self.assertEqual(result['all_owner_turn_totals']['alloc'], 26001)

    def test_unscoped_or_nested_counts_are_rejected(self):
        for key in ('nested_steps', 'unscoped_classifications'):
            folder, meter = self.fixture()
            meter[key] = 1
            (folder / 'udp-alloc.json').write_text(json.dumps(meter))
            with self.assertRaises(AssertionError):
                meter_report(folder)

    def test_wrong_denominator_or_histogram_is_rejected(self):
        folder, meter = self.fixture()
        meter['queries'][3] = 5000
        (folder / 'udp-alloc.json').write_text(json.dumps(meter))
        with self.assertRaises(AssertionError):
            meter_report(folder)

    def test_multiple_threads_are_rejected(self):
        folder, _ = self.fixture()
        (folder / 'resources.jsonl').write_text(json.dumps({'processes': [{'thread_count': 2}], 'tree_truncated': False}) + '\n')
        with self.assertRaises(AssertionError):
            meter_report(folder)


if __name__ == '__main__':
    unittest.main()
