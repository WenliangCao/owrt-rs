"""Reject corrupted CPU samples instead of turning them into speedups."""
import json
from pathlib import Path
import tempfile
import unittest

from r101_libubus_paired_report import process_identity, verify_segment


class SampleValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = {'iterations': 1000, 'warmup': 100, 'subject_cpu': 1,
                     'client_cpu': 0, 'clock_resolution_ns': 1}
        self.sample = {
            'n': 1000, 'warmup': 100, 'subject_pid': 36, 'client_pid': 40,
            'subject_cpu': 1, 'client_cpu': 0, 'subject_resolution_ns': 1,
            'client_resolution_ns': 1, 'subject_before_ns': 10000000,
            'subject_after_ns': 60000000, 'client_before_ns': 6000000,
            'client_after_ns': 50000000, 'wall_before_ns': 19000000000,
            'wall_after_ns': 19100000000, 'full_signature_checked': True,
            'last_type_reset_checked_each_cycle': True, 'final_empty': True,
        }
        # Include spaces and ')' in comm: parse from the last closing paren.
        self.stat = '36 (bus ) worker) S ' + '0 ' * 16 + '1 0 1964178\n'
        self.status = 'Pid:\t36\nTgid:\t36\nThreads:\t1\nCpus_allowed_list:\t1\n'
        for when in ['before', 'after']:
            (self.root / f'x-stat-{when}.txt').write_text(self.stat)
            (self.root / f'x-status-{when}.txt').write_text(self.status)

    def verify(self):
        (self.root / 'x.json').write_text(json.dumps(self.sample))
        return verify_segment(self.root, 'x', self.plan, 36)

    def test_known_aggregate_units_and_comm_parsing(self):
        self.assertEqual(process_identity(self.stat), (36, 1964178))
        row = self.verify()
        self.assertEqual([row[k] for k in ['subject_cpu_us', 'client_cpu_us',
                                         'total_cpu_us', 'wall_us']], [50, 44, 94, 100])

    def test_rejects_bad_measurements(self):
        for key, value in [('n', 999), ('warmup', 99), ('subject_pid', 37),
                           ('client_pid', 36), ('subject_cpu', 0), ('client_cpu', 1),
                           ('subject_resolution_ns', 0), ('full_signature_checked', False),
                           ('last_type_reset_checked_each_cycle', False), ('final_empty', False),
                           ('subject_after_ns', 9999999), ('client_after_ns', 900000000),
                           ('wall_after_ns', 19000000000)]:
            with self.subTest(key=key):
                old = self.sample[key]
                self.sample[key] = value
                with self.assertRaises(AssertionError):
                    self.verify()
                self.sample[key] = old

    def test_rejects_reused_pid(self):
        (self.root / 'x-stat-after.txt').write_text(self.stat.replace('1964178', '1964179'))
        with self.assertRaises(AssertionError):
            self.verify()

    def test_rejects_changed_thread_or_affinity(self):
        for text in [self.status.replace('Threads:\t1', 'Threads:\t2'),
                     self.status.replace('Cpus_allowed_list:\t1', 'Cpus_allowed_list:\t0-1')]:
            (self.root / 'x-status-after.txt').write_text(text)
            with self.assertRaises(AssertionError):
                self.verify()


if __name__ == '__main__':
    unittest.main()
