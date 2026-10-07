#!/usr/bin/env python3
"""Offline FD stability controls; no daemon, namespace or Oracle workload."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m5_script_arp as arp


class Clock:
    value = 0.0
    def monotonic(self):
        return self.value
    def sleep(self, seconds):
        self.value += seconds


def identity(target='socket:[31]', inode=31):
    return {'descriptors': {'3': {'target': target, 'device': 8, 'inode': inode,
                                  'mode': 0o140777, 'flags': '02004002', 'mount_id': '8'}},
            'process_starttime_ticks': 100}


class DescriptorStability(unittest.TestCase):
    def observe(self, value, clock, complete=True):
        return {**copy.deepcopy(value), 'complete': complete, 'races': [] if complete else ['FD closed during read'],
                'captured_monotonic_ns': int(clock.value * 1e9), 'captured_wall_ns': int(clock.value * 1e9)}

    def run_guard(self, path, values, expected=None, timeout=.08):
        clock = Clock(); index = 0
        def snapshot(pid):
            nonlocal index
            item = values[min(index, len(values) - 1)]; index += 1
            if isinstance(item, tuple):
                value, complete = item
            else:
                value, complete = item, True
            return self.observe(value, clock, complete)
        with patch.object(arp, 'descriptor_snapshot', side_effect=snapshot), \
                patch.object(arp.time, 'monotonic', side_effect=clock.monotonic), \
                patch.object(arp.time, 'sleep', side_effect=clock.sleep):
            return arp.stable_descriptors(26, path, expected=expected, timeout=timeout)

    def test_baseline_must_stabilize_before_health(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'baseline.json'
            transient = identity('/proc/26/net/if_inet6', 50)
            result = self.run_guard(path, [transient, identity(), identity(), identity()])
            self.assertTrue(result['passed']); self.assertEqual(result['stable_identity'], identity())
            self.assertEqual([row['consecutive_stable_samples'] for row in result['observations']], [1, 1, 2, 3])
            self.assertEqual(len(json.loads(path.read_text())['observations']), 4)

    def test_transient_extra_fd_is_observed_then_exact_set_must_hold(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'recovery.json'
            extra = identity(); extra['descriptors']['19'] = identity('/proc/26/net/if_inet6', 90)['descriptors']['3']
            result = self.run_guard(path, [extra, extra, identity(), identity(), identity()], expected=identity())
            self.assertTrue(result['passed']); self.assertEqual(result['stable_identity'], identity())
            self.assertEqual(len(result['observations']), 5)
            self.assertEqual(result['observations'][0]['descriptors']['19']['target'], '/proc/26/net/if_inet6')
            self.assertFalse(result['observations'][0]['matches_expected'])
            self.assertEqual(result['observations'][-1]['consecutive_stable_samples'], 3)
            self.assertGreaterEqual(result['observations'][-1]['captured_monotonic_ns'], 80_000_000)

    def test_permanent_extra_fd_and_same_count_replacements_are_rejected(self):
        extra = identity(); extra['descriptors']['19'] = identity('/leaked/file', 91)['descriptors']['3']
        changed_number = identity(); changed_number['descriptors']['4'] = changed_number['descriptors'].pop('3')
        for label, value in [('leak', extra), ('same-count-target', identity('socket:[99]', 99)),
                             ('same-count-number', changed_number), ('same-target-inode', identity(inode=99))]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'failed.json'
                with self.subTest(label=label), self.assertRaises(TimeoutError):
                    self.run_guard(path, [value], expected=identity())
                receipt = json.loads(path.read_text())
                self.assertFalse(receipt['passed'])
                self.assertTrue(receipt['observations'])
                self.assertTrue(all(row['consecutive_stable_samples'] == 0 for row in receipt['observations']))

    def test_race_and_intervening_change_reset_consecutive_stability(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'race.json'
            result = self.run_guard(path, [identity(), (identity(), False), identity(), identity(), identity()], expected=identity())
            self.assertEqual([row['consecutive_stable_samples'] for row in result['observations']], [1, 0, 1, 2, 3])
            self.assertFalse(result['observations'][1]['complete'])

    def test_process_identity_change_and_unstable_baseline_are_rejected(self):
        reused = identity(); reused['process_starttime_ticks'] = 101
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TimeoutError):
                self.run_guard(Path(directory) / 'pid.json', [reused], expected=identity())
            with self.assertRaises(TimeoutError):
                self.run_guard(Path(directory) / 'baseline.json', [identity(), reused] * 5)


class DescriptorSnapshot(unittest.TestCase):
    def test_snapshot_records_number_target_inode_flags_mount_and_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); process = root / '26'; (process / 'fd').mkdir(parents=True)
            (process / 'fdinfo').mkdir()
            values = ['S'] + ['0'] * 18 + ['123'] + ['0'] * 2
            (process / 'stat').write_text('26 (fixture daemon) ' + ' '.join(values))
            target = root / 'actual-open-file'; target.write_text('fixture')
            (process / 'fd/3').symlink_to(target)
            (process / 'fdinfo/3').write_text('pos:\t0\nflags:\t02004002\nmnt_id:\t8\n')
            result = arp.descriptor_snapshot(26, root)
            self.assertTrue(result['complete']); self.assertEqual(result['process_starttime_ticks'], 123)
            self.assertEqual(result['descriptors']['3']['target'], str(target))
            self.assertEqual(result['descriptors']['3']['inode'], target.stat().st_ino)
            self.assertEqual(result['descriptors']['3']['flags'], '02004002')
            self.assertGreater(result['captured_monotonic_ns'], result['started_monotonic_ns'])
            (process / 'fdinfo/3').unlink()
            incomplete = arp.descriptor_snapshot(26, root)
            self.assertFalse(incomplete['complete']); self.assertTrue(incomplete['races'])


if __name__ == '__main__':
    unittest.main()
