#!/usr/bin/env python3
"""Prepared reload evidence rejects false no-ops and CPU from reset/check work."""
import copy
import json
import shutil
from pathlib import Path
import tempfile
import unittest

from analyze_candidate import derive, prepared_exec


class ReloadEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raw = Path(self.tmp.name)
        self.lane = self.raw / 'single_change'
        self.lane.mkdir()
        self.one = self.lane / 'iteration-000000'
        self.one.mkdir()
        self.md5 = b'11 network\n22 firewall\n'
        self.events = (7).to_bytes(4, 'little') + b'network' + bytes(4)
        for path, value in ((self.raw / 'single.md5', self.md5),
                            (self.lane / 'expected.md5', self.md5),
                            (self.lane / 'expected.events', self.events),
                            (self.one / 'after.md5', self.md5),
                            (self.one / 'repeat.md5', self.md5),
                            (self.one / 'after.events', self.events),
                            (self.one / 'repeat.events', b'')):
            path.write_bytes(value)
        for execution in ('exec', 'repeat'):
            for kind in ('stdout', 'stderr'):
                (self.one / (execution + '.' + kind)).write_bytes(b'')
            (self.one / (execution + '.status')).write_text('exit status: 0\n')
        (self.raw / 'reload-roles.json').write_text(json.dumps({'ubusd': 1, 'receiver': 2, 'logd': 3}))
        dependencies = []
        for pid in (1, 2, 3):
            before = {'pid': pid, 'start_ticks': 1, 'process_cpu_resolution_ns': 1,
                      'process_cpu_ns': 10000, 'child_cpu_ticks': 0}
            after = {**before, 'process_cpu_ns': 11000}
            dependencies.append({'pid': pid, 'before': before, 'after': after, 'cpu_clock_ns': 1000})
        self.sample = {'iteration': 0, 'phase': 'measured', 'event': 'completed',
                       'latency_ns': 1000000, 'prepare_ns': 9000000, 'validation_ns': 8000000,
                       'command_user_us': 100, 'command_system_us': 200, 'caller_cpu_ns': 5000,
                       'child_counter_source': 'getrusage(RUSAGE_CHILDREN)',
                       'command_before': {'user_us': 100000, 'system_us': 200000},
                       'command_after': {'user_us': 100100, 'system_us': 200200},
                       'dependencies': dependencies, 'baseline_matches': True,
                       'events_match': True, 'repeat_silent': True}
        self.data = {'mode': 'prepared-exec', 'successful': 1, 'warmup': 0, 'timeouts': 0,
                     'resource_samples': 0, 'task_samples': 0, 'measured': [self.sample], 'latency_ns': [1000000],
                     'wall_s': .001, 'envelope_s': .100, 'ops_per_s': 1000,
                     'mean_us': 1000, 'p50_us': 1000, 'p95_us': 1000, 'p99_us': 1000,
                     'accounting': 'per-exec', 'dependency_envelope': copy.deepcopy(dependencies)}
        self.journal()

    def journal(self):
        start = {'iteration': 0, 'phase': 'measured', 'event': 'started'}
        (self.lane / 'samples.jsonl').write_text(json.dumps(start) + '\n' + json.dumps(self.sample) + '\n')

    def derive(self):
        return prepared_exec(self.raw / 'single_change.json', self.data)

    def test_exec_cpu_and_throughput_exclude_reset_checks_and_repeat(self):
        result = self.derive()
        self.assertEqual(result['command_tree_cpu_us_per_op'], 300)
        self.assertEqual(result['client_cpu_clock_us_per_op'], 5)
        self.assertEqual(result['ubusd_cpu_clock_us_per_op'], 1)
        self.assertEqual(result['prepare_us_per_op'], 9000)
        self.assertEqual(result['validation_us_per_op'], 8000)
        self.assertEqual(result['ops_per_s'], 1000)

    def test_complete_four_side_collection_keeps_new_cpu_and_fixture_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sides = ['stock', 'r89', 'r94', 'candidate']
            subjects = dict(zip(sides, ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]))
            settings = {'component': 'reload-config', 'matrix': True, 'baseline_label': 'r89',
                        'schedule': 'random-blocks', 'reload_prepared_exec': True,
                        'reload_workloads': ['single_change'], 'reload_warmup': 0,
                        'extra_baselines': {'r94': {'subject_sha256': subjects['r94'],
                            'provenance': {'subject_sha256': subjects['r94']}}}}
            for name, value in {'order.json': sides, 'subjects.json': subjects,
                                'settings.json': settings,
                                'host-manifest.json': {'components': {'ubusd': {'original': {'sha256': 'bus'}}}}}.items():
                (root / name).write_text(json.dumps(value))
            for phase in ('before', 'after'):
                (root / ('health-' + phase + '.json')).write_text(json.dumps({'boot_id': 'boot'}))
                (root / ('config-' + phase + '.sha256')).write_text('unchanged production')
            (root / 'COMPLETE').touch()
            for index, side in enumerate(sides, 1):
                local = root / f'{index:02d}-{side}'
                raw = local / 'raw'
                shutil.copytree(self.raw, raw)
                (local / 'COMPLETE').touch(); (raw / 'COMPLETE').touch()
                (local / 'raw.tar.gz').write_bytes(b'archive fixture')
                (raw / 'single_change.json').write_text(json.dumps({**self.data, 'errors': 0, 'daemon_cpu': []}))
                (raw / 'meta.json').write_text(json.dumps({'component': 'reload-config',
                    'dependencies': 'original OpenWrt', 'subject_pid': None, 'iterations': 20}))
                values = {'binary-sha256.txt': subjects[side], 'boot-id.txt': 'boot',
                          'benchmark-sha256.txt': 'bench /bench\nns /ns',
                          'harness-sha256.txt': 'harness /harness', 'kernel.txt': 'kernel',
                          'reload-fixtures.sha256': 'unchanged fixture',
                          'reload-running-dependencies.sha256': 'bus /proc/1/exe\nbench /proc/2/exe\nlog /proc/3/exe',
                          'reload-dependencies.sha256': 'bus /sbin/ubusd\nlog /sbin/logd\n' + subjects['stock'] + ' /sbin/reload_config'}
                for name, value in values.items(): (raw / name).write_text(value + '\n')
            result = derive(root, 'four-side prepared fixture')
            self.assertTrue(result['acceptance_eligible'])
            summary = result['summary']['single_change']
            self.assertEqual(summary['candidate']['command_tree_cpu_us_per_op']['median'], 300)
            self.assertEqual(summary['candidate']['receiver_cpu_clock_us_per_op']['median'], 1)
            self.assertIn('candidate_vs_r94_pct', summary)
            (root / '03-r94/raw/reload-fixtures.sha256').write_text('wrong fixture')
            with self.assertRaisesRegex(AssertionError, 'fixtures changed'): derive(root, 'bad')

    def test_missing_duplicate_wrong_order_or_nonzero_result_is_rejected(self):
        for bad in (b'', self.events * 2, self.events[:-1] + b'\1', b'network\n'):
            with self.subTest(bad=bad):
                (self.one / 'after.events').write_bytes(bad)
                with self.assertRaises(AssertionError): self.derive()

    def test_repeat_event_and_complete_baseline_mismatch_are_rejected(self):
        (self.one / 'repeat.events').write_bytes(self.events)
        with self.assertRaises(AssertionError): self.derive()
        (self.one / 'repeat.events').write_bytes(b'')
        (self.one / 'after.md5').write_bytes(self.md5[:-1])
        with self.assertRaises(AssertionError): self.derive()

    def test_cpu_counter_and_journal_mismatch_are_rejected(self):
        self.sample['command_user_us'] += 1
        self.journal()
        with self.assertRaisesRegex(AssertionError, 'raw counters'): self.derive()
        self.sample['command_user_us'] -= 1
        with self.assertRaisesRegex(AssertionError, 'durable'): self.derive()

    def test_envelope_time_cannot_be_called_exec_throughput(self):
        self.data['wall_s'] = self.data['envelope_s']
        with self.assertRaisesRegex(AssertionError, 'reset/check'): self.derive()


if __name__ == '__main__':
    unittest.main()
