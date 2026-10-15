import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import udp_stage_device_run as stage
from udp_stage_device_run import GROUPS, MODES, schedule, stage_report


class StageGateTests(unittest.TestCase):
    def fixture(self, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        def counts(number):
            return dict(scheduled=number, sent=number, correct=number, timeout=0,
                        wrong=0, transport_error=0, scheduled_skipped=0)
        (folder / 'prewarm.json').write_text(json.dumps({'measurement': counts(1000), 'interrupted': False, 'output_failed': False}))
        (folder / 'client.json').write_text(json.dumps({'warmup': counts(1000), 'measurement': counts(4000),
                                                       'interrupted': False, 'output_failed': False}))
        sample = {'processes': [{'pid': 42, 'starttime_ticks': 100, 'thread_count': 1}], 'tree_truncated': False}
        for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl'):
            (folder / name).write_text(json.dumps(sample) + '\n')
        fields = ['0'] * 30
        fields[17], fields[19] = '1', '100'
        (folder / 'final.stat').write_text('42 (dnsmasq) ' + ' '.join(fields))
        for name in ('netns.txt', 'daemon.netns'):
            (folder / name).write_text('net:[1234]\n')
        if mode is not None:
            selected = MODES.index(mode)
            report = {'scope': 'excluded synthetic cumulative-path intervention, not oracle correctness or accepted performance',
                      'mode': selected, 'matched_queries': 6000, 'prewarm_threshold': 1000,
                      'cuts_by_mode': [5000 if index == selected and selected else 0 for index in range(4)]}
            (folder / 'udp-stage.json').write_text(json.dumps(report))
        return folder

    def test_frozen_order_is_five_separate_alternating_pairs_per_group(self):
        rows = schedule()
        self.assertEqual(len(rows), 50)
        self.assertEqual(len({row['label'] for row in rows}), 50)
        for index, (name, left, right) in enumerate(GROUPS):
            group = rows[index * 10:(index + 1) * 10]
            self.assertEqual({row['group'] for row in group}, {name})
            self.assertEqual([row['side'] for row in group], ['c', 'rust', 'rust', 'c', 'c', 'rust', 'rust', 'c', 'c', 'rust'])
            self.assertEqual([row['round'] for row in group], [1, 1, 2, 2, 3, 3, 4, 4, 5, 5])
            for row in group:
                self.assertEqual((row['artifact'], row['mode']), left if row['side'] == 'c' else right)

    def test_every_mode_and_originals_have_required_cohorts(self):
        for mode in (None,) + MODES:
            result = stage_report(self.fixture(mode), mode)
            self.assertEqual(result['correct_fixture_replies'], 6000)
            self.assertEqual(result['thread_samples'], 3)
            self.assertEqual(result['raw'] is None, mode is None)

    def test_wrong_mode_threshold_matching_or_cuts_is_rejected(self):
        for key, value in [('mode', 2), ('mode', True), ('matched_queries', 5000),
                           ('prewarm_threshold', 999), ('cuts_by_mode', [0, 5001, 0, 0]),
                           ('cuts_by_mode', [1, 5000, 0, 0]), ('cuts_by_mode', [0, 5000, 0])]:
            folder = self.fixture('receive')
            report = json.loads((folder / 'udp-stage.json').read_text())
            report[key] = value
            (folder / 'udp-stage.json').write_text(json.dumps(report))
            with self.assertRaises(AssertionError):
                stage_report(folder, 'receive')

    def test_prewarm_failure_is_rejected_even_with_correct_stage_counts(self):
        folder = self.fixture('receive')
        prewarm = json.loads((folder / 'prewarm.json').read_text())
        prewarm['measurement']['correct'] = 999
        prewarm['measurement']['wrong'] = 1
        (folder / 'prewarm.json').write_text(json.dumps(prewarm))
        with self.assertRaises(AssertionError):
            stage_report(folder, 'receive')

    def test_extra_thread_or_different_namespace_is_rejected(self):
        folder = self.fixture('full')
        sample = {'processes': [{'pid': 42, 'starttime_ticks': 100, 'thread_count': 2}], 'tree_truncated': False}
        (folder / 'resources.jsonl').write_text(json.dumps(sample) + '\n')
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')
        folder = self.fixture('full')
        (folder / 'daemon.netns').write_text('net:[9999]\n')
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')

    def test_full_cut_or_original_sidecar_is_rejected(self):
        folder = self.fixture('full')
        report = json.loads((folder / 'udp-stage.json').read_text())
        report['cuts_by_mode'][0] = 5000
        (folder / 'udp-stage.json').write_text(json.dumps(report))
        with self.assertRaises(AssertionError):
            stage_report(folder, 'full')
        with self.assertRaises(AssertionError):
            stage_report(folder, None)

    def run_controller_failure(self, partial_archive, cleanup_fault=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        out = root / 'out'
        health = root / 'health.json'
        health.write_text(json.dumps({'valid': True, 'elapsed_seconds': 125, 'threshold_ms': 200}))
        plan = Path(__file__).resolve().parents[2] / 'docs/dnsmasq/audits/perf-opt-20261015/loop/A53_UDP_STAGE_DEVICE_PLAN.json'
        def archived(destination, label):
            (destination / (label + '.tar.gz')).write_bytes(b'first archive bytes')
            if partial_archive:
                raise ValueError('partial archive extraction failure')
            (destination / (label + '.archive.json')).write_text('{"files":{}}')
            return root
        argv = ['udp_stage_device_run.py', '--plan', str(plan), '--health-baseline', str(health),
                '--stage-hash', '0' * 64, '--out', str(out)]
        def ssh(command, **kwargs):
            if cleanup_fault and command.startswith('cat '):
                raise TimeoutError('guard copy timeout')
            return SimpleNamespace(stdout=b'', returncode=0)
        def stop_owned(reason):
            self.assertTrue((out / 'failure.json').exists())
            if cleanup_fault:
                raise TimeoutError('cleanup timeout')
        fault = TimeoutError('cleanup timeout') if cleanup_fault else None
        with patch('sys.argv', argv), patch.object(stage, 'verify_files'), patch.object(stage, 'set_slots') as slots, \
             patch.object(stage.run, 'production_identity', return_value=[1, 2]), \
             patch.object(stage.run, 'ssh', side_effect=ssh), \
             patch.object(stage.run, 'guard_start', return_value=(3, 4)), \
             patch.object(stage.run, 'guard_check', return_value=True), patch.object(stage.run, 'guard_stop', side_effect=fault), \
             patch.object(stage.run, 'stop_owned', side_effect=stop_owned), patch.object(stage.run, 'external_health'), \
             patch.object(stage.run, 'archive_run', side_effect=archived) as archive, \
             patch.object(stage.run, 'validate', side_effect=ValueError('malformed client JSON')), \
             patch.object(stage.subprocess, 'Popen') as launch:
            launch.return_value.poll.return_value = 0
            launch.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError, 'partial archive extraction failure' if partial_archive else 'malformed client JSON'):
                stage.main()
        archive.assert_called_once()
        launch.assert_called_once()
        self.assertEqual(slots.call_count, 2)
        self.assertEqual(slots.call_args.args[1:], ('e', 'f'))
        failure = json.loads((out / 'failure.json').read_text())
        self.assertEqual(failure['recovery']['archive_attempt_preserved'], schedule()[0]['label'])
        self.assertEqual(failure['recovery']['archive_manifest_complete'], not partial_archive)
        self.assertEqual((out / (schedule()[0]['label'] + '.tar.gz')).read_bytes(), b'first archive bytes')
        self.assertFalse((out / 'complete.json').exists())
        self.assertTrue((out / 'restored.json').exists())
        if cleanup_fault:
            self.assertIn('cleanup timeout', failure['recovery']['stop_owned_error'])
            self.assertEqual(len(json.loads((out / 'cleanup.json').read_text())['errors']), 4)

    def test_validator_exception_preserves_completed_archive_and_stops(self):
        self.run_controller_failure(partial_archive=False)

    def test_partial_archive_failure_preserves_first_bytes_and_stops(self):
        self.run_controller_failure(partial_archive=True)

    def test_cleanup_timeouts_preserve_original_failure_and_attempt_restore(self):
        self.run_controller_failure(partial_archive=False, cleanup_fault=True)


if __name__ == '__main__':
    unittest.main()
