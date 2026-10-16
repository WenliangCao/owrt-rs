import json
import hashlib
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

    def test_product_prototypes_are_single_static_groups_without_stage_modes(self):
        import address_dispatch_device_run as address
        import udp_name_buffer_device_run as names
        import udp_idle_batch_device_run as idle
        import fresh_address_device_run as fresh
        import cache_cold_metadata_device_run as cold
        import fresh_address_frame_device_run as frame
        import host_miss_index_device_run as host
        import local_cache_integration_device_run as integration
        import local_address_miss_stack_device_run as local_stack
        for entry, role in ((address, 'address-dispatch'), (names, 'udp-name-buffer'),
                            (idle, 'udp-idle-batch'), (fresh, 'fresh-address'),
                            (cold, 'cache-cold-metadata'), (frame, 'fresh-address-frame'),
                            (host, 'host-miss-index'), (integration, 'local-cache-integration'),
                            (local_stack, 'local-address-miss-stack')):
            with patch.multiple(stage, PREFIX=stage.PREFIX, GROUPS=stage.GROUPS,
                                ARTIFACT_ROLES=stage.ARTIFACT_ROLES, EXPERIMENT_ROLE=stage.EXPERIMENT_ROLE):
                entry.configure()
                rows = schedule()
                self.assertEqual(len(rows), 10)
                self.assertEqual([row['side'] for row in rows], ['c', 'rust', 'rust', 'c', 'c', 'rust', 'rust', 'c', 'c', 'rust'])
                self.assertTrue(all(row['mode'] is None for row in rows))
                self.assertEqual({row['artifact'] for row in rows}, {'f', role})
                self.assertEqual(stage.ARTIFACT_ROLES, {'e', 'f', role})
                self.assertEqual(stage.EXPERIMENT_ROLE, role)
        self.assertEqual(len(schedule()), 50)

    def test_every_mode_and_originals_have_required_cohorts(self):
        for mode in (None,) + MODES:
            result = stage_report(self.fixture(mode), mode)
            self.assertEqual(result['correct_fixture_replies'], 6000)
            self.assertEqual(result['thread_samples'], 3)
            self.assertEqual(result['raw'] is None, mode is None)

    def test_cached_local_name_uses_accepted_e_and_preserves_f_restore_role(self):
        import cached_local_name_device_run as names
        import cached_zero_frame_device_run as frames
        for entry, role in ((names, 'cached-local-name'), (frames, 'cached-zero-frame')):
            with patch.multiple(stage, PREFIX=stage.PREFIX, GROUPS=stage.GROUPS,
                                ARTIFACT_ROLES=stage.ARTIFACT_ROLES, EXPERIMENT_ROLE=stage.EXPERIMENT_ROLE):
                entry.configure()
                rows = schedule()
                self.assertEqual(len(rows), 10)
                self.assertEqual([row['side'] for row in rows], ['c', 'rust', 'rust', 'c', 'c', 'rust', 'rust', 'c', 'c', 'rust'])
                self.assertEqual({row['artifact'] for row in rows if row['side'] == 'c'}, {'e'})
                self.assertEqual({row['artifact'] for row in rows if row['side'] == 'rust'}, {role})
                self.assertTrue(all(row['mode'] is None for row in rows))
                self.assertEqual(stage.ARTIFACT_ROLES, {'e', 'f', role})
        self.assertEqual(len(schedule()), 50)

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
        data = json.loads(plan.read_text())
        data['health_evidence_sha256'] = hashlib.sha256(Path(stage.health_evidence.__file__).read_bytes()).hexdigest()
        plan = root / 'plan.json'
        plan.write_text(json.dumps(data))
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

    def run_guard_tail(self, unsafe_tail=False):
        import cached_zero_frame_device_run as entry
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / 'out'
            health = root / 'health.json'
            health.write_text(json.dumps({'valid': True, 'elapsed_seconds': 125, 'threshold_ms': 200}))
            plan = Path(__file__).resolve().parents[2] / 'docs/dnsmasq/audits/perf-opt-20261015/loop/A53_CACHED_ZERO_FRAME_DEVICE_PLAN.json'
            data = json.loads(plan.read_text())
            data['health_evidence_sha256'] = hashlib.sha256(Path(stage.health_evidence.__file__).read_bytes()).hexdigest()
            plan = root / 'plan.json'
            plan.write_text(json.dumps(data))
            (root / 'COMPLETE').write_text('complete\n')
            start = dict(event='start', production_pid=3086, production_starttime=2115, ipv4_default_initial=1)
            sample = dict(event='sample', elapsed_s=0, production_pid=3086, production_starttime=2115,
                          mem_available_kib=90000, ipv4_default=1, dns_ok=1, dns_rtt_ms=.5,
                          http_status=403, http_rtt_ms=50)
            prefix = [start, sample, {**sample, 'elapsed_s': 400}]
            tail = {**sample, 'elapsed_s': 401, 'http_status': 0, 'dns_ok': 0}
            if unsafe_tail:
                tail['mem_available_kib'] = 1
            final = prefix + [tail, dict(event='monitor_stopped', elapsed_s=401.1)]
            encode = lambda rows: b''.join((json.dumps(row) + '\n').encode() for row in rows)
            stopped = False
            def ssh(command, **kwargs):
                if command.startswith('cat ') and command.endswith('.jsonl'):
                    return SimpleNamespace(stdout=encode(final if stopped else prefix), returncode=0)
                return SimpleNamespace(stdout=b'', returncode=0)
            def stop(identity):
                nonlocal stopped
                self.assertEqual(validate.call_count, 10)
                self.assertEqual((out / 'pre-stop-prefix.jsonl').read_bytes(), encode(prefix))
                self.assertTrue((out / 'stop-request.json').exists())
                stopped = True
            def external(destination, finished, failed):
                (destination / 'external-health.jsonl').write_bytes(encode([
                    dict(ip_version=version, exit=0, result='200 0.08') for version in (4, 6)]))
            argv = ['stage', '--plan', str(plan), '--health-baseline', str(health),
                    '--experiment-hash', '0' * 64, '--out', str(out)]
            with patch.multiple(stage, PREFIX=stage.PREFIX, GROUPS=stage.GROUPS,
                                ARTIFACT_ROLES=stage.ARTIFACT_ROLES, EXPERIMENT_ROLE=stage.EXPERIMENT_ROLE), \
                 patch('sys.argv', argv), patch.object(stage, 'verify_files'), patch.object(stage, 'set_slots'), \
                 patch.object(stage.run, 'production_identity', return_value=[3086, 2115]), \
                 patch.object(stage.run, 'ssh', side_effect=ssh), \
                 patch.object(stage.run, 'guard_start', return_value=(3, 4)), \
                 patch.object(stage.run, 'guard_check', return_value=True), \
                 patch.object(stage.run, 'guard_stop', side_effect=stop), \
                 patch.object(stage.run, 'stop_owned') as emergency_stop, \
                 patch.object(stage.run, 'external_health', side_effect=external), \
                 patch.object(stage.run, 'archive_run', return_value=root), \
                 patch.object(stage.run, 'validate', return_value=[]) as validate, \
                 patch.object(stage, 'stage_report', return_value={}), \
                 patch.object(stage.analyze, 'traffic', return_value={}), \
                 patch.object(stage, 'comparisons', return_value={}), \
                 patch.object(stage.subprocess, 'Popen') as launch:
                entry.configure()
                launch.return_value.poll.return_value = 0
                launch.return_value.returncode = 0
                if unsafe_tail:
                    with self.assertRaises(AssertionError):
                        stage.main()
                else:
                    stage.main()
            self.assertTrue(stopped)
            self.assertEqual(launch.call_count, 10)
            self.assertEqual((out / 'complete.json').exists(), not unsafe_tail)
            self.assertEqual((out / 'failure.json').exists(), unsafe_tail)
            self.assertEqual(emergency_stop.call_count, int(unsafe_tail))
            self.assertTrue((out / 'restored.json').exists())
            guards = list(out.glob('a53-cached-zero-frame-guard-*.jsonl'))
            self.assertEqual(len(guards), 1)
            self.assertEqual(guards[0].read_bytes(), encode(final))

    def test_all_ten_windows_finish_before_guard_prefix_then_cancelled_tail(self):
        self.run_guard_tail()

    def test_unsafe_shutdown_tail_prevents_complete_without_replacing_windows(self):
        self.run_guard_tail(unsafe_tail=True)


if __name__ == '__main__':
    unittest.main()
