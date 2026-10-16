"""Full controller scene boundaries with fake SSH/processes; no device access."""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import device_health_baseline as health
import perf_opt_device_run as run


def encode(rows):
    return b''.join((json.dumps(row) + '\n').encode() for row in rows)


class GuardBoundaryTests(unittest.TestCase):
    def simulate(self, scenes=('udp-hit',), fault=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        out = root / 'result'
        baseline = root / 'baseline.json'
        baseline.write_text(json.dumps({'valid': True, 'elapsed_seconds': 125, 'threshold_ms': 200}))
        segments, launches, archives, deletions = [], [], [], []
        external = [dict(ip_version=v, exit=0, result='200 0.08') for v in (4, 6)]
        start = dict(event='start', production_pid=3086, production_starttime=2115, ipv4_default_initial=1)
        sample = dict(event='sample', elapsed_s=0, production_pid=3086, production_starttime=2115,
                      mem_available_kib=90000, ipv4_default=1, dns_ok=1, dns_rtt_ms=.5,
                      http_status=403, http_rtt_ms=50)

        class Monitor:
            def __init__(self, target, args, daemon):
                self.target, self.args = target, args

            def start(self):
                self.target(*self.args)

            def join(self, timeout):
                if fault == 'external-after-capture':
                    (out / 'external-health.jsonl').write_bytes(encode(external + [
                        dict(ip_version=4, exit=28, result='000 5.0')]))

            def is_alive(self):
                return fault == 'external-still-alive'

        def guard_start(pid, label, threshold):
            self.assertEqual((pid, threshold), (3086, 200))
            prefix = [copy.deepcopy(start), copy.deepcopy(sample), {**sample, 'elapsed_s': 325}]
            tail = {**sample, 'elapsed_s': 326, 'http_status': 0, 'dns_ok': 0}
            if fault == 'prefix-http':
                prefix[-1]['http_status'] = 0
            if fault == 'unsafe-tail':
                tail['mem_available_kib'] = 65535
            final = prefix + [tail, dict(event='monitor_stopped', elapsed_s=326.1)]
            if fault == 'missing-stopped':
                final.pop()
            capture = encode(prefix) + encode([tail])[:17]
            if fault == 'partial-capture-changed':
                capture = encode(prefix) + b'{"event": "sample", "elapsed_s": 999'
            segments.append(dict(label=label, prefix=encode(prefix), capture=capture,
                                 final=encode(final), stopped=False, archives_at_start=len(archives)))
            return (100 + len(segments), 200 + len(segments))

        def ssh(command, **kwargs):
            if command.startswith('cat ') and command.endswith('.jsonl'):
                segment = segments[-1]
                if not segment['stopped']:
                    self.assertEqual(len(archives) - segment['archives_at_start'], 10)
                    for label in archives[-10:]:
                        self.assertTrue((out / 'runs' / label / 'final.stat').exists())
                        self.assertTrue((out / (label + '.archive.json')).exists())
                raw = segment['final'] if segment['stopped'] else segment['capture']
                return SimpleNamespace(stdout=raw, returncode=0)
            if command.startswith('rm -rf -- '):
                deletions.append(command)
            return SimpleNamespace(stdout=b'', returncode=0)

        def stop(identity):
            segment = segments[-1]
            evidence = out / segment['label']
            self.assertEqual(len(archives) - segment['archives_at_start'], 10)
            self.assertEqual((evidence / 'pre-stop-capture.raw').read_bytes(), segment['capture'])
            self.assertEqual((evidence / 'pre-stop-prefix.jsonl').read_bytes(), segment['prefix'])
            self.assertTrue((evidence / 'stop-request.json').exists())
            segment['stopped'] = True

        def launch(argv, **kwargs):
            launches.append(argv[-1])
            return SimpleNamespace(poll=lambda: 0, returncode=0)

        def archive(destination, label):
            folder = destination / 'runs' / label
            folder.mkdir(parents=True)
            (folder / 'final.stat').write_text('fixed final CPU endpoint\n')
            (folder / 'COMPLETE').write_text('complete\n')
            (destination / (label + '.tar.gz')).write_bytes(b'retained archive')
            (destination / (label + '.archive.json')).write_text('{"files":{}}')
            archives.append(label)
            return folder

        def external_health(destination, finished, failed):
            (destination / 'external-health.jsonl').write_bytes(encode(external))

        argv = ['full-run', '--out', str(out), '--prefix', 'boundary',
                '--health-baseline', str(baseline)]
        if scenes is not None:
            argv += ['--scenes', *scenes]
        with patch('sys.argv', argv), patch.object(run, 'ssh', side_effect=ssh), \
             patch.object(run, 'production_identity', return_value=[3086, 2115]), \
             patch.object(run, 'guard_start', side_effect=guard_start), \
             patch.object(run, 'guard_check', return_value=True), \
             patch.object(run, 'guard_stop', side_effect=stop), \
             patch.object(run, 'stop_owned') as emergency_stop, \
             patch.object(run, 'external_health', side_effect=external_health), \
             patch.object(run, 'archive_run', side_effect=archive), \
             patch.object(run, 'validate', return_value=[]), \
             patch.object(run.subprocess, 'Popen', side_effect=launch), \
             patch.object(run.threading, 'Thread', Monitor), patch.object(run.time, 'sleep'), \
             contextlib.redirect_stdout(io.StringIO()):
            if fault:
                with self.assertRaises((AssertionError, RuntimeError)):
                    run.main()
            else:
                run.main()
        return out, segments, launches, archives, deletions, emergency_stop.call_count

    def test_all_original_110_windows_archive_before_11_distinct_stop_boundaries(self):
        out, segments, launches, archives, deletions, stops = self.simulate(scenes=None)
        self.assertEqual((len(launches), len(archives), len(deletions), len(segments), stops),
                         (110, 110, 110, 11, 0))
        expected = [f'boundary-{scene[0]}-r{pair}-{side}' for scene in run.SCENES
                    for pair in range(1, 6)
                    for side in (('c', 'rust') if pair % 2 else ('rust', 'c'))]
        self.assertEqual(archives, expected)
        self.assertEqual(len({segment['label'] for segment in segments}), 11)
        for segment in segments:
            evidence = out / segment['label']
            self.assertEqual((out / (segment['label'] + '.jsonl')).read_bytes(), segment['final'])
            self.assertEqual((evidence / 'pre-stop-capture.raw').read_bytes(), segment['capture'])
            result = json.loads((evidence / 'guard-verification.json').read_text())
            self.assertEqual((result['qualified_samples'], result['final_tail_samples']), (2, 1))
        self.assertEqual(json.loads((out / 'complete.json').read_text()),
                         {'complete': True, 'windows': 110, 'valid': 110})
        self.assertFalse((out / 'failure.json').exists())
        self.assertEqual(json.loads((out / 'identity.json').read_text())['health_evidence_sha256'],
                         run.HEALTH_EVIDENCE_SHA)

    def test_every_guard_validation_failure_retains_original_windows_and_stops(self):
        for fault in ('prefix-http', 'unsafe-tail', 'partial-capture-changed', 'missing-stopped'):
            with self.subTest(fault=fault):
                out, segments, launches, archives, deletions, stops = self.simulate(
                    scenes=('udp-hit', 'udp-miss'), fault=fault)
                self.assertEqual((len(launches), len(archives), len(deletions), len(segments), stops),
                                 (10, 10, 10, 1, 1))
                self.assertFalse((out / 'complete.json').exists())
                self.assertEqual(len(json.loads((out / 'failure.json').read_text())['results']), 10)
                self.assertEqual((out / (segments[0]['label'] + '.jsonl')).read_bytes(), segments[0]['final'])

    def test_external_tail_or_live_monitor_cannot_publish_complete(self):
        for fault in ('external-after-capture', 'external-still-alive'):
            with self.subTest(fault=fault):
                out, _, launches, archives, _, stops = self.simulate(fault=fault)
                self.assertEqual((len(launches), len(archives), stops), (10, 10, 1))
                self.assertTrue((out / 'failure.json').exists())
                self.assertFalse((out / 'complete.json').exists())

    def test_helper_identity_failure_precedes_any_device_action(self):
        with patch('sys.argv', ['full-run', '--out', '/unused', '--health-baseline', '/unused']), \
             patch.object(run, 'HEALTH_EVIDENCE_SHA', '0' * 64), patch.object(run, 'ssh') as ssh:
            with self.assertRaisesRegex(RuntimeError, 'helper identity'):
                run.main()
        ssh.assert_not_called()

    def test_legacy_controller_run_cannot_be_resumed_as_captured_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'result'
            out.mkdir()
            baseline = Path(temporary) / 'baseline.json'
            baseline.write_text(json.dumps({'valid': True, 'elapsed_seconds': 125, 'threshold_ms': 200}))
            (out / 'identity.json').write_text(json.dumps({
                'production_pid_start': [3086, 2115], 'comparison': {'c': 'c', 'rust': 'r'},
                'threshold_ms': 200, 'health_baseline_sha256': hashlib.sha256(baseline.read_bytes()).hexdigest(),
                'controller_sha256': health.CONTROLLER_SHA}))
            argv = ['full-run', '--out', str(out), '--health-baseline', str(baseline),
                    '--c-hash', 'c', '--rust-hash', 'r', '--resume']
            with patch('sys.argv', argv), patch.object(run, 'ssh') as ssh, \
                 patch.object(run, 'production_identity', return_value=[3086, 2115]):
                with self.assertRaisesRegex(RuntimeError, 'resume identity differs: controller_sha256'):
                    run.main()
            ssh.assert_not_called()
            self.assertFalse((out / 'complete.json').exists())

    def test_import_orders_do_not_add_top_level_dependency_or_change_baseline_pin(self):
        for order in ('import perf_opt_device_run; import device_health_baseline',
                      'import device_health_baseline; import perf_opt_device_run'):
            script = order + '; assert device_health_baseline.CONTROLLER_SHA == ' + repr(health.CONTROLLER_SHA)
            result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).parent,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest(), health.CONTROLLER_SHA)


if __name__ == '__main__':
    unittest.main()
