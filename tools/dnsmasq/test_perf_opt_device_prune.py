"""Controller cleanup order with fake SSH/processes; no device access."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import perf_opt_device_run as run


class PruneTests(unittest.TestCase):
    def simulate(self, invalid_first=False, archive_failure=False, cleanup_failure=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        out = base / 'result'
        health = base / 'health.json'
        health.write_text(json.dumps({'valid': True, 'elapsed_seconds': 125, 'threshold_ms': 200}))
        archived, deleted = [], []
        stopped = False
        start = dict(event='start', production_pid=1, production_starttime=2, ipv4_default_initial=1)
        sample = dict(event='sample', elapsed_s=125, production_pid=1, production_starttime=2,
                      mem_available_kib=90000, ipv4_default=1, dns_ok=1, dns_rtt_ms=.5,
                      http_status=403, http_rtt_ms=50)
        encode = lambda rows: b''.join((json.dumps(row) + '\n').encode() for row in rows)

        def archive(folder, label):
            if archive_failure:
                raise RuntimeError('copy hash mismatch')
            retained = folder / 'runs' / label
            retained.mkdir(parents=True, exist_ok=True)
            (folder / (label + '.archive.json')).write_text('{}')
            archived.append(label)
            return retained

        def validate(folder, scene, expected_hash):
            return ['fixture invalid'] if invalid_first and folder.name.endswith('-r1-c') else []

        def ssh(command, **kwargs):
            if command.startswith('cat ') and command.endswith('.jsonl'):
                rows = [start, sample]
                if stopped:
                    rows.append(dict(event='monitor_stopped', elapsed_s=126))
                return SimpleNamespace(stdout=encode(rows), returncode=0)
            if command.startswith('rm -rf -- '):
                label = Path(command.removeprefix('rm -rf -- ')).name
                self.assertIn(label, archived)
                self.assertTrue((out / (label + '.archive.json')).exists())
                progress = json.loads((out / 'progress.json').read_text())
                self.assertEqual(progress[-1]['label'], label)
                self.assertTrue(progress[-1]['valid'])
                deleted.append(label)
                if cleanup_failure:
                    raise RuntimeError('fixture prune failure')
            return SimpleNamespace(stdout=b'', returncode=0)

        def stop(identity):
            nonlocal stopped
            stopped = True

        def external(destination, finished, failed):
            (destination / 'external-health.jsonl').write_bytes(encode([
                dict(ip_version=v, exit=0, result='200 0.08') for v in (4, 6)]))

        process = SimpleNamespace(poll=lambda: 0, returncode=0)
        argv = ['run', '--out', str(out), '--prefix', 'fixture', '--health-baseline', str(health),
                '--scenes', 'udp-hit']
        with patch('sys.argv', argv), patch.object(run, 'ssh', side_effect=ssh), \
             patch.object(run, 'production_identity', return_value=[1, 2]), \
             patch.object(run, 'external_health', side_effect=external), patch.object(run, 'guard_start', return_value=(3, 4)), \
             patch.object(run, 'guard_check', return_value=True), patch.object(run, 'guard_stop', side_effect=stop), \
             patch.object(run, 'stop_owned'), patch.object(run, 'archive_run', side_effect=archive), \
             patch.object(run, 'validate', side_effect=validate), \
             patch.object(run.subprocess, 'Popen', return_value=process), \
             contextlib.redirect_stdout(io.StringIO()):
            if archive_failure or cleanup_failure:
                expected = 'copy hash mismatch' if archive_failure else 'fixture prune failure'
                with self.assertRaisesRegex(RuntimeError, expected):
                    run.main()
            else:
                run.main()
        return out, archived, deleted

    def test_valid_windows_pruned_only_after_archive_and_progress(self):
        out, archived, deleted = self.simulate()
        self.assertEqual(len(deleted), 10)
        self.assertEqual(deleted, archived)
        self.assertEqual(len(json.loads((out / 'progress.json').read_text())), 10)

    def test_invalid_window_is_retained_and_reported(self):
        out, archived, deleted = self.simulate(invalid_first=True)
        self.assertEqual(len(archived), 10)
        self.assertEqual(len(deleted), 9)
        self.assertNotIn('fixture-udp-hit-r1-c', deleted)
        self.assertFalse(json.loads((out / 'progress.json').read_text())[0]['valid'])

    def test_archive_verification_failure_never_prunes(self):
        out, archived, deleted = self.simulate(archive_failure=True)
        self.assertEqual(deleted, [])
        self.assertTrue((out / 'failure.json').exists())

    def test_cleanup_failure_does_not_overwrite_completed_archive(self):
        out, archived, deleted = self.simulate(cleanup_failure=True)
        self.assertEqual(archived, ['fixture-udp-hit-r1-c'])
        self.assertEqual(deleted, archived)
        failure = json.loads((out / 'failure.json').read_text())
        self.assertEqual(failure['recovery'], {'attempt_already_archived': archived[0]})
        self.assertEqual(len(json.loads((out / 'progress.json').read_text())), 1)


if __name__ == '__main__':
    unittest.main()
