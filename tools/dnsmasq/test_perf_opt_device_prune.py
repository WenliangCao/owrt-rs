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

        process = SimpleNamespace(poll=lambda: 0, returncode=0)
        argv = ['run', '--out', str(out), '--prefix', 'fixture', '--health-baseline', str(health),
                '--scenes', 'udp-hit']
        with patch('sys.argv', argv), patch.object(run, 'ssh', side_effect=ssh), \
             patch.object(run, 'production_identity', return_value=[1, 2]), \
             patch.object(run, 'external_health'), patch.object(run, 'guard_start', return_value=(3, 4)), \
             patch.object(run, 'guard_check', return_value=True), patch.object(run, 'guard_stop'), \
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
