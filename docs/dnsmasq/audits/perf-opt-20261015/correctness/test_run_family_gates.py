"""Local orchestration controls; never execute or replace a product gate."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_family_gates as runner


class SchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(source=self.root, out=self.root, elf=self.root / 'elf',
            link_map=self.root / 'map', base_identity=self.root / 'base', commit='a' * 40, jobs=3)
        self.families = [{'id': f'family-{i}', 'steps': [{'id': 'paired'}]} for i in range(8)]
        self.report = {'elf_sha256': 'b' * 64, 'families': [], 'pauses': []}
        self.lock, self.started, self.active, self.maximum = threading.Lock(), [], 0, 0
        self.duplicate, self.bad_c, self.block = False, False, None

    def fake_run(self, argv, **kwargs):
        ident = argv[argv.index('--family') + 1]
        folder = Path(argv[argv.index('--out') + 1])
        with self.lock:
            self.started.append(ident)
            self.active += 1
            self.maximum = max(self.maximum, self.active)
        if self.block:
            self.block.wait(3)
        time.sleep(.02)
        jobs = [{'id': ident + '-paired', 'passed': True}]
        if self.duplicate:
            jobs += jobs
        value = {'commands': jobs, 'passed': True, 'selected_families': [ident],
                 'source_commit': self.args.commit, 'elf_sha256': self.report['elf_sha256'],
                 'c_sha256': '0' * 64 if self.bad_c else
                    '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'}
        folder.mkdir()
        (folder / 'result.json').write_text(json.dumps(value))
        with self.lock:
            self.active -= 1
        return SimpleNamespace(returncode=0)

    def run_scheduler(self):
        with patch.object(runner.subprocess, 'run', self.fake_run), contextlib.redirect_stdout(io.StringIO()):
            return runner.supervise(self.args, self.families, {}, self.report)

    def wait_for(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)

    def test_parallel_bound_and_complete_distinct_outputs(self):
        completed = self.run_scheduler()
        self.assertEqual(self.maximum, 3)
        self.assertEqual(len(completed), 8)
        self.assertEqual(len(self.report['families']), 8)
        self.assertTrue(all(row['passed'] for row in self.report['families']))

    def test_serial_mode_preserves_order(self):
        self.args.jobs = 1
        self.run_scheduler()
        self.assertEqual(self.maximum, 1)
        self.assertEqual(self.started, [f['id'] for f in self.families])

    def test_duplicate_job_count_is_rejected_and_active_jobs_drain(self):
        self.duplicate = True
        completed = self.run_scheduler()
        self.assertFalse(completed)
        self.assertEqual(len(self.started), 3)
        self.assertEqual(self.active, 0)
        self.assertTrue(all(not row['passed'] for row in self.report['families']))

    def test_wrong_c_identity_is_rejected(self):
        self.bad_c = True
        self.assertFalse(self.run_scheduler())
        self.assertTrue(all(not row['passed'] for row in self.report['families']))

    def test_pause_drains_without_starting_more_and_resumes(self):
        self.block = threading.Event()
        thread = threading.Thread(target=self.run_scheduler)
        thread.start()
        self.wait_for(lambda: len(self.started) == 3)
        (self.root / 'PAUSE').touch()
        self.block.set()
        self.wait_for(lambda: self.report['pauses'] and
                      'quiet_ready_epoch' in self.report['pauses'][0])
        self.assertEqual(len(self.started), 3)
        self.assertEqual(self.active, 0)
        (self.root / 'PAUSE').unlink()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(self.started), 8)
        self.assertIn('end_epoch', self.report['pauses'][0])


if __name__ == '__main__':
    unittest.main()
