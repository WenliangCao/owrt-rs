#!/usr/bin/env python3
"""Offline failure injection for the R112 shell collector and report validator."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from r105_rx_spare_report import verify_memory_snapshots


STATUS = """Name: ubusd
State: S (sleeping)
Tgid: 42
Pid: 42
Threads: 1
Cpus_allowed_list: 1
VmRSS: 512 kB
RssAnon: 48 kB
VmData: 56 kB
"""


def stat(start=123, state='S'):
    return '42 (ubusd test) ' + ' '.join([state] + ['0'] * 18 + [str(start)]) + '\n'


class MemoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.raw = Path(self.temporary.name)
        source = Path(__file__).with_name('r112_rx_memory.sh').read_text()
        self.functions = source[source.index('status_values() {'):source.index('for clients in 0 1 8 32 64;')]
        self.metrics = {}
        (self.raw / 'stat-64-start.txt').write_text(stat())
        for phase, suffix, metric_phase in [('before', '-before', 'before'), ('held', '', 'after'),
                                            ('after-disconnect', '-after-disconnect', 'after_disconnect')]:
            (self.raw / f'status-64{suffix}.txt').write_text(STATUS)
            for boundary in ('before', 'after'):
                (self.raw / f'stat-64-{phase}-{boundary}.txt').write_text(stat())
            for name, value in [('vmrss', 512), ('rssanon', 48), ('vmdata', 56)]:
                self.metrics[f'{name}_{metric_phase}_kb'] = value
        (self.raw / 'exit-64.txt').write_text('143\n')

    def tearDown(self):
        self.temporary.cleanup()

    def shell(self, command, *args):
        return subprocess.run(['/bin/sh', '-c', 'set -eu\n' + self.functions + command,
                               'test', *map(str, args)], text=True, capture_output=True)

    def test_valid_snapshot_and_shell_parser(self):
        verify_memory_snapshots(self.raw, 64, self.metrics)
        result = self.shell('status_values 42 "$1"', self.raw / 'status-64-before.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '512,48,56')
        result = self.shell('daemon=42; process_identity "$1"', self.raw / 'stat-64-start.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '42 123')

    def test_invalid_status_is_rejected_by_shell_and_report(self):
        path = self.raw / 'status-64-before.txt'
        for invalid in [STATUS.replace('RssAnon: 48 kB\n', ''), STATUS + 'RssAnon: 48 kB\n',
                        STATUS.replace('S (sleeping)', 'Z (zombie)'), STATUS.replace('48 kB', '48 MB'),
                        STATUS.replace('48 kB', 'oops kB'), STATUS.replace('Pid: 42', 'Pid: 43')]:
            with self.subTest(status=invalid):
                path.write_text(invalid)
                self.assertNotEqual(self.shell('status_values 42 "$1"', path).returncode, 0)
                with self.assertRaises((AssertionError, KeyError)):
                    verify_memory_snapshots(self.raw, 64, self.metrics)

    def test_pid_reuse_and_zombie_stat_are_rejected(self):
        path = self.raw / 'stat-64-after-disconnect-after.txt'
        for invalid in (stat(start=124), stat(state='Z')):
            path.write_text(invalid)
            with self.assertRaises(AssertionError):
                verify_memory_snapshots(self.raw, 64, self.metrics)
        result = self.shell('daemon=42; process_identity "$1"', path)
        self.assertNotEqual(result.returncode, 0)

    def test_csv_disagreement_and_unexpected_exit_are_rejected(self):
        self.metrics['rssanon_after_kb'] = 0
        with self.assertRaises(AssertionError):
            verify_memory_snapshots(self.raw, 64, self.metrics)
        self.metrics['rssanon_after_kb'] = 48
        (self.raw / 'exit-64.txt').write_text('7\n')
        with self.assertRaises(AssertionError):
            verify_memory_snapshots(self.raw, 64, self.metrics)

    def test_stop_does_not_swallow_abnormal_wait_status(self):
        # Supply an already-failed child; stubs isolate the wait-status branch.
        command = '''
process_identity() { printf 'identity\n'; }
kill() { return 0; }
daemon_identity=identity
out=$1; clients=64
/bin/sh -c 'exit 7' & daemon=$!
stop_daemon
'''
        self.assertNotEqual(self.shell(command, self.raw).returncode, 0)
        self.assertEqual((self.raw / 'exit-64.txt').read_text().strip(), '7')


if __name__ == '__main__':
    unittest.main()
