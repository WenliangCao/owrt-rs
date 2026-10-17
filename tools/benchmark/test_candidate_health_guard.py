"""Offline guard admission, argv and stop-boundary checks. No remote access."""
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import run_candidate as runner


ROOT = '/tmp/dnsmasq-perf-core-test'
HELPER = '/tmp/r85-procd-012345abcdef/owned_group.sh'
RECEIPT = '/tmp/r85-procd-012345abcdef/group-01.identity'


class HealthGuardTests(unittest.TestCase):
    def test_missing_guard_and_replaced_pid_cannot_launch(self):
        for failure in (subprocess.CalledProcessError(1, 'missing guard'), None):
            ssh = Mock(side_effect=failure) if failure else Mock(return_value=b'56 66\n')
            with self.subTest(failure=failure), patch.object(runner.subprocess, 'Popen') as launch:
                with self.assertRaises((subprocess.CalledProcessError, RuntimeError)):
                    runner.health_guarded_window(['ssh', 'fixture'], ssh, 'original command',
                        ROOT, (55, 66), HELPER, RECEIPT, io.StringIO())
                launch.assert_not_called()

    def test_guard_root_is_rejected_before_ssh(self):
        for root in ('/tmp/dnsmasq-perf-x;touch X', '/tmp/dnsmasq-perf-x/../other',
                     '/tmp/dnsmasq-perf-x\nbad', '/rom'):
            ssh = Mock()
            with self.subTest(root=root), self.assertRaises(ValueError):
                runner.health_guard_identity(ssh, root)
            ssh.assert_not_called()

    def test_original_command_is_one_exact_quoted_argument(self):
        command = "VAR='two words' /bin/sh /tmp/isolated.sh '/path with spaces;$(false)'"
        process = Mock(); process.wait.return_value = 0
        with patch.object(runner.subprocess, 'Popen', return_value=process) as launch:
            code = runner.health_guarded_window(['ssh', 'fixture'], Mock(return_value=b'55 66\n'),
                command, ROOT, (55, 66), HELPER, RECEIPT, io.StringIO())
        argv = shlex.split(launch.call_args.args[0][-1])
        self.assertEqual(argv, ['setsid', '/bin/sh', HELPER, ROOT, 'run', '55', '66', RECEIPT, command])
        self.assertEqual(code, 0)
        process.wait.assert_called_once_with(timeout=5)

    def test_guard_change_during_wait_stops_only_receipted_group(self):
        calls = []
        def ssh(command):
            calls.append(command)
            if ' stop ' in command:
                return b''
            return b'55 66\n' if len(calls) == 1 else b'55 67\n'
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 5), 0]
        process.poll.return_value = None
        with patch.object(runner.subprocess, 'Popen', return_value=process):
            with self.assertRaisesRegex(RuntimeError, 'PID/start changed'):
                runner.health_guarded_window(['ssh', 'fixture'], ssh, 'original',
                    ROOT, (55, 66), HELPER, RECEIPT, io.StringIO())
        self.assertEqual(shlex.split(calls[-1]), ['/bin/sh', HELPER, ROOT, 'stop', RECEIPT])
        self.assertEqual(process.wait.call_args_list[-1].kwargs, {'timeout': 15})
        process.kill.assert_not_called()

    def test_host_timeout_stops_owned_group_without_changing_workload_budget(self):
        ssh = Mock(return_value=b'55 66\n')
        process = Mock(); process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 5), 0]
        with patch.object(runner.subprocess, 'Popen', return_value=process), \
                patch.object(runner.time, 'monotonic', side_effect=[0, 661]):
            with self.assertRaisesRegex(RuntimeError, 'host deadline'):
                runner.health_guarded_window(['ssh', 'fixture'], ssh, 'original',
                    ROOT, (55, 66), HELPER, RECEIPT, io.StringIO())
        self.assertIn(' stop ', ssh.call_args.args[0])


class OwnedShellTests(unittest.TestCase):
    """Run the fixed shell against fake proc records, with signals logged only."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dnsmasq-perf-', dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / 'proc'; self.proc.mkdir()
        self.script = self.root / 'owned_group.sh'
        self.receipt = self.root / 'group-01.identity'
        self.calls = self.root / 'signals'
        source = Path(__file__).with_name('owned_group.sh').read_text()
        shim = f'''
stat() {{ printf '%s\\n' {os.getuid()}; }}
kill() {{ printf '%s\\n' "$*" >> {shlex.quote(str(self.calls))}; }}
mkdir -p {shlex.quote(str(self.proc))}/$$
printf '%s (sh) S 1 %s' "$$" "$$" > {shlex.quote(str(self.proc))}/$$/stat
i=6
while [ "$i" -lt 22 ]; do printf ' 0' >> {shlex.quote(str(self.proc))}/$$/stat; i=$((i+1)); done
printf ' 999\\n' >> {shlex.quote(str(self.proc))}/$$/stat
'''
        self.script.write_text(source.replace('/proc/', str(self.proc) + '/').replace('set -eu\n', 'set -eu\n' + shim, 1))
        self.guard = self.proc / '55'; self.guard.mkdir()
        (self.guard / 'exe').symlink_to(self.root / 'device_perf_guard')
        self.proc_stat(55, 55, 66)
        (self.root / 'guard.identity').write_text('55 66\n')

    def proc_stat(self, pid, group, start):
        directory = self.proc / str(pid); directory.mkdir(exist_ok=True)
        (directory / 'stat').write_text(f'{pid} (sh) S 1 {group}' + ' 0' * 16 + f' {start}\n')

    def invoke(self, *args):
        return subprocess.run(['/bin/sh', str(self.script), str(self.root), *args],
                              capture_output=True, timeout=5)

    def test_leader_publishes_identity_waits_and_clears_only_its_group(self):
        marker = self.root / 'workload'
        command = f'test -s {shlex.quote(str(self.root / "active.group"))} && printf ran > {shlex.quote(str(marker))}'
        result = self.invoke('run', '55', '66', str(self.receipt), command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(marker.read_text(), 'ran')
        self.assertRegex(self.receipt.read_text(), r'^\d+ 999\n$')
        self.assertFalse((self.root / 'active.group').exists())
        self.assertFalse((self.root / 'active.group.new').exists())

    def test_missing_changed_or_stopped_guard_never_runs_payload(self):
        marker = self.root / 'workload'
        for defect in ('missing', 'changed', 'stop'):
            with self.subTest(defect=defect):
                (self.root / 'guard.identity').write_text('55 66\n')
                if defect == 'missing': (self.root / 'guard.identity').unlink()
                if defect == 'changed': (self.root / 'guard.identity').write_text('56 66\n')
                if defect == 'stop': (self.root / 'STOP').touch()
                result = self.invoke('run', '55', '66', str(self.receipt), f'printf ran > {shlex.quote(str(marker))}')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse(self.receipt.exists())

    def test_cancel_before_publication_prevents_delayed_launch(self):
        stopped = self.invoke('stop', str(self.receipt))
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        marker = self.root / 'workload'
        result = self.invoke('run', '55', '66', str(self.receipt), f'printf ran > {shlex.quote(str(marker))}')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertFalse(self.receipt.exists())

    def test_stop_requires_pid_start_group_and_exact_root_helper_receipt_argv(self):
        self.proc_stat(77, 77, 88)
        self.receipt.write_text('77 88\n')
        (self.root / 'active.group').write_text('77 88\n')
        cmdline = self.proc / '77/cmdline'
        tokens = ['/bin/sh', str(self.script), str(self.root), 'run', '55', '66', str(self.receipt), 'original']
        def store(parts): cmdline.write_bytes(b'\0'.join(value.encode() for value in parts) + b'\0')
        for defect in ('start', 'pgid', 'root', 'helper', 'receipt', 'active'):
            with self.subTest(defect=defect):
                self.proc_stat(77, 77, 88)
                (self.root / 'active.group').write_text('77 88\n')
                store(tokens)
                if self.calls.exists(): self.calls.unlink()
                if defect == 'start': self.proc_stat(77, 77, 89)
                if defect == 'pgid': self.proc_stat(77, 78, 88)
                if defect in ('root', 'helper', 'receipt'):
                    index = {'helper': 1, 'root': 2, 'receipt': 6}[defect]
                    changed = list(tokens); changed[index] += '-wrong'; store(changed)
                if defect == 'active': (self.root / 'active.group').write_text('78 88\n')
                self.invoke('stop', str(self.receipt))
                self.assertFalse(self.calls.exists(), defect)
        self.proc_stat(77, 77, 88); (self.root / 'active.group').write_text('77 88\n'); store(tokens)
        result = self.invoke('stop', str(self.receipt))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls.read_text(), '-KILL -- -77\n')


if __name__ == '__main__':
    unittest.main()
