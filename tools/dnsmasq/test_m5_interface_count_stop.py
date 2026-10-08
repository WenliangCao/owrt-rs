#!/usr/bin/env python3
"""Prepared offline controls; no ptrace, daemon, namespace or DNS execution."""
import errno
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import m5_interface_records as gate


def stopped(sig=signal.SIGTRAP, event=0):
    return (event << 16) | (sig << 8) | 0x7f


class CountStops(unittest.TestCase):
    def control(self, directory):
        report = {'events': [{'phase': 'request', 'cycle': 0}],
                  'polls': [{'cycle': 1, 'syscall': 73, 'result': 1}]}
        ptrace = Mock()
        owner = gate.EnumerationCountControl(123, ptrace, Path(directory) / 'count.json', report)
        return owner, ptrace, report

    def test_blocked_ppoll_is_interrupted_and_detached_without_a_daemon_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            owner.stop_path.write_text('both received\n')
            with patch.object(gate.os, 'waitpid', side_effect=[(0, 0), (123, stopped(signal.SIGTRAP | 0x80))]), \
                    patch.object(gate.time, 'sleep'), patch.object(gate.os, 'kill') as kill:
                owner.wait()
                owner.detach()
            self.assertEqual(ptrace.call_args_list, [unittest.mock.call(0x4207), unittest.mock.call(17, 0, 0)])
            kill.assert_not_called()
            self.assertTrue(report['trace_control']['detached'])
            self.assertEqual(report['trace_control']['detach_stop']['kind'], 'syscall')
            self.assertEqual(report['polls'], [{'cycle': 1, 'syscall': 73, 'result': 1}])
            self.assertEqual(report['events'], [{'phase': 'request', 'cycle': 0}])

    def test_already_waitable_stop_detaches_without_resuming_or_interrupting(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            owner.stop_path.write_text('both received\n')
            with patch.object(gate.os, 'waitpid', return_value=(123, stopped(event=128))):
                owner.wait()
                owner.detach()
            ptrace.assert_called_once_with(17, 0, 0)
            self.assertEqual(report['trace_control']['stop_reason'], 'both received')

    def test_interrupt_race_still_reaps_the_real_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            owner.stop_path.write_text('both received\n')
            ptrace.side_effect = [OSError(errno.EIO, 'already stopped'), None]
            with patch.object(gate.os, 'waitpid', side_effect=[(0, 0), (123, stopped(event=128))]), \
                    patch.object(gate.time, 'sleep'):
                owner.wait()
                owner.detach()
            self.assertEqual(report['trace_control']['interrupt_race_errno'], errno.EIO)
            self.assertTrue(report['trace_control']['detached'])

    def test_real_signal_delivery_is_reinjected_on_resume_and_detach(self):
        with tempfile.TemporaryDirectory() as directory:
            for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGUSR2, signal.SIGTRAP):
                owner, ptrace, _ = self.control(directory)
                owner.attached = True
                owner.stopped = gate.enumeration_stop(stopped(sig))
                owner.resume()
                ptrace.assert_called_once_with(24, 0, sig)
                ptrace.reset_mock()
                owner.stopped = gate.enumeration_stop(stopped(sig))
                owner.detach()
                ptrace.assert_called_once_with(17, 0, sig)

    def test_group_stop_uses_listen_and_preserves_only_the_existing_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            owner.stopped = gate.enumeration_stop(stopped(signal.SIGSTOP, 128))
            owner.resume()
            ptrace.assert_called_once_with(0x4208)
            owner.stopped = gate.enumeration_stop(stopped(signal.SIGSTOP, 128))
            ptrace.reset_mock()
            with patch.object(gate.os, 'kill') as kill:
                owner.detach()
            kill.assert_called_once_with(123, signal.SIGSTOP)
            ptrace.assert_called_once_with(17, 0, 0)
            self.assertEqual(report['trace_control']['preserved_group_signal'], signal.SIGSTOP)

    def test_initial_external_group_stop_is_rejected_then_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, _ = self.control(directory)
            with patch.object(gate.os, 'waitpid', return_value=(123, stopped(signal.SIGTSTP, 128))), \
                    patch.object(gate.os, 'kill') as kill:
                with self.assertRaisesRegex(AssertionError, 'already externally group-stopped'):
                    owner.attach()
                owner.detach()
            self.assertEqual(ptrace.call_args_list,
                             [unittest.mock.call(0x4206, 0, 1), unittest.mock.call(0x4207), unittest.mock.call(17, 0, 0)])
            kill.assert_called_once_with(123, signal.SIGTSTP)

    def test_normal_attach_is_seize_and_preserves_a_frozen_tracing_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            with patch.object(gate.os, 'waitpid', return_value=(123, stopped(event=128))):
                owner.attach()
            self.assertTrue(owner.attached)
            self.assertEqual(owner.stopped['kind'], 'interrupt')
            self.assertEqual(report['trace_control']['initial_stop']['kind'], 'interrupt')
            self.assertEqual(ptrace.call_args_list, [unittest.mock.call(0x4206, 0, 1), unittest.mock.call(0x4207)])

    def test_cleanup_of_a_running_owner_obtains_a_stop_before_detach(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            with patch.object(gate.os, 'waitpid', return_value=(123, stopped(event=128))):
                owner.detach()
            self.assertEqual(ptrace.call_args_list, [unittest.mock.call(0x4207), unittest.mock.call(17, 0, 0)])
            owner.detach()
            self.assertEqual(ptrace.call_count, 2)
            self.assertTrue(report['trace_control']['detached'])

    def test_missing_interrupt_ack_is_bounded_and_does_not_claim_detach(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            owner.stop_path.write_text('both received\n')
            with patch.object(gate.os, 'waitpid', return_value=(0, 0)), \
                    patch.object(gate.time, 'monotonic', side_effect=[0, 3]):
                with self.assertRaises(TimeoutError):
                    owner.wait()
            ptrace.assert_called_once_with(0x4207)
            self.assertFalse(report['trace_control']['detached'])

    def test_owner_exit_or_an_unknown_ptrace_event_is_not_a_completed_run(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            with patch.object(gate.os, 'waitpid', return_value=(123, 0)):
                with self.assertRaisesRegex(AssertionError, 'owner ended'):
                    owner.wait()
            self.assertFalse(owner.attached)
            self.assertFalse(report['trace_control']['detached'])
            ptrace.assert_not_called()
        for status in (stopped(event=6), stopped(signal.SIGUSR1, 128)):
            with self.assertRaisesRegex(AssertionError, 'unexpected enum count ptrace event'):
                gate.enumeration_stop(status)
        with tempfile.TemporaryDirectory() as directory:
            owner, ptrace, report = self.control(directory)
            owner.attached = True
            with patch.object(gate.os, 'waitpid', return_value=(123, stopped(event=6))):
                with self.assertRaisesRegex(AssertionError, 'unexpected enum count ptrace event'):
                    owner.wait()
                owner.detach()
            ptrace.assert_called_once_with(17, 0, 0)
            self.assertEqual(report['trace_control']['detach_stop']['kind'], 'unexpected-event')


class CountCutoff(unittest.TestCase):
    def test_interrupt_cutoff_does_not_fabricate_a_poll_exit_or_syscall_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'count.json'
            Path(str(output) + '.go').write_text('both queued\n')
            wait_index = -1

            def waitpid(pid, flags):
                nonlocal wait_index
                wait_index += 1
                if wait_index == 0:
                    return pid, stopped(event=128)
                if wait_index == 4:
                    Path(str(output) + '.stop').write_text('both received\n')
                    return 0, 0
                return pid, stopped(signal.SIGTRAP | 0x80)

            def ptrace(request, pid, address, data):
                if request.value == 0x420e:
                    # Two real entries, one real exit; the final interrupted
                    # exit must never be queried or counted by the tracer.
                    if wait_index not in (1, 2, 3):
                        raise AssertionError('cleanup syscall was counted')
                    info = (gate.ctypes.c_ubyte * 128).from_address(data.value)
                    info[0] = 2 if wait_index == 2 else 1
                elif request.value == 0x4204:
                    iov = (gate.ctypes.c_void_p * 2).from_address(data.value)
                    registers = (gate.ctypes.c_ulonglong * 34).from_address(iov[0])
                    registers[8] = 73
                    registers[0] = 1 if wait_index == 2 else 0
                    registers[1] = 0
                return 0

            libc = Mock()
            libc.ptrace.side_effect = ptrace
            with patch.object(gate.platform, 'machine', return_value='aarch64'), \
                    patch.object(gate.ctypes, 'CDLL', return_value=libc), \
                    patch.object(gate.os, 'waitpid', side_effect=waitpid), \
                    patch.object(gate.time, 'sleep'), patch.object(gate.os, 'kill') as kill:
                self.assertEqual(gate.trace_enumeration(123, 'rust', 'count', output), 0)
            result = json.loads(output.read_text())
            self.assertEqual(result['syscalls']['73'], {'entries': 2, 'exits': 1})
            self.assertEqual(result['polls'], [{'cycle': 1, 'syscall': 73, 'result': 1, 'ready': []}])
            self.assertEqual(result['trace_control']['cutoff_syscall']['syscall'], 73)
            self.assertTrue(result['completed'])
            self.assertTrue(result['trace_control']['detached'])
            kill.assert_not_called()


class ControllerStops(unittest.TestCase):
    def test_completed_controller_keeps_the_marker_and_does_not_send_a_signal(self):
        tracer = Mock(pid=456)
        tracer.poll.return_value = None
        tracer.wait.return_value = 0
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'count.json'
            self.assertEqual(gate.stop_enumeration_count(tracer, output), 0)
            self.assertEqual(Path(str(output) + '.stop').read_text(), 'both received\n')
            receipt = json.loads(Path(str(output) + '.controller.json').read_text())
        tracer.send_signal.assert_not_called()
        tracer.wait.assert_called_once_with(5)
        tracer.kill.assert_not_called()
        self.assertFalse(receipt['forced_kill'])
        self.assertEqual(receipt['tracer_pid'], 456)

    def test_abort_marker_does_not_claim_both_replies_and_early_failure_is_not_hidden(self):
        tracer = Mock(pid=456)
        tracer.poll.return_value = 1
        tracer.wait.return_value = 1
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'count.json'
            self.assertEqual(gate.stop_enumeration_count(tracer, output, completed=False), 1)
            self.assertEqual(Path(str(output) + '.stop').read_text(), 'controller cleanup\n')
        tracer.send_signal.assert_not_called()
        tracer.kill.assert_not_called()

    def test_forced_kill_is_recorded_and_cannot_pass_the_count_gate(self):
        tracer = Mock(pid=456)
        tracer.poll.return_value = None
        tracer.wait.side_effect = [subprocess.TimeoutExpired('tracer', 5), -signal.SIGKILL]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'count.json'
            with self.assertRaisesRegex(AssertionError, 'did not detach within 5 seconds'):
                gate.stop_enumeration_count(tracer, output)
            receipt = json.loads(Path(str(output) + '.controller.json').read_text())
        tracer.kill.assert_called_once_with()
        self.assertTrue(receipt['forced_kill'])
        self.assertEqual(receipt['exit'], -signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
