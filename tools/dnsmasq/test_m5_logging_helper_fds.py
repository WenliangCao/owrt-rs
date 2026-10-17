"""Exact supplemental helper pipe contracts; the original two-FD gate stays default."""
import copy
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import m5_logging as logging


def descriptor(fd, inode, direction, cloexec=True):
    flags = (0o2000000 if cloexec else 0) | {'read': 0, 'write': 1, 'read-write': 2}[direction]
    return logging.helper_fd_observation(fd, f'pipe:[{inode}]', f'flags:\t{flags:o}\n')


def observation(copies=1, cloexec=True):
    return [{'pid': 71, 'descriptors': [
        descriptor(4 + index, 123, 'read', cloexec) for index in range(copies)
    ] + [descriptor(8 + index, 456, 'write', cloexec) for index in range(copies)]}]


class HelperFdObservationTests(unittest.TestCase):
    def test_linux_flags_and_inode_are_recorded_without_host_constants(self):
        row = logging.helper_fd_observation(7, 'pipe:[12345]', 'pos:\t0\nflags:\t02004001\nmnt_id:\t17\n')
        self.assertEqual(row, {'fd': 7, 'target': 'pipe:[12345]', 'flags_octal': '02004001',
                               'pipe_inode': 12345, 'direction': 'write', 'cloexec': True})
        row = logging.helper_fd_observation(9, 'socket:[12345]', 'flags:\t02\n')
        self.assertIsNone(row['pipe_inode'])
        self.assertEqual(row['direction'], 'read-write')
        self.assertFalse(row['cloexec'])

    def test_missing_or_invalid_flags_fail_observation(self):
        for text in ['pos:\t0\n', 'flags:\t0x80000\n', 'flags:\t9\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                logging.helper_fd_observation(7, 'pipe:[12345]', text)

    def test_observer_keeps_each_nonstdio_fd_and_raw_flags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            folder = root / '71'
            (folder / 'fd').mkdir(parents=True)
            (folder / 'fdinfo').mkdir()
            os.symlink('/dev/null', folder / 'fd' / '0')
            expected = observation(2)
            for row in reversed(expected[0]['descriptors']):
                os.symlink(row['target'], folder / 'fd' / str(row['fd']))
                (folder / 'fdinfo' / str(row['fd'])).write_text('flags:\t' + row['flags_octal'] + '\n')
            self.assertEqual(logging.observe_helper_fds(71, root), expected[0])


class HelperFdContractTests(unittest.TestCase):
    def test_fork_and_selfexec_have_distinct_exact_contracts(self):
        self.assertEqual(logging.helper_pipe_errors(observation(1), 1), [])
        self.assertEqual(logging.helper_pipe_errors(observation(2), 2), [])
        # The original C contract does not assert an unverified CLOEXEC value.
        self.assertEqual(logging.helper_pipe_errors(observation(1, cloexec=False), 1), [])
        self.assertTrue(logging.helper_pipe_errors(observation(1), 2))
        self.assertTrue(logging.helper_pipe_errors(observation(2), 1))

    def test_extra_pipe_socket_missing_cloexec_and_wrong_direction_are_rejected(self):
        for mutation in ['fifth-same-inode', 'third-pipe', 'socket', 'missing-cloexec',
                         'wrong-copy-direction', 'both-read', 'read-write', 'one-pipe',
                         'duplicate-fd-number', 'stdio-fd', 'incomplete', 'forged-cloexec',
                         'forged-inode', 'forged-direction']:
            with self.subTest(mutation=mutation):
                rows = observation(2)
                fds = rows[0]['descriptors']
                if mutation == 'fifth-same-inode': fds.append(descriptor(10, 123, 'read'))
                elif mutation == 'third-pipe': fds[1] = descriptor(5, 789, 'read')
                elif mutation == 'socket': fds[1] = logging.helper_fd_observation(5, 'socket:[789]', 'flags:\t02000000\n')
                elif mutation == 'missing-cloexec': fds[1] = descriptor(5, 123, 'read', False)
                elif mutation == 'wrong-copy-direction': fds[1] = descriptor(5, 123, 'write')
                elif mutation == 'both-read': fds[2:] = [descriptor(8, 456, 'read'), descriptor(9, 456, 'read')]
                elif mutation == 'read-write': fds[1] = descriptor(5, 123, 'read-write')
                elif mutation == 'one-pipe': fds[2:] = [descriptor(8, 123, 'write'), descriptor(9, 123, 'write')]
                elif mutation == 'duplicate-fd-number': fds[1]['fd'] = fds[0]['fd']
                elif mutation == 'stdio-fd': fds[1]['fd'] = 2
                elif mutation == 'incomplete': fds[1].pop('flags_octal')
                elif mutation == 'forged-cloexec': fds[1]['flags_octal'] = '0'
                elif mutation == 'forged-inode': fds[1]['pipe_inode'] = 999
                elif mutation == 'forged-direction': fds[1]['direction'] = 'write'
                self.assertTrue(logging.helper_pipe_errors(rows, 2))

    def test_fork_rejects_same_pipe_or_same_direction(self):
        for second in [descriptor(8, 123, 'write'), descriptor(8, 456, 'read')]:
            rows = observation()
            rows[0]['descriptors'][1] = second
            self.assertTrue(logging.helper_pipe_errors(rows, 1))

    def test_missing_or_multiple_helpers_are_rejected(self):
        for rows in [None, [], [None], observation() * 2, [{'pid': 71}], [{'descriptors': [None] * 4}]]:
            with self.subTest(rows=rows):
                self.assertTrue(logging.helper_pipe_errors(rows, 2))

    def row(self, copies=1):
        return {'ready': True, 'exit': 0, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': '',
                'helper_states': [{'same_session': True, 'same_group': True, 'cwd': '/',
                                   'stdio': ['null'] * 3, 'fd_count': 2 * copies,
                                   'only_command_event_pipes': True}],
                'helper_fd_observations': observation(copies)}

    def case(self, contract=None):
        case = {'id': 'helper-fd-control', 'kind': 'run', 'mode': ['-k'], 'helper_fds': True}
        if contract is not None: case['helper_fd_contract'] = contract
        return case

    def test_legacy_default_still_rejects_four_fds_and_accepts_old_raw_schema(self):
        original = self.row()
        original.pop('helper_fd_observations')
        self.assertEqual(logging.compare(original, copy.deepcopy(original), self.case()), [])
        self.assertEqual(logging.compare(self.row(), self.row(), self.case()), [])
        failures = logging.compare(self.row(), self.row(2), self.case())
        self.assertTrue(any(row.get('kind') == 'helper-startup-owned-FD-control' for row in failures))

    def test_supplemental_comparison_is_exact_and_keeps_raw_inodes(self):
        for contract, copies in [('fork', 1), ('selfexec', 2)]:
            with self.subTest(contract=contract):
                left, right = self.row(), self.row(copies)
                for fd in right['helper_fd_observations'][0]['descriptors']:
                    fd.update(descriptor(fd['fd'] + 20, fd['pipe_inode'] + 1000, fd['direction']))
                before = copy.deepcopy((left, right))
                self.assertEqual(logging.compare(left, right, self.case(contract)), [])
                self.assertEqual((left, right), before)
                self.assertTrue(logging.compare(self.row(), self.row(3 - copies), self.case(contract)))
        self.assertTrue(logging.compare(self.row(2), self.row(2), self.case('selfexec')))

    def test_summary_cannot_hide_bad_structure_and_other_state_stays_checked(self):
        for mutation in ['missing-raw', 'missing-cloexec', 'third-pipe', 'wrong-cwd']:
            with self.subTest(mutation=mutation):
                right = self.row(2)
                if mutation == 'missing-raw': right.pop('helper_fd_observations')
                elif mutation == 'wrong-cwd': right['helper_states'][0]['cwd'] = '/wrong'
                elif mutation == 'missing-cloexec': right['helper_fd_observations'][0]['descriptors'][0] = descriptor(4, 123, 'read', False)
                else: right['helper_fd_observations'][0]['descriptors'][0] = descriptor(4, 789, 'read')
                self.assertTrue(logging.compare(self.row(), right, self.case('selfexec')))

    def test_cli_cannot_apply_supplemental_contract_to_the_original_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'identity-only'
            binary.write_bytes(b'never executed')
            out = root / 'private' / 'result'
            base = ['m5_logging.py', '--image-root', str(root), '--rust', str(binary),
                    '--rust-sha256', logging.sha256(binary), '--source-commit', 'fixture',
                    '--output', str(out), '--scopes', 'daemon', '--helper-fd-contract', 'selfexec']
            for extra in [[], ['--scenarios', 'daemon-pid-open-failure']]:
                with self.subTest(extra=extra), patch.object(sys, 'argv', base + extra), \
                        patch.object(logging.os, 'geteuid', return_value=0), \
                        patch.dict(os.environ, {'DNSMASQ_TEST_ISOLATED': '1'}), \
                        patch.object(logging, 'prepare') as prepare, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    with self.assertRaises(SystemExit) as raised:
                        logging.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertIn('explicit helper-startup scenarios only', stderr.getvalue())
                    prepare.assert_not_called()
                    self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
