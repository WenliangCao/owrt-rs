"""Offline controls only: no target process is created or limited."""
import copy
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import selfexec_fd_headroom as pressure


class HoleTests(unittest.TestCase):
    def test_startup_callback_work_preserves_two_and_rejects_wrong_or_partial(self):
        for count in (1, 2):
            result = pressure.jail.startup_callback_work(pressure.jail.CALLBACK * count)
            self.assertTrue(result['valid'])
            self.assertEqual(result['count'], count)
            self.assertEqual(result['raw'], pressure.jail.CALLBACK * count)
        for raw in (None, '', pressure.jail.CALLBACK[:-1], pressure.jail.CALLBACK + 'tftp unrelated\n'):
            self.assertFalse(pressure.jail.startup_callback_work(raw)['valid'])

    def test_helper_negative_needs_typed_no_proc_failure_not_exit_alone(self):
        row = {'mode': 'helper', 'forced': False, 'exit': 5, 'initial_dns': {'ok': False},
               'callback': None, 'helper_child': {'captured': False},
               'entry_receipt': {'proc_exists': False, 'namespace_pid': 1, 'uid': 0, 'gid': 0},
               'entry_boundary': {'proc_exists': False, 'errors': []}}
        self.assertTrue(pressure.jail.helper_negative_shape(row))
        changes = [('mode', 'resolver'), ('forced', True), ('exit', 1),
                   ('initial_dns', {'ok': True}), ('callback', pressure.jail.CALLBACK),
                   ('helper_child', {'captured': True}), ('helper_child', {}),
                   ('entry_receipt', {'proc_exists': True, 'namespace_pid': 1, 'uid': 0, 'gid': 0}),
                   ('entry_boundary', {'proc_exists': False, 'errors': ['wrong mount']}),
                   ('error', 'unrelated tool failure')]
        for key, value in changes:
            invalid = copy.deepcopy(row); invalid[key] = value
            with self.subTest(key=key, value=value):
                self.assertFalse(pressure.jail.helper_negative_shape(invalid))
        self.assertFalse(pressure.jail.helper_negative_shape({'exit': 5}))

    def test_dense_and_sparse_inventories_keep_exact_holes(self):
        for fds in [list(range(12)), [0, 2, 5, 900], [7, 1000], []]:
            for wanted in pressure.LEVELS:
                with self.subTest(fds=fds, wanted=wanted):
                    soft, holes = pressure.limit_for_holes(fds, wanted, 1024)
                    self.assertEqual(holes, [fd for fd in range(soft) if fd not in fds])
                    self.assertEqual(len(holes), wanted)
                    self.assertNotIn(soft, fds)
        self.assertEqual(pressure.limit_for_holes([0, 2, 5, 900], 2, 1024), (4, [1, 3]))

    def test_invalid_inventory_and_insufficient_old_limit_are_rejected(self):
        for fds, wanted, old in [([0, 0], 2, 1024), ([-1], 2, 1024), ([True], 2, 1024),
                                 ([0], 5, 1024), ([0, 1, 2], 2, 4)]:
            with self.subTest(fds=fds, wanted=wanted, old=old), self.assertRaises(ValueError):
                pressure.limit_for_holes(fds, wanted, old)

    def test_delayed_pressure_events_cannot_prove_recovery(self):
        old = f'tftp {len(pressure.PAYLOAD)} 127.0.0.1 /fixture/tftp/fd-pressure-2.bin\n'
        self.assertEqual(pressure.callback_count(old, 'fd-pressure-2'), 1)
        self.assertEqual(pressure.callback_count(old, 'fd-recovery-2'), 0)
        self.assertEqual(pressure.callback_count(old + old, 'fd-pressure-2'), 2)
        packet = pressure.jail.query('fd-pressure-2.lookup.jail.test')
        with self.assertRaises(AssertionError):
            pressure.jail.resolver_answer(packet, 'fd-recovery-2.lookup.jail.test')

    def test_public_helper_fixture_keeps_readable_payloads_and_valid_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'fixture').mkdir()
            (root / 'fixture/config').write_text('dhcp-script=/fixture/script\n')
            (root / 'fixture/script').write_text('#!/bin/sh\nexit 0\n')
            pressure.prepare_pressure(root, 'helper')
            for payload in (root / 'fixture/tftp').iterdir():
                self.assertEqual(payload.read_bytes(), pressure.PAYLOAD)
                self.assertEqual(payload.stat().st_mode & 0o777, 0o644)
            subprocess.run(['sh', '-n', str(root / 'fixture/script')], check=True)

    def test_shared_jail_script_keeps_explicit_proc_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); image = base / 'image'
            (image / 'usr/sbin').mkdir(parents=True); (image / 'etc').mkdir()
            (image / 'usr/sbin/dnsmasq').write_bytes(b'image placeholder')
            binary = base / 'binary'; binary.write_bytes(b'candidate placeholder')
            for visible in [False, True]:
                out = base / str(visible); out.mkdir()
                with patch.object(pressure.jail.os, 'chown'), \
                        patch.object(pressure.jail.os, 'listxattr', return_value=[], create=True), \
                        patch.object(pressure.jail.os, 'mknod', side_effect=lambda path, *args: Path(path).touch()):
                    root = pressure.jail.prepare_root(image, binary, out, True, visible)
                text = (root / 'fixture/script').read_text()
                self.assertIn('[ -d /proc/self/fd ]' if visible else '[ ! -e /proc ]', text)
                self.assertFalse((root / 'proc').exists(), 'proc is mounted only inside the target namespace')
                subprocess.run(['sh', '-n', str(root / 'fixture/script')], check=True)

    def test_partial_raw_stage_survives_a_protocol_exception(self):
        def broken(*args):
            args[-1]['operation'].append({'wire': 'preserve-this-failed-packet'})
            raise ValueError('bad response')
        with tempfile.TemporaryDirectory() as temporary, patch.object(pressure, 'run_stage', side_effect=broken):
            root = Path(temporary) / 'rootfs'; root.mkdir()
            result = pressure.stage(None, 'helper', root, 'pressure', None, None, None, None, None)
            saved = json.loads((root.parent / 'pressure-stage.json').read_text())
            self.assertFalse(result['passed'])
            self.assertEqual(saved['operation'], [{'wire': 'preserve-this-failed-packet'}])
            self.assertIn('bad response', saved['error'])


class LimitTransactionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.output = Path(self.folder.name) / 'limit.json'
        self.current = {'pid': 71, 'starttime_ticks': 99, 'pgrp': 70, 'state': 'S'}
        self.limits = (1024, 4096); self.signals = []; self.changes = []
        self.fds = [{'fd': fd, 'target': '/dev/null', 'flags_octal': '2000000', 'fdinfo': 'flags:\t2000000\n'}
                    for fd in [0, 1, 2, 900]]
        self.patches = [patch.object(pressure, 'identity', side_effect=lambda pid: dict(self.current)),
                        patch.object(pressure, 'fd_snapshot', side_effect=self.snapshot),
                        patch.object(pressure.resource, 'prlimit', side_effect=self.prlimit, create=True),
                        patch.object(pressure.os, 'pidfd_open', return_value=700, create=True),
                        patch.object(pressure.signal, 'pidfd_send_signal', side_effect=self.send, create=True),
                        patch.object(pressure.os, 'close')]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.folder.cleanup()

    def snapshot(self, pid):
        return {'identity': dict(self.current), 'limits': list(self.limits), 'fds': copy.deepcopy(self.fds), 'at_ns': 1}

    def prlimit(self, pid, which, values=None):
        old = self.limits
        if values is not None:
            self.assertEqual(self.current['state'], 'T', 'limits must change only while target is stopped')
            self.assertEqual(values[1], 4096, 'hard limit must be preserved')
            self.changes.append(tuple(values)); self.limits = tuple(values)
        return old

    def send(self, pidfd, sig):
        self.assertEqual(pidfd, 700)
        self.signals.append(sig)
        self.current['state'] = 'T' if sig == signal.SIGSTOP else 'S'

    def transaction(self, wanted=2):
        return pressure.LimitChange(71, 70, wanted, self.output)

    def test_exact_apply_and_finally_restore_for_each_level(self):
        for wanted in pressure.LEVELS:
            with self.subTest(wanted=wanted):
                change = self.transaction(wanted)
                try:
                    change.apply()
                    self.assertEqual(self.current['state'], 'S')
                    self.assertEqual(self.limits, (3 + wanted, 4096))
                    self.assertEqual(len(change.record['available_fds']), wanted)
                    self.assertEqual(change.record['before']['fds'], self.fds)
                finally:
                    change.restore(); change.close()
                self.assertEqual(self.limits, (1024, 4096))
                self.assertTrue(change.record['restore']['restored'])
                self.assertTrue(self.output.exists())

    def test_reused_pid_or_foreign_group_is_never_limited_or_restored(self):
        self.current['pgrp'] = 80
        with self.assertRaisesRegex(RuntimeError, 'owned process group'): self.transaction()
        self.current['pgrp'] = 70
        change = self.transaction(); change.apply(); self.current['starttime_ticks'] += 1
        count = len(self.changes); signals = len(self.signals)
        change.restore(); change.close()
        self.assertEqual(len(self.changes), count)
        self.assertEqual(len(self.signals), signals)
        self.assertFalse(change.record['restore']['restored'])

    def test_preexisting_stop_is_not_resumed(self):
        self.current['state'] = 'T'; change = self.transaction()
        with self.assertRaisesRegex(RuntimeError, 'already stopped'): change.apply()
        change.restore(); change.close()
        self.assertEqual(self.signals, [])
        self.assertEqual(self.changes, [])

    def test_wrong_baseline_is_not_silently_changed(self):
        self.limits = (2048, 4096); change = self.transaction()
        with self.assertRaisesRegex(RuntimeError, '1024/4096'): change.apply()
        change.restore(); change.close()
        self.assertEqual(self.limits, (2048, 4096))
        self.assertEqual(self.current['state'], 'S')
        self.assertEqual(self.changes, [])

    def test_inventory_failure_after_mutation_still_restores(self):
        original = self.snapshot
        def snapshot(pid):
            value = original(pid)
            if self.limits != (1024, 4096): value['fds'].append({'fd': 3, 'target': 'unexpected'})
            return value
        change = self.transaction()
        with patch.object(pressure, 'fd_snapshot', side_effect=snapshot):
            try:
                with self.assertRaisesRegex(RuntimeError, 'inventory'): change.apply()
            finally:
                change.restore(); change.close()
        self.assertEqual(self.limits, (1024, 4096))
        self.assertTrue(change.record['restore']['restored'])

    def test_external_limit_change_is_not_overwritten(self):
        change = self.transaction(); change.apply(); self.limits = (7, 4096)
        count = len(self.changes); change.restore(); change.close()
        self.assertEqual(len(self.changes), count)
        self.assertFalse(change.record['restore']['restored'])
        self.assertIn('outside this fixture', change.record['restore']['error'])
        self.assertEqual(self.current['state'], 'S')

    def test_dead_target_restore_is_recorded_without_a_signal(self):
        change = self.transaction(); change.apply(); count = len(self.signals)
        with patch.object(pressure, 'identity', side_effect=ProcessLookupError('gone')):
            change.restore()
        change.close()
        self.assertEqual(len(self.signals), count)
        self.assertFalse(change.record['restore']['restored'])


if __name__ == '__main__':
    unittest.main()
