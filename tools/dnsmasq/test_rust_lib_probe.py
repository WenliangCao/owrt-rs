"""Offline identity tests; synthetic ELF headers are never executed."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import lease_insert_diff as lease
import rust_lib_probe as probe
import stale_metadata_diff as stale


class ProbeBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'source'
        for name in ('dnsmasq/src/lib.rs', 'dnsmasq/platform/src/lib.rs', 'ubus/src/lib.rs'):
            path = self.source / 'components' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// synthetic source\n')
        self.output = self.root / 'private/probe-tests'
        self.output.mkdir(parents=True)
        self.binary = self.output / 'lib-dnsmasq_rs'
        header = bytearray(64)
        header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<H', header, 18, 183)
        self.binary.write_bytes(header)
        self.cache = self.root / 'private/cargo-target'
        self.receipt = self.output / 'build.json'
        self.before = self.output / 'probe-source-before.json'
        files = probe.source_files(self.source)
        self.before.write_text(json.dumps(files) + '\n')
        self.build = {'source': str(self.source), 'kind': 'probe-tests', 'opt_level': '3',
                      'features': '', 'cargo_target_dir': str(self.cache), 'diagnostic_only': True,
                      'source_files': files, 'source_before_sha256': probe.digest(self.before),
                      'artifacts': [{'path': self.binary.name, 'bytes': self.binary.stat().st_size,
                                     'sha256': probe.digest(self.binary)}]}
        self.save()

    def save(self, value=None):
        self.receipt.write_text(json.dumps(value or self.build) + '\n')

    def extend_source(self, names):
        for name in names:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// synthetic source\n')
        self.build['source_files'] = probe.source_files(self.source)
        self.before.write_text(json.dumps(self.build['source_files']) + '\n')
        self.build['source_before_sha256'] = probe.digest(self.before)
        self.save()

    def cli(self):
        return ['--rust-test-binary', str(self.binary), '--rust-source-root', str(self.source),
                '--rust-build-receipt', str(self.receipt), '--rust-cargo-target-dir', str(self.cache)]

    def libtest(self, test, prefix, rows):
        return ('running 1 test\ntest ' + test + ' ... ' + prefix + rows[0] + '\n'
                + ''.join(prefix + row + '\n' for row in rows[1:])
                + '\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out\n')

    def validate(self):
        return probe.validate(self.binary, self.source, self.receipt, self.cache)

    def test_custom_cache_requires_explicit_match_and_rechecks_without_default_fallback(self):
        with self.assertRaises(ValueError):
            probe.validate(self.binary, self.source, self.receipt)
        binding = self.validate()
        probe.recheck(binding)
        self.assertEqual(binding['cargo_target_dir'], str(self.cache))
        self.build['cargo_target_dir'] = str(probe.SHARED_TARGET)
        self.save()
        with self.assertRaises(ValueError):
            probe.recheck(binding)
        probe.validate(self.binary, self.source, self.receipt)

    def test_copy_in_selected_cache_or_symlink_to_it_is_rejected(self):
        self.cache.mkdir(parents=True)
        cached = self.cache / self.binary.name
        cached.write_bytes(self.binary.read_bytes())
        with self.assertRaisesRegex(ValueError, 'immutable private copy'):
            probe.validate(cached, self.source, self.receipt, self.cache)
        self.binary.unlink()
        self.binary.symlink_to(cached)
        with self.assertRaisesRegex(ValueError, 'immutable private copy'):
            self.validate()

    def test_relative_cache_cannot_bind_receipt(self):
        with self.assertRaisesRegex(ValueError, 'absolute'):
            probe.validate(self.binary, self.source, self.receipt, Path('private/cache'))

    def test_existing_receipt_guards_remain_mandatory(self):
        for field, value in [('kind', 'tests'), ('opt_level', 's'), ('features', 'm6b-diagnostics'),
                             ('diagnostic_only', False), ('source_files', {}),
                             ('source_before_sha256', '0' * 64), ('artifacts', [])]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.build)
                changed[field] = value
                self.save(changed)
                with self.assertRaises(ValueError):
                    self.validate()
        self.save()
        self.before.write_text('{}\n')
        with self.assertRaises(ValueError):
            self.validate()

    def test_platform_source_change_is_rejected_on_recheck(self):
        binding = self.validate()
        (self.source / 'components/dnsmasq/platform/src/lib.rs').write_text('// changed\n')
        with self.assertRaises(ValueError):
            probe.recheck(binding)

    def test_cli_binds_cache_and_rejects_partial_copy(self):
        parser = argparse.ArgumentParser()
        probe.add_arguments(parser)
        argv = ['--rust-test-binary', str(self.binary), '--rust-source-root', str(self.source),
                '--rust-build-receipt', str(self.receipt), '--rust-cargo-target-dir', str(self.cache)]
        binary, source, binding = probe.selection(parser.parse_args(argv), self.root, self.output)
        self.assertEqual((binary, source), (self.binary, self.source))
        probe.recheck(binding)
        with self.assertRaises(ValueError):
            probe.selection(parser.parse_args(argv[2:]), self.root, self.output)
        with self.assertRaises(ValueError):
            probe.selection(parser.parse_args(argv + ['--local-native']), self.root, self.output)

    def test_oracle_native_mode_still_rejected_without_old_cache(self):
        with self.assertRaisesRegex(ValueError, 'forbidden on Oracle'):
            probe.local_only(self.root, self.output, '/home/ubuntu/new-root/source', '/usr/bin/cargo')

    def test_lease_copied_mode_executes_only_bound_probe_and_keeps_ttl_comparison(self):
        self.extend_source(['components/dnsmasq/src/dns/' + name for name in
                            ('daemon.rs', 'daemon_lease_cache_tests.rs', 'cache_engine.rs', 'cache.rs',
                             'cache_reply.rs', 'local.rs', 'lease_names.rs', 'service.rs', 'wire.rs')])
        baseline = self.root / 'private/lease-baseline'; baseline.mkdir()
        (baseline / 'local-answer-oracle').write_bytes(b'synthetic C identity, never executed')
        label, _, commands = next(lease.corpus())
        wire = lease.response('lease', [('lease', 1, 89, bytes([192, 0, 2, 7]))]).hex()
        rows = ['NONE', 'P 0', wire, 'N 1', 'NONE', 'N 0']
        (baseline / '00.input').write_text('\n'.join(commands) + '\n')
        (baseline / '00.conf').write_text('synthetic config\n')
        (baseline / '00.stdout').write_text('\n'.join(rows) + '\n')
        (baseline / 'result.json').write_text(json.dumps({
            'failures': [], 'c_oracle_sha256': probe.digest(baseline / 'local-answer-oracle'),
            'rows': [{'case': 0, 'label': label}]}))
        parser = argparse.ArgumentParser(); probe.add_arguments(parser)
        args = parser.parse_args(self.cli())
        args.compare_baseline = baseline; args.cargo = '/must-not-build/cargo'
        changed = list(rows)
        changed[2] = lease.response('lease', [('lease', 1, 90, bytes([192, 0, 2, 7]))]).hex()
        for number, actual in enumerate((rows, changed)):
            out = self.root / ('private/lease-run-' + str(number)); out.mkdir()
            result = subprocess.CompletedProcess([], 0, self.libtest(lease.TEST, 'LEASE_CACHE_ORACLE ', actual), '')
            with patch.object(lease.subprocess, 'run', return_value=result) as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(lease.compare(args, out), number)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], probe.argv(self.binary, lease.TEST))
            report = json.loads((out / 'result.json').read_text())
            self.assertEqual(len(report['mismatches']), number)
            self.assertEqual(report['rust_probe']['cargo_target_dir'], str(self.cache))

    def test_stale_copied_mode_executes_only_bound_probe_and_keeps_metadata_comparison(self):
        self.extend_source(['components/dnsmasq/src/dns/daemon_stale_tests.rs',
                            'components/dnsmasq/Cargo.toml', 'components/dnsmasq/Cargo.lock'])
        baseline = self.root / 'private/stale-baseline'; baseline.mkdir()
        (baseline / 'c-oracle').write_bytes(b'synthetic C identity, never executed')
        identity = {'source_sha256': stale.SOURCE_HASHES, 'binary': 'c-oracle',
                    'binary_sha256': probe.digest(baseline / 'c-oracle'),
                    'driver_sha256': probe.digest(Path(stale.__file__).with_name('cache_answer_driver.c'))}
        folder = baseline / 'trace'; folder.mkdir()
        (folder / 'config.conf').write_text('synthetic config\n')
        (folder / 'commands.txt').write_text('T 100 512 00\n')
        (folder / 'cases.json').write_text(json.dumps([{'case': 'synthetic', 'command': 'T 100 512 00'}]))
        wire = lease.response('lease', [('lease', 1, 89, bytes([192, 0, 2, 7]))]).hex()
        rows = ['T 0 0 ' + wire]
        (folder / 'c.stdout').write_text(rows[0] + '\n')
        profile = {'label': 'synthetic', 'scope': 'offline fixture', 'folder': 'trace', 'commands': 1,
                   'config_sha256': probe.digest(folder / 'config.conf'),
                   'commands_sha256': probe.digest(folder / 'commands.txt'),
                   'trace_sha256': probe.digest(folder / 'c.stdout')}
        (baseline / 'identity.json').write_text(json.dumps(identity))
        (baseline / 'result.json').write_text(json.dumps({'identity': identity, 'passed': 1131,
            'failed': 0, 'inject_error': False, 'profiles': [profile]}))
        for number, extra in enumerate(([], ['--inject-error'])):
            out = self.root / ('private/stale-run-' + str(number))
            argv = ['stale_metadata_diff.py', '--baseline', str(baseline), '--out', str(out), *self.cli(), *extra]
            result = subprocess.CompletedProcess([], 0, self.libtest(stale.TEST, 'STALE_ORACLE ', rows), '')
            with patch.object(sys, 'argv', argv), patch.object(stale.subprocess, 'run', return_value=result) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(stale.main(), bool(number))
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], probe.argv(self.binary, stale.TEST))
            report = json.loads((out / 'result.json').read_text())
            self.assertEqual(report['mismatches'], number)
            self.assertEqual(report['rust_probe']['cargo_target_dir'], str(self.cache))


if __name__ == '__main__':
    unittest.main()
