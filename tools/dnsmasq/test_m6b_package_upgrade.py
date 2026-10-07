#!/usr/bin/env python3
"""Minimal offline package-version/transition guards; no SDK or APK execution."""
import copy
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import build_package as build
import m4_package_lifecycle as lifecycle
import m5_final_validation as final


METADATA = """info:
  name: dnsmasq
  version: 2.93-r2
  arch: aarch64_cortex-a53
  depends:
    - libc
    - libubus20251202
  provides:
    - dnsmasq-any
scripts:
  post-install: |
  pre-deinstall: |
  post-upgrade: |
"""


class PackageUpgradeGuards(unittest.TestCase):
    def test_release_default_and_metadata_cannot_silently_use_r2_for_r3(self):
        self.assertEqual(build.package_id(), '2.93-r2')
        self.assertEqual(build.audit_metadata(METADATA)['version'], '2.93-r2')
        self.assertEqual(build.audit_metadata(METADATA.replace('r2', 'r3'), '3')['version'], '2.93-r3')
        with self.assertRaises(ValueError): build.audit_metadata(METADATA, '3')
        with self.assertRaises(ValueError): build.audit_metadata(METADATA.replace('r2', 'r3'))
        for value in ['1', '03', '4', '3;id', 3, None]:
            with self.subTest(value=value), self.assertRaises(ValueError): build.package_id(value)

    def test_frozen_release_is_required_for_r3_but_legacy_r2_freeze_stays_valid(self):
        source = {'src': 'a'*64}; sdk = {'archive_sha256': 'b'*64, 'files': {'rules': 'c'*64}}
        value = {'schema': 1, 'frozen': True, 'source_commit': 'd'*40, 'source_date_epoch': 123,
                 'rust_elf_sha256': 'e'*64, 'source_files': source, 'sdk_archive_sha256': 'b'*64,
                 'sdk_files': sdk['files'], 'postprocess': {'mode': 'none', 'input_sha256': 'e'*64,
                    'output_sha256': 'e'*64, 'reason': 'qualified ELF'}}
        build.verify_freeze(value, source, sdk, 'd'*40, '123', 'e'*64)
        with self.assertRaises(ValueError): build.verify_freeze(value, source, sdk, 'd'*40, '123', 'e'*64, '3')
        value['package_release'] = '3'
        build.verify_freeze(value, source, sdk, 'd'*40, '123', 'e'*64, '3')
        with self.assertRaises(ValueError): build.verify_freeze(value, source, sdk, 'd'*40, '123', 'e'*64)

    def test_previous_identity_is_complete_and_exact_and_m5_needs_no_baseline(self):
        args = SimpleNamespace(package_release='2', previous_apk=None, previous_apk_sha256=None,
                               previous_elf_sha256=None, previous_source_commit=None)
        self.assertIsNone(lifecycle.previous_inputs(args))
        args.package_release = '3'
        with self.assertRaises(RuntimeError): lifecycle.previous_inputs(args)
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'm5.apk'; path.write_bytes(b'synthetic, not real accepted APK')
            args.previous_apk = path
            args.previous_apk_sha256 = lifecycle.M5_BASELINE['apk_sha256']
            args.previous_elf_sha256 = lifecycle.M5_BASELINE['elf_sha256']
            args.previous_source_commit = lifecycle.M5_BASELINE['source_commit']
            with patch.object(lifecycle, 'sha256', return_value=args.previous_apk_sha256):
                self.assertEqual(lifecycle.previous_inputs(args)['package_id'], '2.93-r2')
                for field in ['previous_apk_sha256', 'previous_elf_sha256', 'previous_source_commit']:
                    altered = copy.copy(args); setattr(altered, field, 'f'*len(getattr(args, field)))
                    with self.subTest(field=field), self.assertRaises(RuntimeError): lifecycle.previous_inputs(altered)
            with self.assertRaises(RuntimeError): lifecycle.previous_inputs(args)

    def test_m6b_prepare_commands_and_artifact_keep_the_release_binding(self):
        self.assertEqual(final.package_inputs('m5', {}), ('2', None))
        with self.assertRaises(ValueError): final.package_inputs('m6b', {})
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'm5.apk'; path.write_bytes(b'synthetic')
            previous = dict(lifecycle.M5_BASELINE, path=str(path))
            with patch.object(final, 'digest', return_value=previous['apk_sha256']):
                release, previous = final.package_inputs('m6b', {'previous_package': previous})
                self.assertEqual(release, '3')
                with self.assertRaises(ValueError): final.package_inputs('m6b', {'package_release': '2', 'previous_package': previous})
            spec = {'source_root': '/source', 'source_commit': 'a'*40, 'source_date_epoch': 123,
                    'output': '/source/private/final', 'elf': '/qualified', 'elf_sha256': 'b'*64,
                    'sdk': '/sdk', 'budget': '/budget', 'source_files': {}, 'image_root': '/image', 'runtime_root': '/runtime',
                    'stock_apk': '/stock.apk', 'variant_apks': [], 'variant_dependency_apks': [],
                    'validation_mode': 'm6b', 'package_release': '3', 'previous_package': previous}
            package = final.commands(spec, 'package', Path('/source/private/attempt'))[0]
            self.assertEqual(package['argv'][-2:], ['--package-release', '3'])
            leaf = final.commands(spec, 'lifecycle', Path('/source/private/attempt'))[0]
            self.assertIn('dnsmasq-2.93-r3.apk', ' '.join(leaf['argv']))
            self.assertTrue(leaf['checks']['previous_upgrade.passed'])
            self.assertEqual(len(leaf['inventory']['ids']), 14)
            self.assertEqual(len(leaf['checks']['previous_upgrade.stages']), 6)
            for field, flag in [('path', '--previous-apk'), ('apk_sha256', '--previous-apk-sha256'),
                                ('elf_sha256', '--previous-elf-sha256'), ('source_commit', '--previous-source-commit')]:
                self.assertEqual(leaf['argv'][leaf['argv'].index(flag)+1], previous[field])
            artifact = Path(name) / 'candidate.apk'; artifact.write_bytes(b'synthetic candidate')
            report = {'sdk_recipe_restored': True, 'elf': {'sha256': 'b'*64},
                      'artifact': {'name': artifact.name, 'sha256': build.sha(artifact)},
                      'package_release': '3', 'apk_metadata': {'version': '2.93-r3'}}
            final.package_artifact(report, 0, 'b'*64, Path(name) / 'manifest.json', '3')
            report['apk_metadata']['version'] = '2.93-r2'
            with self.assertRaises(ValueError): final.package_artifact(report, 0, 'b'*64, Path(name) / 'manifest.json', '3')

    def test_summary_exposes_r3_and_previous_upgrade_without_fabricating_missing_gates(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            spec = {'validation_mode': 'm6b', 'package_release': '3', 'previous_package': dict(lifecycle.M5_BASELINE),
                    'source_commit': 'a'*40, 'elf_sha256': 'b'*64, 'elf_bytes': 2000000, 'output': str(root)}
            manifest = root / 'identity.json'; final.save(manifest, spec)
            leaf = root / 'lifecycle-leaf.json'
            final.save(leaf, {'status': 'passed', 'candidate_package_id': '2.93-r3',
                'previous_upgrade': dict(lifecycle.M5_BASELINE, passed=True),
                'stages': [{'name': 'm5-to-candidate-upgrade'}, {'name': 'direct-m5-downgrade'}]})
            attempt = root / 'lifecycle-attempt'; attempt.mkdir()
            completion = {'phase': 'lifecycle', 'passed': True, 'source_commit': spec['source_commit'],
                'elf_sha256': spec['elf_sha256'], 'manifest_sha256': final.digest(manifest),
                'attempt': str(attempt), 'commands': [{'result': str(leaf)}]}
            final.save(attempt / 'result.json', completion); final.save(root / 'completed.json', {'lifecycle': completion})
            with patch.object(final, 'verify_identity'), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(final.summary(SimpleNamespace(manifest=manifest)))
            summary = json.loads((root / 'summary.json').read_text())
            self.assertEqual(summary['expected_package_id'], '2.93-r3')
            self.assertEqual(summary['previous_package']['source_commit'], lifecycle.M5_BASELINE['source_commit'])
            self.assertTrue(summary['package_lifecycle']['previous_upgrade']['passed'])
            self.assertFalse(summary['functional_validation_passed'])
            self.assertIn('package', summary['missing_phases'])

    def test_transition_chain_requires_real_version_change_and_two_m5_rollbacks(self):
        class FakeCase:
            def __init__(self, wrong_upgrade=False): self.version = '2.93-r1'; self.calls = []; self.wrong_upgrade = wrong_upgrade
            def apk(self, args, label):
                self.calls.append((label, args))
                if self.wrong_upgrade and label == 'm5-to-candidate-upgrade': return
                self.version = '2.93-r2' if args[-1] == '/m4/previous.apk' else '2.93-r3'
            def activate_after_transaction(self, label): self.calls.append((label, ['restart']))
            def capture(self, label, sha, version, *rest):
                if self.version != version: raise RuntimeError('installed version did not change')
                self.calls.append((label, ['capture', sha, version]))
            def remove(self, label, configs): self.version = None; self.calls.append((label, ['del', 'dnsmasq']))
        args = SimpleNamespace(package_release='3', candidate_elf_sha256='a'*64)
        report = {'previous_package': dict(lifecycle.M5_BASELINE)}; case = FakeCase()
        lifecycle.previous_upgrade_chain(case, args, {}, {}, {}, {}, report)
        self.assertTrue(report['previous_upgrade']['passed'])
        self.assertEqual(report['previous_upgrade']['stages'], ['stock-to-m5-baseline', 'm5-to-candidate-upgrade',
            'direct-m5-downgrade', 'm5-to-candidate-for-removal', 'candidate-remove-for-m5-rollback', 'm5-rollback-after-removal'])
        self.assertTrue(all('--force-reinstall' not in argv for _, argv in case.calls))
        failed = {'previous_package': dict(lifecycle.M5_BASELINE)}
        with self.assertRaises(RuntimeError): lifecycle.previous_upgrade_chain(FakeCase(True), args, {}, {}, {}, {}, failed)
        self.assertFalse(failed['previous_upgrade']['passed'])


if __name__ == '__main__': unittest.main()
