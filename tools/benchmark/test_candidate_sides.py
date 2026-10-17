#!/usr/bin/env python3
"""Four-side provenance and complete-block negative checks, without a device."""
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

from analyze_candidate import derive
from analyze_httpd_memory import derive as derive_memory
from analyze_rpc_client import derive as derive_rpc_client
from run_candidate import extra_baseline_records
from selftest_lanes import native_sample


class ExtraBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.elf = self.root / 'original-elf'
        self.elf.write_bytes(b'preserved original ELF fixture')
        self.sha = hashlib.sha256(self.elf.read_bytes()).hexdigest()
        self.evidence = self.root / 'provenance.json'
        self.evidence.write_text(json.dumps({'subject_sha256': self.sha, 'formal': False,
                                             'missing_records': ['canonical build']}))

    def records(self):
        return extra_baseline_records(['r94=' + str(self.elf)], ['r94=' + str(self.evidence)], 'r89')

    def test_preserves_diagnostic_provenance_without_inventing_manifest(self):
        record = self.records()['r94']
        self.assertEqual(record['subject_sha256'], self.sha)
        self.assertFalse(record['provenance']['formal'])
        self.assertEqual(record['evidence_sha256'], hashlib.sha256(self.evidence.read_bytes()).hexdigest())
        self.assertNotIn('manifest', record)

    def test_elf_change_and_unpaired_evidence_are_rejected(self):
        self.elf.write_bytes(b'not the preserved ELF')
        with self.assertRaisesRegex(ValueError, 'mismatch'): self.records()
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            extra_baseline_records(['r94=' + str(self.elf)], [], 'r89')

    def test_duplicate_reserved_and_path_labels_are_rejected(self):
        for labels in (['r94', 'r94'], ['r89'], ['stock'], ['../r94']):
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                extra_baseline_records([label + '=' + str(self.elf) for label in labels], [], 'r89')


class FourSideAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sides = ['stock', 'r89', 'r94', 'candidate']
        self.order = self.sides + self.sides[::-1] + ['r89', 'candidate', 'stock', 'r94']
        self.subjects = dict(zip(self.sides, ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]))
        self.settings = {'component': 'procd', 'matrix': True, 'baseline_label': 'r89',
                         'schedule': 'random-blocks', 'procd_workloads': ['system_info'],
                         'procd_warmup': 1,
                         'extra_baselines': {'r94': {'subject_sha256': self.subjects['r94'],
                                                     'provenance': {'subject_sha256': self.subjects['r94']}}}}
        self.put('order.json', self.order); self.put('subjects.json', self.subjects)
        self.put('settings.json', self.settings)
        self.put('host-manifest.json', {'components': {'ubusd': {'original': {'sha256': 'u' * 64}}}})
        for phase in ('before', 'after'):
            self.put('health-' + phase + '.json', {'boot_id': 'boot'})
            (self.root / ('config-' + phase + '.sha256')).write_text('same config')
        (self.root / 'COMPLETE').touch()
        for index, side in enumerate(self.order, 1):
            local = self.root / f'{index:02d}-{side}'; raw = local / 'raw'; raw.mkdir(parents=True)
            (local / 'COMPLETE').touch(); (raw / 'COMPLETE').touch()
            for name, value in {'meta.json': {'component': 'procd', 'dependencies': 'original OpenWrt',
                                              'subject_pid': 1, 'iterations': 4},
                                'system_info.json': native_sample(),
                                'resident.json': {'processes': [{**native_sample()['daemon_cpu'][0]['after'], 'VmPTE': 8}],
                                                  'temperature_millic': 42000}}.items():
                (raw / name).write_text(json.dumps(value))
            for name, value in {'binary-sha256.txt': self.subjects[side], 'subject-sha256.txt': self.subjects[side],
                                'dependencies-sha256.txt': 'u' * 64, 'boot-id.txt': 'boot',
                                'benchmark-sha256.txt': 'client /tool\nnamespace /ns\n',
                                'harness-sha256.txt': 'harness', 'procd-fixtures.sha256': 'fixture',
                                'kernel.txt': 'fixed-kernel'}.items():
                (raw / name).write_text(value.rstrip('\n') + '\n')
            (local / 'raw.tar.gz').write_bytes(b'fixture archive')

    def put(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def store_native_identity(self, identity):
        (self.root / 'host-running-hashes.txt').write_text(identity)
        for phase in ('before', 'after'):
            path = self.root / ('health-' + phase + '.json')
            health = json.loads(path.read_text())
            health['native_identity'] = identity
            self.put(path.name, health)
        for index, side in enumerate(self.order, 1):
            for phase in ('before', 'after'):
                (self.root / f'{index:02d}-{side}' / f'production-{phase}.txt').write_text(identity)

    def enable_native(self, extra_dns=False):
        names = sorted(('uci', 'reload-config', 'fw4', 'logd', 'httpd', 'rpcd',
                        'procd', 'ubusd', 'netifd', 'dnsmasq'))
        components = {name: {'rust_sha256': hashlib.sha256(name.encode()).hexdigest()} for name in names}
        manifest = {'deployment_layout': 'native-ten', 'source_commit': 'e' * 40,
                    'components': components}
        self.put('native-manifest.json', manifest)
        digest = hashlib.sha256((self.root / 'native-manifest.json').read_bytes()).hexdigest()
        self.put('settings.json', {**self.settings, 'stack': 'native', 'native_manifest_sha256': digest})
        health = {'boot_id': 'boot', 'mode': 'native', 'verified_components': names,
                  'native_source_commit': manifest['source_commit'], 'native_manifest_sha256': digest}
        for phase in ('before', 'after'):
            self.put('health-' + phase + '.json', health)
        rows = []
        for index, name in enumerate(names, 10):
            pid, start = ('-', '-') if name in ('uci', 'reload-config', 'fw4') else (str(index), '100')
            if name == 'procd': pid = '1'
            rows.append(f'{name} {pid} {start} {components[name]["rust_sha256"]}')
        if extra_dns:
            rows.append('dnsmasq 99 101 ' + components['dnsmasq']['rust_sha256'])
        identity = '\n'.join(rows) + '\n'
        self.store_native_identity(identity)
        return health, manifest, identity

    def test_four_sides_and_r94_delta_survive_aggregation(self):
        result = derive(self.root, 'fixture')
        self.assertEqual(result['measured_sides'], tuple(self.sides))
        self.assertEqual(len(result['runs']), 12)
        self.assertIn('candidate_vs_r94_pct', result['summary']['system_info'])
        self.assertEqual(result['summary']['system_info']['r94']['mean_us']['n'], 3)

    def test_markdown_keeps_daemon_own_cpu_clock(self):
        output = self.root / 'published'
        subprocess.run([sys.executable, str(Path(__file__).with_name('analyze_candidate.py')),
                        str(self.root), '--output', str(output), '--label', 'daemon fixture'],
                       check=True, capture_output=True)
        markdown = (output / 'results.md').read_text()
        self.assertIn('CPU 口径：subject_own_cpu_clock_us_per_op', markdown)
        self.assertIn('1.00 / 5000.00', markdown)

    def test_missing_fourth_side_is_rejected_before_reading_windows(self):
        self.put('order.json', [side for side in self.order if side != 'r94'])
        with self.assertRaisesRegex(AssertionError, 'missing historical'): derive(self.root, 'bad')

    def test_duplicate_side_in_a_block_is_rejected(self):
        order = copy.copy(self.order); order[0], order[4] = order[4], order[0]
        self.put('order.json', order)
        with self.assertRaisesRegex(AssertionError, 'incomplete comparison block'): derive(self.root, 'bad')

    def test_dependency_change_is_rejected(self):
        (self.root / '01-stock/raw/dependencies-sha256.txt').write_text('other ubusd\n')
        with self.assertRaisesRegex(AssertionError, 'exact image'): derive(self.root, 'bad')

    def test_native_exact_ten_and_multiple_dns_instances_are_preserved(self):
        _, manifest, identity = self.enable_native(extra_dns=True)
        result = derive(self.root, 'native fixture')
        health = result['native_health']
        self.assertEqual(health['mode'], 'native')
        self.assertEqual(health['source_commit'], manifest['source_commit'])
        self.assertEqual(len(health['verified_components']), 10)
        self.assertIn('dnsmasq', health['verified_components'])
        self.assertEqual(health['identity_sha256'], hashlib.sha256(identity.encode()).hexdigest())
        self.assertNotIn('native_identity', health)

    def test_native_health_rejects_missing_extra_and_duplicate_components(self):
        health, _, identity = self.enable_native()
        health['native_identity'] = identity
        names = health['verified_components']
        for invalid in (names[:-1], names + ['other'], names[:-1] + [names[0]],
                        sorted(['other' if name == 'dnsmasq' else name for name in names])):
            with self.subTest(components=invalid):
                self.put('health-after.json', {**health, 'verified_components': invalid})
                with self.assertRaisesRegex(AssertionError, 'exactly ten'):
                    derive(self.root, 'invalid native components')

    def test_native_mode_cannot_be_mislabelled(self):
        health, _, identity = self.enable_native()
        self.put('health-after.json', {**health, 'native_identity': identity, 'mode': 'rust'})
        with self.assertRaisesRegex(AssertionError, 'mode mismatch'):
            derive(self.root, 'mixed modes')
        self.enable_native()
        settings = json.loads((self.root / 'settings.json').read_text())
        self.put('settings.json', {**settings, 'stack': 'rust'})
        with self.assertRaisesRegex(AssertionError, 'mode mismatch'):
            derive(self.root, 'native evidence labelled rust')

    def test_native_manifest_requires_exact_bytes_and_matching_source(self):
        self.enable_native()
        path = self.root / 'native-manifest.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(AssertionError, 'manifest bytes changed'):
            derive(self.root, 'reserialized manifest')
        health, _, identity = self.enable_native()
        for phase in ('before', 'after'):
            self.put('health-' + phase + '.json', {**health, 'native_identity': identity,
                                                 'native_source_commit': 'f' * 40})
        with self.assertRaisesRegex(AssertionError, 'source mismatch'):
            derive(self.root, 'different source')

    def test_native_identity_rejects_wrong_hash_missing_component_and_duplicate_pid(self):
        _, manifest, identity = self.enable_native()
        rows = identity.splitlines()
        variants = (
            (identity.replace(manifest['components']['dnsmasq']['rust_sha256'], '0' * 64), 'differs from manifest'),
            ('\n'.join(row for row in rows if not row.startswith('dnsmasq ')) + '\n', 'exactly ten'),
            (identity + next(row for row in rows if row.startswith('rpcd ')) + '\n', 'duplicate native component'),
            (identity + next(row for row in rows if row.startswith('dnsmasq ')) + '\n', 'duplicate native daemon PID'),
            (identity.replace('procd 1 ', 'procd 88 '), 'PID 1'),
        )
        for invalid, expected in variants:
            with self.subTest(expected=expected):
                self.store_native_identity(invalid)
                with self.assertRaisesRegex(AssertionError, expected):
                    derive(self.root, 'invalid native identity')

    def test_native_window_identity_change_is_rejected(self):
        _, _, identity = self.enable_native()
        (self.root / '03-r94/production-after.txt').write_text(identity.replace('procd 1 ', 'procd 88 '))
        with self.assertRaisesRegex(AssertionError, 'production identity changed'):
            derive(self.root, 'changed production')

    def test_native_diagnostic_analyzers_apply_the_same_health_gate(self):
        health, _, identity = self.enable_native()
        self.put('health-after.json', {**health, 'native_identity': identity,
                                      'verified_components': health['verified_components'][:-1]})
        settings = json.loads((self.root / 'settings.json').read_text())
        self.put('settings.json', {**settings, 'matrix': False, 'held_connections': 64})
        with self.assertRaisesRegex(AssertionError, 'exactly ten'):
            derive_memory(self.root)
        self.put('order.json', ['stock', 'candidate'])
        self.put('settings.json', {**settings, 'component': 'rpcd', 'matrix': False,
                                   'rpc_client_diagnostic': True})
        self.put('client-probe.json', {'diagnostic_only': True})
        with self.assertRaisesRegex(AssertionError, 'exactly ten'):
            derive_rpc_client(self.root)


class UciFourSideAnalysisTests(unittest.TestCase):
    workloads = ('export_network', 'export_64', 'set_commit_get', 'get_network',
                 'export_multi', 'show_long', 'delta_64', 'batch_read16')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sides = ['stock', 'r89', 'r94', 'candidate']
        self.order = self.sides + self.sides[::-1] + ['r89', 'candidate', 'stock', 'r94']
        subjects = dict(zip(self.sides, ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]))
        settings = {'component': 'uci', 'matrix': True, 'baseline_label': 'r89',
                    'schedule': 'random-blocks', 'extra_baselines': {
                        'r94': {'subject_sha256': subjects['r94'],
                                'provenance': {'subject_sha256': subjects['r94'], 'formal': False}}}}
        for name, value in {'order.json': self.order, 'subjects.json': subjects,
                            'settings.json': settings}.items():
            (self.root / name).write_text(json.dumps(value))
        for phase in ('before', 'after'):
            (self.root / ('health-' + phase + '.json')).write_text(json.dumps({'boot_id': 'boot'}))
            (self.root / ('config-' + phase + '.sha256')).write_text('same config')
        (self.root / 'COMPLETE').touch()
        cpu = {'stock': 2100, 'r89': 1400, 'r94': 1100, 'candidate': 1000}
        for index, side in enumerate(self.order, 1):
            local = self.root / f'{index:02d}-{side}'; raw = local / 'raw'; raw.mkdir(parents=True)
            (local / 'COMPLETE').touch(); (raw / 'COMPLETE').touch()
            (local / 'raw.tar.gz').write_bytes(b'fixture archive')
            (raw / 'meta.json').write_text(json.dumps({'component': 'uci',
                'dependencies': 'original OpenWrt', 'subject_pid': None, 'iterations': 80}))
            for name, value in {'binary-sha256.txt': subjects[side], 'boot-id.txt': 'boot',
                                'benchmark-sha256.txt': 'client /tool\nnamespace /ns\n',
                                'harness-sha256.txt': 'harness', 'kernel.txt': 'fixed-kernel',
                                'uci-fixtures.sha256': 'network /etc/config/network\nlong /etc/config/ucilong\ndelta /tmp/uci-delta/r84fixture\n'}.items():
                (raw / name).write_text(value.rstrip('\n') + '\n')
            sample = native_sample(n=4, warm=5)
            sample.update(daemon_cpu=[], child_cpu_s=0)
            for phase, extra in (('before', 0), ('after', 2 * cpu[side])):
                sample['client_' + phase].update(child_cpu_ticks=200,
                    rusage_children_user_us=1000000 + extra,
                    rusage_children_system_us=1000000 + extra,
                    rusage_children_counter_source='getrusage(RUSAGE_CHILDREN)')
            for workload in self.workloads:
                (raw / (workload + '.json')).write_text(json.dumps(sample))

    def test_expanded_four_sides_keep_command_cpu_and_three_baseline_comparisons(self):
        result = derive(self.root, 'UCI expanded fixture')
        self.assertTrue(result['acceptance_eligible'])
        self.assertEqual(result['measured_sides'], tuple(self.sides))
        self.assertEqual(set(result['summary']), set(self.workloads))
        self.assertEqual(len(result['runs']), 3 * 4 * len(self.workloads))
        self.assertEqual(result['resident'], [])
        self.assertFalse(result['extra_baselines']['r94']['provenance']['formal'])
        for workload in self.workloads:
            summary = result['summary'][workload]
            self.assertEqual(summary['candidate']['command_tree_cpu_us_per_op']['median'], 1000)
            self.assertEqual(summary['candidate']['command_tree_cpu_us_per_op']['n'], 3)
            self.assertEqual(summary['candidate']['subject_cpu_us_per_op']['median'], 0)
            for comparison, baseline in (('candidate_vs_stock_pct', 2100),
                                         ('candidate_vs_baseline_pct', 1400),
                                         ('candidate_vs_r94_pct', 1100)):
                self.assertAlmostEqual(summary[comparison]['command_tree_cpu_us_per_op'],
                                       (1000 / baseline - 1) * 100)

    def test_markdown_uses_fine_command_cpu_instead_of_zero_legacy_ticks(self):
        output = self.root / 'published'
        subprocess.run([sys.executable, str(Path(__file__).with_name('analyze_candidate.py')),
                        str(self.root), '--output', str(output), '--label', 'UCI fixture'],
                       check=True, capture_output=True)
        markdown = (output / 'results.md').read_text()
        self.assertIn('CPU 口径：command_tree_cpu_us_per_op', markdown)
        for workload in self.workloads:
            self.assertIn('| ' + workload + ' | 1.00 / 2100.00 | 1.00 / 1400.00 | '
                          '1.00 / 1100.00 | 1.00 / 1000.00 |', markdown)
        self.assertIn('+0.00% / -52.38% | +0.00% / -28.57% | +0.00% / -9.09%', markdown)

    def test_changed_fixture_on_one_historical_side_is_rejected(self):
        (self.root / '03-r94/raw/uci-fixtures.sha256').write_text('different delta content\n')
        with self.assertRaisesRegex(AssertionError, 'fixtures changed'):
            derive(self.root, 'changed UCI fixture')

    def test_missing_expanded_workload_and_wrong_iteration_count_are_rejected(self):
        path = self.root / '04-candidate/raw/batch_read16.json'
        contents = path.read_bytes(); path.unlink()
        with self.assertRaises(FileNotFoundError):
            derive(self.root, 'missing batch lane')
        path.write_bytes(contents)
        path = self.root / '04-candidate/raw/meta.json'
        meta = json.loads(path.read_text()); meta['iterations'] = 100
        path.write_text(json.dumps(meta))
        with self.assertRaises(AssertionError):
            derive(self.root, 'wrong UCI sample count')

    def test_one_legacy_row_cannot_claim_fine_command_cpu_for_complete_matrix(self):
        path = self.root / '04-candidate/raw/delta_64.json'
        sample = json.loads(path.read_text())
        del sample['client_after']['rusage_children_system_us']
        path.write_text(json.dumps(sample))
        with self.assertRaisesRegex(AssertionError, 'partial'):
            derive(self.root, 'partial command counter')
        for phase in ('before', 'after'):
            for field in list(sample['client_' + phase]):
                if field.startswith('rusage_children_'):
                    del sample['client_' + phase][field]
        path.write_text(json.dumps(sample))
        result = derive(self.root, 'one legacy row')
        self.assertFalse(result['acceptance_eligible'])
        self.assertTrue(any('getrusage' in reason for reason in result['limitations']))
        self.assertNotIn('command_tree_cpu_us_per_op', result['summary']['delta_64']['candidate'])
        self.assertEqual(result['summary']['delta_64']['candidate']['subject_cpu_us_per_op']['median'], 0)


if __name__ == '__main__':
    unittest.main()
