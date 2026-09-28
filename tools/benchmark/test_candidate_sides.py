#!/usr/bin/env python3
"""Four-side provenance and complete-block negative checks, without a device."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from analyze_candidate import derive
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

    def test_four_sides_and_r94_delta_survive_aggregation(self):
        result = derive(self.root, 'fixture')
        self.assertEqual(result['measured_sides'], tuple(self.sides))
        self.assertEqual(len(result['runs']), 12)
        self.assertIn('candidate_vs_r94_pct', result['summary']['system_info'])
        self.assertEqual(result['summary']['system_info']['r94']['mean_us']['n'], 3)

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


if __name__ == '__main__':
    unittest.main()
