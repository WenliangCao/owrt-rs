"""Comparator identity gates; synthetic timings are never acceptance evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import perf_opt_tables as tables


ROOT = Path(__file__).resolve().parents[2]
E = '8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27'


def complete_summary(left, right):
    data = {'schema': 1, 'complete': True, 'window_count': 110, 'valid_windows': 110,
            'parse_failures': [], 'identity': {'production_sha256': tables.DEPLOYED,
            'comparison': {'c': left, 'rust': right}, 'scenes': [[s] for s in tables.SCENES]},
            'windows': [], 'comparisons': {}}
    for scene in tables.SCENES:
        metrics = {key: tables.compare([2] * 5, [1] * 5,
                   resolution=1 if scene.endswith(('small', 'large')) else 0)
                   for key in ('p50_ms', 'p95_ms')}
        metrics['cpu_us'] = tables.compare([120] * 5, [100] * 5, cpu=([120] * 5, [100] * 5))
        metrics.update({key: {'left': tables.spread([1] * 5), 'right': tables.spread([1] * 5)}
                        for key in tables.RESOURCES})
        if scene in ('dhcp', 'dhcp-home6'):
            for key in ('dora_p50_ms', 'dora_p95_ms'):
                metrics[key] = (tables.compare([2] * 5, [1] * 5) if scene == 'dhcp' else
                                {'left': tables.spread([2] * 5), 'right': tables.spread([1] * 5), 'ranked': False})
        data['comparisons'][scene] = metrics
        for number in range(1, 6):
            for side in (('c', 'rust') if number % 2 else ('rust', 'c')):
                latency, cpu = (2, 120) if side == 'c' else (1, 100)
                data['windows'].append({'label': f'{scene}-{number}-{side}', 'scene': scene,
                    'round': number, 'side': side, 'valid': True, 'errors': [], 'raw_verified_files': 1,
                    'elf_sha256': left if side == 'c' else right,
                    'latency_ms': {'p50': latency, 'p95': latency},
                    'dora_latency_ms': {'p50': latency, 'p95': latency},
                    'cpu_ticks': cpu, 'cpu_us_per_operation': cpu, **{key: 1 for key in tables.RESOURCES}})
    return data


class ComparatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = complete_summary(tables.DEPLOYED, E)

    def prospective(self):
        # No metrics or frozen statistical gates change with the identity remap.
        data = copy.deepcopy(self.original)
        data['identity']['comparison'] = {'c': E, 'rust': 'f' * 64}
        for window in data['windows']:
            window['elf_sha256'] = data['identity']['comparison'][window['side']]
        return data

    def test_legacy_complete_candidate_still_valid(self):
        tables.validate(self.original, 'candidate')

    def test_new_comparator_requires_exact_explicit_identity(self):
        data = self.prospective()
        with self.assertRaisesRegex(ValueError, 'wrong left comparator'):
            tables.validate(data, 'candidate')
        tables.validate(data, 'candidate', E)
        with self.assertRaisesRegex(ValueError, 'wrong left comparator'):
            tables.validate(data, 'candidate', 'e' * 64)

    def test_comparator_override_cannot_override_production_or_windows(self):
        data = self.prospective()
        data['identity']['production_sha256'] = E
        with self.assertRaisesRegex(ValueError, 'device environment'):
            tables.validate(data, 'candidate', E)
        data = self.prospective()
        data['windows'][0]['valid'] = False
        with self.assertRaisesRegex(ValueError, 'invalid/unverified window'):
            tables.validate(data, 'candidate', E)

    def test_cli_requires_hash_and_label_and_renders_explicit_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            candidate = folder / 'synthetic-identity-only.json'
            candidate.write_text(json.dumps(self.prospective()))
            baseline = folder / 'synthetic-baseline.json'
            baseline.write_text(json.dumps(complete_summary(tables.EXACT_C, tables.DEPLOYED)))
            output = folder / 'report.md'
            command = [sys.executable, str(ROOT / 'tools/dnsmasq/perf_opt_tables.py'),
                       '--baseline', str(baseline),
                       '--candidate', str(candidate), '--output', str(output)]
            for options in [[], ['--candidate-baseline-sha256', E],
                            ['--candidate-baseline-label', 'Candidate E'],
                            ['--candidate-baseline-sha256', E, '--candidate-baseline-label', ' ']]:
                result = subprocess.run(command + options, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(output.exists())
            result = subprocess.run(command + ['--candidate-baseline-sha256', E,
                                    '--candidate-baseline-label', 'Candidate E'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('| Candidate E | ' + E + ' |', output.read_text())


if __name__ == '__main__':
    unittest.main()
