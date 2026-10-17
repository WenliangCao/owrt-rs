import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import safe_v022_qualification as gate


class QualificationGateTests(unittest.TestCase):
    """Synthetic receipts test refusal paths, never qualify a real artifact."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.plan = self.root / 'plan.json'
        self.plan.write_text('{"prefix":"synthetic"}\n')
        self.path = self.root / 'qualification.json'
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        self.release = self.root / 'release.json'
        self.source = {'commit': 'a' * 40, 'inputs_digest': 'b' * 64}
        self.k = self.file('k', 'baseline')
        candidate = self.file('candidate', 'candidate')
        package = self.file('package', 'apk')
        receipt = self.file('receipt', 'synthetic reviewed receipt')
        self.value = {
            'schema': 1, 'status': 'qualified', 'prefix': 'synthetic',
            'plan_sha256': gate.sha(self.plan), 'bundle_manifest_sha256': gate.BUNDLE_SHA256,
            'driver_sha256': gate.sha(Path(gate.__file__).with_name('safe_v022_device_run.py')),
            'startup_runner_sha256': gate.sha(Path(gate.__file__).with_name('safe_v022_startup_run.py')),
            'source': self.source,
            'artifacts': {'k': {**self.k, 'name': 'artifact-k'},
                          'candidate': {**candidate, 'name': 'artifact-candidate'}},
            'package': package,
            'pgo': {'status': 'qualified', 'source_commit': self.source['commit'],
                    'source_inputs_digest': self.source['inputs_digest'],
                    'elf_sha256': candidate['sha256'], 'apk_sha256': package['sha256'],
                    'profile_mismatch_warnings': 0, 'compiler_warnings': 0,
                    'profile': self.file('profile', 'new profile'), 'receipt': receipt},
            'checks': {name: {'status': 'qualified', 'source_commit': self.source['commit'],
                             'source_inputs_digest': self.source['inputs_digest'],
                             'elf_sha256': candidate['sha256'], 'receipt': receipt}
                       for name in gate.REQUIRED_CHECKS},
            'startup_boundary': {'helper_proc': 'absent', 'resolver_proc': 'present',
                                 'nofile_soft': 1024, 'nofile_hard': 4096,
                                 'production_limits_receipt': receipt, 'k_no_proc_lookup_negative': receipt},
            'files': {name: self.file('tool-' + name, name) for name in gate.REQUIRED_FILES},
            'release_file': str(self.release),
        }
        self.value['checks']['correctness'].update(families=44, jobs=67, unresolved_differences=0,
                                                   original_results_retained=True)
        self.value['checks']['no_proc'].update(negative_control_verified=True, helper_and_runtime_lookup=True)
        self.value['checks']['startup_tools']['tool_sha256'] = {
            'device_selfexec_lifecycle': self.value['files']['device_selfexec_lifecycle']['sha256']}
        self.value['checks']['pressure_tools']['local_tools'] = {'pressure.py': self.file('pressure.py', 'oracle only')}
        (self.bundle / 'manifest.json').write_text('{"support_binaries":{}}')
        self.mock_bundle = patch.object(gate, 'verify_bundle', return_value={})
        self.mock_k = patch.object(gate, 'K_SHA256', self.k['sha256'])
        self.mock_bundle.start(); self.mock_k.start()
        self.addCleanup(self.mock_bundle.stop); self.addCleanup(self.mock_k.stop)

    def file(self, name, text):
        path = self.root / name
        path.write_text(text)
        return {'local': str(path), 'sha256': gate.sha(path), 'bytes': path.stat().st_size}

    def write(self, value=None, authorized=True):
        value = self.value if value is None else value
        self.path.write_text(json.dumps(value))
        self.release.write_text(json.dumps({
            'execution_authorized': authorized, 'scope': 'isolated device performance only',
            'qualification_sha256': gate.sha(self.path), 'plan_sha256': gate.sha(self.plan),
            'source_commit': value['source']['commit'],
            'elf_sha256': value['artifacts']['candidate']['sha256'],
            'root_instruction': 'synthetic test only',
        }))

    def load(self):
        return gate.load_qualification(self.path, self.bundle, self.plan)

    def test_complete_synthetic_contract_and_oracle_tools_not_staged(self):
        self.write()
        result = self.load()
        self.assertNotIn('pressure.py', result['files'])

    def test_missing_release_never_enables_execution(self):
        self.write(authorized=False)
        with self.assertRaisesRegex(ValueError, 'not released'):
            self.load()

    def test_changed_receipt_is_rejected(self):
        self.write()
        (self.root / 'receipt').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            self.load()

    def test_plain_or_other_source_receipt_is_rejected(self):
        for name in gate.REQUIRED_CHECKS:
            value = copy.deepcopy(self.value)
            value['checks'][name]['source_commit'] = 'c' * 40
            self.write(value)
            with self.subTest(check=name), self.assertRaises(ValueError):
                self.load()
        value = copy.deepcopy(self.value)
        value['checks']['no_proc']['elf_sha256'] = 'c' * 64
        self.write(value)
        with self.assertRaisesRegex(ValueError, 'final PGO'):
            self.load()

    def test_pgo_source_output_and_warning_gates(self):
        for key, wrong in [('source_commit', 'c' * 40), ('elf_sha256', 'c' * 64),
                           ('apk_sha256', 'c' * 64), ('profile_mismatch_warnings', 1), ('compiler_warnings', 1)]:
            value = copy.deepcopy(self.value); value['pgo'][key] = wrong
            self.write(value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load()

    def test_unresolved_correctness_and_wrong_startup_boundary_rejected(self):
        value = copy.deepcopy(self.value); value['checks']['correctness']['unresolved_differences'] = 1
        self.write(value)
        with self.assertRaises(ValueError): self.load()
        for key, wrong in [('helper_proc', 'present'), ('resolver_proc', 'absent'), ('nofile_soft', 1048576)]:
            value = copy.deepcopy(self.value); value['startup_boundary'][key] = wrong
            self.write(value)
            with self.subTest(key=key), self.assertRaises(ValueError): self.load()

    def test_bound_host_code_and_release_tamper_rejected(self):
        value = copy.deepcopy(self.value); value['driver_sha256'] = 'd' * 64
        self.write(value)
        with self.assertRaisesRegex(ValueError, 'host code'): self.load()
        self.write()
        changed = json.loads(self.path.read_text()); changed['notes'] = 'after release'
        self.path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'release identity'): self.load()


if __name__ == '__main__':
    unittest.main()
