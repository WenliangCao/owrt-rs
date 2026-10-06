import contextlib
from concurrent.futures import ThreadPoolExecutor
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m5_final_validation as final


class FinalValidationTests(unittest.TestCase):
    def test_input_example_has_two_variants_and_five_dependencies(self):
        spec = json.loads(Path(final.__file__).with_name('m5_final_inputs.example.json').read_text())
        self.assertEqual(len(spec['variant_apks']), 2)
        self.assertEqual(len(spec['variant_dependency_apks']), 5)
        self.assertTrue(all(Path(path).name.startswith('dnsmasq-') for path in spec['variant_apks']))
        self.assertTrue(all(not Path(path).name.startswith('dnsmasq-') for path in spec['variant_dependency_apks']))

    def test_partial_result_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'result.json'
            final.save(path, {'qualified': False})
            with self.assertRaises(ValueError): final.check_result(path, {'qualified': True})
            with self.assertRaises(KeyError): final.check_result(path, {'missing': []})
            final.save(path, {'qualified': True, 'cases': [{'id': 'a'}]})
            with self.assertRaises(ValueError):
                final.check_result(path, {'qualified': True}, {'field': 'cases', 'key': 'id', 'ids': ['a', 'b']})

    def test_only_reviewable_size_failure_continues(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'candidate.apk').write_bytes(b'reviewable fixture')
            report = {'status': 'failed', 'failure_boundary': 'size-target', 'artifact_identity_verified': True,
                      'sdk_recipe_restored': True, 'elf': {'sha256': 'a' * 64},
                      'artifact': {'name': 'candidate.apk', 'sha256': final.digest(root / 'candidate.apk')}}
            result = final.package_artifact(report, 1, 'a' * 64, root / 'manifest.json')
            self.assertEqual(result['size_acceptance'], 'pending-user-after-report')
            for field, bad in [('failure_boundary', 'source-identity'), ('sdk_recipe_restored', False),
                               ('artifact_identity_verified', False)]:
                changed = copy.deepcopy(report); changed[field] = bad
                with self.assertRaises(ValueError): final.package_artifact(changed, 1, 'a' * 64, root / 'manifest.json')
            with self.assertRaises(ValueError): final.package_artifact(report, 1, 'b' * 64, root / 'manifest.json')
            (root / 'candidate.apk').write_bytes(b'changed')
            with self.assertRaises(ValueError): final.package_artifact(report, 1, 'a' * 64, root / 'manifest.json')

    def test_failed_result_preserves_command_and_does_not_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / 'fixture.py'
            script.write_text('import json,pathlib,sys\np=pathlib.Path(sys.argv[1]);p.parent.mkdir(parents=True);p.write_text(json.dumps({"wrong": True}))\n')
            spec = {'source_root': str(root), 'output': str(root), 'source_commit': 'b' * 40,
                    'image_root': '/unused', 'runtime_root': '/unused', 'elf': '/unused', 'elf_sha256': 'a' * 64,
                    'family_registry': {'families': [{'id': 'fixture', 'steps': [{'id': 'paired',
                        'argv': [final.sys.executable, str(script), '{out}/result.json'],
                        'result': '{out}/result.json', 'checks': {'qualified': True}}]}]}}
            manifest = root / 'identity.json'; final.save(manifest, spec)
            args = final.argparse.Namespace(manifest=manifest, phase='families', attempt=1, exclusive_window=False)
            with patch.object(final, 'verify_identity'), patch.object(final.os, 'geteuid', return_value=0), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(final.run(args))
            result = json.loads((root / 'runs/families/attempt-1/result.json').read_text())
            self.assertFalse(result['passed']); self.assertEqual(result['commands'][0]['returncode'], 0)
            self.assertTrue(result['failures'])
            self.assertNotIn('families', json.loads((root / 'completed.json').read_text()))
            self.assertTrue((root / 'runs/families/attempt-1/fixture/result.json').is_file())

    def test_resource_and_fuzz_schedule_keep_required_windows(self):
        spec = {'source_root': '/source', 'output': '/source/private/final', 'image_root': '/image',
                'runtime_root': '/runtime', 'elf': '/elf', 'elf_sha256': 'a' * 64, 'source_commit': 'b' * 40,
                'cpus': [0, 1]}
        jobs = final.commands(spec, 'resources', Path('/source/private/final/runs/resources/attempt-1'))
        self.assertEqual(len(jobs), 2)
        for job in jobs:
            self.assertEqual(job['argv'][job['argv'].index('--duration-seconds') + 1], '300')
            self.assertEqual(job['checks'], {'accepted': True})
        for job in final.commands(spec, 'fuzz', Path('/source/private/final/runs/fuzz/attempt-1')):
            self.assertIn('-max_total_time=1800', job['argv'])

    def test_parallel_partial_families_require_the_whole_frozen_union(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); names = ['a', 'b', 'c', 'd']
            spec = {'output': str(root), 'source_commit': 'b' * 40, 'elf_sha256': 'a' * 64,
                    'family_registry': {'families': [{'id': name, 'steps': [{'id': 'paired'}]} for name in names]}}
            def result(name, passed=True):
                attempt = root / name; attempt.mkdir(exist_ok=True)
                return {'phase': 'families', 'passed': passed, 'failures': [], 'attempt': str(attempt),
                        'source_commit': spec['source_commit'], 'elf_sha256': spec['elf_sha256'],
                        'manifest_sha256': 'c' * 64,
                        'commands': [{'id': name + '-paired', 'family': name, 'passed': passed}]}
            final.publish(spec, 'c' * 64, result('a'))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertIn('family:a', completed); self.assertNotIn('families', completed)
            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(lambda name: final.publish(spec, 'c' * 64, result(name)), names[1:]))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertTrue(completed['families']['passed'])
            self.assertEqual(len(completed['families']['family_receipts']), 4)
            final.publish(spec, 'c' * 64, result('a', False))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertNotIn('families', completed); self.assertNotIn('family:a', completed)
            final.publish(spec, 'c' * 64, result('a', True))
            final.publish(spec, 'd' * 64, dict(result('a'), manifest_sha256='d' * 64))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertNotIn('families', completed)
            with self.assertRaises(ValueError): final.prerequisite(spec, 'd' * 64, completed, 'families')


if __name__ == '__main__': unittest.main()
