import contextlib
from concurrent.futures import ThreadPoolExecutor
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import m5_final_validation as final


class LateGuardTests(unittest.TestCase):
    def test_prepare_keeps_unmeasured_guard_required_without_changing_identity(self):
        spec = {'validation_mode': 'm6b'}; before = copy.deepcopy(spec)
        with patch.object(final, 'commands', return_value=[]) as commands:
            schedule = final.prepare_schedule(spec, Path('/private/final'))
        self.assertEqual(spec, before)
        self.assertEqual(commands.call_count, 6)
        self.assertEqual(schedule['perf-guard'], {'status': 'pending-measured-plan', 'required': True})
        self.assertIn('perf-guard', final.completion_status(spec, {})['missing_phases'])
        self.assertIn('perf-guard', final.phase_prerequisites(spec, 'package'))

    def fixture(self, root):
        root = root.resolve()
        tools = root / 'tools/dnsmasq'; tools.mkdir(parents=True)
        native = {'tools_files': {}, 'native': {}}
        for name in ('m6a_loadgen', 'm6a_upstream'):
            source = tools / (name + '.c'); source.write_text('synthetic source ' + name)
            elf = root / name; elf.write_bytes(b'synthetic helper ' + name.encode())
            native['tools_files'][name + '.c'] = final.digest(source)
            native['native'][name] = {'path': str(elf), 'sha256': final.digest(elf)}
        manifest = root / 'native.json'; final.save(manifest, native)
        plan = root / 'guard.json'
        final.save(plan, {'schema': 1, 'frozen': True, 'basis': 'unit-test only',
            'thresholds': {'udp_p50_max_ns': 1000000, 'idle_cpu_max_seconds': 0.1,
                           'tcp_peak_pss_max_kib': 7000},
            'native_manifest': {'path': str(manifest), 'sha256': final.digest(manifest)}})
        spec = {'validation_mode': 'm6b', 'source_root': str(root), 'source_commit': 'b' * 40,
                'elf': '/final-elf', 'elf_sha256': 'a' * 64, 'image_root': '/image',
                'runtime_root': '/runtime', 'build_json': '/build.json', 'assets': {}}
        return spec, plan

    def test_late_binding_pins_plan_native_and_sources_and_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, plan = self.fixture(root)
            before = copy.deepcopy(spec)
            binding = final.bind_guard(spec, plan, final.digest(plan))
            final.verify_guard_binding(spec, binding)
            self.assertEqual(spec, before)
            for expected in (None, 'c' * 64):
                with self.assertRaises(ValueError): final.bind_guard(spec, plan, expected)
            with self.assertRaises(ValueError):
                final.bind_guard(dict(spec, perf_guard_plan='/other'), plan, final.digest(plan))
            with self.assertRaises(ValueError):
                final.verify_guard_binding(spec, dict(binding, assets={}))
            (root / 'm6a_loadgen').write_bytes(b'changed helper')
            with self.assertRaises(ValueError): final.verify_guard_binding(spec, binding)

    def test_guard_prerequisite_rejects_changed_elf_checks_and_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, plan = self.fixture(root)
            binding = final.bind_guard(spec, plan, final.digest(plan))
            attempt = root / 'attempt'; attempt.mkdir()
            bound = dict(spec, perf_guard_plan=binding['path'])
            jobs = final.commands(bound, 'perf-guard', attempt)
            result_path = Path(jobs[0]['result']); result_path.parent.mkdir()
            final.save(result_path, jobs[0]['checks'])
            jobs[0].update(passed=True, returncode=0, result_sha256=final.digest(result_path))
            receipt = attempt / 'result.json'
            record = {'passed': True, 'manifest_sha256': 'd' * 64,
                'source_commit': spec['source_commit'], 'elf_sha256': spec['elf_sha256'],
                'attempt': str(attempt), 'guard_binding': binding, 'commands': jobs}
            final.save(receipt, record)
            final.prerequisite(spec, 'd' * 64, {'perf-guard': record}, 'perf-guard')
            for key in ('argv', 'checks'):
                changed = copy.deepcopy(record)
                if key == 'argv':
                    argv = changed['commands'][0]['argv']; argv[argv.index('--elf') + 1] = '/other-elf'
                else: changed['commands'][0]['checks'] = {}
                final.save(receipt, changed)
                with self.assertRaises(ValueError):
                    final.prerequisite(spec, 'd' * 64, {'perf-guard': changed}, 'perf-guard')
            final.save(receipt, record); final.save(result_path, {'passed': True})
            with self.assertRaises(ValueError):
                final.prerequisite(spec, 'd' * 64, {'perf-guard': record}, 'perf-guard')


class ValidationModeTests(unittest.TestCase):
    def test_m6b_product_identity_rejects_s_and_instrumentation_but_keeps_m5_policy(self):
        product = {'features': '', 'opt_level': '3'}
        final.validate_qualification_build('m6b', product)
        variants = [{'features': '', 'opt_level': level} for level in ['s', 'z', 3, None]]
        variants += [{'features': 'm6b-diagnostics', 'opt_level': '3'}, {'opt_level': '3'}]
        for variant in variants:
            with self.subTest(variant=variant):
                with self.assertRaises(ValueError):
                    final.validate_qualification_build('m6b', variant)
                final.validate_qualification_build('m5', variant)

    def test_m5_default_still_requires_both_real_fuzz_phases(self):
        completed = {name: {'passed': True} for name in final.M6B_PHASES if name != 'perf-guard'}
        self.assertEqual(final.required_phases({}), final.PHASES)
        self.assertEqual(final.phase_prerequisites({}, 'package'), final.PHASES[:6])
        status = final.completion_status({}, completed)
        self.assertEqual(status['missing_phases'], ['fuzz-build', 'fuzz'])
        self.assertEqual(status['excluded_phases'], {})

    def test_m6b_requires_real_guard_and_six_functional_phases_without_fabricating_fuzz_pass(self):
        spec = {'validation_mode': 'm6b', 'phases': list(final.M6B_PHASES)}
        completed = {name: {'passed': True} for name in final.M6B_PHASES}
        status = final.completion_status(spec, completed)
        self.assertEqual(status['missing_phases'], [])
        self.assertEqual(final.phase_prerequisites(spec, 'package'), ['families', 'm2', 'perf-guard', 'resources', 'pressure'])
        self.assertEqual(final.phase_prerequisites(spec, 'lifecycle'), final.M6B_PHASES[:-1])
        self.assertEqual(set(status['excluded_phases']), {'fuzz-build', 'fuzz'})
        self.assertTrue(all(row['status'] == 'excluded-not-required' and row['passed'] is None
                            for row in status['excluded_phases'].values()))
        self.assertNotIn('fuzz', completed)
        completed['pressure']['passed'] = False
        self.assertEqual(final.completion_status(spec, completed)['missing_phases'], ['pressure'])
        completed['pressure']['passed'] = 'yes'
        self.assertEqual(final.completion_status(spec, completed)['missing_phases'], ['pressure'])

    def test_manifest_cannot_select_a_smaller_phase_subset_or_execute_excluded_fuzz(self):
        for spec in ({'validation_mode': 'other'}, {'phases': final.M6B_PHASES},
                     {'validation_mode': 'm6b', 'phases': ['families', 'package']}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                final.required_phases(spec)
        with self.assertRaisesRegex(ValueError, 'excluded-not-required'):
            final.phase_prerequisites({'validation_mode': 'm6b'}, 'fuzz')
        self.assertEqual(final.phase_prerequisites({'validation_mode': 'm6b'}, 'full-cache-600'), ['resources'])

    def test_m6b_run_rejects_fuzz_before_creating_any_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = {'validation_mode': 'm6b', 'output': str(root), 'family_registry': {'families': []}}
            manifest = root / 'identity.json'; final.save(manifest, spec)
            args = final.argparse.Namespace(manifest=manifest, phase='fuzz', attempt=1, exclusive_window=False)
            with patch.object(final, 'verify_identity'), patch.object(final.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(ValueError, 'excluded-not-required'):
                    final.run(args)
            self.assertFalse((root / 'runs').exists())
            self.assertFalse((root / 'completed.json').exists())

    def test_m6b_summary_labels_exclusions_and_still_reports_missing_real_phases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = {'validation_mode': 'm6b', 'output': str(root), 'source_commit': 'b' * 40,
                    'elf_sha256': 'a' * 64, 'elf_bytes': 1929256}
            manifest = root / 'identity.json'; final.save(manifest, spec)
            final.save(root / 'completed.json', {})
            with patch.object(final, 'verify_identity'), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(final.summary(final.argparse.Namespace(manifest=manifest)))
            result = json.loads((root / 'summary.json').read_text())
            self.assertFalse(result['functional_validation_passed'])
            self.assertEqual(result['missing_phases'], final.M6B_PHASES)
            self.assertEqual(result['excluded_phases']['fuzz']['status'], 'excluded-not-required')
            self.assertIsNone(result['excluded_phases']['fuzz']['passed'])
            self.assertEqual(result['phases'], {})
            self.assertTrue((root / 'M6B_FUNCTIONAL_REPORT.draft.md').exists())
            self.assertFalse((root / 'M5_REPORT.draft.md').exists())


class FinalValidationTests(unittest.TestCase):
    def test_explicit_cargo_cache_is_bound_to_fuzz_build_and_default_stays_unchanged(self):
        spec = {'source_root': '/source', 'output': '/source/private/final', 'image_root': '/image',
                'runtime_root': '/runtime', 'elf': '/elf', 'elf_sha256': 'a' * 64, 'source_commit': 'b' * 40}
        output = Path('/source/private/final/runs/fuzz-build/attempt-1')
        original = final.commands(spec, 'fuzz-build', output)[0]['argv']
        self.assertEqual(original[:5], ['runuser', '-u', 'ubuntu', '--', 'sh'])
        self.assertEqual(final.cargo_target(spec), final.TARGET)
        cache = '/home/ubuntu/new-root/private/cargo-target'
        changed = final.commands(dict(spec, cargo_target_dir=cache), 'fuzz-build', output)[0]['argv']
        self.assertEqual(changed[:6], ['runuser', '-u', 'ubuntu', '--', 'env', 'ORACLE_BUILD_TARGET_DIR=' + cache])
        self.assertEqual(changed[6:], original[4:])
        self.assertEqual(final.cargo_target({'cargo_target_dir': cache}), Path(cache))
        with self.assertRaises(ValueError):
            final.cargo_target({'cargo_target_dir': 'private/cache'})

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

    def test_release_map_uses_actual_build_receipt_and_rejects_an_old_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'link.map'; path.write_bytes(b'link evidence')
            spec = {'build_json': str(root / 'build.json'), 'bindings': {'link_map': str(path)}}
            build = {'link_map': {'path': 'link.map', 'sha256': final.digest(path)}}
            final.verify_release_map(spec, build)
            with self.assertRaises(ValueError): final.verify_release_map(spec, {'artifacts': []})
            old = root / 'old'; old.mkdir(); (old / 'link.map').write_bytes(path.read_bytes())
            spec['bindings']['link_map'] = str(old / 'link.map')
            with self.assertRaises(ValueError): final.verify_release_map(spec, build)

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
            self.assertEqual(job['timeout_seconds'], 1920)

    def fuzz_fixture(self, root, *, durations=None, failed=None, artifact=None, starters=3):
        build = root / 'build'; build.mkdir(); (root / 'starts').mkdir()
        durations = durations or {name: .3 for name in final.FUZZ}
        script = f'''#!{final.sys.executable}
import json,pathlib,sys,time
root=pathlib.Path({str(root)!r});target=pathlib.Path(sys.argv[0]).name
corpus=pathlib.Path(sys.argv[1]);folder=corpus.parent
(root/'starts'/target).write_text(str(time.time_ns()))
deadline=time.monotonic()+2
while len(list((root/'starts').iterdir()))<{starters}:
    if time.monotonic()>deadline:sys.exit(9)
    time.sleep(.005)
print('executing '+target,flush=True)
time.sleep({durations!r}[target])
(corpus/'generated').write_bytes(target.encode())
if target=={artifact!r}:(folder/'artifacts'/'crash-fixture').write_bytes(b'preserved failure input')
(root/(target+'.finished')).write_text(str(time.time_ns()))
sys.exit(7 if target=={failed!r} else 0)
'''
        for target in final.FUZZ:
            path = build / target; path.write_text(script); path.chmod(0o755)
        final.save(build / 'build.json', {'kind': 'fuzz', 'artifacts': [
            {'path': target, 'sha256': final.digest(build / target)} for target in final.FUZZ]})
        spec = {'source_root': str(root), 'output': str(root), 'source_commit': 'b' * 40,
                'image_root': '/unused', 'runtime_root': '/unused', 'elf': '/unused', 'elf_sha256': 'a' * 64,
                'family_registry': {'families': []}, 'fuzz_build_directory': str(build)}
        attempt = root / 'runs/fuzz/attempt-1'
        return spec, attempt, final.commands(spec, 'fuzz', attempt)

    def test_three_fuzz_processes_really_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, attempt, jobs = self.fuzz_fixture(root)
            attempt.mkdir(parents=True)
            # Only this short fixture lowers the gate; production has no override.
            with patch.object(final, 'FUZZ_SECONDS', .2):
                records, failures = final.run_fuzz(spec, attempt, jobs)
            self.assertEqual(failures, [])
            starts = [int(path.read_text()) for path in (root / 'starts').iterdir()]
            finishes = [int((root / (name + '.finished')).read_text()) for name in final.FUZZ]
            self.assertLess(max(starts), min(finishes))
            self.assertEqual(len({record['pid'] for record in records}), 3)
            for record in records:
                self.assertTrue(record['passed']); self.assertGreaterEqual(record['elapsed_seconds'], .2)
                self.assertLess(record['started_at_unix_ns'], record['finished_at_unix_ns'])
                self.assertEqual(record['instrumented_target_sha256'], final.digest(jobs[0]['argv'][0]))
                self.assertEqual(record['artifact_entries'], [])
                self.assertEqual(record['final_corpus']['generated'], final.hashlib.sha256(record['id'].encode()).hexdigest())
                self.assertIn(record['id'], Path(record['log']).read_text())
                self.assertEqual(json.loads((attempt / (record['id'] + '.json')).read_text()), record)
            self.assertEqual(json.loads((attempt / 'commands.json').read_text()), records)

    def test_failed_fuzz_target_keeps_all_peers_and_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec, attempt, jobs = self.fuzz_fixture(root,
                durations={'dns_wire': .03, 'dhcp_packet': .3, 'config_line': .4}, failed='dns_wire', artifact='dns_wire')
            manifest = root / 'identity.json'; final.save(manifest, spec)
            args = final.argparse.Namespace(manifest=manifest, phase='fuzz', attempt=1, exclusive_window=False)
            with patch.object(final, 'verify_identity'), patch.object(final.os, 'geteuid', return_value=0), \
                    patch.object(final, 'prerequisite', return_value={'artifact_directory': spec['fuzz_build_directory']}), \
                    patch.object(final, 'FUZZ_SECONDS', .2), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(final.run(args))
            result = json.loads((attempt / 'result.json').read_text()); records = result['commands']
            self.assertFalse(result['passed']); self.assertEqual(len(records), 3)
            failed, *peers = records
            self.assertEqual(failed['returncode'], 7); self.assertFalse(failed['passed'])
            self.assertTrue(any('exited 7' in error for error in failed['failures']))
            self.assertTrue(any('produced artifacts' in error for error in failed['failures']))
            self.assertEqual(failed['artifact_entries'], ['crash-fixture'])
            self.assertEqual((Path(failed['artifact_directory']) / 'crash-fixture').read_bytes(), b'preserved failure input')
            self.assertTrue(all(record['passed'] and record['returncode'] == 0 for record in peers))
            self.assertTrue(all(record['finished_at_unix_ns'] > failed['finished_at_unix_ns'] for record in peers))
            self.assertEqual(len(result['failures']), len(failed['failures']))
            self.assertAlmostEqual(result['target_seconds'], sum(record['elapsed_seconds'] for record in records))
            self.assertNotIn('fuzz', json.loads((root / 'completed.json').read_text()))
            self.assertTrue(all((attempt / (record['id'] + '.json')).is_file() for record in records))

    def test_fuzz_identity_rejection_still_collects_other_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, attempt, jobs = self.fuzz_fixture(root, starters=2)
            build = Path(spec['fuzz_build_directory']) / 'build.json'; receipt = json.loads(build.read_text())
            receipt['artifacts'][0]['sha256'] = '0' * 64; final.save(build, receipt)
            attempt.mkdir(parents=True)
            with patch.object(final, 'FUZZ_SECONDS', .2): records, failures = final.run_fuzz(spec, attempt, jobs)
            self.assertTrue(failures); self.assertIsNone(records[0]['returncode'])
            self.assertTrue(any('instrumented target changed' in error for error in records[0]['failures']))
            self.assertFalse((root / 'starts/dns_wire').exists())
            self.assertTrue(all(record['passed'] for record in records[1:]))

    def test_short_fuzz_runs_cannot_satisfy_the_production_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, attempt, jobs = self.fuzz_fixture(root, durations={name: .03 for name in final.FUZZ})
            attempt.mkdir(parents=True)
            records, failures = final.run_fuzz(spec, attempt, jobs)
            self.assertEqual(final.FUZZ_SECONDS, 1800); self.assertEqual(len(records), 3)
            self.assertEqual(len(failures), 3)
            self.assertTrue(all(record['returncode'] == 0 and not record['passed'] for record in records))
            self.assertTrue(all('30-minute' in record['failures'][0] for record in records))

    def test_fuzz_timeout_stops_and_preserves_every_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); spec, attempt, jobs = self.fuzz_fixture(root, durations={name: 5 for name in final.FUZZ})
            attempt.mkdir(parents=True)
            for job in jobs: job['timeout_seconds'] = .2
            started = time.monotonic()
            records, failures = final.run_fuzz(spec, attempt, jobs)
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(len(records), 3); self.assertTrue(failures)
            self.assertTrue(all(not record['passed'] and record['returncode'] is not None for record in records))
            self.assertTrue(all(any('job timeout' in error for error in record['failures']) for record in records))
            self.assertFalse(list(root.glob('*.finished')))

    def test_parallel_partial_families_require_the_whole_frozen_union(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); names = ['a', 'b', 'c', 'd']
            spec = {'output': str(root), 'source_commit': 'b' * 40, 'elf_sha256': 'a' * 64,
                    'source_root': '/source', 'image_root': '/image', 'runtime_root': '/runtime', 'elf': '/elf',
                    'family_registry': {'families': [{'id': name, 'steps': [{'id': 'paired', 'argv': ['/usr/bin/true'],
                        'result': '{out}/fixture-result.json', 'checks': {'qualified': True}}]} for name in names]}}
            def result(name, passed=True):
                attempt = root / name; attempt.mkdir(exist_ok=True)
                (attempt / name).mkdir(exist_ok=True)
                output = attempt / name / 'fixture-result.json'
                final.save(output, {'qualified': passed})
                return {'phase': 'families', 'passed': passed, 'failures': [], 'attempt': str(attempt),
                        'selected_families': [name],
                        'source_commit': spec['source_commit'], 'elf_sha256': spec['elf_sha256'],
                        'manifest_sha256': 'c' * 64,
                        'commands': [{'id': name + '-paired', 'family': name, 'passed': passed,
                                      'returncode': 0 if passed else 1, 'result': str(output),
                                      'result_sha256': final.digest(output), 'checks': {'qualified': True},
                                      'argv': ['/usr/bin/true'], 'timeout_seconds': 3600}]}
            final.publish(spec, 'c' * 64, result('a'))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertIn('family:a', completed); self.assertNotIn('families', completed)
            with ThreadPoolExecutor(max_workers=3) as pool:
                list(pool.map(lambda name: final.publish(spec, 'c' * 64, result(name)), names[1:]))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertTrue(completed['families']['passed'])
            self.assertEqual(len(completed['families']['family_receipts']), 4)
            final.prerequisite(spec, 'c' * 64, completed, 'families')
            altered = root / 'c/c/fixture-result.json'
            final.save(altered, {'qualified': False})
            with self.assertRaises(ValueError): final.prerequisite(spec, 'c' * 64, completed, 'families')
            final.save(altered, {'qualified': True})
            final.publish(spec, 'c' * 64, result('a', False))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertNotIn('families', completed); self.assertNotIn('family:a', completed)
            final.publish(spec, 'c' * 64, result('a', True))
            final.publish(spec, 'd' * 64, dict(result('a'), manifest_sha256='d' * 64))
            completed = json.loads((root / 'completed.json').read_text())
            self.assertNotIn('families', completed)
            with self.assertRaises(ValueError): final.prerequisite(spec, 'd' * 64, completed, 'families')


if __name__ == '__main__': unittest.main()
