#!/usr/bin/env python3
"""Freeze eight guarded R140 router confirmation windows; never run them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
C_SHA = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R136_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
BENCHMARK_SHA = '0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693'
GUARD_SHA = '58b96cc6307dc7d3810003fcc557f361901630227ae32100575b0da342a65d6d'
NAMESPACE_SHA = 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'
ORDERS = [('c', 'r136', 'candidate') if i % 2 == 0 else ('candidate', 'r136', 'c')
          for i in range(8)]
LANES = [('register_1', 'register-cycle', [1, 8]),
         ('register_16', 'register-cycle', [16, 8]),
         ('event_1', 'register-watch', [1, 1]),
         ('event_8', 'register-watch', [8, 1]),
         ('event_nomatch', 'register-watch', [1, 0]),
         ('lookup', 'lookup', ['bench.target']),
         ('invoke', 'rpc', ['bench.target', 'ping', {'n': 1}, {'ok': 1}])]
PREREQUISITES = [f'private/r140/router-correctness-01/{case}/result.json'
                 for case in ('wire', 'fd')]
HEALTH = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
          'same_production_identity', 'same_host_mounts')
PROVIDER = {'objects': 1, 'allowed_cpus': [0, 1], 'cpu_in_daemon_metric': False}
RULES = {
    'pairing': 'Same window and lane; eight non-reused A53/R136 pairs, plus independent same-window A53/C comparisons.',
    'primary': 'In each window take the equal-weight geometric mean of seven latency-mean A53/R136 ratios. Median across eight windows < 0.98 and at least seven window geometric means < 1.',
    'latency_veto': 'Any individual lane mean/p95/p99 A53/R136 ratio median > 1.03 and at least seven of eight ratios > 1 rejects the candidate.',
    'secondary': 'Report register_1 p95 against both controls separately; it cannot override the primary or latency veto.',
    'required_metrics': ['mean_us', 'p50_us', 'p95_us', 'p99_us', 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op'],
    'cpu_hard_gate': False,
    'resources': 'Report all process-clock CPU, ELF bytes, and daemon before/after VmRSS/RssAnon/VmData/VmHWM snapshots and increases. No full-memory equivalence claim.',
    'numeric': 'Lane ratios use exact fractions. Window geometric means use 60-digit Decimal arithmetic rounded to 30 decimal places before median and strict gate comparisons.',
    'interpretation': 'Equal weights are an engineering selection, not a traffic mix, a 9:1 business score, significance, equivalence, or whole-system dominance.',
    'stopping': 'Exactly eight complete clean windows and all 168 cases; no retries, exclusions, changed thresholds, or data-dependent extra windows.',
}


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def relative(path):
    return str((ROOT / path).resolve().relative_to(ROOT))


def verify_build(results_path, candidate_sha):
    """Bind the measured ELF to an exact-control, same-source A53-only build."""
    results_path = ROOT / results_path
    plan_path = results_path.with_name('frozen-plan.json')
    results = json.loads(results_path.read_text())
    plan = json.loads(plan_path.read_text())
    if results.get('passed') is not True or results['frozen_plan_sha256'] != sha(plan_path):
        raise ValueError('A53 build proof failed or frozen-plan hash differs')
    variants = {value['label']: value for value in results['variants']}
    sources = {value['label']: value['source_sha256'] for value in plan['variants']}
    if len(results['variants']) != 2 or len(plan['variants']) != 2 or set(variants) != {'control', 'a53'} or set(sources) != {'control', 'a53'} or not sources['control']:
        raise ValueError('expected exact control and A53 build proof')
    if sources['control'] != sources['a53'] or any(
            v['status'] != 'built' or v.get('source_unchanged') is not True for v in variants.values()):
        raise ValueError('control/A53 source changed or differs')
    if variants['control']['sha256'] != R136_SHA or variants['a53']['sha256'] != candidate_sha:
        raise ValueError('A53 build ELF identity differs')
    flags = results['effective_rustflags']
    if flags['a53'] != flags['control'] + ['-Ctarget-cpu=cortex-a53'] or any('target-cpu' in x for x in flags['control']):
        raise ValueError('effective recipe change is not A53-only')
    if plan['target_cpu_supported'] is not True or plan['router_cpu_parts'] != ['0xd03', '0xd03']:
        raise ValueError('stored target CPU evidence differs')
    assignments = plan['rustflags_assignment']
    if assignments['a53'] != assignments['control'][:-1] + ' -Ctarget-cpu=cortex-a53"':
        raise ValueError('RUSTFLAGS recipe change differs')
    return {'results': relative(results_path), 'plan': relative(plan_path),
            'source_sha256': sources['control'], 'effective_rustflags': flags,
            'builder_sha256': plan['builder_sha256'],
            'candidate_builder_sha256': plan['candidate_builder_sha256'],
            'control_reproduced_r136': True, 'same_sources': True,
            'only_extra_flag': '-Ctarget-cpu=cortex-a53', 'std_rebuilt': False}


def verify_oracle(path, candidate_sha):
    report = json.loads((ROOT / path).read_text())
    if report.get('passed') is not True or report['artifacts']['candidate_sha256'] != candidate_sha or report['artifacts']['r136_sha256'] != R136_SHA:
        raise ValueError('Oracle functional proof did not pass for these exact ELFs')
    if report['source']['same_runtime_as_r136'] is not True or report['unit_tests']['failed'] != 0 or report['unit_tests']['passed'] < 1 or report['unit_tests']['flags_match_release'] is not True:
        raise ValueError('Oracle same-runtime/whole-unit-suite/target-flags proof differs')
    unit_sha = report['artifacts']['unit_tests_sha256']
    if not re.fullmatch('[0-9a-f]{64}', unit_sha):
        raise ValueError('invalid Oracle unit ELF identity')
    return {'path': path, 'sha256': sha(path), 'passed': True, 'performance_filter': False,
            'unit_tests_sha256': unit_sha}


def verify_lane_smoke(path, candidate_sha):
    report = json.loads((ROOT / path).read_text())
    expected = {'schema': 1, 'passed': True, 'candidate_sha256': candidate_sha,
                'benchmark_sha256': BENCHMARK_SHA, 'template_sha256': sha('tools/r140/formal.sh.in'),
                'cases': 14, 'iterations': 100, 'warmup': 20, 'no_performance_gate': True,
                'provider_identity_fixture_and_cleanup_passed': True,
                'daemon_identities_and_cleanup_passed': True, 'all_artifacts_unchanged': True}
    if any(type(report.get(k)) is not type(v) or report[k] != v for k, v in expected.items()):
        raise ValueError('original-caller seven-lane smoke proof differs')
    records = report['records']
    if len(records) != 14 or {(r['side'], r['lane']) for r in records} != {(s, n) for s in ('c', 'candidate') for n, _, _ in LANES} or any(
            r['passed'] is not True or r['successful'] != 100 or r['errors'] != 0 for r in records):
        raise ValueError('seven-lane smoke matrix incomplete')
    return {'path': path, 'sha256': sha(path), 'template_sha256': expected['template_sha256'],
            'cases': 14, 'passed': True, 'performance_filter': False}


def verify_prerequisites(candidate_sha, boot):
    inputs, units = list(PREREQUISITES), []
    for path in PREREQUISITES:
        folder = Path(path).parent
        result = json.loads((ROOT / path).read_text())
        if result.get('candidate_sha256') != candidate_sha or not all(
                result.get(key) is True for key in HEALTH):
            raise ValueError(f'correctness gate is not valid for this candidate: {path}')
        if result.get('exit') != 0 or result.get('correctness_smoke_only') is not True:
            raise ValueError(f'expected successful correctness collection: {path}')
        health_paths = [str(folder / f'health-{phase}.json') for phase in ('before', 'after')]
        health = [json.loads((ROOT / name).read_text()) for name in health_paths]
        if health[0] != health[1] or health[0]['boot_id'] != boot or health[0]['mode'] != 'stock':
            raise ValueError(f'correctness boot/production health differs: {path}')
        inputs.extend(health_paths)
        if 'unit_tests' in result:
            unit = result['unit_tests']
            log = str(folder / 'unit-tests.log')
            if unit.get('exit') != 0 or unit.get('filter') != '' or not re.fullmatch(
                    '[0-9a-f]{64}', unit.get('sha256', '')) or not re.search(
                    rb'test result: ok\. [1-9][0-9]* passed; 0 failed;', (ROOT / log).read_bytes()):
                raise ValueError(f'full nonempty Rust unit suite did not pass: {path}')
            inputs.append(log)
            units.append({'result': path, **unit})
    if not units:
        raise ValueError('wire/FD prerequisites must include the full Rust unit suite')
    return inputs, units


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'private/r140/formal-plan-01')
    parser.add_argument('--results', type=Path, default=Path('private/r140/formal-01'))
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--build-results', type=Path, default=Path('private/r140/build-01/results.json'))
    parser.add_argument('--oracle-report', type=Path, default=Path('docs/reviews/r140-correctness-results.json'))
    parser.add_argument('--lane-smoke-report', type=Path, default=Path('docs/reviews/r140-lane-smoke-results.json'))
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', args.candidate_sha256):
        parser.error('candidate SHA-256 must contain 64 lowercase hex characters')
    out = ROOT / relative(args.out)
    results = relative(args.results)
    candidate = relative(args.candidate)
    if out.exists() or (ROOT / results).exists():
        parser.error('plan and results directories must both be new')
    if out == ROOT / results or out in (ROOT / results).parents or ROOT / results in out.parents:
        parser.error('plan and results directories must be disjoint')
    driver = 'tools/r95_device_smoke.py'
    guard = 'private/r95/guard'
    recovery = 'private/r96/recovery-full/recovery-gate.json'
    benchmark = 'private/r134/bins-ubusd/owrt-benchmark'
    before = 'private/r136/build-01/combined/ubusd-rs'
    stock = 'private/r95/ubusd-pilot/stock'
    if sha(benchmark) != BENCHMARK_SHA:
        parser.error('benchmark differs from the original R136 matrix caller')
    if sha(guard) != GUARD_SHA:
        parser.error('guard differs from the frozen R95 helper')
    subjects = {'c': {'path': stock, 'sha256': C_SHA},
                'r136': {'path': before, 'sha256': R136_SHA},
                'candidate': {'path': candidate, 'sha256': args.candidate_sha256}}
    for side, identity in subjects.items():
        if sha(identity['path']) != identity['sha256']:
            parser.error(f'{side} ELF does not match the selected identity')
    gate = json.loads((ROOT / recovery).read_text())
    if gate.get('offline_backup_verified') is not True or gate.get('configuration_matches_backup') is not True:
        parser.error('invalid recovery gate')
    build = verify_build(relative(args.build_results), args.candidate_sha256)
    oracle = verify_oracle(relative(args.oracle_report), args.candidate_sha256)
    lane_smoke = verify_lane_smoke(relative(args.lane_smoke_report), args.candidate_sha256)
    prerequisite_inputs, units = verify_prerequisites(args.candidate_sha256, gate['boot_id'])
    if any(unit['sha256'] != oracle['unit_tests_sha256'] for unit in units):
        parser.error('router unit ELF differs from the verified A53 Oracle test build')
    inputs = [driver, 'tools/r84_device_probe.py', 'tools/benchmark/isolated.sh',
              'tools/r134/ubusd_router_finish.py', 'tools/r140/formal.sh.in',
              'tools/r140/make_formal_plan.py', 'tools/r140/analyze_formal.py',
              'tools/r140/test_formal.py',
              'tools/r139/analyze_affinity.py', 'tools/r139/make_affinity_plan.py',
              'tools/r130_registration_report.py',
              'docs/reviews/R140_ROUTER_PLAN.md', guard, recovery, benchmark,
              stock, before, candidate, build['results'], build['plan'], oracle['path'], lane_smoke['path'], *prerequisite_inputs]
    input_sha256 = {path: sha(path) for path in inputs}
    template = (ROOT / 'tools/r140/formal.sh.in').read_text()
    substitutions = {'C_SHA256': C_SHA, 'R136_SHA256': R136_SHA,
                     'CANDIDATE_SHA256': args.candidate_sha256,
                     'BENCHMARK_SHA256': input_sha256[benchmark],
                     'NAMESPACE_SHA256': NAMESPACE_SHA}
    scripts = []
    for order in ORDERS:
        text = template.replace('@ORDER@', ' '.join(order))
        for key, value in substitutions.items():
            text = text.replace(f'@{key}@', value)
        if re.search(r'@[A-Z0-9_]+@', text):
            parser.error('unresolved workload template parameter')
        subprocess.run(['/bin/sh', '-n'], input=text, text=True, check=True)
        scripts.append(text)
    out.mkdir(parents=True, exist_ok=False)
    steps = []
    for i, text in enumerate(scripts):
        script = out / f'window-{i}.sh'
        script.write_text(text)
        path = relative(script)
        input_sha256[path] = sha(path)
        dest = f'{results}/window-{i}'
        argv = [driver, 'ubusd', candidate, dest, '--recovery-gate', recovery,
                '--guard', guard, '--benchmark', benchmark, '--before-candidate', before,
                '--workload-script', path, '--iterations', '10000', '--pilot']
        steps.append({'name': f'window-{i}', 'argv': argv, 'driver_result': f'{dest}/result.json'})
    plan = {
        'schema_version': 1,
        'scope': 'R140 independent eight-window physical-router Cortex-A53 candidate comparison; no deployment',
        'output': results, 'window_count': 8, 'case_count': 168, 'orders': ORDERS,
        'subjects': subjects, 'candidate_sha256': args.candidate_sha256,
        'build': build,
        'oracle_correctness': oracle,
        'lane_smoke': lane_smoke,
        'elf_bytes': {side: (ROOT / identity['path']).stat().st_size for side, identity in subjects.items()},
        'benchmark': {'path': benchmark, 'sha256': input_sha256[benchmark]},
        'namespace_sha256': NAMESPACE_SHA,
        'iterations': 10000, 'warmup': 20,
        'lanes': [{'name': name, 'command': command, 'parameters': parameters,
                   'iterations': 10000, 'warmup': 20} for name, command, parameters in LANES],
        'runtime': {'daemon_cpu': 1, 'caller_allowed_cpus': [0, 1],
                    'socket': '/var/run/ubus/ubus.sock', 'default_acl': True,
                    'daemon_argv0': '/sbin/ubusd', 'event_benchmark_slot': False,
                    'provider': PROVIDER,
                    'lane_order': [name for name, _, _ in LANES]},
        'decision_rules': RULES,
        'collection_notes': [
            'The inherited driver uses --pilot only to permit this custom timed workload; this plan freezes the independent decision rules.',
            'Each subject runs all seven lanes in fixed order in one daemon; candidate/C endpoint order alternates, R136 remains in the middle.',
            'Caller CPU allowance is 0-1. Original caller has no live caller mask/context snapshots; parent allowance and exact launch argv are recorded.',
            'Registration event lanes validate ubus.object events; they do not cover general user SEND, memory or full-system integration.',
            'The one-object provider starts only after the five registration/event lanes. Its CPU is not included in daemon CPU; lookup and invoke use the same frozen caller and JSON validation.',
            'The guarded driver must retain all six health/cleanup flags; host production stays C throughout.',
        ],
        'prerequisites': PREREQUISITES, 'unit_tests': units,
        'steps': steps, 'input_sha256': input_sha256,
    }
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(relative(out / 'plan.json'))


if __name__ == '__main__':
    main()
