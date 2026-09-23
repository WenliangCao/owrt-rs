#!/usr/bin/env python3
"""Freeze eight guarded R136 router confirmation windows; never run them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
C_SHA = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
R134_SHA = '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0'
CANDIDATE_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
NAMESPACE_SHA = 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'
ORDERS = [('c', 'r134', 'candidate') if i % 2 == 0 else ('candidate', 'r134', 'c')
          for i in range(8)]
LANES = [('register_1', 'register-cycle', [1, 8]),
         ('register_16', 'register-cycle', [16, 8]),
         ('event_1', 'register-watch', [1, 1]),
         ('event_8', 'register-watch', [8, 1]),
         ('event_nomatch', 'register-watch', [1, 0])]


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def relative(path):
    return str((ROOT / path).resolve().relative_to(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'private/r136/formal-plan-01')
    parser.add_argument('--results', type=Path, default=Path('private/r136/formal-01'))
    parser.add_argument('--candidate', type=Path, default=Path('private/r136/build-01/combined/ubusd-rs'))
    parser.add_argument('--candidate-sha256', default=CANDIDATE_SHA)
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
    benchmark = 'private/r135/owrt-benchmark'
    before = 'private/r134/bins-ubusd/ubusd-rs'
    stock = 'private/r95/ubusd-pilot/stock'
    subjects = {'c': {'path': stock, 'sha256': C_SHA},
                'r134': {'path': before, 'sha256': R134_SHA},
                'candidate': {'path': candidate, 'sha256': args.candidate_sha256}}
    for side, identity in subjects.items():
        if sha(identity['path']) != identity['sha256']:
            parser.error(f'{side} ELF does not match the selected identity')
    prerequisites = [f'private/r136/router-correctness-01/{case}/result.json'
                     for case in ('events', 'fd')]
    for path in prerequisites:
        result = json.loads((ROOT / path).read_text())
        if result.get('candidate_sha256') != args.candidate_sha256 or not all(
            result.get(key) is True for key in ('passed', 'cleanup_verified', 'same_boot',
                                               'same_config', 'same_production_identity', 'same_host_mounts')):
            parser.error(f'correctness gate is not valid for this candidate: {path}')
    inputs = [driver, 'tools/r84_device_probe.py', 'tools/benchmark/isolated.sh',
              'tools/r134/ubusd_router_finish.py', 'tools/r135/formal.sh.in',
              'tools/r136/make_formal_plan.py', 'tools/r136/analyze_formal.py',
              'tools/r135/analyze_router.py', 'tools/r135/analyze_screen.py',
              'tools/r130_registration_report.py',
              'docs/reviews/R136_ROUTER_PLAN.md', guard, recovery, benchmark,
              stock, before, candidate, *prerequisites]
    input_sha256 = {path: sha(path) for path in inputs}
    template = (ROOT / 'tools/r135/formal.sh.in').read_text()
    substitutions = {'C_SHA256': C_SHA, 'R134_SHA256': R134_SHA,
                     'CANDIDATE_SHA256': args.candidate_sha256,
                     'BENCHMARK_SHA256': input_sha256[benchmark],
                     'NAMESPACE_SHA256': NAMESPACE_SHA}
    scripts = []
    for order in ORDERS:
        text = template.replace('@ORDER@', ' '.join(order))
        for key, value in substitutions.items():
            text = text.replace(f'@{key}@', value)
        if re.search(r'@[A-Z_]+@', text):
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
        'scope': 'R136 independent eight-window physical-router combined-allocation candidate confirmation; no deployment',
        'output': results, 'window_count': 8, 'orders': ORDERS,
        'subjects': subjects, 'candidate_sha256': args.candidate_sha256,
        'benchmark': {'path': benchmark, 'sha256': input_sha256[benchmark]},
        'namespace_sha256': NAMESPACE_SHA,
        'iterations': 10000, 'warmup': 20,
        'lanes': [{'name': name, 'command': command, 'parameters': parameters,
                   'iterations': 10000, 'warmup': 20} for name, command, parameters in LANES],
        'runtime': {'daemon_cpu': 1, 'caller_allowed_cpus': [0, 1],
                    'socket': '/var/run/ubus/ubus.sock', 'default_acl': True,
                    'daemon_argv0': '/sbin/ubusd', 'event_benchmark_slot': False,
                    'lane_order': [name for name, _, _ in LANES]},
        'decision_rules': {
            'pairing': 'same window and lane; each of the eight guarded windows is one pair',
            'effect': 'median of eight (candidate / baseline - 1) * 100 paired changes',
            'lower_is_better': True,
            'comparisons': ['candidate_vs_r134', 'candidate_vs_c'],
            'descriptive': {'win': 'median_delta_pct < -1 and lower_windows >= 7',
                            'loss': 'median_delta_pct > 1 and higher_windows >= 7',
                            'otherwise': 'unresolved; values inside the inclusive [-1, 1] band are a practical tie'},
            'primary': {'lane': 'event_8', 'metric': 'mean_us', 'baseline': 'r134',
                        'pass': 'median_delta_pct < -1 and lower_windows >= 7'},
            'acceptance': {'requires_primary': True, 'baseline': 'r134',
                           'reject_on_descriptive_loss': ['mean_us', 'p95_us', 'p99_us'],
                           'scope': 'all five lanes; CPU savings cannot offset a latency loss'},
            'required_metrics': ['mean_us', 'p50_us', 'p95_us', 'p99_us',
                                 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op'],
            'required_reporting': 'all five lanes, both controls, all eight paired changes and all required metrics',
            'interpretation': 'descriptive per-metric decisions, not familywise all-metric dominance or language limit proof',
            'stopping': 'exactly eight complete clean windows; no data-dependent additions, retries, or excluded windows',
        },
        'collection_notes': [
            'The inherited driver uses --pilot only to permit this custom timed workload; this plan freezes the independent decision rules.',
            'Each subject runs all five lanes in fixed order in one daemon; candidate/C endpoint order alternates, R134 remains in the middle.',
            'Caller CPU allowance is 0-1, not exclusive CPU pinning; last_processor is a boundary snapshot, not a migration count.',
            'Registration event lanes validate ubus.object events; they do not cover general user SEND, memory or full-system integration.',
            'The guarded driver must retain all six health/cleanup flags; host production stays C throughout.',
        ],
        'prerequisites': prerequisites, 'steps': steps, 'input_sha256': input_sha256,
    }
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(relative(out / 'plan.json'))


if __name__ == '__main__':
    main()
