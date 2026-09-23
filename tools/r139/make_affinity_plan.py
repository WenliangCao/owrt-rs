#!/usr/bin/env python3
"""Freeze four guarded, exact-ELF caller-placement windows; never run them."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
C_SHA = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
# Keep the full production candidate identity explicit; no alternate ELF flag.
CANDIDATE_SHA = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
BENCHMARK_SHA = '0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693'
NAMESPACE_SHA = 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'
FORWARD = ['c-allowed', 'candidate-allowed', 'c-split', 'candidate-split',
           'c-colocated', 'candidate-colocated']
ROTATED = ['candidate-split', 'c-split', 'candidate-colocated', 'c-colocated',
           'candidate-allowed', 'c-allowed']
ORDERS = [FORWARD, list(reversed(FORWARD)), ROTATED, list(reversed(ROTATED))]
HEALTH = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
          'same_production_identity', 'same_host_mounts')


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def relative(path):
    return str((ROOT / path).resolve().relative_to(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('private/r139/affinity-plan-01'))
    parser.add_argument('--results', type=Path, default=Path('private/r139/affinity-01'))
    args = parser.parse_args()
    out, results = ROOT / relative(args.out), relative(args.results)
    result_path = ROOT / results
    if out.exists() or result_path.exists():
        parser.error('plan and results directories must both be new')
    if out == result_path or out in result_path.parents or result_path in out.parents:
        parser.error('plan and results directories must be disjoint')
    driver, guard = 'tools/r95_device_smoke.py', 'private/r95/guard'
    recovery = 'private/r96/recovery-full/recovery-gate.json'
    benchmark = 'private/r134/bins-ubusd/owrt-benchmark'
    stock = 'private/r95/ubusd-pilot/stock'
    candidate = 'private/r136/build-01/combined/ubusd-rs'
    subjects = {'c': {'path': stock, 'sha256': C_SHA},
                'candidate': {'path': candidate, 'sha256': CANDIDATE_SHA}}
    for path, expected in [(stock, C_SHA), (candidate, CANDIDATE_SHA), (benchmark, BENCHMARK_SHA)]:
        if sha(path) != expected:
            parser.error(f'exact ELF identity mismatch: {path}')
    # Bytes prove the original helper commands exist; the target workload also
    # executes both pin modes and checks their inherited masks before timing.
    binary = (ROOT / benchmark).read_bytes()
    if any(token not in binary for token in (b'exec-cpu', b'exec-cpu-as')):
        parser.error('original benchmark lacks the required helper commands')
    prerequisites = [f'private/r136/router-correctness-01/{case}/result.json'
                     for case in ('events', 'fd')]
    for path in prerequisites:
        result = json.loads((ROOT / path).read_text())
        if result.get('candidate_sha256') != CANDIDATE_SHA or not all(
                result.get(key) is True for key in HEALTH):
            parser.error(f'prior exact-ELF correctness gate invalid: {path}')
    inputs = [driver, 'tools/r84_device_probe.py', 'tools/benchmark/isolated.sh',
              'tools/benchmark/src/affinity.rs', 'tools/r134/ubusd_router_finish.py',
              'tools/r139/affinity.sh.in', 'tools/r139/make_affinity_plan.py',
              'docs/reviews/R139_AFFINITY_PLAN.md', guard, recovery,
              benchmark, stock, candidate, *prerequisites]
    input_sha256 = {path: sha(path) for path in inputs}
    template = (ROOT / 'tools/r139/affinity.sh.in').read_text()
    substitutions = {'C_SHA256': C_SHA, 'CANDIDATE_SHA256': CANDIDATE_SHA,
                     'BENCHMARK_SHA256': BENCHMARK_SHA, 'NAMESPACE_SHA256': NAMESPACE_SHA}
    scripts = []
    for order in ORDERS:
        script = template.replace('@ORDER@', ' '.join(order))
        for key, value in substitutions.items():
            script = script.replace(f'@{key}@', value)
        if re.search(r'@[A-Z_]+@', script):
            parser.error('unresolved workload template parameter')
        subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True)
        scripts.append(script)
    out.mkdir(parents=True, exist_ok=False)
    steps = []
    for i, script in enumerate(scripts):
        path = relative(out / f'window-{i}.sh')
        (ROOT / path).write_text(script)
        input_sha256[path] = sha(path)
        dest = f'{results}/window-{i}'
        argv = [driver, 'ubusd', candidate, dest, '--recovery-gate', recovery,
                '--guard', guard, '--benchmark', benchmark, '--workload-script', path,
                '--iterations', '10000', '--pilot']
        steps.append({'name': f'window-{i}', 'argv': argv, 'driver_result': f'{dest}/result.json'})
    plan = {
        'schema_version': 1, 'scope': 'R139 original-caller affinity diagnostic; no adoption or deployment',
        'output': results, 'window_count': 4, 'case_count': 24, 'orders': ORDERS,
        'subjects': subjects, 'candidate_sha256': CANDIDATE_SHA,
        'benchmark': {'path': benchmark, 'sha256': BENCHMARK_SHA},
        'namespace_sha256': NAMESPACE_SHA, 'iterations': 10000, 'warmup': 20,
        'lane': {'name': 'register_1', 'command': 'register-cycle', 'parameters': [1, 8]},
        'runtime': {'daemon_cpu': 1, 'socket': '/var/run/ubus/ubus.sock',
                    'daemon_argv0': '/sbin/ubusd', 'default_acl': True,
                    'fresh_daemon_per_case': True,
                    'caller_allowed_cpus': {'allowed': [0, 1], 'split': [0], 'colocated': [1]}},
        'decision_rules': {
            'primary_metric': 'p95_us',
            'gap_pct': 'g[w,p] = 100 * (candidate[w,p] / c[w,p] - 1)',
            'replication': 'median(g[w,allowed]) > 5 and g[w,allowed] > 0 in at least 3/4 windows',
            'interaction_pp': 'd[w,p] = g[w,p] - g[w,allowed], p in split,colocated',
            'placement_sensitivity': 'abs(median(d[w,p])) >= 10 percentage points and at least 3/4 d[w,p] strictly share its sign',
            'interpretation': 'Without replication, placement effects do not explain the original slow tail. With replication, a qualifying interaction signals placement sensitivity only, not a scheduler mechanism or a runtime fix.',
            'required_metrics': ['mean_us', 'p50_us', 'p95_us', 'p99_us',
                                 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op'],
            'required_reporting': 'All 24 cases, four paired gaps at every placement, both interaction series, all metrics and correctness/health/archive/cleanup checks.',
            'stopping': 'Exactly four complete clean windows; no retries, changed thresholds, excluded windows or data-dependent extra windows.',
        },
        'collection_notes': [
            'Two orders and their reversals balance condition positions and C/candidate order; cases are serial.',
            'The original caller performs full signature preflight and final empty check, and exports every ordered latency sample.',
            'The original exec-cpu helper sets and verifies its own affinity before exec. Both helper masks are exercised before timed cases.',
            'Parent allowance 0-1 and daemon live identity/mask are recorded. No live caller snapshot or per-cycle migration record exists; only the exact helper, recorded launch argv and successful exit attest caller pinning.',
            'No caller/daemon rebuild, per-operation probe, tracing, sysctl, governor, IRQ or production affinity change.',
            'The existing exact R136 router wire/events and FD gates are prerequisites; no redundant unit or router correctness rerun.',
            'All six guarded health/cleanup flags and raw archive/expanded-file reconciliation remain required.',
        ],
        'prerequisites': prerequisites, 'steps': steps, 'input_sha256': input_sha256,
    }
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(relative(out / 'plan.json'))


if __name__ == '__main__':
    main()
