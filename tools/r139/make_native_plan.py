#!/usr/bin/env python3
"""Freeze four native-caller windows after its exact-ELF Oracle smoke; never run."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from make_affinity_plan import (ROOT, C_SHA, CANDIDATE_SHA, BENCHMARK_SHA,
                                NAMESPACE_SHA, HEALTH, sha, relative)

ORDERS = [['c', 'candidate'], ['candidate', 'c'], ['candidate', 'c'], ['c', 'candidate']]
LIBRARIES = ('libubus.so.20251202', 'libubox.so.20260213', 'libc.so', 'libgcc_s.so.1')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--caller', type=Path, required=True)
    parser.add_argument('--smoke', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=Path('private/r139/native-plan-01'))
    parser.add_argument('--results', type=Path, default=Path('private/r139/native-01'))
    args = parser.parse_args()
    out, results = ROOT / relative(args.out), relative(args.results)
    result_path = ROOT / results
    if out.exists() or result_path.exists():
        parser.error('plan and results directories must both be new')
    if out == result_path or out in result_path.parents or result_path in out.parents:
        parser.error('plan and results directories must be disjoint')
    caller, smoke_path = relative(args.caller), relative(args.smoke)
    caller_sha = sha(caller)
    smoke = json.loads((ROOT / smoke_path).read_text())
    if (smoke.get('passed') is not True or smoke.get('identities_unchanged') is not True
            or smoke.get('caller_sha256') != caller_sha):
        parser.error('Oracle smoke did not pass for this exact caller ELF')
    subjects = smoke.get('subjects', [])
    if len(subjects) != 2 or {s['label']: s['sha256'] for s in subjects} != {'exactc': C_SHA, 'combined': CANDIDATE_SHA}:
        parser.error('Oracle smoke subjects are not exact C/R136')
    if (len(smoke.get('cases', [])) != 2 or {c['label'] for c in smoke['cases']} != {'exactc', 'combined'}
            or not all(c.get('passed') is True for c in smoke['cases'])):
        parser.error('Oracle smoke requires exactly two passing functional cases')
    libraries = {Path(path).name: value for path, value in smoke.get('libraries', {}).items()}
    if (len(smoke.get('libraries', {})) != 4 or set(libraries) != set(LIBRARIES)
            or not all(re.fullmatch(r'[0-9a-f]{64}', v) for v in libraries.values())):
        parser.error('Oracle smoke lacks the four exact image library identities')
    driver, guard = 'tools/r95_device_smoke.py', 'private/r95/guard'
    recovery = 'private/r96/recovery-full/recovery-gate.json'
    benchmark = 'private/r134/bins-ubusd/owrt-benchmark'
    stock, candidate = 'private/r95/ubusd-pilot/stock', 'private/r136/build-01/combined/ubusd-rs'
    for path, expected in [(stock, C_SHA), (candidate, CANDIDATE_SHA), (benchmark, BENCHMARK_SHA)]:
        if sha(path) != expected:
            parser.error(f'exact ELF identity mismatch: {path}')
    prerequisites = [f'private/r136/router-correctness-01/{case}/result.json' for case in ('events', 'fd')]
    for path in prerequisites:
        result = json.loads((ROOT / path).read_text())
        if result.get('candidate_sha256') != CANDIDATE_SHA or not all(result.get(k) is True for k in HEALTH):
            parser.error(f'prior exact-ELF correctness gate invalid: {path}')
    inputs = [driver, 'tools/r84_device_probe.py', 'tools/benchmark/isolated.sh',
              'tools/r134/ubusd_router_finish.py', 'tools/r139/make_affinity_plan.py',
              'tools/r139/native.sh.in', 'tools/r139/make_native_plan.py',
              'tools/benchmark/register_libubus_latency.c',
              'tools/benchmark/build-register-libubus-latency.sh', 'tools/benchmark/build-register-libubus.sh',
              'docs/reviews/R139_NATIVE_PLAN.md', guard, recovery, benchmark, stock,
              candidate, caller, smoke_path, *prerequisites]
    input_sha256 = {path: sha(path) for path in inputs}
    template = (ROOT / 'tools/r139/native.sh.in').read_text()
    replacements = {'C_SHA256': C_SHA, 'CANDIDATE_SHA256': CANDIDATE_SHA,
                    'BENCHMARK_SHA256': BENCHMARK_SHA, 'CALLER_SHA256': caller_sha,
                    'NAMESPACE_SHA256': NAMESPACE_SHA,
                    'LIBRARY_IDENTITIES': '\n'.join(f'{libraries[name]}  /lib/{name}' for name in LIBRARIES)}
    scripts = []
    for order in ORDERS:
        script = template.replace('@ORDER@', ' '.join(order))
        for key, value in replacements.items():
            script = script.replace(f'@{key}@', value)
        if re.search(r'@[A-Z_]+@', script):
            parser.error('unresolved workload template parameter')
        subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True)
        scripts.append(script)
    out.mkdir(parents=True, exist_ok=False)
    steps = []
    for i, script in enumerate(scripts):
        path, dest = relative(out / f'window-{i}.sh'), f'{results}/window-{i}'
        (ROOT / path).write_text(script)
        input_sha256[path] = sha(path)
        argv = [driver, 'ubusd', candidate, dest, '--recovery-gate', recovery,
                '--guard', guard, '--benchmark', benchmark, '--event-benchmark', caller,
                '--workload-script', path, '--iterations', '10000', '--pilot']
        steps.append({'name': f'window-{i}', 'argv': argv, 'driver_result': f'{dest}/result.json'})
    plan = {
        'schema_version': 1, 'scope': 'Independent native libubus registration diagnostic; no adoption or deployment',
        'output': results, 'window_count': 4, 'case_count': 8, 'orders': ORDERS,
        'subjects': {'c': {'path': stock, 'sha256': C_SHA},
                     'candidate': {'path': candidate, 'sha256': CANDIDATE_SHA}},
        'candidate_sha256': CANDIDATE_SHA,
        'benchmark': {'path': benchmark, 'sha256': BENCHMARK_SHA},
        'caller': {'path': caller, 'sha256': caller_sha, 'slot': '/tmp/bin/event-benchmark'},
        'native_smoke': {'path': smoke_path, 'sha256': sha(smoke_path)},
        'libraries': {f'/lib/{name}': libraries[name] for name in LIBRARIES},
        'namespace_sha256': NAMESPACE_SHA, 'iterations': 10000, 'warmup': 20,
        'runtime': {'daemon_cpu': 1, 'caller_cpu': 0, 'socket': '/var/run/ubus/ubus.sock',
                    'daemon_argv0': '/sbin/ubusd', 'default_acl': True, 'fresh_daemon_per_case': True},
        'decision_rules': {
            'primary_metric': 'p95_us', 'gap_pct': 'g[w] = 100 * (candidate[w] / c[w] - 1)',
            'lower': 'median(g) < -5 and at least 3/4 g strictly negative',
            'higher': 'median(g) > 5 and at least 3/4 g strictly positive',
            'otherwise': 'unresolved; does not demonstrate equivalence',
            'required_metrics': ['mean_us', 'p50_us', 'p95_us', 'p99_us',
                                 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op'],
            'required_reporting': 'All eight cases, all four paired gaps and within-caller metrics, correctness/health/archive/cleanup checks.',
            'stopping': 'Exactly four complete clean windows, no excluded cases, retries, threshold changes or data-dependent extensions.',
        },
        'collection_notes': [
            'Native caller has independent per-cycle wall samples, outer CPU clocks and full preflight/final signature checks.',
            'No absolute native-versus-Rust caller comparison or cancellation of prior Rust-caller tail losses; no adoption claim.',
            'CPU brackets include loop and timestamp overhead; no per-operation overhead subtraction.',
            'Exact existing daemon correctness gates are reused; no runtime ELF rebuild.',
            'Root alone may launch after the affinity series has finished and cleanup is verified; this constructor never launches or waits on a series.',
            'All six driver health/cleanup gates and raw archive reconciliation are required.',
        ],
        'prerequisites': prerequisites, 'steps': steps, 'input_sha256': input_sha256,
    }
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(relative(out / 'plan.json'))


if __name__ == '__main__':
    main()
