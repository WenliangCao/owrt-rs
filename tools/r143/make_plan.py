#!/usr/bin/env python3
"""Freeze current R136/C monitor coverage; no collection or runtime change."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r139.make_affinity_plan import C_SHA, CANDIDATE_SHA, BENCHMARK_SHA, NAMESPACE_SHA, HEALTH, sha, relative
from r134.ubusd_stress_oracle import HELPER_SHA, LIBRARIES

MEMORY_SHA = '2db999c1d14c641eb689c161c444a6355c617694eb6acaa20aaf4bd142f7b62a'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=('monitor', 'memory'))
    parser.add_argument('--out', type=Path)
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    kind = args.kind
    out = ROOT / relative(args.out or Path(f'private/r143/{kind}-plan-01'))
    results = relative(args.results or Path(f'private/r143/{kind}-01'))
    if out.exists() or (ROOT / results).exists():
        parser.error('plan and result destinations must be new')
    if out == ROOT / results or out in (ROOT / results).parents or ROOT / results in out.parents:
        parser.error('plan and result destinations must be disjoint')
    policy_path = 'tools/r143/policy.json'
    policy = json.loads((ROOT / policy_path).read_text())
    iterations, count = (5000, 10) if kind == 'monitor' else (1, 3)
    orders = [['c', 'candidate'] if i % 2 == 0 else ['candidate', 'c'] for i in range(count)]
    caller = ('private/r131-completion/stress/r131-event-stress-libubus' if kind == 'monitor'
              else 'private/r142/memory-helper-build-01/monitor-memory')
    caller_sha = HELPER_SHA if kind == 'monitor' else MEMORY_SHA
    benchmark = 'private/r134/bins-ubusd/owrt-benchmark'
    stock, candidate = 'private/r95/ubusd-pilot/stock', 'private/r136/build-01/combined/ubusd-rs'
    driver, guard, recovery = 'tools/r95_device_smoke.py', 'private/r95/guard', 'private/r96/recovery-full/recovery-gate.json'
    for path, expected in [(stock, C_SHA), (candidate, CANDIDATE_SHA), (benchmark, BENCHMARK_SHA), (caller, caller_sha)]:
        if sha(path) != expected:
            parser.error(f'exact artifact differs: {path}')
    prerequisites = [f'private/r136/router-correctness-01/{case}/result.json' for case in ('events', 'fd')]
    for path in prerequisites:
        result = json.loads((ROOT / path).read_text())
        if result.get('candidate_sha256') != CANDIDATE_SHA or not all(result.get(k) is True for k in HEALTH):
            parser.error(f'prior exact daemon correctness gate invalid: {path}')
    proofs = ['docs/reviews/r142-memory-helper-smoke.json'] if kind == 'memory' else []
    if proofs:
        proof = json.loads((ROOT / proofs[0]).read_text())
        cases = {row['subject']: row for row in proof['cases']}
        if (proof.get('passed') is not True or proof.get('helper_sha256') != caller_sha
                or proof.get('benchmark_sha256') != BENCHMARK_SHA or proof.get('mode') != 'smoke'
                or any(cases[s]['passed'] is not True or cases[s]['daemon_sha256'] != h
                for s, h in [('c', C_SHA), ('r136', CANDIDATE_SHA)])):
            parser.error('exact C/R136 memory helper smoke must pass')
    inputs = [driver, 'tools/r84_device_probe.py', 'tools/benchmark/isolated.sh',
              'tools/r134/ubusd_router_finish.py', 'tools/r139/make_affinity_plan.py',
              'tools/r134/ubusd_stress_oracle.py', 'tools/r143/make_plan.py', 'tools/r143/router.sh.in',
              policy_path, 'tools/r143/analyze_router.py', 'tools/r143/test_analyze_router.py',
              'tools/r130_registration_report.py', 'tools/r139/analyze_affinity.py',
              'docs/reviews/R143_MONITOR_PLAN.md', guard, recovery, benchmark, stock, candidate, caller,
              *prerequisites, *proofs]
    inputs += (['tools/benchmark/r131_event_stress_libubus.c'] if kind == 'monitor'
               else ['tools/benchmark/examples/monitor_memory.rs', 'tools/benchmark/build-monitor-memory.sh'])
    frozen = {path: sha(path) for path in inputs}
    command = ('set -- "$bench" exec-cpu 0 "$caller" event-stress "$socket" monitor 5000 "$pid"'
               if kind == 'monitor' else 'set -- "$bench" exec-cpu 0 "$caller" "$socket" "$pid" sample')
    replacements = {'C_SHA256': C_SHA, 'CANDIDATE_SHA256': CANDIDATE_SHA, 'BENCHMARK_SHA256': BENCHMARK_SHA,
                    'CALLER_SHA256': caller_sha, 'NAMESPACE_SHA256': NAMESPACE_SHA,
                    'LIBRARY_IDENTITIES': '\n'.join(f'{h}  {path}' for path, h in LIBRARIES.items()),
                    'ITERATIONS': str(iterations), 'CALLER_COMMAND': command}
    template = (ROOT / 'tools/r143/router.sh.in').read_text()
    scripts = []
    for order in orders:
        script = template.replace('@ORDER@', ' '.join(order))
        for key, value in replacements.items():
            script = script.replace(f'@{key}@', value)
        if re.search(r'@[A-Z_]+@', script):
            parser.error('unresolved workload parameter')
        subprocess.run(['/bin/sh', '-n'], input=script, text=True, check=True)
        scripts.append(script)
    out.mkdir(parents=True, exist_ok=False)
    steps = []
    for i, script in enumerate(scripts):
        path, dest = relative(out / f'window-{i}.sh'), f'{results}/window-{i}'
        (ROOT / path).write_text(script)
        frozen[path] = sha(path)
        argv = [driver, 'ubusd', candidate, dest, '--recovery-gate', recovery, '--guard', guard,
                '--benchmark', benchmark, '--event-benchmark', caller, '--workload-script', path,
                '--iterations', str(iterations), '--pilot']
        steps.append({'name': f'window-{i}', 'argv': argv, 'driver_result': f'{dest}/result.json'})
    plan = {'schema_version': 1, 'scope': 'Current R136 monitor coverage versus exact C; no candidate adoption or deployment',
            'kind': kind, 'output': results, 'window_count': count, 'case_count': count * 2, 'orders': orders,
            'subjects': {'c': {'path': stock, 'sha256': C_SHA}, 'candidate': {'path': candidate, 'sha256': CANDIDATE_SHA}},
            'candidate_sha256': CANDIDATE_SHA, 'benchmark': {'path': benchmark, 'sha256': BENCHMARK_SHA},
            'caller': {'path': caller, 'sha256': caller_sha, 'slot': '/tmp/bin/event-benchmark'},
            'namespace_sha256': NAMESPACE_SHA, 'libraries': LIBRARIES,
            'iterations': iterations, 'warmup': 20 if kind == 'monitor' else 0,
            'runtime': {'daemon_cpu': 1, 'caller_cpu': 0, 'socket': '/var/run/ubus/ubus.sock',
                        'daemon_argv0': '/sbin/ubusd', 'default_acl': True, 'fresh_daemon_per_case': True},
            'policy': policy, 'policy_sha256': sha(policy_path), 'prerequisites': prerequisites,
            'proofs': proofs, 'steps': steps, 'input_sha256': frozen}
    (out / 'plan.json').write_text(json.dumps(plan, indent=2, allow_nan=False) + '\n')
    print(relative(out / 'plan.json'))


if __name__ == '__main__':
    main()
