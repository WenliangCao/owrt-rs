#!/usr/bin/env python3
"""Freeze two opposite-order registration diagnostic windows, without running."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
C = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
CANDIDATE = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'
CALLER = '4930759767aeadb8f5c3267a1346a2d76e75862cd8575da59881a81081c68d0f'
NAMESPACE = 'fd9f853b341168ffad52e891913d3ba6a414ce0b9272a74a3f624952fcbb14c2'


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', default='private/r137-phase/router-plan-01')
    parser.add_argument('--results', default='private/r137-phase/router-01')
    args = parser.parse_args()
    out, dest = [(ROOT / value).resolve() for value in (args.out, args.results)]
    assert out.is_relative_to(ROOT) and dest.is_relative_to(ROOT)
    assert not out.exists() and not dest.exists() and out != dest
    assert out not in dest.parents and dest not in out.parents
    results = str(dest.relative_to(ROOT))
    subjects = {'c': {'path': 'private/r95/ubusd-pilot/stock', 'sha256': C},
                'candidate': {'path': 'private/r136/build-01/combined/ubusd-rs', 'sha256': CANDIDATE}}
    caller = {'path': 'private/r137-phase/owrt-register-phase', 'sha256': CALLER}
    for item in [*subjects.values(), caller]:
        assert sha(item['path']) == item['sha256']
    driver, guard = 'tools/r95_device_smoke.py', 'private/r95/guard'
    recovery = 'private/r96/recovery-full/recovery-gate.json'
    prerequisites = [f'private/r136/router-correctness-01/{kind}/result.json' for kind in ('events', 'fd')]
    inputs = {path: sha(path) for path in [driver, guard, recovery, caller['path'],
        *[v['path'] for v in subjects.values()], *prerequisites, 'tools/r84_device_probe.py',
        'tools/r134/ubusd_router_finish.py', 'tools/benchmark/isolated.sh',
        'tools/r137/make_phase_plan.py', 'tools/r137/registration_phase.sh.in',
        'docs/reviews/R137_REGISTRATION_PHASE_PLAN.md']}
    template = (ROOT / 'tools/r137/registration_phase.sh.in').read_text()
    orders = [{'sides': ['c', 'candidate'], 'modes': ['cycle-wall', 'phase-wall', 'phase-cpu'], 'methods': [1, 16]},
              {'sides': ['candidate', 'c'], 'modes': ['phase-cpu', 'phase-wall', 'cycle-wall'], 'methods': [16, 1]}]
    out.mkdir(parents=True)
    steps = []
    for index, order in enumerate(orders):
        text = template
        for key, value in {'C_SHA': C, 'CANDIDATE_SHA': CANDIDATE, 'CALLER_SHA': CALLER, 'NAMESPACE_SHA': NAMESPACE,
                           'SIDE_ORDER': ' '.join(order['sides']), 'MODE_ORDER': ' '.join(order['modes']),
                           'METHOD_ORDER': ' '.join(map(str, order['methods']))}.items():
            text = text.replace('@' + key + '@', value)
        assert not re.search(r'@[A-Z_]+@', text)
        subprocess.run(['/bin/sh', '-n'], input=text, text=True, check=True)
        script = out / f'window-{index}.sh'
        script.write_text(text)
        workload = str(script.relative_to(ROOT))
        inputs[workload] = sha(workload)
        target = f'{results}/window-{index}'
        steps.append({'name': f'window-{index}', 'argv': [driver, 'ubusd', subjects['candidate']['path'], target,
            '--guard', guard, '--recovery-gate', recovery, '--benchmark', caller['path'],
            '--workload-script', workload, '--iterations', '2000', '--pilot'], 'driver_result': target + '/result.json'})
    plan = {'schema_version': 1, 'scope': 'R137 phase diagnostic and observer perturbation; not formal acceptance',
            'output': results, 'candidate_sha256': CANDIDATE, 'subjects': subjects, 'caller': caller,
            'namespace_sha256': NAMESPACE, 'orders': orders, 'iterations': 2000, 'warmup': 200, 'probe_count': 256,
            'affinity': {'daemon': [1], 'caller': [0, 1]}, 'prerequisites': prerequisites,
            'steps': steps, 'input_sha256': inputs,
            'rules': {'repeat_or_exclude': False, 'performance_acceptance': False,
                'observer_calibration': 'Compare phase-wall/cycle-wall and phase-cpu/phase-wall separately by side and method count.',
                'tail': 'Within each case report phase and CPU co-occurrence in its own cycle p95 tail and remaining samples.',
                'limits': 'CPU spans include instrumentation and may overlap across cores; never subtract both CPU values from wall or claim scheduler wait.',
                'daemon': 'Exact C and R136 binaries unchanged. No tracing, sysctl or affinity changes to production.'}}
    (out / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print(str((out / 'plan.json').relative_to(ROOT)))


if __name__ == '__main__':
    main()
