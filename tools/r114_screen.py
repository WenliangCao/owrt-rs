#!/usr/bin/env python3
"""Collect the fixed R114 memory/CPU ablation, one physical window at a time."""
import json
from pathlib import Path
import subprocess
import sys

from r105_user_event_paired_report import verify_window as verify_cpu
from r113_memory_runner import REPO, HEALTH, digest, read, verify_window as verify_memory


def verify_inputs(plan):
    for path, expected in plan['files'].items():
        assert digest(REPO / path) == expected, (path, 'changed input')
    for relative in plan['physical_preflights']:
        result = read(REPO / relative / 'result.json')
        assert all(result.get(key) is True for key in HEALTH)
        assert result['candidate_sha256'] == plan['candidate_sha256']
        assert result['exit'] == 0 and result['correctness_smoke_only'] and not result['installed']
    gates = read(REPO / plan['oracle_gates'])
    assert gates['passed'] is True and gates['finished']
    assert {r['name'] for r in gates['results']} == set(plan['required_gates'])
    assert len(gates['results']) == len(plan['required_gates']) == 6
    assert all(r['required'] is True and r['exit'] == 0 for r in gates['results'])
    assert gates['binary_sha256']['ubusd-rs'] == plan['candidate_sha256']
    gate = read(REPO / plan['recovery_gate_path'])
    assert gate['offline_backup_verified'] and gate['configuration_matches_backup']
    assert gate['boot_id'] == plan['boot_id']


def main():
    path = REPO / 'docs/reviews/r114-screen-plan.json'
    plan, plan_sha = read(path), digest(path)
    verify_inputs(plan)
    out = REPO / plan['output']
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    (out / 'plan.json').write_bytes(path.read_bytes())
    for name, spec in plan['measurements'].items():
        (out / name).mkdir()
        (out / name / 'plan.json').write_text(json.dumps(spec, indent=2) + '\n')
    window = None
    try:
        for step in plan['schedule']:
            verify_inputs(plan)
            assert digest(path) == plan_sha
            name = step['measurement']
            spec = plan['measurements'][name]
            if name == 'memory':
                window = out / name / f'{step["block"]:02d}-{step["side"]}'
                candidate = plan['artifacts'][spec['subjects'][step['side']]]
                extra = []
            else:
                block = next(b for b in spec['blocks'] if b['block'] == step['block'])
                window = out / name / f'{step["block"]:02d}'
                candidate = plan['artifacts'][spec['subjects'][block['slots']['b']]]
                control = plan['artifacts'][spec['subjects'][block['slots']['a']]]
                extra = ['--before-candidate', str(REPO / control)]
            command = [sys.executable, str(REPO / 'tools/r95_device_smoke.py'), 'ubusd',
                       str(REPO / candidate), str(window), '--pilot',
                       '--iterations', str(spec['iterations']),
                       '--benchmark', str(REPO / spec['benchmark_path']),
                       '--workload-script', str(REPO / spec['workload_script']),
                       '--guard', str(REPO / plan['guard_path']),
                       '--recovery-gate', str(REPO / plan['recovery_gate_path']), *extra]
            print(f'START {name}/{window.name}', flush=True)
            with window.with_suffix('.log').open('wb') as log:
                subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, check=True)
            if name == 'memory':
                verify_memory(window, spec, step['side'])
            else:
                verify_cpu(window, spec, block)
            verify_inputs(plan)
            assert digest(path) == plan_sha
            print(f'VERIFIED {name}/{window.name}', flush=True)
        reports = {}
        for name, spec in plan['measurements'].items():
            root = out / name
            (root / 'COMPLETE').touch()
            reporter = ('tools/r105_rx_spare_report.py' if name == 'memory'
                        else 'tools/r105_user_event_paired_report.py')
            prefix = ['memory'] if name == 'memory' else []
            subprocess.run([sys.executable, str(REPO / reporter), *prefix,
                            str(root), str(root / 'plan.json'), str(root / 'report.json')],
                           cwd=REPO, check=True)
            reports[name] = read(root / 'report.json')
        growth = [r['rssanon_growth_kb'] for r in reports['memory']['runs']
                  if r['side'] == 'candidate' and r['workload'] == 64]
        assert len(growth) == 2
        (out / 'report.json').write_text(json.dumps({
            'plan_sha256': plan_sha, 'reports': reports,
            'memory_gate_passed': all(x <= 38.4 for x in growth),
            'candidate_64_client_growth_kib': growth,
            'performance_acceptance': None, 'all_windows_cleaned_and_stock': True,
            'limits': plan['scope'],
        }, indent=2) + '\n')
        (out / 'COMPLETE').touch()
        print('COMPLETE: retain all exploratory ratios; no performance acceptance', flush=True)
    except BaseException as error:
        (out / 'FAILED.json').write_text(json.dumps({
            'window': str(window), 'type': type(error).__name__, 'error': str(error),
        }, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
