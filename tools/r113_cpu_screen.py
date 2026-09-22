#!/usr/bin/env python3
"""Run the frozen, exploratory R113 event CPU screen on the physical router."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from r105_user_event_paired_report import verify_window
from r113_memory_runner import REPO, digest, read, verify_files, verify_prerequisites


def verify_inputs(plan):
    for path, expected in plan['files'].items():
        assert digest(REPO / path) == expected, (path, 'changed input')
    memory_plan = read(REPO / plan['memory_plan'])
    verify_files(memory_plan)
    prerequisites = verify_prerequisites(memory_plan)
    memory = REPO / plan['memory_root']
    assert (memory / 'COMPLETE').is_file(), 'memory collection incomplete'
    assert read(memory / 'report.json')['all_windows_cleaned_and_production_stock'] is True
    # A failed memory threshold is reportable evidence, not a collection error.
    assert len(read(memory / 'memory-gate.json')['candidate_64_client_rssanon_growth_kib']) == 2
    prerequisites['memory-report'] = digest(memory / 'report.json')
    prerequisites['memory-gate'] = digest(memory / 'memory-gate.json')
    return prerequisites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, default=REPO / 'docs/reviews/r113-cpu-screen-plan.json')
    parser.add_argument('--out', type=Path, default=REPO / 'private/r113-fd-boundary/cpu-screen')
    args = parser.parse_args()
    path, out = args.plan.resolve(), args.out.resolve()
    plan, plan_sha = read(path), digest(path)
    prerequisites = verify_inputs(plan)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    (out / 'plan.json').write_bytes(path.read_bytes())
    (out / 'prerequisites.json').write_text(json.dumps(prerequisites, indent=2) + '\n')
    series_plans = {}
    for series in plan['series']:
        root = out / series['name']
        root.mkdir()
        spec = {**plan['common'], **series['measurement']}
        series_plans[series['name']] = spec
        (root / 'plan.json').write_text(json.dumps(spec, indent=2) + '\n')
    window = None
    try:
        for item in plan['schedule']:
            assert digest(path) == plan_sha, 'plan changed'
            assert verify_inputs(plan) == prerequisites, 'prerequisites changed'
            spec = series_plans[item['series']]
            block = next(row for row in spec['blocks'] if row['block'] == item['block'])
            window = out / item['series'] / f'{item["block"]:02d}'
            a, b = (plan['artifacts'][spec['subjects'][block['slots'][slot]]] for slot in ('a', 'b'))
            command = [sys.executable, str(REPO / 'tools/r95_device_smoke.py'), 'ubusd',
                       str(REPO / b), str(window), '--pilot', '--iterations', str(spec['iterations']),
                       '--before-candidate', str(REPO / a),
                       '--benchmark', str(REPO / plan['benchmark_path']),
                       '--workload-script', str(REPO / spec['workload_script']),
                       '--guard', str(REPO / plan['guard_path']),
                       '--recovery-gate', str(REPO / plan['recovery_gate_path'])]
            print(f'START {item["series"]}/{window.name}', flush=True)
            with window.with_suffix('.log').open('wb') as log:
                subprocess.run(command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, check=True)
            verify_window(window, spec, block)
            assert verify_inputs(plan) == prerequisites and digest(path) == plan_sha
            print(f'VERIFIED {item["series"]}/{window.name}', flush=True)
        reports = {}
        for name in series_plans:
            root = out / name
            (root / 'COMPLETE').touch()
            subprocess.run([sys.executable, str(REPO / 'tools/r105_user_event_paired_report.py'),
                            str(root), str(root / 'plan.json'), str(root / 'report.json')],
                           cwd=REPO, check=True)
            reports[name] = read(root / 'report.json')
        (out / 'report.json').write_text(json.dumps({
            'plan_sha256': plan_sha, 'series': reports,
            'scope': plan['scope'], 'all_windows_cleaned_and_stock': True,
        }, indent=2) + '\n')
        (out / 'COMPLETE').touch()
        print('COMPLETE: exploratory ratios only; no performance acceptance', flush=True)
    except BaseException as error:
        (out / 'FAILED.json').write_text(json.dumps({
            'window': str(window), 'type': type(error).__name__, 'error': str(error),
        }, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
