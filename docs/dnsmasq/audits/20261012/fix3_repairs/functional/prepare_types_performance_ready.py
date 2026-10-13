#!/usr/bin/env python3
"""Bind fresh types-artifact functional/build completion before performance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and not sys.flags.optimize
    private = args.root / 'private'
    output = private / 'performance-types-ready.json'
    assert not output.exists()
    paths = {'build_result': private / 'build-types-result.json',
             'functional_plan': private / 'functional-types-v2-plan.json',
             'functional_state': private / 'functional-types-v2/state.json',
             'initial_harness_plan': private / 'functional-types-plan.json',
             'initial_harness_failed_state': private / 'functional-types/state.json',
             'previous_functional_state': private / 'functional-continuation/state.json',
             'previous_original_strict_failed_state': private / 'functional/state.json',
             'previous_performance_summary': private / 'performance-paired-01/summary.json',
             'performance_plan': private / 'performance-types-01/plan.json'}
    build, plan, state, performance = (read(paths[name]) for name in
                                     ('build_result', 'functional_plan', 'functional_state', 'performance_plan'))
    assert build['passed'] and state['passed']
    assert len(state['commands']) == 49 and all(row['passed'] and row['returncode'] == 0 for row in state['commands'])
    assert state['plan_sha256'] == sha(paths['functional_plan'])
    assert state['source_commit'] == performance['source_commit'] == 'ceea2ec6eb5eeee8e61e3da1c97aeb38aaf999b3'
    assert len(state['families']) == 14 and sum(row['commands'] for row in state['families'].values()) == 35
    candidate = performance['groups']['fix']
    assert sha(candidate['elf']) == candidate['sha256'] == '0410d96c9c42e0fc3616d499547fe4ba7d7657b236d8d55daa0664a483b8b743'
    assert sha(paths['build_result']) == '136771836bb925bef1bceba2a8102407c181caaa206c9d67a3f882e3d08656f4'
    assert sha(paths['performance_plan']) == '19ceee2f9b9b9dfd976e7031534593175be8d5094196e4871371f1b073937028'
    for record in state['commands']:
        assert sha(record['result']) == record['result_sha256']
    native = state['commands'][0]
    assert native['id'] == 'config-state-probe' and read(native['result'])['cases'] == 19
    assert native['native_adapter_identity']['target'] == 'aarch64-unknown-linux-gnu'
    for value in native['native_probe_identity'].values():
        assert sha(value['path']) == value['sha256']
    assert sha(native['native_adapter_receipt']['path']) == native['native_adapter_receipt']['sha256']
    original = next(row['strict_result'] for row in state['commands'] if row['id'] == 'A10-and-original-DNS')
    assert original['passed'] and original['C_equal_responses'] == 366 and len(original['predeclared_exact_baseline_checks']) == 2
    failed = read(paths['initial_harness_failed_state'])
    assert not failed['passed'] and len(failed['commands']) == 1 and failed['commands'][0]['returncode'] == 1
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from audit_20261011_pie_cost import foreign_workloads
    from build_package import inputs
    assert inputs(Path(plan['source'])) == plan['source_files']
    for path, expected in plan['assets'].items():
        assert sha(path) == expected, path
    invocation = read(private / 'functional-types-v2-invocation.json')
    controller = Path('/proc') / str(invocation['pid']) / 'stat'
    for _ in range(20):
        try:
            done = controller.read_text().rpartition(')')[2].split()[0] == 'Z'
        except FileNotFoundError:
            done = True
        if done:
            break
        time.sleep(.1)
    else:
        raise RuntimeError('functional controller still active')
    busy = foreign_workloads()
    assert not busy, busy
    ready = {'schema': 'dnsmasq-fix3-types-performance-ready-v1', 'functional_complete': True, 'builds_complete': True,
             'source_commit': state['source_commit'], 'candidate_sha256': candidate['sha256'],
             'fresh_functional_commands': 49, 'actual_zero_exit_commands': 49,
             'SDK_daemon_family_commands': 48, 'native_state_probe_commands': 1, 'native_state_cases': 19,
             'known_parser_baseline': original, 'prior_failed_attempts_retained': True,
             'foreign_after': busy, 'created_unix_ns': time.time_ns(),
             'generator': {'path': str(Path(__file__).resolve()), 'sha256': sha(__file__)},
             'references': {name: {'path': str(path), 'sha256': sha(path)} for name, path in paths.items()}}
    ready.update({name + '_sha256': sha(path) for name, path in paths.items()})
    output.write_text(json.dumps(ready, indent=2) + '\n')
    print(json.dumps({'ready': str(output), 'sha256': sha(output), 'foreign_after': []}))


if __name__ == '__main__':
    main()
