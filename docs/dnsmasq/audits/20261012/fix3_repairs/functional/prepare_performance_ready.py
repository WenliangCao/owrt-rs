#!/usr/bin/env python3
"""Read-only handoff after functional assertions/builds and process cleanup."""
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
    root = args.root
    private = root / 'private'
    output = private / 'performance-ready.json'
    assert not output.exists()
    paths = {'build_result': private / 'build-result.json',
             'original_functional_plan': private / 'functional-plan.json',
             'original_functional_state': private / 'functional/state.json',
             'continuation_plan': private / 'functional-continuation-plan.json',
             'functional_state': private / 'functional-continuation/state.json',
             'supplemental_plan': private / 'functional-supplement-plan.json',
             'performance_plan': private / 'performance-paired-01/plan.json'}
    values = {name: read(path) for name, path in paths.items()}
    build, original, state, continuation, performance = (values[name] for name in
        ('build_result', 'original_functional_state', 'functional_state', 'continuation_plan', 'performance_plan'))
    assert build['passed'] and state['passed'] and state['total_dispositions'] == 47
    assert state['executed_zero_exit_commands'] == 46 and state['original_strict_script_nonzero_exit'] == 1
    assert len(state['commands']) == 38 and all(row['passed'] and row['returncode'] == 0 for row in state['commands'])
    assert len(state['reused_commands']) == 8 and all(row['passed'] and row['returncode'] == 0 for row in state['reused_commands'])
    assert not original['passed'] and original['commands'][8]['returncode'] == 1
    assert state['strict_script_assessment']['accepted'] and state['strict_script_assessment']['other_responses_equal'] == 366
    assert state['plan_sha256'] == sha(paths['continuation_plan'])
    assert continuation['primary_state_sha256'] == sha(paths['original_functional_state'])
    assert continuation['primary_plan_sha256'] == sha(paths['original_functional_plan'])
    assert continuation['supplement_plan_sha256'] == sha(paths['supplemental_plan'])
    assert state['source_commit'] == performance['source_commit'] == '0ff33bb025bd789aac78e3f6878456449fbde7fc'
    candidate = performance['groups']['fix']
    assert sha(candidate['elf']) == candidate['sha256'] == '05f35c832c7d405aebdc8ef94ac8f479f81bfcdc6f1f066625ab94a5c0c0303a'
    assert sha(paths['build_result']) == '59dcb4760c695c05c37cc421de12824bd3a58acecb7fbdaea0be5839093041d8'
    for record in state['commands'] + state['reused_commands']:
        assert sha(record['result']) == record['result_sha256']
    assessment = state['strict_script_assessment']
    assert sha(assessment['result']) == assessment['result_sha256']
    sys.path.insert(0, str(root / 'source/tools/dnsmasq'))
    from audit_20261011_pie_cost import foreign_workloads
    from build_package import inputs
    assert inputs(root / 'source') == continuation['source_files']
    for path, expected in continuation['assets'].items():
        assert sha(path) == expected, path
    # The state is written just before the controller exits; wait only for that
    # already finished controller, without rerunning or changing any workload.
    invocation = read(private / 'functional-continuation-invocation.json')
    controller = Path('/proc') / str(invocation['pid']) / 'stat'
    for _ in range(20):
        if not controller.exists() or controller.read_text().rpartition(')')[2].split()[0] == 'Z':
            break
        time.sleep(.1)
    else:
        raise RuntimeError('functional controller still active')
    busy = foreign_workloads()
    assert not busy, busy
    ready = {'schema': 'dnsmasq-fix3-performance-ready-v1', 'functional_complete': True, 'builds_complete': True,
             'source_commit': state['source_commit'], 'candidate_sha256': candidate['sha256'],
             'functional_total_dispositions': 47, 'actual_zero_exit_commands': 46,
             'original_strict_exit_1_retained': True, 'strict_script_assessment': assessment,
             'foreign_after': busy, 'created_unix_ns': time.time_ns(),
             'generator': {'path': str(Path(__file__).resolve()), 'sha256': sha(__file__)},
             'references': {name: {'path': str(path), 'sha256': sha(path)} for name, path in paths.items()}}
    ready.update({name + '_sha256': sha(path) for name, path in paths.items()})
    output.write_text(json.dumps(ready, indent=2) + '\n')
    print(json.dumps({'ready': str(output), 'sha256': sha(output), 'foreign_after': []}))


if __name__ == '__main__':
    main()
