#!/usr/bin/env python3
"""Revalidate the fixed v0.3.2 listener evidence without rerunning 161 unchanged cases.

The original failed result stays immutable. Exactly two authorized F23 cases
come from new-1; new-1 through new-4 must all pass and have identical observations.
The complete 163-case inventory, comparator and negative controls run again.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

import m5_listeners as listener


COMMIT = 'a170caa5d74f928186d63e6c4d879688deee3a4c'
ELF = '2a22f6327d81e25c8bf9e891d21842e5ef0d33ec074e5004506388f3b616e2a2'
C_ELF = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
ORIGINAL_RESULT = '33441e136adf88247cad01bcfaeb644a1a016a483958f125fcf613c5ee5b4216'
ORIGINAL_TOOL = 'ff420cd1c61351893b0c9fb730ab2672e5a6c9f126673bdc2e69bf4d72c39709'
NAMES = ['runtime-shared-dns-both-dynamic', 'runtime-shared-all-dynamic']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def collect(original, rounds, out):
    assert __debug__ and not out.exists()
    out.mkdir()
    files = {}
    def record(path):
        assert path.is_file() and not path.is_symlink(), path
        files[str(path)] = sha(path)
    def read(path):
        record(path)
        return json.loads(path.read_text())
    def observed(folder, names):
        pair = [read(folder / side / 'observed.json') for side in ('c', 'rust')]
        assert [item['binary_sha256'] for item in pair] == [C_ELF, ELF]
        assert all(not item['failures'] for item in pair)
        for side in ('c', 'rust'):
            for name in names:
                paths = sorted((folder / side / name).rglob('*'))
                assert paths, (folder, side, name)
                for path in paths:
                    assert not path.is_symlink(), path
                    if path.is_file(): record(path)
        return pair

    assert sha(original / 'result.json') == ORIGINAL_RESULT
    old = read(original / 'result.json')
    parent = read(original.parent / 'result.json')
    assert parent['source_commit'] == COMMIT and parent['elf_sha256'] == ELF
    assert parent['c_sha256'] == C_ELF and parent['passed'] is False
    assert old['cases'] == 163 and old['exits'] == {'c': 0, 'rust': 0} and not old['qualified']
    guards = [('rust', name + ': reference guard ' + case) for name, cases in (
        (NAMES[0], ['shared-after-trigger-udp', 'shared-after-trigger-tcp']),
        (NAMES[1], ['shared-after-release-tcp', 'shared-after-release-tftp'])) for case in cases]
    assert len(old['failures']) == 6
    assert sorted((row['side'], row['error']) for row in old['failures'] if 'error' in row) == sorted(guards)
    assert sorted(row['name'] for row in old['failures'] if 'name' in row) == sorted(NAMES)
    old_tools = read(original / 'tools.json')
    assert old_tools['m5_listeners.py'] == ORIGINAL_TOOL
    current_tools = {name: sha(listener.HERE / name) for name in old_tools}
    assert all(old_tools[name] == current_tools[name] for name in old_tools
               if name not in ('m5_listeners.py', 'm5_listeners.json'))
    old_plan = read(original / 'plan.json')
    plan = read(listener.HERE / 'm5_listeners.json')
    expected_plan = copy.deepcopy(old_plan)
    for name in NAMES:
        expected_plan['required_observations'][name] = plan['required_observations'][name]
    old_requirement = next(row for row in expected_plan['requirements'] if row['id'] == 'partial-dynamic-listener')
    old_requirement['boundary'] = next(row['boundary'] for row in plan['requirements']
                                       if row['id'] == 'partial-dynamic-listener')
    assert expected_plan == plan, 'unrelated fixture/checklist changed'
    cases = listener.scenarios()
    assert len(cases) == 163 and plan['required_cases'] == [item['name'] for item in cases]
    assert plan['required_observations'] == {item['name']: listener.expected_labels(item) for item in cases}
    left, right = observed(original, plan['required_cases'])
    assert all([row['name'] for row in side['rows']] == plan['required_cases'] for side in (left, right))
    unchanged = [item for item in cases if item['name'] not in NAMES]
    original_pair = copy.deepcopy([left, right])
    retained = [dict(side, rows=[row for row in side['rows'] if row['name'] not in NAMES]) for side in (left, right)]
    assert len(unchanged) == 161 and not listener.compare(*retained, unchanged)
    selected = [item for item in cases if item['name'] in NAMES]
    first = None
    new_receipts = []
    for number in range(1, 5):
        folder = rounds / f'new-{number}'
        result = read(folder / 'result.json')
        assert read(folder / 'tools.json') == current_tools
        assert read(folder / 'plan.json') == plan
        pair = observed(folder, NAMES)
        assert all(side['selected'] == NAMES for side in pair)
        assert result['cases'] == 2 and result['exits'] == {'c': 0, 'rust': 0}
        assert result['failures'] == [] and result['qualified'] is False
        assert not listener.compare(*pair, selected)
        controls = listener.negative_controls(*pair, selected)
        assert result['negative_controls'] == controls and controls and all(row['rejected'] for row in controls)
        rows = [side['rows'] for side in pair]
        if number == 1: first = rows
        assert rows == first, 'directed rounds differ; cannot select a preferred round'
        new_receipts.append(dict(round=number, result_sha256=sha(folder / 'result.json')))
    for side, replacements in zip((left, right), first):
        by_name = {row['name']: row for row in replacements}
        side['rows'] = [by_name.get(row['name'], row) for row in side['rows']]
    for before, after in zip(original_pair, (left, right)):
        assert [row for row in before['rows'] if row['name'] not in NAMES] == [row for row in after['rows'] if row['name'] not in NAMES]
    failures = listener.compare(left, right, cases)
    controls = listener.negative_controls(left, right, cases)
    qualified = not failures and bool(controls) and all(row['rejected'] for row in controls)
    assert qualified, (failures, [row for row in controls if not row['rejected']])
    assert all(sha(path) == digest for path, digest in files.items()), 'raw evidence changed during validation'
    listener.save(out / 'raw-files.json', files)
    listener.save(out / 'c-observed.json', left)
    listener.save(out / 'rust-observed.json', right)
    scope = 'cross-attempt revalidation: original 161 unchanged cases plus fixed new-1 F23 cases; new-1..4 all pass identically'
    result = dict(qualified=qualified, cases=163, observations=sum(len(row['rows']) for row in right['rows']),
        binary_sha256=ELF, bytes=old['bytes'], failures=failures, negative_controls=controls,
        reference_differences=listener.reference_differences(left, right, cases), scope=scope,
        original_failed_result=dict(path=str(original / 'result.json'), sha256=ORIGINAL_RESULT, unchanged=True),
        original_tools=old_tools, current_tools=current_tools, new_rounds=new_receipts,
        reused_cases=161, replaced_cases=NAMES, selected_round=1, raw_files_sha256=sha(out / 'raw-files.json'),
        collector_sha256=sha(__file__))
    listener.save(out / 'result.json', result)
    family = dict(source_commit=COMMIT, elf_sha256=ELF, c_sha256=C_ELF,
        canonical_family_plan_sha256=parent['canonical_family_plan_sha256'], selected_families=['m5_listeners'],
        complete_44_families=False, passed=qualified, scope=scope,
        families={'m5_listeners': dict(completed=1, expected=1, passed=qualified)},
        commands=[dict(id='m5_listeners-paired', family='m5_listeners', argv=list(sys.orig_argv),
            passed=qualified, returncode=0, checks={'qualified': True}, result=str(out / 'result.json'),
            result_sha256=sha(out / 'result.json'))])
    listener.save(out / 'family-result.json', family)
    print(json.dumps(dict(qualified=qualified, cases=163, negative_controls=len(controls),
        result_sha256=sha(out / 'result.json'), family_result_sha256=sha(out / 'family-result.json'))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'rounds', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    collect(*(getattr(args, name).resolve() for name in ('original', 'rounds', 'out')))
