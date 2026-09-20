#!/usr/bin/env python3
"""Verify the frozen physical registry-heap diagnostic; no RSS/PSS verdict."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    plan = json.loads(a.plan.read_text())
    assert (a.root / 'MEMORY_COMPLETE').exists()
    fields = plan.get('dimensions', ['objects', 'path_bytes'])
    expected = ({tuple(row) for row in plan['scenarios']} if 'scenarios' in plan
                else {(n, size) for n in plan['objects'] for size in plan['path_bytes']})
    runs, boots, gates = [], set(), set()
    for index, side in enumerate(plan['order'], 1):
        root = a.root / f'memory-{index}-{side}'
        result = json.loads((root / 'result.json').read_text())
        assert result['exit'] == 0 and result['pilot_only'] and not result['installed']
        assert result['production_mode'] == 'stock' and result['implementation'] == 'rs'
        assert result['iterations'] == plan['iterations'] and not result['matrix']
        for key in ('passed', 'cleanup_verified', 'same_boot', 'same_config',
                    'same_production_identity', 'same_host_mounts'):
            assert result[key], (root, key)
        assert result['candidate_sha256'] == plan['subjects'][side]
        assert result['driver_sha256'] == plan['driver_sha256']
        assert result['workload_sha256'] == plan['workload_sha256']
        before = json.loads((root / 'health-before.json').read_text())
        after = json.loads((root / 'health-after.json').read_text())
        assert before['boot_id'] == after['boot_id']
        boots.add(before['boot_id'])
        gates.add((result['guard_sha256'], result['recovery_gate_sha256']))
        assert (root / 'raw/COMPLETE').exists()
        assert (root / 'raw/binary-sha256.txt').read_text().split()[0] == plan['subjects'][side]
        with (root / 'raw' / plan.get('csv', 'registry.csv')).open() as stream:
            rows = [{key: int(value) for key, value in row.items()} for row in csv.DictReader(stream)]
        assert len(rows) == len(expected)
        assert {tuple(r[key] for key in fields) for r in rows} == expected
        assert all(r['construction_peak_requested_bytes'] >= r['retained_requested_bytes'] > 0 for r in rows)
        runs.append({'index': index, 'side': side, 'rows': rows,
                     'result_sha256': digest(root / 'result.json'),
                     'raw_sha256': digest(root / 'raw.tar.gz')})
    assert len(boots) == len(gates) == 1
    repeat_agreement = all([r['rows'] for r in runs if r['side'] == side][0]
                           == [r['rows'] for r in runs if r['side'] == side][1]
                           for side in plan['subjects'])
    a.output.write_text(json.dumps({'plan_sha256': digest(a.plan), 'plan': plan,
                                   'all_windows_cleaned_and_production_stock': True,
                                   'repeat_exact_agreement': repeat_agreement,
                                   'superiority_verdict': None,
                                   'scope': plan.get('scope', 'Requested Rust heap of actual Registry only; excludes allocator rounding, libc internals, clients, stack, code and kernel'),
                                   'runs': runs}, indent=2) + '\n')


if __name__ == '__main__':
    main()
