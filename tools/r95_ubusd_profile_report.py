#!/usr/bin/env python3
"""Verify and summarize the frozen physical dispatch diagnostics, not full-daemon performance."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('plan', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--backpressure', action='store_true')
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    prefix = 'backpressure' if args.backpressure else 'profile'
    marker = 'BACKPRESSURE_COMPLETE' if args.backpressure else 'PROFILE_COMPLETE'
    assert (args.root / marker).exists()
    expected = ({f'backpressure_{mode}_{n}' for mode in ('all', 'prefix') for n in (16, 64, 256)}
                if args.backpressure else {f'lookup_{mode}_objects_{n}_methods_{m}'
                                          for mode in ('exact', 'all', 'prefix')
                                          for n, m in ((1, 1), (64, 1), (128, 1), (1, 64))})
    runs, boots, gates = [], set(), set()
    for index, side in enumerate(plan['order'], 1):
        root = args.root / f'{prefix}-{index}-{side}'
        result = json.loads((root / 'result.json').read_text())
        for key in ('passed', 'cleanup_verified', 'same_boot', 'same_config',
                    'same_production_identity', 'same_host_mounts'):
            assert result[key], (root, key)
        assert result['exit'] == 0 and result['pilot_only'] and not result['installed']
        assert result['production_mode'] == 'stock' and result['implementation'] == 'rs'
        assert not result['matrix'] and result['iterations'] == plan['iterations']
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
        rows = []
        with (root / 'raw/profile.csv').open() as stream:
            for row in csv.DictReader(stream):
                assert int(row['iterations']) == plan['iterations']
                value = {'stage': row['stage'], 'ns_per_op': float(row['ns_per_op'])}
                assert math.isfinite(value['ns_per_op']) and value['ns_per_op'] > 0
                for metric in ('allocations', 'reallocations', 'allocated_bytes'):
                    value[metric] = int(row[metric])
                    assert value[metric] >= 0
                rows.append(value)
        assert len(rows) == len(expected) and {r['stage'] for r in rows} == expected
        runs.append({'index': index, 'side': side, 'metrics': rows,
                     'result_sha256': digest(root / 'result.json'),
                     'raw_sha256': digest(root / 'raw.tar.gz')})
    assert len(boots) == len(gates) == 1
    summary = {}
    for stage in sorted(expected):
        sides = {}
        for side in plan['subjects']:
            rows = [m for r in runs if r['side'] == side for m in r['metrics'] if m['stage'] == stage]
            assert len(rows) == 2
            sides[side] = {key: statistics.median(r[key] for r in rows)
                           for key in ('ns_per_op', 'allocations', 'reallocations', 'allocated_bytes')}
        summary[stage] = {'sides': sides, 'ratio_of_side_medians_ns_delta_pct':
                         100 * (sides['candidate']['ns_per_op'] / sides['before']['ns_per_op'] - 1)}
    args.output.write_text(json.dumps({'plan_sha256': digest(args.plan), 'plan': plan,
                                      'scope': 'Instrumented Rust dispatch/socket-pair fixture; no C comparison, no daemon event loop',
                                      'memory_scope': 'Requested bytes summed across allocation/reallocation calls, not peak/live heap or RSS',
                                      'all_windows_cleaned_and_production_stock': True,
                                      'superiority_verdict': None, 'runs': runs, 'summary': summary}, indent=2) + '\n')


if __name__ == '__main__':
    main()
