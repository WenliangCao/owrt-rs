#!/usr/bin/env python3
"""Validate one frozen candidate's three rotation cases and bound query-order gate."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    inputs = {}

    def read(path):
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        result = json.loads(path.read_text())
        assert result['rust_sha256'] == args.rust_sha256
        assert result['c_sha256'] == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
        return result

    report = {'product_commit': args.commit, 'rust_sha256': args.rust_sha256,
              'cases': {}, 'query_order': []}
    for case in ('warm', 'repeated-original', 'unique'):
        result = read(args.evidence / f'rotation-{args.label}-{case}/result.json')
        c, rust = [run['orders'] for run in result['runs']]
        expected = 20 if case == 'warm' else 6020
        assert len(c) == len(rust) == expected
        differences = [a['label'] for a, b in zip(c, rust) if a != b]
        assert result['orders_matched'] == (not differences)
        row = {'driver_sha256': result['driver_sha256'], 'observations': expected,
               'raw_differences': differences, 'relative_orders_matched': result.get('relative_orders_matched'),
               'sides': []}
        for run in result['runs']:
            assert len(run['connections']) == 20 and all(connection['ok'] for connection in run['connections'])
            assert run['udp_after'] and run['exit_before_cleanup'] is None
            assert not run.get('driver_error') and run['cgroup_removed']
            assert 'oom_kill 0' in run['final_cgroup']['memory.events'].splitlines()
            assert not run['cleanup_cgroup']['cgroup.procs']
            pss = {sample['label']: sample['stats']['sum']['Pss'] for sample in run['samples']}
            row['sides'].append({'side': run['side'], 'healthy': True,
                'peak_bytes': int(run['final_cgroup']['memory.peak']), 'pss_kib': pss})
        report['cases'][case] = row
    result = read(args.evidence / f'ptr-collision-{args.label}/result.json')
    for run in result['runs']:
        minimal = run['minimal']
        name = minimal['selected']
        decoded = {phase: [row['data'] for row in minimal[phase]['records']]
                   for phase in ('before', 'forward', 'after')}
        assert decoded == {'before': [name, 'x.test'],
                           'forward': ['192.0.4.1', '192.0.2.1'], 'after': ['x.test', name]}
        assert all(not minimal[phase]['flags'] & 0x20f for phase in decoded)
        assert minimal['order_changed']
        assert len(next(iter(run['before'].values()))['records']) == 201
        report['query_order'].append({'side': run['side'], 'fixture': minimal['fixture'],
            'selected': name, 'sequence': decoded,
            'raw_minimal': {phase: minimal[phase] for phase in decoded}, 'identity': run['identity']})
    report['inputs_sha256'] = inputs
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
