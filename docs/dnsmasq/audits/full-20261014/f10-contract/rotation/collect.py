#!/usr/bin/env python3
"""Recompute rotation health and strict/relative comparisons from raw evidence."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    inputs = {}

    def read(path):
        inputs[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        return json.loads(path.read_text())

    report = {'product_commit': 'b99eae7e54c1d3922368513714da2eaef09cef58',
              'rust_sha256': 'edf0f62ca08946cd35aa5b48255575546baaec53d3273723fb25550eb14e5fac',
              'c_sha256': '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
              'cases': {}}
    for case in ('warm', 'repeated-original', 'unique'):
        result = read(args.new / f'rotation-b99e-{case}/result.json')
        assert result['rust_sha256'] == report['rust_sha256']
        assert result['c_sha256'] == report['c_sha256']
        sides = []
        for run in result['runs']:
            assert len(run['connections']) == 20 and all(row['ok'] for row in run['connections'])
            assert run['udp_after'] and run['exit_before_cleanup'] is None
            assert not run.get('driver_error') and run['cgroup_removed']
            assert 'oom_kill 0' in run['final_cgroup']['memory.events'].splitlines()
            assert not run['cleanup_cgroup']['cgroup.procs']
            pss = {row['label']: row['stats']['sum']['Pss'] for row in run['samples']}
            sides.append({'side': run['side'], 'healthy': True,
                          'peak_bytes': int(run['final_cgroup']['memory.peak']),
                          'pss_kib': pss,
                          'twenty_clients_extra_pss_kib': pss['new_tcp_20'] - pss['parent_udp_warmed']})
        c, rust = [run['orders'] for run in result['runs']]
        differences = [a['label'] for a, b in zip(c, rust) if a != b]
        assert len(c) == len(rust)
        assert result['orders_matched'] == (not differences)
        report['cases'][case] = {
            'driver_sha256': result['driver_sha256'], 'observations': len(c),
            'raw_differences': differences,
            'relative_orders_matched': result.get('relative_orders_matched'), 'sides': sides}
    old = read(args.old / 'fixed-cgroup64-60k-rolling/result.json')
    baseline = read(args.old / 'old-60k-rolling/result.json')
    report['retained_negative_controls'] = {
        'old_fixed_rust_identical': old['runs'][1]['orders'] == baseline['runs'][1]['orders'],
        'fixed_vs_c_differences': sum(a != b for a, b in zip(old['runs'][0]['orders'], old['runs'][1]['orders'])),
        'old_vs_c_differences': sum(a != b for a, b in zip(baseline['runs'][0]['orders'], baseline['runs'][1]['orders']))}
    new = read(args.new / 'rotation-b99e-unique/result.json')
    report['unique_controls'] = {}
    for case in ('fixed-cgroup64-60k-rolling-unique', 'final-cgroup64-60k-rolling-unique',
                 'relative-cgroup64-60k-rolling-unique-repeat'):
        prior = read(args.old / case / 'result.json')
        row = {}
        for index, side in enumerate(('c', 'rust')):
            a, b = prior['runs'][index]['orders'], new['runs'][index]['orders']
            assert len(a) == len(b) == 6020
            row[side + '_raw_differences'] = [x['label'] for x, y in zip(a, b) if x['wire'] != y['wire']]
        report['unique_controls'][case] = row
    report['inputs_sha256'] = inputs
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
