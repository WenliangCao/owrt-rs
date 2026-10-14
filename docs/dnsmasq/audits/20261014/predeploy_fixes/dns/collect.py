#!/usr/bin/env python3
"""Publish synthetic DNS observations and hashes, never private packets/config."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.tools))
    from predeploy_audit_dns import compare
    from dns_service_probe import semantics
    args.out.mkdir(parents=True, exist_ok=False)
    private = args.root / 'private'
    pairs = {
        'minimal-before': ('c-minimal-before-02', 'rust-minimal-before-02'),
        'minimal-after': ('c-minimal-sdk02', 'rust-minimal-sdk02'),
        'dotless-before': ('c-dotless-final-01', 'rust-dotless-original-02'),
        'dotless-after': ('c-dotless-sdk02', 'rust-dotless-sdk02'),
    }
    summary = {'collector_sha256': sha(Path(__file__)), 'comparisons': {}, 'sources': {}}
    observations = {}
    def source(label):
        path = private / label / 'result.json'
        value = json.loads(path.read_text())
        summary['sources'][label] = {'result_sha256': sha(path),
            'binary_sha256': value['binary_sha256'], 'tool_sha256': value['tool_sha256']}
        return value
    for label, (reference, candidate) in pairs.items():
        compare(SimpleNamespace(reference=private / reference / 'result.json',
                                candidate=private / candidate / 'result.json', out=args.out / label))
        comparison = json.loads((args.out / label / 'comparison.json').read_text())
        summary['comparisons'][label] = {**comparison['totals'],
            'upstream_requests': {side: comparison['upstream'][side]['requests'] for side in ('c', 'rust')},
            'process_exits': comparison['process_exits'], 'harness_errors': comparison['harness_errors']}
        observations[label] = {}
        for side, run in [('c', reference), ('rust', candidate)]:
            observations[label][side] = [{
                'label': case['label'], 'daemon_alive': case['daemon_alive'],
                'clients': [{k: v for k, v in row.items() if k != 'elapsed'} for row in case['clients']],
            } for case in source(run)['cases']]
    save(args.out / 'observations.json', observations)
    boundaries = {}
    for label, reference, candidate in [
        ('final', 'c-rule-boundary-sdk02', 'rust-rule-boundary-sdk02'),
        ('original-direct-control', 'c-rule-direct-control', 'rust-rule-direct-original'),
    ]:
        c, rust = source(reference), source(candidate)
        rows = []
        for first, second in zip(c['cases'], rust['cases']):
            count = first['literal_count']
            paths = [private / side / str(count) / 'answer.reply' for side in (reference, candidate)]
            a, b = [semantics(path.read_bytes()) for path in paths]
            unordered = lambda value: {**value, 'records': sorted(value['records'], key=lambda rr: json.dumps(rr, sort_keys=True))}
            rows.append({'literal_count': count, 'c': first, 'rust': second,
                'raw_bytes_equal': paths[0].read_bytes() == paths[1].read_bytes(),
                'ordered_semantics_equal': a == b,
                'all_fields_except_rr_order_equal': unordered(a) == unordered(b),
                'c_first_three_addresses': [rr['data'] for rr in a['records'][:3]],
                'rust_first_three_addresses': [rr['data'] for rr in b['records'][:3]],
            })
        boundaries[label] = rows
    boundaries['sdk01_negative_control'] = source('rust-rule-boundary-intermediate-01')['cases']
    summary['literal_boundary'] = {label: [
        {key: row[key] for key in ('literal_count', 'raw_bytes_equal', 'ordered_semantics_equal', 'all_fields_except_rr_order_equal')}
        for row in rows] for label, rows in boundaries.items() if label != 'sdk01_negative_control'}
    summary['literal_boundary']['ordering_scope'] = 'Pre-existing same-domain literal RR ordering difference, independently reproduced by querying the owner directly in the original audited Rust ELF; not ignored for ordered equality.'
    summary['literal_boundary']['sdk01_overflow_control'] = boundaries['sdk01_negative_control'][1]
    save(args.out / 'literal-boundary.json', boundaries)
    save(args.out / 'summary.json', summary)
    assert summary['comparisons']['minimal-after']['client_semantic_mismatches'] == 0
    assert summary['comparisons']['dotless-after']['client_semantic_mismatches'] == 0
    assert boundaries['final'][1]['raw_bytes_equal']
    assert all(row['all_fields_except_rr_order_equal'] for row in boundaries['final'])
    assert not boundaries['original-direct-control'][0]['ordered_semantics_equal']


if __name__ == '__main__':
    main()
