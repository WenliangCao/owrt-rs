#!/usr/bin/env python3
"""Recompute repeated-address findings from preserved exact-image observations."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reverse_model(names, unique):
    """Model only cache.c's temporary reverse chain, not DNS answer ordering.

    cache_reload uses (1232 + MAXDNAME + RRFIXEDSZ) / sizeof(crec*) = 187
    buckets. add_hosts_entry first calls cache_find_by_name for duplicate
    detection. That lookup repurposes each matching entry's next link for its
    answer chain, whose tail is cache_head. Here None represents cache_head's
    free records: none has an IPv4 flag and none can match a hosts address.
    The subsequent reverse-owner lookup traverses the same next links.
    """
    buckets = [None] * 187
    by_name = {}
    entries = []

    def insert(name, address):
        prior = by_name.get(name, [])
        for offset, entry in enumerate(prior):
            entries[entry][2] = prior[offset + 1] if offset + 1 < len(prior) else None
        bucket = 0
        for byte in map(int, address.split('.')):
            bucket = (2 * bucket + byte) % len(buckets)
        lookup = buckets[bucket]
        while lookup is not None and entries[lookup][1] != address:
            lookup = entries[lookup][2]
        reverse = lookup is None
        entry = len(entries)
        entries.append([name, address, buckets[bucket] if reverse else None, reverse])
        if reverse:
            buckets[bucket] = entry
        by_name.setdefault(name, []).append(entry)

    insert('ready.test', '192.0.2.41')
    for i in range(names):
        for j in (0, 1):
            address = (f'10.{j + 1}.{i // 256}.{i % 256}' if unique
                       else f'192.0.{j + 2}.{i % 250 + 1}')
            insert(f'host{i:06d}.test', address)
    return {(name, address): reverse for name, address, _, reverse in entries
            if name.startswith('host')}


def cache_flags(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.search(r'(host\d{6}\.test)\s+([\d.]+)\s+(4F[ R]I)', line)
        if match:
            key = match[1], match[2]
            assert key not in result, f'duplicate cache dump row: {key}'
            result[key] = match[3] == '4FRI'
    return result


def classify(rows):
    orders = [row['addresses'] for row in rows]
    if all(order == orders[0] for order in orders):
        return 'constant'
    if all(order == orders[0][::1 if i % 2 == 0 else -1]
           for i, order in enumerate(orders)):
        return 'alternating'
    return 'other'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rotation-evidence', type=Path, required=True)
    parser.add_argument('--followup-evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    inputs = {}

    def read(path):
        inputs[str(path)] = sha(path)
        return json.loads(path.read_text())

    fixed = read(args.rotation_evidence / 'fixed-cgroup64-60k-rolling/result.json')
    old = read(args.rotation_evidence / 'old-60k-rolling/result.json')
    fixed_orders = [run['orders'] for run in fixed['runs']]
    old_orders = [run['orders'] for run in old['runs']]
    assert all(len(rows) == 6020 for rows in fixed_orders + old_orders)
    assert fixed_orders[1] == old_orders[1]
    differences = [c for c, rust in zip(*fixed_orders) if c != rust]
    report = {
        'scope': 'Exact-image diagnostic evidence; no product or router changes',
        'original_rolling': {
            'observations_per_side': 6020,
            'old_fixed_rust_identical': True,
            'fixed_vs_c_differences': len(differences),
            'old_vs_c_differences': sum(c != rust for c, rust in zip(*old_orders)),
            'c_vs_c_differing_labels': [a['label'] for a, b in zip(fixed_orders[0], old_orders[0])
                                       if a != b],
            'fixed_difference_groups': dict(Counter(row['label'].rsplit('-', 1)[0]
                                                    for row in differences)),
        }, 'diagnostics': {},
    }
    for case in ('repeated', 'repeated-dump', 'unique-dump'):
        result = read(args.followup_evidence / case / 'result.json')
        runs = result['runs']
        assert len(runs) == 4
        assert all(run['exit_before_cleanup'] is None and run['udp_after'] for run in runs)
        assert runs[1]['warmup'] == runs[2]['warmup']
        assert runs[1]['probes'] == runs[2]['probes']
        assert runs[0]['binary_sha256'] == runs[3]['binary_sha256'] == fixed['c_sha256']
        assert runs[1]['binary_sha256'] == old['rust_sha256']
        assert runs[2]['binary_sha256'] == fixed['rust_sha256']
        summary = {
            'driver_sha256': result['driver_sha256'],
            'names': result['names'], 'unique_addresses': result['unique_addresses'],
            'old_fixed_rust_warmup_and_probes_identical': True,
            'runs': [],
        }
        predicted = reverse_model(result['names'], result['unique_addresses'])
        for run in runs:
            row = {'label': run['label'], 'binary_sha256': run['binary_sha256'],
                   'probes': {name: classify(values) for name, values in run['probes'].items()}}
            if 'cache_dump' in run:
                path = args.followup_evidence / case / run['label'] / 'daemon.log'
                inputs[str(path)] = sha(path)
                assert inputs[str(path)] == run['daemon_log_sha256']
                observed = cache_flags(path)
                assert observed == predicted, 'source model does not match exact C flags'
                grouped = {}
                for (name, _), reverse in observed.items():
                    grouped.setdefault(name, set()).add(reverse)
                mixed = {name for name, flags in grouped.items() if len(flags) > 1}
                row['reverse_model_matched_records'] = len(observed)
                row['mixed_reverse_names'] = len(mixed)
                row['probe_reverse_flags'] = {name: {
                    address: reverse for (owner, address), reverse in observed.items()
                    if owner == name} for name in run['probes']}
                if case == 'repeated-dump':
                    explained = sum(f'host{int(d["label"].rsplit("-", 1)[1]):06d}.test' in mixed
                                    for d in differences)
                    row['original_differences_on_mixed_reverse_names'] = explained
                    assert explained == len(differences) == 188
            summary['runs'].append(row)
        report['diagnostics'][case] = summary
    report['inputs_sha256'] = inputs
    report['analyzer_sha256'] = sha(Path(__file__))
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'fixed_differences': len(differences), 'all_explained_by_mixed_reverse': True,
                      'output': str(args.output)}))


if __name__ == '__main__':
    main()
