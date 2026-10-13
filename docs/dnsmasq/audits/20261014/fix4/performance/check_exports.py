#!/usr/bin/env python3
"""Independent consistency/wire check of the final SDK seven-profile export.

The runner rehashes private raw files. This separately checks retained direct
wire proofs, accounting, balanced triples, numerical reductions and source IDs.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import struct


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(directory):
    files = {name: directory / (name + '.json')
             for name in ('plan', 'run', 'summary', 'counter-check', 'local-source-check')}
    data = {name: json.loads(path.read_text()) for name, path in files.items()}
    plan, run, summary, checks = (data[name] for name in ('plan', 'run', 'summary', 'counter-check'))
    assert summary['plan_sha256'] == data['local-source-check']['plan_sha256'] == sha(files['plan'])
    assert all(row['passed'] and not row['mismatches'] for row in data['local-source-check']['checks'].values())
    assert summary['complete'] and not summary['errors'] and run['status'] == 'complete'
    assert summary['groups'] == plan['groups']
    ids = [w['id'] for w in plan['windows']]
    assert len(ids) == len(set(ids)) == 63
    assert all([w['id'] for w in dataset['windows']] == ids for dataset in (run, summary, checks))
    assert all(w['returncode'] == 0 for w in run['windows'])
    assert all(a['ended'] <= b['started'] for a, b in zip(run['windows'], run['windows'][1:]))
    totals, direct_packets = Counter(), 0
    for planned, observed, validated in zip(plan['windows'], summary['windows'], checks['windows']):
        assert validated['actual_elf_sha256'] == plan['groups'][planned['variant']]['sha256']
        for key in ('profile', 'round', 'variant', 'declarations', 'rrtype'):
            assert planned[key] == observed[key]
        assert validated['validated_cache_names'] == 4096 and validated['upstream_disabled_requests'] == 0
        load = observed['load_counters']
        assert not load['interrupted'] and not load['output_failed']
        assert (load['warmup_seconds'], load['measurement_seconds'], load['rate']) == (3, 15, 1000)
        for phase in ('warmup', 'measurement'):
            counters = load[phase]
            assert counters['scheduled'] == counters['sent'] == counters['correct']
            assert not any(counters[key] for key in ('wrong', 'timeout', 'transport_error', 'scheduled_skipped'))
            totals.update({key: counters[key] for key in checks['counters']})
        assert load['measurement']['correct_in_window'] == 15000
        proof = validated['direct_raw_proof']
        if planned['declarations'] == 0:
            assert proof is None
            continue
        assert proof['declarations'] == planned['declarations'] and proof['rrtype'] == planned['rrtype']
        assert set(proof['replies']) == {'udp', 'tcp'}
        query = bytes.fromhex(proof['query_hex'])
        assert struct.unpack('!6H', query[:12]) == (0x51a1, 0x0100, 1, 0, 0, 0)
        payload = bytes.fromhex('abcd' if planned['rrtype'] == 65401 else 'c0000201')
        expected = (struct.pack('!6H', 0x51a1, 0x8580, 1, 1, 0, 0) + query[12:]
                    + struct.pack('!HHHIH', 0xc00c, planned['rrtype'], 1, 3600, len(payload)) + payload)
        for reply in proof['replies'].values():
            assert reply['correct'] and bytes.fromhex(reply['hex']) == expected
            direct_packets += 1
    assert dict(totals) == checks['counters']
    assert checks['maximum_nr_throttled'] == checks['maximum_throttled_usec'] == 0
    configs = {(row['profile'], row['round']): row['sha256'] for row in checks['triple_config_checks']}
    profiles = list(dict.fromkeys(row['profile'] for row in plan['windows']))
    assert len(configs) == 21 and len(profiles) == 7
    orders = {1: ['c', 'main', 'current'], 2: ['main', 'current', 'c'], 3: ['current', 'c', 'main']}
    flags = ('--scenario', '--rate', '--clients', '--cache-names', '--seed', '--warmup', '--duration',
             '--saturation-seconds', '--loadgen', '--upstream', '--image-root', '--cpu-daemon',
             '--cpu-upstream', '--cpu-load', '--cpu-control', '--tcp-profile')
    for profile in profiles:
        for round_no in (1, 2, 3):
            triple = [w for w in plan['windows'] if w['profile'] == profile and w['round'] == round_no]
            assert [w['variant'] for w in triple] == orders[round_no]
            for w in triple:
                row = next(r for r in checks['windows'] if r['id'] == w['id'])
                assert row['raw_assets']['config'] == configs[(profile, round_no)]
            for flag in flags:
                assert len({w['argv'][w['argv'].index(flag) + 1] for w in triple}) == 1
    assert len(summary['comparisons']) == 35
    for row in summary['comparisons']:
        for variant in ('c', 'main', 'current'):
            values = [next(w['metrics'][row['metric']] for w in summary['windows']
                           if (w['profile'], w['variant'], w['round']) == (row['profile'], variant, n))
                      for n in (1, 2, 3)]
            median = statistics.median(values)
            assert row['values'][variant] == values and row['medians'][variant] == median
            assert row['relative_ranges'][variant] == (max(values) - min(values)) / median
        for variant in ('c', 'main'):
            assert row['current_over_' + variant] == row['medians']['current'] / row['medians'][variant] - 1
    return dict(passed=True, windows=63, configuration_triples=21, direct_raw_aa_packets=direct_packets,
                counters=dict(totals), zero_throttle_samples=checks['cgroup_samples'],
                script_sha256=sha(Path(__file__)),
                inputs={name: sha(path) for name, path in files.items()},
                limit='Local exported accounting and wire checks; private raw rehash is performed by the runner.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    result = check(args.directory)
    path = args.directory / 'independent-check.json'
    assert not path.exists(), path
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
