#!/usr/bin/env python3
"""Independently check retained three-way summaries locally, without Oracle I/O.

Example: python3 independent_check.py --prefix before --output before-independent-check.json
This checks the exported evidence, not the private raw files on Oracle.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[6]
VARIANTS = ('c', 'main', 'current')
ORDER = {1: ['c', 'main', 'current'], 2: ['main', 'current', 'c'], 3: ['current', 'c', 'main']}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, label):
    if not value:
        raise ValueError(label)


def check(plan, summary, counters, run):
    windows = plan['windows']
    ids = [row['id'] for row in windows]
    require(ids and len(ids) == len(set(ids)), 'nonempty unique plan windows')
    for data in (summary, counters, run):
        require([row['id'] for row in data['windows']] == ids, 'all exported window identities/order match')
    require(summary['complete'] and not summary['errors'] and run['status'] == 'complete', 'complete series')
    require(all(row['returncode'] == 0 for row in run['windows']), 'all window exits successful')
    require(all(a['ended'] <= b['started'] for a, b in zip(run['windows'], run['windows'][1:])),
            'serial windows do not overlap')
    require(summary['groups'] == plan['groups'], 'summary implementation identities match frozen plan')
    profiles = list(dict.fromkeys(row['profile'] for row in windows))
    totals = Counter()
    raw_proofs = 0
    for planned, measured, validated in zip(windows, summary['windows'], counters['windows']):
        for key in ('profile', 'variant', 'round', 'declarations', 'rrtype'):
            require(measured[key] == planned[key], 'measured window metadata matches plan')
        require(validated['actual_elf_sha256'] == plan['groups'][planned['variant']]['sha256'],
                'actual process ELF matches selected implementation')
        require(validated['validated_cache_names'] == 4096 and validated['upstream_disabled_requests'] == 0,
                'cache proof and disabled upstream summary')
        load = measured['load_counters']
        require(not load['interrupted'] and not load['output_failed'], 'native load completed')
        for phase in ('warmup', 'measurement'):
            values = load[phase]
            require(values['scheduled'] == values['sent'] == values['correct'], 'all scheduled queries correct')
            require(all(values[key] == 0 for key in ('wrong', 'timeout', 'transport_error', 'scheduled_skipped')),
                    'no native errors or skipped requests')
            totals.update({key: values[key] for key in counters['counters']})
        require(load['measurement']['correct_in_window'] == load['measurement']['correct'],
                'no measured correct responses complete outside the window')
        proof = validated['direct_raw_proof']
        if planned['declarations'] == 0:
            require(proof is None, 'ordinary window has no raw declaration proof')
            continue
        require(proof['declarations'] == planned['declarations'] and proof['rrtype'] == planned['rrtype'],
                'direct proof uses the planned raw declarations/type')
        require(set(proof['replies']) == {'udp', 'tcp'}, 'both direct transports retained')
        query = bytes.fromhex(proof['query_hex'])
        require(struct.unpack('!6H', query[:12]) == (0x51a1, 0x0100, 1, 0, 0, 0), 'direct query header')
        # Independent exact wire expectation also requires AA. The fixture
        # upstream emits 0x8180 with this same A value, so data alone is not proof.
        expected = (struct.pack('!6H', 0x51a1, 0x8580, 1, 1, 0, 0) + query[12:]
                    + struct.pack('!HHHIH', 0xc00c, planned['rrtype'], 1, 3600, 4)
                    + bytes.fromhex('c0000201'))
        for reply in proof['replies'].values():
            require(reply['correct'] and bytes.fromhex(reply['hex']) == expected,
                    'direct raw answer independently matches exact AA wire response')
            require(reply['decoded']['flags'] == 0x8580, 'decoded AA agrees with raw wire')
            raw_proofs += 1
    require(dict(totals) == counters['counters'], 'aggregate counters independently recomputed')
    require(counters['maximum_nr_throttled'] == counters['maximum_throttled_usec'] == 0,
            'exported cgroup throttle maxima are zero')
    triple_checks = {(row['profile'], row['round']): row for row in counters['triple_config_checks']}
    require(len(triple_checks) == len(counters['triple_config_checks']) == len(profiles) * 3,
            'exactly three configuration triples per profile')
    shared_args = ('--scenario', '--tcp-profile', '--rate', '--clients', '--cache-names', '--seed',
                   '--warmup', '--duration', '--saturation-seconds', '--loadgen', '--upstream',
                   '--image-root', '--cpu-daemon', '--cpu-upstream', '--cpu-load', '--cpu-control')
    for profile in profiles:
        for round_no in range(1, 4):
            triple = [row for row in windows if row['profile'] == profile and row['round'] == round_no]
            require([row['variant'] for row in triple] == ORDER[round_no], 'balanced Latin-square order')
            expected_hash = triple_checks[(profile, round_no)]['sha256']
            for row in triple:
                recorded = next(item for item in counters['windows'] if item['id'] == row['id'])
                require(recorded['raw_assets']['config'] == expected_hash, 'same configuration in every triple')
            for flag in shared_args:
                require(len({row['argv'][row['argv'].index(flag) + 1] for row in triple}) == 1,
                        'same seeded workload/tools/affinities within triple: ' + flag)
    metrics = ('cpu_us_per_correct', 'p95_ns', 'pss_kib', 'rss_kib', 'fd_count')
    require({(r['profile'], r['metric']) for r in summary['comparisons']}
            == {(p, m) for p in profiles for m in metrics}
            and len(summary['comparisons']) == len(profiles) * len(metrics), 'complete unique metric rows')
    for row in summary['comparisons']:
        for variant in VARIANTS:
            values = [next(w['metrics'][row['metric']] for w in summary['windows']
                           if w['profile'] == row['profile'] and w['variant'] == variant and w['round'] == number)
                      for number in range(1, 4)]
            median = statistics.median(values)
            require(values == row['values'][variant] and median == row['medians'][variant], 'values/median recompute')
            require((max(values) - min(values)) / median == row['relative_ranges'][variant], 'relative range recompute')
        for reference in ('c', 'main'):
            require(row['current_over_' + reference]
                    == row['medians']['current'] / row['medians'][reference] - 1, 'median ratio recompute')
    return {'windows': len(windows), 'configuration_triples': len(triple_checks),
            'metric_rows': len(summary['comparisons']), 'raw_udp_tcp_aa_wire_proofs': raw_proofs,
            'counters': dict(totals), 'exported_cgroup_points': counters['cgroup_samples']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--source-review', type=Path)
    parser.add_argument('--reference-source', type=Path, default=ROOT / 'private/dnsmasq-rewrite/reference/dnsmasq-2.93')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'output must be fresh')
    paths = {key: args.directory / f'{args.prefix}-{key}.json' for key in ('plan', 'summary', 'counter-check', 'run')}
    paths['source-review'] = args.source_review or args.directory / 'source-review.json'
    data = {key: json.loads(path.read_text()) for key, path in paths.items()}
    receipt = {'schema': 1, 'status': 'running', 'script': {'name': Path(__file__).name, 'sha256': sha(Path(__file__))},
               'inputs': {key: {'name': path.name, 'sha256': sha(path)} for key, path in paths.items()},
               'scope': 'Independent local consistency and retained direct-wire recheck; no Oracle access or raw-file rehash'}
    error = None
    try:
        require(data['summary']['plan_sha256'] == sha(paths['plan']), 'summary binds exact plan bytes')
        receipt['checks'] = check(data['plan'], data['summary'], data['counter-check'], data['run'])
        source = data['source-review']
        for name, identity in source['reference']['files'].items():
            require(sha(args.reference_source / name) == identity['sha256'], 'exact C source hash: ' + name)
        main = source['main_tcp']
        content = subprocess.check_output(['git', 'show', main['commit'] + ':' + main['path']], cwd=ROOT)
        require(hashlib.sha256(content).hexdigest() == main['file_sha256'], 'main Git file source identity')
        receipt['source_checks'] = {'exact_c_files': len(source['reference']['files']), 'main_git_file': True}
        receipt['status'] = 'passed'
    except Exception as caught:
        error = caught
        receipt.update(status='failed', error=repr(caught))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'sha256': sha(args.output), 'status': receipt['status']}))
    if error:
        raise error


if __name__ == '__main__':
    main()
