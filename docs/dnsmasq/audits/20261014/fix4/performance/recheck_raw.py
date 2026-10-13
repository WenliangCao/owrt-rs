#!/usr/bin/env python3
"""Independently reduce retained timing files and rehash evidence after load.

No experiment is rerun. The scheduled-to-completion distribution additionally
includes each query's recorded scheduled-to-actual-send lag.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantiles(values):
    values = sorted(values)
    return {name: values[math.ceil(len(values) * fraction) - 1]
            for name, fraction in [('p50', .5), ('p95', .95), ('p99', .99)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dns', required=True, type=Path)
    parser.add_argument('--startup', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert not args.output.exists()
    summary = json.loads((args.dns / 'summary.json').read_text())
    checks = json.loads((args.dns / 'counter-check.json').read_text())
    plan = json.loads((args.dns / 'plan.json').read_text())
    assert summary['complete'] and summary['plan_sha256'] == sha(args.dns / 'plan.json')
    for path, expected in plan['assets'].items():
        assert sha(Path(path)) == expected, path
    raw_index, timings = {}, []
    for path in [args.dns / 'foreign-before.json', *args.dns.glob('*.foreign-before.json')]:
        assert json.loads(path.read_text()) == [], path
        raw_index[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    for row, counter in zip(summary['windows'], checks['windows']):
        assert row['id'] == counter['id']
        folder = args.dns / row['id']
        for name, expected in {**row['raw_inputs'], **counter['raw_assets']}.items():
            path = folder / name
            assert sha(path) == expected, path
        if counter['direct_raw_proof'] is not None:
            assert json.loads((folder / 'same-type-proof.json').read_text()) == counter['direct_raw_proof']
        for name in ('result.json', 'load.json', 'epoch.json', 'resources.json', 'load.latencies.bin',
                     'load.send-lag.bin', 'config', 'upstream.json', 'cache-proof.json',
                     'process-identity.json', 'load.wire-samples.jsonl', 'same-type-proof.json'):
            path = folder / name
            if path.exists():
                raw_index[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size}
        result = json.loads((folder / 'result.json').read_text())
        points = result['measurement']['cpu_points']
        before, after = [points[name]['cgroup_cpu']['usage_usec']
                         for name in ('measurement-start', 'measurement-end')]
        assert (after - before) / 15000 == row['metrics']['cpu_us_per_correct']
        latencies = list(struct.iter_unpack('<QQQHHBBBB', (folder / 'load.latencies.bin').read_bytes()))
        lags = list(struct.iter_unpack('<QQ', (folder / 'load.send-lag.bin').read_bytes()))
        assert len(latencies) == len(lags) == 15000
        assert all(a[0] == b[0] and a[5] == 0 for a, b in zip(latencies, lags))
        latency = quantiles([item[1] for item in latencies])
        assert latency['p95'] == row['metrics']['p95_ns']
        scheduled = quantiles([a[1] + b[1] for a, b in zip(latencies, lags)])
        timings.append(dict(id=row['id'], profile=row['profile'], variant=row['variant'], round=row['round'],
                            cpu_us=after - before, cpu_us_per_correct=(after - before) / 15000,
                            actual_send_to_complete_ns=latency, scheduled_to_complete_ns=scheduled,
                            scheduled_to_send_ns=quantiles([item[1] for item in lags])))
    startup = json.loads((args.startup / 'result.json').read_text())
    assert startup['passed'] and startup['status'] == 'complete' and len(startup['runs']) == 36
    startup_rows = []
    for row in startup['runs']:
        assert row['passed'] and not row['errors'] and row['exit'] == 0
        assert row['actual_exe_sha256'] == startup['identities'][row['variant']]
        for path in (args.startup / row['directory']).iterdir():
            if path.is_file():
                raw_index[str(path)] = {'sha256': sha(path), 'bytes': path.stat().st_size}
    for count in startup['counts']:
        replies = {r['query']['reply_hex'] for r in startup['runs'] if r['count'] == count}
        assert len(replies) == 1, (count, 'different DNS reply')
        metrics = {}
        for metric in ('initial_cache_reload_log_observed_seconds', 'ready_cpu_seconds',
                       'VmHWM_kib', 'VmRSS_kib', 'Pss_kib'):
            values = {side: [r[metric] for r in startup['runs'] if r['count'] == count and r['variant'] == side]
                      for side in ('c', 'main', 'head')}
            assert all(len(v) == 3 for v in values.values())
            metrics[metric] = dict(values=values, medians={k: statistics.median(v) for k, v in values.items()})
        startup_rows.append(dict(host_records=count, metrics=metrics))
    evidence = dict(passed=True, script_sha256=sha(Path(__file__)),
                    scope='Fresh independent raw CPU/timing reduction, source/assets rehash and startup evidence index',
                    dns_plan_sha256=sha(args.dns / 'plan.json'), startup_result_sha256=sha(args.startup / 'result.json'),
                    frozen_assets_rehashed=len(plan['assets']), dns_windows=len(timings),
                    startup_runs=36, windows=timings, startup=startup_rows, raw_index=raw_index,
                    limits=['Startup CPU has 10 ms tick granularity; log wall timing polls every 5 ms.',
                            'Scheduled-to-completion sums retained lag and latency; it is not a fresh workload.',
                            'Only the listed raw timing/proof/resource files are indexed; extracted rootfs is private.'])
    args.output.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps(dict(passed=True, windows=63, startup_runs=36, raw_files=len(raw_index))))


if __name__ == '__main__':
    main()
