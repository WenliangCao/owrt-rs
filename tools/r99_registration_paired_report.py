#!/usr/bin/env python3
"""Paired-window CPU analysis; segments are not independent replicates."""
import argparse
import json
from pathlib import Path
import statistics
from r99_registration_cpu_report import digest, median_interval, verify_sample


def verify_window(root, plan, block, iterations=None):
    read = lambda name: json.loads((root / name).read_text())
    result = read('result.json')
    slots = block['slots']
    assert set(slots) == {'a', 'b'} and set(slots.values()) == set(plan['subjects'])
    assert result['exit'] == 0 and result['pilot_only'] and not result['installed'] and not result['matrix']
    assert result['production_mode'] == 'stock' and result['implementation'] == 'rs'
    for key in ['passed', 'cleanup_verified', 'same_boot', 'same_config', 'same_production_identity', 'same_host_mounts']:
        assert result[key], (root, key)
    for key in ['benchmark_sha256', 'driver_sha256', 'workload_sha256', 'guard_sha256', 'recovery_gate_sha256']:
        assert result[key] == plan[key]
    assert result['candidate_sha256'] == plan['subjects'][slots['b']]
    assert result['before_candidate_sha256'] == plan['subjects'][slots['a']]
    n = iterations if iterations is not None else plan['iterations']
    assert result['iterations'] == n and (root / 'raw/COMPLETE').exists()
    assert (root / 'raw/binary-sha256.txt').read_text().split()[0] == plan['subjects'][slots['b']]
    assert (root / 'raw/control-sha256.txt').read_text().split()[0] == plan['subjects'][slots['a']]
    assert (root / 'raw/benchmark-sha256.txt').read_text().split()[0] == plan['benchmark_sha256']
    assert read('health-before.json')['boot_id'] == read('health-after.json')['boot_id'] == plan['boot_id']
    meta = read('raw/meta.json')
    assert meta['iterations'] == n and meta['warmup'] == plan['warmup']
    assert meta['segments'] == 40 and meta['serial_cpu_loop'] is True
    assert meta['subject_cpu'] == plan['subject_cpu'] and meta['client_cpu'] == plan['client_cpu']
    assert meta['a_pid'] != meta['b_pid']
    for slot in ['a', 'b']:
        for when in ['before', 'after']:
            assert not (root / f'raw/{slot}-objects-{when}.txt').read_text().strip()
    rows = []
    identities = {'a': set(), 'b': set()}
    for quartet in range(10):
        order = 'abba' if quartet % 2 == 0 else 'baab'
        for offset, slot in enumerate(order):
            i = quartet * 4 + offset + 1
            sample = read(f'raw/segment-{i}-{slot}.json')
            assert sample['subject_pid'] == meta[slot + '_pid']
            row = verify_sample(sample, plan, n)
            assert row['subject_before']['pid'] == meta[slot + '_pid']
            identities[slot].add(row['subject_before']['start_ticks'])
            rows.append(dict(row, segment=i, slot=slot, side=slots[slot]))
    assert len(list((root / 'raw').glob('segment-*.json'))) == 40
    assert all(len(ids) == 1 for ids in identities.values())
    aggregate = {}
    for side in plan['subjects']:
        selected = [r for r in rows if r['side'] == side]
        assert len(selected) == 20
        aggregate[side] = {metric: statistics.mean(r[metric] for r in selected) for metric in plan['metrics']}
    return {'block': block['block'], 'slots': slots, 'segments': rows, 'aggregate': aggregate,
            'frequency_before': (root / 'raw/frequency-before.txt').read_text(),
            'frequency_after': (root / 'raw/frequency-after.txt').read_text(),
            'result_sha256': digest(root / 'result.json'), 'raw_sha256': digest(root / 'raw.tar.gz')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    assert (a.root / 'COMPLETE').exists()
    plan = json.loads(a.plan.read_text())
    runs = [verify_window(a.root / f"{b['block']:02d}", plan, b) for b in plan['blocks']]
    m = len(plan['contrasts']) * len(plan['interval_metrics'])
    summaries = []
    for numerator, denominator in plan['contrasts']:
        for metric in plan['metrics']:
            ratios = [r['aggregate'][numerator][metric] / r['aggregate'][denominator][metric] for r in runs]
            summaries.append({'numerator': numerator, 'denominator': denominator, 'metric': metric,
                              'paired_ratio': ratios, 'median_ratio': statistics.median(ratios),
                              'interval': median_interval(ratios, m) if metric in plan['interval_metrics'] else None})
    gate = None
    if plan['kind'] == 'aa':
        assert len(set(plan['subjects'].values())) == 1
        lo, hi = plan['calibration_median_band']
        gate = {s['metric']: s['interval'] is not None and lo <= s['interval']['lower'] and s['interval']['upper'] <= hi
                for s in summaries if s['metric'] in plan['interval_metrics']}
    a.output.write_text(json.dumps({'plan_sha256': digest(a.plan), 'plan': plan, 'runs': runs, 'summaries': summaries,
                                   'preliminary_calibration_gate': gate, 'all_windows_cleaned_and_stock': True,
                                   'limits': 'One independent ratio per physical window. Segments are aggregated, never counted as independent trials. Co-resident paired processes with serial requests are a diagnostic condition, not full-system latency or memory acceptance.'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
