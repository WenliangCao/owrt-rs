#!/usr/bin/env python3
"""Verify serial router CPU evidence and compute exact median rank intervals."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def median_interval(values, comparisons, alpha=0.05):
    """Distribution-free median interval, with Bonferroni family coverage."""
    assert comparisons >= 1 and values and 0 < alpha < 1
    assert all(math.isfinite(v) for v in values)
    n = len(values)
    ranks = [k for k in range(1, (n + 1) // 2 + 1)
             if sum(math.comb(n, j) for j in range(k)) / 2**n <= alpha / (2 * comparisons)]
    if not ranks:
        return None
    k = max(ranks)
    ordered = sorted(values)
    return {"lower": ordered[k - 1], "upper": ordered[n - k], "rank": k,
            "marginal_coverage_lower_bound": 1 - 2 * sum(math.comb(n, j) for j in range(k)) / 2**n}


def allowed(status):
    return next(line.split(':', 1)[1].strip() for line in status.splitlines()
                if line.startswith('Cpus_allowed_list:'))


def verify_sample(j, plan, n):
    assert j['mode'] == 'serial_cpu_loop' and j['successful'] == n and j['errors'] == 0
    assert j['warmup'] == plan['warmup']
    assert j['wall_s'] > 0 and math.isclose(j['ops_per_s'], n / j['wall_s'], rel_tol=1e-8)
    for who, cpu in [('subject', plan['subject_cpu']), ('client', plan['client_cpu'])]:
        a, b = j[who + '_before'], j[who + '_after']
        assert a['pid'] == b['pid'] and a['start_ticks'] == b['start_ticks']
        assert a['Threads'] == b['Threads'] == 1
        assert a['process_cpu_resolution_ns'] == b['process_cpu_resolution_ns'] > 0
        lo, hi = j[who + '_cpu_start_ns'], j[who + '_cpu_end_ns']
        assert a['process_cpu_ns'] <= lo <= hi <= b['process_cpu_ns']
        assert j[who + '_cpu_clock_ns'] == hi - lo > 0
        assert allowed(j[who + '_status']) == str(cpu)
    return {'subject_cpu_us': j['subject_cpu_clock_ns'] / n / 1000,
            'client_cpu_us': j['client_cpu_clock_ns'] / n / 1000,
            'wall_us': j['wall_s'] / n * 1e6,
            'wall_s': j['wall_s'], 'ops_per_s': j['ops_per_s'],
            'subject_before': j['subject_before'], 'subject_after': j['subject_after'],
            'client_before': j['client_before'], 'client_after': j['client_after']}


def verify_run(root, plan, side, iterations=None):
    read = lambda p: json.loads((root / p).read_text())
    r = read('result.json')
    assert r['exit'] == 0 and r['pilot_only'] and not r['installed'] and not r['matrix']
    assert r['production_mode'] == 'stock'
    assert r['implementation'] == plan.get('implementations', {}).get(side, 'c' if side == 'stock' else 'rs')
    for key in ['passed', 'cleanup_verified', 'same_boot', 'same_config', 'same_production_identity', 'same_host_mounts']:
        assert r[key], (root, key)
    for key, value in [('candidate_sha256', plan['subjects'][side]), ('benchmark_sha256', plan['benchmark_sha256']),
                       ('driver_sha256', plan['driver_sha256']), ('workload_sha256', plan['workload_sha256']),
                       ('guard_sha256', plan['guard_sha256']), ('recovery_gate_sha256', plan['recovery_gate_sha256'])]:
        assert r[key] == value, (root, key)
    n = iterations if iterations is not None else plan['iterations']
    assert r['iterations'] == n
    assert (root / 'raw/COMPLETE').exists()
    assert (root / 'raw/binary-sha256.txt').read_text().split()[0] == plan['subjects'][side]
    assert (root / 'raw/benchmark-sha256.txt').read_text().split()[0] == plan['benchmark_sha256']
    assert not (root / 'raw/objects-before.txt').read_text().strip()
    assert not (root / 'raw/objects-after.txt').read_text().strip()
    before, after = read('health-before.json'), read('health-after.json')
    assert before['boot_id'] == after['boot_id'] == plan['boot_id']
    meta = read('raw/meta.json')
    j = read('raw/register_cpu_1_8.json')
    assert meta['serial_cpu_loop'] is True
    assert meta['subject_cpu'] == plan['subject_cpu'] and meta['client_cpu'] == plan['client_cpu']
    assert j['mode'] == 'serial_cpu_loop' and j['successful'] == n and j['errors'] == 0
    assert j['warmup'] == meta['warmup'] == plan['warmup']
    assert meta['iterations'] == n and j['subject_pid'] == meta['subject_pid']
    assert j['wall_s'] > 0 and math.isclose(j['ops_per_s'], n / j['wall_s'], rel_tol=1e-8)
    assert allowed((root / 'raw/subject-status-before.txt').read_text()) == str(plan['subject_cpu'])
    assert allowed((root / 'raw/subject-status-after.txt').read_text()) == str(plan['subject_cpu'])
    return dict(verify_sample(j, plan, n),
                frequency_before=(root / 'raw/frequency-before.txt').read_text(),
                frequency_after=(root / 'raw/frequency-after.txt').read_text(),
                result_sha256=digest(root / 'result.json'), raw_sha256=digest(root / 'raw.tar.gz'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    assert (a.root / 'COMPLETE').exists()
    plan = json.loads(a.plan.read_text())
    rows = []
    for block in plan['blocks']:
        assert set(block['order']) == set(plan['subjects'])
        for side in block['order']:
            row = verify_run(a.root / f"{block['block']:02d}-{side}", plan, side)
            rows.append(dict(row, block=block['block'], side=side))
    contrasts = plan['contrasts']
    m = len(contrasts) * len(plan['interval_metrics'])
    summaries = []
    for numerator, denominator in contrasts:
        for metric in plan['metrics']:
            ratios = []
            for block in plan['blocks']:
                values = {r['side']: r[metric] for r in rows if r['block'] == block['block']}
                ratios.append(values[numerator] / values[denominator])
            summaries.append({'numerator': numerator, 'denominator': denominator, 'metric': metric,
                              'paired_ratio': ratios, 'median_ratio': statistics.median(ratios),
                              'interval': median_interval(ratios, m) if metric in plan['interval_metrics'] else None})
    calibration = None
    if plan.get('kind') == 'aa':
        assert len(set(plan['subjects'].values())) == 1, 'A/A requires byte-identical subjects'
        lo, hi = plan['calibration_median_band']
        calibration = {s['metric']: s['interval'] is not None and lo <= s['interval']['lower']
                       and s['interval']['upper'] <= hi
                       for s in summaries if s['metric'] in plan['interval_metrics']}
    a.output.write_text(json.dumps({'plan_sha256': digest(a.plan), 'plan': plan, 'runs': rows,
                                   'summaries': summaries, 'preliminary_calibration_gate': calibration,
                                   'all_windows_cleaned_and_stock': True,
                                   'limits': 'Independent-run median assumptions required; A/A calibration is workload and session specific. No latency, PSS, whole-memory, equivalence or full ubusd superiority verdict.'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
