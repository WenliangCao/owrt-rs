#!/usr/bin/env python3
"""Validate exact-image C caller windows before aggregating independent ratios."""
import argparse
import json
from pathlib import Path
import statistics

from r99_registration_cpu_report import digest, median_interval


def process_identity(raw):
    pid, tail = raw.split(' (', 1)
    fields = tail.rsplit(')', 1)[1].split()
    # After comm, fields start at stat field 3 (state).
    assert len(fields) >= 20 and fields[17] == '1'
    return int(pid), int(fields[19])


def verify_segment(root, prefix, plan, subject_pid):
    sample = json.loads((root / f'{prefix}.json').read_text())
    assert sample['n'] == plan['iterations'] and sample['warmup'] == plan['warmup']
    assert sample['subject_pid'] == subject_pid
    assert sample['client_pid'] > 0 and sample['client_pid'] != subject_pid
    assert sample['subject_cpu'] == plan['subject_cpu'] == 1
    assert sample['client_cpu'] == plan['client_cpu'] == 0
    for key in ['full_signature_checked', 'last_type_reset_checked_each_cycle', 'final_empty']:
        assert sample[key] is True
    for who in ['subject', 'client']:
        assert sample[f'{who}_resolution_ns'] == plan['clock_resolution_ns']
    identities = []
    for when in ['before', 'after']:
        identities.append(process_identity((root / f'{prefix}-stat-{when}.txt').read_text()))
        status = dict(line.split(':', 1) for line in
                      (root / f'{prefix}-status-{when}.txt').read_text().splitlines() if ':' in line)
        assert int(status['Pid']) == int(status['Tgid']) == subject_pid
        assert int(status['Threads']) == 1 and status['Cpus_allowed_list'].strip() == '1'
    assert identities[0] == identities[1] and identities[0][0] == subject_pid
    elapsed = {}
    for clock in ['subject', 'client', 'wall']:
        before, after = sample[f'{clock}_before_ns'], sample[f'{clock}_after_ns']
        assert isinstance(before, int) and isinstance(after, int) and 0 <= before < after
        elapsed[clock] = after - before
    assert elapsed['subject'] <= elapsed['wall'] and elapsed['client'] <= elapsed['wall']
    n = sample['n']
    return {
        'subject_identity': identities[0], 'client_pid': sample['client_pid'],
        'subject_cpu_us': elapsed['subject'] / n / 1000,
        'client_cpu_us': elapsed['client'] / n / 1000,
        'total_cpu_us': (elapsed['subject'] + elapsed['client']) / n / 1000,
        'wall_us': elapsed['wall'] / n / 1000,
    }


def verify_window(root, plan, block):
    result = json.loads((root / 'result.json').read_text())
    assert result['exit'] == 0 and result['pilot_only'] and not result['installed']
    assert not result['correctness_smoke_only'] and not result['matrix']
    assert result['implementation'] == 'rs' and result['production_mode'] == 'stock'
    assert result['iterations'] == plan['iterations']
    for key in ['passed', 'cleanup_verified', 'same_boot', 'same_config',
                'same_production_identity', 'same_host_mounts']:
        assert result[key] is True
    for key in ['driver_sha256', 'workload_sha256', 'benchmark_sha256',
                'guard_sha256', 'recovery_gate_sha256']:
        assert result[key] == plan[key]
    slots = block['slots']
    assert set(slots) == {'a', 'b'} and set(slots.values()) == set(plan['subjects'])
    assert result['candidate_sha256'] == plan['subjects'][slots['b']]
    assert result['before_candidate_sha256'] == plan['subjects'][slots['a']]
    for when in ['before', 'after']:
        assert json.loads((root / f'health-{when}.json').read_text())['boot_id'] == plan['boot_id']
    raw = root / 'raw'
    assert (raw / 'COMPLETE').is_file()
    for filename, expected in [('binary-sha256.txt', plan['subjects'][slots['b']]),
                               ('control-sha256.txt', plan['subjects'][slots['a']]),
                               ('benchmark-sha256.txt', plan['benchmark_sha256'])]:
        assert (raw / filename).read_text().split()[0] == expected
    libraries = {}
    for line in (raw / 'libraries.sha256').read_text().splitlines():
        value, name = line.split()
        assert name not in libraries
        libraries[name] = value
    assert libraries == plan['libraries']
    meta = json.loads((raw / 'meta.json').read_text())
    for key in ['iterations', 'warmup', 'subject_cpu', 'client_cpu']:
        assert meta[key] == plan[key]
    assert meta['segments'] == 40 and meta['serial_cpu_loop'] is True
    assert meta['a_pid'] != meta['b_pid']
    identities = {'a': set(), 'b': set()}
    rows = []
    for quartet in range(10):
        for offset, slot in enumerate('abba' if quartet % 2 == 0 else 'baab'):
            i = quartet * 4 + offset + 1
            row = verify_segment(raw, f'segment-{i}-{slot}', plan, meta[f'{slot}_pid'])
            identities[slot].add(tuple(row['subject_identity']))
            rows.append(dict(row, segment=i, slot=slot, side=slots[slot]))
    assert len(list(raw.glob('segment-*.json'))) == 40
    assert all(len(value) == 1 for value in identities.values())
    for slot in slots:
        for when in ['before', 'after']:
            assert not (raw / f'{slot}-objects-{when}.txt').read_text().strip()
    aggregate = {}
    for side in plan['subjects']:
        selected = [r for r in rows if r['side'] == side]
        assert len(selected) == 20
        aggregate[side] = {key: statistics.mean(r[key] for r in selected) for key in plan['metrics']}
    return {'block': block['block'], 'slots': slots, 'segments': rows, 'aggregate': aggregate,
            'result_sha256': digest(root / 'result.json'), 'raw_sha256': digest(root / 'raw.tar.gz'),
            'frequency_before': (raw / 'frequency-before.txt').read_text(),
            'frequency_after': (raw / 'frequency-after.txt').read_text()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    assert (args.root / 'COMPLETE').is_file()
    plan = json.loads(args.plan.read_text())
    runs = [verify_window(args.root / f"{b['block']:02d}", plan, b) for b in plan['blocks']]
    family = plan['family_comparisons']
    assert family >= len(plan['contrasts']) * len(plan['interval_metrics'])
    summaries = []
    for numerator, denominator in plan['contrasts']:
        for metric in plan['metrics']:
            ratios = [r['aggregate'][numerator][metric] / r['aggregate'][denominator][metric] for r in runs]
            summaries.append({'numerator': numerator, 'denominator': denominator, 'metric': metric,
                              'paired_ratio': ratios, 'median_ratio': statistics.median(ratios),
                              'interval': median_interval(ratios, family) if metric in plan['interval_metrics'] else None})
    args.output.write_text(json.dumps({'plan_sha256': digest(args.plan), 'plan': plan,
                                      'runs': runs, 'summaries': summaries,
                                      'all_windows_cleaned_and_stock': True,
                                      'limits': 'Exact-image C caller condition only. One independent ratio per window; segments are not independent replicates. No pooling with Rust callers or full-system superiority inference.'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
