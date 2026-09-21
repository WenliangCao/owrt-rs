#!/usr/bin/env python3
"""Verify paired user-event segments and report one CPU ratio per router window."""
import argparse
import json
from pathlib import Path
import statistics

from r101_libubus_paired_report import process_identity
from r99_registration_cpu_report import digest, median_interval


def read(path):
    return json.loads(path.read_text())


def segment(raw, prefix, plan, pid, lane):
    sample = read(raw / f'{prefix}.json')
    assert sample['n'] == plan['iterations'] and sample['warmup'] == plan['warmup']
    assert sample['subject_pid'] == pid != sample['client_pid']
    assert sample['subject_cpu'] == 1 and sample['client_cpu'] == 0
    _, listeners, matched = lane.split('_')
    listeners, matched = int(listeners), bool(int(matched))
    assert sample['listeners'] == listeners and sample['matched'] == matched
    assert sample['payload_checked'] and sample['handlers_removed']
    assert sample['received'] == (sample['n'] * listeners if matched else 0)
    assert sample['warmup_received'] == (sample['warmup'] * listeners if matched else 0)
    assert sample['subject_resolution_ns'] == sample['client_resolution_ns'] == 1
    identities = []
    for when in ('before', 'after'):
        identities.append(process_identity((raw / f'{prefix}-stat-{when}.txt').read_text()))
        status = dict(line.split(':', 1) for line in (raw / f'{prefix}-status-{when}.txt').read_text().splitlines() if ':' in line)
        assert int(status['Pid']) == int(status['Tgid']) == pid
        assert int(status['Threads']) == 1 and status['Cpus_allowed_list'].strip() == '1'
    assert identities[0] == identities[1] and identities[0][0] == pid
    elapsed = {clock: sample[f'{clock}_after_ns'] - sample[f'{clock}_before_ns']
               for clock in ('subject', 'client', 'wall')}
    assert 0 < elapsed['subject'] <= elapsed['wall'] and 0 < elapsed['client'] <= elapsed['wall']
    n = sample['n'] * 1000
    return {'subject_identity': identities[0], 'subject_cpu_us': elapsed['subject'] / n,
            'client_cpu_us': elapsed['client'] / n, 'total_cpu_us': (elapsed['subject'] + elapsed['client']) / n,
            'wall_us': elapsed['wall'] / n}


def verify_window(root, plan, block):
    r = read(root / 'result.json')
    assert r['exit'] == 0 and r['pilot_only'] and not r['installed'] and not r['matrix']
    assert r['production_mode'] == 'stock' and r['implementation'] == 'rs'
    assert not r['correctness_smoke_only'] and r['iterations'] == plan['iterations']
    for key in ('passed', 'cleanup_verified', 'same_boot', 'same_config', 'same_production_identity', 'same_host_mounts'):
        assert r[key] is True
    for key in ('benchmark_sha256', 'workload_sha256', 'driver_sha256', 'guard_sha256', 'recovery_gate_sha256'):
        assert r[key] == plan[key]
    slots = block['slots']
    assert set(slots) == {'a', 'b'} and set(slots.values()) == set(plan['subjects'])
    assert r['candidate_sha256'] == plan['subjects'][slots['b']]
    assert r['before_candidate_sha256'] == plan['subjects'][slots['a']]
    for when in ('before', 'after'):
        assert read(root / f'health-{when}.json')['boot_id'] == plan['boot_id']
    raw = root / 'raw'
    assert (raw / 'COMPLETE').is_file()
    for name, expected in [('binary-sha256.txt', plan['subjects'][slots['b']]),
                           ('control-sha256.txt', plan['subjects'][slots['a']]),
                           ('benchmark-sha256.txt', plan['benchmark_sha256'])]:
        assert (raw / name).read_text().split()[0] == expected
    assert {line.split()[1]: line.split()[0] for line in (raw / 'libraries.sha256').read_text().splitlines()} == plan['libraries']
    meta = read(raw / 'meta.json')
    assert meta['iterations'] == plan['iterations'] and meta['warmup'] == plan['warmup']
    assert meta['segments'] == 24 and meta['subject_cpu'] == 1 and meta['client_cpu'] == 0
    assert meta['serial_cpu_loop'] and meta['a_pid'] != meta['b_pid']
    rows, identities = [], {'a': set(), 'b': set()}
    i = 0
    for lane in plan['lanes']:
        for slot in 'abbabaab':
            i += 1
            row = segment(raw, f'{lane}-segment-{i}-{slot}', plan, meta[f'{slot}_pid'], lane)
            identities[slot].add(tuple(row['subject_identity']))
            rows.append({**row, 'segment': i, 'lane': lane, 'side': slots[slot], 'slot': slot})
    assert len(list(raw.glob('*-segment-*.json'))) == i == 24
    assert all(len(v) == 1 for v in identities.values())
    for slot in slots:
        for when in ('before', 'after'):
            assert not (raw / f'{slot}-objects-{when}.txt').read_text().strip()
    aggregate = {}
    for lane in plan['lanes']:
        aggregate[lane] = {}
        for side in plan['subjects']:
            selected = [r for r in rows if r['lane'] == lane and r['side'] == side]
            assert len(selected) == 4
            aggregate[lane][side] = {metric: statistics.mean(r[metric] for r in selected) for metric in plan['metrics']}
    return {'block': block['block'], 'slots': slots, 'segments': rows, 'aggregate': aggregate,
            'result_sha256': digest(root / 'result.json'), 'raw_sha256': digest(root / 'raw.tar.gz')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('plan', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    plan = read(a.plan)
    assert (a.root / 'COMPLETE').is_file()
    runs = [verify_window(a.root / f"{b['block']:02d}", plan, b) for b in plan['blocks']]
    assert plan['family_comparisons'] >= len(plan['lanes']) * len(plan['metrics'])
    summary = []
    for lane in plan['lanes']:
        for metric in plan['metrics']:
            ratios = [r['aggregate'][lane]['candidate'][metric] / r['aggregate'][lane]['before'][metric] for r in runs]
            summary.append({'lane': lane, 'metric': metric, 'paired_ratios': ratios,
                            'median_ratio': statistics.median(ratios),
                            'interval': median_interval(ratios, plan['family_comparisons'])})
    a.output.write_text(json.dumps({'plan_sha256': digest(a.plan), 'plan': plan, 'runs': runs, 'summary': summary,
                                   'all_windows_cleaned_and_stock': True,
                                   'limits': 'One independent observation per window; four segments per side are aggregated. Rank intervals assume independent identically distributed block ratios. Scope is only these direct-user-event workloads.'}, indent=2) + '\n')


if __name__ == '__main__':
    main()
