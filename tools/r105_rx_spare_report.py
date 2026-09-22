#!/usr/bin/env python3
"""Verify and summarize R105 memory or direct-event exploratory router blocks."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(rows, plan, metric, lane):
    selected = [r for r in rows if r['workload'] == lane]
    sides = {side: [r[metric] for r in selected if r['side'] == side]
             for side in plan['subjects']}
    assert all(len(v) == len(plan['blocks']) for v in sides.values())
    pairs = {}
    for control in plan['subjects']:
        if control == 'candidate':
            continue
        values = []
        differences = []
        for block in plan['blocks']:
            pair = {r['side']: r[metric] for r in selected if r['block'] == block['block']}
            differences.append(pair['candidate'] - pair[control])
            values.append(100 * (pair['candidate'] / pair[control] - 1) if pair[control] else None)
        pairs[control] = {'per_block_difference': differences,
                          'median_difference': statistics.median(differences),
                          'per_block_delta_pct': values,
                          'median_delta_pct': statistics.median(values) if None not in values else None}
    return {'sides': {s: {'values': v, 'median': statistics.median(v)} for s, v in sides.items()},
            'paired_exploration': pairs}


def collect(root, plan, stage):
    assert (root / 'COMPLETE').is_file(), 'collection incomplete'
    rows, windows, boots, guards = [], [], set(), set()
    script = plan.get('workload_script',
                      'tools/r104_rx_memory.sh' if stage == 'memory' else 'tools/r103_user_event.sh')
    for block in plan['blocks']:
        for side in block['order']:
            window = root / f"{block['block']:02d}-{side}"
            result = read(window / 'result.json')
            assert result['exit'] == 0 and result['pilot_only'] and not result['installed']
            assert not result['matrix'] and not result['correctness_smoke_only']
            assert result['production_mode'] == 'stock'
            assert result['implementation'] == ('c' if side == 'stock' else 'rs')
            assert result['iterations'] == plan['iterations']
            for key in ('passed', 'cleanup_verified', 'same_boot', 'same_config',
                        'same_production_identity', 'same_host_mounts'):
                assert result[key] is True, (window, key)
            assert result['candidate_sha256'] == plan['subjects'][side]
            assert result['benchmark_sha256'] == plan['benchmark_sha256']
            assert result['driver_sha256'] == plan['source_scripts']['tools/r95_device_smoke.py']
            assert result['workload_sha256'] == plan['source_scripts'][script]
            guards.add((result['guard_sha256'], result['recovery_gate_sha256']))
            for when in ('before', 'after'):
                boots.add(read(window / f'health-{when}.json')['boot_id'])
            raw = window / 'raw'
            assert (raw / 'COMPLETE').is_file()
            assert (raw / 'binary-sha256.txt').read_text().split()[0] == plan['subjects'][side]
            assert (raw / 'benchmark-sha256.txt').read_text().split()[0] == plan['benchmark_sha256']
            common = {'block': block['block'], 'side': side}
            windows.append({**common, 'result_sha256': digest(window / 'result.json'),
                            'raw_archive_sha256': digest(window / 'raw.tar.gz')})
            if stage == 'memory':
                table = list(csv.DictReader((raw / 'memory.csv').read_text().splitlines()))
                assert [int(r['clients']) for r in table] == plan['workloads']
                for row in table:
                    count = int(row['clients'])
                    if count:
                        holder = read(raw / f'clients-{count}.json')
                        assert holder['clients'] == holder['ping_frames_sent'] == count
                        assert holder['replies_validated'] is True and holder['holding'] is True
                        assert not (raw / f'clients-{count}.err').read_text()
                    assert row['pss_before_kb'] == row['pss_after_kb'] == 'NA'
                    metrics = {k: int(v) for k, v in row.items() if k != 'clients' and not k.startswith('pss')}
                    assert all(v >= 0 for v in metrics.values())
                    for name in ('vmrss', 'rssanon', 'vmdata'):
                        metrics[name + '_growth_kb'] = metrics[name + '_after_kb'] - metrics[name + '_before_kb']
                    if 'argv0' in plan:
                        command = (raw / f'cmdline-{count}.txt').read_text().splitlines()
                        assert len(command) == 3 and command[:2] == [plan['argv0'], '-s']
                    if plan.get('after_disconnect'):
                        reclaimed = (raw / f'after-disconnect-{count}.csv').read_text().strip().split(',')
                        assert len(reclaimed) == 4 and reclaimed[3] == 'NA'
                        for name, value in zip(('vmrss', 'rssanon', 'vmdata'), reclaimed[:3]):
                            value = int(value)
                            assert value >= 0
                            metrics[name + '_after_disconnect_kb'] = value
                            metrics[name + '_retained_growth_kb'] = value - metrics[name + '_before_kb']
                    rows.append({**common, 'workload': count, **metrics})
            else:
                meta = read(raw / 'meta.json')
                assert meta['iterations'] == plan['iterations'] and meta['warmup'] == plan['warmup']
                assert meta['subject_cpu'] == 1 and meta['client_cpu'] == 0 and meta['exact_image_caller']
                for when in ('before', 'after'):
                    assert not (raw / f'objects-{when}.txt').read_text().strip()
                for lane in plan['workloads']:
                    sample = read(raw / f'{lane}.json')
                    _, listeners, matched = lane.split('_')
                    listeners, matched = int(listeners), bool(int(matched))
                    assert sample['n'] == plan['iterations'] and sample['warmup'] == plan['warmup']
                    assert sample['listeners'] == listeners and sample['matched'] == matched
                    assert sample['subject_pid'] == meta['subject_pid'] != sample['client_pid']
                    assert sample['subject_cpu'] == 1 and sample['client_cpu'] == 0
                    assert sample['subject_resolution_ns'] == sample['client_resolution_ns'] == 1
                    assert sample['payload_checked'] and sample['handlers_removed']
                    assert sample['received'] == (sample['n'] * listeners if matched else 0)
                    assert sample['warmup_received'] == (sample['warmup'] * listeners if matched else 0)
                    elapsed = {clock: sample[f'{clock}_after_ns'] - sample[f'{clock}_before_ns']
                               for clock in ('subject', 'client', 'wall')}
                    assert 0 < elapsed['subject'] <= elapsed['wall']
                    assert 0 < elapsed['client'] <= elapsed['wall']
                    metrics = {f'{clock}_cpu_us_per_send': elapsed[clock] / 1000 / sample['n']
                               for clock in ('subject', 'client')}
                    metrics['wall_us_per_send'] = elapsed['wall'] / 1000 / sample['n']
                    rows.append({**common, 'workload': lane, **metrics})
    assert len(boots) == len(guards) == 1, 'boot or guard identities changed'
    return rows, windows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('memory', 'user-event'))
    parser.add_argument('root', type=Path)
    parser.add_argument('plan', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    plan = read(args.plan)
    rows, windows = collect(args.root, plan, args.stage)
    metrics = ([f'{name}_{suffix}_kb' for name in ('vmrss', 'rssanon', 'vmdata')
                for suffix in ('before', 'after', 'growth')]
               if args.stage == 'memory' else plan['metrics'])
    if args.stage == 'memory' and plan.get('after_disconnect'):
        metrics += [f'{name}_{suffix}_kb' for name in ('vmrss', 'rssanon', 'vmdata')
                    for suffix in ('after_disconnect', 'retained_growth')]
    summary = {str(lane): {metric: summarize(rows, plan, metric, lane) for metric in metrics}
               for lane in plan['workloads']}
    result = {'schema_version': 1, 'plan_sha256': digest(args.plan), 'plan': plan,
              'all_windows_cleaned_and_production_stock': True, 'windows': windows,
              'runs': rows, 'summary': summary, 'superiority_verdict': None,
              'limitations': ('Exploratory paired blocks only. RSS counters may be imprecise; '
                              'no PSS or kernel-buffer/peak claim. Event loop clocks do not '
                              'measure per-request tail latency. No pooling earlier runs.')}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'runs': len(rows), 'windows': len(windows), 'superiority_verdict': None}))


if __name__ == '__main__':
    main()
