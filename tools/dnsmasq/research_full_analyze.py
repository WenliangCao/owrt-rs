#!/usr/bin/env python3
"""Derive the existing eleven-scene table plus the frozen UDP-hit nine pairs."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

import perf_opt_analyze as original
from research_device_run import clock_measurement


def analyze(folder):
    identity = json.loads((folder / 'identity.json').read_text())
    scenes = {row[0]: row for row in identity['scenes']}
    rows = []
    for row in json.loads((folder / 'progress.json').read_text()):
        raw = folder / 'runs' / row['label']
        scene = scenes[row['scene']]
        if scene[1].startswith('life-'):
            measurement = original.lifecycle(raw, row)
        else:
            measurement = original.traffic(raw, row, scene[4], scene[5])
            if scene[1] == 'udp':
                measurement['cpu_clock'] = clock_measurement(raw, measurement)
        rows.append({**row, 'measurement': measurement})
    comparisons = {}
    for name, scene in scenes.items():
        sides = {side: sorted([row for row in rows if row['scene'] == name and row['side'] == side],
                              key=lambda row: row['round']) for side in ('c', 'rust')}
        required = 9 if name == 'udp-hit' else 5
        if any(len(v) != required or any(not row['valid'] for row in v) for v in sides.values()):
            continue
        left, right = ([row['measurement'] for row in sides[side]] for side in ('c', 'rust'))
        metrics = {}
        for key in ('p50', 'p95'):
            metrics[key + '_ms'] = original.compare([r['latency_ms'][key] for r in left],
                [r['latency_ms'][key] for r in right], resolution=1 if scene[1].startswith('life-') else 0)
        metrics['cpu_us'] = original.compare([r['cpu_us_per_operation'] for r in left],
            [r['cpu_us_per_operation'] for r in right],
            cpu=([r['cpu_ticks'] for r in left], [r['cpu_ticks'] for r in right]))
        if required == 9:
            for metric in metrics.values():
                metric['direction_pairs_required'] = 8
                metric['discernible'] = metric['discernible'] and metric['same_direction_pairs'] >= 8
                if not metric['discernible']: metric['direction'] = 'within_variation_or_resolution'
        resources = {key: {'left': original.spread([r[key] for r in left]),
                           'right': original.spread([r[key] for r in right])}
                     for key in ('rss_median_kib', 'rss_peak_kib', 'anon_peak_kib', 'file_peak_kib',
                                 'shmem_peak_kib', 'tree_fd_peak', 'parent_fd_peak')}
        comparison = {'pairs': required, 'original_primary_metrics': metrics, 'resources': resources}
        if scene[1] == 'udp':
            valid = all(r['cpu_clock']['valid'] for r in left + right)
            comparison['cpu_clock_valid'] = valid
            if valid:
                delta = [b['cpu_clock']['cpu_us_per_operation'] - a['cpu_clock']['cpu_us_per_operation']
                         for a, b in zip(left, right)]
                comparison['cpu_clock_pair_differences_us'] = delta
                comparison['cpu_clock_pair_summary'] = original.spread(delta)
                if required == 9:
                    ordered = sorted(delta)
                    comparison['cpu_clock_interval_d2_d8'] = [ordered[1], ordered[7]]
                    comparison['cpu_clock_three_pair_block_medians'] = [statistics.median(delta[i:i + 3]) for i in (0, 3, 6)]
        comparisons[name] = comparison
    return {'identity': identity, 'windows': rows, 'comparisons': comparisons,
            'primary_comparisons': sum(len(c['original_primary_metrics']) for c in comparisons.values()),
            'scope': 'UDP-hit uses nine pairs and the frozen CPU-clock confirmation rule; legacy W diagnostics require eight directions. Other ten scenes retain five-pair legacy criteria. TCP/fork, DHCP and lifecycle CPU scopes are unchanged. No historical pooling.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = analyze(args.folder)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'windows': len(result['windows']), 'primary_comparisons': result['primary_comparisons'],
                      'sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()}))
