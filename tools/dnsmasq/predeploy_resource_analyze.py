#!/usr/bin/env python3
"""Derive redacted aggregates from private predeploy_resources.py output.

Only monitor counters and synthetic workload records are read. Configuration,
leases, packet samples, hostnames, addresses, logs, and raw device dumps are
never inspected or copied to the report. No third-party packages are needed.
"""
import argparse
import collections
import hashlib
import json
import math
import re
import statistics
import struct
from pathlib import Path

LATENCY = struct.Struct('<QQQHHBBBB')
LAG = struct.Struct('<QQ')
COUNTERS = ('scheduled', 'sent', 'correct', 'timeout', 'wrong',
            'transport_error', 'scheduled_skipped', 'stale_reply',
            'datagrams_sent', 'release_sent', 'dora_correct', 'renew_correct',
            'correct_in_window', 'correct_after_window', 'send_lag_count',
            'send_lag_sum_ns', 'send_lag_max_ns')
QTYPES = {1: 'A', 5: 'CNAME', 16: 'TXT', 28: 'AAAA'}
KINDS = {0: 'intended_hit', 1: 'intended_miss', 2: 'dhcp_cycle'}


def read_json(path):
    return json.loads(path.read_text())


def samples(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def distribution(values):
    """Nearest-rank quantiles; retain n so small-sample tails are visible."""
    if not values:
        return None
    values = sorted(values)
    return {'n': len(values), 'min': values[0], 'mean': statistics.mean(values),
            'median': statistics.median(values),
            'p50': values[math.ceil(len(values) * .50) - 1],
            'p95': values[math.ceil(len(values) * .95) - 1],
            'p99': values[math.ceil(len(values) * .99) - 1], 'max': values[-1]}


def record_file(path, record):
    data = path.read_bytes()
    if len(data) % record.size:
        raise ValueError(f'{path.name}: incomplete binary record')
    return list(record.iter_unpack(data))


def workload(folder, mode):
    source = read_json(folder / (mode + '.json'))
    if source['latency_record_bytes'] != 32 or source['latency_byte_order'] != 'little':
        raise ValueError('unsupported latency format')
    if source.get('saturation_seconds', 0):
        raise ValueError('resource windows must not contain a saturation phase')
    rows = record_file(folder / (mode + '.latencies.bin'), LATENCY)
    lags = record_file(folder / (mode + '.send-lag.bin'), LAG)
    if len({r[0] for r in rows}) != len(rows) or len({r[0] for r in lags}) != len(lags):
        raise ValueError(f'{mode}: duplicate sequence')
    lag_by_sequence = dict(lags)
    if set(lag_by_sequence) != {r[0] for r in rows}:
        raise ValueError(f'{mode}: latency/send-lag sequence mismatch')
    counts = collections.Counter(r[5] for r in rows)
    expected = source['measurement']
    if any(counts[n] != expected[key] for n, key in
           enumerate(('correct', 'timeout', 'wrong', 'transport_error'))):
        raise ValueError(f'{mode}: record/status counter mismatch')
    if len(rows) != expected['sent'] or sum(lag_by_sequence.values()) != expected['send_lag_sum_ns']:
        raise ValueError(f'{mode}: record count or send-lag sum mismatch')
    groups = collections.defaultdict(list)
    for row in rows:
        sequence, latency, sent, client, qtype, status, phase, kind, pad = row
        if phase != 1 or status not in range(4) or kind not in KINDS or pad:
            raise ValueError(f'{mode}: unsupported record value')
        groups['all'].append(row)
        groups[KINDS[kind]].append(row)
        if mode != 'dhcp':
            label = QTYPES.get(qtype, f'type_{qtype}')
            groups[label].append(row)
            groups[KINDS[kind] + '/' + label].append(row)
    summaries = {}
    for label, group in sorted(groups.items()):
        correct = [r for r in group if r[5] == 0]
        summaries[label] = {
            'completed': len(group), 'correct': len(correct),
            'status_counts': {key: sum(r[5] == n for r in group) for n, key in
                              enumerate(('correct', 'timeout', 'wrong', 'transport_error'))},
            'correct_latency_us': distribution([r[1] / 1000 for r in correct]),
            'send_lag_us': distribution([lag_by_sequence[r[0]] / 1000 for r in group]),
            'correct_scheduled_to_completion_us': distribution(
                [(r[1] + lag_by_sequence[r[0]]) / 1000 for r in correct])}
    return {
        'clients': source['clients'], 'offered_rate_per_second': source['rate'],
        'measurement_seconds': source['measurement_seconds'],
        'warmup_seconds': source['warmup_seconds'],
        'warmup': {key: source['warmup'][key] for key in COUNTERS},
        'measurement': {key: expected[key] for key in COUNTERS},
        'successful_rate_per_second': expected['correct_in_window'] / source['measurement_seconds'],
        'interrupted': source['interrupted'], 'output_failed': source['output_failed'],
        'tcp_connections': source['tcp_connections'],
        'tcp_reconnections': source['tcp_reconnections'],
        'tcp_idle_connection_errors': source['tcp_idle_connection_errors'],
        'groups': summaries}, source


def endpoint(row):
    root = row['processes'][0]
    own = root['user_ticks'] + root['system_ticks']
    waited = root['waited_child_user_ticks'] + root['waited_child_system_ticks']
    return {'monotonic_ns': row['monotonic_ns'], 'root_own_ticks': own,
            'root_waited_child_ticks': waited, 'tree_ticks': row['tree_cpu_ticks'],
            'live_descendant_ticks': row['tree_cpu_ticks'] - own - waited,
            'sampled_process_count': len(row['processes'])}


def cpu_interval(start, end, cores, requested_start=None, requested_end=None):
    if start is None or end is None or end['monotonic_ns'] <= start['monotonic_ns']:
        return None
    hz = start['clock_ticks_per_second']
    if end['clock_ticks_per_second'] != hz:
        raise ValueError('clock tick rate changed')
    seconds = (end['monotonic_ns'] - start['monotonic_ns']) / 1e9
    first, last = endpoint(start), endpoint(end)
    tick_delta = last['tree_ticks'] - first['tree_ticks']
    own_delta = last['root_own_ticks'] - first['root_own_ticks']
    waited_delta = last['root_waited_child_ticks'] - first['root_waited_child_ticks']
    host_delta = [b - a for a, b in zip(start['host_cpu_ticks'], end['host_cpu_ticks'])][:8]
    host_total = sum(host_delta)
    host_busy = host_total - host_delta[3] - host_delta[4]
    return {'start': first, 'end': last, 'duration_seconds': seconds,
            'clock_ticks_per_second': hz, 'tree_ticks_delta': tick_delta,
            'root_own_ticks_delta': own_delta, 'root_waited_child_ticks_delta': waited_delta,
            'tree_cpu_seconds': tick_delta / hz,
            'tree_one_core_percent': 100 * tick_delta / hz / seconds,
            'tree_whole_machine_percent': 100 * tick_delta / hz / seconds / cores,
            'root_own_one_core_percent': 100 * own_delta / hz / seconds,
            'one_tick_one_core_percentage_points': 100 / hz / seconds,
            'host_busy_percent': 100 * host_busy / host_total if host_total else None,
            'host_cpu_ticks_delta_first_eight': host_delta,
            'requested_start_error_seconds': ((start['monotonic_ns'] - requested_start) / 1e9
                                               if requested_start is not None else None),
            'requested_end_error_seconds': ((end['monotonic_ns'] - requested_end) / 1e9
                                             if requested_end is not None else None),
            'negative_tree_delta': tick_delta < 0}


def memory(rows):
    if not rows:
        return None
    values = collections.defaultdict(list)
    for row in rows:
        processes = row['processes']
        root = processes[0]
        values['root_hwm_kib'].append(root['hwm_kib'])
        values['tree_rss_kib'].append(row['tree_rss_kib'])
        values['process_count'].append(len(processes))
        values['root_fd_count'].append(root['fd_count'])
        values['root_threads'].append(root['thread_count'])
        for field in ('rss_kib', 'rss_anon_kib', 'rss_file_kib', 'rss_shmem_kib', 'pss_kib'):
            if root.get(field) is not None:
                values['root_' + field].append(root[field])
            if field != 'rss_kib' and all(p.get(field) is not None for p in processes):
                values['tree_' + field].append(sum(p[field] for p in processes))
        values['root_rss_unclassified_kib'].append(
            root['rss_kib'] - root['rss_anon_kib'] - root['rss_file_kib'] - root.get('rss_shmem_kib', 0))
        for key in ('MemTotal', 'MemAvailable', 'Shmem', 'Cached', 'Slab', 'SwapTotal', 'SwapFree'):
            if key in row['meminfo_kib']:
                values['host_' + key + '_kib'].append(row['meminfo_kib'][key])
    result = {key: distribution(data) for key, data in sorted(values.items())}
    for field in ('root_rss_shmem_kib', 'tree_rss_shmem_kib', 'root_pss_kib', 'tree_pss_kib'):
        if len(values[field]) != len(rows):
            result[field] = None
    result['sample_count'] = len(rows)
    result['uss_kib'] = None
    return result


def nearest(rows, when):
    return min(rows, key=lambda row: abs(row['monotonic_ns'] - when))


def temporal_memory(rows, active_start, active_end, drained):
    fields = ('root_rss_kib', 'root_rss_anon_kib', 'tree_rss_kib')

    def summary(selected):
        if not selected:
            return None
        data = memory(selected)
        return {'sample_count': len(selected),
                'first_sample_monotonic_ns': selected[0]['monotonic_ns'],
                'last_sample_monotonic_ns': selected[-1]['monotonic_ns'],
                'sample_span_seconds': (selected[-1]['monotonic_ns'] - selected[0]['monotonic_ns']) / 1e9,
                'kib': {field: {key: data[field][key] for key in ('min', 'median', 'max')}
                        for field in fields}}

    first_end = min(active_end, active_start + 10_000_000_000)
    last_start = max(active_start, active_end - 10_000_000_000)
    first = summary([r for r in rows if active_start <= r['monotonic_ns'] < first_end])
    last = summary([r for r in rows if last_start <= r['monotonic_ns'] <= active_end])
    late = summary([r for r in rows if max(active_start, active_end - 60_000_000_000)
                    <= r['monotonic_ns'] <= active_end])
    post = [r for r in rows if drained <= r['monotonic_ns'] <= drained + 20_000_000_000]

    def snapshot(row):
        root = row['processes'][0]
        return {'root_rss_kib': root['rss_kib'], 'root_rss_anon_kib': root['rss_anon_kib'],
                'tree_rss_kib': row['tree_rss_kib']}

    post_endpoints = None
    if post:
        start_values, end_values = snapshot(post[0]), snapshot(post[-1])
        post_endpoints = {'sample_count': len(post),
                          'first_sample_monotonic_ns': post[0]['monotonic_ns'],
                          'last_sample_monotonic_ns': post[-1]['monotonic_ns'],
                          'sample_span_seconds': (post[-1]['monotonic_ns'] - post[0]['monotonic_ns']) / 1e9,
                          'first_kib': start_values, 'last_kib': end_values,
                          'last_minus_first_kib': {field: end_values[field] - start_values[field]
                                                  for field in fields}}
    return {'active_first_10_seconds': first, 'active_last_10_seconds': last,
            'active_last_60_seconds': late,
            'active_last_minus_first_median_kib': {
                field: last['kib'][field]['median'] - first['kib'][field]['median']
                for field in fields} if first and last else None,
            'active_first_last_intervals_overlap_seconds': max(0, first_end - last_start) / 1e9,
            'post_idle_first_20_seconds_endpoints': post_endpoints,
            'interpretation': 'short-window temporal observations only; not a memory-leak test'}


def window(folder, spec, cores):
    workloads, sources = {}, {}
    for mode in ('udp', 'tcp', 'dhcp'):
        workloads[mode], sources[mode] = workload(folder, mode)
    rows = samples(folder / 'metrics.jsonl')
    if len(rows) < 2 or any(b['monotonic_ns'] <= a['monotonic_ns'] for a, b in zip(rows, rows[1:])):
        raise ValueError('missing or nonmonotonic monitor samples')
    starts = {row['processes'][0]['starttime_ticks'] for row in rows}
    if len(starts) != 1:
        raise ValueError('root process identity changed')
    warm_start = min(s['warmup_start_ns'] for s in sources.values())
    active_start = min(s['measurement_start_ns'] for s in sources.values())
    active_end = max(s['measurement_end_ns'] for s in sources.values())
    drained = max(s['run_end_ns'] for s in sources.values())
    pre = [row for row in rows if row['monotonic_ns'] <= warm_start]
    active = [row for row in rows if active_start <= row['monotonic_ns'] <= active_end]
    post = [row for row in rows if row['monotonic_ns'] >= drained]
    upstream = read_json(folder / 'upstream.json')
    upstream_counts = {key: upstream['phases']['steady'][key] for key in
                       ('requests', 'replies', 'generated_replies', 'disabled_requests',
                        'dropped_requests', 'invalid_queries', 'udp_requests', 'tcp_requests')}
    dns_sent = sum(workloads[m]['measurement']['sent'] for m in ('udp', 'tcp'))
    warnings = []
    if any(row['tree_truncated'] for row in rows):
        warnings.append('process tree truncated: tree CPU/memory incomplete')
    if any(row['children_disappeared'] for row in rows):
        warnings.append('children disappeared while sampling: endpoints can race with reaping')
    decreases = sum(b['tree_cpu_ticks'] < a['tree_cpu_ticks'] for a, b in zip(rows, rows[1:]))
    if decreases:
        warnings.append('sampled cumulative tree CPU decreased: inspect reaping/sampling race')
    if not all('proc_stat_ppid_fallback_used' in row for row in rows):
        warnings.append('legacy monitor lacks child-discovery fallback evidence; tree scope unverified')
    if not any(row['tree_pss_kib'] is not None for row in rows):
        warnings.append('PSS unavailable from proc; RSS sum double-counts shared pages; USS not inferred')
    if len(post) < 2:
        warnings.append('insufficient post-drain samples for post-idle CPU')
    if not active:
        warnings.append('no monitor samples strictly inside measurement')
    workers = []
    for path in sorted(folder.glob('worker-*.jsonl')):
        worker_rows = samples(path)
        if len(worker_rows) >= 2:
            workers.append({'sample_count': len(worker_rows),
                            'observed_interval': cpu_interval(worker_rows[0], worker_rows[-1], cores)})
    return {
        'name': spec['name'], 'profile': spec['profile'], 'implementation': spec['implementation'],
        'workloads': workloads,
        'cpu': {
            'active_measurement': cpu_interval(nearest(rows, active_start), nearest(rows, active_end),
                                               cores, active_start, active_end),
            'full_window_drained': cpu_interval(rows[0], rows[-1], cores),
            'pre_idle': cpu_interval(pre[0], pre[-1], cores) if len(pre) >= 2 else None,
            'post_idle': cpu_interval(post[0], post[-1], cores) if len(post) >= 2 else None},
        'memory': {'active_measurement': memory(active), 'full_window': memory(rows),
                   'pre_idle': memory(pre), 'post_idle': memory(post)},
        'memory_temporal': temporal_memory(rows, active_start, active_end, drained),
        'sampling': {'sample_count': len(rows), 'cpu_decreasing_intervals': decreases,
                     'children_disappeared': sum(row['children_disappeared'] for row in rows),
                     'tree_truncated': any(row['tree_truncated'] for row in rows),
                     'fallback_used_samples': sum(row.get('proc_stat_ppid_fallback_used', False) for row in rows),
                     'last_sample_after_workload_drain_seconds': (rows[-1]['monotonic_ns'] - drained) / 1e9,
                     'workload_start_skew_seconds': (max(s['measurement_start_ns'] for s in sources.values()) - active_start) / 1e9},
        'upstream_steady': upstream_counts,
        'upstream_steady_requests_per_dns_sent': upstream_counts['requests'] / dns_sent if dns_sent else None,
        'workers_observed_intervals': workers, 'warnings': warnings}


def comparison(c_value, r_value):
    return {'C': c_value, 'R': r_value, 'R_minus_C': r_value - c_value,
            'R_div_C': r_value / c_value if c_value else None,
            'relative_change_percent': 100 * (r_value - c_value) / c_value if c_value else None}


def metrics(row):
    result = {}
    for phase, data in row['cpu'].items():
        if data:
            for key in ('tree_one_core_percent', 'tree_whole_machine_percent', 'tree_cpu_seconds'):
                result[f'cpu.{phase}.{key}'] = data[key]
    for phase, data in row['memory'].items():
        if not data:
            continue
        for key in ('root_rss_kib', 'tree_rss_kib', 'root_rss_anon_kib', 'tree_rss_anon_kib',
                    'root_rss_file_kib', 'tree_rss_file_kib', 'root_rss_shmem_kib', 'tree_rss_shmem_kib',
                    'host_MemAvailable_kib', 'host_Shmem_kib'):
            if data.get(key):
                for stat in ('p50', 'min', 'max'):
                    result[f'memory.{phase}.{key}.{stat}'] = data[key][stat]
    for mode, work in row['workloads'].items():
        result[f'{mode}.successful_rate_per_second'] = work['successful_rate_per_second']
        for group, data in work['groups'].items():
            for key in ('correct_latency_us', 'send_lag_us', 'correct_scheduled_to_completion_us'):
                if data[key]:
                    for quantile in ('p50', 'p95', 'p99'):
                        result[f'{mode}.{group}.{key}.{quantile}'] = data[key][quantile]
    return result


def paired_summary(rows):
    result = {}
    for profile in sorted({row['profile'] for row in rows}):
        selected = [row for row in rows if row['profile'] == profile]
        grouped = {impl: [metrics(r) for r in selected if r['implementation'] == impl] for impl in ('C', 'R')}
        if not all(grouped.values()):
            result[profile] = {'paired_windows': 0, 'incomplete': True}
            continue
        keys = set.intersection(*(set(m) for group in grouped.values() for m in group))
        medians = {key: comparison(*(statistics.median(m[key] for m in grouped[impl])
                                    for impl in ('C', 'R'))) for key in sorted(keys)}
        pairs = []
        for index in range(0, len(selected) - 1, 2):
            pair = selected[index:index + 2]
            if {r['implementation'] for r in pair} != {'C', 'R'}:
                continue
            by_impl = {r['implementation']: metrics(r) for r in pair}
            pairs.append({'order': [r['implementation'] for r in pair],
                          'windows': [r['name'] for r in pair],
                          'metrics': {key: comparison(by_impl['C'][key], by_impl['R'][key])
                                      for key in sorted(keys)}})
        paired = {key: {
            'R_minus_C': distribution([p['metrics'][key]['R_minus_C'] for p in pairs]),
            'relative_change_percent': distribution([p['metrics'][key]['relative_change_percent'] for p in pairs
                                                     if p['metrics'][key]['relative_change_percent'] is not None])}
                  for key in sorted(keys)}
        totals = {impl: {mode: {key: (max if key == 'send_lag_max_ns' else sum)(
                                        r['workloads'][mode]['measurement'][key] for r in selected
                                        if r['implementation'] == impl) for key in COUNTERS}
                         for mode in ('udp', 'tcp', 'dhcp')} for impl in ('C', 'R')}
        result[profile] = {'window_counts': {impl: len(group) for impl, group in grouped.items()},
                           'paired_windows': len(pairs), 'median_window_metrics': medians,
                           'paired_metric_differences': paired, 'pairs': pairs,
                           'measurement_counter_totals': totals}
    return result


def health_summary(folder):
    rows = [read_json(path) for path in sorted(folder.glob('*.json'))
            if re.fullmatch(r'(initial|final|\d+-(daily|busy)-[CR]-(before|after|during-\d+))\.json', path.name)]
    def all_checked(field):
        return all(r[field] for r in rows) if rows and all(field in r for r in rows) else None
    return {'checks': len(rows), 'all_dns_ok': all_checked('dns_ok'),
            'all_wan_up': all_checked('wan_up'),
            'all_wan_probes_ok': all_checked('wan_probe_ok'),
            'min_mem_available_kib': min((r['mem_available_kib'] for r in rows), default=None),
            'production_start_ticks_unchanged': len({r['production_start_ticks'] for r in rows}) == 1,
            'production_artifact_config_hashes_unchanged': len({json.dumps(r['hashes'], sort_keys=True) for r in rows}) == 1}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cores', type=int, default=2)
    args = parser.parse_args()
    if args.cores <= 0:
        parser.error('--cores must be positive')
    state = read_json(args.input / 'state.json')
    rows, skipped = [], []
    for spec in state['windows']:
        if not re.fullmatch(r'\d+-(daily|busy)-[CR]', spec['name']):
            raise ValueError('unexpected window name')
        if spec['profile'] not in ('daily', 'busy') or spec['implementation'] not in ('C', 'R'):
            raise ValueError('unexpected workload or implementation')
        folder = args.input / spec['name']
        if not (folder / 'COMPLETE').is_file():
            skipped.append(spec['name'])
            continue
        rows.append(window(folder, spec, args.cores))
    cleanup_path = args.input / 'cleanup.json'
    cleanup = read_json(cleanup_path) if cleanup_path.is_file() else {}
    output = {
        'schema': 1, 'complete': state.get('complete', False), 'smoke': state['smoke'],
        'artifact_sha256': state['artifact_sha256'], 'cores_for_normalization': args.cores,
        'analyzer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'method': {
            'latency_unit': 'microseconds; correct completions only; nearest-rank p50/p95/p99',
            'quantiles': 'window summaries are not pooled; comparisons use median of window metrics',
            'cpu': 'cumulative root+live descendants+waited descendants; nearest measurement endpoints; full first/last endpoints also retained',
            'host_cpu': 'busy excludes idle+iowait; first eight /proc/stat fields avoid guest double count',
            'memory': 'KiB; sampled RSS tree sums double-count shared pages; PSS null when unavailable; USS never inferred',
            'cache_kind': 'intended hit/miss is generator selection, not evidence of an actual cache hit',
            'qtype': 'wire QTYPE; A includes both direct A answers and CNAME-to-A workload',
            'pairing': 'adjacent opposite implementations within profile, in execution order; descriptive small-sample comparisons, no significance claim',
            'workers': 'observed first/last worker samples only; exit CPU after final sample can be missing'},
        'health': health_summary(args.input),
        'cleanup': {key: cleanup.get(key) for key in
                    ('root_removed', 'test_processes_remaining', 'test_ports_bound')},
        'skipped_incomplete_windows': skipped, 'windows': rows, 'profiles': paired_summary(rows)}
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True, allow_nan=False) + '\n')
    print(json.dumps({'windows_analyzed': len(rows), 'incomplete_windows': skipped,
                      'complete': output['complete'], 'smoke': output['smoke']}))


if __name__ == '__main__':
    main()
