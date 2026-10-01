#!/usr/bin/env python3
"""Read-only audit of the frozen 2026-10-01 C cost evidence; never runs a server.

Full profile tables are decoded from existing perf.data with:
perf report -i FILE --stdio --no-children --sort dso,symbol \
    --show-nr-samples --percent-limit 0 -g none
Save stdout as ROOT/analysis/{hot,mixed,tcp}-self-full.txt.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import re
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def quantiles(values):
    values = sorted(values)
    return {f'p{p}': values[(len(values) * p + 99) // 100 - 1]
            for p in ([50, 95, 99] if len(values) >= 10000 else [50, 95])} if values else {}


def corpus_items(path):
    """Read the frozen generator's length-prefixed, uncompressed questions."""
    raw, offset, items = path.read_bytes(), 0, Counter()
    while offset < len(raw):
        size = struct.unpack_from('!H', raw, offset)[0]
        packet = raw[offset + 2:offset + 2 + size]
        offset += 2 + size
        require(len(packet) == size, 'truncated corpus')
        labels, pos = [], 12
        while packet[pos]:
            length = packet[pos]
            require(length <= 63, 'corpus label encoding')
            labels.append(packet[pos + 1:pos + 1 + length].decode('ascii'))
            pos += length + 1
        kind, klass = struct.unpack_from('!HH', packet, pos + 1)
        require(kind in [1, 28] and klass == 1, 'corpus type/class')
        items[f'{".".join(labels)} {kind}'] += 1
    return items


def audit_round(root, directory, recorded, profile=False):
    path = root / directory
    data = read(path / 'result.json')
    require(data == {k: v for k, v in recorded.items()
                     if k not in ['reused_from', 'original_summary_sha256']}, f'{directory}: summary differs')
    require(data['status'] == 'passed' and data['profile_only'] == profile, f'{directory}: failed/mixed scope')
    require(sha(path / 'corpus.bin') == data['corpus']['corpus_sha256'], 'corpus identity')
    require(sha(path / 'dnsmasq.conf') == data['config_sha256'], 'config identity')
    client = data['client']
    with (path / 'client-latencies.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    count = 20000 if data['scenario'] == 'tcp' else 100000
    require(len(rows) == count == client['planned'] == client['sent'] == client['success'], 'request count')
    require(all(row['status'] == 'success' and int(row['index']) == i for i, row in enumerate(rows)), 'CSV status/index')
    require(not any(client[k] for k in ['errors', 'timeouts', 'not_sent']), 'client failures')
    rate = 2000 if data['scenario'] == 'tcp' else 10000
    for i, row in enumerate(rows):
        require(int(row['planned_ns']) == client['start_ns'] + i * 1000000000 // rate, 'offered schedule')
        require(0 < int(row['sent_ns']) <= int(row['received_ns']) <= int(row['validated_ns']), 'timestamps')
    for key, end, start in [('actual_rtt_ns', 'received_ns', 'sent_ns'),
                            ('planned_rtt_ns', 'received_ns', 'planned_ns'),
                            ('send_lateness_ns', 'sent_ns', 'planned_ns'),
                            ('validation_ns', 'validated_ns', 'received_ns')]:
        require(quantiles([int(row[end]) - int(row[start]) for row in rows]) == client[key], key)
    require(client['send_lateness_ns']['p95'] < 5000000, 'late offered schedule')
    connections = read(path / 'connection-latencies.json')
    for kind in ['connect', 'close']:
        require(len(connections[kind + '_ns']) == client[kind + '_count'], 'connection count')
        require(quantiles(connections[kind + '_ns']) == client[kind + '_ns'], 'connection quantiles')
    before, after = data['upstream_before'], data['upstream_after']
    forwarded = after['received'] - before['received']
    negative = after['negative'] - before['negative']
    require(forwarded == data['upstream_queries'] == after['sent'] - before['sent'], 'upstream counts')
    require(forwarded == (0 if data['scenario'] == 'hot' else 20000 + negative), 'upstream class total')
    planned = corpus_items(path / 'corpus.bin')
    require(sum(planned.values()) == count, 'corpus question count')
    if 'by_item' in before:
        observed = Counter(after['by_item']) - Counter(before['by_item'])
        require(sum(observed.values()) == forwarded, 'per-item total')
        for item, seen in observed.items():
            require(item in planned and not item.startswith('hot-'), 'unplanned/hot upstream query')
            require(1 <= seen <= planned[item] if item.startswith('neg-') else seen == 1, 'upstream duplicate')
        for item in planned:
            if item.startswith(('measure-unique-', 'measure-tcp-')):
                require(observed[item] == 1, 'missing unique upstream query')
    final = read(path / 'upstream-final.json')
    require(len(final['delay_ns']) == final['delay_count'] == after['delay_count'], 'upstream delay count')
    delays = final['delay_ns'][before['delay_count']:after['delay_count']]
    require(len(delays) == forwarded and not final['failures'], 'upstream delay window/failures')
    mb, ma = data['metrics_before'], data['metrics_after']
    require(ma['inserted'] - mb['inserted'] == forwarded, 'cache insertion/IPC completion')
    server_rows = re.findall(r'queries sent (\d+), retried (\d+), failed (\d+)',
                             (path / 'dnsmasq.log').read_text())
    require(len(server_rows) == 2 and server_rows[0][1:] == server_rows[1][1:] == ('0', '0'), 'raw server retry/failure counters')
    for key in ['server_retries_parent', 'server_failures_parent']:
        if key in mb:
            require(ma[key] == mb[key], key)
    if data['scenario'] == 'tcp':
        require(client['connect_count'] == client['close_count'] == after['connections'] - before['connections'] == 200, 'TCP reuse')
    samples = read(path / 'resources.json')
    peaks = {key: max(row['total'][key] for row in samples) for key in ['rss', 'pss', 'uss', 'fds', 'threads']}
    peaks.update(processes=max(row['process_count'] for row in samples), samples=len(samples),
                 vanished_during_samples=sum(row['vanished_during_sample'] for row in samples))
    require(peaks == data['sampled_peaks'], 'resource peaks')
    require(data['daemon_shutdown'] == 'exited 0; process group empty', 'shutdown')
    controls = read(path / 'perf-control.json')
    require([row['command'] for row in controls] == ['enable', 'disable'], 'perf controls')
    require(all(row['ack_hex'] == '61636b0a00' for row in controls), 'perf acknowledgement')
    require(controls[0]['acknowledged_ns'] == data['perf_enabled_ns'] < client['start_ns']
            < client['end_ns'] < data['perf_disabled_ns'] == controls[1]['acknowledged_ns'], 'perf boundaries')
    proc = {key: data['proc_after'][key] - data['proc_before'][key]
            for key in ['user_ticks', 'system_ticks', 'child_user_ticks', 'child_system_ticks']}
    require(sum(proc.values()) * 10000000 == data['proc_cpu_ns'], '100 Hz proc CPU')
    result = {key: data[key] for key in ['scenario', 'corpus', 'config_sha256', 'sampled_peaks',
              'drain_ns', 'observer_cpu_ns', 'upstream_cpu_ns', 'throughput_completed_per_second', 'daemon_shutdown']}
    result.update(directory=directory, profile_only=profile, client=client, proc_cpu_ticks=proc,
                  upstream_queries=forwarded, negative_retrievals=negative,
                  upstream_delay_ns=quantiles(delays), perf_window_ns=data['perf_disabled_ns'] - data['perf_enabled_ns'],
                  sampled_children_peak=peaks['processes'] - 1,
                  c_tcp_children_high_water=ma['tcp_high_water_since_dump'])
    for label, select in [('parent', lambda p: p['pid'] == data['daemon_pid']),
                          ('children', lambda p: p['pid'] != data['daemon_pid'])]:
        result[label + '_sampled_peaks'] = {
            key: max(sum(p[key] for p in row['processes'] if select(p)) for row in samples)
            for key in ['rss', 'pss', 'uss', 'fds', 'threads']}
    result['last_sample'] = samples[-1]['total'] | {'processes': samples[-1]['process_count']}
    result['first_sample'] = samples[0]['total'] | {'processes': samples[0]['process_count']}
    elapsed = max(10000000000, client['end_ns'] - client['start_ns'])
    require(result['throughput_completed_per_second'] == count * 1000000000 / elapsed, 'throughput')
    if not profile:
        perf = {}
        for line in (path / 'perf-stat.txt').read_text().splitlines():
            fields = line.split(';')
            if len(fields) >= 5 and fields[2] in data['perf']:
                perf[fields[2]] = {'value': float(fields[0]), 'unit': fields[1],
                                   'event_runtime_ns': int(fields[3]), 'running_percent': float(fields[4])}
        require(perf == data['perf'], 'raw perf counters')
        require(all(row['running_percent'] == 100 for row in perf.values()), 'counter multiplexing')
        require(perf['task-clock']['unit'] == '' and perf['task-clock']['value'] == data['c_cpu_ns'], 'calibrated task-clock unit')
        require(data['c_cpu_ns'] / count == data['c_cpu_ns_per_completed'], 'CPU denominator')
        require(abs(data['c_cpu_ns'] - data['proc_cpu_ns']) <= max(50000000, .1 * data['c_cpu_ns']), 'perf/proc CPU scope')
        result.update(perf=perf, c_cpu_ns=data['c_cpu_ns'], c_cpu_ns_per_completed=data['c_cpu_ns_per_completed'])
    result['artifacts'] = {file.name: sha(file) for file in sorted(path.iterdir()) if file.is_file()}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    measured, profiles = [read(root / name / 'summary.json') for name in ['measure-02', 'profile-01']]
    calibration = read(root / 'calibration-04/summary.json')
    require(calibration['status'] == 'passed' and calibration['perf_calibration']['status'] == 'passed', 'calibration')
    require(sha(root / 'calibration-04/summary.json') == measured['calibration_sha256'], 'calibration identity')
    for field in ['reference_sha256', 'tool_sha256', 'plan_sha256']:
        require(measured[field] == profiles[field] == calibration[field], field)
    old = read(root / 'measure-01/summary.json')
    require(old['status'] == 'failed' and old['rounds'][1]['status'] == 'failed', 'retain rejected mixed window')
    require(measured['rounds'][0]['original_summary_sha256'] == sha(root / 'measure-01/summary.json'), 'reuse identity')
    require(measured['status'] == profiles['status'] == 'passed', 'series status')
    require([r['scenario'] for r in measured['rounds']] == ['hot', 'mixed', 'tcp', 'mixed', 'tcp', 'hot', 'tcp', 'hot', 'mixed'], 'frozen order')
    require([r['scenario'] for r in profiles['rounds']] == ['hot', 'mixed', 'tcp'], 'profile order')
    result = {'scope': measured['scope'], 'reference_sha256': measured['reference_sha256'],
              'tool_sha256': measured['tool_sha256'], 'plan_sha256': measured['plan_sha256'],
              'audit_tool_sha256': sha(Path(__file__)),
              'dependency_identities': {Path(path).name: value
                                        for path, value in measured['reference_identity']['dependencies'].items()},
              'kernel': measured['kernel'], 'architecture': measured['architecture'], 'affinity': measured['affinity'],
              'formal_rounds': [], 'profiles': [], 'summary_artifacts': {}}
    for index, row in enumerate(measured['rounds']):
        directory = f"{'measure-01' if index == 0 else 'measure-02'}/round-{index // 3 + 1}-{row['scenario']}"
        result['formal_rounds'].append(audit_round(root, directory, row))
    for row in profiles['rounds']:
        scenario = row['scenario']
        detail = audit_round(root, f'profile-01/round-1-{scenario}', row, profile=True)
        table = root / 'analysis' / f'{scenario}-self-full.txt'
        symbols, dsos = [], Counter()
        for line in table.read_text().splitlines():
            match = re.match(r'\s*(\d+\.\d+)%\s+(\d+)\s+(\S+)\s+\[(.)\]\s+(\S+)', line)
            if match:
                pct, count, dso, _, symbol = match.groups()
                symbols.append({'period_percent_rounded': float(pct), 'samples': int(count), 'dso': dso, 'symbol': symbol})
                dsos[dso] += int(count)
        require('# Total Lost Samples: 0' in table.read_text(), 'lost profile samples')
        stderr = (root / detail['directory'] / 'perf.stderr').read_text()
        require(sum(dsos.values()) == int(re.search(r'\((\d+) samples\)', stderr)[1]), 'profile sample accounting')
        require(dsos['dnsmasq'] >= 100, 'insufficient C samples')
        detail.update(sample_count=sum(dsos.values()), dso_sample_counts=dict(dsos), top_self_symbols=symbols[:15],
                      full_table_sha256=sha(table), lost_samples=0)
        result['profiles'].append(detail)
    for path in sorted(root.glob('*/summary.json')):
        result['summary_artifacts'][str(path.relative_to(root))] = {'sha256': sha(path), 'status': read(path)['status']}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Audited 9 formal windows, 3 separate profiles; 660000 formal successes, 0 errors/timeouts.')


if __name__ == '__main__':
    main()
