#!/usr/bin/env python3
"""Independent read-only raw archive/count/health audit; never imports analyzer."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import tarfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def quantile_check(samples, actual):
    ordered = sorted(samples)
    assert len(ordered) == actual['n'] and ordered
    for label, fraction in [('min', 0), ('p50', .5), ('p95', .95), ('max', 1)]:
        assert ordered[max(1, math.ceil(fraction * len(ordered))) - 1] == actual[label]
    assert actual['p99'] == (ordered[math.ceil(.99 * len(ordered)) - 1] if len(ordered) >= 10000 else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['base', 'summary', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    base = args.base
    identity = json.loads((base / 'identity.json').read_text())
    progress = json.loads((base / 'progress.json').read_text())
    summary = json.loads(args.summary.read_text())
    complete = json.loads((base / 'complete.json').read_text())
    assert complete == {'complete': True, 'windows': 110, 'valid': 110}
    expected = {(scene[0], round_, side) for scene in identity['scenes']
                for round_ in range(1, 6) for side in ['c', 'rust']}
    assert len(expected) == len(progress) == 110
    assert {(v['scene'], v['round'], v['side']) for v in progress} == expected
    assert all(v['valid'] and not v['errors'] for v in progress)
    assert len({v['label'] for v in progress}) == 110
    windows = {v['label']: v for v in summary['windows']}
    assert len(windows) == 110 and set(windows) == {v['label'] for v in progress}
    totals = Counter()
    archived_files = 0
    for scene in identity['scenes']:
        order = [v['side'] for v in progress if v['scene'] == scene[0]]
        assert order == [side for round_ in range(1, 6)
                         for side in (['c', 'rust'] if round_ % 2 else ['rust', 'c'])]
    for row in progress:
        label = row['label']
        folder, actual = base / 'runs' / label, windows[label]
        manifest = json.loads((base / (label + '.archive.json')).read_text())
        archive = base / (label + '.tar.gz')
        assert sha(archive) == manifest['archive_sha256']
        assert (folder / 'COMPLETE').read_text().strip() == 'complete'
        with tarfile.open(archive) as stream:
            files = [member for member in stream.getmembers() if member.isfile()]
            assert all(member.name.startswith(label + '/') for member in files)
            members = {member.name.removeprefix(label + '/'): member for member in files}
            assert len(members) == len(files)
            assert set(members) == set(manifest['files'])
            for name, digest in manifest['files'].items():
                assert sha(folder / name) == digest
                assert hashlib.sha256(stream.extractfile(members[name]).read()).hexdigest() == digest
                archived_files += 1
        expected_elf = identity['comparison'][row['side']]
        assert (folder / 'elf.sha256').read_text().split()[0] == expected_elf == actual['elf_sha256']
        if (folder / 'lifecycle.jsonl').exists():
            observations = lines(folder / 'lifecycle.jsonl')
            assert len(observations) == 20 and all(v['ok'] for v in observations)
            quantile_check([v['latency_ns'] / 1e6 for v in observations], actual['latency_ms'])
            cpu, hz = map(int, re.search(r'children_cpu_usec=(\d+) clk_tck=(\d+)',
                                       (folder / 'lifecycle.stderr').read_text()).groups())
            assert actual['cpu_us_per_operation'] == cpu / 20 and actual['cpu_hz'] == hz
            totals['lifecycle_observations'] += len(observations)
            continue
        assert (folder / 'live.sha256').read_text().split()[0] == expected_elf
        load = json.loads((folder / 'client.json').read_text())
        assert not load['interrupted'] and not load['output_failed']
        for phase, seconds in [('warmup', 5), ('measurement', 20)]:
            counts = load[phase]
            assert all(counts[key] == seconds * load['rate'] for key in ['scheduled', 'sent', 'correct'])
            assert not any(counts[key] for key in ['timeout', 'wrong', 'transport_error', 'scheduled_skipped'])
            totals[phase + '_correct'] += counts['correct']
        latencies = list(struct.iter_unpack('<QQQHHBBBB', (folder / 'client.latencies.bin').read_bytes()))
        lags = list(struct.iter_unpack('<QQ', (folder / 'client.send-lag.bin').read_bytes()))
        assert len(latencies) == len(lags) == load['measurement']['correct']
        lag_by_id = dict(lags)
        assert len(lag_by_id) == len(lags) and {v[0] for v in latencies} == set(lag_by_id)
        assert all(v[5] == 0 and v[6] == 1 and v[8] == 0 for v in latencies)
        quantile_check([v[1] / 1e6 for v in latencies], actual['latency_ms'])
        quantile_check([(v[1] + lag_by_id[v[0]]) / 1e6 for v in latencies], actual['scheduled_latency_ms'])
        before, after = (lines(folder / name)[0] for name in ['before.jsonl', 'after.jsonl'])
        assert len(before['processes']) == len(after['processes']) == 1
        first, last = before['processes'][0], after['processes'][0]
        assert (first['pid'], first['starttime_ticks']) == (last['pid'], last['starttime_ticks'])
        fields = ['user_ticks', 'system_ticks', 'waited_child_user_ticks', 'waited_child_system_ticks']
        deltas = [last[key] - first[key] for key in fields]
        assert min(deltas) >= 0
        hz = before['clock_ticks_per_second']
        assert hz == after['clock_ticks_per_second'] == 100
        operations = load['warmup']['correct'] + load['measurement']['correct']
        assert actual['cpu_ticks'] == sum(deltas) and actual['cpu_operations'] == operations
        assert actual['cpu_us_per_operation'] == sum(deltas) / hz * 1e6 / operations
        if (folder / 'client.dhcp-dora.jsonl').exists():
            dora = lines(folder / 'client.dhcp-dora.jsonl')
            assert len(dora) == load['clients'] == load['warmup']['dora_correct']
            quantile_check([(v['ack_ns'] - v['sent_ns']) / 1e6 for v in dora], actual['dora_latency_ms'])
            totals['dora_observations'] += len(dora)
    guards, cancelled_http = [], []
    for path in sorted(base.glob('*-guard-*.jsonl')):
        rows = lines(path)
        assert rows[0]['event'] == 'start' and rows[-1]['event'] == 'monitor_stopped'
        assert set(v['event'] for v in rows) == {'start', 'sample', 'monitor_stopped'}
        samples = [v for v in rows if v['event'] == 'sample']
        assert all((v['production_pid'], v['production_starttime']) == tuple(identity['production_pid_start'])
                   and v['mem_available_kib'] >= 65536 and v['ipv4_default'] == 1
                   and v['dns_ok'] in [-1, 1] and v['slow_dns_probes'] == 0 for v in samples)
        scene = path.name.split('-guard-')[0].removeprefix('base2-')
        last_window_end = 0
        for window in (v for v in progress if v['scene'] == scene):
            # Guard epoch is integer time_t; controller checkpoints retain fractions.
            assert rows[0]['epoch'] <= int(window['epoch']) <= rows[-1]['epoch']
            folder = base / 'runs' / window['label']
            start, end = (datetime.strptime((folder / name).read_text().strip(),
                         '%a %b %d %H:%M:%S UTC %Y').replace(tzinfo=timezone.utc).timestamp()
                         for name in ['start.txt', 'end.txt'])
            assert rows[0]['epoch'] <= start <= end <= rows[-1]['epoch']
            last_window_end = max(last_window_end, end)
        for sample in samples:
            if sample['http_status'] not in [-1, 403]:
                # This is an incomplete probe, never a passed HTTP observation.
                # monitor_stopped is emitted only after the signal handler sets
                # interrupted; the unchanged guard suppresses health failure then.
                assert sample == samples[-1] and sample['http_status'] == 0
                assert sample['epoch'] == rows[-1]['epoch'] and sample['epoch'] > last_window_end
                assert 0 <= rows[-1]['elapsed_s'] - sample['elapsed_s'] < 1
                cancelled_http.append({'scene': scene, 'epoch': sample['epoch'],
                    'last_window_end_epoch': last_window_end, 'http_status': 0,
                    'classification': 'terminal signal-interrupted probe; not counted as pass'})
        dns = [v['dns_rtt_ms'] for v in samples if v['dns_ok'] == 1]
        http = [v['http_rtt_ms'] for v in samples if v['http_status'] == 403]
        assert dns and http and max(dns) <= identity['threshold_ms']
        guards.append({'scene': scene, 'sha256': sha(path), 'samples': len(samples),
                       'start_epoch': rows[0]['epoch'], 'stop_epoch': rows[-1]['epoch'],
                       'dns_samples': len(dns), 'dns_max_ms': max(dns),
                       'http_samples': len(http), 'http_max_ms': max(http),
                       'memory_min_kib': min(v['mem_available_kib'] for v in samples)})
    assert len(guards) == 11 and {v['scene'] for v in guards} == {s[0] for s in identity['scenes']}
    external = lines(base / 'external-health.jsonl')
    assert all(v['exit'] == 0 and not v['error'] and v['result'].split()[0] == '200' for v in external)
    assert external[0]['epoch'] - min(v['start_epoch'] for v in guards) < 2
    assert max(v['stop_epoch'] for v in guards) - external[-1]['epoch'] < 35
    health = {str(version): {'samples': sum(v['ip_version'] == version for v in external),
              'max_ms': max(float(v['result'].split()[1]) * 1000 for v in external if v['ip_version'] == version)}
              for version in [4, 6]}
    report = {'scope': 'independent local raw recovery; no router access; no analyzer import',
              'passed': True, 'windows': len(progress), 'archive_files_verified_twice': archived_files,
              'counts': dict(totals), 'guards': guards, 'external_health': health,
              'cancelled_http_probes': cancelled_http,
              'summary_sha256': sha(args.summary), 'identity_sha256': sha(base / 'identity.json'),
              'progress_sha256': sha(base / 'progress.json'),
              'external_health_sha256': sha(base / 'external-health.jsonl'),
              'local_audit_attempts': [
                  'Attempt 1 rejected tar member comparison until observed label/ prefix was handled.',
                  'Attempt 2 rejected controller fractional epoch versus integer guard epoch; raw start/end coverage added.',
                  'Attempt 3 rejected terminal HTTP status0; source-bound interrupted cancellation classified explicitly, never passed.'],
              'limitations': ['No production router state was sampled during this offline audit.',
                             'Guard CPU is record-only by the approved frozen policy.',
                             'This confirms baseline evidence, not candidate improvement.']}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'windows': len(progress), 'files': archived_files,
                      'counts': dict(totals), 'external_health': health}))


if __name__ == '__main__':
    main()
