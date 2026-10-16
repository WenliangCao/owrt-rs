#!/usr/bin/env python3
"""Original 125s guard baseline, qualified from bytes captured before SIGTERM."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import threading
import time

import perf_opt_device_run as run

CONTROLLER_SHA = '7c93cfb1ec060a11cebfa14d1a5cf1a31d6bdf40853ed6c4287b4630108e21df'


def complete_prefix(capture):
    """Keep only whole JSONL records, without inspecting probe outcomes."""
    end = capture.rfind(b'\n') + 1
    assert end > 0, 'no complete pre-stop record'
    return capture[:end]


def capture_before_stop(out, label):
    capture = run.ssh(f'cat {run.ROOT}/{label}.jsonl').stdout
    (out / 'pre-stop-capture.raw').write_bytes(capture)
    prefix = complete_prefix(capture)
    (out / 'pre-stop-prefix.jsonl').write_bytes(prefix)
    run.write(out / 'stop-request.json', {'epoch_before_stop_call': time.time(),
              'monotonic_before_stop_call': time.monotonic(),
              'complete_prefix_bytes': len(prefix), 'captured_bytes': len(capture),
              'prefix_sha256': hashlib.sha256(prefix).hexdigest(),
              'capture_sha256': hashlib.sha256(capture).hexdigest()})
    return prefix


def validate_guard_evidence(prefix, final, external, production, capture):
    assert prefix.endswith(b'\n') and final.endswith(b'\n')
    assert complete_prefix(capture) == prefix, 'prefix does not match complete capture records'
    assert final.startswith(capture), 'final evidence changed captured bytes'
    assert final.startswith(prefix), 'final evidence changed the pre-stop prefix'
    before = [json.loads(line) for line in prefix.splitlines()]
    rows = [json.loads(line) for line in final.splitlines()]
    assert before[0]['event'] == rows[0]['event'] == 'start'
    assert [before[0]['production_pid'], before[0]['production_starttime']] == production
    assert all(row['event'] == 'sample' for row in before[1:])
    assert rows[-1]['event'] == 'monitor_stopped'
    assert all(row['event'] == 'sample' for row in rows[1:-1]), 'unexpected/stop event'
    qualified, all_samples = before[1:], rows[1:-1]
    assert qualified
    assert qualified[-1]['elapsed_s'] >= 120, 'pre-stop coverage below120s'
    elapsed = [row['elapsed_s'] for row in all_samples] + [rows[-1]['elapsed_s']]
    assert elapsed == sorted(elapsed) and rows[-1]['elapsed_s'] >= 120
    # These safety gates cover every final sample, including shutdown tail.
    assert all([row['production_pid'], row['production_starttime']] == production for row in all_samples)
    assert all(row['mem_available_kib'] >= 65536 for row in all_samples)
    assert rows[0]['ipv4_default_initial'] != 1 or all(row['ipv4_default'] == 1 for row in all_samples)
    # Probe qualification has an actual capture-time boundary, never status-based
    # filtering. The complete final tail remains evidence, not a successful probe.
    assert all(row['dns_ok'] in (-1, 1) for row in qualified)
    assert all(row['http_status'] in (-1, 200, 301, 302, 401, 403) for row in qualified)
    dns = sorted(row['dns_rtt_ms'] for row in qualified if row['dns_ok'] == 1)
    http = [row['http_rtt_ms'] for row in qualified if row['http_status'] != -1]
    assert dns and http
    assert {row['ip_version'] for row in external} == {4, 6}
    assert all(row['exit'] == 0 and row['result'].startswith('200 ') for row in external)
    return qualified, all_samples, rows[-1]


def validate_baseline(prefix, final, external, production, capture):
    qualified, all_samples, end = validate_guard_evidence(prefix, final, external, production, capture)
    dns = sorted(row['dns_rtt_ms'] for row in qualified if row['dns_ok'] == 1)
    http = [row['http_rtt_ms'] for row in qualified if row['http_status'] != -1]
    p95 = dns[max(0, math.ceil(len(dns) * .95) - 1)]
    threshold = math.ceil(max(200, p95 * 10))
    assert threshold <= 700
    return {'valid': True, 'elapsed_seconds': qualified[-1]['elapsed_s'],
            'final_elapsed_seconds': end['elapsed_s'], 'dns_samples': len(dns),
            'dns_p95_ms': p95, 'dns_max_ms': max(dns), 'http_samples': len(http),
            'http_max_ms': max(http), 'threshold_ms': threshold,
            'qualification_scope': 'Complete prefix captured and saved before guard stop request',
            'qualified_samples': len(qualified), 'final_samples': len(all_samples),
            'final_tail_samples': len(all_samples) - len(qualified),
            'pre_stop_prefix_sha256': hashlib.sha256(prefix).hexdigest(),
            'raw_sha256': hashlib.sha256(final).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--label-prefix', required=True)
    args = parser.parse_args()
    assert args.label_prefix and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in args.label_prefix)
    assert hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest() == CONTROLLER_SHA
    args.out.mkdir(parents=True, exist_ok=False)
    run.ssh(f'test ! -e {run.ROOT}/STOP && test ! -e {run.ROOT}/active.group')
    production = run.production_identity()
    label = args.label_prefix + '-' + str(time.time_ns())
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=run.external_health, args=(args.out, finished, failed), daemon=True)
    guard = None
    error = None
    try:
        guard = run.guard_start(production[0], label, 200)
        run.write(args.out / 'start.json', {'production_pid_start': production, 'guard_pid_start': guard,
                  'label': label, 'epoch': time.time(),
                  'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
        monitor.start()
        started = time.monotonic()
        while time.monotonic() - started < 125:
            if failed.wait(5) or not run.guard_check(guard):
                raise RuntimeError('health failure or guard identity changed')
        prefix = capture_before_stop(args.out, label)
        run.guard_stop(guard)
        guard = None
        finished.set()
        monitor.join(timeout=12)
        if monitor.is_alive() or failed.is_set():
            raise RuntimeError('external health failed or did not finish')
        for _ in range(10):
            raw = run.ssh(f'cat {run.ROOT}/{label}.jsonl').stdout
            rows = [json.loads(line) for line in raw.splitlines()]
            if rows and rows[-1].get('event') == 'monitor_stopped':
                break
            time.sleep(.2)
        (args.out / 'health-baseline.jsonl').write_bytes(raw)
        (args.out / 'health-baseline.stderr').write_bytes(run.ssh(f'cat {run.ROOT}/{label}.stderr').stdout)
        after = run.production_identity()
        run.ssh(f'test ! -e {run.ROOT}/STOP && test ! -e {run.ROOT}/active.group')
        assert after == production
        external = [json.loads(line) for line in (args.out / 'external-health.jsonl').read_text().splitlines()]
        summary = validate_baseline(prefix, raw, external, production,
                                    (args.out / 'pre-stop-capture.raw').read_bytes())
        run.write(args.out / 'summary.json', summary)
        run.write(args.out / 'receipt.json', {'production_pid_start_before': production,
                  'production_pid_start_after': after, 'production_sha256': run.PRODUCTION,
                  'guard_label': label, 'external_checks': len(external), 'all_external_passed': True,
                  'minimum_available_memory_kib': min(row['mem_available_kib'] for row in rows if row['event'] == 'sample'),
                  'guard_end': 'explicit SIGTERM; monitor_stopped; no STOP or active group',
                  'files': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in sorted(args.out.iterdir()) if path.is_file()}})
        print(json.dumps(summary), flush=True)
    except BaseException as caught:
        error = caught
        failure = {'error': repr(caught), 'label': label, 'epoch': time.time()}
        run.write(args.out / 'failure.json', failure)
        try:
            run.stop_owned('health_baseline_prefix_failed')
        except Exception as stop_error:
            failure['stop_error'] = repr(stop_error)
            run.write(args.out / 'failure.json', failure)
        raise
    finally:
        finished.set()
        cleanup = []
        if guard is not None:
            try:
                run.guard_stop(guard)
            except Exception as stop_error:
                cleanup.append(repr(stop_error))
        if monitor.is_alive():
            monitor.join(timeout=12)
        if error is not None:
            for suffix in ('jsonl', 'stderr'):
                try:
                    result = run.ssh(f'cat {run.ROOT}/{label}.{suffix}', check=False)
                    (args.out / ('failed-guard.' + suffix)).write_bytes(result.stdout)
                except Exception as copy_error:
                    cleanup.append(repr(copy_error))
        if cleanup:
            run.write(args.out / 'cleanup-errors.json', cleanup)


if __name__ == '__main__':
    main()
