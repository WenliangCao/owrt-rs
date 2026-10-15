#!/usr/bin/env python3
"""Three fixed, excluded E UDP allocation windows using the frozen device case."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import threading
import time

import perf_opt_device_run as run


def meter_report(folder):
    meter = json.loads((folder / 'udp-alloc.json').read_text())
    assert meter['kinds'] == ['no_packet_or_error', 'other_packet', 'local', 'cached', 'stale']
    assert meter['columns'] == ['alloc', 'dealloc', 'realloc', 'requested_bytes', 'released_bytes']
    assert meter['turn_kinds'] == ['no_packet', 'cached_only', 'mixed_or_other']
    assert meter['turn_columns'] == ['turns', 'cached_queries', 'alloc', 'dealloc', 'realloc', 'requested_bytes', 'released_bytes']
    assert meter['nested_steps'] == meter['unscoped_classifications'] == 0
    queries, totals, turns = meter['queries'], meter['totals'], meter['whole_owner_turns']
    histogram = meter['cached_allocation_histogram_64_is_overflow']
    assert len(queries) == len(totals) == 5 and all(len(row) == 5 for row in totals)
    assert len(turns) == 3 and all(len(row) == 7 for row in turns) and len(histogram) == 65
    assert all(type(v) is int and v >= 0 for v in queries + histogram
               + [v for row in totals + turns for v in row])
    prewarm = json.loads((folder / 'prewarm.json').read_text())
    load = json.loads((folder / 'client.json').read_text())
    counts = prewarm['measurement']
    assert all(counts[key] == 1000 for key in ('scheduled', 'sent', 'correct'))
    assert all(counts[key] == 0 for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
    assert not prewarm['interrupted'] and not prewarm['output_failed']
    consumed = counts['correct'] + load['warmup']['correct'] + load['measurement']['correct']
    assert sum(queries[1:]) == consumed
    assert queries[3] > 0 and sum(histogram) == queries[3]
    assert sum(row[1] for row in turns) == queries[3]
    assert totals[3][0] >= sum(i * count for i, count in enumerate(histogram))
    if histogram[64] == 0:
        assert totals[3][0] == sum(i * count for i, count in enumerate(histogram))
    assert turns[1][0] > 0 and turns[1][1] > 0
    samples = [json.loads(line) for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl')
               for line in (folder / name).read_text().splitlines()]
    assert samples and all(len(row['processes']) == 1 and not row['tree_truncated'] for row in samples)
    assert all(row['processes'][0]['thread_count'] == 1 for row in samples)
    return {'raw': meter, 'consumed_packet_steps': consumed, 'thread_samples': len(samples),
            'cached_step_per_query': {key: value / queries[3] for key, value in zip(meter['columns'], totals[3])},
            'conditional_cached_only_turn_per_query': {key: value / turns[1][1]
                for key, value in zip(meter['columns'], turns[1][2:])},
            'all_owner_turn_totals': dict(zip(meter['turn_columns'], map(sum, zip(*turns)))),
            'scope': 'Counts only; all CPU/latency EXCLUDED. Whole turns are normal owner-loop totals, not startup/report/entire process lifetime.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--health-baseline', type=Path, required=True)
    parser.add_argument('--elf-hash', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    assert plan['labels'] == [f'e-udp-allocation-r{n}-rust' for n in range(1, 4)]
    assert hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest() == plan['validator_controller_sha256']
    health = json.loads(args.health_baseline.read_text())
    assert health['valid'] and health['elapsed_seconds'] >= 120 and 1 <= health['threshold_ms'] <= 700
    assert len(args.elf_hash) == 64 and all(c in '0123456789abcdef' for c in args.elf_hash)
    scene = run.SCENES[0]
    assert list(scene[1:]) == ['udp', 'hit', 200, 5, 20, 150]
    args.out.mkdir(parents=True, exist_ok=False)
    identity = run.production_identity()
    run.write(args.out / 'identity.json', {'scope': 'EXCLUDED count-only; never timing acceptance',
        'plan_sha256': hashlib.sha256(args.plan.read_bytes()).hexdigest(), 'elf_sha256': args.elf_hash,
        'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'validator_sha256': hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest(),
        'production_pid_start': identity, 'production_sha256': run.PRODUCTION,
        'health_summary_sha256': hashlib.sha256(args.health_baseline.read_bytes()).hexdigest()})
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=run.external_health, args=(args.out, finished, failed), daemon=True)
    guard = None
    guard_label = 'e-udp-allocation-guard-' + str(time.time_ns())
    label = None
    results = []
    try:
        guard = run.guard_start(identity[0], guard_label, health['threshold_ms'])
        monitor.start()
        for label in plan['labels']:
            assert run.production_identity() == identity and not failed.is_set()
            output = run.ROOT + '/runs/' + label + '/udp-alloc.json'
            command = 'DNSMASQ_UDP_ALLOC_OUT=' + shlex.quote(output) + ' setsid /bin/sh ' + run.ROOT + '/group.sh '
            command += shlex.join(['rust', label, *map(str, scene[1:])])
            with (args.out / (label + '.controller.log')).open('xb') as log:
                process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', 'openwrt', command], stdout=log, stderr=log)
                started = time.monotonic()
                while process.poll() is None:
                    if failed.wait(5) or not run.guard_check(guard) or time.monotonic() - started > 100:
                        raise RuntimeError('health/guard/case deadline')
            if not run.guard_check(guard):
                raise RuntimeError('guard unavailable at completion')
            run.ssh(f'rm -f {run.ROOT}/active.group')
            folder = run.archive_run(args.out, label)
            errors = run.validate(folder, scene, args.elf_hash)
            if process.returncode:
                errors.append('case exit ' + str(process.returncode))
            measurement = None
            try:
                measurement = meter_report(folder)
            except Exception as error:
                errors.append('meter validation: ' + repr(error))
            row = {'label': label, 'valid': not errors, 'errors': errors, 'case_exit': process.returncode,
                   'daemon_exit': 0 if process.returncode == 0 and (folder / 'COMPLETE').exists() else None,
                   'daemon_exit_basis': 'Unchanged set-e case passes final wait for daemon before COMPLETE.',
                   'meter': measurement, 'epoch': time.time()}
            results.append(row)
            run.write(args.out / 'progress.json', results)
            print(json.dumps({'label': label, 'valid': row['valid'], 'errors': errors}), flush=True)
            if errors or failed.is_set():
                raise RuntimeError('invalid allocation diagnostic; no automatic replacement')
            run.ssh('rm -rf -- ' + shlex.quote(run.ROOT + '/runs/' + label))
        run.guard_stop(guard)
        guard = None
        run.write(args.out / 'complete.json', {'complete': True, 'windows': 3, 'valid': 3, 'timing_eligible': False})
    except BaseException as error:
        run.stop_owned('e_udp_allocation_diagnostic_failed')
        recovery = {}
        if label is not None and not any(row['label'] == label for row in results):
            try:
                run.archive_run(args.out, label)
                recovery['attempt_archived'] = label
            except Exception as archive_error:
                recovery['archive_error'] = repr(archive_error)
        run.write(args.out / 'failure.json', {'error': repr(error), 'label': label, 'results': results, 'recovery': recovery})
        raise
    finally:
        finished.set()
        if monitor.is_alive():
            monitor.join(timeout=12)
        if guard is not None:
            run.guard_stop(guard)
        for suffix in ('jsonl', 'stderr'):
            result = run.ssh(f'cat {run.ROOT}/{guard_label}.{suffix}', check=False)
            (args.out / (guard_label + '.' + suffix)).write_bytes(result.stdout)


if __name__ == '__main__':
    main()
