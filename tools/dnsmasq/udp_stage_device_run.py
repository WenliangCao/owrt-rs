#!/usr/bin/env python3
"""Frozen fifty-window A53 diagnostic using unchanged case, guard and statistics."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import threading
import time

import perf_opt_analyze as analyze
import perf_opt_device_run as run
import device_health_baseline as health_evidence

MODES = ('full', 'receive', 'before-answer', 'skip-local')
PREFIX = 'a53-stage'
ARTIFACT_ROLES = {'exact-c', 'e', 'stage', 'f'}
EXPERIMENT_ROLE = 'stage'
GROUPS = (
    ('exact-c-vs-e', ('exact-c', None), ('e', None)),
    ('e-vs-stage-full', ('e', None), ('stage', 'full')),
    ('stage-full-vs-receive', ('stage', 'full'), ('stage', 'receive')),
    ('stage-full-vs-before-answer', ('stage', 'full'), ('stage', 'before-answer')),
    ('stage-full-vs-skip-local', ('stage', 'full'), ('stage', 'skip-local')),
)


def schedule():
    return [{'group': name, 'round': number, 'side': side,
             'artifact': (left if side == 'c' else right)[0],
             'mode': (left if side == 'c' else right)[1],
             'label': f'{PREFIX}-{name}-r{number}-{side}'}
            for name, left, right in GROUPS for number in range(1, 6)
            for side in (('c', 'rust') if number % 2 else ('rust', 'c'))]


def stage_report(folder, mode):
    prewarm = json.loads((folder / 'prewarm.json').read_text())
    load = json.loads((folder / 'client.json').read_text())
    for counts, expected in ((prewarm['measurement'], 1000),
                             (load['warmup'], 1000), (load['measurement'], 4000)):
        assert all(counts[key] == expected for key in ('scheduled', 'sent', 'correct'))
        assert all(counts[key] == 0 for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
    assert not prewarm['interrupted'] and not prewarm['output_failed']
    assert not load['interrupted'] and not load['output_failed']
    samples = [json.loads(line) for name in ('before.jsonl', 'resources.jsonl', 'after.jsonl')
               for line in (folder / name).read_text().splitlines()]
    assert samples and all(len(row['processes']) == 1 and not row['tree_truncated'] for row in samples)
    assert all(row['processes'][0]['thread_count'] == 1 for row in samples)
    owner = samples[0]['processes'][0]
    assert all((row['processes'][0]['pid'], row['processes'][0]['starttime_ticks'])
               == (owner['pid'], owner['starttime_ticks']) for row in samples)
    final_stat = (folder / 'final.stat').read_text()
    final_fields = final_stat.rsplit(')', 1)[1].split()
    assert int(final_stat.split()[0]) == owner['pid']
    assert int(final_fields[17]) == 1 and int(final_fields[19]) == owner['starttime_ticks']
    assert (folder / 'netns.txt').read_text().strip() == (folder / 'daemon.netns').read_text().strip()
    sidecar = folder / 'udp-stage.json'
    report = None
    if mode is not None:
        report = json.loads(sidecar.read_text())
        selected = MODES.index(mode)
        assert report['scope'] == 'excluded synthetic cumulative-path intervention, not oracle correctness or accepted performance'
        assert type(report['mode']) is int and report['mode'] == selected
        assert type(report['matched_queries']) is int and report['matched_queries'] == 6000
        assert type(report['prewarm_threshold']) is int and report['prewarm_threshold'] == 1000
        cuts = report['cuts_by_mode']
        assert len(cuts) == 4 and all(type(v) is int for v in cuts)
        assert cuts == [5000 if index == selected and selected else 0 for index in range(4)]
    else:
        assert not sidecar.exists()
    return {'correct_fixture_replies': 6000, 'thread_samples': len(samples), 'raw': report}


def verify_files(expected):
    checks = [f'test "$(sha256sum {shlex.quote(run.ROOT + "/" + name)} | cut -d " " -f 1)" = {digest}'
              for name, digest in expected.items()]
    run.ssh('set -eu\n' + '\n'.join(checks))


def set_slots(artifacts, left, right):
    # Immutable sources are separately verified. Replace only idle task slots.
    script = ['set -eu', f'test ! -e {run.ROOT}/active.group',
              f'for p in /proc/[0-9]*/exe; do case "$(readlink "$p" 2>/dev/null || :)" in {run.ROOT}/dnsmasq-*) exit 2;; esac; done']
    for side, artifact in (('c', left), ('rust', right)):
        entry = artifacts[artifact]
        source, target = run.ROOT + '/' + entry['name'], run.ROOT + '/dnsmasq-' + side
        script += [f'test "$(sha256sum {source} | cut -d " " -f 1)" = {entry["sha256"]}',
                   f'cp {source} {target}.new', f'chmod 755 {target}.new',
                   f'test "$(sha256sum {target}.new | cut -d " " -f 1)" = {entry["sha256"]}',
                   f'mv {target}.new {target}']
    run.ssh('\n'.join(script))


def comparisons(results):
    output = {}
    for name, left, right in GROUPS:
        sides = [[row for row in results if row['group'] == name and row['side'] == side]
                 for side in ('c', 'rust')]
        if any(len(rows) != 5 or not all(row['valid'] for row in rows) for rows in sides):
            continue
        a, b = [[row['measurement'] for row in sorted(rows, key=lambda row: row['round'])] for rows in sides]
        values = {key + '_ms': analyze.compare([row['latency_ms'][key] for row in a],
                                              [row['latency_ms'][key] for row in b]) for key in ('p50', 'p95')}
        values['cpu_us'] = analyze.compare([row['cpu_us_per_operation'] for row in a],
                                           [row['cpu_us_per_operation'] for row in b],
                                           cpu=([row['cpu_ticks'] for row in a], [row['cpu_ticks'] for row in b]))
        for key in ('rss_median_kib', 'rss_peak_kib', 'anon_peak_kib', 'file_peak_kib',
                    'shmem_peak_kib', 'tree_fd_peak', 'parent_fd_peak'):
            values[key] = {'left': analyze.spread([row[key] for row in a]),
                           'right': analyze.spread([row[key] for row in b])}
        output[name] = {'left': left, 'right': right, 'metrics': values}
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--health-baseline', type=Path, required=True)
    parser.add_argument('--experiment-hash', '--stage-hash', dest='stage_hash', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    assert plan['schedule'] == schedule()
    assert hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest() == plan['controller_sha256']
    assert hashlib.sha256(Path(analyze.__file__).read_bytes()).hexdigest() == plan['analyzer_sha256']
    assert hashlib.sha256(Path(health_evidence.__file__).read_bytes()).hexdigest() == plan['health_evidence_sha256']
    health = json.loads(args.health_baseline.read_text())
    assert health['valid'] and health['elapsed_seconds'] >= 120 and 1 <= health['threshold_ms'] <= 700
    assert len(args.stage_hash) == 64 and all(c in '0123456789abcdef' for c in args.stage_hash)
    artifacts = plan['artifacts']
    artifacts[EXPERIMENT_ROLE]['sha256'] = args.stage_hash
    assert all(entry['name'] == PREFIX + '-artifact-' + name for name, entry in artifacts.items())
    assert set(artifacts) == ARTIFACT_ROLES
    assert all(len(entry['sha256']) == 64 and all(c in '0123456789abcdef' for c in entry['sha256'])
               for entry in artifacts.values())
    scene = run.SCENES[0]
    assert list(scene[1:]) == ['udp', 'hit', 200, 5, 20, 150]
    args.out.mkdir(parents=True, exist_ok=False)
    identity = run.production_identity()
    verify_files({**plan['measurement_artifacts'], **plan['original_slots'],
                  **{entry['name']: entry['sha256'] for entry in artifacts.values()}})
    run.ssh(f'test ! -e {run.ROOT}/STOP && test ! -e {run.ROOT}/active.group')
    run.write(args.out / 'identity.json', {'scope': plan['scope'], 'production_pid_start': identity,
        'production_sha256': run.PRODUCTION, 'artifacts': artifacts, 'schedule': schedule(),
        'plan_sha256': hashlib.sha256(args.plan.read_bytes()).hexdigest(),
        'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'controller_sha256': plan['controller_sha256'], 'analyzer_sha256': plan['analyzer_sha256'],
        'health_evidence_sha256': plan['health_evidence_sha256'],
        'health_summary_sha256': hashlib.sha256(args.health_baseline.read_bytes()).hexdigest()})
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=run.external_health, args=(args.out, finished, failed), daemon=True)
    guard = guard_label = label = current_group = None
    results = []
    archive_attempted = set()
    cleanup_errors = []
    try:
        guard_label = PREFIX + '-guard-' + str(time.time_ns())
        guard = run.guard_start(identity[0], guard_label, health['threshold_ms'])
        monitor.start()
        for window in schedule():
            assert run.production_identity() == identity and not failed.is_set()
            if window['group'] != current_group:
                _, left, right = next(group for group in GROUPS if group[0] == window['group'])
                verify_files(plan['measurement_artifacts'])
                set_slots(artifacts, left[0], right[0])
                current_group = window['group']
            label = window['label']
            command = ''
            if window['mode'] is not None:
                command = 'DNSMASQ_UDP_STAGE=' + shlex.quote(window['mode']) + ' DNSMASQ_UDP_STAGE_OUT='
                command += shlex.quote(run.ROOT + '/runs/' + label + '/udp-stage.json') + ' '
            command += 'setsid /bin/sh ' + run.ROOT + '/group.sh '
            command += shlex.join([window['side'], label, *map(str, scene[1:])])
            with (args.out / (label + '.controller.log')).open('xb') as log:
                process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', 'openwrt', command], stdout=log, stderr=log)
                started = time.monotonic()
                while process.poll() is None:
                    if failed.wait(5) or not run.guard_check(guard) or time.monotonic() - started > 100:
                        raise RuntimeError('health/guard/case deadline')
            if not run.guard_check(guard):
                raise RuntimeError('guard unavailable at completion')
            run.ssh(f'rm -f {run.ROOT}/active.group')
            archive_attempted.add(label)
            folder = run.archive_run(args.out, label)
            expected = artifacts[window['artifact']]['sha256']
            errors = run.validate(folder, scene, expected)
            if process.returncode:
                errors.append('case exit ' + str(process.returncode))
            diagnostic = measurement = None
            try:
                diagnostic = stage_report(folder, window['mode'])
                measurement = analyze.traffic(folder, {'valid': not errors})
            except Exception as error:
                errors.append('diagnostic/traffic validation: ' + repr(error))
            row = {**window, 'valid': not errors, 'errors': errors, 'elf_sha256': expected,
                   'case_exit': process.returncode, 'daemon_exit': 0 if process.returncode == 0 and (folder / 'COMPLETE').exists() else None,
                   'daemon_exit_basis': 'Unchanged set-e case passes final wait for daemon before COMPLETE.',
                   'diagnostic': diagnostic, 'measurement': measurement, 'epoch': time.time()}
            results.append(row)
            run.write(args.out / 'progress.json', results)
            print(json.dumps({'label': label, 'valid': row['valid'], 'errors': errors}), flush=True)
            if errors or failed.is_set():
                raise RuntimeError('invalid diagnostic; no automatic replacement')
            run.ssh('rm -rf -- ' + shlex.quote(run.ROOT + '/runs/' + label))
        finished.set()
        monitor.join(timeout=12)
        if monitor.is_alive() or failed.is_set():
            raise RuntimeError('external health failed or did not finish')
        if not run.guard_check(guard):
            raise RuntimeError('guard unavailable at final completion')
        # All windows, CPU endpoints and archives are already complete. Retain
        # a capture-time qualification boundary before SIGTERM can cancel probes.
        health_evidence.capture_before_stop(args.out, guard_label)
        run.guard_stop(guard)
        guard = None
        run.write(args.out / 'summary.json', {'scope': plan['scope'], 'windows': results, 'comparisons': comparisons(results)})
    except BaseException as error:
        recovery = {}
        failure_record = {'error': repr(error), 'label': label, 'results': results, 'recovery': recovery}
        run.write(args.out / 'failure.json', failure_record)
        try:
            run.stop_owned(PREFIX.replace('-', '_') + '_diagnostic_failed')
        except Exception as stop_error:
            recovery['stop_owned_error'] = repr(stop_error)
            cleanup_errors.append({'action': 'stop_owned', 'error': repr(stop_error)})
        if label in archive_attempted:
            recovery['archive_attempt_preserved'] = label
            recovery['archive_manifest_complete'] = (args.out / (label + '.archive.json')).exists()
        elif label is not None:
            try:
                archive_attempted.add(label)
                run.archive_run(args.out, label)
                recovery['attempt_archived'] = label
            except Exception as archive_error:
                recovery['archive_error'] = repr(archive_error)
                cleanup_errors.append({'action': 'archive_failed_window', 'error': repr(archive_error)})
        run.write(args.out / 'failure.json', failure_record)
        raise
    finally:
        finished.set()
        if monitor.is_alive():
            monitor.join(timeout=12)
        if guard is not None:
            try:
                run.guard_stop(guard)
            except Exception as error:
                cleanup_errors.append({'action': 'guard_stop', 'error': repr(error)})
        if guard_label is not None:
            for suffix in ('jsonl', 'stderr'):
                try:
                    result = run.ssh(f'cat {run.ROOT}/{guard_label}.{suffix}', check=False)
                    (args.out / (guard_label + '.' + suffix)).write_bytes(result.stdout)
                    if result.returncode:
                        raise RuntimeError('guard evidence copy exit ' + str(result.returncode))
                except Exception as error:
                    cleanup_errors.append({'action': 'copy_guard_' + suffix, 'error': repr(error)})
        # Leave a failed active-group marker untouched; recovery then needs its
        # ownership evidence checked before retrying restoration manually.
        try:
            set_slots(artifacts, 'e', 'f')
            verify_files(plan['original_slots'])
            assert run.production_identity() == identity
            run.write(args.out / 'restored.json', {'slots': plan['original_slots'], 'production_pid_start': identity})
        except Exception as error:
            run.write(args.out / 'restore-failure.json', {'error': repr(error)})
            cleanup_errors.append({'action': 'restore_slots', 'error': repr(error)})
        run.write(args.out / 'cleanup.json', {'errors': cleanup_errors})
    if cleanup_errors:
        raise RuntimeError('diagnostic cleanup incomplete; see cleanup.json')
    try:
        qualified, samples, end = health_evidence.validate_guard_evidence(
            (args.out / 'pre-stop-prefix.jsonl').read_bytes(),
            (args.out / (guard_label + '.jsonl')).read_bytes(),
            [json.loads(line) for line in (args.out / 'external-health.jsonl').read_text().splitlines()], identity,
            (args.out / 'pre-stop-capture.raw').read_bytes())
    except Exception as error:
        failure = {'error': repr(error),
                  'scope': 'Final guard evidence gate; original windows retained, no complete marker',
                  'results': results}
        run.write(args.out / 'failure.json', failure)
        try:
            run.stop_owned(PREFIX.replace('-', '_') + '_final_guard_evidence_failed')
        except Exception as stop_error:
            failure['stop_owned_error'] = repr(stop_error)
            run.write(args.out / 'failure.json', failure)
        raise
    run.write(args.out / 'guard-verification.json', {'qualified_samples': len(qualified),
              'final_samples': len(samples), 'final_tail_samples': len(samples) - len(qualified),
              'pre_stop_elapsed_seconds': qualified[-1]['elapsed_s'], 'final_elapsed_seconds': end['elapsed_s']})
    run.write(args.out / 'complete.json', {'complete': True, 'windows': len(schedule()),
              'valid': len(results), 'candidate_eligible': False})


if __name__ == '__main__':
    main()
