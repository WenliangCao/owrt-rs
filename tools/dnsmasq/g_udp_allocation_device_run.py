#!/usr/bin/env python3
"""Three fixed, excluded G UDP allocation windows using the frozen device case."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import threading
import time

import perf_opt_device_run as run
import device_health_baseline as health_evidence
import udp_allocation_device_run as meter_source

# The historical E parser is reused without edits; actual counts are not targets.
meter_report = meter_source.meter_report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--health-baseline', type=Path, required=True)
    parser.add_argument('--elf-hash', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    assert plan['labels'] == [f'g-udp-allocation-r{n}-rust' for n in range(1, 4)]
    assert hashlib.sha256(Path(run.__file__).read_bytes()).hexdigest() == plan['validator_controller_sha256']
    assert hashlib.sha256(Path(meter_source.__file__).read_bytes()).hexdigest() == plan['meter_parser_module_sha256']
    assert hashlib.sha256(Path(health_evidence.__file__).read_bytes()).hexdigest() == plan['runtime_health_helper_sha256']
    assert args.elf_hash == plan['diagnostic_ELF_sha256']
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
        'meter_parser_module_sha256': plan['meter_parser_module_sha256'],
        'runtime_health_helper_sha256': plan['runtime_health_helper_sha256'],
        'production_pid_start': identity, 'production_sha256': run.PRODUCTION,
        'health_summary_sha256': hashlib.sha256(args.health_baseline.read_bytes()).hexdigest()})
    finished, failed = threading.Event(), threading.Event()
    monitor = threading.Thread(target=run.external_health, args=(args.out, finished, failed), daemon=True)
    guard = None
    guard_label = 'g-udp-allocation-guard-' + str(time.time_ns())
    label = None
    results = []
    archive_attempted = set()
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
            archive_attempted.add(label)
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
        finished.set()
        monitor.join(timeout=12)
        if monitor.is_alive() or failed.is_set() or not run.guard_check(guard):
            raise RuntimeError('health unavailable at completion')
        # All three original windows/endpoints/archives are finished. Runtime
        # capture has no fresh-baseline120s/sample-count requirement.
        prefix = health_evidence.capture_before_stop(args.out, guard_label)
        run.guard_stop(guard)
        guard = None
        for _ in range(10):
            final = run.ssh(f'cat {run.ROOT}/{guard_label}.jsonl').stdout
            (args.out / (guard_label + '.jsonl')).write_bytes(final)
            if final.endswith(b'\n'):
                rows = [json.loads(line) for line in final.splitlines()]
                if rows and rows[-1].get('event') == 'monitor_stopped':
                    break
            time.sleep(.2)
        external = [json.loads(line) for line in (args.out / 'external-health.jsonl').read_text().splitlines()]
        qualified, samples, end = health_evidence.validate_runtime_guard_evidence(
            prefix, final, external, identity, (args.out / 'pre-stop-capture.raw').read_bytes())
        run.write(args.out / 'guard-verification.json', {
            'qualified_samples': len(qualified), 'final_samples': len(samples),
            'final_tail_samples': len(samples) - len(qualified),
            'pre_stop_elapsed_seconds': qualified[-1]['elapsed_s'] if qualified else None,
            'final_elapsed_seconds': end['elapsed_s']})
    except BaseException as error:
        recovery = {}
        failure = {'error': repr(error), 'label': label, 'results': results, 'recovery': recovery}
        run.write(args.out / 'failure.json', failure)
        try:
            run.stop_owned('g_udp_allocation_diagnostic_failed')
        except Exception as stop_error:
            recovery['stop_error'] = repr(stop_error)
        if label in archive_attempted:
            recovery['first_archive_attempt_preserved'] = label
        elif label is not None:
            try:
                archive_attempted.add(label)
                run.archive_run(args.out, label)
                recovery['attempt_archived'] = label
            except Exception as archive_error:
                recovery['archive_error'] = repr(archive_error)
        run.write(args.out / 'failure.json', failure)
        raise
    finally:
        finished.set()
        cleanup = []
        if monitor.is_alive():
            monitor.join(timeout=12)
        if guard is not None:
            try:
                run.guard_stop(guard)
            except Exception as error:
                cleanup.append({'action': 'guard_stop', 'error': repr(error)})
        for suffix in ('jsonl', 'stderr'):
            target = args.out / (guard_label + '.' + suffix)
            if target.exists():
                continue
            try:
                result = run.ssh(f'cat {run.ROOT}/{guard_label}.{suffix}', check=False)
                target.write_bytes(result.stdout)
                if result.returncode:
                    raise RuntimeError('guard evidence copy exit ' + str(result.returncode))
            except Exception as error:
                cleanup.append({'action': 'copy_guard_' + suffix, 'error': repr(error)})
        run.write(args.out / 'cleanup.json', {'errors': cleanup})
    if cleanup:
        raise RuntimeError('count-only cleanup incomplete; no complete marker')
    run.write(args.out / 'complete.json', {'complete': True, 'windows': 3, 'valid': 3, 'timing_eligible': False})


if __name__ == '__main__':
    main()
