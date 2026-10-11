#!/usr/bin/env python3
"""A07 same-source linkage-cost screen; never an M6 performance qualification.

prepare writes a frozen plan only. run must be requested after functional
validation has finished and all other Oracle workloads have stopped. No retries
or best-attempt selection: interrupted/invalid windows remain inconclusive.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path('/home/ubuntu/dnsmasq-audit-fix-20261011')
SOURCE = ROOT / 'source-02'
TOOLS = SOURCE / 'tools/dnsmasq'
BASE = Path('/home/ubuntu/dnsmasq-tftp-repair-889fe4f5/source/private/m6b-final-hosts/identity.json')
NATIVE = Path('/home/ubuntu/dnsmasq-final135-889fe4f5/private/native')
ARTIFACTS = {
    'static': ('static-02', '2c475f83983596d2a4e7dd7927f2116bf1fa41e0d8ac6fe6ab66f98950f72549'),
    'pie': ('pie-02', 'bf0eb539b5bc788b635376ab1480b5cfb7e7b56bae838fa0c964794ab9be67d3'),
}
PROFILES = [
    ('udp-hit', 'hit', 'hit', 10000, 4096),
    ('tcp-miss', 'tcp', 'miss', 10000, 4096),
    ('dhcp-lease', 'dhcp', 'hit', 20, 256),
    ('reload-concurrent', 'reload', 'hit', 1000, 256),
]


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def prepare(out):
    if 'private' not in out.parts:
        raise ValueError('private output required')
    out.mkdir(parents=True, exist_ok=False)
    assets = [Path(__file__).resolve(), ROOT / 'private/plan-before-validation.json',
              NATIVE / 'm6a_loadgen', NATIVE / 'm6a_upstream']
    assets += [TOOLS / name for name in ['m6a_window.py', 'm6a_analyze.py', 'run_isolated.sh',
                                        'm2_rootfs.py', 'dns_service_probe.py', 'm5_final_validation.py']]
    groups = {}
    for variant, (directory, expected) in ARTIFACTS.items():
        elf = ROOT / 'private' / directory / 'dnsmasq-rs'
        receipt = elf.parent / 'build.json'
        build = read(receipt)
        if sha(elf) != expected or build['source'] != str(SOURCE) or build['opt_level'] != '3' or build['features'] != '':
            raise ValueError('candidate/source/build identity mismatch: ' + variant)
        if build['artifacts'] != [dict(path=elf.name, bytes=elf.stat().st_size, sha256=expected)]:
            raise ValueError('build receipt differs from candidate: ' + variant)
        groups[variant] = dict(elf=str(elf), sha256=expected, bytes=elf.stat().st_size)
        assets.extend([elf, receipt])
    image_root = Path(read(BASE)['image_root'])
    assets.append(image_root / 'usr/sbin/dnsmasq')
    plan = dict(scope='A07 scoped linkage-cost screen; not M6 qualification or router performance evidence',
                source=str(SOURCE), image_root=str(image_root), groups=groups,
                predefined_screen=read(ROOT / 'private/plan-before-validation.json')['pie_screen'],
                assets={str(path): sha(path) for path in assets}, windows=[])
    for round_no in range(1, 4):
        order = ['static', 'pie'] if round_no % 2 else ['pie', 'static']
        for profile, scenario, tcp, rate, names in PROFILES:
            for variant in order:
                ident = f'{profile}-r{round_no}-{variant}'
                argv = ['bash', str(TOOLS / 'run_isolated.sh'), 'python3', str(TOOLS / 'm6a_window.py'),
                        '--implementation', 'rs', '--rust', groups[variant]['elf'],
                        '--expected-rust-sha', groups[variant]['sha256'], '--image-root', str(image_root),
                        '--loadgen', str(NATIVE / 'm6a_loadgen'), '--upstream', str(NATIVE / 'm6a_upstream'),
                        '--preflight', '--scenario', scenario, '--tcp-profile', tcp, '--round', str(round_no),
                        '--rate', str(rate), '--cache-names', str(names), '--clients', '20',
                        '--warmup', '10', '--duration', '30', '--saturation-seconds', '0',
                        '--cpu-daemon', '0', '--cpu-upstream', '1', '--cpu-load', '2', '--cpu-control', '3',
                        '--drain-sample-seconds', '0,1,5', '--drain-timeout-seconds', '65',
                        '--seed', str(0x4d364100 + round_no), '--output', str(out / ident)]
                plan['windows'].append(dict(id=ident, profile=profile, variant=variant, round=round_no, argv=argv))
    save(out / 'plan.json', plan)
    print(json.dumps(dict(status='prepared-only-no-load', windows=len(plan['windows']), plan=str(out / 'plan.json'))))


def verify_assets(plan):
    for path, expected in plan['assets'].items():
        if sha(path) != expected:
            raise ValueError('frozen asset changed: ' + path)


def foreign_workloads():
    # Read-only exclusion check. Never kill another experiment's process.
    own = os.getpid()
    found = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal() or int(proc.name) == own:
            continue
        try:
            raw = (proc / 'cmdline').read_bytes().split(b'\0')
            basenames = [Path(part.decode(errors='replace')).name for part in raw if part]
            if any(name.startswith(('m5_', 'm6a_', 'm6b_', 'audit_20261011_families'))
                   or name in ('dnsmasq', 'dnsmasq-rs', 'cargo', 'rustc', 'cc1', 'cc1plus', 'make', 'ninja')
                   for name in basenames):
                found.append(dict(pid=int(proc.name), argv=[part.decode(errors='replace') for part in raw if part]))
        except (OSError, PermissionError):
            pass
    return found


def run(out):
    if os.geteuid() != 0:
        raise ValueError('sudo required')
    plan = read(out / 'plan.json')
    verify_assets(plan)
    if (out / 'run.json').exists():
        raise ValueError('this plan already has an attempt; no automatic reruns')
    busy = foreign_workloads()
    if busy:
        save(out / 'foreign-workloads.json', busy)
        raise ValueError('other Oracle workloads remain; do not start this screen')
    if not {0, 1, 2, 3} <= os.sched_getaffinity(0):
        raise ValueError('CPUs 0,1,2,3 unavailable')
    os.sched_setaffinity(0, {3})
    sys.path.insert(0, str(TOOLS))
    import m5_final_validation as cleanup
    state = dict(status='running', scope=plan['scope'], started_ns=time.time_ns(), windows=[])
    save(out / 'run.json', state)
    try:
        for window in plan['windows']:
            verify_assets(plan)
            record = dict(id=window['id'], started_ns=time.time_ns(), status='running')
            state['windows'].append(record)
            save(out / 'run.json', state)
            with (out / (window['id'] + '.log')).open('wb') as log:
                process = subprocess.Popen(window['argv'], cwd=SOURCE, stdout=log, stderr=log, start_new_session=True)
                known = {}
                try:
                    deadline = time.monotonic() + 180
                    while process.poll() is None:
                        cleanup.remember_job_processes(process, known)
                        if time.monotonic() > deadline:
                            raise TimeoutError(window['id'])
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                finally:
                    cleanup.stop_job_processes(process, known)
            record.update(returncode=process.returncode, ended_ns=time.time_ns(),
                          status='completed' if process.returncode == 0 else 'invalid')
            save(out / 'run.json', state)
            print(json.dumps(record), flush=True)
            if process.returncode:
                raise ValueError('window failed; retained without retry: ' + window['id'])
        verify_assets(plan)
        state['status'] = 'complete'
    except BaseException as error:
        state['status'] = 'terminated-incomplete' if isinstance(error, KeyboardInterrupt) else 'failed-incomplete'
        state['error'] = repr(error)
        raise
    finally:
        state['ended_ns'] = time.time_ns()
        save(out / 'run.json', state)
    return summarize(out)


def metric_comparison(static, pie):
    a, b = statistics.median(static), statistics.median(pie)
    wa = (max(static) - min(static)) / a
    wb = (max(pie) - min(pie)) / b
    delta = b / a - 1
    direction = sum(y > x for x, y in zip(static, pie))
    return dict(static_rounds=static, pie_rounds=pie, static_median=a, pie_median=b,
                relative_delta=delta, static_W=wa, pie_W=wb, max_W=max(wa, wb),
                worse_direction_rounds=direction,
                regression_flag=delta > .10 and delta > max(wa, wb) and direction == 3)


def summarize(out):
    plan = read(out / 'plan.json')
    verify_assets(plan)
    sys.path.insert(0, str(TOOLS))
    from m6a_analyze import analyze_window
    result = dict(scope=plan['scope'], plan_sha256=sha(out / 'plan.json'), windows=[], comparisons=[], errors=[],
                  limited_windows=[], complete=False, accepted=False)
    groups = plan['groups']
    result['elf_size'] = dict(static_bytes=groups['static']['bytes'], pie_bytes=groups['pie']['bytes'],
                             ratio=groups['pie']['bytes'] / groups['static']['bytes'],
                             passed=groups['pie']['bytes'] <= groups['static']['bytes'] * 1.05)
    for window in plan['windows']:
        folder = out / window['id']
        try:
            actual = read(folder / 'process-identity.json')
            observed = analyze_window(folder)
            save(folder / 'analysis.json', observed)
            expected = groups[window['variant']]['sha256']
            if actual['sha256'] != expected or observed['identity']['expected_elf_sha256'] != expected:
                raise ValueError('actual ELF identity mismatch')
            if not observed['pilot'] or not observed['methodology_valid'] or observed['analysis_errors']:
                raise ValueError('invalid scoped methodology: ' + repr(observed['analysis_errors']))
            measurement = observed['measurement']
            errors = {key: measurement['origin_counts'][key] for key in ('wrong', 'timeout', 'transport_error')}
            errors.update({'aux_' + key: value['errors'] for key, value in observed['auxiliary'].items()})
            for phase in ('warmup', 'measurement'):
                errors.update({phase + '_' + key: observed['load_counters'][phase][key]
                               for key in ('wrong', 'timeout', 'transport_error')})
            if window['profile'] == 'dhcp-lease' and not observed['behavior_checks']['dhcp_release_endstate']['leasefile_empty']:
                errors['dhcp_release_endstate'] = 1
            if any(errors.values()):
                result['errors'].append(dict(id=window['id'], behavior_errors=errors))
            metrics = dict(cpu_us_per_correct=measurement['cpu_us_per_correct'], p95_ns=measurement['latency_ns']['p95'])
            if any(value is None or not math.isfinite(value) or value <= 0 for value in metrics.values()):
                raise ValueError('missing/invalid CPU or p95 measurement')
            if measurement['generator_limited']:
                result['limited_windows'].append(dict(id=window['id'], reasons=measurement['generator_limit_reasons']))
            result['windows'].append(dict(id=window['id'], profile=window['profile'], variant=window['variant'],
                                          round=window['round'], actual_elf_sha256=actual['sha256'],
                                          metrics=metrics, errors=errors, analysis_sha256=sha(folder / 'analysis.json'),
                                          raw_inputs=observed['input_sha256']))
        except Exception as error:
            result['errors'].append(dict(id=window['id'], error=repr(error)))
    result['complete'] = len(result['windows']) == 24
    if result['complete']:
        for profile, *_ in PROFILES:
            rows = [row for row in result['windows'] if row['profile'] == profile]
            for metric in ('cpu_us_per_correct', 'p95_ns'):
                values = {variant: [next(row['metrics'][metric] for row in rows if row['variant'] == variant and row['round'] == n)
                                    for n in range(1, 4)] for variant in ('static', 'pie')}
                result['comparisons'].append(dict(profile=profile, metric=metric,
                                                 **metric_comparison(values['static'], values['pie'])))
    result['accepted'] = bool(result['complete'] and not result['errors'] and not result['limited_windows']
                              and result['elf_size']['passed'] and not any(row['regression_flag'] for row in result['comparisons']))
    result['verdict'] = 'no_linkage_cost_regression_flag_in_this_screen' if result['accepted'] else 'reject_or_document_targeted_followup'
    save(out / 'summary.json', result)
    print(json.dumps(dict(summary=str(out / 'summary.json'), accepted=result['accepted'], complete=result['complete'],
                          errors=result['errors'], limited_windows=result['limited_windows'],
                          regression_flags=[row for row in result['comparisons'] if row['regression_flag']]), indent=2))
    return int(not result['accepted'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run', 'summarize'))
    parser.add_argument('--out', type=Path, default=ROOT / 'private/pie-screen-02')
    args = parser.parse_args()
    out = args.out.resolve()
    if args.action == 'prepare':
        prepare(out)
        return 0
    if args.action == 'summarize':
        return summarize(out)
    with (ROOT / 'private/pie-screen.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Share the build owner's lock for the entire screen; nonblocking
        # acquisition prevents waiting behind a build or lock-order deadlock.
        with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as build_lock:
            fcntl.flock(build_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return run(out)


if __name__ == '__main__':
    raise SystemExit(main())
