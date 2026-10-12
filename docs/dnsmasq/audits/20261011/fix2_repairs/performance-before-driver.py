#!/usr/bin/env python3
"""Frozen O1 paired Oracle CPU confirmation; prepare never builds or runs load."""
import argparse
import fcntl
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess
import sys
import time

MAIN_COMMIT = 'be531cee49e366bb5044443d473944dbea45b87e'
MAIN = Path('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/main-release/dnsmasq-rs')
MAIN_SHA = '0846cb40b702bc863386441b8c52daf7c0675f023fa7cbb33e471210f3d5918e'
NATIVE = Path('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/performance/native')
NATIVE_SHAS = {'m6a_loadgen': '959fcdbf1fb2cd9ac682ed51ef35ba1811f4f744d743c09fa71a8f598460c8f1',
               'm6a_upstream': 'ee5259b721a7f0f45acd769b791b5c004620f14c0af2fc067f8548bd7878da35'}
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
PROFILES = [('udp-miss', 'miss', 'miss', 2000, 4096),
            ('tcp-hit', 'tcp', 'hit', 500, 4096), ('dhcp-lease', 'dhcp', 'hit', 20, 256)]
PAIRS = 6
T95_DF5 = 2.570581835636305


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def image_digest(tools):
    sys.path.insert(0, str(tools))
    from m2_rootfs import _base_manifest
    return hashlib.sha256(json.dumps(_base_manifest(IMAGE), sort_keys=True).encode()).hexdigest()


def verify(plan):
    for name, digest in plan['assets'].items():
        require(sha(name) == digest, 'frozen asset changed: ' + name)
    require(image_digest(Path(plan['source']) / 'tools/dnsmasq') == plan['image_manifest_sha256'],
            'image content/modes/timestamps/symlinks changed')


def normalize_flags(flags):
    return re.sub(r'--remap-path-prefix=\S+=/build', '--remap-path-prefix=SOURCE=/build', flags)


def prepare(args):
    source, candidate, identity_path, out = (p.resolve() for p in
        (args.source, args.candidate, args.source_identity, args.out))
    require('private' in out.parts and not out.exists(), 'fresh private output required')
    identity = read(identity_path)
    require(identity['source_commit'] == args.source_commit, 'candidate source commit mismatch')
    require(sha(candidate) == args.candidate_sha, 'candidate ELF SHA mismatch')
    tools = source / 'tools/dnsmasq'
    sys.path.insert(0, str(tools))
    from build_package import inputs
    if 'source_files' in identity:
        require(inputs(source) == identity['source_files'], 'source identity map differs')
    groups = {}
    assets = [Path(__file__).resolve(), identity_path, IMAGE / 'usr/sbin/dnsmasq']
    image_provenance = IMAGE.parent / 'image-identity.json'
    if image_provenance.is_file():
        assets.append(image_provenance)
    for variant, elf, expected in [('main', MAIN, MAIN_SHA), ('fix', candidate, args.candidate_sha)]:
        receipt = elf.parent / 'build.json'
        build = read(receipt)
        require(sha(elf) == expected, variant + ' artifact mismatch')
        require(build['kind'] == 'release' and build['opt_level'] == '3' and build['features'] == '',
                variant + ' must be standard opt3 feature-off Oracle release')
        require(build['artifacts'] == [dict(path=elf.name, bytes=elf.stat().st_size, sha256=expected)],
                variant + ' build receipt mismatch')
        if variant == 'fix':
            require(Path(build['source']).resolve() == source, 'candidate build source mismatch')
        groups[variant] = dict(elf=str(elf), sha256=expected, bytes=elf.stat().st_size,
                               build_receipt=str(receipt), build=build)
        assets.extend([elf, receipt])
    main_flags = normalize_flags(groups['main']['build']['rustflags'])
    fix_flags = normalize_flags(groups['fix']['build']['rustflags'])
    require(fix_flags == main_flags + ' -Crelocation-model=pie -Ctarget-feature=+crt-static',
            'Oracle release flags differ beyond declared static PIE change')
    prior_native_plan = read('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/performance/plan.json')
    for filename in ('m6a_loadgen.c', 'm6a_upstream.c'):
        old_hashes = {digest for path, digest in prior_native_plan['assets'].items() if Path(path).name == filename}
        require(old_hashes == {sha(tools / filename)}, 'native source differs from prior compiled tool: ' + filename)
    for name, expected in NATIVE_SHAS.items():
        require(sha(NATIVE / name) == expected, 'native tool changed: ' + name)
        assets.append(NATIVE / name)
    assets += sorted(tools.glob('*.py'))
    assets += [tools / name for name in ('run_isolated.sh', 'm6a_loadgen.c', 'm6a_upstream.c', 'oracle_build.sh')]
    assets += [Path('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/identity.json'),
               Path('/home/ubuntu/dnsmasq-audit-fix2-20261011/private/performance/plan.json')]
    out.mkdir(parents=True)
    plan = dict(schema=1, scope='O1 long-window paired Oracle main-vs-fix CPU confirmation; not M6 or router qualification',
        source=str(source), source_commit=args.source_commit, main_commit=MAIN_COMMIT,
        source_identity=identity, groups=groups, image_manifest_sha256=image_digest(tools),
        image_provenance_available=image_provenance.is_file(), assets={str(p): sha(p) for p in assets}, windows=[],
        measurement=dict(idle_seconds=10, warmup_seconds=30, measured_seconds=120, pairs_per_profile=PAIRS,
                         cpus=dict(daemon=0, upstream=1, generator=2, controller=3), clients=20,
                         drain_seconds=[0, 1, 5], saturation=False, tracing=False, idle_subtraction=False),
        statistics=dict(primary='measurement cgroup usage_usec delta / successful completions inside the measurement epoch',
            secondary=['paired absolute microseconds difference', 'cgroup user/system microseconds per completion',
                       'raw CPU total and busy fraction', 'median pair ratio', 'AB and BA groups', 'p95 latency',
                       'idle CPU (not subtracted)', 'PSS', 'send lag', 'upstream counts', 'per-second cgroup deltas'],
            estimate='geometric mean of six paired fix/main CPU ratios; 95% t interval on paired log ratios, df=5, t=2.570581835636305',
            diagnostic='all six pair values, median, AB/BA subgroup medians, and exact 64-sign-flip p on mean paired log ratio; p is descriptive only',
            decision=['Lower 95% ratio bound >1: CPU cost increase confirmed for this Oracle workload, even if smaller than 10%.',
                      'Lower bound >1.10: increase above 10% confirmed; point estimate >1.10 without this bound retains magnitude uncertainty.',
                      'CI crossing 1 is unresolved, not proof of noise or no regression. Conflicting median/AB/BA groups require causal follow-up.',
                      'Upper bound <1.10 can bound this tested workload below the 10% scale, but cannot establish zero regression.',
                      'No W/range filter, no all-directions requirement, no pooling request samples as independent runs.',
                      'Intervals are per scenario and rely on paired log-ratio assumptions; not familywise confidence across three scenarios.'],
            invalid_data='Never delete, retry, replace or select windows. Preserve behavior errors and method failures. Report all analyzable values; incomplete/invalid/generator-limited scenarios cannot close the performance question.'),
        attribution=dict(policy='Separate diagnostic windows only after all primary windows; never substitute traced CPU for primary values.',
            sequence=['Inspect paired cgroup user/system, idle, boundary lag, per-core steal/pressure, send lag, socket/FD and upstream counts first.',
                      'For each unresolved or confirmed excess, use a separate main/fix pair with perf stat hardware counters when available; retain PMU permission/support failures.',
                      'Then use perf record or strace in separate windows to locate CPU versus syscall/wakeup/persistence cost. Never run both tracers in one window.',
                      'Symbolized or privately instrumented rebuilds and one-change counterfactuals require a separately frozen diagnostic plan; do not attribute layout/static PIE or a source function without evidence.'],
            hypotheses=['UDP miss adds upstream server-counter HashMap updates, elapsed-time read and post-policy reply-header accounting.',
                        'TCP hit now checks cache-aware local/CNAME priority before cached answer, adding lookups/parsing; branch repair may alter this path.',
                        'DHCP measures full DORA+renew+release cycles, lease/DNS publication and persistence, not one ACK. Inspect userspace versus filesystem/syscall changes.',
                        'RELRO mprotect and initial hosts rebuild occur before warmup; they cannot directly explain steady-state repeated cost, but code/layout differences may affect it.']))
    for pair in range(1, PAIRS + 1):
        order = ['main', 'fix'] if pair % 2 else ['fix', 'main']
        rotation = (pair - 1) % len(PROFILES)
        for profile, scenario, tcp, rate, names in PROFILES[rotation:] + PROFILES[:rotation]:
            seed = 0x4f314900 + pair
            for variant in order:
                ident = f'{profile}-p{pair}-{variant}'
                argv = ['sh', str(tools / 'run_isolated.sh'), 'python3', str(tools / 'm6a_window.py'),
                    '--implementation', 'rs', '--rust', groups[variant]['elf'], '--expected-rust-sha', groups[variant]['sha256'],
                    '--image-root', str(IMAGE), '--loadgen', str(NATIVE / 'm6a_loadgen'), '--upstream', str(NATIVE / 'm6a_upstream'),
                    '--preflight', '--scenario', scenario, '--tcp-profile', tcp, '--round', str(pair), '--rate', str(rate),
                    '--cache-names', str(names), '--clients', '20', '--idle-seconds', '10', '--warmup', '30', '--duration', '120',
                    '--saturation-seconds', '0', '--cpu-daemon', '0', '--cpu-upstream', '1', '--cpu-load', '2', '--cpu-control', '3',
                    '--drain-sample-seconds', '0,1,5', '--drain-timeout-seconds', '30', '--seed', str(seed), '--output', str(out / ident)]
                plan['windows'].append(dict(id=ident, profile=profile, pair=pair, variant=variant,
                                             order='AB' if order[0] == 'main' else 'BA', seed=seed, rate=rate, argv=argv))
    require(len(plan['windows']) == 36, 'plan inventory mismatch')
    save(out / 'plan.json', plan)
    print(json.dumps(dict(status='prepared-only', windows=36, plan=str(out / 'plan.json'), sha256=sha(out / 'plan.json'))))


def host_sample():
    values = dict(monotonic_ns=time.monotonic_ns(), realtime_ns=time.time_ns())
    for name in ('stat', 'loadavg', 'pressure/cpu', 'pressure/io', 'pressure/memory'):
        path = Path('/proc') / name
        if path.exists():
            values[name] = path.read_text()
    return values


def paired(values):
    ratios = [row['fix'] / row['main'] for row in values]
    logs = [math.log(ratio) for ratio in ratios]
    mean = statistics.mean(logs)
    spread = statistics.stdev(logs) / math.sqrt(len(logs))
    low, high = math.exp(mean - T95_DF5 * spread), math.exp(mean + T95_DF5 * spread)
    flips = [abs(statistics.mean(sign * value for sign, value in zip(signs, logs)))
             for signs in itertools.product((-1, 1), repeat=PAIRS)]
    pvalue = sum(value >= abs(mean) - 1e-15 for value in flips) / len(flips)
    return dict(pairs=values, pair_ratios=ratios, median_pair_ratio=statistics.median(ratios),
        geometric_mean_ratio=math.exp(mean), paired_log_t_95_ratio_interval=[low, high],
        mean_absolute_us_delta=statistics.mean(row['fix'] - row['main'] for row in values),
        median_absolute_us_delta=statistics.median(row['fix'] - row['main'] for row in values),
        order_groups={order: dict(ratios=[ratio for row, ratio in zip(values, ratios) if row['order'] == order],
                           median_ratio=statistics.median(ratio for row, ratio in zip(values, ratios) if row['order'] == order))
                      for order in ('AB', 'BA')},
        descriptive_exact_sign_flip_p=pvalue, increased_pairs=sum(value > 1 for value in ratios),
        numerical_CI_lower_bound_above_one=low > 1, numerical_CI_lower_bound_above_1_10=low > 1.10,
        below_10_percent_upper_bound=high < 1.10,
        interpretation='confirmed CPU increase' if low > 1 else 'unresolved; inspect paired/order and causal evidence' if high >= 1 else 'decrease in this scenario')


def analyze_one_window(folder, expected_sha, profile, analyze_window):
    raw = read(folder / 'result.json')
    analysis = analyze_window(folder)
    m, load, points = analysis['measurement'], read(folder / 'load.json'), read(folder / 'cpu-points.json')
    actual = read(folder / 'process-identity.json')
    require(actual['sha256'] == expected_sha, 'executed ELF mismatch')
    before, after = [points[key]['cgroup_cpu'] for key in ('measurement-start', 'measurement-end')]
    correct = m['completion_counts']['correct']
    breakdown = {key: (after[key] - before[key]) / correct for key in ('usage_usec', 'user_usec', 'system_usec')}
    errors = {phase + '_' + key: load[phase].get(key, 0) for phase in ('warmup', 'measurement')
              for key in ('scheduled_skipped', 'wrong', 'timeout', 'transport_error')}
    if profile == 'dhcp-lease':
        errors['leasefile_nonempty'] = not analysis['behavior_checks']['dhcp_release_endstate']['leasefile_empty']
    row = dict(status='analyzed', metrics=dict(cpu_us_per_correct=m['cpu_us_per_correct'], **breakdown,
        p95_ns=m['latency_ns']['p95'], cpu_total_us=m['cpu_microseconds'], correct=correct,
        busy_fraction=m['cpu_seconds'] / m['seconds'], **m['resources']['sampled_tree_peaks']),
        method_valid=analysis['methodology_valid'], analysis_errors=analysis['analysis_errors'],
        behavior_errors=errors, runner_accepted=raw.get('accepted'), runner_errors=raw.get('errors', []),
        generator_limited=m['generator_limited'], generator_limit_reasons=m['generator_limit_reasons'],
        send_lag_ns=m['send_lag_ns'], boundary_capture_lag_ns=m['cpu_capture_lag_ns'],
        cgroup_boundary_delta={key: after.get(key, 0) - before.get(key, 0) for key in
            ('usage_usec', 'user_usec', 'system_usec', 'nr_throttled', 'throttled_usec')},
        idle=raw['measurement'].get('idle_cpu'), upstream=analysis.get('upstream'))
    row['valid_for_comparison'] = (row['method_valid'] and not row['analysis_errors']
        and not any(errors.values()) and not row['generator_limited'] and raw.get('accepted') is True)
    return row, analysis


def summarize(out):
    plan = read(out / 'plan.json')
    verify(plan)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from m6a_analyze import analyze_window
    result = dict(schema=1, scope=plan['scope'], plan_sha256=sha(out / 'plan.json'), statistics=plan['statistics'],
                  windows=[], comparisons=[], errors=[])
    for window in plan['windows']:
        folder = out / window['id']
        row = {k: v for k, v in window.items() if k != 'argv'}
        result['windows'].append(row)
        row['controller_evidence'] = {suffix: dict(path=str(out / (window['id'] + suffix)), sha256=sha(out / (window['id'] + suffix)))
            for suffix in ('.log', '.host.jsonl', '.foreign-before.json') if (out / (window['id'] + suffix)).exists()}
        if not (folder / 'result.json').exists():
            row.update(status='not-analyzable', reason='no completed result');continue
        try:
            extracted, analysis = analyze_one_window(folder, plan['groups'][window['variant']]['sha256'],
                                                       window['profile'], analyze_window)
            row.update(extracted)
            save(folder / 'paired-analysis.json', analysis)
            if not row['valid_for_comparison']:
                result['errors'].append(dict(id=row['id'], reason='retained invalid/behavior-error/generator-limited window'))
        except Exception as error:
            row.update(status='analysis-failed', error=repr(error))
            result['errors'].append(dict(id=row['id'], error=repr(error)))
        row['raw_files'] = {str(p.relative_to(folder)): sha(p) for p in sorted(folder.rglob('*'))
                            if p.is_file() and 'filesystem' not in p.relative_to(folder).parts}
    result['complete'] = len(result['windows']) == 36 and all(row['status'] == 'analyzed' for row in result['windows'])
    for profile, *_ in PROFILES:
        rows = [row for row in result['windows'] if row['profile'] == profile]
        if all(row['status'] == 'analyzed' for row in rows):
            values = []
            for number in range(1, PAIRS + 1):
                pair = {row['variant']: row for row in rows if row['pair'] == number}
                values.append(dict(pair=number, order=pair['main']['order'],
                    main=pair['main']['metrics']['cpu_us_per_correct'], fix=pair['fix']['metrics']['cpu_us_per_correct']))
            comparison = dict(profile=profile, all_pairs_retained=True,
                scenario_valid=all(row['valid_for_comparison'] for row in rows), **paired(values))
            comparison['CPU_increase_confirmed'] = comparison['scenario_valid'] and comparison['numerical_CI_lower_bound_above_one']
            comparison['above_10_percent_confirmed'] = comparison['scenario_valid'] and comparison['numerical_CI_lower_bound_above_1_10']
            if not comparison['scenario_valid']:
                comparison['interpretation'] = 'unresolved methodology/behavior/generator issue; all numerical observations retained'
            result['comparisons'].append(comparison)
    save(out / 'summary.json', result)
    print(json.dumps(dict(complete=result['complete'], errors=result['errors'], comparisons=result['comparisons']), indent=2))
    return result


def run(args):
    out = args.out.resolve()
    plan = read(out / 'plan.json')
    verify(plan)
    require(os.geteuid() == 0, 'root required')
    require(not (out / 'run.json').exists(), 'attempt already exists; no replacement or automatic retry')
    ready = read(args.ready_receipt)
    require(ready.get('functional_complete') is True and ready.get('builds_complete') is True,
            'all function/build work must have completed before performance')
    require(ready.get('source_commit') == plan['source_commit'] and
            ready.get('candidate_sha256') == plan['groups']['fix']['sha256'], 'ready receipt candidate mismatch')
    save(out / 'ready-receipt.json', ready)
    sys.path.insert(0, str(Path(plan['source']) / 'tools/dnsmasq'))
    from audit_20261011_pie_cost import foreign_workloads
    from m5_final_validation import remember_job_processes, stop_job_processes
    require({0, 1, 2, 3} <= os.sched_getaffinity(0), 'CPUs 0..3 unavailable')
    state = dict(status='running', started_ns=time.time_ns(), plan_sha256=sha(out / 'plan.json'),
                 ready_receipt_sha256=sha(args.ready_receipt), windows=[])
    def interrupted(number, frame):
        raise InterruptedError(f'performance run interrupted by signal {number}')
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGINT, signal.SIGTERM)}
    with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.sched_setaffinity(0, {3})
        save(out / 'run.json', state)
        try:
            for window in plan['windows']:
                verify(plan)
                busy = foreign_workloads()
                save(out / (window['id'] + '.foreign-before.json'), busy)
                require(not busy, 'foreign experiment active before window: ' + window['id'])
                row = dict(id=window['id'], started_ns=time.time_ns())
                state['windows'].append(row);save(out / 'run.json', state)
                with (out / (window['id'] + '.log')).open('wb') as log, (out / (window['id'] + '.host.jsonl')).open('w') as host:
                    process = subprocess.Popen(window['argv'], cwd=plan['source'], stdout=log, stderr=log,
                        start_new_session=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                    known = {}
                    try:
                        deadline = time.monotonic() + 360
                        while process.poll() is None:
                            remember_job_processes(process, known)
                            host.write(json.dumps(host_sample()) + '\n');host.flush()
                            if time.monotonic() > deadline:
                                raise TimeoutError(window['id'])
                            try:
                                process.wait(timeout=1)
                            except subprocess.TimeoutExpired:
                                pass
                    finally:
                        stop_job_processes(process, known)
                row.update(returncode=process.returncode, ended_ns=time.time_ns())
                save(out / 'run.json', state);print(json.dumps(row), flush=True)
                require(not process.returncode or (out / window['id'] / 'result.json').exists(),
                        'catastrophic harness failure without result; preserve incomplete attempt')
            verify(plan)
            busy = foreign_workloads()
            save(out / 'foreign-after.json', busy)
            require(not busy, 'foreign workload after performance series')
            state['status'] = 'complete'
        except BaseException as error:
            state.update(status='incomplete', error=repr(error));raise
        finally:
            state['ended_ns'] = time.time_ns();save(out / 'run.json', state)
            for number, handler in previous.items():
                signal.signal(number, handler)
    return summarize(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prepare_args = sub.add_parser('prepare')
    for name in ('source', 'candidate', 'source-identity', 'out'):
        prepare_args.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'candidate-sha'):
        prepare_args.add_argument('--' + name, required=True)
    run_args = sub.add_parser('run')
    run_args.add_argument('--out', type=Path, required=True)
    run_args.add_argument('--ready-receipt', type=Path, required=True)
    summary_args = sub.add_parser('summarize');summary_args.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'prepare':prepare(args)
    elif args.action == 'run':run(args)
    else:summarize(args.out.resolve())


if __name__ == '__main__':
    main()
