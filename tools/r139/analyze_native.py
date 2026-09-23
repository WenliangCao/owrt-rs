#!/usr/bin/env python3
"""Verify four native-libubus registration windows and report all paired gaps.

Local evidence only. The independent caller does not replace the prior Rust
caller, establish a kernel cause, or authorize daemon adoption/deployment.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r130_registration_report import archive_hashes, argv, check, digest, hashes, proc_identity, read
from r139.analyze_affinity import integer, series, status
from r139.make_affinity_plan import BENCHMARK_SHA, C_SHA, CANDIDATE_SHA, HEALTH, NAMESPACE_SHA

CALLER_SHA = '959819747e8e9d221c8ebd02e31cb9ddf71c346a255277f997acb34b8b32ccfd'
ORDERS = [['c', 'candidate'], ['candidate', 'c'], ['candidate', 'c'], ['c', 'candidate']]
SUBJECTS = {'c': C_SHA, 'candidate': CANDIDATE_SHA}
METRICS = ('mean_us', 'p50_us', 'p95_us', 'p99_us', 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op')
ALL_METRICS = (*METRICS, 'outer_wall_us_per_op')
SOCKET, BENCH, CALLER = '/var/run/ubus/ubus.sock', '/tmp/bin/owrt-benchmark', '/tmp/bin/event-benchmark'
COMMAND = ['/sbin/ubusd', '-s', SOCKET]
IDENTITIES = {'/sbin/ubusd': C_SHA, '/tmp/bin/ubusd-rs': CANDIDATE_SHA,
              BENCH: BENCHMARK_SHA, CALLER: CALLER_SHA, '/tmp/bin/ns-exec': NAMESPACE_SHA}
LIBRARIES = {
    '/lib/libubus.so.20251202': '2967f7ce6e29e290eac0b76e88fc6b5d639763fa78be1e1b889fb088d9acda04',
    '/lib/libubox.so.20260213': 'a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063',
    '/lib/libc.so': '8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b',
    '/lib/libgcc_s.so.1': '33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c',
}


def load_plan(path):
    plan = read(path)
    check(plan['schema_version'] == 1 and plan['orders'] == ORDERS
          and plan['window_count'] == 4 and plan['case_count'] == 8
          and len(plan['steps']) == 4 and plan['iterations'] == 10000 and plan['warmup'] == 20,
          'expected four frozen two-case windows, 10000 cycles/20 warmup')
    check({k: v['sha256'] for k, v in plan['subjects'].items()} == SUBJECTS
          and plan['candidate_sha256'] == CANDIDATE_SHA and plan['benchmark']['sha256'] == BENCHMARK_SHA
          and plan['caller']['sha256'] == CALLER_SHA and plan['caller']['slot'] == CALLER
          and plan['namespace_sha256'] == NAMESPACE_SHA and plan['libraries'] == LIBRARIES,
          'exact artifact/library identities differ')
    check(plan['runtime'] == {'daemon_cpu': 1, 'caller_cpu': 0, 'socket': SOCKET,
          'daemon_argv0': '/sbin/ubusd', 'default_acl': True, 'fresh_daemon_per_case': True},
          'runtime contract differs')
    rules = plan['decision_rules']
    check(rules['primary_metric'] == 'p95_us' and rules['required_metrics'] == list(METRICS)
          and rules['gap_pct'] == 'g[w] = 100 * (candidate[w] / c[w] - 1)'
          and rules['lower'] == 'median(g) < -5 and at least 3/4 g strictly negative'
          and rules['higher'] == 'median(g) > 5 and at least 3/4 g strictly positive'
          and rules['otherwise'] == 'unresolved; does not demonstrate equivalence', 'diagnostic rules differ')
    inputs = plan['input_sha256']
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        check(not relative.is_absolute() and '..' not in relative.parts
              and re.fullmatch('[0-9a-f]{64}', expected), 'invalid frozen input')
        check(digest(ROOT / name) == expected, f'frozen input changed: {name}')
    smoke_info = plan['native_smoke']
    check(inputs[smoke_info['path']] == smoke_info['sha256'], 'smoke not frozen')
    smoke = read(ROOT / smoke_info['path'])
    check(smoke['passed'] is True and smoke['identities_unchanged'] is True
          and smoke['caller_sha256'] == CALLER_SHA
          and len(smoke['cases']) == 2 and {c['label'] for c in smoke['cases']} == {'exactc', 'combined'}
          and all(c['passed'] is True for c in smoke['cases'])
          and {s['label']: s['sha256'] for s in smoke['subjects']} == {'exactc': C_SHA, 'combined': CANDIDATE_SHA}
          and {f'/lib/{Path(p).name}': v for p, v in smoke['libraries'].items()} == LIBRARIES,
          'exact native-caller functional smoke differs')
    settings = []
    for index, step in enumerate(plan['steps']):
        args = step['argv']
        check(step['name'] == f'window-{index}' and len(args) == 17
              and args[:2] == ['tools/r95_device_smoke.py', 'ubusd']
              and args[2] == plan['subjects']['candidate']['path']
              and args[3] == f'{plan["output"]}/window-{index}' and args[-1] == '--pilot'
              and step['driver_result'] == f'{args[3]}/result.json', 'driver/window contract differs')
        flags = dict(zip(args[4:-1:2], args[5:-1:2]))
        check(set(flags) == {'--guard', '--recovery-gate', '--benchmark', '--event-benchmark',
                            '--workload-script', '--iterations'}
              and flags['--iterations'] == '10000' and flags['--benchmark'] == plan['benchmark']['path']
              and flags['--event-benchmark'] == plan['caller']['path'], 'driver flags differ')
        files = {'driver': args[0], 'candidate': args[2], 'guard': flags['--guard'],
                 'recovery_gate': flags['--recovery-gate'], 'benchmark': flags['--benchmark'],
                 'event_benchmark': flags['--event-benchmark'], 'workload': flags['--workload-script']}
        settings.append({key: inputs[value] for key, value in files.items()})
    common = {k: v for k, v in settings[0].items() if k != 'workload'}
    check(all({k: v for k, v in row.items() if k != 'workload'} == common for row in settings),
          'subjects/tools changed across windows')
    gate = read(ROOT / flags['--recovery-gate'])
    check(gate['offline_backup_verified'] is True and gate['configuration_matches_backup'] is True,
          'recovery gate invalid')
    for name in plan['prerequisites']:
        check(name in inputs, 'unfrozen prerequisite')
        result = read(ROOT / name)
        check(result.get('candidate_sha256') == CANDIDATE_SHA and all(result.get(k) is True for k in HEALTH),
              'exact-daemon prerequisite failed')
    return plan, settings, gate['boot_id']


def measurement(data, daemon_id, n=10000, warmup=20):
    for key in ('n', 'successful', 'latency_sample_count'):
        check(integer(data[key], key, 1) == n, f'{key}: count differs')
    check(integer(data['warmup'], 'warmup') == warmup and integer(data['errors'], 'errors') == 0,
          'warmup/errors differ')
    check(integer(data['subject_pid'], 'subject PID', 1) == daemon_id[0]
          and integer(data['client_pid'], 'caller PID', 1) != daemon_id[0]
          and integer(data['subject_cpu'], 'daemon CPU') == 1
          and integer(data['client_cpu'], 'caller CPU') == 0, 'caller identity/affinity differs')
    check(all(data[k] is True for k in ('full_signature_checked', 'last_type_reset_checked_each_cycle',
          'final_empty', 'final_signature_checked', 'latency_overhead_unsubtracted')), 'caller validation failed')
    check(data['latency_clock'] == 'CLOCK_MONOTONIC'
          and data['latency_quantile'] == 'ordered[round((n-1)*q)]', 'clock/quantile convention differs')
    for key in ('subject_resolution_ns', 'client_resolution_ns', 'latency_resolution_ns'):
        integer(data[key], key, 1)
    samples = data['latency_ns']
    check(len(samples) == n and all(type(x) is int and x > 0 for x in samples), 'invalid raw latency vector')
    ordered = sorted(samples)
    metrics = {'mean_us': Fraction(sum(samples), n * 1000)}
    for key, percent in (('p50_us', 50), ('p95_us', 95), ('p99_us', 99)):
        metrics[key] = Fraction(ordered[((n - 1) * percent + 50) // 100], 1000)
    for key, value in metrics.items():
        check(type(data[key]) in (int, float) and math.isfinite(data[key])
              and math.isclose(data[key], float(value), rel_tol=0, abs_tol=1e-8), f'{key}: raw arithmetic differs')
    for prefix, metric in (('subject', 'daemon_cpu_us_per_op'), ('client', 'caller_cpu_us_per_op'),
                           ('wall', 'outer_wall_us_per_op')):
        before = integer(data[prefix + '_before_ns'], prefix + ' before', 1)
        after = integer(data[prefix + '_after_ns'], prefix + ' after', 1)
        check(after > before, f'{prefix}: clock regressed')
        metrics[metric] = Fraction(after - before, n * 1000)
    check(sum(samples) <= data['wall_after_ns'] - data['wall_before_ns'], 'samples exceed outer wall interval')
    return metrics


def comparisons(indexed):
    result = {}
    for metric in ALL_METRICS:
        c = [indexed[w, 'c'][metric] for w in range(4)]
        candidate = [indexed[w, 'candidate'][metric] for w in range(4)]
        gaps = [100 * (b / a - 1) for a, b in zip(c, candidate)]
        result[metric] = {'c_by_window': list(map(float, c)), 'candidate_by_window': list(map(float, candidate)),
                          'absolute_delta_us': series([b - a for a, b in zip(c, candidate)]),
                          'delta_pct': series(gaps)}
    primary = [100 * (indexed[w, 'candidate']['p95_us'] / indexed[w, 'c']['p95_us'] - 1)
               for w in range(4)]
    decision = ('lower' if statistics.median(primary) < -5 and sum(x < 0 for x in primary) >= 3 else
                'higher' if statistics.median(primary) > 5 and sum(x > 0 for x in primary) >= 3 else 'unresolved')
    return {'paired_candidate_vs_c': result, 'primary_p95_diagnostic': decision,
            'interpretation': 'Four descriptive native-caller windows only; unresolved is not equivalence. '
                              'No absolute comparison to another caller, withdrawal of prior Rust-caller losses, or adoption.'}


def analyze(root, plan_path):
    plan, settings, boot = load_plan(plan_path)
    check((root / 'COMPLETE').is_file() and digest(root / 'plan.json') == digest(plan_path),
          'series incomplete or captured plan differs')
    check({p.name for p in root.glob('window-*') if p.is_dir()} == {f'window-{i}' for i in range(4)},
          'exactly four windows required')
    check(read(root / 'steps.json') == [{'name': f'window-{i}', 'exit': 0} for i in range(4)],
          'outer runner steps differ')
    records, windows, indexed, series_health = [], [], {}, None
    for w, expected in enumerate(settings):
        window, raw = root / f'window-{w}', root / f'window-{w}' / 'raw'
        check((raw / 'COMPLETE').is_file() and not any((base / marker).exists()
              for base in (root, window, raw) for marker in ('FAILED', 'FAILED.json', 'failure.json')),
              'failed/incomplete evidence')
        raw_hashes = archive_hashes(window)
        result = read(window / 'result.json')
        check(all(result.get(k) is True for k in HEALTH), 'driver health/cleanup failed')
        mode = {'exit': 0, 'component': 'ubusd', 'implementation': 'rs', 'iterations': 10000,
                'installed': False, 'matrix': False, 'production_mode': 'stock',
                'pilot_only': True, 'correctness_smoke_only': False}
        check(all(type(result.get(k)) is type(v) and result[k] == v for k, v in mode.items()), 'collection mode differs')
        check(all(result.get(k + '_sha256') == v for k, v in expected.items()), 'driver/tool identities differ')
        health = [read(window / f'health-{phase}.json') for phase in ('before', 'after')]
        check(health[0] == health[1] and health[0]['boot_id'] == boot and health[0]['mode'] == 'stock'
              and (series_health is None or health[0] == series_health), 'health/boot identity changed')
        series_health = health[0]
        check(set(health[0]['verified_components']) == {'procd', 'ubusd', 'netifd', 'rpcd', 'logd',
              'httpd', 'uci', 'fw4', 'reload-config'}, 'production identity coverage differs')
        check((raw / 'boot-id.txt').read_text().strip() == boot
              and (raw / 'kernel.txt').read_text().strip() == '6.12.94'
              and (raw / 'cpus-online.txt').read_text().strip() == '0-1', 'raw target differs')
        for name in ('expected-identities.txt', 'identities-before.txt', 'identities-after.txt'):
            check(hashes(raw / name) == IDENTITIES, 'raw artifact identities differ')
        check(hashes(raw / 'binary-sha256.txt') == {'/tmp/bin/ubusd-rs': CANDIDATE_SHA}, 'driver subject differs')
        check(sorted((raw / 'identity-check.log').read_text().splitlines()) == sorted(f'{p}: OK' for p in IDENTITIES),
              'artifact identity check differs')
        check(hashes(raw / 'expected-libraries.txt') == LIBRARIES, 'exact image libraries differ')
        for phase in ('before', 'after'):
            check(sorted((raw / f'library-check-{phase}.log').read_text().splitlines())
                  == sorted(f'{p}: OK' for p in LIBRARIES), 'library hash verification failed')
        check((raw / 'order.txt').read_text().split() == ORDERS[w]
              and {p.name for p in raw.iterdir() if p.is_dir()} == set(ORDERS[w]), 'case set/order differs')
        parent = status(raw / 'parent-before.status', (0, 1))[0]
        status(raw / 'parent-after.status', (0, 1), parent)
        seen = set()
        for side in ORDERS[w]:
            folder = raw / side
            check((folder / 'COMPLETE').is_file() and {p.name for p in folder.glob('*.json')} == {'register_1.json'},
                  'case incomplete/extra records')
            check(all(not (folder / p).read_bytes() for p in ('caller.log', 'daemon.log', 'objects-after.txt')),
                  'case logs/objects nonempty')
            check((folder / 'caller-exit.txt').read_text().strip() == '0'
                  and (folder / 'daemon-exit.txt').read_text().strip() in ('0', '143'), 'case exit differs')
            daemon_id = proc_identity(folder / 'before.stat')
            check(daemon_id not in seen and proc_identity(folder / 'after.stat') == daemon_id, 'daemon reused/replaced')
            seen.add(daemon_id)
            check(argv(folder / 'expected.cmdline') == COMMAND, 'expected daemon argv differs')
            for phase in ('before', 'after'):
                status(folder / f'{phase}.status', (1,), daemon_id[0])
                check(argv(folder / f'{phase}.cmdline') == COMMAND
                      and hashes(folder / f'{phase}-exe.sha256') == {f'/proc/{daemon_id[0]}/exe': SUBJECTS[side]},
                      'live daemon argv/ELF differs')
                if side == 'c':
                    check((folder / f'{phase}.maps').stat().st_size > 0, 'C library maps missing')
            check(argv(folder / 'caller-command.argv') == [BENCH, 'exec-cpu', '0', CALLER, SOCKET,
                  '10000', '20', str(daemon_id[0])], 'native caller launch argv differs')
            metrics = measurement(read(folder / 'register_1.json'), daemon_id)
            indexed[w, side] = metrics
            records.append({'window': w, 'side': side, 'raw_sha256': raw_hashes[f'{side}/register_1.json'],
                            'metrics': {k: float(v) for k, v in metrics.items()}})
        windows.append({'window': w, 'order': ORDERS[w], 'raw_sha256': raw_hashes,
                        'archive_sha256': digest(window / 'raw.tar.gz'), 'result_sha256': digest(window / 'result.json'),
                        'health_sha256': {p: digest(window / f'health-{p}.json') for p in ('before', 'after')}})
    check(len(records) == len(indexed) == 8, 'expected all eight cases')
    return {'schema_version': 1, 'scope': 'Independent native libubus registration diagnostic; no adoption',
            'verified': True, 'windows_verified': 4, 'case_count': 8, 'subjects': SUBJECTS,
            'caller_sha256': CALLER_SHA, 'helper_sha256': BENCHMARK_SHA, 'libraries': LIBRARIES,
            'plan_sha256': digest(plan_path), 'analyzer_sha256': digest(Path(__file__)),
            'support_sha256': {p: digest(ROOT / p) for p in ('tools/r130_registration_report.py',
                'tools/r139/analyze_affinity.py', 'tools/r139/make_affinity_plan.py')},
            'decision_rules': plan['decision_rules'], 'windows': windows, 'records': records,
            'comparisons': comparisons(indexed), 'limitations': [
                'All eight cases and four same-boot stock-production windows retained; no performance adoption.',
                'Native and Rust callers are independent workloads; no absolute cross-caller comparison or cancellation of prior Rust-caller tail losses.',
                'Raw chronological latency samples retain clock overhead; mean and quantiles are recomputed. CPU clocks span instrumentation and loop work.',
                'Outer wall and CPU deltas are recomputed from boundary clocks; they do not identify scheduler waiting, and CPU is not subtracted from wall.',
                'Caller performs affinity checks before/after measurement; no external live caller maps, per-cycle migration, or scheduler trace was collected.',
                'Four image libraries are checked on disk before/after; exact caller ELF and its clean dynamic loader environment are frozen. C daemon maps are retained.',
                'Guard assertions and identical before/after health establish stock identity/configuration/mount preservation and cleanup; no raw device identifiers are published.',
                'Only one-method registration is exercised; object/user events, memory and integrated components remain outside this diagnostic.',
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root, args.plan)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
    print(json.dumps({'verified_windows': 4, 'cases': 8,
                      'primary_p95_diagnostic': report['comparisons']['primary_p95_diagnostic']}))


if __name__ == '__main__':
    main()
