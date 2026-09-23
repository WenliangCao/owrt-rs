#!/usr/bin/env python3
"""Verify frozen R136/C monitor and memory router coverage; local evidence only."""
import argparse
from fractions import Fraction
import json
from math import comb
from pathlib import Path, PurePosixPath
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r130_registration_report import archive_hashes, argv, check, digest, hashes, proc_identity, read, unique
from r139.analyze_affinity import integer, series, status
from r139.make_affinity_plan import BENCHMARK_SHA, C_SHA, CANDIDATE_SHA, HEALTH, NAMESPACE_SHA
from r134.ubusd_stress_oracle import HELPER_SHA, LIBRARIES, validate

POLICY = Path(__file__).with_name('policy.json')
MEMORY_SHA = '2db999c1d14c641eb689c161c444a6355c617694eb6acaa20aaf4bd142f7b62a'
SUBJECTS = {'c': C_SHA, 'candidate': CANDIDATE_SHA}
SOCKET, BENCH, CALLER = '/var/run/ubus/ubus.sock', '/tmp/bin/owrt-benchmark', '/tmp/bin/event-benchmark'
COMMAND = ['/sbin/ubusd', '-s', SOCKET]
LATENCY = ('mean_us', 'p95_us', 'p99_us')
METRICS = ('mean_us', 'p50_us', 'p95_us', 'p99_us', 'wall_us_per_op', 'daemon_cpu_us_per_op', 'caller_cpu_us_per_op')
MEMORY = ('rss_kib', 'rssanon_kib', 'vmdata_kib', 'vmhwm_kib')
PHASES = (('empty', 0), ('connected', 0), ('monitored_small', 16), ('large_32768', 32768),
          ('large_262144', 262144), ('large_786432', 786432), ('stopped_connected', 0), ('disconnected', 0))
SUPPORT = ('tools/r130_registration_report.py', 'tools/r139/analyze_affinity.py',
           'tools/r139/make_affinity_plan.py', 'tools/r134/ubusd_stress_oracle.py')


def binomial_tail(k, n=10):
    check(type(k) is int and 0 <= k <= n, 'invalid support count')
    return Fraction(sum(comb(n, j) for j in range(k, n + 1)), 2 ** n)


def holm(values):
    """Return adjusted values in input order; all arithmetic remains rational."""
    check(values and all(0 <= p <= 1 for p in values), 'invalid p values')
    adjusted, previous = [Fraction(0)] * len(values), Fraction(0)
    for rank, index in enumerate(sorted(range(len(values)), key=values.__getitem__)):
        previous = max(previous, min(Fraction(1), (len(values) - rank) * values[index]))
        adjusted[index] = previous
    return adjusted


def exact(value):
    return {'numerator': value.numerator, 'denominator': value.denominator, 'value': float(value)}


def summary(values):
    return {**series(values), 'minimum': float(min(values)), 'maximum': float(max(values))}


def performance_comparisons(indexed):
    check(set(indexed) == {(w, s) for w in range(10) for s in SUBJECTS}, 'ten complete paired windows required')
    result, hypotheses, pvalues = {}, [], []
    for metric in METRICS:
        c = [indexed[w, 'c'][metric] for w in range(10)]
        rust = [indexed[w, 'candidate'][metric] for w in range(10)]
        check(all(v > 0 for v in c + rust), 'nonpositive metric')
        ratios = [b / a for a, b in zip(c, rust)]
        median = statistics.median(ratios)
        result[metric] = {'c_by_window': list(map(float, c)), 'r136_by_window': list(map(float, rust)),
                          'ratios_by_window': list(map(float, ratios)), 'median_ratio': exact(median),
                          'absolute_delta_us': summary([b - a for a, b in zip(c, rust)]),
                          'delta_pct': summary([100 * (r - 1) for r in ratios]),
                          'below_0_99_windows': sum(r < Fraction(99, 100) for r in ratios),
                          'above_1_01_windows': sum(r > Fraction(101, 100) for r in ratios),
                          'median_within_1pct': abs(median - 1) <= Fraction(1, 100)}
        if metric in LATENCY:
            for direction, boundary in (('lower', Fraction(99, 100)), ('higher', Fraction(101, 100))):
                k = sum(r < boundary if direction == 'lower' else r > boundary for r in ratios)
                pvalue = binomial_tail(k)
                hypotheses.append({'metric': metric, 'direction': direction, 'threshold': exact(boundary),
                                   'supporting_windows': k, 'n': 10, 'raw_p': exact(pvalue)})
                pvalues.append(pvalue)
    check(len(hypotheses) == 6, 'complete six-test family required')
    for row, adjusted in zip(hypotheses, holm(pvalues)):
        row.update({'holm_p': exact(adjusted), 'confirmed': adjusted <= Fraction(1, 20)})
    for metric in LATENCY:
        confirmed = [h['direction'] for h in hypotheses if h['metric'] == metric and h['confirmed']]
        check(len(confirmed) <= 1, 'opposing directions cannot both be confirmed')
        result[metric]['direction'] = confirmed[0] + '_beyond_1pct' if confirmed else 'unresolved'
    return {'paired_r136_vs_c': result, 'hypotheses': hypotheses, 'family_size': 6,
            'primary_mean_direction': result['mean_us']['direction'], 'adoption_decision': False,
            'confirmed_negative_metrics': [m for m in LATENCY if result[m]['direction'] == 'higher_beyond_1pct']}


def jsonl(path):
    return [json.loads(line, object_pairs_hook=unique) for line in path.read_text().splitlines()]


def performance(rows, daemon_id):
    validate('\n'.join(json.dumps(row) for row in rows), 'monitor', 5000, daemon_id[0])
    result = rows[-1]
    for row in rows[:-1]:
        for field in ('rss_kib', 'rssanon_kib', 'vmdata_kib', 'fds'):
            integer(row[field], field)
    baseline = integer(rows[0]['fds'], 'baseline FD', 1)
    check([row['fds'] for row in rows[:-1]] == [baseline, baseline + 3, baseline + 3, baseline], 'monitor FD counts differ')
    samples = sorted(result['latency_ns'])
    wall = integer(result['wall_ns'], 'outer wall', 1)
    check(sum(samples) <= wall, 'sample sum exceeds outer wall')
    metrics = {'mean_us': Fraction(sum(samples), 5000000), 'wall_us_per_op': Fraction(wall, 5000000)}
    for name, percentile in (('p50_us', 50), ('p95_us', 95), ('p99_us', 99)):
        metrics[name] = Fraction(samples[(4999 * percentile + 50) // 100], 1000)
    for source, target in (('daemon_cpu_ns', 'daemon_cpu_us_per_op'), ('caller_cpu_ns', 'caller_cpu_us_per_op')):
        value = integer(result[source], source, 1)
        check(value <= wall, 'CPU exceeds outer wall')
        metrics[target] = Fraction(value, 5000000)
    return metrics, [{k: v for k, v in r.items() if k != 'subject_pid'} for r in rows[:-1]]


def memory(rows, daemon_id):
    check(len(rows) == 17 and rows[-1] == {'phase': 'COMPLETE', 'full_mirror_bytes_checked': True,
          'mirror_frames': 10, 'subject_pid': daemon_id[0], 'smoke': False}, 'memory completion/fixture differs')
    baseline = integer(rows[0]['fds'], 'baseline FD', 1)
    previous = 0
    snapshots = []
    for index, row in enumerate(rows[:-1]):
        phase, size = PHASES[index // 2]
        delay = (1000, 5000)[index % 2]
        check(row['phase'] == phase and row['payload_bytes'] == size and row['delay_ms'] == delay
              and row['subject_pid'] == daemon_id[0] and row['start_ticks'] == str(daemon_id[1]), 'memory snapshot identity/phase differs')
        check(row['fds'] == baseline + (0 if phase in ('empty', 'disconnected') else 2), 'memory FD count differs')
        elapsed = integer(row['elapsed_ms'], 'elapsed milliseconds')
        check(elapsed >= index // 2 * 5000 + delay and elapsed > previous, 'sample wait absent or too short')
        previous = elapsed
        for field in MEMORY:
            integer(row[field], field)
        snapshots.append({k: v for k, v in row.items() if k not in ('subject_pid', 'start_ticks')})
    for row in snapshots:
        empty = snapshots[0 if row['delay_ms'] == 1000 else 1]
        row['growth_from_empty_kib'] = {m: row[m] - empty[m] for m in MEMORY}
    return snapshots


def memory_comparisons(records):
    indexed = {(r['window'], r['side'], s['phase'], s['delay_ms']): s for r in records for s in r['snapshots']}
    check(len(records) == 6 and len(indexed) == 96, 'three complete memory windows required')
    comparisons = []
    for phase, _ in PHASES:
        for delay in (1000, 5000):
            for metric in MEMORY:
                c = [indexed[w, 'c', phase, delay][metric] for w in range(3)]
                rust = [indexed[w, 'candidate', phase, delay][metric] for w in range(3)]
                comparisons.append({'phase': phase, 'delay_ms': delay, 'metric': metric,
                                    'c_by_window_kib': c, 'r136_by_window_kib': rust,
                                    'r136_minus_c_kib': summary([b - a for a, b in zip(c, rust)])})
    positive = [{'window': r['window'], 'side': r['side'], 'phase': s['phase'], 'delay_ms': s['delay_ms'],
                 'metric': m, 'growth_kib': value} for r in records for s in r['snapshots']
                for m, value in s['growth_from_empty_kib'].items() if value > 0]
    return {'paired_r136_minus_c': comparisons, 'positive_within_process_growth': positive,
            'inference': 'descriptive only; no significance, equivalence, peak/heap/PSS or resource acceptance',
            'adoption_decision': False}


def load_plan(path):
    plan, policy = read(path), read(POLICY)
    kind = plan['kind']
    check(kind in ('monitor', 'memory'), 'unknown series')
    count, iterations, warmup = (10, 5000, 20) if kind == 'monitor' else (3, 1, 0)
    orders = [['c', 'candidate'] if i % 2 == 0 else ['candidate', 'c'] for i in range(count)]
    caller_sha = HELPER_SHA if kind == 'monitor' else MEMORY_SHA
    check(plan['schema_version'] == 1 and plan['orders'] == orders and plan['window_count'] == count
          and plan['case_count'] == 2 * count and len(plan['steps']) == count
          and plan['iterations'] == iterations and plan['warmup'] == warmup, 'fixed series dimensions differ')
    check(plan['policy'] == policy and plan['policy_sha256'] == digest(POLICY), 'frozen policy changed')
    check({k: v['sha256'] for k, v in plan['subjects'].items()} == SUBJECTS
          and plan['candidate_sha256'] == CANDIDATE_SHA and plan['benchmark']['sha256'] == BENCHMARK_SHA
          and plan['caller']['sha256'] == caller_sha and plan['caller']['slot'] == CALLER
          and plan['namespace_sha256'] == NAMESPACE_SHA and plan['libraries'] == LIBRARIES, 'exact identities differ')
    check(plan['runtime'] == {'daemon_cpu': 1, 'caller_cpu': 0, 'socket': SOCKET, 'daemon_argv0': '/sbin/ubusd',
          'default_acl': True, 'fresh_daemon_per_case': True}, 'runtime contract differs')
    inputs = plan['input_sha256']
    check(set(SUPPORT) | {'tools/r143/analyze_router.py', 'tools/r143/test_analyze_router.py',
          'tools/r143/policy.json', 'docs/reviews/R143_MONITOR_PLAN.md'} <= set(inputs), 'analysis inputs not frozen')
    for name, expected in inputs.items():
        p = PurePosixPath(name)
        check(not p.is_absolute() and '..' not in p.parts and re.fullmatch('[0-9a-f]{64}', expected), 'invalid frozen input')
        check(digest(ROOT / name) == expected, f'frozen input changed: {name}')
    settings = []
    for i, step in enumerate(plan['steps']):
        args = step['argv']
        check(step['name'] == f'window-{i}' and len(args) == 17 and args[:2] == ['tools/r95_device_smoke.py', 'ubusd']
              and args[2] == plan['subjects']['candidate']['path'] and args[3] == f'{plan["output"]}/window-{i}'
              and args[-1] == '--pilot' and step['driver_result'] == f'{args[3]}/result.json', 'driver/window contract differs')
        flags = dict(zip(args[4:-1:2], args[5:-1:2]))
        check(set(flags) == {'--guard', '--recovery-gate', '--benchmark', '--event-benchmark', '--workload-script', '--iterations'}
              and flags['--iterations'] == str(iterations) and flags['--benchmark'] == plan['benchmark']['path']
              and flags['--event-benchmark'] == plan['caller']['path'], 'driver flags differ')
        files = {'driver': args[0], 'candidate': args[2], 'guard': flags['--guard'], 'recovery_gate': flags['--recovery-gate'],
                 'benchmark': flags['--benchmark'], 'event_benchmark': flags['--event-benchmark'], 'workload': flags['--workload-script']}
        settings.append({k: inputs[v] for k, v in files.items()})
    common = {k: v for k, v in settings[0].items() if k != 'workload'}
    check(all({k: v for k, v in s.items() if k != 'workload'} == common for s in settings), 'tools changed across windows')
    gate = read(ROOT / flags['--recovery-gate'])
    check(gate['offline_backup_verified'] is True and gate['configuration_matches_backup'] is True, 'recovery gate invalid')
    check(len(plan['prerequisites']) == 2, 'exact R136 prerequisites missing')
    for name in plan['prerequisites']:
        check(name in inputs, 'unfrozen prerequisite')
        result = read(ROOT / name)
        check(result.get('candidate_sha256') == CANDIDATE_SHA and all(result.get(k) is True for k in HEALTH), 'prerequisite failed')
    check(len(plan['proofs']) == (1 if kind == 'memory' else 0), 'helper proof set differs')
    for name in plan['proofs']:
        check(name in inputs, 'unfrozen helper smoke')
        proof = read(ROOT / name)
        cases = {r['subject']: r for r in proof['cases']}
        check(proof['passed'] is True and proof['helper_sha256'] == MEMORY_SHA and proof['benchmark_sha256'] == BENCHMARK_SHA
              and all(cases[s]['passed'] is True and cases[s]['daemon_sha256'] == h for s, h in [('c', C_SHA), ('r136', CANDIDATE_SHA)]), 'helper smoke differs')
    return plan, settings, gate['boot_id']


def analyze(root, plan_path):
    plan, settings, boot = load_plan(plan_path)
    count, kind = plan['window_count'], plan['kind']
    check((root / 'COMPLETE').is_file() and digest(root / 'plan.json') == digest(plan_path), 'series incomplete/plan differs')
    check({p.name for p in root.glob('window-*') if p.is_dir()} == {f'window-{i}' for i in range(count)}, 'exact window set required')
    check(read(root / 'steps.json') == [{'name': f'window-{i}', 'exit': 0} for i in range(count)], 'outer steps differ')
    identities = {'/sbin/ubusd': C_SHA, '/tmp/bin/ubusd-rs': CANDIDATE_SHA, BENCH: BENCHMARK_SHA,
                  CALLER: plan['caller']['sha256'], '/tmp/bin/ns-exec': NAMESPACE_SHA}
    records, windows, indexed, seen, series_health = [], [], {}, set(), None
    for w, expected in enumerate(settings):
        window, raw = root / f'window-{w}', root / f'window-{w}' / 'raw'
        check((raw / 'COMPLETE').is_file() and not any((base / marker).exists() for base in (root, window, raw)
              for marker in ('FAILED', 'FAILED.json', 'failure.json')), 'failed/incomplete evidence')
        raw_hashes = archive_hashes(window)
        result = read(window / 'result.json')
        check(all(result.get(k) is True for k in HEALTH), 'driver health/cleanup failed')
        mode = {'exit': 0, 'component': 'ubusd', 'implementation': 'rs', 'iterations': plan['iterations'], 'installed': False,
                'matrix': False, 'production_mode': 'stock', 'pilot_only': True, 'correctness_smoke_only': False}
        check(all(type(result.get(k)) is type(v) and result[k] == v for k, v in mode.items()), 'collection mode differs')
        check(all(result.get(k + '_sha256') == v for k, v in expected.items()), 'driver/tool identities differ')
        health = [read(window / f'health-{p}.json') for p in ('before', 'after')]
        check(health[0] == health[1] and health[0]['boot_id'] == boot and health[0]['mode'] == 'stock'
              and (series_health is None or health[0] == series_health), 'health/boot changed')
        series_health = health[0]
        check(set(health[0]['verified_components']) == {'procd', 'ubusd', 'netifd', 'rpcd', 'logd', 'httpd', 'uci', 'fw4', 'reload-config'}, 'stock component coverage differs')
        check((raw / 'boot-id.txt').read_text().strip() == boot and (raw / 'kernel.txt').read_text().strip() == '6.12.94'
              and (raw / 'cpus-online.txt').read_text().strip() == '0-1', 'raw target differs')
        for name in ('expected-identities.txt', 'identities-before.txt', 'identities-after.txt'):
            check(hashes(raw / name) == identities, 'raw artifact identities differ')
        check(hashes(raw / 'binary-sha256.txt') == {'/tmp/bin/ubusd-rs': CANDIDATE_SHA}, 'driver subject differs')
        check(sorted((raw / 'identity-check.log').read_text().splitlines()) == sorted(f'{p}: OK' for p in identities), 'identity check differs')
        check(hashes(raw / 'expected-libraries.txt') == LIBRARIES, 'libraries differ')
        for phase in ('before', 'after'):
            check(sorted((raw / f'library-check-{phase}.log').read_text().splitlines()) == sorted(f'{p}: OK' for p in LIBRARIES), 'library check failed')
        check((raw / 'order.txt').read_text().split() == plan['orders'][w]
              and {p.name for p in raw.iterdir() if p.is_dir()} == set(SUBJECTS), 'case set/order differs')
        parent = status(raw / 'parent-before.status', (0, 1))[0]
        status(raw / 'parent-after.status', (0, 1), parent)
        for side in plan['orders'][w]:
            folder = raw / side
            check((folder / 'COMPLETE').is_file() and {p.name for p in folder.glob('*.jsonl')} == {'caller.jsonl'}, 'case incomplete/extra data')
            check(all(not (folder / name).read_bytes() for name in ('caller.log', 'daemon.log', 'objects-after.txt')), 'nonempty logs/objects')
            check((folder / 'caller-exit.txt').read_text().strip() == '0'
                  and (folder / 'daemon-exit.txt').read_text().strip() in ('0', '143'), 'case exit differs')
            daemon_id = proc_identity(folder / 'before.stat')
            check(daemon_id not in seen and proc_identity(folder / 'after.stat') == daemon_id, 'daemon reused/replaced')
            seen.add(daemon_id)
            check(argv(folder / 'expected.cmdline') == COMMAND, 'expected daemon argv differs')
            for phase in ('before', 'after'):
                status(folder / f'{phase}.status', (1,), daemon_id[0])
                check(argv(folder / f'{phase}.cmdline') == COMMAND
                      and hashes(folder / f'{phase}-exe.sha256') == {f'/proc/{daemon_id[0]}/exe': SUBJECTS[side]}, 'live argv/ELF differs')
                if side == 'c':
                    check('/sbin/ubusd' in (folder / f'{phase}.maps').read_text()
                          and '/lib/libc.so' in (folder / f'{phase}.maps').read_text(), 'C maps incomplete')
            suffix = ['event-stress', SOCKET, 'monitor', '5000', str(daemon_id[0])] if kind == 'monitor' else [SOCKET, str(daemon_id[0]), 'sample']
            check(argv(folder / 'caller-command.argv') == [BENCH, 'exec-cpu', '0', CALLER, *suffix], 'caller command differs')
            record = {'window': w, 'side': side, 'raw_sha256': raw_hashes[f'{side}/caller.jsonl']}
            if kind == 'monitor':
                metrics, diagnostic = performance(jsonl(folder / 'caller.jsonl'), daemon_id)
                indexed[w, side] = metrics
                record.update({'metrics': {k: float(v) for k, v in metrics.items()}, 'memory_diagnostic': diagnostic})
            else:
                record['snapshots'] = memory(jsonl(folder / 'caller.jsonl'), daemon_id)
            records.append(record)
        windows.append({'window': w, 'order': plan['orders'][w], 'raw_sha256': raw_hashes,
                        'archive_sha256': digest(window / 'raw.tar.gz'), 'result_sha256': digest(window / 'result.json'),
                        'health_sha256': {p: digest(window / f'health-{p}.json') for p in ('before', 'after')}})
    check(len(records) == 2 * count, 'all cases required')
    return {'schema_version': 1, 'scope': plan['scope'], 'kind': kind, 'verified': True, 'window_count': count,
            'case_count': len(records), 'samples': 100000 if kind == 'monitor' else 96,
            'subjects': SUBJECTS, 'caller_sha256': plan['caller']['sha256'], 'plan_sha256': digest(plan_path),
            'policy': plan['policy'], 'policy_sha256': digest(POLICY), 'analyzer_sha256': digest(Path(__file__)),
            'support_sha256': {p: digest(ROOT / p) for p in SUPPORT}, 'windows': windows, 'records': records,
            'comparisons': performance_comparisons(indexed) if kind == 'monitor' else memory_comparisons(records),
            'limitations': ['Only current R136 versus C coverage; no rejected R142 candidate, adoption or deployment.',
                'Paired windows are the statistical units; exact sign inference assumes independent window signs. Holm does not repair serial dependence.',
                'Caller poll/validation and timer overhead remain included; no per-operation migration or scheduler trace and no wall-minus-CPU inference.',
                'Memory snapshots are separate descriptive residency observations, not peak allocation, heap, PSS, equivalence or resource acceptance.',
                'Every frozen window and negative observation remains; this coverage does not cancel earlier registration-tail findings.']}


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
    print(json.dumps({'verified': True, 'kind': report['kind'], 'windows': report['window_count'],
                      'primary': report['comparisons'].get('primary_mean_direction'), 'adoption_decision': False}))


if __name__ == '__main__':
    main()
