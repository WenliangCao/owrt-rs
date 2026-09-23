#!/usr/bin/env python3
"""Offline validation of eight R140 windows and the frozen seven-lane rules."""
import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from pathlib import Path, PurePosixPath
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from r130_registration_report import archive_hashes, argv, check, digest, hashes, proc_identity, read
from r139.analyze_affinity import measurement, status
from r140.make_formal_plan import (BENCHMARK_SHA, C_SHA, GUARD_SHA, HEALTH, LANES as WORKLOADS,
    NAMESPACE_SHA, ORDERS, PREREQUISITES, PROVIDER, R136_SHA, RULES, verify_build, verify_lane_smoke, verify_oracle, verify_prerequisites)

SIDES = ('c', 'r136', 'candidate')
LANES = tuple(name for name, _, _ in WORKLOADS)
METRICS = tuple(RULES['required_metrics'])
MEMORY = ('VmRSS', 'RssAnon', 'VmData', 'VmHWM')
BINARIES = {'c': '/sbin/ubusd', 'r136': '/tmp/bin/before-rs', 'candidate': '/tmp/bin/ubusd-rs'}
BENCH, SOCKET = '/tmp/bin/owrt-benchmark', '/var/run/ubus/ubus.sock'
COMMAND = ['/sbin/ubusd', '-s', SOCKET]


def load_plan(path):
    plan = read(path)
    check(plan['schema_version'] == 1 and plan['window_count'] == 8 and plan['case_count'] == 168
          and plan['orders'] == [list(order) for order in ORDERS] and len(plan['steps']) == 8,
          'expected eight frozen 21-case windows')
    check(plan['iterations'] == 10000 and plan['warmup'] == 20 and plan['decision_rules'] == RULES,
          'frozen counts/rules differ')
    check(plan['lanes'] == [{'name': n, 'command': c, 'parameters': p, 'iterations': 10000, 'warmup': 20}
                           for n, c, p in WORKLOADS], 'lane definitions differ')
    check(plan['runtime'] == {'daemon_cpu': 1, 'caller_allowed_cpus': [0, 1], 'socket': SOCKET,
          'default_acl': True, 'daemon_argv0': '/sbin/ubusd', 'event_benchmark_slot': False,
          'provider': PROVIDER, 'lane_order': list(LANES)}, 'runtime contract differs')
    subjects = {s: p['sha256'] for s, p in plan['subjects'].items()}
    check(set(subjects) == set(SIDES) and subjects['c'] == C_SHA and subjects['r136'] == R136_SHA
          and subjects['candidate'] == plan['candidate_sha256'] and plan['benchmark']['sha256'] == BENCHMARK_SHA
          and plan['namespace_sha256'] == NAMESPACE_SHA, 'artifact identities differ')
    inputs = plan['input_sha256']
    for name, expected in inputs.items():
        relative = PurePosixPath(name)
        check(not relative.is_absolute() and '..' not in relative.parts
              and re.fullmatch('[0-9a-f]{64}', expected), 'invalid frozen input')
        check(digest(ROOT / name) == expected, f'frozen input changed: {name}')
    check(plan['build'] == verify_build(plan['build']['results'], subjects['candidate'])
          and all(plan['build'][name] in inputs for name in ('results', 'plan')), 'build proof changed')
    check(plan['oracle_correctness'] == verify_oracle(plan['oracle_correctness']['path'], subjects['candidate'])
          and plan['oracle_correctness']['path'] in inputs, 'Oracle functional proof changed')
    check(plan['lane_smoke'] == verify_lane_smoke(plan['lane_smoke']['path'], subjects['candidate'])
          and plan['lane_smoke']['path'] in inputs, 'original-caller lane smoke proof changed')
    check(plan['elf_bytes'] == {s: (ROOT / p['path']).stat().st_size for s, p in plan['subjects'].items()}, 'ELF size changed')
    settings = []
    for i, step in enumerate(plan['steps']):
        args = step['argv']
        check(len(args) == 17 and args[:2] == ['tools/r95_device_smoke.py', 'ubusd']
              and args[2] == plan['subjects']['candidate']['path'] and args[-1] == '--pilot'
              and step['name'] == f'window-{i}' and args[3] == f'{plan["output"]}/window-{i}'
              and step['driver_result'] == f'{args[3]}/result.json', 'driver/window contract differs')
        flags = dict(zip(args[4:-1:2], args[5:-1:2]))
        check(set(flags) == {'--guard', '--recovery-gate', '--benchmark', '--before-candidate', '--workload-script', '--iterations'}
              and flags['--iterations'] == '10000' and flags['--benchmark'] == plan['benchmark']['path']
              and flags['--before-candidate'] == plan['subjects']['r136']['path'], 'driver flags differ')
        files = {'driver': args[0], 'candidate': args[2], 'guard': flags['--guard'],
                 'recovery_gate': flags['--recovery-gate'], 'benchmark': flags['--benchmark'],
                 'before_candidate': flags['--before-candidate'], 'workload': flags['--workload-script']}
        settings.append({key: inputs[value] for key, value in files.items()})
    common = {k: v for k, v in settings[0].items() if k != 'workload'}
    check(all({k: v for k, v in row.items() if k != 'workload'} == common for row in settings)
          and common['guard'] == GUARD_SHA, 'common tools/subjects changed')
    gate = read(ROOT / files['recovery_gate'])
    check(gate['offline_backup_verified'] is True and gate['configuration_matches_backup'] is True, 'invalid recovery gate')
    prerequisite_inputs, units = verify_prerequisites(subjects['candidate'], gate['boot_id'])
    check(plan['prerequisites'] == PREREQUISITES and plan['unit_tests'] == units
          and all(name in inputs for name in prerequisite_inputs)
          and all(unit['sha256'] == plan['oracle_correctness']['unit_tests_sha256'] for unit in units),
          'wire/FD/unit gates differ')
    return plan, settings, subjects, gate['boot_id']


def process(folder, prefix, cpus, command, sha, expected_id=None):
    identity = proc_identity(folder / f'{prefix}before.stat')
    check((expected_id is None or identity == expected_id)
          and proc_identity(folder / f'{prefix}after.stat') == identity, 'live process identity changed')
    snapshots = {}
    for phase in ('before', 'after'):
        _, observed = status(folder / f'{prefix}{phase}.status', cpus, identity[0])
        check(argv(folder / f'{prefix}{phase}.cmdline') == command
              and hashes(folder / f'{prefix}{phase}-exe.sha256') == {f'/proc/{identity[0]}/exe': sha}, 'live argv/ELF differs')
        snapshots[phase] = {key: int(observed[key].split()[0]) for key in MEMORY}
        check(all(observed[key].split()[1:] == ['kB'] for key in MEMORY), 'resident units differ')
    snapshots['after_minus_before'] = {key: snapshots['after'][key] - snapshots['before'][key] for key in MEMORY}
    return identity, snapshots


def expected_caller(side, lane, pid):
    common = [BENCH]
    if lane in LANES[:5]:
        _, command, parameters = next(row for row in WORKLOADS if row[0] == lane)
        return [*common, command, SOCKET, *map(str, parameters), '10000', '20', str(pid)]
    if lane == 'lookup':
        return [*common, 'lookup', SOCKET, 'bench.target', '10000', '20', str(pid)]
    return [*common, 'rpc', SOCKET, 'bench.target', 'ping', f'/tmp/out/{side}/invoke-input.data',
            f'/tmp/out/{side}/invoke-expected.data', '10000', '20', str(pid)]


def compare(values, baseline):
    ratios = [a / b for a, b in zip(values, baseline)]
    median = statistics.median(ratios)
    return {'ratios_by_window': list(map(float, ratios)),
            'delta_pct_by_window': [float(100 * (r - 1)) for r in ratios],
            'median_ratio': float(median), 'median_delta_pct': float(100 * (median - 1)),
            'higher_windows': sum(r > 1 for r in ratios), 'lower_windows': sum(r < 1 for r in ratios),
            'above_3pct_in_seven_windows': median > Fraction(103, 100) and sum(r > 1 for r in ratios) >= 7}


def decisions(indexed):
    groups = {control: {lane: {metric: compare(
        [indexed[w, 'candidate', lane][metric] for w in range(8)],
        [indexed[w, control, lane][metric] for w in range(8)]) for metric in METRICS}
        for lane in LANES} for control in ('r136', 'c')}
    geometric = []
    with localcontext() as context:
        context.prec = 60
        for w in range(8):
            product = Fraction(1)
            for lane in LANES:
                product *= indexed[w, 'candidate', lane]['mean_us'] / indexed[w, 'r136', lane]['mean_us']
            value = (Decimal(product.numerator) / Decimal(product.denominator)) ** (Decimal(1) / 7)
            geometric.append(value.quantize(Decimal('1e-30')))
        median = statistics.median(geometric)
    primary = median < Decimal('.98') and sum(value < 1 for value in geometric) >= 7
    losses = [{'lane': lane, 'metric': metric, **groups['r136'][lane][metric]}
              for lane in LANES for metric in ('mean_us', 'p95_us', 'p99_us')
              if groups['r136'][lane][metric]['above_3pct_in_seven_windows']]
    return {'comparisons': groups,
            'primary': {'geometric_ratio_by_window': list(map(str, geometric)),
                        'median_geometric_ratio': str(median), 'median_delta_pct': float((median - 1) * 100),
                        'lower_windows': sum(value < 1 for value in geometric), 'passed': primary},
            'latency_vetoes': losses, 'performance_rule_passed': primary and not losses,
            'secondary_register_1_p95': {c: groups[c]['register_1']['p95_us'] for c in groups},
            'higher_medians': [{'control': c, 'lane': lane, 'metric': metric, **value}
                               for c, lanes in groups.items() for lane, metrics in lanes.items()
                               for metric, value in metrics.items() if value['median_delta_pct'] > 0]}


def analyze(root, plan_path):
    plan, settings, subjects, boot = load_plan(plan_path)
    check((root / 'COMPLETE').is_file() and digest(root / 'plan.json') == digest(plan_path), 'series incomplete/plan differs')
    check({p.name for p in root.glob('window-*') if p.is_dir()} == {f'window-{i}' for i in range(8)}, 'exactly eight windows required')
    check(read(root / 'steps.json') == [{'name': f'window-{i}', 'exit': 0} for i in range(8)], 'outer steps differ')
    windows, records, resident, indexed, series_health = [], [], {}, {}, None
    for w, expected in enumerate(settings):
        window, raw = root / f'window-{w}', root / f'window-{w}' / 'raw'
        check((raw / 'COMPLETE').is_file() and not any((base / marker).exists() for base in (root, window)
              for marker in ('FAILED', 'FAILED.json', 'failure.json')), 'failed/incomplete evidence')
        raw_hashes = archive_hashes(window)
        result = read(window / 'result.json')
        check(all(result.get(key) is True for key in HEALTH), 'health/cleanup failed')
        mode = {'exit': 0, 'component': 'ubusd', 'implementation': 'rs', 'iterations': 10000, 'installed': False,
                'matrix': False, 'production_mode': 'stock', 'pilot_only': True, 'correctness_smoke_only': False}
        check(all(type(result.get(k)) is type(v) and result[k] == v for k, v in mode.items())
              and all(result.get(k + '_sha256') == v for k, v in expected.items()), 'driver mode/input differs')
        health = [read(window / f'health-{p}.json') for p in ('before', 'after')]
        check(health[0] == health[1] and health[0]['boot_id'] == boot and health[0]['mode'] == 'stock'
              and (series_health is None or series_health == health[0]), 'health/boot/production changed')
        series_health = health[0]
        check(set(health[0]['verified_components']) == {'procd', 'ubusd', 'netifd', 'rpcd', 'logd', 'httpd', 'uci', 'fw4', 'reload-config'}, 'production coverage differs')
        check((raw / 'boot-id.txt').read_text().strip() == boot and (raw / 'kernel.txt').read_text().strip() == '6.12.94', 'raw target differs')
        identities = {BINARIES[s]: subjects[s] for s in SIDES}
        identities.update({BENCH: BENCHMARK_SHA, '/tmp/bin/ns-exec': NAMESPACE_SHA})
        check(all(hashes(raw / name) == identities for name in ('identities.txt', 'identities-after.txt', 'expected-identities.txt'))
              and hashes(raw / 'binary-sha256.txt') == {BINARIES['candidate']: subjects['candidate']}, 'raw ELF identities differ')
        check(sorted((raw / 'identity-check.log').read_text().splitlines()) == sorted(f'{p}: OK' for p in identities), 'identity check differs')
        check((raw / 'order.txt').read_text().split() == plan['orders'][w]
              and {p.name for p in raw.iterdir() if p.is_dir()} == set(SIDES), 'subject set/order differs')
        parent = status(raw / 'parent-before.status', (0, 1))[0]
        status(raw / 'parent-after.status', (0, 1), parent)
        seen = set()
        for side in plan['orders'][w]:
            folder = raw / side
            check((folder / 'COMPLETE').is_file() and {p.name for p in folder.glob('*.json')} == {f'{lane}.json' for lane in LANES}, 'subject/lane set differs')
            check(not (folder / 'objects-after.txt').read_bytes() and not (folder / 'daemon.log').read_bytes()
                  and (folder / 'daemon-exit.txt').read_text().strip() in ('0', '143'), 'daemon incomplete/log/objects')
            check(argv(folder / 'expected.cmdline') == COMMAND, 'daemon expected argv differs')
            daemon_id, snapshots = process(folder, '', (1,), COMMAND, subjects[side])
            check(daemon_id not in seen, 'daemon reused between subjects')
            seen.add(daemon_id)
            resident[w, side] = snapshots
            for lane in LANES:
                check(not (folder / f'{lane}.log').read_bytes() and (folder / f'{lane}.exit').read_text().strip() == '0'
                      and argv(folder / f'{lane}.argv') == expected_caller(side, lane, daemon_id[0]), 'caller launch/exit/log differs')
                data = read(folder / f'{lane}.json')
                metrics, context = measurement(data, daemon_id)
                indexed[w, side, lane] = metrics
                proc = data['daemon_cpu'][0]
                records.append({'window': w, 'side': side, 'lane': lane, 'raw_sha256': raw_hashes[f'{side}/{lane}.json'],
                                'metrics': {k: float(v) for k, v in metrics.items()}, 'daemon_context_switch_deltas': context,
                                'daemon_native_memory_kib': {p: {k: proc[p][k] for k in MEMORY if k in proc[p]} for p in ('before', 'after')}})
            provider_command = [BENCH, 'serve', SOCKET, '1']
            check(argv(folder / 'provider-expected.cmdline') == provider_command, 'provider expected argv differs')
            provider_id, _ = process(folder, 'provider-', (0, 1), provider_command, BENCHMARK_SHA)
            check(provider_id != daemon_id and not (folder / 'provider.log').read_bytes()
                  and (folder / 'provider-exit.txt').read_text().strip() in ('0', '143'), 'provider failed/identity alias')
            check(all((folder / f'provider-objects-{p}.txt').read_bytes() == b'bench.target\n' for p in ('before', 'after'))
                  and (folder / 'invoke-input.data').read_bytes() == b'{"n":1}\n'
                  and (folder / 'invoke-expected.data').read_bytes() == b'{"ok":1}\n', 'sentinel fixture differs')
        windows.append({'window': w, 'order': plan['orders'][w], 'raw_sha256': raw_hashes,
                        'archive_sha256': digest(window / 'raw.tar.gz'), 'result_sha256': digest(window / 'result.json'),
                        'health_sha256': {p: digest(window / f'health-{p}.json') for p in ('before', 'after')}})
    check(len(records) == len(indexed) == 168, 'expected all 168 cases')
    memory = [{'window': w, 'side': s, 'snapshots_kib': resident[w, s]} for w in range(8) for s in SIDES]
    increases = [{'window': w, 'control': control, 'phase': phase, 'metric': metric,
                  'candidate': resident[w, 'candidate'][phase][metric], 'control_value': resident[w, control][phase][metric],
                  'delta_kib': resident[w, 'candidate'][phase][metric] - resident[w, control][phase][metric]}
                 for w in range(8) for control in ('c', 'r136') for phase in ('before', 'after', 'after_minus_before') for metric in MEMORY
                 if resident[w, 'candidate'][phase][metric] > resident[w, control][phase][metric]]
    return {'schema_version': 1, 'scope': 'R140 eight-window A53-only compiler comparison; no deployment',
            'verified': True, 'windows_verified': 8, 'case_count': 168, 'plan_sha256': digest(plan_path),
            'analyzer_sha256': digest(Path(__file__)), 'subjects': subjects, 'benchmark_sha256': BENCHMARK_SHA,
            'build': plan['build'], 'elf_bytes': plan['elf_bytes'], 'rules': RULES, 'windows': windows, 'records': records,
            'daemon_memory': memory, 'all_candidate_memory_increases': increases, **decisions(indexed),
            'limitations': [
                'Equal weights are an engineering choice, not real traffic or a 9:1 business score. Frozen engineering gates are not statistical significance or equivalence.',
                'All eight windows and 168 cases are retained. Historical R136/R139 and Oracle timing observations are excluded.',
                'CPU is fully reported without a statistical CPU veto; substantial unexpected costs still need engineering assessment. A passed rule is not deployment authorization.',
                'Original caller has no live CPU placement/context snapshots. Parent allowance and exact launch argv are verified; there is no per-operation migration or scheduling trace.',
                'Daemon CPU is recomputed from process-clock snapshots; caller CPU has a delta only. Provider CPU is excluded. No wall-minus-CPU inference is made.',
                'Resident values describe before/after the seven-lane lifecycle; VmHWM is a process high-water value. PSS, full peak attribution, long-term retention and full R136 memory fixtures are not revalidated.',
                'One-object lookup/invoke sentinels and registration-generated events do not cover general user SEND, all other lanes, or nine-component integration.',
                'Guard assertions cover config/mount/production identity inside each window; exact inputs and same health/boot agree across windows. Raw host process identities are not separately archived.',
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = analyze(args.root, args.plan)
    with args.output.open('x') as output:
        json.dump(report, output, indent=2, allow_nan=False)
        output.write('\n')
    print(json.dumps({'windows': 8, 'cases': 168, 'primary': report['primary'],
                      'latency_veto_count': len(report['latency_vetoes']), 'performance_rule_passed': report['performance_rule_passed']}))


if __name__ == '__main__':
    main()
