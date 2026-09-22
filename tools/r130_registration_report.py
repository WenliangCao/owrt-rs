#!/usr/bin/env python3
"""Verify frozen R130 router windows and report all six lanes without pooling.

Usage: r130_registration_report.py PLAN ROOT OUTPUT
Reads local evidence only. CPU/op uses process clocks over the 5000 timed
operations; warmup is outside that interval. Provider CPU is never daemon CPU.
"""

import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import tarfile


REPO = Path(__file__).resolve().parent.parent
SUBJECTS = ('c', 'r124', 'r130')
REGISTER = ('register_1_8', 'register_16_8')
GUARDS = ('guard_lookup_exact', 'guard_lookup_all', 'guard_lookup_prefix', 'guard_invoke')
LANES = REGISTER + GUARDS
METRICS = ('mean_us', 'p50_us', 'p95_us', 'p99_us',
           'daemon_cpu_us_per_op', 'caller_cpu_us_per_op')
TOOL_KEYS = ('benchmark_sha256', 'workload_sha256', 'driver_sha256',
             'guard_sha256', 'recovery_gate_sha256')
HEALTH_KEYS = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
               'same_production_identity', 'same_host_mounts')
SOCKET = '/var/run/ubus/ubus.sock'
BENCH = '/tmp/bin/owrt-benchmark'
RULES = {
    'comparison_for_acceptance': 'r130/r124',
    'registration_mean': 'Both lanes: all six paired deltas < 0 and median <= -3%.',
    'registration_guard': 'Reject if p95, p99 or daemon CPU/op paired median > +5%.',
    'shared_helper_guard': 'Reject if any reported metric has all six deltas > 0 and median > +5%.',
    'engineering_tie': 'Absolute median <= 1%; not statistical equivalence.',
    'c_comparison': 'Independent descriptive comparison; does not replace the R124 change gate.',
}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f'nonfinite JSON: {value}')))


def hashes(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})\s+(.+)', line)
        check(match is not None and match[2] not in result, f'{path}: invalid/duplicate SHA256 row')
        result[match[2]] = match[1]
    return result


def proc_identity(path):
    match = re.fullmatch(r'([0-9]+) \(.*\) (.*)\n?', path.read_text())
    check(match is not None, f'{path}: invalid proc stat')
    fields = match[2].split()
    check(len(fields) >= 20 and fields[0] in ('R', 'S', 'D', 'I'), f'{path}: process not live')
    return int(match[1]), int(fields[19])


def proc_status(path, pid, cpu):
    values = dict(line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)
    values = {key: value.strip() for key, value in values.items()}
    check(values.get('Pid') == values.get('Tgid') == str(pid), f'{path}: PID/Tgid mismatch')
    check(values.get('Threads') == '1' and values.get('Cpus_allowed_list') == str(cpu),
          f'{path}: threads/CPU affinity mismatch')
    return values


def argv(path):
    data = path.read_bytes()
    check(data.endswith(b'\0'), f'{path}: cmdline is not NUL terminated')
    return [value.decode() for value in data[:-1].split(b'\0')]


def archive_hashes(window):
    raw = window / 'raw'
    actual = {}
    for path in raw.rglob('*'):
        check(not path.is_symlink() and (path.is_file() or path.is_dir()), f'{path}: nonregular evidence')
        if path.is_file():
            actual[path.relative_to(raw).as_posix()] = digest(path)
    archived = {}
    with tarfile.open(window / 'raw.tar.gz', 'r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            check(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                  f'{window}: unsafe archive member')
            if member.isdir():
                continue
            check(member.isfile() and name not in archived, f'{window}: nonregular/duplicate archive member')
            archived[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    check(actual == archived, f'{window}: archive differs from expanded raw evidence')
    return dict(sorted(actual.items()))


def verify_plan(plan):
    check(plan.get('schema_version') == 1 and set(plan['subjects']) == set(SUBJECTS), 'invalid R130 plan')
    check(plan['iterations'] == 5000 and plan['warmup'] == 20, 'frozen counts must be 5000/20')
    for value in (*plan['subjects'].values(), *(plan[key] for key in (*TOOL_KEYS, 'namespace_sha256', 'harness_sha256'))):
        check(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid frozen SHA256')
    expected = [subject for permutation in itertools.permutations(SUBJECTS) for subject in permutation]
    check(len(plan['runs']) == 18, 'expected 18 windows')
    for index, (run, subject) in enumerate(zip(plan['runs'], expected), 1):
        check(run['index'] == index and run['label'] == subject, 'frozen six-permutation schedule differs')
    check(digest(REPO / 'tools/benchmark/isolated.sh') == plan['harness_sha256'],
          'local namespace harness differs from frozen plan')
    if 'orchestrator_sha256' in plan:
        # The plan records the outer device runner separately from the
        # namespace workload; raw windows retain its result hash/health gate.
        check(re.fullmatch('[0-9a-f]{64}', plan['orchestrator_sha256']),
              'invalid frozen orchestrator SHA256')
    if 'reporter_sha256' in plan:
        check(digest(Path(__file__)) == plan['reporter_sha256'], 'reporter differs from frozen plan')


def process_evidence(raw, role, cpu, expected_argv, expected_sha):
    result = {}
    for phase in ('before', 'after'):
        prefix = raw / f'{role}-{phase}'
        identity = proc_identity(Path(str(prefix) + '.stat'))
        pid, start = identity
        values = proc_status(Path(str(prefix) + '.status'), pid, cpu)
        check(argv(Path(str(prefix) + '.cmdline')) == expected_argv, f'{prefix}: argv differs')
        check(hashes(Path(str(prefix) + '.exe-sha256')) == {f'/proc/{pid}/exe': expected_sha},
              f'{prefix}: live executable hash differs')
        check(Path(str(prefix) + '.starttime').read_text().strip() == str(start), f'{prefix}: starttime differs')
        result[phase] = {'pid': pid, 'start_ticks': start, 'status': values}
    check((result['before']['pid'], result['before']['start_ticks']) ==
          (result['after']['pid'], result['after']['start_ticks']), f'{role}: process replaced')
    return result


def expected_client_args(lane, daemon, provider):
    if lane in REGISTER:
        methods, size = lane.removeprefix('register_').split('_')
        return [BENCH, 'register-cycle', SOCKET, methods, size, '5000', '20', str(daemon)]
    monitored = f'{daemon},{provider}'
    if lane == 'guard_invoke':
        return [BENCH, 'rpc-fixture', SOCKET, '5000', '20', monitored]
    path = {'guard_lookup_exact': 'bench.target', 'guard_lookup_all': '*', 'guard_lookup_prefix': 'bench.*'}[lane]
    return [BENCH, 'lookup-fixture', SOCKET, path, '64', '5000', '20', monitored]


def measured_lane(raw, lane, daemon, provider):
    measurement = read(raw / f'{lane}.json')
    n = 5000
    check(measurement['schema'] == 1 and measurement['successful'] == n and measurement['warmup'] == 20
          and measurement['errors'] == 0, f'{lane}: failed operation/count mismatch')
    latencies = measurement['latency_ns']
    check(len(latencies) == n and all(type(value) is int and value > 0 for value in latencies), f'{lane}: invalid raw latencies')
    ordered = sorted(latencies)
    timings = {'mean_us': sum(ordered) / n / 1000}
    for name, percentile in (('p50_us', .50), ('p95_us', .95), ('p99_us', .99)):
        timings[name] = ordered[math.floor((n - 1) * percentile + .5)] / 1000
    for key, value in timings.items():
        check(math.isclose(measurement[key], value, rel_tol=1e-10, abs_tol=1e-9), f'{lane}: {key} differs from raw latencies')
    check(measurement['wall_s'] > 0 and math.isclose(measurement['ops_per_s'], n / measurement['wall_s'], rel_tol=1e-10),
          f'{lane}: invalid wall/throughput arithmetic')
    caller_id = proc_identity(raw / f'caller-{lane}.stat')
    proc_status(raw / f'caller-{lane}.status', caller_id[0], 0)
    check(argv(raw / f'caller-{lane}.exec-cmdline') == expected_client_args(lane, daemon[0], provider[0]),
          f'{lane}: caller planned exec argv differs')
    check(argv(raw / f'caller-{lane}.launcher-cmdline')[:2] == ['/bin/sh', '-c'], f'{lane}: caller launcher differs')
    expected = [daemon] if lane in REGISTER else [daemon, provider]
    processes = measurement['daemon_cpu']
    check(len(processes) == len(expected), f'{lane}: monitored role count differs')
    hz = measurement['clock_ticks_per_second']
    check(hz > 0, f'{lane}: invalid tick rate')
    for process, identity in zip(processes, expected):
        before, after = process['before'], process['after']
        check((process['pid'], before['start_ticks']) == identity and
              (before['pid'], before['start_ticks']) == (after['pid'], after['start_ticks']) == identity,
              f'{lane}: monitored PID/starttime or role order differs')
        check(before['process_cpu_resolution_ns'] == after['process_cpu_resolution_ns'] > 0,
              f'{lane}: CPU clock resolution differs')
        delta = after['process_cpu_ns'] - before['process_cpu_ns']
        check(delta >= 0 and type(process['cpu_clock_ns']) is int and process['cpu_clock_ns'] == delta,
              f'{lane}: process CPU clock arithmetic mismatch')
        for seconds, ticks in (('cpu_s', 'cpu_ticks'), ('child_cpu_s', 'child_cpu_ticks')):
            check(after[ticks] >= before[ticks] and math.isclose(process[seconds], (after[ticks] - before[ticks]) / hz, abs_tol=1e-9),
                  f'{lane}: {seconds} tick arithmetic mismatch')
    check(type(measurement['client_cpu_clock_ns']) is int and measurement['client_cpu_clock_ns'] > 0,
          f'{lane}: invalid caller CPU clock')
    metrics = {**timings, 'daemon_cpu_us_per_op': processes[0]['cpu_clock_ns'] / n / 1000,
               'caller_cpu_us_per_op': measurement['client_cpu_clock_ns'] / n / 1000}
    provider_cpu = processes[1]['cpu_clock_ns'] / n / 1000 if len(processes) == 2 else None
    return {'metrics': metrics, 'provider_cpu_us_per_op': provider_cpu,
            'caller_pid': caller_id[0], 'caller_start_ticks': caller_id[1],
            'measurement': measurement}


def verify_window(root, plan, run):
    label = f'{run["index"]:02d}-{run["label"]}'
    window, subject = root / label, run['label']
    raw = window / 'raw'
    check((raw / 'COMPLETE').is_file() and not (window / 'FAILED.json').exists(), f'{label}: incomplete/failed window')
    result = read(window / 'result.json')
    check(all(result.get(key) is True for key in HEALTH_KEYS), f'{label}: health/cleanup failure')
    check(result['exit'] == 0 and result['component'] == 'ubusd' and result['production_mode'] == 'stock'
          and result['installed'] is False and result['pilot_only'] is True and result['matrix'] is False
          and result['correctness_smoke_only'] is False and result['iterations'] == 5000,
          f'{label}: collection mode mismatch')
    implementation = 'c' if subject == 'c' else 'rs'
    check(result['implementation'] == implementation and result['candidate_sha256'] == plan['subjects'][subject],
          f'{label}: subject identity mismatch')
    check(all(result[key] == plan[key] for key in TOOL_KEYS), f'{label}: driver/tool hashes differ')
    health = [read(window / f'health-{phase}.json') for phase in ('before', 'after')]
    check(health[0] == health[1] and health[0]['mode'] == 'stock' and health[0]['boot_id'] == plan['boot_id'],
          f'{label}: health/boot differs')
    check((raw / 'boot-id.txt').read_text().strip() == plan['boot_id'], f'{label}: raw boot differs')
    executable = '/sbin/ubusd' if implementation == 'c' else '/tmp/bin/ubusd-rs'
    for file in ('binary-sha256.txt', 'binary-after-sha256.txt'):
        check(hashes(raw / file) == {executable: plan['subjects'][subject]}, f'{label}: binary hash differs')
    for file in ('benchmark-sha256.txt', 'benchmark-after-sha256.txt'):
        check(hashes(raw / file) == {BENCH: plan['benchmark_sha256'], '/tmp/bin/ns-exec': plan['namespace_sha256']},
              f'{label}: helper hash differs')
    check(hashes(raw / 'harness-sha256.txt') == {'/tmp/workload.sh': plan['workload_sha256']}, f'{label}: workload hash differs')
    daemon = process_evidence(raw, 'daemon', 1, ['/sbin/ubusd', '-s', SOCKET], plan['subjects'][subject])
    provider = process_evidence(raw, 'provider', 0, [BENCH, 'serve', SOCKET, '64'], plan['benchmark_sha256'])
    daemon_id = (daemon['before']['pid'], daemon['before']['start_ticks'])
    provider_id = (provider['before']['pid'], provider['before']['start_ticks'])
    check(daemon_id[0] != provider_id[0], f'{label}: daemon/provider PID alias')
    meta = read(raw / 'meta.json')
    check(meta == {'subject_pid': daemon_id[0], 'iterations': 5000, 'warmup': 20, 'daemon_cpu': 1,
                   'caller_cpu': 0, 'provider_cpu': 0, 'guard_iterations': 5000,
                   'guard_fixture_objects': 64, 'daemon_argv0': '/sbin/ubusd'}, f'{label}: workload metadata differs')
    snapshots = {}
    for phase in ('before', 'after-registration', 'after'):
        check((raw / f'objects-{phase}.txt').read_bytes() == b'', f'{label}: objects remain at {phase}')
        snapshot = read(raw / f'{phase}.json')
        check(len(snapshot['processes']) == 1 and
              (snapshot['processes'][0]['pid'], snapshot['processes'][0]['start_ticks']) == daemon_id,
              f'{label}: memory snapshot process identity differs')
        snapshots[phase] = snapshot
    lanes = {lane: measured_lane(raw, lane, daemon_id, provider_id) for lane in LANES}
    callers = [row['caller_pid'] for row in lanes.values()]
    check(len(set(callers)) == len(LANES) and not set(callers) & {daemon_id[0], provider_id[0]},
          f'{label}: caller PID alias')
    evidence = {path.name: digest(path) for path in window.iterdir() if path.is_file()}
    return {'index': run['index'], 'label': label, 'subject': subject, 'block': (run['index'] - 1) // 3 + 1,
            'subject_sha256': plan['subjects'][subject], 'daemon': daemon, 'provider': provider,
            'health': health[0], 'memory_snapshots': snapshots, 'lanes': lanes,
            'window_files_sha256': dict(sorted(evidence.items())), 'raw_sha256': archive_hashes(window)}


def summarize(values):
    check(len(values) == 6 and all(math.isfinite(value) for value in values), 'expected six finite paired values')
    middle = statistics.median(values)
    return {'paired_delta_pct': values, 'median_delta_pct': middle, 'range_delta_pct': [min(values), max(values)],
            'all_lower': all(value < 0 for value in values), 'all_higher': all(value > 0 for value in values),
            'engineering_tie': abs(middle) <= 1,
            'clear_regression': all(value > 0 for value in values) and middle > 5}


def comparisons(windows):
    result = {}
    for control in ('r124', 'c'):
        lanes = {}
        for lane in LANES:
            metrics = {}
            for metric in METRICS:
                values = []
                for block in range(1, 7):
                    pair = {window['subject']: window for window in windows if window['block'] == block}
                    candidate = pair['r130']['lanes'][lane]['metrics'][metric]
                    baseline = pair[control]['lanes'][lane]['metrics'][metric]
                    check(baseline > 0, f'{lane}/{metric}: nonpositive control')
                    values.append((candidate / baseline - 1) * 100)
                metrics[metric] = summarize(values)
            lanes[lane] = metrics
        result[f'r130_vs_{control}'] = lanes
    return result


def decision(comparison):
    gains, rejects = {}, []
    for lane in REGISTER:
        metrics = comparison[lane]
        gains[lane] = metrics['mean_us']['all_lower'] and metrics['mean_us']['median_delta_pct'] <= -3
        for metric in ('p95_us', 'p99_us', 'daemon_cpu_us_per_op'):
            if metrics[metric]['median_delta_pct'] > 5:
                rejects.append(f'{lane}/{metric}: median regression exceeds 5%')
    for lane in GUARDS:
        for metric in METRICS:
            if comparison[lane][metric]['clear_regression']:
                rejects.append(f'{lane}/{metric}: all six increase and median exceeds 5%')
    verdict = 'reject' if rejects else 'engineering_gate_pass' if all(gains.values()) else 'defer_no_stable_3pct_gain'
    return {'verdict': verdict, 'registration_mean_pass': gains, 'rejection_reasons': rejects,
            'scope': 'Frozen workload engineering gate only; requires separately recorded protocol/FD correctness gates.'}


def report(plan_path, root):
    plan = read(plan_path)
    verify_plan(plan)
    expected = {f'{run["index"]:02d}-{run["label"]}' for run in plan['runs']}
    actual = {path.name for path in root.iterdir() if path.is_dir() and re.match(r'^\d+-', path.name)}
    check(actual == expected, 'missing or unexpected window directories; no exclusion/replacement allowed')
    if (root / 'plan.json').exists():
        check(read(root / 'plan.json') == plan, 'collection plan differs from supplied frozen plan')
    windows = [verify_window(root, plan, run) for run in plan['runs']]
    paired = comparisons(windows)
    return {'schema_version': 1, 'scope': 'Physical router R130/R124/C registration and shared reply guards',
            'plan_sha256': digest(plan_path), 'reporter_sha256': digest(Path(__file__)),
            'subjects': plan['subjects'], 'counts': {'windows': 18, 'blocks': 6, 'lanes': 6,
                                                   'timed_ops_per_lane_window': 5000, 'warmup': 20},
            'assertions': {'window_health_cleanup': True, 'raw_archive_identity': True,
                           'daemon_affinity_argv_elf_starttime': True, 'provider_affinity_elf_starttime': True,
                           'caller_pre_exec_affinity_and_planned_argv': True, 'full_latency_and_cpu_arithmetic': True,
                           'namespace_harness_local_frozen_hash_only': True},
            'rules': RULES, 'windows': windows, 'comparisons': paired,
            'decision_vs_r124': decision(paired['r130_vs_r124']),
            'limitations': [
                'Six three-subject blocks; no population significance, independence or equivalence claim.',
                'Each ratio compares complete windows within the same block; per-operation samples are not independent replicates.',
                'CPU clocks exclude warmup; daemon is the first monitored PID; provider and caller remain separate.',
                'Caller affinity is observed before exec and inherited; no separate observation during its measured loop.',
                'Memory is retained process/system snapshots, not peak allocation, PSS superiority or a leak proof.',
                'Namespace bootstrap harness hash is checked locally; existing driver does not preserve its remote hash.',
                'C comparison uses these windows only; no ratios imported from R128 or historical releases.',
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = report(args.plan.resolve(), args.root.resolve())
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')


if __name__ == '__main__':
    main()
