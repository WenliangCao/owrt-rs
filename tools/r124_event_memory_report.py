#!/usr/bin/env python3
"""Verify R124 event-memory evidence and describe paired KiB measurements.

Usage: r124_event_memory_report.py PLAN ROOT OUTPUT
Only completed local evidence is read. No collection, remote access, estimates
for unavailable PSS, confidence intervals, or acceptance decision are made.
"""

import argparse
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


REPO = Path(__file__).resolve().parent.parent
SIZES = (32768, 262144, 786432)
METRICS = ('vmrss_kb', 'rssanon_kb', 'vmdata_kb', 'pss_kb')
HEADER = ('payload_bytes', 'phase', 'delay_seconds', 'daemon_pid',
          *METRICS, 'fds')
PHASES = (('empty', 0), ('connected', 1), ('connected', 5),
          ('held', 1), ('held', 5), ('disconnected', 1), ('disconnected', 5))
HEALTH = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
          'same_production_identity', 'same_host_mounts')
IDENTITIES = ('driver_sha256', 'workload_sha256', 'benchmark_sha256',
              'guard_sha256', 'recovery_gate_sha256')
SOCKET = '/var/run/ubus/r124-memory.sock'
LIBRARIES = {'/lib/libubus.so.20251202', '/lib/libubox.so.20260213', '/lib/libc.so',
             '/lib/libgcc_s.so.1', '/lib/libblobmsg_json.so.20260213', '/usr/lib/libjson-c.so.5.4.0'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        check(key not in result, f'duplicate JSON key: {key}')
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def integer(text, context):
    check(isinstance(text, str) and re.fullmatch(r'[0-9]+', text),
          f'{context}: expected unsigned decimal integer')
    return int(text)


def hashes(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})\s+(.+)', line)
        check(match is not None, f'{path}: invalid sha256sum line')
        check(match[2] not in result, f'{path}: duplicate path {match[2]}')
        result[match[2]] = match[1]
    return result


def process_identity(path):
    lines = path.read_text().splitlines()
    check(len(lines) == 1, f'{path}: expected one proc stat line')
    match = re.fullmatch(r'([0-9]+) \(.*\) (.*)', lines[0])
    check(match is not None, f'{path}: invalid proc stat')
    fields = match[2].split()
    check(len(fields) >= 20 and fields[0] in ('R', 'S', 'D', 'T', 't', 'I', 'W'),
          f'{path}: invalid/live process state')
    pid = integer(match[1], str(path))
    start = integer(fields[19], str(path))
    check(pid > 0, f'{path}: nonpositive PID')
    return pid, start


def status_metrics(path, pid):
    fields = {}
    for line in path.read_text().splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        check(key not in fields, f'{path}: duplicate status field {key}')
        fields[key] = value.split()
    check(fields.get('Pid') == fields.get('Tgid') == [str(pid)], f'{path}: PID/Tgid mismatch')
    check(fields.get('Threads') == ['1'], f'{path}: expected one daemon thread')
    check(fields.get('Cpus_allowed_list') == ['1'], f'{path}: daemon not pinned to CPU 1')
    state = fields.get('State', [])
    check(state and state[0] in ('R', 'S', 'D', 'T', 't', 'I', 'W'), f'{path}: daemon not live')
    result = {}
    for source, target in (('VmRSS', 'vmrss_kb'), ('RssAnon', 'rssanon_kb'), ('VmData', 'vmdata_kb')):
        value = fields.get(source, [])
        check(len(value) == 2 and value[1] == 'kB', f'{path}: invalid {source} units')
        result[target] = integer(value[0], f'{path}: {source}')
    return result


def pss_value(prefix):
    rollup = Path(str(prefix) + '-smaps-rollup.txt')
    error = Path(str(prefix) + '-smaps-error.txt')
    if not rollup.is_file():
        check(not error.exists(), f'{prefix}: smaps error exists without attempted rollup')
        return 'NA'
    check(error.is_file(), f'{prefix}: missing smaps read-error evidence')
    if error.read_text():
        return 'NA'  # A failed cat may leave a partial rollup file.
    values = []
    for line in rollup.read_text().splitlines():
        if line.startswith('Pss:'):
            match = re.fullmatch(r'Pss:\s+([0-9]+)\s+kB\s*', line)
            check(match is not None, f'{rollup}: malformed Pss field')
            values.append(int(match[1]))
    check(len(values) <= 1, f'{rollup}: duplicate Pss fields')
    return values[0] if values else 'NA'


def uptime(path):
    words = path.read_text().split()
    check(len(words) == 2 and all(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', x) for x in words),
          f'{path}: invalid proc uptime')
    return Decimal(words[0])


def cpu_set(text):
    cpus = set()
    for part in text.strip().split(','):
        match = re.fullmatch(r'([0-9]+)(?:-([0-9]+))?', part)
        check(match is not None, 'invalid online CPU list')
        first, last = int(match[1]), int(match[2] or match[1])
        check(first <= last, 'reversed online CPU range')
        cpus.update(range(first, last + 1))
    check({0, 1} <= cpus, 'required CPUs 0 and 1 are not online')
    return sorted(cpus)


def encoded_lengths(payload_bytes):
    """Exact helper envelope lengths, including ubus's 8-byte message header."""
    pad = lambda n: (n + 3) & ~3
    field = lambda name, n: pad(4 + pad(2 + len(name) + 1) + n)
    data = 4 + field('bytes', payload_bytes + 1)
    event_name_bytes = len('r124.memory') + 1
    request = 4 + 8 + pad(4 + len('send') + 1)
    request += pad(4 + field('id', event_name_bytes) + field('data', data - 4))
    relay = 4 + 8 + pad(4 + event_name_bytes) + pad(4 + data - 4)
    return {'data_blob_bytes': data, 'request_frame_bytes': 8 + request,
            'relay_frame_bytes': 8 + relay}


def verify_helper(case, payload_bytes, pid, baseline):
    lines = (case / 'helper.jsonl').read_text().splitlines()
    check(len(lines) == 3, f'{case}: helper must emit exactly three phases')
    rows = [json.loads(line, object_pairs_hook=unique_object) for line in lines]
    check([r['phase'] for r in rows] == ['READY', 'DELIVERED', 'CLOSED'],
          f'{case}: helper phase order mismatch')
    helper_pids, times = set(), []
    for index, row in enumerate(rows):
        expected_payload = 16 if index == 0 else payload_bytes
        expected = {'subject_pid': pid, 'subject_cpu': 1, 'client_cpu': 0,
                    'large_payload_bytes': payload_bytes, 'payload_bytes': expected_payload,
                    'received': 1, 'total_received': 1 if index == 0 else 2,
                    'base_fds': baseline, **encoded_lengths(expected_payload)}
        for key, value in expected.items():
            check(type(row.get(key)) is int and row[key] == value,
                  f'{case}: {row["phase"]} {key} mismatch')
        check(row.get('payload_checked') is True and row.get('listener_barrier') is True,
              f'{case}: missing payload or listener-drain barrier')
        check(row.get('holding') is (index < 2) and row.get('handlers_removed') is (index == 2),
              f'{case}: helper ownership/removal phase mismatch')
        check(type(row.get('helper_pid')) is int and row['helper_pid'] > 0 and row['helper_pid'] != pid,
              f'{case}: invalid helper PID')
        check(type(row.get('monotonic_ns')) is int and row['monotonic_ns'] > 0,
              f'{case}: invalid helper clock')
        helper_pids.add(row['helper_pid'])
        times.append(row['monotonic_ns'])
    check(len(helper_pids) == 1 and times[0] < times[1] < times[2],
          f'{case}: helper identity or phase-clock order changed')
    check((case / 'helper-exit.txt').read_text().strip() == '0', f'{case}: helper failed')
    check((case / 'helper.log').read_bytes() == b'', f'{case}: helper stderr is nonempty')
    check((case / 'daemon-exit.txt').read_text().strip() in ('0', '143'), f'{case}: daemon exit failed')
    return rows


def verify_archive(window):
    raw = window / 'raw'
    actual = {}
    for path in raw.rglob('*'):
        check(not path.is_symlink(), f'{path}: symlink in raw evidence')
        if path.is_file():
            actual[path.relative_to(raw).as_posix()] = digest(path)
        else:
            check(path.is_dir(), f'{path}: special file in raw evidence')
    archived = {}
    with tarfile.open(window / 'raw.tar.gz', 'r:gz') as archive:
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            parts = PurePosixPath(name).parts
            check(not PurePosixPath(name).is_absolute() and '..' not in parts,
                  f'{window}: unsafe archive member')
            if member.isdir():
                continue
            check(member.isfile(), f'{window}: non-regular archived evidence')
            check(name not in archived, f'{window}: duplicate archived member {name}')
            data = archive.extractfile(member).read()
            archived[name] = hashlib.sha256(data).hexdigest()
    check(actual == archived, f'{window}: archive and expanded raw evidence differ')
    return dict(sorted(actual.items()))


def verify_plan(plan):
    check(set(plan['subjects']) == {'c', 'r124'}, 'expected only exact C and R124 subjects')
    check(plan['candidate_sha256'] == plan['subjects']['r124'], 'candidate SHA mismatch')
    check(set(plan['libraries']) == LIBRARIES, 'expected the six frozen exact-image libraries')
    for sha in (*plan['subjects'].values(), *plan['libraries'].values(),
                *(plan[key] for key in (*IDENTITIES, 'namespace_sha256'))):
        check(re.fullmatch(r'[0-9a-f]{64}', sha), 'invalid frozen SHA256')
    windows = plan['windows']
    expected = [('c', 1, 1), ('r124', 1, 1), ('r124', 2, 2), ('c', 2, 2)]
    check(len(windows) == 4, 'expected four frozen windows')
    check([(w['subject'], w['order'], w['block']) for w in windows] == expected,
          'window subjects/size orders/blocks do not match the reversed design')
    labels = set()
    for index, window in enumerate(windows, 1):
        check(window['index'] == index, 'window index mismatch')
        label = window['label']
        check(re.fullmatch(r'[A-Za-z0-9_-]+', label) and label not in labels, 'invalid/duplicate window label')
        labels.add(label)
        check(window['implementation'] == ('c' if window['subject'] == 'c' else 'rs'),
              f'{label}: implementation mismatch')
    frozen = {}
    for name, sha in plan['files'].items():
        path = REPO / name
        check(path.is_file() and digest(path) == sha, f'{name}: frozen input changed or missing')
        frozen[name] = sha
    return frozen


def verify_window(window, plan, spec):
    check(not (window / 'FAILED.json').exists(), f'{window}: failed window')
    result = read(window / 'result.json')
    check(all(result.get(key) is True for key in HEALTH), f'{window}: health/cleanup gate failed')
    check(result['exit'] == 0 and result['pilot_only'] is True and result['installed'] is False
          and result['matrix'] is False and result['correctness_smoke_only'] is False,
          f'{window}: invalid collection mode/result')
    check(result['component'] == 'ubusd' and result['production_mode'] == 'stock', f'{window}: production mode changed')
    check(result['implementation'] == spec['implementation'] and result['iterations'] == spec['order'],
          f'{window}: implementation/size-order mismatch')
    subject_sha = plan['subjects'][spec['subject']]
    check(result['candidate_sha256'] == subject_sha, f'{window}: exact subject SHA mismatch')
    check(all(result[key] == plan[key] for key in IDENTITIES), f'{window}: tool/gate SHA mismatch')
    health = [read(window / f'health-{when}.json') for when in ('before', 'after')]
    check(health[0] == health[1] and health[0]['boot_id'] == plan['boot_id']
          and health[0]['mode'] == 'stock', f'{window}: health/boot/stock mode changed')
    raw = window / 'raw'
    check((raw / 'COMPLETE').is_file() and not (raw / 'FAILED.json').exists(), f'{window}: raw collection incomplete')
    raw_hashes = verify_archive(window)
    executable = '/sbin/ubusd' if spec['implementation'] == 'c' else '/tmp/bin/ubusd-rs'
    check(hashes(raw / 'binary-sha256.txt') == {executable: subject_sha}, f'{window}: raw binary mismatch')
    check(hashes(raw / 'benchmark-sha256.txt') == {
        '/tmp/bin/owrt-benchmark': plan['benchmark_sha256'], '/tmp/bin/ns-exec': plan['namespace_sha256'],
        '/tmp/bin/guard': plan['guard_sha256']}, f'{window}: raw helper identities mismatch')
    check(hashes(raw / 'workload-sha256.txt') == {'/tmp/workload.sh': plan['workload_sha256']},
          f'{window}: raw workload identity mismatch')
    check(hashes(raw / 'libraries.sha256') == plan['libraries'], f'{window}: six-library identities mismatch')
    verified = (raw / 'libraries-verified.txt').read_text().splitlines()
    check(len(verified) == 6 and set(verified) == {name + ': OK' for name in plan['libraries']},
          f'{window}: library post-check failed')
    check((raw / 'boot-id.txt').read_text().strip() == plan['boot_id'], f'{window}: raw boot changed')
    kernel = (raw / 'kernel.txt').read_text().strip()
    check(kernel and '\n' not in kernel, f'{window}: invalid kernel identity')
    cpus = cpu_set((raw / 'cpus-online.txt').read_text())
    sizes = list(SIZES if spec['order'] == 1 else reversed(SIZES))
    meta = read(raw / 'meta.json')
    expected_meta = {'implementation': spec['implementation'], 'order': spec['order'], 'sizes': sizes,
                     'cases': 3, 'subject_cpu': 1, 'client_cpu': 0,
                     'phase_delays_seconds': [1, 5], 'small_payload_bytes': 16}
    check(meta == expected_meta, f'{window}: workload metadata differs')
    reader = csv.DictReader((raw / 'memory.csv').read_text().splitlines())
    check(reader.fieldnames == list(HEADER), f'{window}: memory CSV header mismatch')
    rows = list(reader)
    check(len(rows) == 21 and all(set(row) == set(HEADER) for row in rows), f'{window}: expected 21 CSV snapshots')
    expected_keys = [(size, phase, delay) for size in sizes for phase, delay in PHASES]
    check([(integer(r['payload_bytes'], str(window)), r['phase'], integer(r['delay_seconds'], str(window)))
           for r in rows] == expected_keys, f'{window}: snapshot order/size/phase mismatch')
    cases, snapshots, identities, observed_times, starts = [], [], set(), [], []
    for size_index, size in enumerate(sizes, 1):
        case = raw / str(size)
        check((case / 'COMPLETE').is_file() and not (case / 'FAILED.json').exists(), f'{case}: incomplete case')
        identity = process_identity(case / 'stat-start.txt')
        check(identity not in identities, f'{case}: daemon identity reused between sizes')
        identities.add(identity)
        pid, starttime = identity
        starts.append(starttime)
        baseline = integer((case / 'baseline-fds.txt').read_text().strip(), str(case))
        check(baseline > 0, f'{case}: empty baseline FD set')
        helper = verify_helper(case, size, pid, baseline)
        case_rows = []
        phase_origins = {phase: uptime(case / f'{phase}-start-uptime.txt')
                         for phase in ('connected', 'held', 'disconnected')}
        previous = None
        for row in rows[(size_index - 1) * 7:size_index * 7]:
            phase, delay = row['phase'], int(row['delay_seconds'])
            prefix = case / f'{phase}-{delay}'
            for when in ('before', 'after'):
                check(process_identity(Path(str(prefix) + f'-stat-{when}.txt')) == identity,
                      f'{prefix}: PID/starttime changed')
            metrics = status_metrics(Path(str(prefix) + '-status.txt'), pid)
            metrics['pss_kb'] = pss_value(prefix)
            for metric in METRICS:
                check(row[metric] == str(metrics[metric]), f'{prefix}: CSV {metric} differs from proc evidence')
            check(integer(row['daemon_pid'], str(prefix)) == pid, f'{prefix}: CSV PID mismatch')
            fds = Path(str(prefix) + '-fds.txt').read_text().splitlines()
            fd_numbers = [integer(fd, str(prefix)) for fd in fds]
            expected_fds = baseline + (2 if phase in ('connected', 'held') else 0)
            check(len(fd_numbers) == len(set(fd_numbers)) == expected_fds
                  and integer(row['fds'], str(prefix)) == expected_fds, f'{prefix}: FD count mismatch')
            check(hashes(Path(str(prefix) + '-exe.sha256')) == {f'/proc/{pid}/exe': subject_sha},
                  f'{prefix}: mapped executable SHA mismatch')
            check(Path(str(prefix) + '-cmdline.txt').read_text().splitlines() == ['/sbin/ubusd', '-s', SOCKET],
                  f'{prefix}: daemon argv mismatch')
            observed = uptime(Path(str(prefix) + '-uptime.txt'))
            check(previous is None or observed > previous, f'{prefix}: nonmonotonic snapshot uptime')
            previous = observed
            observed_times.append(observed)
            origin = phase_origins.get(phase)
            elapsed = observed - origin if origin is not None else None
            if elapsed is not None:
                check(elapsed >= Decimal(delay) - Decimal('0.02'), f'{prefix}: sample precedes requested delay')
            snapshot = {'payload_bytes': size, 'size_index': size_index, 'phase': phase,
                        'nominal_delay_seconds': delay, 'daemon_pid': pid, 'daemon_starttime_ticks': starttime,
                        'uptime_seconds': float(observed),
                        'phase_start_uptime_seconds': float(origin) if origin is not None else 'NA',
                        'phase_elapsed_seconds': float(elapsed) if elapsed is not None else 'NA',
                        'fds': expected_fds, 'fd_numbers': sorted(fd_numbers), **metrics}
            case_rows.append(snapshot)
            snapshots.append(snapshot)
        by_phase = {(r['phase'], r['nominal_delay_seconds']): r for r in case_rows}
        check(Decimal(str(by_phase[('empty', 0)]['uptime_seconds'])) <= phase_origins['connected'],
              f'{case}: connected phase precedes empty baseline')
        for earlier, later in (('connected', 'held'), ('held', 'disconnected')):
            check(Decimal(str(by_phase[(earlier, 5)]['uptime_seconds'])) <= phase_origins[later],
                  f'{case}: phase order overlaps')
        cases.append({'payload_bytes': size, 'size_index': size_index, 'daemon_pid': pid,
                      'daemon_starttime_ticks': starttime, 'baseline_fds': baseline,
                      'helper_phases': helper})
    check(len(identities) == len({pid for pid, _ in identities}) == 3
          and all(a < b for a, b in zip(starts, starts[1:]))
          and all(a < b for a, b in zip(observed_times, observed_times[1:])),
          f'{window}: three fresh cases not collected in order')
    return {**spec, 'subject_sha256': subject_sha, 'kernel': kernel, 'online_cpus': cpus,
            'result_sha256': digest(window / 'result.json'),
            'health_before_sha256': digest(window / 'health-before.json'),
            'health_after_sha256': digest(window / 'health-after.json'),
            'raw_archive_sha256': digest(window / 'raw.tar.gz'), 'raw_sha256': raw_hashes,
            'cases': cases, 'snapshots': snapshots}


def subtract(left, right):
    return {key: left[key] - right[key] if left[key] != 'NA' and right[key] != 'NA' else 'NA'
            for key in METRICS}


def comparisons(windows):
    result = []
    for block in (1, 2):
        pair = {w['subject']: w for w in windows if w['block'] == block}
        for size in SIZES:
            for delay in (1, 5):
                subjects = {}
                for subject in ('c', 'r124'):
                    snapshots = pair[subject]['snapshots']
                    absolute = {}
                    elapsed = {}
                    for phase in ('empty', 'connected', 'held', 'disconnected'):
                        row = next(r for r in snapshots if r['payload_bytes'] == size and r['phase'] == phase
                                   and r['nominal_delay_seconds'] == (0 if phase == 'empty' else delay))
                        absolute[phase] = {key: row[key] for key in METRICS}
                        elapsed[phase] = row['phase_elapsed_seconds']
                    subjects[subject] = {'window': pair[subject]['label'], 'absolute_kib': absolute,
                                         'phase_elapsed_seconds': elapsed,
                                         'held_minus_connected_kib': subtract(absolute['held'], absolute['connected']),
                                         'disconnected_minus_empty_kib': subtract(absolute['disconnected'], absolute['empty'])}
                c, candidate = subjects['c'], subjects['r124']
                differences = {'absolute_kib': {phase: subtract(candidate['absolute_kib'][phase], c['absolute_kib'][phase])
                                                for phase in ('empty', 'connected', 'held', 'disconnected')},
                               'held_minus_connected_kib': subtract(candidate['held_minus_connected_kib'], c['held_minus_connected_kib']),
                               'disconnected_minus_empty_kib': subtract(candidate['disconnected_minus_empty_kib'], c['disconnected_minus_empty_kib'])}
                result.append({'block': block, 'payload_bytes': size, 'nominal_delay_seconds': delay,
                               'subjects': subjects, 'r124_minus_c': differences})
    return result


def report(plan_path, root):
    plan = read(plan_path)
    frozen = verify_plan(plan)
    check((root / 'COMPLETE').is_file() and not (root / 'FAILED.json').exists(), 'root collection incomplete/failed')
    if (root / 'plan.json').exists():
        check((root / 'plan.json').read_bytes() == plan_path.read_bytes(), 'root frozen plan differs')
    windows = [verify_window(root / spec['label'], plan, spec) for spec in plan['windows']]
    check(len({w['kernel'] for w in windows}) == 1 and len({tuple(w['online_cpus']) for w in windows}) == 1,
          'kernel or online CPUs changed between windows')
    return {'schema_version': 1, 'plan_sha256': digest(plan_path), 'reporter_sha256': digest(Path(__file__)),
            'frozen_files_sha256': frozen, 'candidate_sha256': plan['candidate_sha256'],
            'subjects': plan['subjects'], 'boot_id': plan['boot_id'], 'units': 'KiB (proc kB)',
            'window_count': len(windows), 'snapshot_count': sum(len(w['snapshots']) for w in windows),
            'all_windows_cleaned_and_production_stock': True, 'windows': windows,
            'paired_by_block_size_delay': comparisons(windows), 'acceptance': None,
            'limits': [
                'Two chronological reversed blocks; descriptive absolute values and differences only, no confidence intervals.',
                'Each payload size starts a fresh daemon; empty, connected-small-event, held-large-event and disconnected baselines differ.',
                'RSS counters can be imprecise. Unavailable PSS and differences involving it remain NA.',
                'Snapshots are not allocation peaks or kernel/socket-buffer totals and do not measure CPU, latency or whole-component memory.',
                'Actual phase elapsed seconds use proc uptime only; helper CLOCK_MONOTONIC timestamps remain separate.',
                'Empty has no phase-start marker: its absolute uptime is preserved and phase elapsed is NA.',
                'Nominal 1/5-second delays are not substituted for observed sampling times. Earlier experiments are not pooled.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path)
    parser.add_argument('root', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = report(args.plan.resolve(), args.root.resolve())
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'windows': result['window_count'], 'snapshots': result['snapshot_count'],
                      'paired_cells': len(result['paired_by_block_size_delay']), 'acceptance': None}))


if __name__ == '__main__':
    main()
