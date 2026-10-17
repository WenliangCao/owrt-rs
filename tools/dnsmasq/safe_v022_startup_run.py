#!/usr/bin/env python3
"""Forty bounded starts through the traffic driver's existing health boundary."""
import hashlib
import json
from pathlib import Path
import statistics


ORDER = (('helper', 'k'), ('helper', 'candidate'),
         ('resolver', 'candidate'), ('resolver', 'k'))


def labels(prefix):
    return [f'{prefix}-startup-{mode}-{role}' for mode, role in ORDER]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fd_inventory(path):
    result = []
    for line in path.read_text().splitlines():
        if line.startswith('fd='):
            number, target = line[3:].split(' target=', 1)
            result.append({'fd': int(number), 'target': target})
        elif line.startswith('flags:'):
            require(bool(result), 'FD flags without descriptor')
            result[-1]['flags'] = int(line.split()[1], 8)
    require(bool(result) and len({row['fd'] for row in result}) == len(result), 'missing/duplicate FD evidence')
    require(all('flags' in row for row in result), 'missing FD flags')
    for row in result:
        row['cloexec'] = bool(row['flags'] & 0o2000000)
        row['opath'] = bool(row['flags'] & 0o10000000)
        row['pipe'] = row['target'].startswith('pipe:[')
    return sorted(result, key=lambda row: row['fd'])


def validate(folder, mode, role, expected):
    require((folder / 'COMPLETE').is_file(), 'startup group did not complete')
    require((folder / 'probe.exit').read_text().strip() == '0', 'startup probe failed')
    require(not (folder / 'startup.stderr').read_bytes(), 'startup probe wrote stderr')
    for name in ('elf.sha256', 'elf-after.sha256'):
        require((folder / name).read_text().split()[0] == expected, 'startup ELF identity differs')
    rows = [json.loads(line) for line in (folder / 'startup.jsonl').read_text().splitlines()]
    starts = [row for row in rows if row['kind'] == 'startup']
    summaries = [row for row in rows if row['kind'] == 'summary']
    require(len(starts) == 10 and len(summaries) == 1 and [row['index'] for row in starts] == list(range(10)),
            'startup count/order differs')
    summary = summaries[0]
    require(summary['ok'] and summary['completed'] == 10 and summary['cpu_complete'], 'startup summary incomplete')
    proc_mode = 'absent' if mode == 'helper' else 'present'
    inventory = []
    for row in starts:
        require(row['ok'] and row['cpu_complete'] and row['all_children_reaped'] and
                row['owner_reaped'] and row['owner_wait_status'] == 0 and not row['forced_cleanup'] and
                not row['bad_exits'] and row['period_overrun_ns'] == 0, 'startup/reaping/cadence failed')
        require(row['mode'] == mode and row['proc_mode'] == proc_mode and
                row['nofile_soft'] == 1024 and row['nofile_hard'] == 4096, 'startup boundary differs')
        require(row['ready_ns'] - row['start_ns'] == row['latency_ns'] and
                row['start_ns'] < row['ready_ns'] <= row['snapshot_ns'] <= row['finished_ns'],
                'startup timing boundaries differ')
        for kind in ('user', 'system'):
            require(row[f'children_{kind}_usec'] - row[f'setup_{kind}_usec'] == row[f'timed_tree_{kind}_usec'],
                    'measured wrapper CPU accounting differs')
        resources = row['resources']
        require(len(resources) == (2 if mode == 'helper' else 1), 'unexpected startup process cohort')
        require(resources[0]['uid'] == resources[0]['gid'] == 453 and resources[0]['cap_eff'] == 0x3400,
                'owner credentials differ')
        trial = folder / 'trials' / f'run-{row["index"]:02d}'
        owner = fd_inventory(trial / 'owner-fds.raw')
        require(len(owner) == resources[0]['fd_count'], 'owner FD inventory differs')
        image = [fd for fd in owner if fd['opath']]
        require(len(image) == (1 if role == 'candidate' else 0) and
                all(fd['cloexec'] and fd['target'].endswith('/usr/sbin/dnsmasq') for fd in image),
                'owner retained image FD contract differs')
        item = {'index': row['index'], 'owner': owner}
        if mode == 'helper':
            require(row['callback_exact_once'] is True and resources[1]['uid'] == resources[1]['gid'] == 0,
                    'helper callback or credentials differ')
            helper = fd_inventory(trial / 'helper-fds.raw')
            require(len(helper) == resources[1]['fd_count'], 'helper FD inventory differs')
            pipes = [fd for fd in helper if fd['fd'] > 2]
            copies = 2 if role == 'candidate' else 1
            require(len(pipes) == 2 * copies and all(fd['pipe'] for fd in pipes), 'helper inherited unexpected FD')
            groups = {}
            for fd in pipes:
                groups.setdefault(fd['target'], []).append(fd)
            require(len(groups) == 2 and all(len(group) == copies for group in groups.values()),
                    'helper underlying pipe count differs')
            require(sorted([sorted(fd['flags'] & 3 for fd in group) for group in groups.values()]) ==
                    [[0] * copies, [1] * copies], 'helper pipe directions differ')
            require(role != 'candidate' or all(fd['cloexec'] for fd in pipes), 'helper pipe missing CLOEXEC')
            item['helper'] = helper
        inventory.append(item)
    for key in ('children_user_usec', 'children_system_usec', 'timed_tree_user_usec', 'timed_tree_system_usec'):
        require(summary[key] == sum(row[key] for row in starts), 'ten-start CPU sum differs: ' + key)
    return {'mode': mode, 'artifact': role, 'starts': starts, 'summary': summary, 'fd_inventory': inventory,
            'startup_jsonl_sha256': hashlib.sha256((folder / 'startup.jsonl').read_bytes()).hexdigest()}


def execute_supplement(ctx, qualification):
    # Import lazily so offline validation does not import a live controller.
    from safe_v022_device_run import execute_owned_group
    run = ctx['run']
    prefix = qualification['prefix']
    groups = []
    for (mode, role), label in zip(ORDER, labels(prefix)):
        folder, exit_code = execute_owned_group(ctx, label, 'safe_v022_startup_group.sh',
                                               [mode, role, label], 100)
        require(exit_code == 0, 'startup group failed; archived attempt retained')
        result = validate(folder, mode, role, qualification['artifacts'][role]['sha256'])
        groups.append({'label': label, **result})
        run.write(ctx['out'] / 'startup-progress.json', groups)
    comparisons = {}
    for mode in ('helper', 'resolver'):
        left, right = [next(row for row in groups if row['mode'] == mode and row['artifact'] == role)
                       for role in ('k', 'candidate')]
        latency = {role: statistics.median(row['latency_ns'] for row in group['starts']) / 1e6
                   for role, group in (('k', left), ('candidate', right))}
        comparisons[mode] = {
            'median_ready_ms': latency,
            'median_ready_delta_ms': latency['candidate'] - latency['k'],
            'ten_start_timed_tree_cpu_us': {role: sum(group['summary'][key] for key in
                 ('timed_tree_user_usec', 'timed_tree_system_usec')) for role, group in (('k', left), ('candidate', right))},
            'scope': 'one ten-start block per artifact, no paired-order or significance claim; 1ms ready observation floor',
        }
    result = {'starts': 40, 'groups': groups, 'comparisons': comparisons,
              'cpu': 'RUSAGE_CHILDREN after all owned descendants reaped; whole and measured pre-exec setup retained; '
                     'timed subtracts only child RUSAGE_SELF setup; returned unit1us, not a measured accuracy guarantee',
              'fd': 'all descriptors include stdio; owner O_PATH+1 and helper two-pipe duplication+2 checked; '
                    'pending resolver pipe/stdio evidence belongs to separate qualified Oracle pressure fixture',
              'scope': 'helper no-proc; resolver proc-visible on both sides because K no-proc runtime lookup fails',
              'status': 'COLLECTED_REQUIRES_FINAL_REVIEW'}
    run.write(ctx['out'] / 'startup-supplement.json', result)
    require(all(value['median_ready_delta_ms'] <= 1 for value in comparisons.values()),
            'startup median regressed by more than1ms; final promotion requires root review')
    return result
