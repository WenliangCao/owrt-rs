#!/usr/bin/env python3
"""Count one complete strace process tree; elapsed strace time is not a metric."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arguments(body):
    """Split syscall arguments while retaining nested strace structures."""
    start = body.index('(') + 1
    depth = 0
    quote = False
    escape = False
    result = []
    at = start
    for index in range(start, len(body)):
        char = body[index]
        if quote:
            if escape:
                escape = False
            elif char == '\\':
                escape = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
        elif char in '([{':
            depth += 1
        elif char == ')' and depth == 0:
            result.append(body[at:index].strip())
            return result
        elif char in ')]}':
            depth -= 1
        elif char == ',' and depth == 0:
            result.append(body[at:index].strip())
            at = index + 1
    return []


def fd_role(value):
    if 'NETLINK' in value:
        return 'netlink'
    if 'pipe:' in value:
        return 'pipe'
    if ':15354' in value:
        return 'upstream-socket'
    if 'TCP' in value:
        return 'downstream-tcp' if '->' in value else 'tcp-listener'
    if 'UDP' in value:
        return 'dns-udp' if ':15353' in value else 'other-udp'
    if 'daemon.log' in value:
        return 'daemon-log'
    if '.stdout' in value or '.stderr' in value:
        return 'diagnostic-output'
    if '</' in value:
        return 'other-file'
    return 'unannotated'


def parameter_counts(name, body):
    args = arguments(body)
    result = []
    if not args:
        return result
    fd_calls = {'read', 'readv', 'write', 'writev', 'recvmsg', 'recvmmsg', 'recvfrom',
                'sendmsg', 'sendmmsg', 'sendto', 'fcntl', 'ioctl', 'setsockopt',
                'getsockopt', 'close', 'accept', 'accept4', 'shutdown'}
    if name in fd_calls:
        result.append('fd_role=' + fd_role(args[0]))
    if name in ('recvmsg', 'sendmsg') and len(args) >= 3:
        result.append('flags=' + args[2])
    if name in ('recvfrom', 'sendto') and len(args) >= 4:
        result.append('flags=' + args[3])
    if name in ('recvmmsg', 'sendmmsg') and len(args) >= 4:
        result.append('flags=' + args[3])
        result.append('vlen=' + args[2])
    if name in ('read', 'write', 'recvfrom', 'sendto') and len(args) >= 3:
        result.append('requested_bytes=' + args[2])
    if name in ('readv', 'writev') and len(args) >= 3:
        result.append('iovcnt=' + args[2])
    if name in ('readv', 'writev', 'recvmsg', 'sendmsg', 'recvmmsg', 'sendmmsg'):
        result.extend('iov_len=' + value for value in re.findall(r'iov_len=(\d+)', body))
        result.extend('cmsg_type=' + value for value in re.findall(r'cmsg_type=(\w+)', body))
        result.extend('controllen=' + value for value in re.findall(r'msg_controllen=(\d+)', body))
    if name in ('poll', 'ppoll') and len(args) >= 3:
        result.append('nfds=' + args[1])
        timeout = args[2]
        kind = ('infinite' if timeout in ('NULL', '-1') else 'zero' if timeout == '0'
                or timeout == '{tv_sec=0, tv_nsec=0}' else 'positive')
        result.append('timeout=' + kind)
        result.extend('interest=' + value for value in re.findall(r'(?<!r)events=([^},]+)', args[0]))
    if name in ('clock_gettime', 'clock_getres', 'clock_nanosleep'):
        result.append('clock=' + args[0])
    if name in ('fcntl', 'ioctl') and len(args) >= 2:
        result.append('command=' + args[1])
        if name == 'fcntl' and len(args) >= 3:
            result.append('argument=' + args[2])
    if name in ('setsockopt', 'getsockopt') and len(args) >= 3:
        result.append('option=' + args[1] + '/' + args[2])
        if name == 'setsockopt' and len(args) >= 4:
            # Scalar values reveal blocking/ancillary settings without storing
            # synthetic packet contents or variable process addresses.
            if re.fullmatch(r'\[-?\d+\]', args[3]):
                result.append('value=' + args[3])
    return result


def parse(lines, root_pid):
    calls = defaultdict(lambda: defaultdict(lambda: {
        'entered': 0, 'completed': 0, 'boundary_completions': 0,
        'errors': Counter(), 'return_values': Counter(), 'parameters': Counter()}))
    pending = {}
    parents = {}
    exited = set()
    execs = []
    unparsed = []
    for line in lines:
        match = re.match(r'\s*(\d+)\s+(\d+\.\d+)\s+(.*)', line.rstrip())
        if not match:
            if line.strip():
                unparsed.append(line.rstrip())
            continue
        pid, _, body = match.groups()
        pid = int(pid)
        if body.startswith('+++ exited') or body.startswith('+++ killed'):
            exited.add(pid)
            continue
        if body.startswith('--- ') or body.startswith('+++ '):
            continue
        resumed = re.match(r'<\.\.\. (\w+) resumed>(.*)', body)
        boundary = False
        if resumed:
            name, tail = resumed.groups()
            if pid in pending:
                old_name, beginning = pending.pop(pid)
                assert old_name == name, (pid, old_name, name)
                body = beginning + tail
            else:
                boundary = True
                body = name + '(<entry-before-capture>' + tail
        else:
            entry = re.match(r'(\w+)\(', body)
            if not entry:
                unparsed.append(line.rstrip())
                continue
            name = entry[1]
            calls[pid][name]['entered'] += 1
        unfinished = next((marker for marker in ('<unfinished ...>', '<detached ...>') if marker in body), None)
        if unfinished:
            assert pid not in pending
            pending[pid] = (name, body.split(unfinished)[0])
            continue
        row = calls[pid][name]
        row['completed'] += 1
        row['boundary_completions'] += int(boundary)
        returned = re.search(r'\)\s+=\s+(0x[0-9a-f]+|-?\d+|\?)(?:\s+([A-Z][A-Z0-9_]+))?', body)
        if returned:
            value, error = returned.groups()
            row['return_values'][value] += 1
            if value == '-1' and error:
                row['errors'][error] += 1
            if name in ('fork', 'vfork', 'clone', 'clone3') and value.isdigit() and int(value) > 0:
                child = int(value)
                assert child not in parents or parents[child] == pid
                parents[child] = pid
        if not boundary:
            row['parameters'].update(parameter_counts(name, body))
            flags = re.search(r'\(flags ([^)]+)\)', body)
            if name == 'fcntl' and flags:
                row['parameters']['return_flags=' + flags[1]] += 1
        if name in ('execve', 'execveat'):
            execs.append({'pid': pid, 'call': body})
    pids = set(calls)
    for pid in pids:
        seen = set()
        cursor = pid
        while cursor != root_pid:
            assert cursor not in seen and cursor in parents, ('unowned/unbound PID', pid, cursor)
            seen.add(cursor)
            cursor = parents[cursor]
    return {'calls': dict(calls), 'parents': parents, 'exited': sorted(exited),
            'incomplete_entries': {pid: name for pid, (name, _) in pending.items()},
            'execs': execs, 'unparsed_lines': unparsed}


def aggregate(calls, pids, queries):
    result = defaultdict(lambda: {'entered': 0, 'completed': 0, 'boundary_completions': 0,
                                 'errors': Counter(), 'return_values': Counter(), 'parameters': Counter()})
    for pid in pids:
        for name, row in calls.get(pid, {}).items():
            for key in ('entered', 'completed', 'boundary_completions'):
                result[name][key] += row[key]
            for key in ('errors', 'return_values', 'parameters'):
                result[name][key].update(row[key])
    for row in result.values():
        row['entered_per_completed_client_query'] = row['entered'] / queries
    return dict(sorted(result.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    p = args.capture
    client = json.loads((p / 'client.json').read_text())
    complete = json.loads((p / 'complete.json').read_text())
    tail = json.loads((p / 'tree-tail.json').read_text())
    assert complete['valid_count_profile'] and complete['tree_tail_complete']
    assert tail['complete'] and not tail['remaining_children']
    assert not client['interrupted'] and not client['output_failed']
    expected_counts = (500, 2000) if client['mode'] == 'dhcp' else (1000, 4000)
    if client['mode'] == 'dhcp':
        assert not json.loads((p / 'fixed-count-validation.json').read_text())['errors']
    for phase, expected in zip(('warmup', 'measurement'), expected_counts):
        counts = client[phase]
        assert counts['scheduled'] == counts['sent'] == counts['correct'] == expected
        assert all(counts[key] == 0 for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
    identity = json.loads((p / 'process-identity.json').read_text())
    root_pid = identity['pid']
    trace = parse((p / 'syscalls.txt').open(), root_pid)
    assert not trace['unparsed_lines'], trace['unparsed_lines'][:3]
    assert not trace['execs'], 'child exec requires a separate image-mapping identity audit'
    queries = client['warmup']['correct'] + client['measurement']['correct']
    pids = set(trace['calls'])
    report = {'scope': 'Entered/completed calls for the captured owned process tree; complete warmup/measurement operations plus fixed grace, not pure steady per-operation cost.',
              'parser_sha256': sha(Path(__file__)), 'private_directory': str(p),
              'root_pid': root_pid, 'processes': sorted(pids), 'fork_parent_by_pid': trace['parents'],
              'observed_exited_pids': trace['exited'], 'incomplete_entered_calls': trace['incomplete_entries'],
              'exec_calls': trace['execs'], 'queries': queries,
              'tree_tail': tail,
              'client_counts': {key: client[key] for key in ('warmup', 'measurement')},
              'whole_tree': aggregate(trace['calls'], pids, queries),
              'parent_only': aggregate(trace['calls'], [root_pid], queries),
              'children_only': aggregate(trace['calls'], pids - {root_pid}, queries),
              'per_process_entered': {pid: {name: row['entered'] for name, row in sorted(calls.items())}
                                      for pid, calls in trace['calls'].items()},
              'raw_trace': {'bytes': (p / 'syscalls.txt').stat().st_size, 'sha256': sha(p / 'syscalls.txt')},
              'limitations': ['strace elapsed time is not compared.',
                              'vDSO clock calls are invisible to syscall tracing.',
                              'Ancillary flags and buffers are observed; user-space cmsg parsing instructions are not.',
                              'Parameters are counted on completed calls; in-flight boundary calls are listed separately.']}
    args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'bytes': args.out.stat().st_size, 'sha256': sha(args.out), 'pids': sorted(pids)}))


if __name__ == '__main__':
    main()
