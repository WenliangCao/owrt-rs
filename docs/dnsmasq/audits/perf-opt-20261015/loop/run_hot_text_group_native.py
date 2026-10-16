#!/usr/bin/env python3
"""Fixed independent G/c95 mechanism screen, reusing the existing hot15 probe."""
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time

base = Path(sys.argv[1]).resolve()
plan = json.loads((base / 'plan.json').read_text())
assert not (base / 'result.json').exists(), 'fresh attempt required'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
state = {'plan_sha256': sha(base / 'plan.json'), 'runner_sha256': sha(Path(__file__)),
         'status': 'preparing', 'pid': os.getpid(), 'commands': [], 'artifacts': {}, 'rows': []}
stop = False


def save():
    tmp = base / 'result.json.tmp'
    tmp.write_text(json.dumps(state, indent=2) + '\n')
    tmp.replace(base / 'result.json')


def interrupted(_signal, _frame):
    global stop
    stop = True


def check_stop():
    if stop or Path(plan['stop_file']).exists():
        raise RuntimeError('requested stop; partial data retained')


def run(label, argv):
    check_stop()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    row = {'label': label, 'argv': list(map(str, argv)), 'started_epoch': time.time()}
    with (base / (label + '.stdout')).open('wb') as stdout, (base / (label + '.stderr')).open('wb') as stderr:
        p = subprocess.Popen(row['argv'], stdout=stdout, stderr=stderr, start_new_session=True)
        state.update(status='running', active={'label': label, 'pid': p.pid})
        save()
        try:
            while True:
                try:
                    status = p.wait(timeout=.2)
                    break
                except subprocess.TimeoutExpired:
                    check_stop()
                    if time.monotonic_ns() - started > 600 * 10**9:
                        raise RuntimeError('command timeout; partial data retained')
        except BaseException:
            subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(p.pid)], check=False)
            p.wait(timeout=10)
            raise
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    row.update(returncode=status, elapsed_ns=time.monotonic_ns() - started,
               user_cpu_ns=round((after.ru_utime - before.ru_utime) * 1e9),
               system_cpu_ns=round((after.ru_stime - before.ru_stime) * 1e9),
               stdout_sha256=sha(base / (label + '.stdout')), stderr_sha256=sha(base / (label + '.stderr')))
    state['commands'].append(row)
    state['active'] = None
    save()
    assert status == 0, label
    print(label, status, flush=True)
    return json.loads((base / (label + '.stdout')).read_text()) if '-build' not in label else None


def counters(label, operations):
    text = (base / (label + '.csv')).read_text()
    attrs = (base / (label + '.stderr')).read_text().split('perf_event_attr:')[1:]
    assert len(attrs) == 2
    assert all(re.search(r'^\s*inherit\s+1\s*$', a, re.M) and
               re.search(r'^\s*exclude_kernel\s+1\s*$', a, re.M) for a in attrs)
    opened = re.findall(r'sys_perf_event_open: pid (-?\d+)\s+cpu -1\s+group_fd (-?\d+)\s+flags \S+ = (\d+)', (base / (label + '.stderr')).read_text())
    assert len(opened) == 2 and opened[0][0] == opened[1][0]
    assert opened[0][1] == '-1' and opened[1][1] == opened[0][2]
    result = {}
    for event in ('instructions:u', 'cycles:u'):
        rows = [r for r in csv.reader(text.splitlines()) if len(r) >= 5 and r[2] == event]
        raw = re.findall(r'^' + re.escape(event) + r': (\d+) (\d+) (\d+)\s*$', text, re.M)
        assert len(rows) == len(raw) == 1
        count, enabled, running = map(int, raw[0])
        assert count > 0 and 0 < running == enabled, 'unscaled grouped events required'
        assert abs(float(rows[0][0]) - count) <= 1 and float(rows[0][4]) == 100
        result[event] = {'raw_count': count, 'enabled_ns': enabled, 'running_ns': running,
                         'per_operation': count / operations}
    assert len({(r['enabled_ns'], r['running_ns']) for r in result.values()}) == 1
    return {'events': result, 'user_ipc': result['instructions:u']['raw_count'] / result['cycles:u']['raw_count'],
            'csv_sha256': sha(base / (label + '.csv'))}


def verify_sources():
    for row in plan['sources'].values():
        assert all(sha(Path(row['directory']) / path) == digest for path, digest in row['files'].items())


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    assert os.getpriority(os.PRIO_PROCESS, 0) == 0
    os.sched_setaffinity(0, {plan['build_cpu']})
    verify_sources()
    assert sha(base / plan['probe']['file']) == plan['probe']['sha256']
    with Path(plan['build_lock']).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        target = Path(plan['native_target'])
        for side, row in plan['sources'].items():
            source = Path(row['directory'])
            run(side + '-lib-build', ['/home/ubuntu/.cargo/bin/cargo', '+1.98.1', 'build', '--locked',
                '--manifest-path', source / 'components/dnsmasq/Cargo.toml', '--lib', '--release',
                '--target-dir', target, '-j', '1'])
            run(side + '-probe-build', ['/home/ubuntu/.cargo/bin/rustc', '+1.98.1', '--edition=2021',
                '-C', 'opt-level=3', '-C', 'panic=abort', '-C', 'lto=true', '-C', 'codegen-units=1',
                '--extern', 'dnsmasq_rs=' + str(target / 'release/libdnsmasq_rs.rlib'), '-L',
                'dependency=' + str(target / 'release/deps'), base / plan['probe']['file'], '-o', base / side])
            state['artifacts'][side] = {'elf_sha256': sha(base / side), 'rlib_sha256': sha(target / 'release/libdnsmasq_rs.rlib')}
            save()
    verify_sources()
    time.sleep(5)
    for candidate in plan['phase_order']:
        for scene in plan['scenes']:
            for observer, pairs in [('stat', plan['stat_pairs']), ('plain', plan['plain_pairs'])]:
                operations = plan['stat_operations'] if observer == 'stat' else plan['plain_operations'][scene]
                expected = plan['expected_checksum_per_2000000_operations'][scene] * operations // 2000000
                for pair in range(1, pairs + 1):
                    for side in (('G', candidate) if pair % 2 else (candidate, 'G')):
                        label = f'{candidate}-{scene}-{observer}-r{pair}-{side}'
                        assert sha(base / side) == state['artifacts'][side]['elf_sha256']
                        command = ['taskset', '-c', str(plan['cpu']), 'nice', '-n', str(plan['nice']), base / side, scene, operations]
                        if observer == 'stat':
                            command = ['sudo', '-n', 'perf', 'stat', '-vv', '-x,', '-e', plan['stat_event'], '-o', base / (label + '.csv'), '--'] + command
                        result = run(label, command)
                        assert result['scene'] == scene and result['operations'] == operations
                        assert all(result[k] == 0 for k in ('allocations', 'reallocations', 'requested_bytes', 'live_bytes_delta'))
                        assert result['checksum'] == expected
                        row = {'candidate': candidate, 'side': side, 'scene': scene, 'observer': observer,
                               'pair': pair, 'label': label, 'probe': result}
                        if observer == 'stat':
                            row['stat'] = counters(label, operations)
                        else:
                            command_result = state['commands'][-1]
                            row['cpu_ns'] = command_result['user_cpu_ns'] + command_result['system_cpu_ns']
                            row['wall_ns'] = command_result['elapsed_ns']
                        state['rows'].append(row)
                        save()
    verify_sources()
    assert all(sha(base / side) == row['elf_sha256'] for side, row in state['artifacts'].items())
    assert len(state['rows']) == 2 * len(plan['phase_order']) * len(plan['scenes']) * (plan['stat_pairs'] + plan['plain_pairs'])
    state['status'] = 'complete'
except BaseException as error:
    state.update(status='failed_or_stopped', error=repr(error))
    raise
finally:
    save()
