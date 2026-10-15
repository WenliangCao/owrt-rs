#!/usr/bin/env python3
"""Fixed, interruptible count-only screen for two independent F prototypes."""
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tarfile
import time

base = Path(sys.argv[1]).resolve()
plan = json.loads((base / 'plan.json').read_text())
assert not (base / 'result.json').exists(), 'fresh attempt required'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
state = {'plan_sha256': sha(base / 'plan.json'), 'runner_sha256': sha(Path(__file__)),
         'status': 'preparing', 'runner_pid': os.getpid(), 'commands': [], 'artifacts': {}, 'rows': []}
stop_requested = False


def save():
    temporary = base / 'result.json.tmp'
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(base / 'result.json')


class Stopped(Exception):
    pass


def stop_signal(_number, _frame):
    global stop_requested
    stop_requested = True


def should_stop():
    return stop_requested or Path(plan['stop_file']).exists()


def run(label, argv):
    if should_stop():
        raise Stopped()
    entry = {'label': label, 'argv': list(map(str, argv)), 'started_ns': time.time_ns()}
    with (base / (label + '.stdout')).open('wb') as stdout, (base / (label + '.stderr')).open('wb') as stderr:
        child = subprocess.Popen(entry['argv'], stdout=stdout, stderr=stderr, start_new_session=True)
        state.update(status='running', active={'label': label, 'process_group': child.pid})
        save()
        interrupted = False
        while child.poll() is None:
            if should_stop():
                interrupted = True
                subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(child.pid)], check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', '-' + str(child.pid)], check=False)
                    child.wait(timeout=3)
                break
            time.sleep(.2)
    entry.update(returncode=child.returncode, ended_ns=time.time_ns(), interrupted=interrupted,
                 stdout_sha256=sha(base / (label + '.stdout')), stderr_sha256=sha(base / (label + '.stderr')))
    state['commands'].append(entry)
    state['active'] = None
    save()
    print(label, child.returncode, flush=True)
    if interrupted:
        raise Stopped()
    if child.returncode != 0:
        raise RuntimeError('failed attempt retained: ' + label)
    return (base / (label + '.stdout')).read_text()


def stat(label):
    text = (base / (label + '.csv')).read_text()
    fields = [row for row in csv.reader(text.splitlines()) if len(row) >= 5 and row[2] == 'instructions:u']
    raw = re.findall(r'^instructions:u: (\d+) (\d+) (\d+)\s*$', text, re.M)
    assert len(fields) == len(raw) == 1
    count, enabled, running = map(int, raw[0])
    reported = float(fields[0][0])
    assert 0 < running <= enabled and abs(reported - count * enabled / running) <= max(1, reported * 1e-8)
    assert abs(float(fields[0][4]) - 100 * running / enabled) <= .011
    attrs = (base / (label + '.stderr')).read_text()
    assert re.search(r'^\s*inherit\s+1\s*$', attrs, re.M)
    assert re.search(r'^\s*exclude_kernel\s+1\s*$', attrs, re.M)
    return {'raw_count': count, 'reported_count': reported, 'time_enabled_ns': enabled,
            'time_running_ns': running, 'running_percent': float(fields[0][4]),
            'scaled': running != enabled, 'csv_sha256': sha(base / (label + '.csv'))}


def build(side):
    target = Path(plan['native_target'])
    source = base / 'source' / side
    cargo, rustc = '/home/ubuntu/.cargo/bin/cargo', '/home/ubuntu/.cargo/bin/rustc'
    with Path(plan['build_lock']).open('a') as lock:
        while True:
            if should_stop():
                raise Stopped()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(.2)
        if side != 'F':
            run(side + '-libtests', [cargo, '+1.98.1', 'test', '--locked', '--manifest-path',
                source / 'components/dnsmasq/Cargo.toml', '--lib', '--target-dir', target,
                '-j', '1', '--', '--test-threads=1'])
        run(side + '-libbuild', [cargo, '+1.98.1', 'build', '--locked', '--manifest-path',
            source / 'components/dnsmasq/Cargo.toml', '--lib', '--release', '--target-dir', target, '-j', '1'])
        state['artifacts'][side + '-rlib'] = sha(target / 'release/libdnsmasq_rs.rlib')
        for kind, probe in plan['probes'].items():
            for tracked in (True, False):
                name = side + '-' + kind + ('-alloc' if tracked else '-instructions')
                argv = [rustc, '+1.98.1', '--edition=2021', '-C', 'opt-level=3', '-C', 'panic=abort',
                        '-C', 'lto=true', '-C', 'codegen-units=1', '--extern',
                        'dnsmasq_rs=' + str(target / 'release/libdnsmasq_rs.rlib'), '-L',
                        'dependency=' + str(target / 'release/deps'), base / probe['file'], '-o', base / name]
                if tracked:
                    argv += ['--cfg', 'allocation_tracking']
                run(name + '-build', argv)
                state['artifacts'][name] = sha(base / name)
                save()


signal.signal(signal.SIGTERM, stop_signal)
signal.signal(signal.SIGINT, stop_signal)
os.sched_setaffinity(0, {plan['cpu']})
os.nice(plan['nice'])
try:
    for side, source in plan['sources'].items():
        archive = base / (side + '.tar.gz')
        assert sha(archive) == source['archive_sha256']
        destination = base / 'source' / side
        destination.mkdir(parents=True)
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter='data')
        assert all(sha(destination / path) == digest for path, digest in source['files'].items())
    assert all(sha(base / row['file']) == row['sha256'] for row in plan['probes'].values())
    save()
    build('F')
    for candidate in plan['phase_order']:
        build(candidate)
        for kind, scenes in plan['scenes'].items():
            for scene in scenes:
                checksums = {}
                for side in ('F', candidate):
                    label = candidate + '-' + side + '-' + kind + '-' + scene + '-alloc'
                    artifact = base / (side + '-' + kind + '-alloc')
                    assert sha(artifact) == state['artifacts'][artifact.name]
                    row = json.loads(run(label, [artifact, scene, plan['allocation_operations']]))
                    live = row['live_bytes_delta'] if kind == 'hot' else row['allocation_reallocation_requested_live'][3]
                    assert row['operations'] == plan['allocation_operations'] and live == 0
                    checksums[side] = row['checksum']
                    state['rows'].append({'candidate': candidate, 'side': side, 'probe': kind, 'kind': 'allocation', **row})
                    save()
                assert len(set(checksums.values())) == 1
                for pair in range(1, plan['instruction_pairs'] + 1):
                    for side in (('F', candidate) if pair % 2 else (candidate, 'F')):
                        label = candidate + '-' + side + '-' + kind + '-' + scene + '-stat-' + str(pair)
                        artifact = base / (side + '-' + kind + '-instructions')
                        assert sha(artifact) == state['artifacts'][artifact.name]
                        row = json.loads(run(label, ['sudo', '-n', 'perf', 'stat', '-vv', '-x,', '-e',
                            plan['stat_event'], '-o', base / (label + '.csv'), '--', artifact, scene,
                            plan['instruction_operations']]))
                        assert row['operations'] == plan['instruction_operations']
                        assert row['checksum'] * plan['allocation_operations'] == checksums[side] * plan['instruction_operations']
                        counters = [row[k] for k in ('allocations', 'reallocations', 'requested_bytes', 'live_bytes_delta')] if kind == 'hot' else row['allocation_reallocation_requested_live']
                        assert counters == [0, 0, 0, 0]
                        state['rows'].append({'candidate': candidate, 'side': side, 'probe': kind,
                            'kind': 'instructions', 'pair': pair, 'stat': stat(label), **row})
                        save()
    state['status'] = 'complete'
except Stopped:
    state['status'] = 'stopped_for_F_or_root'
except BaseException as error:
    state.update(status='failed', error=repr(error))
    raise
finally:
    state['active'] = None
    save()
    print(json.dumps({'status': state['status'], 'rows': len(state['rows'])}), flush=True)
