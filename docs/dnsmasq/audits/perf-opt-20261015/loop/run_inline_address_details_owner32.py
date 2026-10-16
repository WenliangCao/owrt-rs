#!/usr/bin/env python3
"""Frozen exact-SDK 1df/G owner32 screen; original workload and decisions."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

plan_path = Path(sys.argv[1]).resolve()
plan = json.loads(plan_path.read_text())
out = Path(plan['output'])
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def save(name, value):
    target = out / name
    temporary = target.with_suffix(target.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(target)


def stop(process):
    def exists():
        try:
            os.killpg(process.pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    for signum in ('TERM', 'KILL'):
        process.poll()
        if not exists():
            break
        subprocess.run(['sudo', '-n', 'kill', '-' + signum, '--', '-' + str(process.pid)], check=False)
        deadline = time.monotonic() + 5
        while exists() and time.monotonic() < deadline:
            process.poll()
            time.sleep(.05)
    process.wait(timeout=5)
    assert not exists(), 'owned process group remains'


def interrupted(signum, _frame):
    raise InterruptedError('controller signal ' + str(signum))


def verify():
    assert sha(__file__) == plan['controller_sha256']
    assert plan['artifacts']['inline-address-details']['source'] == plan['candidate_commit']
    for filename, digest in plan['tool_sha256'].items():
        assert sha(filename) == digest, filename
    gate = plan['linux_gate']
    assert sha(gate['path']) == gate['sha256']
    verified = json.loads(Path(gate['path']).read_text())
    assert verified['status'] == 'PASS_FRESH_ORIGINAL_FIVE_RELATED_GROUPS_AND_QUIET'
    assert verified['source_commit'] == plan['artifacts']['inline-address-details']['source']
    assert verified['total_passed'] == gate['expected_passes'] == 963 and verified['research'] == [] and verified['wrapper_exited']
    for side, row in plan['artifacts'].items():
        directory = Path(row['directory'])
        assert sha(directory / 'build.json') == row['build_receipt_sha256']
        built = json.loads((directory / 'build.json').read_text())
        assert built['source_commit'] == row['source'] and built['source_unchanged'] and built['within_existing_budget']
        assert built['status'] == 'built-unqualified'
        assert sha(directory / 'dnsmasq-rs') == row['sha256']
        assert sha(directory / 'link.map') == row['link_map_sha256'] == built['link_map']['sha256']
        assert built['source_files'] == plan['sources'][side]['files']
        source = Path(plan['sources'][side]['directory'])
        assert built['source'] == str(source) and len(built['source_files']) == 179
        assert next(item['sha256'] for item in built['artifacts'] if item['path'] == 'dnsmasq-rs') == row['sha256']
        assert all(sha(source / name) == digest for name, digest in built['source_files'].items())


assert os.getpriority(os.PRIO_PROCESS, 0) == 0
assert plan['candidate_commit'] == '1df135dc2401a9f0ec2f219b1e4a8f07dd637db1'
assert plan['artifacts']['G']['source'] == '185db90c9cabd26c0af09765636ef15bf6d35f79'
assert plan['artifacts']['G']['sha256'] == '9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99'
assert plan['status'] == 'FROZEN_EXACT_SDK_READY_AFTER_EXCLUSIVE_SLOT_RELEASE'
assert not out.exists()
out.mkdir()
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
progress = []
active = None
try:
    verify()
    windows = []
    for observer, pairs in [('stat', 3), ('none', 5)]:
        for load, rate in [('low', 200), ('high', 0)]:
            for pair in range(1, pairs + 1):
                for side in (['G', 'inline-address-details'] if pair % 2 else ['inline-address-details', 'G']):
                    label = f'{observer}-{load}-r{pair}-{side}'
                    argv = ['sudo', '-n', 'unshare', '--net', 'sh', '-c', 'ip link set lo up; exec "$@"',
                            'udp-screen', 'taskset', '-c', '0', 'python3', plan['driver'],
                            '--build', plan['artifacts'][side]['directory'], '--tools', plan['tools'],
                            '--out', str(out / label), '--mode', 'udp', '--profile', 'hit',
                            '--rate', str(rate), '--loadgen-sha256', plan['loadgen_sha256'], '--observer', observer]
                    windows.append({'label': label, 'observer': observer, 'load': load, 'rate': rate,
                                    'pair': pair, 'side': side, 'argv': argv})
    assert len(windows) == 32
    save('identity.json', {'scope': plan['scope'], 'baseline': 'G', 'artifacts': plan['artifacts'],
                          'windows': windows, 'driver_sha256': plan['tool_sha256'][plan['driver']],
                          'controller_sha256': sha(__file__), 'plan_sha256': sha(plan_path),
                          'linux_gate_sha256': plan['linux_gate']['sha256'], 'started_epoch': time.time()})
    for window in windows:
        row = {key: value for key, value in window.items() if key != 'argv'}
        row['started_epoch'] = time.time()
        try:
            with (out / (row['label'] + '.stdout')).open('xb') as stdout, (out / (row['label'] + '.stderr')).open('xb') as stderr:
                active = subprocess.Popen(window['argv'], stdout=stdout, stderr=stderr, start_new_session=True)
                row['pid'] = active.pid
                save('active.json', row)
                row['returncode'] = active.wait(timeout=100)
                assert row['returncode'] == 0, row['label']
            complete = json.loads((out / row['label'] / 'complete.json').read_text())
            assert complete['valid_count_profile'] and complete['tree_tail_complete'] and complete['rate'] == row['rate']
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            try:
                if active is not None:
                    stop(active)
                    row['returncode'] = active.returncode
                    row['group_exited'] = True
                    active = None
                    (out / 'active.json').unlink(missing_ok=True)
            finally:
                row['finished_epoch'] = time.time()
                progress.append(row)
                save('progress.json', progress)
        print(json.dumps(row), flush=True)
    verify()
    save('complete.json', {'complete': True, 'windows': len(progress), 'ended_epoch': time.time()})
except BaseException as error:
    save('failure.json', {'error': repr(error), 'completed_windows': len(progress), 'active_pid': active.pid if active else None})
    raise
