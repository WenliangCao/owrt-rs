#!/usr/bin/env python3
"""Recover the completed R136 window 12 after transport loss, then continue.

No measured window is rerun. The unobserved SSH exit and delayed host snapshot
are retained explicitly. This is specific to the recorded R136 interruption.
"""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tools/r134'))
from r84_device_probe import probe
from r130_registration_report import archive_hashes
from ubusd_router_finish import verify, HEALTH


def main():
    plan_path = ROOT / 'private/r136/completion-plan-01.json'
    plan = json.loads(plan_path.read_text())
    verify(plan)
    out = ROOT / plan['output']
    matrix = out / 'matrix'
    window = matrix / '12-stock'
    assert not (window / 'COMPLETE').exists() and not (out / 'COMPLETE').exists()
    steps = json.loads((out / 'steps.json').read_text())
    assert steps == [{'name': s['name'], 'exit': 0} for s in plan['steps'][:2]]
    assert all((matrix / f'{i:02d}-{side}' / 'COMPLETE').is_file()
               for i, side in enumerate(json.loads((matrix / 'order.json').read_text())[:11], 1))
    assert not any((matrix / f'{i:02d}-{side}').exists() for i, side in
                   enumerate(json.loads((matrix / 'order.json').read_text())[12:], 13))
    remote = json.loads((matrix / 'collector.json').read_text())['remote']
    assert remote == '/tmp/r85-ubusd-ecdf357a3cc7'
    run = remote + '/run-12'
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', 'openwrt']
    def read(command):
        return subprocess.check_output(ssh + [command], timeout=30)
    audit_dir = out / 'transport-recovery'
    audit_dir.mkdir(exist_ok=False)
    (audit_dir / 'remote-inventory.txt').write_bytes(read('ls -la ' + run))
    read('test -f ' + run + '/COMPLETE && test ! -e ' + remote + '/run-13')
    health = probe(host='openwrt', mode='stock', interface='en0')
    assert health == json.loads((matrix / 'health-before.json').read_text())
    (audit_dir / 'health.json').write_text(json.dumps(health, indent=2) + '\n')
    assert read('sha256sum /etc/config/*') == (matrix / 'config-before.sha256').read_bytes()
    running = read('/bin/sh /root/r84/stack-switch.sh verify stock')
    assert running == (matrix / 'host-running-hashes.txt').read_bytes()
    mounts = read('cat /proc/self/mountinfo')
    assert remote.encode() not in mounts and b'r84-isolated.' not in mounts
    (audit_dir / 'mountinfo.txt').write_bytes(mounts)
    monitors = ','.join(line.split()[1] for line in running.decode().splitlines() if line.split()[1] != '-')
    after = read('/root/r84/bins/owrt-benchmark snapshot ' + shlex.quote(monitors))
    before = json.loads((window / 'host-before.json').read_text())
    assert {(p['pid'], p['start_ticks']) for p in before['processes']} == {
        (p['pid'], p['start_ticks']) for p in json.loads(after)['processes']}
    (window / 'host-after.json').write_bytes(after)
    checksums = read('cd ' + run + " && find . -type f -exec sha256sum '{}' ';'")
    (window / 'raw.sha256').write_bytes(checksums)
    with (window / 'raw.tar.gz').open('xb') as stream:
        subprocess.run(ssh + ['tar -czf - -C ' + run + ' .'], stdout=stream, check=True, timeout=180)
    raw = window / 'raw'
    raw.mkdir(exist_ok=False)
    with tarfile.open(window / 'raw.tar.gz') as archive:
        archive.extractall(raw, filter='data')
    for line in checksums.decode().splitlines():
        digest, name = line.split(None, 1)
        path = (raw / name).resolve()
        assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    files = archive_hashes(window)
    assert (raw / 'COMPLETE').is_file()
    assert (raw / 'binary-sha256.txt').read_text().split()[0] == plan['subjects']['stock']['sha256']
    assert (raw / 'boot-id.txt').read_text().strip() == plan['boot_id']
    assert (raw / 'harness-sha256.txt').read_text().split()[0] == plan['input_sha256']['tools/benchmark/isolated.sh']
    meta = json.loads((raw / 'meta.json').read_text())
    read(f'test ! -d /proc/{int(meta["subject_pid"])}')
    recovery = {'schema': 1, 'window': '12-stock', 'recovered_at_unix_ns': time.time_ns(),
                'reason': 'Local collector and tool session disappeared; remote workload already completed.',
                'original_ssh_exit_observed': False, 'host_after_delayed': True,
                'remote_complete_existed_before_download': True, 'repeated_measurements': 0,
                'production_health_config_identity_unchanged': True,
                'original_test_daemon_absent': True, 'host_has_no_owned_test_mount': True,
                'raw_files_verified': len(files),
                'limitations': ['Completion marker and raw checks replace the lost transport exit observation.',
                                'The host-after snapshot was captured on recovery, not immediately after the window.',
                                'Collection paused between windows 12 and 13; all original observations are retained.']}
    (audit_dir / 'recovery.json').write_text(json.dumps(recovery, indent=2) + '\n')
    (window / 'COMPLETE').touch()
    read('rm -rf -- ' + run)
    for step in plan['steps'][2:]:
        verify(plan)
        argv = [sys.executable, *step['argv']]
        if step['name'] == 'matrix':
            argv.append('--resume')
        print('START', step['name'], flush=True)
        with (out / (step['name'] + '-continued.log')).open('xb') as stream:
            code = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT).returncode
        row = {'name': step['name'], 'exit': code}
        if not code and step.get('driver_result'):
            result = json.loads((ROOT / step['driver_result']).read_text())
            if not all(result.get(key) is True for key in HEALTH):
                row['exit'] = 1
        steps.append(row)
        (out / 'steps.json').write_text(json.dumps(steps, indent=2) + '\n')
        if row['exit']:
            (out / 'FAILED').touch()
            raise SystemExit(row['exit'])
        if step.get('completed_group'):
            (ROOT / step['completed_group'] / 'COMPLETE').touch()
        print('PASS', step['name'], flush=True)
    (out / 'COMPLETE').touch()
    print('R136 completion recovered without repeating measured windows', flush=True)


if __name__ == '__main__':
    main()
