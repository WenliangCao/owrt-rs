#!/usr/bin/env python3
"""Recover the completed R136 window 12 after transport loss, then continue.

No measured window is rerun. The unobserved SSH exit and delayed host snapshot
are retained explicitly. This is specific to the recorded R136 interruption.
"""
import argparse
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


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned_processes(inventory, remote):
    lines = inventory.decode().splitlines()
    header, host_mnt, host_pid = lines[0].split('\t')
    assert header == 'HOST'
    owned = []
    for line in lines[1:]:
        pid, root, exe, mount_ns, pid_ns, command = line.split('\t', 5)
        private_namespace = root != '/' or mount_ns != host_mnt or pid_ns != host_pid
        owned_path = any(marker in root + ' ' + exe + ' ' + command
                         for marker in (remote, '/tmp/r84-isolated.'))
        if private_namespace and owned_path:
            owned.append(int(pid))
    return owned


PROCESS_INVENTORY = r'''printf 'HOST\t%s\t%s\n' "$(readlink /proc/1/ns/mnt)" "$(readlink /proc/1/ns/pid)"
for proc in /proc/[0-9]*; do
    exe=$(readlink "$proc/exe" 2>/dev/null) || continue
    case "${exe##*/}" in ubusd|ubusd-rs|owrt-benchmark|ns-exec) ;; *) continue ;; esac
    root=$(readlink "$proc/root" 2>/dev/null) || continue
    mount_ns=$(readlink "$proc/ns/mnt" 2>/dev/null) || continue
    pid_ns=$(readlink "$proc/ns/pid" 2>/dev/null) || continue
    command=$(tr '\000\t\n' '   ' < "$proc/cmdline" 2>/dev/null) || continue
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${proc##*/}" "$root" "$exe" "$mount_ns" "$pid_ns" "$command"
done'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-transport', action='store_true',
                        help='reuse already downloaded window 12 after the first recovery check failed')
    args = parser.parse_args()
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
    if args.resume_transport:
        assert audit_dir.is_dir() and not (audit_dir / 'recovery.json').exists()
    else:
        audit_dir.mkdir(exist_ok=False)
    attempt = audit_dir / ('attempt-' + str(time.time_ns()))
    attempt.mkdir(exist_ok=False)
    provenance = {'schema': 1, 'started_at_unix_ns': time.time_ns(),
                  'actual_argv': [sys.executable, *sys.argv],
                  'tool_path': str(Path(__file__).resolve().relative_to(ROOT)),
                  'tool_sha256': sha(Path(__file__)), 'original_plan_sha256': sha(plan_path),
                  'resume_transport': args.resume_transport}
    (attempt / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (attempt / 'remote-inventory.txt').write_bytes(read('ls -la ' + run))
    read('test -f ' + run + '/COMPLETE && test ! -e ' + remote + '/run-13')
    health = probe(host='openwrt', mode='stock', interface='en0')
    assert health == json.loads((matrix / 'health-before.json').read_text())
    (attempt / 'health.json').write_text(json.dumps(health, indent=2) + '\n')
    assert read('sha256sum /etc/config/*') == (matrix / 'config-before.sha256').read_bytes()
    running = read('/bin/sh /root/r84/stack-switch.sh verify stock')
    assert running == (matrix / 'host-running-hashes.txt').read_bytes()
    mounts = read('cat /proc/self/mountinfo')
    assert remote.encode() not in mounts and b'r84-isolated.' not in mounts
    (attempt / 'mountinfo.txt').write_bytes(mounts)
    processes = read(PROCESS_INVENTORY)
    (attempt / 'process-inventory.tsv').write_bytes(processes)
    assert not owned_processes(processes, remote), 'owned test processes still running'
    monitors = ','.join(line.split()[1] for line in running.decode().splitlines() if line.split()[1] != '-')
    after = read('/root/r84/bins/owrt-benchmark snapshot ' + shlex.quote(monitors))
    before = json.loads((window / 'host-before.json').read_text())
    assert {(p['pid'], p['start_ticks']) for p in before['processes']} == {
        (p['pid'], p['start_ticks']) for p in json.loads(after)['processes']}
    if not args.resume_transport:
        (window / 'host-after.json').write_bytes(after)
        checksums = read('cd ' + run + " && find . -type f -exec sha256sum '{}' ';'")
        (window / 'raw.sha256').write_bytes(checksums)
        with (window / 'raw.tar.gz').open('xb') as stream:
            subprocess.run(ssh + ['tar -czf - -C ' + run + ' .'], stdout=stream, check=True, timeout=180)
    else:
        assert all((window / name).is_file() for name in ('host-after.json', 'raw.sha256', 'raw.tar.gz'))
        checksums = (window / 'raw.sha256').read_bytes()
        assert checksums == read('cd ' + run + " && find . -type f -exec sha256sum '{}' ';'"), 'remote raw changed'
    (attempt / 'host-at-recovery.json').write_bytes(after)
    raw = window / 'raw'
    if not args.resume_transport:
        raw.mkdir(exist_ok=False)
        with tarfile.open(window / 'raw.tar.gz') as archive:
            archive.extractall(raw, filter='data')
    else:
        assert raw.is_dir()
    for line in checksums.decode().splitlines():
        digest, name = line.split(None, 1)
        path = (raw / name).resolve()
        assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    files = archive_hashes(window)
    assert (raw / 'COMPLETE').is_file()
    assert (raw / 'binary-sha256.txt').read_text().split()[0] == plan['subjects']['stock']['sha256']
    assert (raw / 'boot-id.txt').read_text().strip() == plan['boot_id']
    assert (raw / 'harness-sha256.txt').read_text().split()[0] == plan['input_sha256']['tools/benchmark/isolated.sh']
    preserved_names = [f'{i:02d}-{side}' for i, side in
                       enumerate(json.loads((matrix / 'order.json').read_text())[:12], 1)]
    recovery = {'schema': 1, 'window': '12-stock', 'recovered_at_unix_ns': time.time_ns(),
                'reason': 'Local collector and tool session disappeared; remote workload already completed.',
                'original_ssh_exit_observed': False, 'host_after_delayed': True,
                'remote_complete_existed_before_download': True, 'repeated_measurements': 0,
                'production_health_config_identity_unchanged': True,
                'original_test_daemon_absent': True, 'host_has_no_owned_test_mount': True,
                'ownership_check': 'Host process executable/root/mount-namespace/PID-namespace and owned-path inventory; no namespace-local PID lookup.',
                'provenance': str((attempt / 'provenance.json').relative_to(audit_dir)),
                'original_plan_sha256': sha(plan_path), 'recovery_tool_sha256': provenance['tool_sha256'],
                'actual_argv': provenance['actual_argv'],
                'preserved_archive_sha256': {name: sha(matrix / name / 'raw.tar.gz') for name in preserved_names},
                'host_after_sha256': sha(window / 'host-after.json'),
                'raw_files_verified': len(files),
                'limitations': ['Completion marker and raw checks replace the lost transport exit observation.',
                                'The host-after snapshot was captured on recovery, not immediately after the window.',
                                'Collection paused between windows 12 and 13; all original observations are retained.',
                                'The first recovery attempt safely stopped on an invalid host lookup of a namespace-local PID. Its downloaded raw and delayed host-after are preserved; the corrected inventory supplies the ownership check.']}
    (audit_dir / 'recovery.json').write_text(json.dumps(recovery, indent=2) + '\n')
    (window / 'COMPLETE').touch()
    read('rm -rf -- ' + run)
    commands = []
    for step in plan['steps'][2:]:
        verify(plan)
        argv = [sys.executable, *step['argv']]
        if step['name'] == 'matrix':
            argv.append('--resume')
        commands.append({'name': step['name'], 'argv': argv, 'started_at_unix_ns': time.time_ns()})
        (audit_dir / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
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
