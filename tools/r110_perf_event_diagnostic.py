#!/usr/bin/env python3
"""Oracle-only diagnostic: bracket the validated libubus loop with perf ACKs.

No chroot/mount, reference-rootfs writes or production daemon changes. This
does not implement the router recovery gate and must never run on the router.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plan_lane(plan):
    listeners, matched = plan.get('listeners', 1), plan.get('matched', 1)
    assert type(listeners) is int and listeners in (1, 8), 'listeners must be integer 1 or 8'
    assert type(matched) is int and matched in (0, 1), 'matched must be integer 0 or 1'
    assert all('listeners' not in item and 'matched' not in item for item in plan['runs']), \
        'listeners and matched must be plan-level fields'
    return listeners, matched


def stop(process, sig=signal.SIGTERM):
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(sig)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def sample(out, label, held, args, plan, listeners, matched):
    out.mkdir()
    daemon = perf = None
    pipes = []
    binary = Path(args.subjects[label])
    assert sha(binary) == plan['subjects'][label]
    rootfs = args.rootfs
    env = dict(os.environ)
    for key in ('LD_LIBRARY_PATH', 'LD_PRELOAD'):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix='r110-perf-') as temporary:
        sock = str(Path(temporary) / 'bus.sock')
        executable = binary
        if 'launch_names' in plan:
            name = plan['launch_names'][label]
            assert name and len(name) <= 128 and all(c.isalnum() or c in '-_' for c in name)
            executable = Path(temporary) / name
            shutil.copyfile(binary, executable)
            executable.chmod(0o755)
            assert sha(executable) == plan['subjects'][label]
        with (out / 'daemon.log').open('wb') as daemon_log, \
                (out / 'perf.log').open('wb') as perf_log, \
                (out / 'client.log').open('wb') as client_log, \
                (out / 'client.json').open('wb') as client_json:
            try:
                daemon_command = ['taskset', '-c', '1', str(executable), '-s', sock]
                daemon = subprocess.Popen(daemon_command, stdout=daemon_log,
                                          stderr=subprocess.STDOUT, env=env)
                deadline = time.monotonic() + 5
                while not Path(sock).exists():
                    assert daemon.poll() is None, 'daemon exited before readiness'
                    assert time.monotonic() < deadline, 'socket readiness timeout'
                    time.sleep(0.01)
                assert os.sched_getaffinity(daemon.pid) == {1}
                assert sha(f'/proc/{daemon.pid}/exe') == plan['subjects'][label]
                before = Path(f'/proc/{daemon.pid}/stat').read_text()
                ctl_read, ctl_write = os.pipe()
                ack_read, ack_write = os.pipe()
                pipes = [ctl_read, ctl_write, ack_read, ack_write]
                perf_command = ['perf', 'stat', '-D', '-1', '-p', str(daemon.pid),
                                '--control', f'fd:{ctl_read},{ack_write}',
                                '-x', ';', '-o', str(out / 'perf.csv')]
                for event in plan['events']:
                    perf_command.extend(['-e', event])
                perf = subprocess.Popen(perf_command,
                                        pass_fds=(ctl_read, ack_write),
                                        stdout=perf_log, stderr=subprocess.STDOUT,
                                        env=env)
                env['OWRT_PERF_CTL_FD'] = str(ctl_write)
                env['OWRT_PERF_ACK_FD'] = str(ack_read)
                client_command = [str(rootfs / 'lib/libc.so'), '--library-path',
                                  f'{rootfs}/lib:{rootfs}/usr/lib', str(args.client),
                                  'user-event', sock, str(listeners), str(matched),
                                  str(plan['iterations']), str(plan['warmup']),
                                  str(daemon.pid), str(held)]
                subprocess.run(client_command, pass_fds=(ctl_write, ack_read),
                               env=env, stdout=client_json, stderr=client_log,
                               check=True, timeout=plan['sample_timeout_seconds'])
                assert perf.poll() is None, 'perf exited before controlled shutdown'
                stop(perf, signal.SIGINT)
                # perf flushes counts, then re-raises the requested SIGINT.
                assert perf.returncode in (0, -signal.SIGINT), f'perf exit {perf.returncode}'
                after = Path(f'/proc/{daemon.pid}/stat').read_text()
                assert sha(f'/proc/{daemon.pid}/exe') == plan['subjects'][label]
                (out / 'stat-before.txt').write_text(before)
                (out / 'stat-after.txt').write_text(after)
                client_json.flush()
                data = json.loads((out / 'client.json').read_text())
                assert data['perf_controlled'] and data['payload_checked']
                assert type(data['listeners']) is int and data['listeners'] == listeners
                assert data['matched'] is bool(matched)
                assert data['n'] == plan['iterations'] and data['warmup'] == plan['warmup']
                assert data['received'] == plan['iterations'] * listeners * matched
                assert data['warmup_received'] == plan['warmup'] * listeners * matched
                assert data['held_clients'] == held and data['handlers_removed']
                counts = (out / 'perf.csv').read_text()
                assert '<not ' not in counts and 'instructions:u' in counts
                counters = {}
                for line in counts.splitlines():
                    if not line or line.startswith('#'):
                        continue
                    fields = line.split(';')
                    if len(fields) < 5:
                        continue
                    # Reject multiplexing instead of silently scaling short
                    # samples into an apparent instruction/op difference.
                    value, event = float(fields[0]), fields[2].strip()
                    assert float(fields[3]) > 0 and float(fields[4]) == 100.0
                    assert event not in counters
                    counters[event] = value
                assert set(counters) == set(plan['counter_names'])
                metadata = {'label': label, 'held_clients': held,
                            'listeners': listeners, 'matched': matched,
                            'binary_sha256': sha(binary), 'daemon_pid': daemon.pid,
                            'client_sha256': sha(args.client),
                            'perf_control': 'enable/ack before clocks; disable/ack after clocks',
                            'scope': 'Oracle diagnostic only, user-mode PMU counts',
                            'counters': counters,
                            'daemon_command': daemon_command,
                            'argv0_bytes': len(os.fsencode(executable)),
                            'perf_command': perf_command,
                            'client_command': client_command}
                (out / 'meta.json').write_text(json.dumps(metadata, indent=2) + '\n')
            finally:
                stop(perf, signal.SIGINT)
                stop(daemon)
                for fd in pipes:
                    os.close(fd)
    (out / 'COMPLETE').touch()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-host-only', action='store_true', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--subjects', type=json.loads, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and platform.machine() == 'aarch64'
    assert not Path('/etc/openwrt_release').exists(), 'never run this tool on OpenWrt'
    plan = json.loads(args.plan.read_text())
    listeners, matched = plan_lane(plan)
    assert sha(__file__) == plan['runner_sha256']
    assert sha(args.client) == plan['client_sha256']
    for name, digest in plan['libraries'].items():
        assert sha(args.rootfs / name.lstrip('/')) == digest
    for label, digest in plan['subjects'].items():
        assert sha(args.subjects[label]) == digest
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'plan.json').write_bytes(args.plan.read_bytes())
    (args.out / 'host.json').write_text(json.dumps({
        'machine': platform.machine(), 'kernel': platform.release(),
        'perf': subprocess.check_output(['perf', 'version'], text=True).strip(),
        'source_sha256': sha(__file__),
    }, indent=2) + '\n')
    for index, item in enumerate(plan['runs'], 1):
        label, held = item['subject'], item['held_clients']
        print(f'START {index}/{len(plan["runs"])} {label} held={held}', flush=True)
        sample(args.out / f'{index:03d}-{label}-{held}', label, held, args, plan, listeners, matched)
    (args.out / 'COMPLETE').touch()


if __name__ == '__main__':
    main()
