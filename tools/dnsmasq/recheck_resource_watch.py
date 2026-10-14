#!/usr/bin/env python3
"""Run unchanged audit-C windows while reading global conntrack counters.

Explicit router measurement authorization is required. All raw device output
stays in the caller's private directory. This adds no router configuration,
firewall rules, signals, or listeners to the existing loopback-only harness.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import predeploy_resources as audit


def snapshot():
    raw = audit.remote(
        'cat /proc/uptime /proc/sys/net/netfilter/nf_conntrack_count '
        '/proc/sys/net/netfilter/nf_conntrack_max /proc/net/stat/nf_conntrack')
    lines = raw.splitlines()
    keys = lines[3].split()
    per_cpu = []
    for line in lines[4:]:
        values = [int(n, 16) for n in line.split()]
        if len(values) != len(keys):
            raise ValueError('unexpected conntrack counter columns')
        per_cpu.append(dict(zip(keys, values)))
    return {'time_unix': time.time(), 'uptime': float(lines[0].split()[0]),
            'count': int(lines[1]), 'maximum': int(lines[2]),
            'per_cpu': per_cpu, 'raw': raw}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--windows', default='busy:R,busy:C')
    parser.add_argument('--observer', type=Path,
                        help='diagnostic only: attach read-only syscall observer after isolation proof')
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.output / 'kernel-before.raw').write_text(audit.remote('dmesg'))
    command = [sys.executable, str(Path(audit.__file__)), '--artifact', str(args.artifact),
               '--helpers', str(args.helpers), '--output', str(args.output / 'run'),
               '--windows', args.windows, '--retain-answer-errors']
    (args.output / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (args.output / 'conntrack.jsonl').open('w') as counters:
        process = subprocess.Popen(command)
        observers = {}
        uploaded = False
        try:
            while True:
                row = snapshot()
                counters.write(json.dumps(row) + '\n')
                counters.flush()
                if args.observer:
                    try:
                        state = json.loads((args.output / 'run/state.json').read_text())
                    except (FileNotFoundError, json.JSONDecodeError):
                        state = {}
                    root = state.get('root', '')
                    for window in state.get('windows', []):
                        name = window['name']
                        if name in observers or 'socket_proof' not in window or 'end' in window:
                            continue
                        if not root.startswith('/tmp/dnsmasq-audit-c-'):
                            raise ValueError('unexpected test root')
                        if not uploaded:
                            subprocess.run(['scp', '-O', '-q', str(args.observer),
                                            'openwrt:' + root + '/observer'], check=True, timeout=30)
                            audit.remote('chmod 755 ' + root + '/observer')
                            expected = hashlib.sha256(args.observer.read_bytes()).hexdigest()
                            observed = audit.remote('sha256sum ' + root + '/observer').split()[0]
                            if observed != expected:
                                raise ValueError('observer upload identity mismatch')
                            (args.output / 'observer.json').write_text(json.dumps({
                                'sha256': expected, 'diagnostic_only': True,
                                'perturbs_scheduling': True}) + '\n')
                            uploaded = True
                        pid = int(window['socket_proof']['pid'])
                        # GO was already published after proof of TracerPid=0 and
                        # loopback listeners. These windows are diagnostic only.
                        cmd = (f'{root}/observer {pid} {root} 170 '
                               f'>{root}/{name}/syscalls.jsonl 2>{root}/{name}/syscalls.log')
                        observers[name] = subprocess.Popen(audit.SSH + [cmd])
                try:
                    code = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.send_signal(2)  # Python's finally performs owned cleanup.
                process.wait(timeout=60)
            for observer in observers.values():
                observer.wait(timeout=20)
    (args.output / 'kernel-after.raw').write_text(audit.remote('dmesg'))
    (args.output / 'exit.json').write_text(json.dumps({'returncode': code}) + '\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
