#!/usr/bin/env python3
"""Run unchanged audit-C windows while reading global conntrack counters.

Explicit router measurement authorization is required. All raw device output
stays in the caller's private directory. This adds no router configuration,
firewall rules, signals, or listeners to the existing loopback-only harness.
"""
import argparse
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
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.output / 'kernel-before.raw').write_text(audit.remote('dmesg'))
    command = [sys.executable, str(Path(audit.__file__)), '--artifact', str(args.artifact),
               '--helpers', str(args.helpers), '--output', str(args.output / 'run'),
               '--windows', args.windows, '--retain-answer-errors']
    (args.output / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (args.output / 'conntrack.jsonl').open('w') as counters:
        process = subprocess.Popen(command)
        try:
            while True:
                row = snapshot()
                counters.write(json.dumps(row) + '\n')
                counters.flush()
                try:
                    code = process.wait(timeout=5)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.send_signal(2)  # Python's finally performs owned cleanup.
                process.wait(timeout=60)
    (args.output / 'kernel-after.raw').write_text(audit.remote('dmesg'))
    (args.output / 'exit.json').write_text(json.dumps({'returncode': code}) + '\n')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
