#!/usr/bin/env python3
"""Run only in an isolated Linux namespace: drop this probe's local SYNs.

The fixed seven-case gate checks cancellation, connect timeout, outer deadline
and FD recovery. Timing bounds are functional cancellation limits, not a C/Rust
performance comparison. The firewall rule is scoped to the ephemeral loopback
listener and is always removed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    out = args.output.resolve()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        p.error('a dedicated loopback-only test namespace is required')
    if out.exists() or not out.is_relative_to((ROOT / 'private').resolve()):
        p.error('choose a new private output directory')
    out.mkdir(parents=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        rule = ['OUTPUT', '-o', 'lo', '-d', '127.0.0.1/32', '-p', 'tcp', '--dport', str(port), '-j', 'DROP']
        subprocess.run(['iptables', '-A', *rule], check=True)
        try:
            run = subprocess.run([str(args.binary.resolve()), f'127.0.0.1:{port}'], text=True, capture_output=True, timeout=15)
            counters = subprocess.check_output(['iptables', '-L', 'OUTPUT', '-n', '-v', '-x'], text=True)
            (out / 'firewall.txt').write_text(counters)
            drops = [int(line.split()[0]) for line in counters.splitlines()
                     if len(line.split()) > 2 and line.split()[2] == 'DROP']
            assert len(drops) == 1 and drops[0] >= 7, 'SYN-drop counter calibration'
            (out / 'stdout').write_text(run.stdout)
            (out / 'stderr').write_text(run.stderr)
            assert run.returncode == 0, f'probe exited {run.returncode}'
            rows = run.stdout.splitlines()
            assert len(rows) == 8 and rows[-1].startswith('CLOSED 7 '), 'case count/cleanup calibration'
            modes = [line.split()[0] for line in rows[:-1]]
            assert modes == ['cancel'] * 5 + ['connect-timeout', 'deadline']
            closed = rows[-1].split()
            assert closed[2] == closed[3], 'FD growth'
            listener.setblocking(False)
            try:
                connection, _ = listener.accept()
            except BlockingIOError:
                pass
            else:
                connection.close()
                raise AssertionError('SYN-drop calibration failed: accepted a connection')
        finally:
            subprocess.run(['iptables', '-D', *rule], check=True)
    summary = {'cases': 7, 'cancelled_connects': 5, 'connect_timeouts': 1, 'outer_deadlines': 1,
               'fd_before': int(closed[2]), 'fd_after': int(closed[3]), 'accepted_connections': 0,
               'dropped_syn_packets': drops[0],
               'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
               'observed_microseconds': [int(line.split()[1]) for line in rows[:-1]],
               'scope': 'isolated Linux pending-connect cancellation/deadline and fd cleanup; no C/Rust performance claim'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
