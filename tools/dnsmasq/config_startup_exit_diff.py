#!/usr/bin/env python3
"""Configuration startup exit codes against the exact image ELF in its rootfs.

Run through run_isolated.sh. No DNS/DHCP listener is opened. Raw diagnostics
are retained, but only exit status is compared: diagnostic wording is outside
this regression's scope.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess

import m2_rootfs


CASES = (
    ('missing-file', 'conf-file=/m2/absent.conf\n', None, 3),
    ('missing-directory', 'conf-dir=/m2/absent-directory\n', None, 3),
    ('permission-denied', None, '65534:65534', 3),
    ('invalid-syntax', 'invalid-startup-directive\n', None, 1),
    ('valid-config', 'port=0\nno-hosts\nno-resolv\n', None, 0),
)


def run_command(command, body, prefix, timeout=10):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True,
                               env={**os.environ, 'LC_ALL': 'C'})
    timed_out = False
    try:
        stdout, stderr = process.communicate(input=body, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    prefix.with_suffix('.stdout').write_bytes(stdout)
    prefix.with_suffix('.stderr').write_bytes(stderr)
    return {'command': command, 'pid': process.pid, 'exit': process.returncode,
            'timed_out': timed_out}


def compare(rows):
    failures = []
    for label, _, _, expected_c_exit in CASES:
        selected = [row for row in rows if row['case'] == label]
        if sorted(row['side'] for row in selected) != ['c', 'rust']:
            failures.append(f'{label}: missing or duplicate execution')
            continue
        c = next(row for row in selected if row['side'] == 'c')
        rust = next(row for row in selected if row['side'] == 'rust')
        if c['timed_out'] or rust['timed_out']:
            failures.append(f'{label}: command timeout')
        if c['exit'] != expected_c_exit:
            failures.append(f'{label}: C fixture expected exit {expected_c_exit}, got {c["exit"]}')
        if rust['exit'] != c['exit']:
            failures.append(f'{label}: C exit {c["exit"]}, Rust exit {rust["exit"]}')
    if len(rows) != 2 * len(CASES):
        failures.append('unexpected execution count')
    return failures


def negative_controls(rows):
    missing = copy.deepcopy(rows)
    missing.pop()
    changed = copy.deepcopy(rows)
    next(row for row in changed if row['side'] == 'rust')['exit'] ^= 1
    return {'missing-execution': bool(compare(missing)),
            'changed-exit-status': bool(compare(changed))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('run through run_isolated.sh as root')
    if sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        parser.error('isolated loopback-only namespace required')
    out = args.out.resolve()
    if 'private' not in out.parts or out.exists():
        parser.error('fresh output under private/ required')
    root = m2_rootfs.prepare(args.image_root, None, out, args.rust)
    protected = root / 'm2/protected.conf'
    protected.write_text('port=0\n')
    protected.chmod(0o600)
    os.chown(protected, 0, 0)
    rows = []
    for label, body, user, _ in CASES:
        for side, binary in [('c', '/usr/sbin/dnsmasq'), ('rust', '/usr/sbin/dnsmasq-rs')]:
            command = ['chroot']
            if user:
                command.append('--userspec=' + user)
            config = '/m2/protected.conf' if user else '-'
            command.extend([str(root), binary, '--test', '--conf-file=' + config])
            row = run_command(command, body.encode() if body else None, out / (label + '-' + side))
            rows.append({'case': label, 'side': side, **row})
    failures = compare(rows)
    controls = negative_controls(rows)
    if not all(controls.values()):
        failures.append('comparison negative control failed')
    result = {'scope': __doc__.strip(), 'cases': len(CASES), 'rows': rows,
              'c_sha256': m2_rootfs.sha256(root / 'usr/sbin/dnsmasq'),
              'rust_sha256': m2_rootfs.sha256(root / 'usr/sbin/dnsmasq-rs'),
              'tool_sha256': m2_rootfs.sha256(Path(__file__)),
              'negative_controls': controls, 'failures': failures}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'rows'}))
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
