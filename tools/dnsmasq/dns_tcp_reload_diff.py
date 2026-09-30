#!/usr/bin/env python3
"""Exact C/Rust per-TCP-session hosts snapshots across SIGHUP in -k mode.

Run via run_isolated.sh. A private /run tmpfs and bind-mounted evidence folder
contain C's default pid path and readable hosts/config files. No host /run,
production listener, router or DHCP state is accessed. This gate compares DNS
snapshot semantics, not privilege, logging, pid-file or full procd lifecycle.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ask(connection, ident):
    request = query('snapshot.test', 1, ident)
    connection.sendall(struct.pack('!H', len(request)) + request)
    response = exact_read(connection, struct.unpack('!H', exact_read(connection, 2))[0])
    result = semantics(response)
    assert result['id'] == ident, 'transaction ID changed'
    return {'wire': response.hex(), 'reply': result}


def udp(port, ident):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.25)
        client.sendto(query('snapshot.test', 1, ident), ('127.0.0.1', port))
        response = client.recv(65535)
    result = semantics(response)
    assert result['id'] == ident, 'UDP transaction ID changed'
    return {'wire': response.hex(), 'reply': result}


def wait_host(process, port, address):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        assert process.poll() is None, 'daemon exited during ready/reload wait'
        try:
            if any(rr['data'] == address for rr in udp(port, 0x1000)['reply']['records']):
                return
        except (TimeoutError, OSError, ConnectionError):
            pass
        time.sleep(.01)
    raise AssertionError('hosts reload did not finish in bounded wait')


def run(binary, output, port, config, hosts):
    rows, clients = [], []
    with (output / 'stderr').open('w') as log:
        process = subprocess.Popen([str(binary.resolve()), '-k', '-C', str(config)],
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            wait_host(process, port, '192.0.2.11')
            def connect():
                client = socket.create_connection(('127.0.0.1', port), timeout=2)
                client.settimeout(2)
                clients.append(client)
                return client
            def capture(case, result):
                rows.append({'case': case, **result})
            old = connect()
            capture('old-before-reload', ask(old, 0x1100))
            hosts.write_text('192.0.2.12 snapshot.test\n')
            process.send_signal(signal.SIGHUP)
            wait_host(process, port, '192.0.2.12')
            capture('parent-after-reload-1', udp(port, 0x1101))
            capture('old-after-reload-1', ask(old, 0x1102))
            middle = connect()
            capture('new-after-reload-1', ask(middle, 0x1103))
            hosts.write_text('192.0.2.14 snapshot.test\n')
            process.send_signal(signal.SIGHUP)
            wait_host(process, port, '192.0.2.14')
            capture('parent-after-reload-2', udp(port, 0x1104))
            capture('old-after-reload-2', ask(old, 0x1105))
            capture('middle-after-reload-2', ask(middle, 0x1106))
            capture('new-after-reload-2', ask(connect(), 0x1107))
            for client in clients:
                client.close()
            clients.clear()
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0, 'daemon did not shut down successfully'
            assert len(rows) == 8, 'planned query count differs'
            return rows
        finally:
            for client in clients:
                client.close()
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            (output / 'rows.json').write_text(json.dumps(rows, indent=2) + '\n')


def normalized(rows):
    return [{key: value for key, value in row.items() if key != 'wire'} for row in rows]


def calibrate(rows):
    expected = ['192.0.2.11', '192.0.2.12', '192.0.2.11', '192.0.2.12',
                '192.0.2.14', '192.0.2.11', '192.0.2.12', '192.0.2.14']
    assert len(rows) == len(expected)
    for row, address in zip(rows, expected):
        assert row['reply']['flags'] == 0x8580
        assert len(row['reply']['records']) == 1
        record = row['reply']['records'][0]
        assert record['data'] == address and record['ttl'] == 37
    reference = normalized(rows)
    assert reference == normalized(copy.deepcopy(rows))
    for field, value in [('data', '192.0.2.99'), ('ttl', 0)]:
        mutation = copy.deepcopy(rows)
        mutation[2]['reply']['records'][0][field] = value
        assert reference != normalized(mutation), 'behavioral mutation went undetected'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', required=True, type=Path)
    p.add_argument('--rust', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    args = p.parse_args()
    out = args.output.resolve()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        p.error('use a dedicated loopback-only network/mount namespace')
    if out.exists() or not out.is_relative_to((ROOT / 'private').resolve()):
        p.error('choose a new directory under ignored private/')
    out.mkdir(parents=True)
    # Prevent propagation to the host even on machines whose root mount was
    # shared before unshare. All subsequent mount operations stay private.
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,noexec,mode=0755', 'tmpfs', '/run'], check=True)
    if Path('/var/run').resolve() != Path('/run'):
        p.error('this fixture requires /var/run to resolve to the private /run')
    fixture = Path('/run/private')
    fixture.mkdir()
    subprocess.run(['mount', '--bind', str(out), str(fixture)], check=True)
    config, hosts = fixture / 'dnsmasq.conf', fixture / 'hosts'
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config.write_text(f'no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\nlocal-ttl=37\ncache-size=16\naddn-hosts={hosts}\n')
    summary = {'status': 'failed', 'planned_queries': 8, 'matched_queries': 0,
               'identity': {side: digest(getattr(args, side).resolve()) for side in ['reference', 'rust']},
               'scope': 'same -k/config hosts snapshots across two parent SIGHUPs; not privilege/pid-file/procd or performance acceptance'}
    try:
        results = {}
        for side in ['reference', 'rust']:
            hosts.write_text('192.0.2.11 snapshot.test\n')
            output = out / side
            output.mkdir()
            results[side] = run(getattr(args, side), output, port, config, hosts)
            if side == 'reference':
                calibrate(results[side])
        assert normalized(results['reference']) == normalized(results['rust']), 'C/Rust snapshot behavior differs'
        summary.update(status='passed', matched_queries=8, matched_shutdowns=2,
                       calibration={'equal': 1, 'injected_mismatches_detected': 2})
    except Exception as error:
        summary['error'] = repr(error)
    finally:
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        subprocess.run(['umount', str(fixture)], check=True)
        subprocess.run(['umount', '/run'], check=True)
    print(json.dumps(summary, indent=2))
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
