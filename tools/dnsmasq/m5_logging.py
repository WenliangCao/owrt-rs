#!/usr/bin/env python3
"""One exact-image logging/CLI family differential driver; raw evidence retained."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, process_identity, sha256

DEPENDENCIES = ['dns_service_probe.py', 'm2_rootfs.py', 'run_isolated.sh',
                'm5_logging_requirements.json']
FACILITIES = {'kern': 0, 'user': 8, 'mail': 16, 'daemon': 24, 'auth': 32,
              'security': 32, 'syslog': 40, 'lpr': 48, 'news': 56, 'uucp': 64,
              'cron': 72, 'authpriv': 80, 'ftp': 88, 'local0': 128, 'local1': 136,
              'local2': 144, 'local3': 152, 'local4': 160, 'local5': 168,
              'local6': 176, 'local7': 184, 'mark': 192}
RUST_VERSION_IDENTITY = '; dnsmasq-rs 0.1.0 (Rust implementation)'
BASE = ['--no-hosts', '--no-resolv', '--bind-interfaces', '--no-0x20-encode',
        '--listen-address=127.0.0.1', '--port=15353', '--group=root',
        '--pid-file=', '--host-record=ready.logging,192.0.2.1']


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def cases():
    rows = []
    for name, facility in FACILITIES.items():
        rows.append({'id': 'facility-' + name, 'scope': 'sink', 'kind': 'run',
                     'argv': ['--log-facility=' + name], 'facility': facility,
                     'receiver': 'dgram', 'options': ['log-facility']})
    rows.extend([
        {'id': 'facility-uppercase', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=SeCuRiTy'], 'facility': 32, 'receiver': 'dgram',
         'options': ['log-facility']},
        {'id': 'default-normal', 'scope': 'sink', 'kind': 'run', 'argv': [],
         'facility': 24, 'receiver': 'dgram', 'options': ['log-facility', 'no-daemon']},
        {'id': 'default-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': [], 'facility': 128, 'receiver': 'dgram',
         'options': ['log-facility', 'no-daemon']},
        {'id': 'debug-explicit-daemon', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=daemon'], 'facility': 24, 'receiver': 'dgram',
         'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-foreground', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-debug-foreground', 'scope': 'sink', 'kind': 'run', 'mode': ['-d', '-k'],
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'file-create', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o640, 0, 0], 'options': ['log-facility']},
        {'id': 'file-append', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'existing': 'preexisting\n', 'file_mode': 0o604, 'expected_metadata': [0o604, 0, 0],
         'options': ['log-facility']},
        {'id': 'file-owner-normal', 'scope': 'sink', 'kind': 'run', 'user': 'nobody',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o660, 65534, 0], 'options': ['log-facility']},
        {'id': 'file-owner-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'], 'user': 'nobody',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o660, 65534, 0], 'options': ['log-facility', 'no-daemon']},
        {'id': 'file-rotate', 'scope': 'sink', 'kind': 'run', 'rotate': True,
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'options': ['log-facility']},
        {'id': 'file-reopen-fails', 'scope': 'sink', 'kind': 'run', 'rotate': True,
         'reopen_directory': True, 'receiver': 'dgram',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'options': ['log-facility']},
        {'id': 'syslog-stream', 'scope': 'sink', 'kind': 'run', 'receiver': 'stream',
         'facility': 24, 'argv': [], 'options': ['log-facility']},
        {'id': 'file-open-missing-parent', 'scope': 'sink', 'kind': 'run', 'exit': 3,
         'receiver': 'dgram', 'argv': ['--log-facility=/m2/logging/missing/daemon.log'],
         'options': ['log-facility']},
        {'id': 'facility-file-origins', 'scope': 'sink', 'kind': 'run',
         'config': 'log-facility=/m2/logging/daemon.log\n', 'file': 'daemon.log',
         'argv': ['--log-facility=local3'], 'options': ['log-facility']},
    ])
    for name in ['', 'local8', 'audit', '24', 'foo']:
        rows.append({'id': 'bad-facility-' + (name or 'empty'), 'scope': 'sink',
                     'kind': 'test', 'exit': 1, 'argv': ['--log-facility=' + name],
                     'options': ['log-facility', 'test']})
    for name, argv in [('version', ['--version']), ('help', ['--help']),
                       ('help-dhcp', ['--help', 'dhcp']), ('help-dhcp6', ['--help', 'dhcp6']),
                       ('help-unknown', ['--help', 'other']),
                       ('help-dhcp-extra', ['--help', 'dhcp', 'extra'])]:
        rows.append({'id': 'cli-' + name, 'scope': 'cli', 'kind': 'cli', 'argv': argv,
                     'options': ['version'] if name == 'version' else ['help']})
    rows.extend([
        {'id': 'cli-version-invalid-default', 'scope': 'cli', 'kind': 'cli',
         'argv': ['--version'], 'invalid_default': True, 'options': ['version']},
        {'id': 'cli-help-invalid-default', 'scope': 'cli', 'kind': 'cli',
         'argv': ['--help'], 'invalid_default': True, 'options': ['help']},
        {'id': 'test-no-runtime-file', 'scope': 'cli', 'kind': 'test',
         'argv': ['--log-facility=/m2/logging/missing/daemon.log'],
         'options': ['log-facility', 'test']},
        {'id': 'test-debug-stderr', 'scope': 'cli', 'kind': 'test',
         'argv': ['-d', '--log-facility=-'], 'options': ['no-daemon', 'test']},
        {'id': 'no-ident-default', 'scope': 'identity', 'kind': 'run',
         'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user'],
         'chaos': True, 'options': ['no-ident']},
        {'id': 'no-ident-enabled', 'scope': 'identity', 'kind': 'run',
         'argv': ['--log-facility=-', '--no-ident', '--txt-record=kept.logging,explicit-user'],
         'chaos': True, 'options': ['no-ident']},
    ])
    query_modes = [([], 'ordinary'), (['extra'], 'extra'), (['proto'], 'proto'),
                   (['auth'], 'auth'), (['only_failed'], 'only_failed'),
                   ([''], 'ordinary'), (['unknown'], 'ordinary'), (['EXTRA'], 'ordinary'),
                   (['extra,proto'], 'ordinary'), (['proto', 'unknown'], 'proto'),
                   (['extra', 'only_failed'], 'only_failed'), (['auth', 'proto'], 'auth')]
    for index, (modes, expected) in enumerate(query_modes):
        rows.append({'id': f'query-mode-{index:02d}', 'scope': 'query-reference', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries'] +
                             ['--log-queries=' + mode for mode in modes] +
                             ['--host-record=v6.logging,2001:db8::1',
                              '--cname=alias.logging,ready.logging',
                              '--txt-record=kept.logging,explicit-user',
                              '--address=/nxdomain.logging/'],
                     'query_probes': True, 'query_mode': expected, 'options': ['log-queries']})
    rows.append({'id': 'query-debug-proto', 'scope': 'query-reference', 'kind': 'run',
                 'mode': ['-d'], 'argv': ['--log-facility=-', '--log-queries=proto',
                                        '--host-record=v6.logging,2001:db8::1',
                                        '--cname=alias.logging,ready.logging',
                                        '--txt-record=kept.logging,explicit-user',
                                        '--address=/nxdomain.logging/'],
                 'query_probes': True, 'query_mode': 'proto', 'options': ['log-queries', 'no-daemon']})
    rows.extend([
        {'id': 'daemon-default-stderr', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=-'], 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-default-syslog', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': [], 'receiver': 'dgram', 'facility': 24, 'daemonized': True,
         'pidfile': '/m2/logging/daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=./relative.log'], 'file': '/relative.log', 'daemonized': True,
         'pidfile': './daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'foreground-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': ['-k'],
         'argv': ['--log-facility=./relative.log'], 'file': '/relative.log',
         'pidfile': './daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'debug-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=./relative.log'], 'file': '/m2/logging/relative.log',
         'pidfile': './daemon.pid', 'sentinel_pid': True, 'options': ['no-daemon', 'log-facility']},
        {'id': 'debug-sigint-pid', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=-'], 'pidfile': './daemon.pid', 'sentinel_pid': True,
         'signal': 'int', 'exit': 5, 'expect_ready': True, 'options': ['no-daemon']},
        {'id': 'daemon-log-open-failure', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': [], 'config': 'log-facility=/m2/logging/missing/daemon.log\n',
         'exit': 3, 'receiver': 'dgram', 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-log-failure-parent-facility', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=local3'], 'config': 'log-facility=/m2/logging/missing/daemon.log\n',
         'exit': 3, 'receiver': 'dgram', 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-pid-open-failure', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=-'], 'exit': 3, 'receiver': 'dgram', 'daemonized': True,
         'pidfile': '/m2/logging/missing/daemon.pid', 'options': ['no-daemon']},
    ])
    for enabled in [False, True]:
        rows.append({'id': 'no-ident-full-' + ('enabled' if enabled else 'default'),
                     'scope': 'identity-full', 'kind': 'run', 'identity_matrix': True,
                     'reference_defect': 'C TCP have_pseudoheader persists across local/no-server queries',
                     'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user',
                              '--txt-record=version.bind,explicit-user',
                              '--txt-record=explicit.server,server-user'] + (['--no-ident'] if enabled else []),
                     'options': ['no-ident']})
    for name, cls in [('local', 1), ('refused', 255)]:
        rows.append({'id': 'tcp-edns-sticky-' + name, 'scope': 'identity-full', 'kind': 'run',
                     'identity_matrix': True, 'identity_sticky_probe': cls,
                     'reference_defect': 'C TCP have_pseudoheader persists across local/no-server queries',
                     'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user'],
                     'options': ['no-ident']})
    return rows


def normalized(value):
    value = value.replace('dnsmasq-rs:', 'dnsmasq:')
    value = re.sub(r'(?m)^(<\d+>)?[A-Z][a-z]{2} [ 0-9][0-9] \d\d:\d\d:\d\d ',
                   lambda match: (match[1] or '') + '<TIME> ', value)
    return re.sub(r'(dnsmasq(?:-(?:dhcp|tftp|script|debug))?)\[\d+\]:', r'\1[<PID>]:', value)


class Receiver:
    def __init__(self, root, kind):
        self.listener = self.client = None
        self.raw, self.pending = [], b''
        self.kind = kind
        if kind:
            path = image_path(root, '/dev/log', follow_leaf=False)
            path.unlink(missing_ok=True)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM if kind == 'stream' else socket.SOCK_DGRAM)
            self.listener.bind(str(path))
            path.chmod(0o777)
            if kind == 'stream':
                self.listener.listen(1)
            self.listener.setblocking(False)

    def drain(self):
        if not self.listener:
            return
        if self.kind == 'stream' and not self.client:
            try:
                self.client, _ = self.listener.accept()
                self.client.setblocking(False)
            except BlockingIOError:
                return
        endpoint = self.client or self.listener
        while True:
            try:
                data = endpoint.recv(65535)
            except BlockingIOError:
                break
            if not data:
                break
            if self.kind == 'stream':
                self.pending += data
                while b'\0' in self.pending:
                    row, self.pending = self.pending.split(b'\0', 1)
                    self.raw.append(row)
            else:
                if b'\0' in data:
                    raise AssertionError('NUL inside syslog datagram')
                self.raw.append(data)

    def close(self):
        if self.client:
            self.client.close()
        if self.listener:
            self.listener.close()


def exchange(name, kind=1, chaos=False, port=None):
    wire = query(name, kind, 0x7100)
    if chaos:
        wire = wire[:-2] + b'\0\3'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        if port is not None:
            client.bind(('127.0.0.1', port))
        client.settimeout(.03)
        client.sendto(wire, ('127.0.0.1', 15353))
        reply = client.recv(65535)
    if reply[:2] != wire[:2]:
        raise AssertionError('wrong client DNS transaction')
    return semantics(reply), {'request': wire.hex(), 'reply': reply.hex()}


def query_sequence():
    return [('ready.logging', 1), ('ready.logging', 28), ('v6.logging', 28),
            ('alias.logging', 1), ('1.2.0.192.in-addr.arpa', 12),
            ('kept.logging', 16), ('nxdomain.logging', 1), ('ready.logging', 65400)]


def tcp_sequence(probes):
    rows, raw = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.settimeout(.5)
        client.bind(('127.0.0.1', 16502))
        client.connect(('127.0.0.1', 15353))
        for name, kind in probes:
            wire = query(name, kind, 0x7200)
            client.sendall(len(wire).to_bytes(2, 'big') + wire)
            reply = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
            rows.append({'name': name, 'type': kind, 'transport': 'tcp', 'response': semantics(reply)})
            raw.append({'request': wire.hex(), 'reply': reply.hex(), 'transport': 'tcp'})
    return rows, raw


def identity_probes():
    probes = []
    def add(labels, kind=16, cls=3, rd=True, edns=False, do=False, rcode=None, txt=None):
        probes.append({'labels': labels, 'type': kind, 'class': cls, 'rd': rd,
                       'edns': edns, 'do': do, 'rcode': rcode, 'txt': txt})
    for labels in [[b'bind'], [b'server'], [b'version', b'bind'], [b'explicit', b'server'],
                   [b'VeRsIoN', b'BiNd'], [b'foo', b'bar', b'SeRvEr']]:
        for kind in [1, 16, 28, 255]:
            add(labels, kind, rcode=4)
    for labels in [[b'badbind'], [b'badserver'], [b'foo', b'badbind'], [b'foo', b'badserver'],
                   [b'foo.bind'], [b'foo.server']]:
        add(labels, rcode=5)
    for labels in [[b'x.y', b'bind'], [b'x\0y', b'bind'], [b'x\1y', b'server']]:
        add(labels, rcode=4)
    for rd, do in [(False, False), (True, False), (False, True), (True, True)]:
        add([b'binary.dot', b'bind'], rd=rd, edns=True, do=do, rcode=4)
    for labels, value in [([b'kept', b'logging'], 'explicit-user'),
                          ([b'version', b'bind'], 'explicit-user'),
                          ([b'explicit', b'server'], 'server-user')]:
        for kind in [16, 255]:
            add(labels, kind, 1, rcode=0, txt=value)
            # QCLASS ANY does not match an explicit IN TXT: exact C uses
            # t->class==qclass; QTYPE ANY is the independent positive control.
            add(labels, kind, 255)
    return probes


def identity_sequence(transport, calibrate, sticky_probe=None):
    observed, raw = [], []
    endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM)
    endpoint.settimeout(.5)
    if transport == 'tcp':
        endpoint.connect(('127.0.0.1', 15353))
    try:
        probes = identity_probes()
        if sticky_probe is not None:
            # A fresh-connection negative control precedes the EDNS->plain
            # two-query reproduction on this connection.
            base = {'labels': [b'kept', b'logging'], 'type': 16, 'class': sticky_probe,
                    'rd': True, 'edns': False, 'do': False, 'rcode': 0 if sticky_probe == 1 else None,
                    'txt': 'explicit-user' if sticky_probe == 1 else None}
            probes = [base, dict(base, edns=True), base]
        for index, probe in enumerate(probes):
            qname = b''.join(bytes([len(label)]) + label for label in probe['labels']) + b'\0'
            wire = struct.pack('!6H', 0x7300 + index, 0x100 if probe['rd'] else 0,
                               1, 0, 0, int(probe['edns']))
            wire += qname + struct.pack('!HH', probe['type'], probe['class'])
            if probe['edns']:
                wire += b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000 if probe['do'] else 0, 0)
            if transport == 'tcp':
                endpoint.sendall(len(wire).to_bytes(2, 'big') + wire)
                reply = exact_read(endpoint, int.from_bytes(exact_read(endpoint, 2), 'big'))
            else:
                endpoint.sendto(wire, ('127.0.0.1', 15353))
                reply = endpoint.recv(65535)
            answer = semantics(reply)
            if reply[:2] != wire[:2]:
                raise AssertionError('identity query transaction changed')
            if calibrate and probe['rcode'] is not None and answer['flags'] & 15 != probe['rcode']:
                raise AssertionError(('identity RCODE calibration', probe, answer))
            answers = [record for record in answer['records'] if record['section'] == 'answer']
            if calibrate and probe['txt'] is not None:
                expected = (bytes([len(probe['txt'])]) + probe['txt'].encode()).hex()
                if [record['data'] for record in answers] != [expected] or any(record['class'] != 1 for record in answers):
                    raise AssertionError(('explicit IN TXT control', probe, answer))
            elif calibrate and probe['txt'] is None and answers:
                raise AssertionError(('unexpected identity/class255 record', probe, answer))
            row = {'probe': dict(probe, labels=[label.hex() for label in probe['labels']]),
                   'transport': transport, 'response': answer, 'reply_wire': reply.hex()}
            observed.append(row)
            raw.append({'request': wire.hex(), 'reply': reply.hex(), 'transport': transport})
    finally:
        endpoint.close()
    return observed, raw


def run(root, side, case, out):
    if case.get('scope') == 'daemon':
        return run_daemon(root, side, case, out)
    out.mkdir()
    folder = image_path(root, '/m2/logging')
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    (folder / 'config').write_text(case.get('config', ''))
    image_path(root, '/etc/dnsmasq.conf', follow_leaf=False).write_text(
        'unrecognised-directive=fail\n' if case.get('invalid_default') else '')
    if 'existing' in case:
        (folder / case['file']).write_text(case['existing'])
        (folder / case['file']).chmod(case['file_mode'])
    receiver = Receiver(root, case.get('receiver'))
    # C selects the DHCP help list only with exactly argc3 and argv[2]=dhcp.
    argv = [] if case['kind'] == 'cli' else ['-C', '/m2/logging/config']
    if case['kind'] != 'cli':
        argv += BASE + ['--user=' + case.get('user', 'root')]
        argv += ['--test'] if case['kind'] == 'test' else case.get('mode', ['-k'])
    argv += case['argv']
    full = command(root, side, *argv)
    observed = {'ready': False, 'exit': None, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': ''}
    save(out / 'fixture.json', case)
    save(out / 'command.json', full)
    start = time.monotonic()
    trace = {'dns': [], 'command': full}
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
        try:
            deadline = start + 3
            while time.monotonic() < deadline:
                receiver.drain()
                if process.poll() is not None:
                    break
                if case['kind'] == 'run':
                    try:
                        if case.get('query_probes') and b'cleared cache\n' not in (out / 'stderr').read_bytes():
                            time.sleep(.005)
                            continue
                        answer, raw = exchange('ready.logging', port=16500 if case.get('query_probes') else None)
                        if [row['data'] for row in answer['records']] != ['192.0.2.1']:
                            raise AssertionError('wrong readiness answer')
                        observed['ready'] = True
                        trace['dns'].append(raw)
                        trace['identity'] = process_identity(root, process.pid)
                        wanted = sha256(image_path(root, '/usr/sbin/dnsmasq' + ('-rs' if side == 'rust' else '')))
                        if trace['identity']['sha256'] != wanted:
                            raise AssertionError('wrong daemon identity')
                        break
                    except (socket.timeout, ConnectionRefusedError):
                        pass
                time.sleep(.005)
            if observed['ready']:
                if case.get('identity_matrix'):
                    for transport in ['udp', 'tcp']:
                        rows, raw = identity_sequence(transport, side == 'c', case.get('identity_sticky_probe'))
                        observed['dns'].extend(rows)
                        trace['dns'].extend(raw)
                if case.get('query_probes'):
                    for name, kind in query_sequence():
                        answer, raw = exchange(name, kind, port=16501)
                        observed['dns'].append({'name': name, 'type': kind, 'transport': 'udp', 'response': answer})
                        trace['dns'].append(dict(raw, transport='udp'))
                    rows, raw = tcp_sequence(query_sequence())
                    observed['dns'].extend(rows)
                    trace['dns'].extend(raw)
                    answer, raw = exchange('ready.logging', port=16503)
                    observed['dns'].append({'name': 'ready.logging', 'type': 1, 'transport': 'udp-after-tcp', 'response': answer})
                    trace['dns'].append(dict(raw, transport='udp-after-tcp'))
                if case.get('chaos'):
                    for name in ['version.bind', 'authors.bind', 'copyright.bind', 'cachesize.bind',
                                 'insertions.bind', 'evictions.bind', 'hits.bind', 'misses.bind', 'servers.bind']:
                        answer, raw = exchange(name, 16, True)
                        observed['dns'].append({'name': name, 'response': answer})
                        trace['dns'].append(raw)
                    answer, raw = exchange('kept.logging', 16)
                    if [record['data'] for record in answer['records']] != ['0d6578706c696369742d75736572']:
                        raise AssertionError('no-ident changed explicit IN TXT record')
                    observed['dns'].append({'name': 'kept.logging', 'response': answer})
                    trace['dns'].append(raw)
                if case.get('rotate'):
                    path = folder / case['file']
                    path.rename(path.with_suffix('.old'))
                    if case.get('reopen_directory'):
                        path.mkdir()
                    process.send_signal(signal.SIGUSR2)
                    time.sleep(.03)
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(.8)
            except subprocess.TimeoutExpired:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            receiver.drain()
            observed['exit'] = process.returncode
        finally:
            if process.poll() is None:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            receiver.drain()
            receiver.close()
            trace['duration'] = time.monotonic() - start
            trace['stream_tail'] = receiver.pending.hex()
            save(out / 'trace.json', trace)
    for path in sorted(folder.iterdir()):
        if path.name in ['daemon.log', 'daemon.old'] and path.is_file():
            observed['files'][path.name] = path.read_bytes().hex()
            info = path.stat()
            observed['file_metadata'][path.name] = [info.st_mode & 0o777, info.st_uid, info.st_gid]
            (out / path.name).write_bytes(path.read_bytes())
    observed['syslog'] = [row.hex() for row in receiver.raw]
    observed['stdout'] = (out / 'stdout').read_text(errors='backslashreplace')
    observed['stderr'] = (out / 'stderr').read_text(errors='backslashreplace')
    save(out / 'syslog.json', [row.hex() for row in receiver.raw])
    save(out / 'observed.json', observed)
    return observed


def proc_state(pid, root):
    try:
        data = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if data[0] == 'Z':
            return {'pid': pid, 'state': 'Z', 'ppid': int(data[1]),
                    'pgrp': int(data[2]), 'sid': int(data[3])}
        cwd = os.readlink(f'/proc/{pid}/cwd')
        if cwd.startswith(str(root)):
            cwd = '/' + cwd[len(str(root)):].lstrip('/')
        status = Path(f'/proc/{pid}/status').read_text()
        stdio = []
        for fd in [0, 1, 2]:
            target = os.readlink(f'/proc/{pid}/fd/{fd}')
            stdio.append('null' if target.endswith('/dev/null') else
                         'capture' if target.endswith('/stdout') or target.endswith('/stderr') else target)
        return {'pid': pid, 'state': data[0], 'ppid': int(data[1]), 'pgrp': int(data[2]),
                'sid': int(data[3]), 'cwd': cwd, 'stdio': stdio,
                'uid': [int(value) for value in re.search(r'^Uid:\s+(.*)$', status, re.M)[1].split()],
                'gid': [int(value) for value in re.search(r'^Gid:\s+(.*)$', status, re.M)[1].split()]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def reap_children():
    reaped = {}
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if not pid:
            break
        reaped[pid] = os.waitstatus_to_exitcode(status)
    return reaped


def run_daemon(root, side, case, out):
    out.mkdir()
    folder = image_path(root, '/m2/logging')
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    (folder / 'config').write_text(case.get('config', ''))
    debug = '-d' in case['mode']
    pid_path = image_path(root, case['pidfile'] if case['pidfile'].startswith('/') else
                          ('/m2/logging/' if debug else '/') + case['pidfile'].removeprefix('./'))
    pid_path.unlink(missing_ok=True)
    if case.get('sentinel_pid'):
        pid_path.write_text('sentinel\n')
    log_path = image_path(root, case['file']) if case.get('file') else None
    if log_path:
        log_path.unlink(missing_ok=True)
    receiver = Receiver(root, case.get('receiver'))
    executable = '/usr/sbin/dnsmasq' + ('-rs' if side == 'rust' else '')
    argv = ['-C', '/m2/logging/config', *[arg for arg in BASE if arg != '--pid-file='],
            '--user=root', '--pid-file=' + case['pidfile'], *case['mode'], *case['argv']]
    full = command(root, '/bin/sh', '-c', 'cd /m2/logging && exec "$@"', 'logging', executable, *argv)
    save(out / 'fixture.json', case)
    save(out / 'command.json', full)
    observed = {'ready': False, 'exit': None, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': '', 'process': {},
                'pid_written': False, 'pid_after_exit': False, 'live_processes': []}
    trace = {'command': full, 'samples': [], 'reaped': {}}
    service_pid = None
    start = time.monotonic()
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
        try:
            deadline = start + 3
            while time.monotonic() < deadline:
                receiver.drain()
                parent_exit = process.poll()
                if case.get('daemonized'):
                    try:
                        service_pid = int(pid_path.read_text().strip())
                    except (FileNotFoundError, ValueError):
                        pass
                else:
                    service_pid = process.pid
                if service_pid:
                    state = proc_state(service_pid, root)
                    if state and state['state'] != 'Z':
                        try:
                            answer, raw = exchange('ready.logging')
                            if [row['data'] for row in answer['records']] != ['192.0.2.1']:
                                raise AssertionError('wrong daemon readiness answer')
                            observed['ready'] = True
                            trace['dns'] = [raw]
                            trace['identity'] = process_identity(root, service_pid)
                            if trace['identity']['sha256'] != sha256(image_path(root, executable)):
                                raise AssertionError('wrong detached daemon ELF')
                            trace['samples'].append(state)
                            observed['process'] = {'is_original': service_pid == process.pid,
                                'session_leader': state['sid'] == service_pid,
                                'group_leader': state['pgrp'] == service_pid,
                                'cwd': state['cwd'], 'stdio': state['stdio'],
                                'uid': state['uid'], 'gid': state['gid']}
                            observed['pid_written'] = pid_path.exists() and pid_path.read_text() != 'sentinel\n'
                            if not case.get('daemonized') or parent_exit == 0:
                                break
                        except (socket.timeout, ConnectionRefusedError):
                            pass
                if parent_exit is not None and (not case.get('daemonized') or parent_exit != 0):
                    break
                time.sleep(.005)
            if observed['ready']:
                os.kill(service_pid, signal.SIGINT if case.get('signal') == 'int' else signal.SIGTERM)
            if process.poll() is None:
                process.wait(.8)
            observed['exit'] = process.returncode
            deadline = time.monotonic() + .8
            while time.monotonic() < deadline:
                receiver.drain()
                trace['reaped'].update(reap_children())
                # All PID>1 in this private PID namespace are test descendants.
                live = []
                for path in Path('/proc').iterdir():
                    if path.name.isdigit() and int(path.name) > 1:
                        state = proc_state(int(path.name), root)
                        if state:
                            live.append(state)
                if not live:
                    break
                time.sleep(.005)
            observed['live_processes'] = [row['pid'] for row in live]
        finally:
            if process.poll() is None:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            for path in Path('/proc').iterdir():
                if path.name.isdigit() and int(path.name) > 1:
                    try:
                        state = proc_state(int(path.name), root)
                        if state and state['state'] != 'Z':
                            os.kill(int(path.name), signal.SIGKILL)
                            observed['forced'] = True
                    except ProcessLookupError:
                        pass
            trace['reaped'].update(reap_children())
            receiver.drain()
            receiver.close()
            trace['duration'] = time.monotonic() - start
            trace['stream_tail'] = receiver.pending.hex()
            save(out / 'trace.json', trace)
    observed['pid_after_exit'] = pid_path.exists()
    if log_path and log_path.is_file():
        observed['files']['relative.log'] = log_path.read_bytes().hex()
        meta = log_path.stat()
        observed['file_metadata']['relative.log'] = [meta.st_mode & 0o777, meta.st_uid, meta.st_gid]
        (out / 'relative.log').write_bytes(log_path.read_bytes())
    observed['syslog'] = [row.hex() for row in receiver.raw]
    observed['stdout'] = (out / 'stdout').read_text(errors='backslashreplace')
    observed['stderr'] = (out / 'stderr').read_text(errors='backslashreplace')
    save(out / 'observed.json', observed)
    return observed


def compare(reference, candidate, case, reference_only=False):
    failures = []
    expected_ready = case.get('expect_ready', case['kind'] == 'run' and case.get('exit', 0) == 0)
    for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
        for field, expected in [('exit', case.get('exit', 0)), ('ready', expected_ready), ('forced', False)]:
            if row[field] != expected:
                failures.append({'side': side, 'field': field, 'expected': expected, 'actual': row[field]})
    if 'expected_metadata' in case and reference['file_metadata'].get(case['file']) != case['expected_metadata']:
        failures.append({'kind': 'C-file-metadata', 'actual': reference['file_metadata']})
    if case.get('scope') == 'daemon':
        if reference['live_processes']:
            failures.append({'kind': 'C-daemon-descendants', 'actual': reference['live_processes']})
        if reference['ready']:
            daemonized = case.get('daemonized', False)
            expected = {'is_original': not daemonized, 'session_leader': not daemonized,
                        'group_leader': not daemonized, 'cwd': '/m2/logging' if '-d' in case['mode'] else '/',
                        'stdio': ['null', 'capture', 'capture'] if '-d' in case['mode'] else ['null'] * 3,
                        'uid': [0] * 4, 'gid': [0] * 4}
            if reference['process'] != expected:
                failures.append({'kind': 'C-daemon-process-state', 'expected': expected, 'actual': reference['process']})
            if reference['pid_written'] != ('-d' not in case['mode']):
                failures.append({'kind': 'C-daemon-PID-write', 'actual': reference['pid_written']})
            if reference['pid_after_exit'] != (case.get('signal') == 'int'):
                failures.append({'kind': 'C-daemon-PID-cleanup', 'actual': reference['pid_after_exit']})
    if 'facility' in case and expected_ready:
        if not reference['syslog']:
            failures.append({'kind': 'C-no-syslog-records'})
        for record in reference['syslog']:
            text = bytes.fromhex(record).decode()
            match = re.match(r'<(\d+)>', text)
            if not match or (int(match[1]) & ~7) != case['facility']:
                failures.append({'kind': 'C-PRI-facility', 'actual': text})
    if case['kind'] == 'cli':
        expected = ('Known DHCP options:\n' if case['argv'] == ['--help', 'dhcp'] else
                    'Dnsmasq version 2.93  ' if case['argv'] == ['--version'] else
                    'Usage: dnsmasq [options]\n')
        if not reference['stdout'].startswith(expected):
            failures.append({'kind': 'C-CLI-dispatch', 'expected_prefix': expected,
                             'actual': reference['stdout']})
    if case.get('chaos') and any(record.get('section') == 'answer'
                                for answer in reference['dns'] if answer['name'] != 'kept.logging'
                                for record in answer['response']['records']):
        failures.append({'kind': 'C-no-ID-generated-answer', 'actual': reference['dns']})
    if case.get('query_probes'):
        mode, text = case['query_mode'], reference['stderr']
        if mode in ['auth', 'only_failed']:
            if 'query[' in text:
                failures.append({'kind': 'C-query-log-filter', 'mode': mode, 'actual': text})
        elif 'query[A] ready.logging from 127.0.0.1' not in text:
            failures.append({'kind': 'C-query-log-missing', 'mode': mode, 'actual': text})
        if mode == 'proto' and not all(word in text for word in ['UDP ', 'TCP ']):
            failures.append({'kind': 'C-query-protocol-prefix', 'actual': text})
        if mode == 'only_failed' and 'is NXDOMAIN' not in text:
            failures.append({'kind': 'C-query-only-failed-negative', 'actual': text})
    if reference_only:
        return failures
    left, right = copy.deepcopy(reference), copy.deepcopy(candidate)
    for row in [left, right]:
        for stream in ['stdout', 'stderr']:
            row[stream] = normalized(row[stream])
        row['syslog'] = [normalized(bytes.fromhex(value).decode(errors='backslashreplace'))
                         for value in row['syslog']]
        row['files'] = {name: normalized(bytes.fromhex(value).decode(errors='backslashreplace'))
                        for name, value in row['files'].items()}
    if case.get('argv') == ['--version']:
        first, separator, rest = left['stdout'].partition('\n')
        expected = first + RUST_VERSION_IDENTITY + separator + rest
        if right['stdout'] != expected:
            failures.append({'kind': 'Rust-version-identity-and-license', 'expected': expected,
                             'actual': right['stdout']})
        else:
            # This one disclosed first-line difference preserves the exact
            # compile-options/init interface and every GPL/warranty line.
            right['stdout'] = left['stdout']
    if case.get('identity_matrix') and len(left['dns']) == len(right['dns']):
        previous_edns = False
        for index, (expected, actual) in enumerate(zip(left['dns'], right['dns'])):
            if expected['transport'] == 'udp':
                previous_edns = False
            if expected != actual and case.get('reference_defect') and previous_edns:
                corrected = without_leaked_tcp_opt(expected)
                if corrected is not None and actual == corrected:
                    right['dns'][index] = expected
            previous_edns |= expected['transport'] == 'tcp' and expected['probe']['edns']
    for field in left:
        if left[field] != right[field]:
            failures.append({'field': field, 'expected': left[field], 'actual': right[field]})
    return failures


def without_leaked_tcp_opt(row):
    if row['transport'] != 'tcp' or row['probe']['edns']:
        return None
    additions = [record for record in row['response']['records'] if record['section'] == 'additional']
    if len(additions) != 1 or additions[0]['type'] != 41:
        return None
    wire = bytes.fromhex(row['reply_wire'])
    if int.from_bytes(wire[10:12], 'big') != 1:
        return None
    length = 11 + len(bytes.fromhex(additions[0]['data']))
    if wire[-length] != 0:
        return None
    corrected = copy.deepcopy(row)
    corrected_wire = wire[:10] + b'\0\0' + wire[12:-length]
    corrected['reply_wire'] = corrected_wire.hex()
    corrected['response'] = semantics(corrected_wire)
    return corrected


def controls():
    case = {'id': 'control', 'kind': 'run', 'exit': 0}
    row = {'ready': True, 'exit': 0, 'forced': False, 'syslog': [], 'files': {},
           'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': 'dnsmasq: value\n'}
    result = {}
    for field, corrupt in [('exit', 3), ('ready', False), ('forced', True), ('stderr', 'dnsmasq: wrong\n'),
                           ('syslog', ['3c33303e77726f6e67']), ('files', {'daemon.log': '77726f6e67'}),
                           ('file_metadata', {'daemon.log': [0o600, 0, 0]}), ('dns', [{'name': 'wrong'}])]:
        changed = copy.deepcopy(row)
        changed[field] = corrupt
        result[field] = bool(compare(row, changed, case))
    if not all(result.values()):
        raise AssertionError('negative control bypass')
    wrong_help = dict(row, stdout='Usage: dnsmasq [options]\n', ready=False)
    result['help-argc-dispatch'] = bool(compare(wrong_help, wrong_help,
        {'id': 'help-control', 'kind': 'cli', 'argv': ['--help', 'dhcp']}, True))
    if not result['help-argc-dispatch']:
        raise AssertionError('help dispatch calibration bypass')
    version = dict(row, ready=False, stderr='', stdout='Dnsmasq version 2.93  Copyright (c) 2000-2026 Simon Kelley\nCompile time options: fixture\n\nThis software comes with ABSOLUTELY NO WARRANTY.\n')
    candidate = dict(version, stdout=version['stdout'].replace('Simon Kelley\n', 'Simon Kelley' + RUST_VERSION_IDENTITY + '\n'))
    version_case = {'id': 'version-control', 'kind': 'cli', 'argv': ['--version']}
    assert not compare(version, candidate, version_case)
    result['version-identity'] = bool(compare(version, version, version_case))
    corrupt = dict(candidate, stdout=candidate['stdout'].replace('NO WARRANTY', 'SOME WARRANTY'))
    result['version-license'] = bool(compare(version, corrupt, version_case))
    assert result['version-identity'] and result['version-license']
    frozen = {'options': {'example': {'qualification_ready': True,
              'required': [{'id': 'missing-map', 'required_scenarios': []}]}}}
    result['empty-required-map'] = not qualification(frozen, [], False)['example']['closed']
    frozen['options']['example']['required'][0]['required_scenarios'] = ['unexecuted']
    result['unexecuted-required-case'] = not qualification(frozen, [], False)['example']['closed']
    assert result['empty-required-map'] and result['unexecuted-required-case']
    c_wire = bytes.fromhex('732585800001000100000001046b657074076c6f6767696e670000100001c00c0010000100000000000e0d6578706c696369742d7573657200002904d0000000000000')
    leaked = {'transport': 'tcp', 'probe': {'edns': False}, 'reply_wire': c_wire.hex(), 'response': semantics(c_wire)}
    corrected = without_leaked_tcp_opt(leaked)
    preceding = dict(leaked, probe={'edns': True})
    c = dict(row, dns=[preceding, leaked])
    rust = dict(row, dns=[preceding, corrected])
    defect_case = dict(case, identity_matrix=True, reference_defect='C TCP stale OPT')
    assert not compare(c, rust, defect_case)
    corrupt = copy.deepcopy(rust)
    changed_wire = bytes.fromhex(corrected['reply_wire'])
    changed_wire = changed_wire[:3] + bytes([changed_wire[3] | 5]) + changed_wire[4:]
    corrupt['dns'][1] = dict(corrected, reply_wire=changed_wire.hex(), response=semantics(changed_wire))
    result['reference-defect-RCODE-guard'] = bool(compare(c, corrupt, defect_case))
    result['reference-defect-needs-prior-EDNS'] = bool(compare(dict(row, dns=[leaked]), dict(row, dns=[corrected]), defect_case))
    result['reference-defect-never-removes-requested-OPT'] = bool(compare(dict(row, dns=[preceding]), dict(row, dns=[dict(corrected, probe={'edns': True})]), defect_case))
    assert all(result[key] for key in result if key.startswith('reference-defect-'))
    return result


def qualification(required, rows, reference_only):
    executed = {row['id']: row for row in rows}
    result = {}
    for option, definition in required['options'].items():
        checked = []
        for boundary in definition['required']:
            mapping = boundary['required_scenarios']
            checked.append(dict(boundary, checked=not reference_only and bool(mapping)
                                and all(key in executed and not executed[key]['failures'] for key in mapping)))
        result[option] = {'closed': bool(checked) and definition.get('qualification_ready', False)
                          and all(row['checked'] for row in checked), 'required': checked}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scopes', default='sink,cli,identity')
    parser.add_argument('--scenarios')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    calibration = controls()
    if args.self_test:
        print(json.dumps(calibration, sort_keys=True))
        return 0
    if not all([args.image_root, args.rust, args.rust_sha256, args.source_commit, args.output]):
        parser.error('image-root/rust/rust-sha256/source-commit/output required')
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('isolated root namespace required')
    if sha256(args.rust) != args.rust_sha256:
        parser.error('candidate identity mismatch')
    out = args.output.resolve()
    if 'private' not in out.parts or out.exists():
        parser.error('fresh private output required')
    out.mkdir(parents=True)
    scenarios = [case for case in cases() if case['scope'] in args.scopes.split(',')]
    if args.scenarios:
        wanted = set(args.scenarios.split(','))
        if wanted - {case['id'] for case in scenarios}:
            parser.error('unknown scenario')
        scenarios = [case for case in scenarios if case['id'] in wanted]
    driver = out / 'driver'
    driver.mkdir()
    for name in [Path(__file__).name, *DEPENDENCIES]:
        shutil.copy2(Path(__file__).with_name(name), driver / name)
    sides = ['c'] if args.reference_only else ['c', 'rust']
    roots = {side: prepare(args.image_root, None, out / side, args.rust) for side in sides}
    result = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'c_sha256': STOCK_SHA256, 'reference_only': args.reference_only,
              'required_sha256': sha256(Path(__file__).with_name('m5_logging_requirements.json')),
              'driver_sha256': sha256(Path(__file__)), 'negative_controls': calibration,
              'scenarios': [], 'failures': [], 'closed': []}
    for case in scenarios:
        case_out = out / case['id']
        case_out.mkdir()
        row = {'id': case['id'], 'options': case['options'], 'failures': []}
        if case['argv'] == ['--version']:
            row['declared_identity_difference'] = RUST_VERSION_IDENTITY
        try:
            values = {side: run(roots[side], side, case, case_out / side) for side in sides}
            row['failures'] = compare(values['c'], values.get('rust', values['c']), case, args.reference_only)
            if case.get('reference_defect') and not args.reference_only:
                defects = []
                previous_edns = False
                for index, (c_row, rust_row) in enumerate(zip(values['c']['dns'], values['rust']['dns'])):
                    if c_row['transport'] == 'udp':
                        previous_edns = False
                    if previous_edns and c_row != rust_row and without_leaked_tcp_opt(c_row) == rust_row:
                        defects.append({'index': index, 'probe': c_row['probe'],
                                        'c_wire': c_row['reply_wire'], 'rust_wire': rust_row['reply_wire']})
                    previous_edns |= c_row['transport'] == 'tcp' and c_row['probe']['edns']
                row['reference_defect'] = {'source': 'forward.c:2378,2513,2721,2745-2755',
                                           'description': case['reference_defect'], 'affected': defects}
        except Exception as error:
            row['failures'].append({'kind': 'infrastructure', 'error': repr(error)})
        result['scenarios'].append(row)
        save(out / 'progress.json', result)
    result['failures'] = [dict(case=row['id'], **failure)
                          for row in result['scenarios'] for failure in row['failures']]
    required = json.loads(Path(__file__).with_name('m5_logging_requirements.json').read_text())
    result['options'] = qualification(required, result['scenarios'], args.reference_only)
    result['closed'] = [name for name, detail in result['options'].items() if detail['closed']]
    save(out / 'result.json', result)
    print(json.dumps({'cases': len(scenarios), 'failures': len(result['failures']), 'closed': result['closed']}))
    return int(bool(result['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
