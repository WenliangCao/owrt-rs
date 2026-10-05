#!/usr/bin/env python3
"""Ordinary loop.c callers, executed only in the exact-image isolated rootfs."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import answer, query, read_name, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def cases():
    return [
        dict(id='disabled', enabled=False),
        dict(id='healthy', enabled=True),
        dict(id='returned', enabled=True, reflect=True),
        dict(id='returned-hup', enabled=True, reflect=True, hup=True),
        dict(id='healthy-hup', enabled=True, hup=True),
        dict(id='wrong-type', enabled=True, reflect=True, mutation='type'),
        dict(id='wrong-uid', enabled=True, reflect=True, mutation='uid'),
        dict(id='wrong-suffix', enabled=True, reflect=True, mutation='suffix'),
        dict(id='fixed-port', enabled=True, fixed_port=True),
        dict(id='returned-fixed-port', enabled=True, fixed_port=True, reflect=True),
        dict(id='source-port', enabled=True, source_port=True),
        dict(id='domain-only', enabled=True, domain=True),
        dict(id='dotless-only', enabled=True, dotless=True),
    ]


def wait(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('ordinary caller timed out')


class Upstream:
    def __init__(self, case):
        self.case, self.events, self.errors = case, [], []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.2', 15970))
        self.socket.settimeout(.05)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
                if packet[2] & 0x80:
                    continue  # Actual replies to invalid reflected probes are not upstream queries.
                name, end = read_name(packet, 12)
                kind = struct.unpack_from('!H', packet, end)[0]
                probe = bool(re.fullmatch('[0-9a-f]{8}\\.test', name)) and kind == 16 and packet[2:12] == bytes.fromhex('01000001000000000000')
                self.events.append(dict(probe=probe, name=name, type=kind, peer=list(peer),
                                        wire=packet.hex(), semantics=semantics(packet)))
                if probe:
                    if self.case.get('reflect'):
                        reflected = bytearray(packet)
                        mutation = self.case.get('mutation')
                        if mutation == 'type': reflected[end:end + 2] = b'\0\x12'
                        if mutation == 'uid': reflected[13:21] = b'ffffffff' if name[:8] != 'ffffffff' else b'00000000'
                        if mutation == 'suffix': reflected[22:26] = b'test'[:-1] + b'x'
                        self.socket.sendto(reflected, ('127.0.0.1', 15370))
                else:
                    self.socket.sendto(answer(packet), peer)
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set(): self.errors.append(repr(error))
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.thread.is_alive() or self.errors:
            raise AssertionError(self.errors or 'upstream fixture thread leaked')


def dns():
    request = query('ready.loop.test', 1, 0x5151)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.5)
        client.sendto(request, ('127.0.0.1', 15370))
        try:
            reply = client.recv(65535)
        except socket.timeout:
            return {'reply': None, 'wire': None}
    value = semantics(reply)
    assert value['id'] == 0x5151
    return {'reply': value, 'wire': reply.hex()}


def resources(pid):
    return {'threads': len(list(Path(f'/proc/{pid}/task').iterdir())),
            'fds': len(list(Path(f'/proc/{pid}/fd').iterdir()))}


def run(root, side, case, folder):
    folder.mkdir()
    inside = '/m2/loop-' + case['id']
    work = root / inside.lstrip('/')
    work.mkdir()
    server = '127.0.0.2#15970'
    if case.get('source_port'): server += '@127.0.0.1#15570'
    if case.get('domain'): server = '/loop.test/' + server
    if case.get('dotless'): server = '//' + server
    config = ['no-resolv', 'no-hosts', 'no-0x20-encode', 'user=root', 'group=root',
              'listen-address=127.0.0.1', 'port=15370', 'cache-size=0', 'server=' + server,
              'pid-file=' + inside + '/pid', 'log-facility=' + inside + '/log']
    if case['enabled']: config.append('dns-loop-detect')
    if case.get('fixed_port'): config.append('query-port=15570')
    (work / 'config').write_text('\n'.join(config) + '\n')
    (folder / 'config').write_text((work / 'config').read_text())
    syntax = subprocess.run(command(root, side, '--test', '-C', inside + '/config'), capture_output=True, timeout=3)
    result = {'syntax': dict(exit=syntax.returncode, stdout=syntax.stdout.decode(), stderr=syntax.stderr.decode()), 'observations': []}
    upstream = Upstream(case)
    process = None
    try:
        with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr:
            process = subprocess.Popen(command(root, side, '-k', '-C', inside + '/config'), stdout=stdout, stderr=stderr)
            wait(lambda: (work / 'pid').exists() or process.poll() is not None)
            assert process.poll() is None, 'startup failed'
            result['identity'] = process_identity(root, process.pid)
            time.sleep(.15)
            result['resources'] = resources(process.pid)
            result['observations'].append(dns())
            if case.get('hup'):
                process.send_signal(signal.SIGHUP)
                time.sleep(.15)
                result['observations'].append(dns())
                result['after_hup_resources'] = resources(process.pid)
            result['probes'] = copy.deepcopy([event for event in upstream.events if event['probe']])
            result['ordinary_upstream'] = copy.deepcopy([event for event in upstream.events if not event['probe']])
            result['logs'] = [line[line.index('NOT using nameserver'):] if 'NOT using nameserver' in line else line[line.index('using nameserver'):]
                              for line in (work / 'log').read_text().splitlines() if 'using nameserver' in line]
    finally:
        if process is not None:
            if process.poll() is None: process.send_signal(signal.SIGTERM)
            process.wait(timeout=3)
            result['exit'] = process.returncode
        upstream.close()
        result['cleanup'] = {'pid_file': (work / 'pid').exists(), 'live_pids': []}
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    if os.path.realpath(proc / 'root') == str(root): result['cleanup']['live_pids'].append(int(proc.name))
                except (FileNotFoundError, PermissionError): pass
        result['stderr'] = (folder / 'stderr').read_text()
        save(folder / 'observed.json', result)
    return result


def projection(value):
    result = copy.deepcopy(value)
    for key in ['identity', 'stderr', 'resources', 'after_hup_resources']:
        result.pop(key, None)
    result['syntax']['stderr'] = result['syntax']['stderr'].replace('dnsmasq-rs:', 'dnsmasq:')
    for probe in result['probes']:
        probe.pop('wire')
        probe['name'] = '<uid>.test'
        probe['peer'][1] = '<random-port>' if probe['peer'][1] != 15570 else 15570
        probe['semantics']['id'] = '<random-id>'
        probe['semantics']['questions'][0][0] = '<uid>.test'
    for event in result['ordinary_upstream']:
        event.pop('wire')
        if re.fullmatch('[0-9a-f]{8}\\.(test|tesx)', event['name']):
            suffix = event['name'].split('.')[1]
            event['name'] = '<uid>.' + suffix
            event['semantics']['questions'][0][0] = '<uid>.' + suffix
        event['peer'][1] = '<random-port>' if event['peer'][1] != 15570 else 15570
        event['semantics']['id'] = '<random-id>'
    return result


def compare(c, rust, case):
    errors = []
    expected_probes = 1 if case['enabled'] and not any(case.get(key) for key in ['domain', 'dotless', 'fixed_port', 'source_port']) else 0
    for side, value in [('c', c), ('rust', rust)]:
        if len(value['probes']) != expected_probes: errors.append(dict(side=side, kind='probe-count', expected=expected_probes, actual=len(value['probes'])))
        for probe in value['probes']:
            if probe['semantics']['flags'] != 0x0100 or probe['semantics']['questions'][0][1:] != [16, 1] or probe['semantics']['records']:
                errors.append(dict(side=side, kind='probe-wire'))
            if case.get('fixed_port') or case.get('source_port'):
                if probe['peer'] != ['127.0.0.1', 15570]: errors.append(dict(side=side, kind='source-contract', actual=probe['peer']))
        if value['probes'] and any(p['name'] != value['probes'][0]['name'] for p in value['probes']): errors.append(dict(side=side, kind='unstable-uid'))
        if value['resources']['threads'] != 1: errors.append(dict(side=side, kind='extra-thread'))
        if value.get('after_hup_resources') != value['resources'] and case.get('hup'): errors.append(dict(side=side, kind='hup-resource-leak'))
        if value['cleanup'] != {'pid_file': False, 'live_pids': []} or value['exit'] != 0: errors.append(dict(side=side, kind='cleanup'))
    if projection(c) != projection(rust): errors.append(dict(kind='paired-difference', c=projection(c), rust=projection(rust)))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['image-root', 'rust', 'output']: parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--scenarios')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1': parser.error('isolated root required')
    if sha256(args.rust) != args.rust_sha256: parser.error('candidate identity mismatch')
    if args.output.exists() or 'private' not in args.output.resolve().parts: parser.error('fresh private output required')
    args.output.mkdir(parents=True)
    roots = {side: prepare(args.image_root, None, args.output / side, args.rust) for side in ['c', 'rust']}
    selected = [case for case in cases() if not args.scenarios or case['id'] in args.scenarios.split(',')]
    report = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256, 'c_sha256': STOCK_SHA256,
              'driver_sha256': sha256(Path(__file__)), 'cases': [], 'failures': []}
    driver = args.output / 'driver'; driver.mkdir()
    for name in ['m5_loop_detect.py', 'dns_service_probe.py', 'm2_rootfs.py', 'run_isolated.sh']:
        (driver / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    for case in selected:
        folder = args.output / case['id']; folder.mkdir()
        row = {'id': case['id'], 'failures': []}
        try:
            values = {side: run(root, side, case, folder / side) for side, root in roots.items()}
            row['failures'] = compare(values['c'], values['rust'], case)
        except Exception as error: row['failures'].append(dict(kind='infrastructure', error=repr(error)))
        report['cases'].append(row); save(args.output / 'progress.json', report)
    report['failures'] = [dict(case=row['id'], **f) for row in report['cases'] for f in row['failures']]
    report['qualified'] = False  # This first schedule is not the full family closure.
    report['ordinary_schedule_passed'] = not report['failures'] and len(selected) == len(cases())
    save(args.output / 'result.json', report)
    print(json.dumps({'cases': len(selected), 'failures': len(report['failures']), 'qualified': report['qualified']}))
    return int(bool(report['failures']))


if __name__ == '__main__': raise SystemExit(main())
