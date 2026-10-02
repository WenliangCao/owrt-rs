#!/usr/bin/env python3
"""Isolated C-reference checks of wildcard TCP interface admission.

Use run_isolated.sh. Establish the reference with the matching C daemon, then
compare a repaired candidate with --reference. Saved observations can be
checked without network activity using --compare-result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import query, semantics

PORT = 15353
QUERY = query('ready.test')
CASES = (
    ('v4-allowed', 'allowed', '192.0.2.1', '192.0.2.2'),
    ('v4-excluded', 'excluded', '192.0.2.1', '198.51.100.2'),
    ('v4-loopback', None, '192.0.2.1', ''),
    ('v6-allowed', 'allowed', '2001:db8:1::1', '2001:db8:1::2'),
    ('v6-excluded', 'excluded', '2001:db8:1::1', '2001:db8:2::2'),
    ('v6-loopback', None, '2001:db8:1::1', ''),
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def request(destination, source):
    family = socket.AF_INET6 if ':' in destination else socket.AF_INET
    row = {'destination': destination, 'source': source, 'connected': False,
           'request_hex': QUERY.hex()}
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(1)
        if source:
            client.bind((source, 0))
        try:
            client.connect((destination, PORT))
            row['connected'] = True
            row['local'] = list(client.getsockname())
            row['peer'] = list(client.getpeername())
            client.sendall(struct.pack('!H', len(QUERY)) + QUERY)
            header = bytearray()
            while len(header) < 2:
                packet = client.recv(2 - len(header))
                if not packet:
                    row['outcome'] = 'closed' if not header else 'truncated'
                    return row
                header.extend(packet)
            size = struct.unpack('!H', header)[0]
            packet = bytearray()
            while len(packet) < size:
                received = client.recv(size - len(packet))
                if not received:
                    row['outcome'] = 'truncated'
                    row['partial_hex'] = packet.hex()
                    return row
                packet.extend(received)
            row.update(outcome='reply', reply_hex=packet.hex(), reply=semantics(bytes(packet)))
        except (ConnectionResetError, BrokenPipeError) as error:
            row.update(outcome='reset', error=repr(error))
        except TimeoutError as error:
            row.update(outcome='timeout', error=repr(error))
        except OSError as error:
            row.update(outcome='socket-error', error=repr(error))
    return row


def validate(result):
    errors = []
    if result.get('failures') != []:
        errors.append('run has failures or missing failure inventory')
    rows = result.get('rows', [])
    if [row.get('case') for row in rows] != [case[0] for case in CASES]:
        return errors + ['missing, duplicated, reordered or unexpected cases']
    for row, (label, ingress, destination, source) in zip(rows, CASES):
        if row.get('destination') != destination or row.get('source') != source:
            errors.append(label + ': request endpoint differs')
        if row.get('request_hex') != QUERY.hex() or row.get('connected') is not True:
            errors.append(label + ': no successful TCP connection with the fixed request')
        if ingress == 'excluded':
            if row.get('outcome') not in ('closed', 'reset') or 'reply_hex' in row or 'reply' in row:
                errors.append(label + ': expected connection closure without a DNS response')
        else:
            try:
                packet = bytes.fromhex(row['reply_hex'])
                reply = semantics(packet)
                if row.get('outcome') != 'reply' or row.get('reply') != reply:
                    raise ValueError('reply observation does not match saved wire bytes')
                if reply['id'] != 0x2930 or reply['flags'] != 0x8580:
                    raise ValueError('reply ID or DNS flags differ')
                if reply['questions'] != [['ready.test', 1, 1]]:
                    raise ValueError('question differs')
                expected = [{'section': 'answer', 'name': 'ready.test', 'type': 1,
                             'class': 1, 'ttl': 0, 'data': '192.0.2.53'}]
                if reply['records'] != expected:
                    raise ValueError('record differs')
            except (KeyError, TypeError, ValueError, struct.error) as error:
                errors.append(label + ': ' + str(error))
    if result.get('daemon_exit') != 0 or result.get('cleanup_ok') is not True:
        errors.append('daemon or client namespaces did not stop normally')
    return errors


def compare(actual, reference):
    errors = [f'{side}: {error}' for side, value in (('actual', actual), ('reference', reference))
              for error in validate(value)]
    if not errors:
        for left, right in zip(reference['rows'], actual['rows']):
            # EOF versus reset is a transport close race. Both require a
            # successful TCP connection and no response; preserve raw outcomes.
            if left['case'].endswith('-excluded'):
                continue
            if left['reply_hex'] != right['reply_hex']:
                errors.append(left['case'] + ': C/Rust response bytes differ')
    return errors


def run(binary, out):
    commands, children, rows, failures = [], {}, [], []
    daemon = None
    daemon_exit = None
    cleanup_ok = True

    def command(*argv):
        process = subprocess.run(argv, capture_output=True, text=True)
        commands.append({'argv': list(argv), 'exit': process.returncode,
                         'stdout': process.stdout, 'stderr': process.stderr})
        process.check_returncode()
        return process.stdout

    def ns(label, *argv):
        return command('nsenter', '-t', str(children[label].pid), '-n', *argv)

    try:
        for label, number, network in (('allowed', 1, '192.0.2'), ('excluded', 2, '198.51.100')):
            child = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
            children[label] = child
            deadline = time.monotonic() + 3
            while os.readlink(f'/proc/{child.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('client namespace did not become ready')
                time.sleep(.01)
            interface, peer = label + '0', label + '-peer'
            command('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', peer)
            command('ip', 'link', 'set', peer, 'netns', str(child.pid))
            command('ip', 'link', 'set', interface, 'up')
            command('ip', 'addr', 'add', network + '.1/24', 'dev', interface)
            command('ip', '-6', 'addr', 'add', f'2001:db8:{number}::1/64', 'dev', interface, 'nodad')
            ns(label, 'ip', 'link', 'set', 'lo', 'up')
            ns(label, 'ip', 'link', 'set', peer, 'name', 'client0')
            ns(label, 'ip', 'link', 'set', 'client0', 'up')
            ns(label, 'ip', 'addr', 'add', network + '.2/24', 'dev', 'client0')
            ns(label, 'ip', '-6', 'addr', 'add', f'2001:db8:{number}::2/64', 'dev', 'client0', 'nodad')
        ns('excluded', 'ip', 'route', 'add', '192.0.2.1/32', 'via', '198.51.100.1')
        ns('excluded', 'ip', '-6', 'route', 'add', '2001:db8:1::1/128', 'via', '2001:db8:2::1')
        topology = {'server': json.loads(command('ip', '-j', 'addr')), 'clients': {}}
        for label in children:
            topology['clients'][label] = {'addresses': json.loads(ns(label, 'ip', '-j', 'addr')),
                                          'v4_routes': json.loads(ns(label, 'ip', '-j', 'route')),
                                          'v6_routes': json.loads(ns(label, 'ip', '-6', '-j', 'route'))}
        save(out / 'topology.json', topology)
        config = out / 'dnsmasq.conf'
        config.write_text('port=15353\nno-hosts\nno-resolv\nuser=root\ngroup=root\npid-file=\n'
                          'interface=allowed0\nexcept-interface=excluded0\nhost-record=ready.test,192.0.2.53\n')
        argv = [str(binary), '-k', '-C', str(config)]
        save(out / 'daemon-command.json', argv)
        with (out / 'daemon.stdout').open('wb') as stdout, (out / 'daemon.stderr').open('wb') as stderr:
            daemon = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 5
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ready:
                ready.settimeout(.1)
                while True:
                    if daemon.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('daemon failed DNS readiness')
                    ready.sendto(QUERY, ('127.0.0.1', PORT))
                    try:
                        packet = ready.recv(4096)
                        (out / 'ready.reply').write_bytes(packet)
                        if packet[:2] == QUERY[:2] and packet[-4:] == bytes([192, 0, 2, 53]):
                            break
                    except TimeoutError:
                        pass
            for label, ingress, destination, source in CASES:
                row = (request(destination, source) if ingress is None else
                       json.loads(ns(ingress, sys.executable, str(Path(__file__).resolve()),
                                     'client', destination, source)))
                row['case'] = label
                rows.append(row)
                save(out / (label + '.json'), row)
            daemon.send_signal(signal.SIGTERM)
            daemon_exit = daemon.wait(3)
    except Exception as error:
        failures.append(repr(error))
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(3)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
                cleanup_ok = False
        for child in children.values():
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                cleanup_ok = False
        save(out / 'commands.json', commands)
    return {'binary': str(binary), 'binary_sha256': digest(binary), 'probe_sha256': digest(__file__),
            'rows': rows, 'failures': failures, 'daemon_exit': daemon_exit, 'cleanup_ok': cleanup_ok}


def main():
    if sys.argv[1:2] == ['client']:
        print(json.dumps(request(sys.argv[2], sys.argv[3])))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--binary', type=Path)
    action.add_argument('--compare-result', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if 'private' not in out.parts:
        parser.error('evidence must live below private/')
    if args.compare_result and not args.reference:
        parser.error('--compare-result requires --reference')
    if args.binary and (os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1'
                        or [name for _, name in socket.if_nameindex()] != ['lo']):
        parser.error('requires root through run_isolated.sh with only loopback')
    out.mkdir(parents=True, exist_ok=False)
    result = (json.loads(args.compare_result.read_text()) if args.compare_result else
              run(args.binary.resolve(), out))
    if args.compare_result:
        result['saved_input'] = {'path': str(args.compare_result), 'sha256': digest(args.compare_result)}
    result['validation_errors'] = validate(result)
    result['differences'] = []
    if args.reference:
        result['reference'] = {'path': str(args.reference), 'sha256': digest(args.reference)}
        result['differences'] = compare(result, json.loads(args.reference.read_text()))
    save(out / 'result.json', result)
    print(json.dumps({'cases': len(result['rows']), 'failures': result['failures'],
                      'validation_errors': result['validation_errors'], 'differences': result['differences']}))
    return int(bool(result['failures'] or result['validation_errors'] or result['differences']))


if __name__ == '__main__':
    raise SystemExit(main())
