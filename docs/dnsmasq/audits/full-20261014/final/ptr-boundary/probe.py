#!/usr/bin/env python3
"""Observe the minimal repeated-address F_REVERSE/PTR contract on exact ELFs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256

OLD_SHA = 'e2b075617d39cafa7d9443abfabbd18f9d2602dc0b535eed6393ac62ee9bbf77'
FINAL_SHA = 'fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b'
FIXTURE = ('192.0.2.2 old.test\n'
           '192.0.2.1 x.test\n'
           '192.0.3.186 a.test\n'
           '192.0.3.185 a.test\n'
           '192.0.2.1 y.test\n'
           '192.0.2.2 y.test\n')
ADDRESS = ('127.0.0.1', 15353)


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def exchange(name, kind=1, client=None):
    packet = query(name, kind, 0x3412)
    if client is not None:
        client.sendall(struct.pack('!H', len(packet)) + packet)
        response = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(2)
            stream.sendto(packet, ADDRESS)
            response = stream.recv(65535)
    decoded = semantics(response)
    return {'request_wire': packet.hex(), 'response_wire': response.hex(),
            'response_bytes': len(response), 'semantics': decoded,
            'truncated': bool(decoded['flags'] & 0x200),
            'rcode': decoded['flags'] & 15,
            'answer_count': struct.unpack('!H', response[6:8])[0],
            'answer_order': [r['data'] for r in decoded['records'] if r['section'] == 'answer'],
            'rrset': sorted((r['name'], r['type'], r['class'], r['ttl'], r['data'])
                            for r in decoded['records'] if r['section'] == 'answer')}


def run(args, label, binary):
    out = args.output / label
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', binary)
    (root / 'm2/hosts').write_text(FIXTURE)
    argv = command(root, 'c' if label.startswith('c-') else 'rust',
                   '-k', '--conf-file=', '--no-resolv', '--no-hosts',
                   '--user=root', '--group=root', '--listen-address=127.0.0.1',
                   '--bind-interfaces', '--port=15353', '--pid-file=/m2/pid',
                   '--host-record=ready.test,192.0.2.41', '--addn-hosts=/m2/hosts',
                   '--cache-size=1000', '--edns-packet-max=1232',
                   '--local-ttl=37', '--log-queries', '--log-facility=/m2/diagnostic.log')
    result = {'label': label, 'binary_path': str(binary), 'binary_sha256': sha256(binary),
              'argv': argv, 'hosts_sha256': sha256(root / 'm2/hosts'), 'observations': []}
    with (out / 'stderr').open('wb') as log:
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None, 'startup exited'
                try:
                    ready = exchange('ready.test')
                    assert ready['answer_order'] == ['192.0.2.41'], ready
                    break
                except (TimeoutError, ConnectionRefusedError):
                    time.sleep(.02)
            else:
                raise RuntimeError('startup timeout')
            identity = process_identity(root, process.pid)
            assert identity['sha256'] == sha256(binary)
            write(out / 'process-identity.json', identity)

            def observe(label, name, kind, client=None):
                row = {'label': label, 'transport': 'tcp' if client else 'udp',
                       'name': name, 'type': kind, **exchange(name, kind, client)}
                result['observations'].append(row)
                write(out / 'result.json', result)

            for transport in ('udp', 'tcp'):
                client = socket.create_connection(ADDRESS, 2) if transport == 'tcp' else None
                try:
                    if client:
                        client.settimeout(2)
                        exchange('ready.test', client=client)
                    for phase in ('before', 'after'):
                        if phase == 'after':
                            for i in range(6):
                                observe(f'{transport}-forward-y-{i}', 'y.test', 1, client)
                        for address in (1, 2):
                            for i in range(2):
                                observe(f'{transport}-ptr-{phase}-ip{address}-{i}',
                                        f'{address}.2.0.192.in-addr.arpa', 12, client)
                finally:
                    if client:
                        client.close()
            result['ready_after'] = exchange('ready.test')
            result['exit_before_cleanup'] = process.poll()
            if label.startswith('c-'):
                process.send_signal(signal.SIGUSR1)
                for _ in range(100):
                    diagnostic = (root / 'm2/diagnostic.log').read_text()
                    if diagnostic.count('4FRI') + diagnostic.count('4F I') >= 7:
                        break
                    time.sleep(.02)
                else:
                    raise RuntimeError('C cache dump incomplete')
        finally:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            result['exit'] = process.returncode
            diagnostic = root / 'm2/diagnostic.log'
            if diagnostic.exists():
                shutil.copy2(diagnostic, out / 'daemon.log')
                result['daemon_log_sha256'] = sha256(out / 'daemon.log')
            write(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--old-rust', type=Path, required=True)
    parser.add_argument('--final-rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    assert sha256(args.old_rust) == OLD_SHA
    assert sha256(args.final_rust) == FINAL_SHA
    args.output.mkdir()
    shutil.copy2(__file__, args.output / 'driver.py')
    (args.output / 'hosts.fixture').write_text(FIXTURE)
    result = {'driver_sha256': sha256(__file__), 'fixture': FIXTURE,
              'fixture_sha256': sha256(args.output / 'hosts.fixture'), 'runs': []}
    for label, binary in [('c-first', args.image_root / 'usr/sbin/dnsmasq'),
                          ('old-rust', args.old_rust), ('final-rust', args.final_rust),
                          ('c-repeat', args.image_root / 'usr/sbin/dnsmasq')]:
        result['runs'].append(run(args, label, binary))
        write(args.output / 'result.json', result)
        print(label, 'complete', flush=True)
    assert all(r['exit_before_cleanup'] is None and r['exit'] == 0 for r in result['runs'])
    assert all(not o['truncated'] and o['rcode'] == 0
               for r in result['runs'] for o in r['observations'])
    assert result['runs'][0]['observations'] == result['runs'][3]['observations']
    assert result['runs'][1]['observations'] == result['runs'][2]['observations']


if __name__ == '__main__':
    main()
