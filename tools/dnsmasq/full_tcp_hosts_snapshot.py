#!/usr/bin/env python3
"""Exact-image C/Rust TCP hosts snapshots across HUP and hostsdir changes."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, sha256

ADDRESS = ('127.0.0.1', 15353)


def exchange(host, kind=1, client=None):
    packet = query(host, kind, 0x3412)
    if client is not None:
        client.sendall(struct.pack('!H', len(packet)) + packet)
        return exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.settimeout(.4)
        stream.sendto(packet, ADDRESS)
        return stream.recv(65535)


def wait(host, address):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        try:
            if address in [r['data'] for r in semantics(exchange(host))['records']]:
                return
        except (TimeoutError, ConnectionError):
            pass
        time.sleep(.01)
    raise AssertionError((host, address, 'readiness timeout'))


def run(args, side):
    out = args.output / side
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', args.rust)
    hosts = root / 'm2/hosts'
    hosts.write_text('192.0.2.41 hup4.test\n2001:db8::41 hup6.test\n'
                     '192.0.2.1 rr.test\n192.0.2.2 rr.test\n'
                     '2001:db8::1 rr.test\n2001:db8::2 rr.test\n')
    directory = root / 'm2/hostsdir'
    directory.mkdir()
    dynamic = directory / 'dynamic'
    dynamic.write_text('192.0.2.51 dynamic.test\n2001:db8::51 dynamic6.test\n')
    argv = ['-k', '--conf-file=', '--no-resolv', '--no-hosts', '--user=root',
            '--group=root', '--listen-address=127.0.0.1', '--bind-interfaces',
            '--port=15353', '--pid-file=/m2/pid', '--local-ttl=37',
            '--host-record=direct.test,192.0.2.61,2001:db8::61',
            '--addn-hosts=/m2/hosts', '--hostsdir=/m2/hostsdir', '--log-facility=/dev/null']
    result = {'side': side, 'argv': argv, 'observations': []}
    clients = []

    def ask(label, host, kind=1, client=None):
        reply = exchange(host, kind, client)
        result['observations'].append({'label': label, 'wire': reply.hex(), 'answer': semantics(reply)})

    def connect():
        client = socket.create_connection(ADDRESS, 2)
        client.settimeout(2)
        clients.append(client)
        exchange('direct.test', client=client)  # Confirm daemon accepted snapshot.
        return client

    with (out / 'stderr').open('wb') as log:
        process = subprocess.Popen(command(root, side, *argv), stdout=log, stderr=log, start_new_session=True)
        try:
            wait('hup4.test', '192.0.2.41')
            old = connect()
            second = connect()
            for kind in (1, 28):
                for i in range(3):
                    ask(f'old-rr-{kind}-{i}', 'rr.test', kind, old)
                for i in range(3):
                    ask(f'second-rr-{kind}-{i}', 'rr.test', kind, second)
                for i in range(3):
                    ask(f'parent-rr-{kind}-{i}', 'rr.test', kind)
            hosts.write_text('192.0.2.42 hup4.test\n2001:db8::42 hup6.test\n')
            process.send_signal(signal.SIGHUP)
            wait('hup4.test', '192.0.2.42')
            new = connect()
            for label, client in [('old', old), ('second', second), ('new', new), ('parent', None)]:
                for host, kind in [('hup4.test', 1), ('hup6.test', 28), ('direct.test', 1), ('direct.test', 28)]:
                    ask(f'hup-{label}-{host}-{kind}', host, kind, client)
            dynamic.write_text('192.0.2.52 dynamic.test\n2001:db8::52 dynamic6.test\n')
            wait('dynamic.test', '192.0.2.52')
            latest = connect()
            for label, client in [('old', old), ('new', new), ('latest', latest), ('parent', None)]:
                for host, kind in [('dynamic.test', 1), ('dynamic6.test', 28)]:
                    ask(f'inotify-{label}-{host}', host, kind, client)
            result['alive'] = process.poll() is None
        finally:
            for client in clients:
                client.close()
            process.terminate()
            process.wait(3)
            result['exit'] = process.returncode
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    args.output.mkdir()
    result = {'c_sha256': STOCK_SHA256, 'rust_sha256': sha256(args.rust), 'driver_sha256': sha256(__file__)}
    result['runs'] = [run(args, side) for side in ('c', 'rust')]
    result['matched'] = result['runs'][0]['observations'] == result['runs'][1]['observations']
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    assert result['matched'], 'C/Rust snapshots or round-robin order differ'
    print(json.dumps({'matched': True, 'observations': len(result['runs'][0]['observations'])}))


if __name__ == '__main__':
    main()
