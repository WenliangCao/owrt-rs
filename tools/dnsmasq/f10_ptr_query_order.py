#!/usr/bin/env python3
"""Bounded exact-ELF diagnostic: PTR order before and after forward rotation."""
import argparse
import json
import os
from pathlib import Path
import socket
import signal
import struct
import subprocess
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256


def exchange(name, kind, tcp=False):
    packet = query(name, kind, 0x1521)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        if tcp:
            client.connect(('127.0.0.1', 15353))
            client.sendall(struct.pack('!H', len(packet)) + packet)
            response = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        else:
            client.sendto(packet, ('127.0.0.1', 15353))
            response = client.recv(65535)
    decoded = semantics(response)
    return {'wire': response.hex(), 'flags': decoded['flags'],
            'records': [record for record in decoded['records'] if record['section'] == 'answer']}


def run(args, side, selected=None):
    out = args.output / side
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', args.rust)
    fixture = ''.join(f'192.0.{j + 2}.{i % 250 + 1} host{i:06d}.test\n'
                      for i in range(args.names) for j in (0, 1))
    candidates = []
    if args.collision:
        import ipaddress
        def bucket(address):
            value = 0
            for byte in address.packed: value = (2 * value + byte) % 187
            return value
        target_bucket = bucket(ipaddress.IPv4Address('192.0.2.1'))
        for number in range(1, 65536):
            address = ipaddress.IPv4Address(int(ipaddress.IPv4Address('10.0.0.0')) + number)
            if bucket(address) == target_bucket:
                candidates.append(str(address))
                if len(candidates) == 201: break
        assert len(candidates) == 201
        fixture = '192.0.2.1 x.test\n' + ''.join(
            f'{address} a{i:03d}.test\n192.0.4.2 a{i:03d}.test\n192.0.2.1 y{i:03d}.test\n'
            for i, address in enumerate(candidates[:-1])) + '192.0.4.1 x.test\n'
    (root / 'm2/hosts').write_text(fixture)
    argv = command(root, side, '-k', '--conf-file=', '--no-resolv', '--no-hosts',
                   '--user=root', '--group=root', '--listen-address=127.0.0.1',
                   '--bind-interfaces', '--port=15353', '--pid-file=/m2/pid',
                   '--host-record=ready.test,192.0.2.41', '--addn-hosts=/m2/hosts',
                   '--cache-size=1000', '--edns-packet-max=1232', '--log-facility=/dev/null')
    if args.collision:
        argv[argv.index('--cache-size=1000')] = '--cache-size=0'
    result = {'side': side, 'argv': argv, 'fixture_sha256': sha256(root / 'm2/hosts'),
              'before': {}, 'after': {}, 'changed': []}
    with (out / 'stderr').open('wb') as log:
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None
                try:
                    exchange('ready.test', 1)
                    break
                except (TimeoutError, ConnectionRefusedError):
                    time.sleep(.02)
            result['identity'] = process_identity(root, process.pid)
            if args.collision:
                name = '1.2.0.192.in-addr.arpa'
                before = exchange(name, 12, tcp=True)
                result['before'][name] = before
                result['forward'] = [{'name': 'x.test', **exchange('x.test', 1)}]
                after = exchange(name, 12, tcp=True)
                result['after'][name] = after
                result['changed'] = [name] if before['wire'] != after['wire'] else []
                result['udp_after'] = exchange('ready.test', 1)
                result['tcp_after'] = exchange('ready.test', 1, tcp=True)
                result['collision_candidates'] = candidates
                assert not before['flags'] & 0x200 and not after['flags'] & 0x200
                if result['changed']:
                    before_names = [row['data'] for row in before['records']]
                    after_names = [row['data'] for row in after['records']]
                    crossed = [value for value in before_names if value != 'x.test'
                               and (before_names.index(value) < before_names.index('x.test'))
                               != (after_names.index(value) < after_names.index('x.test'))]
                    assert crossed
                    selected = crossed[0]
                if selected is not None:
                    index = int(selected[1:4])
                    minimal = (f'192.0.2.1 x.test\n{candidates[index]} a.test\n'
                               f'192.0.4.2 a.test\n192.0.2.1 {selected}\n192.0.4.1 x.test\n')
                    (root / 'm2/hosts').write_text(minimal)
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.15)
                    before = exchange(name, 12, tcp=True)
                    forward = exchange('x.test', 1)
                    after = exchange(name, 12, tcp=True)
                    result['minimal'] = {'fixture': minimal, 'selected': selected,
                                         'before': before, 'forward': forward, 'after': after,
                                         'order_changed': before['wire'] != after['wire']}
                (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                return result
            for j in (2, 3):
                for octet in range(1, 251):
                    name = f'{octet}.{j}.0.192.in-addr.arpa'
                    # UDP suffices for the small owner counts and keeps all
                    # queries on the parent whose forward rotation is tested.
                    result['before'][name] = exchange(name, 12)
            result['forward'] = []
            for i in range(args.names):
                name = f'host{i:06d}.test'
                result['forward'].append({'name': name, **exchange(name, 1)})
            for name, before in result['before'].items():
                after = result['after'][name] = exchange(name, 12)
                assert not before['flags'] & 0x200 and not after['flags'] & 0x200
                if before['wire'] != after['wire']:
                    result['changed'].append(name)
            result['udp_after'] = exchange('ready.test', 1)
            result['tcp_after'] = exchange('ready.test', 1, tcp=True)
        finally:
            process.terminate()
            try: process.wait(3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--names', type=int, default=2000)
    parser.add_argument('--collision', action='store_true')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert not args.output.exists()
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    args.output.mkdir()
    (args.output / 'driver.py').write_bytes(Path(__file__).read_bytes())
    result = {'driver_sha256': sha256(Path(__file__)), 'rust_sha256': sha256(args.rust),
              'c_sha256': STOCK_SHA256, 'names': args.names, 'runs': []}
    for side in ('c', 'rust'):
        selected = result['runs'][0].get('minimal', {}).get('selected') if result['runs'] else None
        result['runs'].append(run(args, side, selected))
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(side, result['runs'][-1]['changed'], flush=True)


if __name__ == '__main__':
    main()
