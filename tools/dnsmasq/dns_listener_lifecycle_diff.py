#!/usr/bin/env python3
"""One isolated C/Rust service comparison for DNS interface lifecycle."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def query(destination, source, tcp):
    family = socket.AF_INET6 if ':' in destination else socket.AF_INET
    packet = struct.pack('!6H', 123, 0x100, 1, 0, 0, 0) + b'\x05ready\x04test\x00\x00\x01\x00\x01'
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(.5)
        if source:
            client.bind((source, 0))
        try:
            target = socket.getaddrinfo(destination, 15353, family, client.type)[0][4]
            if tcp:
                client.connect(target)
                client.sendall(struct.pack('!H', len(packet)) + packet)
                length = client.recv(2)
                if len(length) != 2:
                    return None
                count = struct.unpack('!H', length)[0]
                response = b''
                while len(response) < count:
                    data = client.recv(count - len(response))
                    if not data:
                        return None
                    response += data
            else:
                client.sendto(packet, target)
                response = client.recv(4096)
            return response.hex()
        except (TimeoutError, ConnectionError, OSError):
            return None


def bound_addresses():
    result = set()
    for file, v6 in [('udp', False), ('udp6', True), ('tcp', False), ('tcp6', True)]:
        for line in Path('/proc/net/' + file).read_text().splitlines()[1:]:
            fields = line.split()
            ip, port = fields[1].split(':')
            if int(port, 16) != 15353 or file.startswith('tcp') and fields[3] != '0A':
                continue
            raw = bytes.fromhex(ip)
            raw = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
            address = str(ipaddress.ip_address(raw))
            result.add((file[:3], address))
    return sorted(result)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'query':
        print(json.dumps(query(sys.argv[2], sys.argv[3], sys.argv[4] == 'tcp')))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    args.out.mkdir(parents=True, exist_ok=False)
    child = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
    daemon = None
    rows = []
    def ns(*args):
        return command('nsenter', '-t', str(child.pid), '-n', *args)
    def wait_for(expected, absent=()):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            bound = bound_addresses()
            if all((transport, address) in bound for address in expected for transport in ('udp', 'tcp')) and all((transport, address) not in bound for address in absent for transport in ('udp', 'tcp')):
                return bound
            assert daemon.poll() is None, 'daemon exited'
            time.sleep(.02)
        raise AssertionError(('listener transition timeout', expected, absent, bound_addresses()))
    def ask(label, destination, source='', tcp=False, local=False):
        answer = query(destination, source, tcp) if local else json.loads(ns(sys.executable, str(Path(__file__).resolve()), 'query', destination, source, 'tcp' if tcp else 'udp'))
        rows.append({'case': label, 'answer': answer})
    try:
        deadline = time.monotonic() + 3
        while os.readlink(f'/proc/{child.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
            assert time.monotonic() < deadline
            time.sleep(.01)
        ns('ip', 'link', 'set', 'lo', 'up')
        command('ip', 'link', 'add', 'test-lan', 'type', 'veth', 'peer', 'name', 'client0')
        command('ip', 'link', 'set', 'client0', 'netns', str(child.pid))
        command('ip', 'link', 'set', 'test-lan', 'up')
        ns('ip', 'link', 'set', 'client0', 'up')
        for address in ['192.0.2.1/24', '2001:db8::1/64', 'fe80::1/64']:
            command('ip', 'addr', 'add', address, 'dev', 'test-lan', *(['nodad'] if ':' in address else []))
        for address in ['192.0.2.2/24', '198.51.100.2/32', '2001:db8::2/64', '2001:db8:9::2/128', 'fe80::2/64']:
            ns('ip', 'addr', 'add', address, 'dev', 'client0', *(['nodad'] if ':' in address else []))
        command('ip', 'route', 'add', '198.51.100.2/32', 'dev', 'test-lan')
        command('ip', '-6', 'route', 'add', '2001:db8:9::2/128', 'dev', 'test-lan')
        for profile, extra in [('local-net', ''), ('explicit-listen', 'listen-address=192.0.2.1\n')]:
            config = args.out / (profile + '.conf')
            config.write_text('port=15353\nno-hosts\nno-resolv\nbind-dynamic\nlocal-service\nhost-record=ready.test,192.0.2.53\n' + extra)
            with (args.out / (profile + '.log')).open('w') as log:
                daemon = subprocess.Popen([str(args.binary), '-d', '-C', str(config)], stdout=log, stderr=log)
                wait_for(['192.0.2.1'])
                for tcp in (False, True):
                    transport = 'tcp' if tcp else 'udp'
                    ask(profile + '-onnet-' + transport, '192.0.2.1', '192.0.2.2', tcp)
                    ask(profile + '-offnet-' + transport, '192.0.2.1', '198.51.100.2', tcp)
                    ask(profile + '-local-to-lan-' + transport, '192.0.2.1', '', tcp, True)
                    if profile == 'local-net':
                        ask('ipv6-onnet-' + transport, '2001:db8::1', '2001:db8::2', tcp)
                        ask('ipv6-offnet-' + transport, '2001:db8::1', '2001:db8:9::2', tcp)
                        ask('ipv6-scoped-' + transport, 'fe80::1%client0', '', tcp)
                if profile == 'local-net':
                    command('ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'test-lan')
                    command('ip', '-6', 'addr', 'add', '2001:db8::3/64', 'dev', 'test-lan', 'nodad')
                    wait_for(['192.0.2.3', '2001:db8::3'])
                    for tcp in (False, True):
                        ask('added-v4-' + str(tcp), '192.0.2.3', '192.0.2.2', tcp)
                        ask('added-v6-' + str(tcp), '2001:db8::3', '2001:db8::2', tcp)
                    command('ip', 'addr', 'del', '192.0.2.3/24', 'dev', 'test-lan')
                    command('ip', '-6', 'addr', 'del', '2001:db8::3/64', 'dev', 'test-lan')
                    wait_for(['192.0.2.1'], ['192.0.2.3', '2001:db8::3'])
                    rows.append({'case': 'removed-listeners', 'answer': 'closed'})
                    ask('surviving-listener', '192.0.2.1', '192.0.2.2')
                daemon.send_signal(signal.SIGTERM)
                daemon.wait(3)
                rows.append({'case': profile + '-exit', 'answer': daemon.returncode})
                daemon = None
                assert bound_addresses() == [], 'listener leak after stop'
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.terminate()
            daemon.wait(3)
        child.terminate()
        child.wait(3)
        (args.out / 'observations.json').write_text(json.dumps(rows, indent=2) + '\n')
    result = {'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(), 'observations': len(rows)}
    if args.reference:
        reference = json.loads(args.reference.read_text())
        assert len(reference) == len(rows)
        result['differences'] = [{'expected': a, 'actual': b} for a, b in zip(reference, rows) if a != b]
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return bool(result.get('differences'))

if __name__ == '__main__':
    raise SystemExit(main())
