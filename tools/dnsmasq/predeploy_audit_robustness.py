#!/usr/bin/env python3
"""Bounded actual-config DNS/DHCP packet audit in disposable namespaces.

Run after actual_config_network.py -> actual_config_rootfs.py. The unchanged
captured config and exact image ELF are inputs; all raw evidence stays private.
This is a deterministic boundary corpus, not exhaustive fuzzing or a DoS test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import shutil
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

from actual_config_e2e import dhcp_request, receive_dhcp
from dns_service_probe import exact_read, name, query
from m2_rootfs import image_elf_command


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def dns_cases():
    base = query('robustness-audit.lan', 1, 0xA055)
    rows = [('valid-a', base), ('valid-aaaa', query('robustness-audit.lan', 28, 0xA055))]
    rows += [('prefix-%d' % n, base[:n]) for n in range(len(base))]
    for offset in (2, 4, 6, 8, 10):
        for value in (0, 1, 2, 255, 65535):
            rows.append(('header-%d-%d' % (offset, value), base[:offset] + struct.pack('!H', value) + base[offset + 2:]))
    for label, wire in [('pointer-self', b'\xc0\x0c'), ('pointer-outside', b'\xff\xff'),
                        ('pointer-header', b'\xc0\x00'), ('label-short', b'\x3fx'),
                        ('label-type-64', b'\x40x'), ('label-type-128', b'\x80x'),
                        ('root', b'\0'), ('empty-label', b'\x01a\0'),
                        ('max-label', bytes([63]) + b'a' * 63 + name('lan')),
                        ('long-name', b''.join(bytes([63]) + b'a' * 63 for _ in range(4)) + b'\0')]:
        rows.append((label, base[:12] + wire + b'\0\1\0\1'))
    for size in (0, 1, 511, 512, 1232, 4096, 65535):
        opt = b'\0' + struct.pack('!HHIH', 41, size, 0, 0)
        rows.append(('edns-size-%d' % size, base[:10] + b'\0\1' + base[12:] + opt))
    for length, payload in ((1, b''), (4, b'\0'), (65535, b''), (4, b'\0\15\0\0'), (4, b'\0\15\xff\xff')):
        rows.append(('edns-tlv-%d-%s' % (length, payload.hex()), base[:10] + b'\0\1' + base[12:] + b'\0' + struct.pack('!HHIH', 41, 1232, 0, length) + payload))
    for size in (511, 512, 1231, 1232, 1233, 4096, 65507):
        rows.append(('padded-%d' % size, base + b'\0' * (size - len(base))))
    rng = random.Random(0xA20261014)
    for index in range(64):
        packet = bytearray(base)
        for _ in range(1 + index % 4):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        rows.append(('mutated-%02d' % index, bytes(packet)))
    return rows


def dns_exchange(server, packet, tcp=False, timeout=.16):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(timeout)
            endpoint.connect((server, 53))
            if tcp:
                endpoint.sendall(struct.pack('!H', len(packet)) + packet)
                reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
            else:
                endpoint.send(packet)
                reply = endpoint.recv(65535)
            return {'reply_hex': reply.hex()}
    except socket.timeout:
        return {'outcome': 'timeout'}
    except (OSError, ConnectionError) as error:
        return {'outcome': type(error).__name__}


def dhcp_cases():
    base = dhcp_request(8, 0xA0550001, bytes.fromhex('02000000ab01'), 'robustness-client')
    # DHCPINFORM doesn't reserve addresses or spend seconds probing new leases.
    rows = [('prefix-%d' % size, base[:size]) for size in (0, 1, 27, 44, 107, 235, 236, 239, 240, 241, 242)]
    for offset, values in ((0, (0, 2, 255)), (1, (0, 255)), (2, (0, 16, 17, 255))):
        for value in values:
            packet = bytearray(base)
            packet[offset] = value
            rows.append(('header-%d-%d' % (offset, value), bytes(packet)))
    for label, options in [('valid-inform', b'\x35\x01\x08\xff'),
                           ('truncated-type', b'\x35\xff\x08'),
                           ('empty-type', b'\x35\0\xff'),
                           ('overrun-host', b'\x35\1\x08\x0c\xffx'),
                           ('empty-prl', b'\x35\1\x08\x37\0\xff'),
                           ('empty-client-id', b'\x35\1\x08\x3d\0\xff'),
                           ('short-fqdn', b'\x35\1\x08\x51\2\4\0\xff'),
                           ('truncated-fqdn-label', b'\x35\1\x08\x51\5\4\0\0\x3fX\xff'),
                           ('overload-file', b'\x35\1\x08\x34\1\1\xff'),
                           ('overload-both', b'\x35\1\x08\x34\1\3\xff'),
                           ('unknown-type', b'\x35\1\xff\xff')]:
        rows.append((label, base[:240] + options))
    return rows


def client(args):
    args.out.mkdir(parents=True)
    results = {'dns': [], 'health': [], 'dhcp': [], 'errors': []}
    healthy = query('robustness-audit.lan', 1, 0xA055)
    corpus = dns_cases()
    if args.quick:
        corpus = [row for row in corpus if row[0] in ('valid-a', 'valid-aaaa', 'padded-4096', 'padded-65507')]
    for tcp in (False, True):
        for index, (label, packet) in enumerate(corpus):
            row = {'case': label, 'tcp': tcp, 'length': len(packet), **dns_exchange(args.server, packet, tcp)}
            (args.out / ('dns-%s-%03d.request' % ('tcp' if tcp else 'udp', index))).write_bytes(packet)
            results['dns'].append(row)
            if index % 20 == 0:
                result = dns_exchange(args.server, healthy, timeout=2)
                results['health'].append({'after': label, 'tcp_corpus': tcp, **result})
                if 'reply_hex' not in result:
                    results['errors'].append('UDP health failed after ' + label)
                    save(args.out / 'result.json', results)
                    return 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, 25, b'client0\0')
        endpoint.bind(('0.0.0.0', 68))
        endpoint.settimeout(.15)
        dhcp_corpus = [] if args.quick else dhcp_cases()
        for index, (label, value) in enumerate(dhcp_corpus):
            packet = bytearray(value)
            if len(packet) >= 16:
                packet[12:16] = socket.inet_aton(args.address)
            if len(packet) >= 8:
                packet[4:8] = struct.pack('!I', 0xA0550000 + index)
            (args.out / ('dhcp-%03d.request' % index)).write_bytes(packet)
            endpoint.sendto(packet, ('255.255.255.255', 67))
            response = None
            try:
                while True:
                    reply = endpoint.recv(65535)
                    if len(packet) >= 8 and reply[4:8] == packet[4:8]:
                        response = reply.hex()
                        break
            except socket.timeout:
                pass
            results['dhcp'].append({'case': label, 'length': len(packet), 'reply_hex': response})
        # A complete DORA verifies that malformed DHCP hasn't stopped allocation.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
            raw.bind(('client0', 0))
            offered = server = None
            for kind in (1, 3):
                xid = 0xA0551000 + kind
                packet = dhcp_request(kind, xid, bytes.fromhex('02000000ab99'), 'audit-robustness', offered, server)
                endpoint.sendto(packet, ('255.255.255.255', 67))
                reply, _, _ = receive_dhcp(raw, xid)
                offered = socket.inet_ntoa(reply[16:20])
                from dhcp_boot_service_diff import options
                lookup = dict(options(reply))
                server = socket.inet_ntoa(bytes.fromhex(lookup[54]))
                results['health'].append({'dhcp_type': kind, 'reply_type': int(lookup[53], 16), 'reply_hex': reply.hex()})
                if int(lookup[53], 16) != {1: 2, 3: 5}[kind]:
                    results['errors'].append('DORA health reply mismatch')
    for tcp in (False, True):
        result = dns_exchange(args.server, healthy, tcp, 2)
        results['health'].append({'final_tcp': tcp, **result})
        if 'reply_hex' not in result:
            results['errors'].append('final DNS health failed')
    save(args.out / 'result.json', results)
    return bool(results['errors'])


def audit(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    # Immutable files were omitted from the captured runtime. Restore exact
    # image defaults only inside actual_config_rootfs's private /etc mount.
    for filename in ('passwd', 'group', 'hosts', 'ethers'):
        destination = Path('/etc') / filename
        if not destination.exists():
            shutil.copy2(args.image_root / 'etc' / filename, destination)
    client_pid = os.environ['DNSMASQ_CLIENT_PID']
    router = os.environ['DNSMASQ_ROUTER_ADDRESS']
    address = router.rsplit('.', 1)[0] + '.2'
    subprocess.run(['nsenter', '-t', client_pid, '-n', 'ip', 'addr', 'add', address + '/24', 'dev', 'client0'], check=True)
    from ubus_contract_diff import Fixture
    busout = args.out / 'ubus'
    busout.mkdir()
    bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), busout)
    bus.start_bus()
    result = {'errors': [], 'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest(),
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'quick': args.quick,
              'immutable_sha256': {filename: hashlib.sha256((Path('/etc') / filename).read_bytes()).hexdigest()
                                   for filename in ('passwd', 'group', 'hosts', 'ethers')}}
    daemon = None
    try:
        command = image_elf_command(args.image_root, args.binary) if args.image_root else [str(args.binary)]
        with (args.out / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(command + ['-C', str(args.config), '-k', '-x', '/var/run/dnsmasq/robustness.pid'], stdout=log, stderr=log)
            deadline = time.monotonic() + 10
            while True:
                assert daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed'
                if 'reply_hex' in dns_exchange(router, query('robustness-audit.lan', 1), timeout=.1):
                    break
                time.sleep(.03)
            proc = subprocess.run(['nsenter', '-t', client_pid, '-n', sys.executable, str(Path(__file__).resolve()),
                '--mode', 'client', '--out', str(args.out / 'client'), '--server', router, '--address', address]
                + (['--quick'] if args.quick else []),
                capture_output=True, text=True, timeout=180)
            save(args.out / 'client-process.json', {'exit': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr})
            result['daemon_alive_after_corpus'] = daemon.poll() is None
            if (args.out / 'client/result.json').exists():
                result['client'] = json.loads((args.out / 'client/result.json').read_text())
            if proc.returncode:
                result['errors'].append('client failed; see private client-process.json')
    except Exception as error:
        result['errors'].append(repr(error))
    finally:
        if daemon and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()
                result['errors'].append('shutdown required SIGKILL')
        result['daemon_exit'] = daemon.returncode if daemon else None
        bus.close()
        result['ubus_checks'] = bus.checks
        save(args.out / 'result.json', result)
    print(json.dumps({'errors': result['errors'], 'daemon_alive_after_corpus': result.get('daemon_alive_after_corpus'),
                      'daemon_exit': result['daemon_exit']}))
    return bool(result['errors'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['audit', 'client'], default='audit')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--reference-build', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--quick', action='store_true', help='two DNS health queries and both oversized TCP controls, followed by DORA')
    parser.add_argument('--server')
    parser.add_argument('--address')
    parser.add_argument('--config', type=Path, default=Path('/var/etc/dnsmasq.conf.cfg01411c'))
    args = parser.parse_args()
    return {'audit': audit, 'client': client}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
