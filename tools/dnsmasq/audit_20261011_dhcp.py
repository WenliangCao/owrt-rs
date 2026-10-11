#!/usr/bin/env python3
"""Independent DHCP audit reproductions; Linux private network namespace only.

Runs the exact-image C ELF through its matching musl loader and the supplied
Rust ELF. Fixtures use synthetic loopback clients. Raw config/wire/log/leases
stay in private output; --report writes only derived observations and hashes.
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
import time

from m2_rootfs import image_elf_command

STOCK_SHA256 = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def option(code, value):
    return bytes([code, len(value)]) + value


def packet(kind, xid, mac=1, rapid=False, wanted=True, name=None):
    data = bytearray(240)
    data[:4] = bytes([1, 1, 6, 0])
    data[4:8] = struct.pack('!I', xid)
    data[10:12] = b'\x80\x00'
    data[28:34] = bytes([2, 0, 0, 0, 0, mac])
    data[236:240] = bytes([99, 130, 83, 99])
    data += option(53, bytes([kind]))
    if wanted:
        data += option(50, socket.inet_aton('127.0.0.30'))
    if kind == 3:
        data += option(54, socket.inet_aton('127.0.0.1'))
    if rapid:
        data += option(80, b'')
    if name:
        data += option(12, name.encode())
    data += option(55, bytes([1, 3, 6, 12, 15, 51, 80]))
    return bytes(data) + b'\xff'


def decode(data):
    fields = {'yiaddr': socket.inet_ntoa(data[16:20]), 'options': {}}
    offset = 240
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        size = data[offset]
        offset += 1
        fields['options'][str(code)] = data[offset:offset + size].hex()
        offset += size
    fields['message_type'] = int(fields['options'].get('53', '0'), 16)
    fields['hostname'] = bytes.fromhex(fields['options'].get('12', '')).decode(errors='backslashreplace')
    return fields


def dns_answer(name, qtype):
    query = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    query += b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0'
    query += struct.pack('!HH', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(1)
        endpoint.sendto(query, ('127.0.0.1', 15353))
        raw = endpoint.recv(4096)
    def parse_name(pos):
        labels = []
        end = None
        while raw[pos]:
            if raw[pos] & 0xc0 == 0xc0:
                end = end or pos + 2
                pos = ((raw[pos] & 63) << 8) | raw[pos + 1]
            else:
                length = raw[pos]
                labels.append(raw[pos + 1:pos + 1 + length].decode(errors='replace'))
                pos += length + 1
        return '.'.join(labels), end or pos + 1
    _, offset = parse_name(12)
    offset += 4
    records = []
    for _ in range(struct.unpack('!H', raw[6:8])[0]):
        owner, offset = parse_name(offset)
        kind, cls, ttl, size = struct.unpack('!HHIH', raw[offset:offset + 10])
        offset += 10
        data = raw[offset:offset + size]
        value = socket.inet_ntoa(data) if kind == 1 else parse_name(offset)[0] if kind == 12 else data.hex()
        records.append({'name': owner, 'type': kind, 'value': value})
        offset += size
    return {'rcode': raw[3] & 15, 'answers': records}


def cases():
    yield {'name': 'multi-mac-static-handoff',
           'config': 'dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual\n',
           'events': [dict(kind=3), dict(kind=1, mac=2), dict(kind=3, mac=2), dict(kind=3, mac=2)]}
    for rapid in (False, True):
        yield {'name': 'hosts-authoritative-' + ('rapid' if rapid else 'request'),
               'config': 'addn-hosts={hosts}\n', 'hosts': '127.0.0.30 authoritative\n',
               'events': [dict(kind=1 if rapid else 3, rapid=rapid, name='claimed')]}
    for rapid in (False, True):
        yield {'name': 'client-hostname-' + ('rapid' if rapid else 'request'),
               'config': '', 'events': [dict(kind=1 if rapid else 3, rapid=rapid, name='claimed')]}
    for policy in ('ignore', 'generate'):
        for wanted in (False, True):
            config = ('dhcp-ignore-names=tag:pool\n' if policy == 'ignore'
                      else 'dhcp-generate-names=tag:pool\n')
            event = dict(kind=1, rapid=True, wanted=wanted)
            if policy == 'ignore':
                event['name'] = 'untrusted'
            yield {'name': f'rapid-range-{policy}-wanted-{str(wanted).lower()}',
                   'config': config, 'events': [event]}


def execute(binary, case, out):
    out.mkdir()
    leasefile = out / 'leases'
    hosts = out / 'hosts'
    hosts.write_text(case.get('hosts', ''))
    config = out / 'dnsmasq.conf'
    config.write_text('no-resolv\nno-hosts\nport=15353\nlisten-address=127.0.0.1\n'
                      'bind-interfaces\nuser=root\ngroup=root\nno-ping\ndhcp-authoritative\n'
                      'dhcp-rapid-commit\nlog-dhcp\n'
                      f'pid-file={out / "pid"}\nlog-facility={out / "service.log"}\n'
                      f'dhcp-leasefile={leasefile}\n'
                      'dhcp-range=set:pool,127.0.0.30,127.0.0.30,255.0.0.0,1h\n'
                      + case['config'].format(hosts=hosts))
    result = {'events': []}
    with (out / 'stdio.log').open('w') as log, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')
        client.bind(('0.0.0.0', 68))
        client.settimeout(1.0)
        process = subprocess.Popen(binary + ['-k', '-C', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError('daemon exited during startup: ' + (out / 'stdio.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', 15353), .05):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('daemon readiness timeout')
                    time.sleep(.02)
            for index, event in enumerate(case['events']):
                xid = 0xabc000 + index
                data = packet(xid=xid, **event)
                (out / f'{index}.request').write_bytes(data)
                client.sendto(data, ('255.255.255.255', 67))
                response = None
                until = time.monotonic() + 1
                while time.monotonic() < until:
                    try:
                        raw, peer = client.recvfrom(65535)
                    except TimeoutError:
                        break
                    if len(raw) >= 240 and struct.unpack('!I', raw[4:8])[0] == xid:
                        (out / f'{index}.reply').write_bytes(raw)
                        response = decode(raw)
                        break
                lease_lines = leasefile.read_text().splitlines() if leasefile.exists() else []
                result['events'].append({'input': event, 'reply': response,
                                         'leases': [line.split()[1:] for line in lease_lines],
                                         'daemon_alive': process.poll() is None})
            result['dns'] = {name: dns_answer(name, kind) for name, kind in
                             [('authoritative', 1), ('claimed', 1), ('untrusted', 1),
                              ('02-00-00-00-00-01', 1), ('30.0.0.127.in-addr.arpa', 12)]}
            process.send_signal(signal.SIGTERM)
            result['exit'] = process.wait(5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    logs = '\n'.join(path.read_text(errors='replace') for path in (out / 'service.log', out / 'stdio.log') if path.exists())
    result['state_error_lines'] = [line.split(': ', 1)[-1] for line in logs.splitlines() if 'AddressInUse' in line]
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rust', type=Path, required=True)
    p.add_argument('--image-root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--source-commit')
    args = p.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or os.geteuid() != 0:
        p.error('root in run_isolated.sh required')
    out = args.out.resolve()
    if 'private' not in out.parts:
        p.error('raw evidence must stay under private/')
    out.mkdir(parents=True, exist_ok=False)
    image = args.image_root.resolve()
    stock = image / 'usr/sbin/dnsmasq'
    assert sha(stock) == STOCK_SHA256
    loader = image / 'lib/ld-musl-aarch64.so.1'
    c = [str(loader), '--library-path', f'{image}/lib:{image}/usr/lib', str(stock)]
    report = {'scope': 'private net/mount/pid namespace; exact image C ELF and its musl loader; synthetic loopback DHCP clients',
              'source_commit': args.source_commit,
              'c_sha256': sha(stock), 'rust_sha256': sha(args.rust), 'tool_sha256': sha(__file__),
              'cases': [], 'matched': 0, 'failures': []}
    for case in cases():
        rows = {side: execute(binary, case, out / f'{case["name"]}-{side}')
                for side, binary in [('c', c), ('rust', image_elf_command(image, args.rust))]}
        matched = rows['c'] == rows['rust']
        healthy = all(row['exit'] == 0 and all(event['daemon_alive'] for event in row['events'])
                      for row in rows.values())
        report['cases'].append({'name': case['name'], 'matched': matched, **rows})
        report['matched'] += matched and healthy
        if not matched or not healthy:
            report['failures'].append(case['name'])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    if report['failures']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
