#!/usr/bin/env python3
"""Independent bounded TFTP service comparison in a private Linux namespace.

Exact image C runs using the image's musl loader. This exercises complete
transfers, negotiation, retry, parsing/error boundaries and single-port mode;
it is not a performance, exhaustive fault-injection or router qualification.
Raw files, wire and logs stay under --out private/. --report is derived data.
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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cases():
    for size in [0, 17, 512, 513, 4097]:
        yield dict(name=f'octet-{size}', data=bytes(range(256)) * (size // 256) + bytes(range(size % 256)))
    yield dict(name='netascii-multiblock', data=(b'abc\nDEF\r\n\nxyz\r' * 100), mode='netascii')
    yield dict(name='netascii-one-byte-block', data=b'\nA\n\nB\r', mode='netascii', options=[('blksize', '1')])
    yield dict(name='window4-multiblock', data=bytes(range(256)) * 3 + b'end', options=[('blksize', '32'), ('windowsize', '4')])
    yield dict(name='window32-multiblock', data=bytes(range(256)) * 20 + b'end', options=[('blksize', '128'), ('windowsize', '32')])
    yield dict(name='all-options', data=b'a' * 1201, options=[('timeout', '1'), ('tsize', '0'), ('windowsize', '4'), ('blksize', '64')])
    yield dict(name='unknown-option', data=b'content', options=[('unknown', '77')])
    yield dict(name='case-insensitive-options', data=b'content', mode='OcTeT', options=[('BlKsIzE', '3'), ('TSIZE', '0')])
    yield dict(name='netascii-ignored-tsize-window', data=b'a\nb\n', mode='netascii', options=[('tsize', '0'), ('windowsize', '4')])
    yield dict(name='retry-first-data', data=b'retransmit-me', retry=True, options=[('timeout', '1')])
    yield dict(name='single-port-window', data=b'A' * 1025, single=True, wildcard=True, options=[('blksize', '128'), ('windowsize', '4')])
    yield dict(name='bound-ipv4-single-port', data=b'A' * 1025, single=True, options=[('blksize', '128'), ('windowsize', '4')])
    yield dict(name='ipv6-octet', data=b'IPv6\0content', ipv6=True)
    yield dict(name='ipv6-single-port', data=b'IPv6 single port', ipv6=True, single=True)
    yield dict(name='missing-file', filename='missing.bin', error=1)
    yield dict(name='parent-traversal', filename='../outside.bin', error=2)
    yield dict(name='write-request', raw=b'\0\2', error=4)
    yield dict(name='invalid-mode', mode='unknown', data=b'content', error=4)
    yield dict(name='short-request', raw=b'\0', silent=True)
    yield dict(name='empty-filename', raw=b'\0\1\0octet\0', error=4)


def request(case):
    if 'raw' in case:
        return case['raw']
    data = b'\0\1' + case.get('filename', 'payload.bin').encode() + b'\0'
    data += case.get('mode', 'octet').encode() + b'\0'
    for name, value in case.get('options', []):
        data += name.encode() + b'\0' + value.encode() + b'\0'
    return data


def transfer(case, out):
    family = socket.AF_INET6 if case.get('ipv6') else socket.AF_INET
    address = '::1' if case.get('ipv6') else '127.0.0.1'
    summary = {'oack': None, 'blocks': [], 'retransmitted_blocks': [], 'server_single_port': None}
    content = bytearray()
    block_size, window_size = 512, 1
    next_block = 1
    dropped = False
    transcript = []
    with socket.socket(family, socket.SOCK_DGRAM) as endpoint:
        endpoint.bind((address, 0))
        endpoint.settimeout(3)
        data = request(case)
        (out / 'request.bin').write_bytes(data)
        endpoint.sendto(data, (address, 69))
        peer = None
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                try:
                    packet, origin = endpoint.recvfrom(65535)
                except TimeoutError:
                    if case.get('silent') and not transcript:
                        summary['silent'] = True
                        break
                    raise
                transcript.append(packet.hex())
                if peer is None:
                    peer = origin
                    summary['server_single_port'] = peer[1] == 69
                assert origin == peer, 'server TID changed during transfer'
                assert len(packet) >= 2
                opcode = struct.unpack('!H', packet[:2])[0]
                if opcode == 5:
                    summary['error_code'] = struct.unpack('!H', packet[2:4])[0]
                    summary['error_message'] = packet[4:].rstrip(b'\0').decode(errors='backslashreplace').replace(str(out / 'files'), '<ROOT>')
                    break
                if opcode == 6:
                    fields = packet[2:].rstrip(b'\0').split(b'\0')
                    assert len(fields) % 2 == 0
                    negotiated = [(fields[i].decode(), fields[i + 1].decode()) for i in range(0, len(fields), 2)]
                    summary['oack'] = negotiated
                    options = dict(negotiated)
                    block_size = int(options.get('blksize', 512))
                    window_size = int(options.get('windowsize', 1))
                    endpoint.sendto(b'\0\4\0\0', peer)
                    continue
                assert opcode == 3 and len(packet) >= 4, f'unexpected TFTP opcode {opcode}'
                number = struct.unpack('!H', packet[2:4])[0]
                if case.get('retry') and not dropped:
                    dropped = True
                    summary['retransmitted_blocks'].append(number)
                    continue
                if number < next_block:
                    summary['retransmitted_blocks'].append(number)
                    endpoint.sendto(struct.pack('!HH', 4, number), peer)
                    if len(summary['retransmitted_blocks']) >= 4:
                        summary['stalled_on_duplicate_data'] = True
                        break
                    continue
                assert number == next_block, f'expected DATA {next_block}, got {number}'
                payload = packet[4:]
                summary['blocks'].append({'number': number, 'length': len(payload)})
                content.extend(payload)
                next_block += 1
                final = len(payload) < block_size
                if final or number % window_size == 0:
                    endpoint.sendto(struct.pack('!HH', 4, number), peer)
                if final:
                    summary['complete'] = True
                    break
            else:
                raise TimeoutError('15 second transfer deadline')
        finally:
            (out / 'wire.json').write_text(json.dumps(transcript, indent=2) + '\n')
            (out / 'received.bin').write_bytes(content)
    if summary.get('complete'):
        summary['bytes'] = len(content)
        summary['sha256'] = digest(content)
        expected = case.get('data', b'')
        if case.get('mode', '').lower() == 'netascii':
            expected = expected.replace(b'\n', b'\r\n')
        summary['content_correct'] = bytes(content) == expected
        assert summary['content_correct'], 'file content differs'
    if 'error' in case:
        assert summary.get('error_code') == case['error'], 'wrong error code'
    elif case.get('silent'):
        assert summary.get('silent'), 'short request unexpectedly answered'
    else:
        assert summary.get('complete'), 'transfer did not finish'
    if not case.get('silent'):
        assert summary['server_single_port'] == bool(case.get('single')), 'wrong transfer port mode'
    return summary


def execute(binary, case, out):
    out.mkdir()
    files = out / 'files'
    files.mkdir()
    (files / 'payload.bin').write_bytes(case.get('data', b''))
    (files / 'payload.bin').chmod(0o644)
    (out / 'outside.bin').write_bytes(b'outside-secret-fixture')
    (out / 'outside.bin').chmod(0o644)
    config = out / 'dnsmasq.conf'
    config.write_text('no-resolv\nno-hosts\nport=15353\nlisten-address=127.0.0.1,::1\n'
                      'user=root\ngroup=root\nenable-tftp\n'
                      + ('' if case.get('wildcard') else 'bind-interfaces\n')
                      +
                      f'tftp-root={files}\npid-file={out / "pid"}\n'
                      f'log-facility={out / "service.log"}\n'
                      + ('tftp-single-port\n' if case.get('single') else ''))
    result = {}
    with (out / 'stdio.log').open('w') as log:
        process = subprocess.Popen(binary + ['-k', '-C', str(config)], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError('startup failed: ' + (out / 'stdio.log').read_text())
                try:
                    with socket.create_connection(('127.0.0.1', 15353), .05):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('readiness timeout')
                    time.sleep(.02)
            try:
                result = transfer(case, out)
                result['verified'] = True
            except Exception as error:
                observed = []
                for data in json.loads((out / 'wire.json').read_text()):
                    packet = bytes.fromhex(data)
                    opcode = struct.unpack('!H', packet[:2])[0]
                    row = {'opcode': opcode}
                    if opcode == 3:
                        row.update(block=struct.unpack('!H', packet[2:4])[0], bytes=len(packet) - 4, sha256=digest(packet[4:]))
                    if opcode == 6:
                        row['options'] = packet[2:].rstrip(b'\0').decode().split('\0')
                    observed.append(row)
                result = {'verified': False, 'exception': repr(error), 'packet_observations': observed,
                          'received_bytes': (out / 'received.bin').stat().st_size, 'received_sha256': sha(out / 'received.bin')}
            process.send_signal(signal.SIGTERM)
            result['exit'] = process.wait(5)
            log_text = (out / 'service.log').read_text(errors='replace') if (out / 'service.log').exists() else ''
            result['send_failures'] = [line.split('failed to send packet:', 1)[1].strip() for line in log_text.splitlines() if 'failed to send packet:' in line]
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or os.geteuid() != 0:
        parser.error('root in run_isolated.sh required')
    out = args.out.resolve()
    if 'private' not in out.parts:
        parser.error('raw evidence must stay under private/')
    out.mkdir(parents=True, exist_ok=False)
    image = args.image_root.resolve()
    stock = image / 'usr/sbin/dnsmasq'
    assert sha(stock) == STOCK_SHA256
    c = [str(image / 'lib/ld-musl-aarch64.so.1'), '--library-path', f'{image}/lib:{image}/usr/lib', str(stock)]
    report = {'scope': 'isolated exact-image ELF/loader service comparison; synthetic loopback v4/v6',
              'source_commit': '3e7df6c1cc45b74f0430e5460379713900172cb4',
              'c_sha256': sha(stock), 'rust_sha256': sha(args.rust), 'tool_sha256': sha(__file__), 'cases': []}
    for case in cases():
        rows = {side: execute(binary, case, out / f'{case["name"]}-{side}')
                for side, binary in [('c', c), ('rust', image_elf_command(image, args.rust))]}
        report['cases'].append({'name': case['name'], **rows, 'match': rows['c'] == rows['rust']})
    report['case_count'] = len(report['cases'])
    report['matched'] = sum(row['match'] for row in report['cases'])
    report['all_verified'] = all(row[side].get('verified') for row in report['cases'] for side in ['c', 'rust'])
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
