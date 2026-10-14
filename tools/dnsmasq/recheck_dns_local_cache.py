#!/usr/bin/env python3
"""Independent exact-image check of repaired local cache paths; isolated only.

Uses the original actual-config network/rootfs harness and upstream process
lifecycle. This file supplies its own packets, decoder, and test sequences.
Raw packets, runtime addresses and configs must remain in a private directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

import predeploy_audit_dns as harness


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def dnsname(value):
    return b''.join(bytes([len(x)]) + x.encode() for x in value.split('.') if x) + b'\0'


def decode(packet):
    def name(pos, seen=()):
        assert pos not in seen and len(seen) < 50
        labels = []
        while True:
            n = packet[pos]
            pos += 1
            if n == 0:
                return '.'.join(labels), pos
            if n & 192 == 192:
                suffix, _ = name(((n & 63) << 8) | packet[pos], seen + (pos - 1,))
                return '.'.join(labels + [suffix]), pos + 1
            assert not n & 192 and pos + n <= len(packet)
            labels.append(packet[pos:pos+n].decode('ascii'))
            pos += n
    ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    pos, questions, records = 12, [], []
    for _ in range(qd):
        owner, pos = name(pos)
        kind, cls = struct.unpack_from('!HH', packet, pos)
        pos += 4
        questions.append([owner, kind, cls])
    for section, count in [('answer', an), ('authority', ns), ('additional', ar)]:
        for _ in range(count):
            owner, pos = name(pos)
            kind, cls, ttl, size = struct.unpack_from('!HHIH', packet, pos)
            pos += 10
            end = pos + size
            assert end <= len(packet)
            data = name(pos)[0] if kind in (2, 5, 12) else packet[pos:end].hex()
            records.append(dict(section=section, owner=owner, type=kind, cls=cls, ttl=ttl, data=data))
            pos = end
    assert pos == len(packet), (pos, len(packet))
    return dict(id=ident, flags=flags, questions=questions, records=records)


def response(packet, host, kind, action, tcp):
    # Names encode every input; no private runtime name is exported.
    qend = 12 + len(dnsname(host)) + 4
    question = packet[12:qend]
    parts = host.split('.')
    if host.startswith('a-'):
        key = parts[0][2:]
        terminal_kind = key.split('-')[0]
        terminal = 't-' + key + ('.lan' if terminal_kind == 'lan' else '.invalid' if terminal_kind == 'invalid' else '')
        owners = [host]
        if '-chain-' in host:
            owners += ['m1-' + key + '.audit.example', 'm2-' + key + '.audit.example']
        owners += [terminal]
        ttl = 2 if '-expire-' in host else 300
        records = b''
        count = len(owners) - 1
        for first, second in zip(owners, owners[1:]):
            data = dnsname(second)
            records += dnsname(first) + struct.pack('!HHIH', 5, 1, ttl, len(data)) + data
        if kind in (1, 28):
            data = socket.inet_aton('8.8.4.4') if kind == 1 else socket.inet_pton(socket.AF_INET6, '2001:4860:4860::8844')
            records += dnsname(terminal) + struct.pack('!HHIH', kind, 1, ttl, len(data)) + data
            count += 1
    else:
        records, count = b'', 0
    return packet[:2] + struct.pack('!5H', 0x8180 | (int.from_bytes(packet[2:4], 'big') & 0x10), 1, count, 0, 0) + question + records


def client(args):
    args.out.mkdir(exist_ok=True)
    rows, ident = [], 1000
    def exchange(label, host, kind, tcp, flags=0x100, edns=0, stream=None):
        nonlocal ident
        ident += 1
        packet = struct.pack('!6H', ident, flags, 1, 0, 0, int(bool(edns))) + dnsname(host) + struct.pack('!HH', kind, 1)
        if edns:
            packet += b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000 if edns == 2 else 0, 0)
        row = dict(label=label, host=host, kind=kind, tcp=tcp, flags=flags, edns=edns, sent=time.time())
        prefix = args.out / str(ident)
        prefix.with_suffix('.request').write_bytes(packet)
        own = stream is None
        try:
            if own:
                stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                stream.settimeout(2)
                stream.connect((args.server, 53))
            if tcp:
                stream.sendall(struct.pack('!H', len(packet)) + packet)
                reply = harness.exact_read(stream, struct.unpack('!H', harness.exact_read(stream, 2))[0])
            else:
                stream.send(packet)
                reply = stream.recv(65535)
            prefix.with_suffix('.reply').write_bytes(reply)
            row['response'] = decode(reply)
            assert row['response']['id'] == ident
            assert row['response']['questions'] == [[host, kind, 1]]
        except (OSError, ConnectionError) as error:
            row['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            if own and stream:
                stream.close()
        row['received'] = time.time()
        rows.append(row)
        save(args.out / 'result.json', rows)
    def names(key):
        suffix = '.lan' if key.startswith('lan-') else '.invalid' if key.startswith('invalid-') else ''
        return 'a-' + key + '.audit.example', 't-' + key + suffix
    for domain in ('lan', 'invalid', 'dotless'):
        for warm_tcp in (False, True):
            for warm_kind in (1, 28):
                key = f'{domain}-chain-{int(warm_tcp)}-{warm_kind}'
                alias, terminal = names(key)
                retained = socket.create_connection((args.server, 53), 2) if warm_tcp else None
                try:
                    exchange(key + '-warm', alias, warm_kind, warm_tcp, stream=retained)
                    for kind in (1, 28, 5, 16, 255, 6, 65):
                        for tcp in (False, True):
                            exchange(key + '-direct', terminal, kind, tcp)
                        # Same-session and freshly accepted TCP cursor, including RD=0,
                        # CD, EDNS and DO. Each upstream observation remains retained.
                        for flags, edns in ((0x100, 0), (0, 0), (0x110, 1), (0x100, 2)):
                            exchange(key + '-alias', alias, kind, True, flags, edns, retained)
                finally:
                    if retained:
                        retained.close()
    # Warm all short-lived entries together, wait past TTL, then compare the
    # retained TCP child's accepted clock against current UDP/new TCP views.
    retained_list = []
    for domain in ('lan', 'invalid', 'dotless'):
        alias, terminal = names(domain + '-expire-1')
        stream = socket.create_connection((args.server, 53), 2)
        retained_list.append((alias, terminal, stream))
        exchange(domain + '-expire-warm', alias, 1, True, stream=stream)
    time.sleep(3.1)
    for alias, terminal, stream in retained_list:
        for target in (terminal, alias):
            exchange('expired-retained', target, 1, True, stream=stream)
            for tcp in (False, True):
                exchange('expired-current', target, 1, tcp)
        stream.close()
    for domain in ('lan', 'invalid', 'dotless'):
        alias, terminal = names(domain + '-hup-1')
        with socket.create_connection((args.server, 53), 2) as stream:
            exchange(domain + '-hup-warm', alias, 1, True, stream=stream)
            os.kill(args.daemon_pid, signal.SIGHUP)
            time.sleep(.15)
            for target in (terminal, alias):
                exchange('hup-retained', target, 28, True, stream=stream)
                for tcp in (False, True):
                    exchange('hup-current', target, 28, tcp)


def run(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    for filename in ('passwd', 'group', 'hosts', 'ethers'):
        destination, source = Path('/etc') / filename, args.image_root / 'etc' / filename
        if not destination.exists() and source.exists():
            shutil.copy2(source, destination)
    client_pid, upstream_pid = os.environ['DNSMASQ_CLIENT_PID'], os.environ['DNSMASQ_UPSTREAM_PID']
    router = os.environ['DNSMASQ_ROUTER_ADDRESS']
    subprocess.run(['nsenter', '-t', client_pid, '-n', 'ip', 'addr', 'add', router.rsplit('.', 1)[0] + '.2/24', 'dev', 'client0'], check=True)
    from ubus_contract_diff import Fixture
    (args.out / 'ubus').mkdir()
    bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), args.out / 'ubus')
    bus.start_bus()
    state = args.out / 'state.json'
    save(state, dict(stage='recheck', delay=.001))
    script = str(Path(__file__).resolve())
    command = [str(args.binary), '-k', '-C', str(args.config), '-x', '/var/run/dnsmasq/recheck.pid']
    if args.image_elf:
        from m2_rootfs import image_elf_command
        command = image_elf_command(args.image_root, args.binary) + command[1:]
    children, logs = [], []
    result = dict(binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), config_sha256=hashlib.sha256(args.config.read_bytes()).hexdigest(), tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), errors=[])
    try:
        for label, argv in [('upstream', ['nsenter', '-t', upstream_pid, '-n', sys.executable, script, '--mode', 'upstream', '--out', str(args.out / 'upstream'), '--state', str(state), '--resolv', str(args.resolv)]), ('daemon', command)]:
            if label == 'daemon':
                deadline = time.monotonic() + 5
                while not (args.out / 'upstream/ready.json').exists():
                    assert time.monotonic() < deadline and children[0].poll() is None
                    time.sleep(.02)
            log = (args.out / (label + '.log')).open('wb')
            logs.append(log)
            children.append(subprocess.Popen(argv, stdout=log, stderr=log))
        deadline = time.monotonic() + 5
        while True:
            assert children[-1].poll() is None and time.monotonic() < deadline
            try:
                with socket.create_connection((router, 53), .1):
                    break
            except OSError:
                time.sleep(.02)
        process = subprocess.run(['nsenter', '-t', client_pid, '-n', sys.executable, script, '--mode', 'client', '--server', router, '--daemon-pid', str(children[-1].pid), '--out', str(args.out / 'client')], capture_output=True, text=True, timeout=180)
        save(args.out / 'client-process.json', dict(exit=process.returncode, stdout=process.stdout, stderr=process.stderr))
        process.check_returncode()
        assert children[-1].poll() is None
    except Exception as error:
        result['errors'].append(repr(error))
    finally:
        for process in reversed(children):
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                result['errors'].append('shutdown required SIGKILL')
        result['process_exits'] = [p.returncode for p in children]
        for log in logs:
            log.close()
        bus.close()
        result['ubus_checks'] = bus.checks
        save(args.out / 'result.json', result)
    return bool(result['errors'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['audit', 'client', 'upstream'], default='audit')
    for key in ('binary', 'image-root', 'reference-build', 'out', 'state'):
        p.add_argument('--' + key, type=Path)
    p.add_argument('--config', type=Path, default=Path('/var/etc/dnsmasq.conf.cfg01411c'))
    p.add_argument('--resolv', type=Path, default=Path('/tmp/resolv.conf.d/resolv.conf.auto'))
    p.add_argument('--server')
    p.add_argument('--daemon-pid', type=int)
    p.add_argument('--image-elf', action='store_true')
    args = p.parse_args()
    harness.response = response
    return {'audit': run, 'client': client, 'upstream': harness.upstream}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
