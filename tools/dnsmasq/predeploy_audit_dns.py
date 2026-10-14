#!/usr/bin/env python3
"""Independent DNS audit under actual_config_network/rootfs (never a router).

The captured config is read unchanged. Four controlled upstreams replace only
the external DNS network, and synthetic LAN IPv6 addresses permit IPv6 clients.
All raw packets and runtime addresses remain in ignored private output.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

from dns_service_probe import exact_read, name, query, read_name, rr, semantics


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def response(packet, host, kind, action, tcp):
    _, end = read_name(packet, 12)
    question = packet[12:end + 4]
    flags, answers, authority, additional, body = 0x8180, 1, 0, 0, b''
    flags |= struct.unpack_from('!H', packet, 2)[0] & 0x10
    if action in ('servfail', 'refused'):
        flags |= 2 if action == 'servfail' else 5
        answers = 0
    elif host.startswith(('nx.', 'nodata.')):
        flags |= 3 if host.startswith('nx.') else 0
        answers, authority = 0, 1
        soa = name('ns.audit.example') + name('admin.audit.example') + struct.pack('!5I', 1, 60, 60, 600, 30)
        body = rr(6, soa, 30, name('audit.example'))
    elif host.startswith('truncated.') and not tcp:
        flags |= 0x200
        answers = 0
    elif host.startswith(('local-chain.', 'local-chain-invalid.', 'local-chain-dotless.')):
        target = 'audit-terminal.lan'
        if host.startswith('local-chain-dotless.'):
            target = 'auditdotless'
        if host.startswith('local-chain-invalid.'):
            target = 'audit-terminal.invalid'
        elif '.outage.' in host:
            target = 'audit-outage-terminal.lan'
        elif '.udp.' in host:
            target = 'audit-udp-terminal.lan'
        elif '.fresh.' in host:
            target = 'audit-fresh-terminal.lan'
        data = {1: socket.inet_aton('8.8.4.4'), 28: socket.inet_pton(socket.AF_INET6, '2001:4860:4860::8844'), 16: b'\x05hello'}
        terminal_kind = kind if kind in data else 1
        answers = 2
        body = rr(5, name(target)) + rr(terminal_kind, data[terminal_kind], owner=name(target))
    elif host.startswith('cname.'):
        answers = 2
        address = socket.inet_pton(socket.AF_INET6, '2001:4860:4860::8844') if kind == 28 else socket.inet_aton('8.8.4.4')
        body = rr(5, name('target.audit.example')) + rr(kind, address, owner=name('target.audit.example'))
    elif kind == 1:
        address = '192.168.88.9' if host.startswith('rebind.') else ('127.0.0.9' if host.startswith('localhost-rebind.') else '8.8.4.4')
        body = rr(1, socket.inet_aton(address), 2 if host.startswith('expiry.') else 120)
    elif kind == 28:
        address = 'fd43:ba17::99' if host.startswith('rebind6.') else ('::1' if host.startswith('localhost-rebind6.') else '2001:4860:4860::8844')
        body = rr(28, socket.inet_pton(socket.AF_INET6, address))
    elif kind == 16:
        large = host.startswith(('large.', 'large-noedns.'))
        text = b'x' * 200 if large else b'audit-text'
        count = 4 if large else 1
        answers = count
        body = b''.join(rr(16, bytes([len(text)]) + text) for _ in range(count))
    elif kind == 65:
        body = rr(65, b'\x00\x01\x00\x00\x01\x00\x03\x02h2')
    else:
        answers = 0
    if host.startswith('ad.'):
        flags |= 0x20
    if struct.unpack_from('!H', packet, 10)[0] and action not in ('servfail', 'refused'):
        additional = 1
        body += b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0)
    return packet[:2] + struct.pack('!5H', flags, 1, answers, authority, additional) + question + body


def upstream(args):
    args.out.mkdir(parents=True)
    addresses = [line.split()[1] for line in args.resolv.read_text().splitlines() if line.split()[:1] == ['nameserver']]
    lock = threading.Lock()
    sockets, errors = [], []
    counter = 0

    def handle(index, packet, peer, tcp):
        nonlocal counter
        host, end = read_name(packet, 12)
        kind = struct.unpack_from('!H', packet, end)[0]
        state = json.loads(args.state.read_text())
        action = state.get('actions', {}).get(str(index), 'answer')
        with lock:
            counter += 1
            seq = counter
            row = {'seq': seq, 'host': host, 'type': kind, 'upstream': index, 'family': ipaddress.ip_address(addresses[index]).version,
                   'tcp': tcp, 'action': action, 'stage': state['stage'], 'time': time.time()}
            with (args.out / 'queries.jsonl').open('a') as out:
                out.write(json.dumps(row) + '\n')
            (args.out / f'{seq:05}.request').write_bytes(packet)
        # Stable endpoint preference and error-before-good timing reduce races
        # when comparing two separate service runs. The raw arrival log remains
        # authoritative; timing alone is never counted as semantic equivalence.
        delay = state.get('delay', .01) * (index + 1)
        if action in ('servfail', 'refused'):
            delay = .001
        if delay:
            time.sleep(delay)
        if action == 'drop':
            return None
        if action == 'tcp-close':
            return b''
        result = response(packet, host, kind, action, tcp)
        (args.out / f'{seq:05}.reply').write_bytes(result)
        return result

    def udp_loop(index, endpoint):
        while True:
            packet, peer = endpoint.recvfrom(65535)
            try:
                result = handle(index, packet, peer, False)
                if result is not None:
                    endpoint.sendto(result, peer)
            except Exception as error:
                errors.append(repr(error))
                save(args.out / 'errors.json', errors)

    def tcp_session(index, conn):
        try:
            with conn:
                conn.settimeout(20)
                while True:
                    packet = exact_read(conn, struct.unpack('!H', exact_read(conn, 2))[0])
                    result = handle(index, packet, conn.getpeername(), True)
                    if result == b'':
                        return
                    if result is not None:
                        conn.sendall(struct.pack('!H', len(result)) + result)
        except (OSError, ConnectionError):
            pass
        except Exception as error:
            errors.append(repr(error))
            save(args.out / 'errors.json', errors)

    def tcp_loop(index, endpoint):
        while True:
            conn, _ = endpoint.accept()
            threading.Thread(target=tcp_session, args=(index, conn), daemon=True).start()

    for index, address in enumerate(addresses):
        for tcp in (False, True):
            endpoint = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                                     socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            endpoint.bind((address, 53))
            if tcp:
                endpoint.listen(64)
            sockets.append(endpoint)
            threading.Thread(target=tcp_loop if tcp else udp_loop, args=(index, endpoint), daemon=True).start()
    save(args.out / 'ready.json', {'upstreams': len(addresses), 'transports': ['udp', 'tcp']})
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        signal.pause()


def one_exchange(spec, out, index=0):
    host, kind = spec['host'], spec.get('type', 1)
    packet = query(host, kind, spec.get('id', 0x4100) + index)
    flags = spec.get('flags', 0x100)
    packet = packet[:2] + struct.pack('!H', flags) + packet[4:]
    if spec.get('edns'):
        packet = packet[:10] + b'\0\1' + packet[12:] + b'\0' + struct.pack('!HHIH', 41, spec['edns'], spec.get('do', 0) * 0x8000, 0)
    result = {'host': host, 'type': kind, 'tcp': spec.get('tcp', False), 'ipv6': spec.get('ipv6', False)}
    if spec.get('raw_hex'):
        packet = bytes.fromhex(spec['raw_hex'])
    (out / f'{index}.request').write_bytes(packet)
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET6 if spec.get('ipv6') else socket.AF_INET,
                           socket.SOCK_STREAM if spec.get('tcp') else socket.SOCK_DGRAM) as endpoint:
            timeout = spec.get('timeout', 3)
            endpoint.settimeout(timeout)
            endpoint.connect(('fd43:ba17::1' if spec.get('ipv6') else spec['server'], 53))
            if spec.get('tcp'):
                endpoint.sendall(struct.pack('!H', len(packet)) + packet)
                reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
            else:
                attempts = spec.get('attempts', 1)
                for attempt in range(attempts):
                    endpoint.send(packet)
                    try:
                        reply = endpoint.recv(65535)
                        break
                    except socket.timeout:
                        if attempt + 1 == attempts:
                            raise
            (out / f'{index}.reply').write_bytes(reply)
            result['response'] = semantics(reply)
            assert result['response']['id'] == int.from_bytes(packet[:2], 'big'), 'query ID mismatch'
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)
    result['elapsed'] = round(time.monotonic() - started, 3)
    return result


def client(args):
    spec = json.loads(args.spec.read_text())
    count = spec.get('count', 1)
    specs = [dict(spec, host=spec['host'].replace('{i}', str(i)), type=(1 if i % 2 else 28) if spec.get('mixed') else spec.get('type', 1)) for i in range(count)]
    if spec.get('sequence'):
        specs = [dict(spec, host=host, type=kind) for host, kind in spec['sequence']]
    if spec.get('pipeline'):
        rows = []
        with socket.create_connection((spec['server'], 53), 4) as endpoint:
            packets = [query(item['host'], item.get('type', 1), 0x5100 + i) for i, item in enumerate(specs)]
            frames = b''.join(struct.pack('!H', len(packet)) + packet for packet in packets)
            if spec.get('cut_upstream_after_first'):
                assert len(packets) == 2
                endpoint.settimeout(2)
                endpoint.sendall(struct.pack('!H', len(packets[0])) + packets[0])
            else:
                # Split both a length prefix and a DNS header before pipelining.
                endpoint.sendall(frames[:1])
                time.sleep(.02)
                endpoint.sendall(frames[1:9])
                time.sleep(.02)
                endpoint.sendall(frames[9:])
            for index, item in enumerate(specs):
                (args.out / f'{index}.request').write_bytes(packets[index])
                started = time.monotonic()
                try:
                    reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
                except (OSError, ConnectionError) as error:
                    rows.append({'host': item['host'], 'type': item.get('type', 1), 'tcp': True, 'ipv6': False,
                                 'error': type(error).__name__ + ': ' + str(error), 'elapsed': round(time.monotonic() - started, 3)})
                    break
                (args.out / f'{index}.reply').write_bytes(reply)
                decoded = semantics(reply)
                assert decoded['id'] == 0x5100 + index
                rows.append({'host': item['host'], 'type': item.get('type', 1), 'tcp': True, 'ipv6': False, 'response': decoded, 'elapsed': round(time.monotonic() - started, 3)})
                if index == 0 and spec.get('cut_upstream_after_first'):
                    path = Path(spec['state'])
                    value = json.loads(path.read_text())
                    value['actions'] = {str(i): 'drop' for i in range(4)}
                    temporary = path.with_suffix('.client-new')
                    save(temporary, value)
                    temporary.replace(path)
                    endpoint.sendall(struct.pack('!H', len(packets[1])) + packets[1])
        save(args.out / 'client.json', rows)
        return
    with ThreadPoolExecutor(max_workers=min(count, 64)) as pool:
        rows = list(pool.map(lambda item: one_exchange(item[1], args.out, item[0]), enumerate(specs)))
    save(args.out / 'client.json', rows)


def audit(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    # Complete files omitted by the runtime capture with the exact image,
    # only inside actual_config_rootfs's private /etc mount.
    for filename in ('passwd', 'group', 'hosts', 'ethers'):
        destination = Path('/etc') / filename
        source = args.image_root / 'etc' / filename
        if not destination.exists() and source.exists():
            shutil.copy2(source, destination)
    state = args.out / 'state.json'
    save(state, {'stage': 'startup'})
    client_pid, upstream_pid = os.environ['DNSMASQ_CLIENT_PID'], os.environ['DNSMASQ_UPSTREAM_PID']
    router = os.environ['DNSMASQ_ROUTER_ADDRESS']
    subprocess.run(['nsenter', '-t', client_pid, '-n', 'ip', 'addr', 'add', router.rsplit('.', 1)[0] + '.2/24', 'dev', 'client0'], check=True)
    subprocess.run(['ip', '-6', 'addr', 'add', 'fd43:ba17::1/64', 'dev', 'br-lan', 'nodad'], check=True)
    subprocess.run(['nsenter', '-t', client_pid, '-n', 'ip', '-6', 'addr', 'add', 'fd43:ba17::2/64', 'dev', 'client0', 'nodad'], check=True)
    from types import SimpleNamespace
    from ubus_contract_diff import Fixture
    bus_out = args.out / 'ubus'
    bus_out.mkdir()
    bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), bus_out)
    bus.start_bus()
    children, logs = [], []
    result = {'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest(),
              'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'cases': [], 'errors': []}
    shutil.copy2(Path(__file__), args.out / 'executed-tool.py')
    script = str(Path(__file__).resolve())
    addresses = [line.split()[1] for line in args.resolv.read_text().splitlines() if line.split()[:1] == ['nameserver']]

    def change(stage, actions=None, delay=.01):
        temporary = state.with_suffix('.new')
        save(temporary, {'stage': stage, 'actions': actions or {}, 'delay': delay})
        temporary.replace(state)

    def case(label, host=None, **spec):
        folder = args.out / label
        folder.mkdir()
        spec.update(host=host or label + '.audit.example', server=router)
        if spec.get('cut_upstream_after_first'):
            spec['state'] = str(state)
        save(folder / 'spec.json', spec)
        process = subprocess.run(['nsenter', '-t', client_pid, '-n', sys.executable, script, '--mode', 'client', '--out', str(folder), '--spec', str(folder / 'spec.json')], capture_output=True, text=True, timeout=40)
        save(folder / 'process.json', {'exit': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr})
        process.check_returncode()
        rows = json.loads((folder / 'client.json').read_text())
        result['cases'].append({'label': label, 'clients': rows, 'daemon_alive': children[-1].poll() is None})
        save(args.out / 'result.json', result)
        assert children[-1].poll() is None, 'daemon died during ' + label
        return rows

    try:
        command = [str(args.binary), '-C', str(args.config), '-k', '-x', '/var/run/dnsmasq/predeploy.pid']
        if args.image_elf:
            from m2_rootfs import image_elf_command
            command = image_elf_command(args.image_root, args.binary) + command[1:]
        for label, argv in [('upstream', ['nsenter', '-t', upstream_pid, '-n', sys.executable, script, '--mode', 'upstream', '--out', str(args.out / 'upstream'), '--state', str(state), '--resolv', str(args.resolv)]), ('daemon', command)]:
            if label == 'daemon':
                deadline = time.monotonic() + 5
                while not (args.out / 'upstream/ready.json').exists():
                    assert time.monotonic() < deadline and children[0].poll() is None
                    time.sleep(.02)
            log = (args.out / (label + '.log')).open('wb')
            logs.append(log)
            children.append(subprocess.Popen(argv, stdout=log, stderr=log))
        deadline = time.monotonic() + 10
        while True:
            assert children[-1].poll() is None and time.monotonic() < deadline, 'daemon startup'
            try:
                with socket.create_connection((router, 53), .1):
                    break
            except OSError:
                time.sleep(.03)
        if args.dotless_cache_only:
            change('dotless-before')
            case('dotless-before', host='auditdotless', type=28, tcp=True)
            change('dotless-cname')
            case('dotless-cname', host='local-chain-dotless.audit.example', pipeline=True,
                 sequence=[['local-chain-dotless.audit.example', kind] for kind in (1, 28)])
            case('dotless-direct-udp', host='auditdotless', type=28)
            case('dotless-direct-tcp', host='auditdotless', type=28, tcp=True)
            result['upstream'] = [json.loads(line) for line in (args.out / 'upstream/queries.jsonl').read_text().splitlines()]
            return 0
        if args.local_cache_only:
            # Isolate terminal visibility from later alias AAAA/TXT/ANY replies.
            for warm_tcp, alias, terminal in (
                (True, 'local-chain.audit.example', 'audit-terminal.lan'),
                (False, 'local-chain.udp.audit.example', 'audit-udp-terminal.lan'),
            ):
                prefix = 'tcp-warm' if warm_tcp else 'udp-warm'
                change(prefix + '-before')
                for tcp in (False, True):
                    case(prefix + '-before-' + ('tcp' if tcp else 'udp'),
                         host=terminal, type=28, tcp=tcp)
                change(prefix)
                case(prefix, host=alias, tcp=warm_tcp)
                change(prefix + '-drop', {str(i): 'drop' for i in range(len(addresses))})
                for tcp in (False, True):
                    for kind in (1, 28):
                        case(prefix + '-terminal-' + ('tcp' if tcp else 'udp') + '-' + str(kind),
                             host=terminal, tcp=tcp, type=kind, timeout=2)
            result['upstream'] = [json.loads(line) for line in (args.out / 'upstream/queries.jsonl').read_text().splitlines()]
            return 0
        if args.public_cache_only:
            change('public-cname-warm')
            case('public-cname-warm', host='cname.public.audit.example', tcp=True)
            change('public-cname-drop', {str(i): 'drop' for i in range(len(addresses))})
            case('public-terminal-a-udp', host='target.audit.example', timeout=1)
            case('public-terminal-a-tcp', host='target.audit.example', tcp=True, timeout=2)
            result['upstream'] = [json.loads(line) for line in (args.out / 'upstream/queries.jsonl').read_text().splitlines()]
            return 0
        if args.focused:
            change('direct-terminal-before')
            case('direct-terminal-before-udp', host='audit-terminal.lan', type=28)
            case('direct-terminal-before-tcp', host='audit-terminal.lan', type=28, tcp=True)
            change('local-chain')
            case('local-chain', host='local-chain.audit.example', pipeline=True,
                 sequence=[['local-chain.audit.example', kind] for kind in (1, 28, 16, 255)])
            change('local-chain-invalid')
            case('local-chain-invalid', host='local-chain-invalid.audit.example', pipeline=True,
                 sequence=[['local-chain-invalid.audit.example', kind] for kind in (1, 28, 16, 255)])
            change('local-chain-outage')
            case('local-chain-outage', host='local-chain.outage.audit.example', pipeline=True, cut_upstream_after_first=True,
                 sequence=[['local-chain.outage.audit.example', kind] for kind in (1, 28)])
            change('udp-local-chain-controls')
            case('udp-local-chain-warm', host='local-chain.udp.audit.example')
            case('new-tcp-after-udp-warm', host='local-chain.udp.audit.example', type=28, tcp=True)
            case('udp-local-chain-aaaa', host='local-chain.udp.audit.example', type=28)
            case('direct-terminal-udp', host='audit-terminal.lan', type=28)
            case('direct-terminal-tcp', host='audit-terminal.lan', type=28, tcp=True)
            case('direct-terminal-a-udp', host='audit-terminal.lan', type=1)
            case('direct-terminal-a-tcp', host='audit-terminal.lan', type=1, tcp=True)
            case('fresh-alias-tcp-aaaa', host='local-chain.fresh.audit.example', type=28, tcp=True)
            for action in ('tcp-close', 'servfail', 'refused'):
                change('tcp-warm-' + action, {str(i): 'answer' if i == 0 else 'drop' for i in range(len(addresses))})
                case('tcp-warm-' + action, timeout=1, attempts=4)
                change('tcp-failover-' + action, {'0': action})
                case('tcp-failover-' + action, tcp=True, timeout=4)
            result['upstream'] = [json.loads(line) for line in (args.out / 'upstream/queries.jsonl').read_text().splitlines()]
            return 0
        for ipv6 in (False, True):
            for tcp in (False, True):
                for kind in (1, 28):
                    label = f'basic-v{6 if ipv6 else 4}-{"tcp" if tcp else "udp"}-{kind}'
                    change(label)
                    case(label, ipv6=ipv6, tcp=tcp, type=kind)
                    case(label + '-cached', host=label + '.audit.example', ipv6=ipv6, tcp=tcp, type=kind)
        for label, kind, extra in [('txt', 16, {}), ('https', 65, {}), ('cname', 1, {}), ('nx', 1, {}), ('nodata', 28, {}), ('rebind', 1, {}), ('localhost-rebind', 1, {}), ('large', 16, {'edns': 1232}), ('large-noedns', 16, {}), ('ad', 1, {'edns': 1232, 'do': 1}), ('cd', 1, {'flags': 0x110, 'edns': 1232})]:
            change(label)
            case(label, type=kind, **extra)
            case(label + '-cached', host=label + '.audit.example', type=kind, **extra)
        for label, host, kind in [('cname-aaaa', 'cname.aaaa.audit.example', 28), ('nx-cross-type', 'nx.audit.example', 28), ('rebind6', 'rebind6.audit.example', 28), ('localhost-rebind6', 'localhost-rebind6.audit.example', 28)]:
            change(label)
            case(label, host=host, type=kind)
        change('truncation')
        case('truncated', edns=1232)
        case('truncated-tcp', host='truncated.audit.example', tcp=True)
        change('expiry')
        case('expiry')
        time.sleep(3)
        case('expiry-after', host='expiry.audit.example')
        for family in (4, 6):
            change('only-upstream-v' + str(family), {str(i): 'answer' if ipaddress.ip_address(address).version == family else 'drop' for i, address in enumerate(addresses)})
            # SIGHUP clears cache/selection only according to the implementation.
            children[-1].send_signal(signal.SIGHUP)
            time.sleep(.2)
            case('only-upstream-v' + str(family), type=28, timeout=1, attempts=4)
        for action in ('drop', 'servfail', 'refused'):
            change('warm-' + action, {str(i): 'answer' if i == 0 else 'drop' for i in range(len(addresses))})
            case('warm-' + action, timeout=1, attempts=4)
            change('failover-' + action, {'0': action})
            case('failover-' + action, timeout=1, attempts=5)
        for action in ('servfail', 'refused', 'drop'):
            change('all-' + action, {str(i): action for i in range(len(addresses))})
            case('all-' + action, timeout=.8, attempts=2)
            change('recover-' + action)
            case('recover-' + action, timeout=1, attempts=4)
        change('parallel-unique', delay=.002)
        case('parallel-unique', host='unique-{i}.audit.example', count=64, mixed=True, timeout=2, attempts=2)
        change('parallel-duplicate', delay=.1)
        case('parallel-duplicate', host='duplicate.audit.example', count=48, timeout=2, attempts=2)
        change('parallel-tcp', delay=.002)
        case('parallel-tcp', host='tcp-{i}.audit.example', count=24, mixed=True, tcp=True, timeout=3)
        change('pipeline', delay=.001)
        case('pipeline', host='pipeline-{i}.audit.example', count=12, mixed=True, pipeline=True)
        idle = [socket.create_connection((router, 53), 2) for _ in range(12)]
        try:
            for index, connection in enumerate(idle):
                connection.sendall(b'\0' if index % 2 else b'\0\x40\0\0\x01\0')
            change('idle-tcp-udp-health')
            case('idle-tcp-udp-health', count=16, host='idle-tcp-health-{i}.audit.example', mixed=True)
        finally:
            for connection in idle:
                connection.close()
        change('health')
        case('health')
        if args.saturation:
            change('saturation', {str(i): 'drop' for i in range(len(addresses))}, delay=0)
            case('saturation', host='saturation-{i}.audit.example', count=176, mixed=True, timeout=.2)
            change('saturation-recovery')
            case('saturation-cached-health', host='health.audit.example')
            case('saturation-new-before-expiry', timeout=.3)
            time.sleep(11)
            case('saturation-new-after-expiry', timeout=2)
            case('saturation-parallel-after-expiry', host='after-saturation-{i}.audit.example', count=48, mixed=True)
        result['upstream'] = [json.loads(line) for line in (args.out / 'upstream/queries.jsonl').read_text().splitlines()]
        if (args.out / 'upstream/errors.json').exists():
            result['errors'].append(json.loads((args.out / 'upstream/errors.json').read_text()))
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
        result['process_exits'] = [process.returncode for process in children]
        for log in logs:
            log.close()
        bus.close()
        result['ubus_checks'] = bus.checks
        result['errors'].extend(check for check in bus.checks if not check['pass'])
        save(args.out / 'result.json', result)
    return bool(result['errors'])


def compare(args):
    """Publish derived observations only, never runtime files or raw packets."""
    c, rust = [json.loads(path.read_text()) for path in (args.reference, args.candidate)]
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    def clients(case):
        return [{key: value for key, value in row.items() if key != 'elapsed'} for row in case['clients']]
    def status(rows):
        return dict(sorted(Counter(row.get('error', 'rcode=' + str(row.get('response', {}).get('flags', 0) & 15)) for row in rows).items()))
    assert [case['label'] for case in c['cases']] == [case['label'] for case in rust['cases']]
    output = {
        'scope': 'Actual captured configuration, exact image C ELF and frozen Rust release; isolated oracle network/mount/PID namespaces',
        'comparison': 'Ignore elapsed time only; keep DNS IDs, flags, questions, ordered records, TTLs, error category/text and daemon liveness',
        'config_sha256': c['config_sha256'],
        'config_identity_equal': c['config_sha256'] == rust['config_sha256'],
        'c_binary_sha256': c['binary_sha256'], 'rust_binary_sha256': rust['binary_sha256'],
        'executed_tool_sha256': {'c': c.get('tool_sha256'), 'rust': rust.get('tool_sha256')},
        'source_result_sha256': {side: hashlib.sha256(path.read_bytes()).hexdigest() for side, path in [('c', args.reference), ('rust', args.candidate)]},
        'cases': [], 'upstream': {}, 'harness_errors': {'c': c['errors'], 'rust': rust['errors']},
        'process_exits': {'c': c['process_exits'], 'rust': rust['process_exits']},
        'ubus_checks': {'c': c['ubus_checks'], 'rust': rust['ubus_checks']},
    }
    for first, second in zip(c['cases'], rust['cases']):
        a, b = clients(first), clients(second)
        output['cases'].append({'label': first['label'], 'clients_each': len(a),
            'exact_client_semantics_equal': a == b, 'daemon_alive_both': first['daemon_alive'] and second['daemon_alive'],
            'c_status': status(a), 'rust_status': status(b),
            'c_semantics_sha256': hashlib.sha256(canonical(a)).hexdigest(),
            'rust_semantics_sha256': hashlib.sha256(canonical(b)).hexdigest()})
    counters = []
    for side, result in [('c', c), ('rust', rust)]:
        rows = Counter((row['stage'], row['host'], row['type'], row['upstream'], row['tcp'], row['action']) for row in result['upstream'])
        counters.append(rows)
        output['upstream'][side] = {'requests': len(result['upstream']), 'by_stage': dict(sorted(Counter(row['stage'] for row in result['upstream']).items()))}
    output['upstream']['endpoint_query_counts_equal'] = counters[0] == counters[1]
    output['upstream']['c_only_counts'] = [[*key, count] for key, count in sorted((counters[0] - counters[1]).items())]
    output['upstream']['rust_only_counts'] = [[*key, count] for key, count in sorted((counters[1] - counters[0]).items())]
    output['totals'] = {'scenarios': len(output['cases']), 'exchanges_each': sum(case['clients_each'] for case in output['cases']),
                        'client_semantic_mismatches': sum(not case['exact_client_semantics_equal'] for case in output['cases'])}
    args.out.mkdir(parents=True, exist_ok=True)
    save(args.out / 'comparison.json', output)
    return bool(output['totals']['client_semantic_mismatches'] or c['errors'] or rust['errors'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['audit', 'client', 'upstream', 'compare'], default='audit')
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--image-elf', action='store_true')
    parser.add_argument('--saturation', action='store_true', help='also exercise default forwarding-table capacity during an upstream outage')
    parser.add_argument('--focused', action='store_true', help='TCP same-session local CNAME terminal and upstream close/error cases')
    parser.add_argument('--dotless-cache-only', action='store_true', help='cached CNAME cursor reaches domain-needed terminal')
    parser.add_argument('--local-cache-only', action='store_true', help='isolate cached local terminals after only one A warmup over each transport')
    parser.add_argument('--public-cache-only', action='store_true', help='one TCP CNAME warmup, then direct terminal A after upstream loss')
    parser.add_argument('--reference-build', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--state', type=Path)
    parser.add_argument('--config', type=Path, default=Path('/var/etc/dnsmasq.conf.cfg01411c'))
    parser.add_argument('--resolv', type=Path, default=Path('/tmp/resolv.conf.d/resolv.conf.auto'))
    args = parser.parse_args()
    return {'audit': audit, 'client': client, 'upstream': upstream, 'compare': compare}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
