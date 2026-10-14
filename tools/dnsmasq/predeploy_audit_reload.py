#!/usr/bin/env python3
"""Actual-config reload audit. Run inside actual_config_network/rootfs isolation.

The source config stays byte-identical until the explicitly labelled config-edit
phase. Only disposable mounts are changed. Raw packets and private names remain
in --out; --mode compare emits only synthetic-case/aggregate derived evidence.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from dns_service_probe import exact_read, query, read_name, rr, semantics
from m2_rootfs import STOCK_SHA256, image_elf_command

CONFIG = Path('/var/etc/dnsmasq.conf.cfg01411c')
RESOLV = Path('/tmp/resolv.conf.d/resolv.conf.auto')
LEASE = Path('/tmp/dhcp.leases')
HOST = Path('/tmp/hosts/predeploy-audit')
V6_ROUTER = 'fd70:2026:1014::1'
V6_CLIENT = 'fd70:2026:1014::2'


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolvers():
    return [line.split()[1] for line in RESOLV.read_text().splitlines()
            if line.split()[:1] == ['nameserver']]


def upstream(args):
    args.out.mkdir(parents=True)
    sockets = []
    for address in resolvers():
        sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((address, 53))
        sockets.append(sock)
    rows = []
    save(args.out / 'ready.json', {'servers': len(sockets)})
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            for sock in select.select(sockets, [], [], .1)[0]:
                packet, peer = sock.recvfrom(65535)
                host, end = read_name(packet, 12)
                kind, cls = struct.unpack_from('!HH', packet, end)
                index = sockets.index(sock)
                # Public synthetic DNS answers avoid stop-dns-rebind rejection.
                data = socket.inet_aton('8.8.4.4') if kind == 1 else socket.inet_pton(socket.AF_INET6, '2001:4860:4860::8844')
                negative = host.startswith('absent-')
                answer = packet[:2] + struct.pack('!5H', 0x8183 if negative else 0x8180, 1, 0 if negative else 1, 0, 0)
                answer += packet[12:end + 4]
                if not negative:
                    answer += rr(kind, data, 120)
                rows.append({'name': host, 'type': kind, 'resolver': index, 'transport': 'udp'})
                save(args.out / 'queries.json', rows)
                (args.out / f'{len(rows):03}.request').write_bytes(packet)
                sock.sendto(answer, peer)
    finally:
        for sock in sockets:
            sock.close()


def client_socket(family, kind):
    """Create the socket in the actual client netns, return to service netns."""
    libc = ctypes.CDLL(None, use_errno=True)
    original = os.open('/proc/self/ns/net', os.O_RDONLY)
    target = os.open('/proc/' + os.environ['DNSMASQ_CLIENT_PID'] + '/ns/net', os.O_RDONLY)
    try:
        if libc.setns(target, 0):
            raise OSError(ctypes.get_errno(), 'client setns')
        try:
            return socket.socket(family, kind)
        finally:
            if libc.setns(original, 0):
                raise OSError(ctypes.get_errno(), 'restore setns')
    finally:
        os.close(original)
        os.close(target)


def exchange(host, kind=1, tcp=False, ipv6=False):
    ident = 0x7a10
    packet = query(host, kind, ident)
    address = V6_ROUTER if ipv6 else os.environ['DNSMASQ_ROUTER_ADDRESS']
    with client_socket(socket.AF_INET6 if ipv6 else socket.AF_INET,
                       socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect((address, 53))
        if tcp:
            sock.sendall(struct.pack('!H', len(packet)) + packet)
            reply = exact_read(sock, struct.unpack('!H', exact_read(sock, 2))[0])
        else:
            sock.send(packet)
            reply = sock.recv(65535)
    parsed = semantics(reply)
    assert parsed['id'] == ident
    return packet, reply, parsed


def atomic_write(path, text):
    temporary = path.with_name('.' + path.name + '.audit-new')
    temporary.write_text(text)
    temporary.chmod(0o644)
    temporary.replace(path)


def run(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    # Captured runtime fixture omits immutable accounts/default data; use the exact image.
    for relative in ('etc/passwd', 'etc/group', 'etc/hosts', 'etc/ethers'):
        if not Path('/' + relative).exists():
            shutil.copy2(args.image_root / relative, '/' + relative)
    original_config, original_resolv = CONFIG.read_text(), RESOLV.read_text()
    addresses = resolvers()
    domain = next(line.split('=', 1)[1] for line in original_config.splitlines() if line.startswith('domain='))
    range_fields = next(line.split('=', 1)[1].split(',') for line in original_config.splitlines() if line.startswith('dhcp-range='))
    start = next(ipaddress.ip_address(field) for field in range_fields if field.count('.') == 3)
    leased = str(start + 5)
    topology = json.loads((Path(os.environ['DNSMASQ_NETWORK_EVIDENCE']) / 'topology.json').read_text())
    router = ipaddress.ip_interface(topology['router'])
    client_address = next(address for address in router.network.hosts() if address != router.ip)
    subprocess.run(['nsenter', '-t', os.environ['DNSMASQ_CLIENT_PID'], '-n', 'ip', 'addr', 'add', f'{client_address}/{router.network.prefixlen}', 'dev', 'client0'], check=True)
    subprocess.run(['ip', '-6', 'addr', 'add', V6_ROUTER + '/64', 'dev', 'br-lan', 'nodad'], check=True)
    subprocess.run(['nsenter', '-t', os.environ['DNSMASQ_CLIENT_PID'], '-n', 'ip', '-6', 'addr', 'add', V6_CLIENT + '/64', 'dev', 'client0', 'nodad'], check=True)
    # A current, synthetic lease tests the actual restore/reload name path.
    LEASE.write_text(f'4102444800 02:00:00:14:10:01 {leased} audit-leased *\n')
    LEASE.chmod(0o644)
    HOST.write_text('192.0.2.31 audit-host\n2001:db8::31 audit-host\n')
    stock = args.image_root / 'usr/sbin/dnsmasq'
    assert sha(stock) == STOCK_SHA256
    binary = stock if args.side == 'c' else args.rust
    command = image_elf_command(args.image_root, binary) + ['-C', str(CONFIG), '-k', '-x', '/var/run/dnsmasq/predeploy.pid']
    result = {'side': args.side, 'binary_sha256': sha(binary), 'original_config_sha256': sha(CONFIG),
              'rows': [], 'errors': [], 'clean_shutdowns': [], 'original_resolver_count': len(addresses)}
    from types import SimpleNamespace
    from ubus_contract_diff import Fixture
    busdir = args.out / 'ubus'
    busdir.mkdir()
    bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), busdir)
    upstream_proc = daemon = None
    logs = []
    try:
        bus.start_bus()
        log = (args.out / 'upstream.log').open('wb'); logs.append(log)
        upstream_proc = subprocess.Popen(['nsenter', '-t', os.environ['DNSMASQ_UPSTREAM_PID'], '-n', sys.executable,
            str(Path(__file__).resolve()), '--mode', 'upstream', '--out', str(args.out / 'upstream')], stdout=log, stderr=log)
        deadline = time.monotonic() + 5
        while not (args.out / 'upstream/ready.json').exists():
            assert upstream_proc.poll() is None and time.monotonic() < deadline
            time.sleep(.02)

        def start(label):
            log = (args.out / (label + '.log')).open('wb'); logs.append(log)
            proc = subprocess.Popen(command, stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                assert proc.poll() is None and time.monotonic() < deadline, 'daemon startup'
                try:
                    _, _, reply = exchange('audit-leased.' + domain)
                    if any(row['data'] == leased for row in reply['records']):
                        return proc
                except (OSError, EOFError):
                    pass
                time.sleep(.02)

        def counts():
            path = args.out / 'upstream/queries.json'
            return json.loads(path.read_text()) if path.exists() else []

        def record(label, host, kind=1, tcp=False, ipv6=False, cache=False):
            before = len(counts())
            began = time.monotonic()
            row = {'case': label, 'transport': 'tcp' if tcp else 'udp', 'client_ipv6': ipv6}
            try:
                sent, received, reply = exchange(host, kind, tcp, ipv6)
                row['reply'] = reply
                (args.out / (label + '.request')).write_bytes(sent)
                (args.out / (label + '.reply')).write_bytes(received)
            except (OSError, EOFError) as error:
                row['error'] = type(error).__name__
            row['elapsed_ms'] = round((time.monotonic() - began) * 1000, 2)
            time.sleep(.025)
            row['new_upstream'] = sorted((item['name'], item['type'], item['resolver']) for item in counts()[before:])
            row['daemon_alive'] = daemon.poll() is None
            if cache:
                row['cache_ttl_window'] = [110, 120]
            result['rows'].append(row)
            return row

        def record_connected(label, endpoint, host):
            sent = query(host, 1, 0x7a10)
            began = time.monotonic()
            endpoint.sendall(struct.pack('!H', len(sent)) + sent)
            received = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
            (args.out / (label + '.request')).write_bytes(sent)
            (args.out / (label + '.reply')).write_bytes(received)
            result['rows'].append({'case': label, 'transport': 'existing-tcp', 'client_ipv6': False,
                'reply': semantics(received), 'new_upstream': [], 'daemon_alive': daemon.poll() is None,
                'elapsed_ms': round((time.monotonic() - began) * 1000, 2)})

        def hup():
            daemon.send_signal(signal.SIGHUP)
            time.sleep(.15)

        def stop():
            daemon.terminate()
            result['clean_shutdowns'].append(daemon.wait(timeout=5))

        daemon = start('initial')
        # Query every captured hosts file record; only aggregates leave private/.
        actual_hosts = []
        for source in [Path('/etc/hosts'), *sorted(Path('/tmp/hosts').glob('*'))]:
            if source == HOST or not source.is_file():
                continue
            for line in source.read_text(errors='replace').splitlines():
                fields = line.split('#', 1)[0].split()
                if len(fields) < 2:
                    continue
                try:
                    address = ipaddress.ip_address(fields[0])
                except ValueError:
                    continue
                for hostname in fields[1:]:
                    actual_hosts.append((hostname, 1 if address.version == 4 else 28))
        for index, (hostname, kind) in enumerate(actual_hosts):
            record(f'captured-host-{index:02}', hostname, kind)
        for tcp in (False, True):
            suffix = '-tcp' if tcp else '-udp'
            record('hosts-short' + suffix, 'audit-host', tcp=tcp)
            record('hosts-fqdn' + suffix, 'audit-host.' + domain, tcp=tcp)
            record('hosts-aaaa' + suffix, 'audit-host.' + domain, 28, tcp=tcp)
            record('hosts-ptr' + suffix, '31.2.0.192.in-addr.arpa', 12, tcp=tcp)
            record('lease-name' + suffix, 'audit-leased.' + domain, tcp=tcp)
            record('lease-ptr' + suffix, ipaddress.ip_address(leased).reverse_pointer, 12, tcp=tcp)
        record('hosts-ipv6-udp', 'audit-host.' + domain, 28, ipv6=True)
        record('hosts-ipv6-tcp', 'audit-host.' + domain, 28, tcp=True, ipv6=True)
        record('cache-fill', 'cache.reload.example', cache=True)
        record('cache-hit', 'cache.reload.example', cache=True)
        existing = client_socket(socket.AF_INET, socket.SOCK_STREAM)
        existing.settimeout(2)
        existing.connect((os.environ['DNSMASQ_ROUTER_ADDRESS'], 53))
        record_connected('existing-tcp-before-hup', existing, 'audit-host.' + domain)
        atomic_write(HOST, '192.0.2.32 audit-host\n2001:db8::32 audit-host\n')
        record('hosts-atomic-before-hup', 'audit-host.' + domain)
        hup()
        record('hosts-atomic-after-hup', 'audit-host.' + domain)
        record_connected('existing-tcp-after-hup', existing, 'audit-host.' + domain)
        existing.close()
        record('hosts-atomic-aaaa', 'audit-host.' + domain, 28, tcp=True)
        record('hosts-old-ptr-removed', '31.2.0.192.in-addr.arpa', 12)
        record('hosts-new-ptr', '32.2.0.192.in-addr.arpa', 12)
        record('lease-after-hup', 'audit-leased.' + domain)
        record('cache-flushed-hup', 'cache.reload.example', cache=True)
        HOST.unlink(); hup()
        record('hosts-deleted-hup', 'audit-host.' + domain)
        atomic_write(HOST, '192.0.2.33 audit-host\n')
        hup()
        record('hosts-recreated-hup', 'audit-host.' + domain, tcp=True)
        # Real generated resolv-file: close/atomic replacement and loss/recovery.
        for index, address in enumerate(addresses):
            atomic_write(RESOLV, f'nameserver {address}\n')
            time.sleep(.25)
            record(f'resolver-only-{index}-a', f'resolver-{index}.reload.example')
            record(f'resolver-only-{index}-aaaa', f'resolver6-{index}.reload.example', 28, ipv6=True)
        atomic_write(RESOLV, '')
        time.sleep(.25)
        record('resolver-empty', 'empty.reload.example')
        RESOLV.unlink(); time.sleep(.25)
        record('resolver-deleted', 'deleted.reload.example')
        atomic_write(RESOLV, original_resolv); time.sleep(.25)
        record('resolver-restored', 'restored.reload.example')
        record('cache-seed-before-resolver-change', 'persist.reload.example', cache=True)
        atomic_write(RESOLV, f'nameserver {addresses[0]}\n'); time.sleep(.25)
        record('cache-retained-resolver-change', 'persist.reload.example', cache=True)
        observations = []
        def continuous_queries():
            for index in range(160):
                tcp, ipv6 = bool(index % 2), bool(index % 4 >= 2)
                began = time.monotonic()
                try:
                    _, _, reply = exchange('audit-host.' + domain, tcp=tcp, ipv6=ipv6)
                    ok = reply['flags'] & 15 == 0 and any(row['data'] == '192.0.2.33' for row in reply['records'])
                    observations.append({'tcp': tcp, 'ipv6': ipv6, 'ok': ok,
                        'elapsed_ms': round((time.monotonic() - began) * 1000, 2)})
                except (OSError, EOFError) as error:
                    observations.append({'tcp': tcp, 'ipv6': ipv6, 'ok': False, 'error': type(error).__name__})
                time.sleep(.002)
        worker = threading.Thread(target=continuous_queries)
        worker.start()
        for _ in range(24):
            daemon.send_signal(signal.SIGHUP)
            time.sleep(.02)
        worker.join(10)
        assert not worker.is_alive()
        save(args.out / 'concurrent-hup-queries.json', observations)
        result['rows'].append({'case': 'concurrent-hup-queries', 'requests': len(observations),
            'successful': sum(row['ok'] for row in observations),
            'new_upstream': [], 'daemon_alive': daemon.poll() is None,
            'elapsed_ms': max((row.get('elapsed_ms', 0) for row in observations), default=0)})
        CONFIG.write_text(original_config + '\nhost-record=config-edit.' + domain + ',192.0.2.77\n')
        hup()
        record('main-config-not-reread-hup', 'config-edit.' + domain)
        record('lease-before-restart', 'audit-leased.' + domain)
        stop()
        daemon = start('restart')
        record('main-config-read-restart', 'config-edit.' + domain)
        record('hosts-read-restart', 'audit-host.' + domain)
        record('lease-restored-restart', 'audit-leased.' + domain)
        record('lease-ptr-restart', ipaddress.ip_address(leased).reverse_pointer, 12, tcp=True)
        # Netlink bind-dynamic: add and remove a second LAN address.
        alternate = str(router.network.network_address + 254)
        if alternate != str(router.ip):
            subprocess.run(['ip', 'addr', 'add', alternate + '/32', 'dev', 'br-lan'], check=True)
            time.sleep(.2)
            previous = os.environ['DNSMASQ_ROUTER_ADDRESS']
            os.environ['DNSMASQ_ROUTER_ADDRESS'] = alternate
            record('new-interface-address-udp', 'audit-host.' + domain)
            record('new-interface-address-tcp', 'audit-host.' + domain, tcp=True)
            os.environ['DNSMASQ_ROUTER_ADDRESS'] = previous
            subprocess.run(['ip', 'addr', 'del', alternate + '/32', 'dev', 'br-lan'], check=True)
            time.sleep(.2)
            record('original-interface-after-remove', 'audit-host.' + domain)
        stop()
        result['lease_preserved'] = any('audit-leased' in line and leased in line for line in LEASE.read_text().splitlines())
        result['status'] = 'completed'
    except Exception as error:
        result['errors'].append(repr(error))
        result['status'] = 'failed'
    finally:
        for process in (daemon, upstream_proc):
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                    result['errors'].append('forced process cleanup')
        bus.close()
        for stream in logs:
            stream.close()
        save(args.out / 'result.json', result)
    print(json.dumps({'side': args.side, 'status': result['status'], 'rows': len(result['rows']), 'errors': result['errors']}))
    return bool(result['errors'])


def compare(args):
    expected = json.loads((args.c_out / 'result.json').read_text())
    actual = json.loads((args.rust_out / 'result.json').read_text())
    def canonical(row):
        row = copy.deepcopy(row)
        row.pop('elapsed_ms')
        if 'cache_ttl_window' in row:
            low, high = row.pop('cache_ttl_window')
            for record in row.get('reply', {}).get('records', []):
                assert low <= record['ttl'] <= high, 'cache TTL outside bounded window'
                record['ttl'] = 'bounded-110..120'
        return row
    rows = []
    for index in range(max(len(expected['rows']), len(actual['rows']))):
        c = expected['rows'][index] if index < len(expected['rows']) else None
        rust = actual['rows'][index] if index < len(actual['rows']) else None
        rows.append({'case': (c or rust)['case'], 'match': bool(c and rust and canonical(c) == canonical(rust)),
                     'c_error': c.get('error') if c else 'missing', 'rust_error': rust.get('error') if rust else 'missing',
                     'c_rcode': c['reply']['flags'] & 15 if c and 'reply' in c else None,
                     'rust_rcode': rust['reply']['flags'] & 15 if rust and 'reply' in rust else None,
                     'c_upstream_count': len(c['new_upstream']) if c else None,
                     'rust_upstream_count': len(rust['new_upstream']) if rust else None})
    summary = {'c_sha256': expected['binary_sha256'], 'rust_sha256': actual['binary_sha256'],
               'config_sha256': expected['original_config_sha256'], 'config_match': expected['original_config_sha256'] == actual['original_config_sha256'],
               'rows': rows, 'matched': sum(row['match'] for row in rows), 'total': len(rows),
               'c_status': expected['status'], 'rust_status': actual['status'],
               'c_cleanup': expected['clean_shutdowns'], 'rust_cleanup': actual['clean_shutdowns'],
               'c_lease_preserved': expected.get('lease_preserved'), 'rust_lease_preserved': actual.get('lease_preserved'),
               'c_errors': expected['errors'], 'rust_errors': actual['errors']}
    for side, trace in [('c', expected), ('rust', actual)]:
        aggregate = next(row for row in trace['rows'] if row['case'] == 'concurrent-hup-queries')
        summary[side + '_concurrent_hup'] = {key: aggregate[key] for key in ('requests', 'successful', 'elapsed_ms')}
        summary[side + '_query_failures'] = sum('error' in row or not row['daemon_alive'] for row in trace['rows'])
    summary['passed'] = (summary['matched'] == summary['total'] and summary['config_match']
        and all(summary[side + '_status'] == 'completed' and not summary[side + '_errors']
            and summary[side + '_query_failures'] == 0 and summary[side + '_cleanup'] == [0, 0]
            and summary[side + '_lease_preserved']
            and summary[side + '_concurrent_hup']['requests'] == summary[side + '_concurrent_hup']['successful'] == 160
            for side in ('c', 'rust')))
    args.out.mkdir(parents=True, exist_ok=True)
    save(args.out / 'summary.json', summary)
    print(json.dumps(summary))
    return not summary['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('run', 'upstream', 'compare'), default='run')
    parser.add_argument('--side', choices=('c', 'rust'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--reference-build', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--c-out', type=Path)
    parser.add_argument('--rust-out', type=Path)
    args = parser.parse_args()
    return {'run': run, 'upstream': upstream, 'compare': compare}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
