#!/usr/bin/env python3
"""Independent actual-config DHCP household lifecycle audit; run isolated.

Use actual_config_network.py -> actual_config_rootfs.py before --mode run.
All raw inputs, leases and packets remain under private/. No router access.
The C baseline is the exact image ELF, loaded using its matching image musl.
"""
import argparse
import copy
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
import threading
import time
from types import SimpleNamespace

from dhcp_boot_service_diff import options
from dns_service_probe import name as wire_name, query, semantics


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def request(client, kind, xid, server, mode='select', requested=None, hostname=True):
    packet = bytearray(240)
    packet[:3] = bytes([1, 1, 6])
    packet[4:8] = struct.pack('!I', xid)
    packet[10:12] = b'\0\0' if mode == 'renew' else b'\x80\0'
    if mode in ('renew', 'rebind', 'release', 'inform'):
        packet[12:16] = socket.inet_aton(client['address'])
    packet[28:34] = bytes.fromhex(client['mac'])
    packet[236:240] = bytes.fromhex('63825363')
    packet += bytes([53, 1, kind, 55, 9, 1, 3, 6, 12, 15, 28, 51, 58, 59])
    if hostname:
        value = client['name'].encode()
        packet += bytes([12, len(value)]) + value
    if client.get('client_id'):
        value = bytes.fromhex(client['client_id'])
        packet += bytes([61, len(value)]) + value
    if client.get('lease_time') is not None:
        packet += bytes([51, 4]) + struct.pack('!I', client['lease_time'])
    if client.get('fqdn'):
        value = bytes([4 if client.get('fqdn_encoded') else 0, 0, 0])
        value += wire_name(client['fqdn']) if client.get('fqdn_encoded') else client['fqdn'].encode()
        packet += bytes([81, len(value)]) + value
    if requested is not None:
        packet += bytes([50, 4]) + socket.inet_aton(requested)
    if mode in ('select', 'release') and kind != 1:
        packet += bytes([54, 4]) + socket.inet_aton(server)
    packet.append(255)
    return bytes(packet)


class Client:
    def __init__(self, args):
        self.args = args
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.raw.bind(('client0', 0))
        self.serial = 0
        self.rows = []

    def send(self, client, kind, mode='select', requested=None, hostname=True):
        self.serial += 1
        xid = 0xA0700000 + self.serial
        packet = request(client, kind, xid, self.args.server, mode, requested, hostname)
        source = client['address'] if mode in ('renew', 'rebind', 'release', 'inform') else '0.0.0.0'
        destination = self.args.server if mode in ('renew', 'release', 'inform') else '255.255.255.255'
        udp = struct.pack('!4H', 68, 67, 8 + len(packet), 0) + packet
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), self.serial, 0,
                             64, 17, 0, socket.inet_aton(source), socket.inet_aton(destination))
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        mac = bytes.fromhex(self.args.router_mac) if destination == self.args.server else b'\xff' * 6
        frame = mac + bytes.fromhex(client['mac']) + b'\x08\x00' + header + udp
        (self.args.out / ('%03d.request' % self.serial)).write_bytes(packet)
        self.raw.send(frame)
        return xid

    def collect(self, pending, timeout=45):
        deadline = time.monotonic() + timeout
        replies = {}
        while pending.keys() - replies.keys():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError('missing DHCP replies: ' + str([pending[x][0] for x in pending.keys() - replies.keys()]))
            self.raw.settimeout(left)
            frame = self.raw.recv(65535)
            if len(frame) < 282 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
                continue
            offset = 14 + (frame[14] & 15) * 4
            src, dst, length = struct.unpack_from('!3H', frame, offset)
            if (src, dst) != (67, 68):
                continue
            packet = frame[offset + 8:offset + length]
            xid = struct.unpack_from('!I', packet, 4)[0]
            if xid not in pending or xid in replies:
                continue
            label, client, expected = pending[xid]
            decoded = options(packet)
            lookup = dict(decoded)
            row = {'label': label, 'client': client['key'], 'type': int(lookup[53], 16),
                   'address': socket.inet_ntoa(packet[16:20]), 'ciaddr': socket.inet_ntoa(packet[12:16]),
                   'flags': packet[10:12].hex(), 'siaddr': socket.inet_ntoa(packet[20:24]),
                   'options': decoded, 'destination': socket.inet_ntoa(frame[30:34])}
            (self.args.out / ('%s.reply' % label)).write_bytes(packet)
            self.rows.append(row)
            if expected is not None and row['type'] != expected:
                raise AssertionError((label, row['type'], expected))
            replies[xid] = row
        return replies

    def one(self, client, label, kind=3, mode='renew', requested=None, expected=5, hostname=True):
        xid = self.send(client, kind, mode, requested, hostname)
        return self.collect({xid: (label, client, expected)})[xid]

    def dora(self, clients, label):
        pending = {self.send(c, 1): (label + '-offer-' + c['key'], c, 2) for c in clients}
        replies = self.collect(pending)
        for xid, row in replies.items():
            pending[xid][1]['address'] = row['address']
            mask = socket.inet_ntoa(bytes.fromhex(dict(row['options'])[1]))
            pending[xid][1]['prefix'] = ipaddress.IPv4Network('0.0.0.0/' + mask).prefixlen
        pending = {self.send(c, 3, requested=c['address']): (label + '-ack-' + c['key'], c, 5) for c in clients}
        self.collect(pending)
        assert len({c['address'] for c in clients}) == len(clients), 'duplicate committed addresses'


def client(args):
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True)
    clients = json.loads(args.state.read_text())
    probe = Client(args)
    result = {'phase': args.phase, 'dhcp': probe.rows, 'dns': [], 'errors': []}
    observer_stop = threading.Event()
    observer_thread = None
    observer_latencies = []

    def observe_dns():
        while not observer_stop.is_set():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                    endpoint.bind((args.observer, 0))
                    endpoint.settimeout(3)
                    began = time.monotonic()
                    endpoint.sendto(query('audit-observer.lan'), (args.server, 53))
                    reply, peer = endpoint.recvfrom(65535)
                assert peer == (args.server, 53) and semantics(reply)['flags'] & 15 == 3
                observer_latencies.append(time.monotonic() - began)
            except Exception as error:
                result['errors'].append('concurrent DNS: ' + repr(error))
            observer_stop.wait(.1)

    try:
        if args.phase == 'initial':
            if args.observer:
                subprocess.run(['ip', 'addr', 'add', args.observer + '/' + args.observer_prefix,
                                'dev', 'client0'], check=True)
                observer_thread = threading.Thread(target=observe_dns)
                observer_thread.start()
            probe.dora(clients, 'batch')
            observer_stop.set()
            if observer_thread:
                observer_thread.join(4)
                assert not observer_thread.is_alive()
                assert len(observer_latencies) >= 10, 'concurrent DNS schedule did not run'
            for c in clients:
                subprocess.run(['ip', 'addr', 'add', '%s/%d' % (c['address'], c['prefix']), 'dev', 'client0'], check=True)
        elif args.phase == 'lifecycle':
            probe.one(clients[0], 'unicast-renew')
            probe.one(clients[1], 'broadcast-rebind', mode='rebind')
            probe.one(clients[2], 'init-reboot', mode='init', requested=clients[2]['address'])
            probe.one(clients[3], 'renew-no-hostname', hostname=False)
            clients[4]['name'] = 'audit-renamed'
            probe.one(clients[4], 'rename')
            clients[5]['name'] = clients[0]['name']
            probe.one(clients[5], 'duplicate-name')
            # A stable RFC 4361-style ID survives a hardware-address change.
            clients[7]['mac'] = '02000000a199'
            probe.one(clients[7], 'client-id-new-mac', mode='init', requested=clients[7]['address'])
            probe.one(clients[8], 'wrong-subnet-init', mode='init', requested='198.51.100.77', expected=6)
            probe.one(clients[8], 'valid-init-after-nak', mode='init', requested=clients[8]['address'])
            probe.one(clients[9], 'inform', kind=8, mode='inform')
        elif args.phase == 'takeover':
            for c in clients:
                if c['key'] != '06':
                    subprocess.run(['ip', 'addr', 'add', '%s/%d' % (c['address'], c['prefix']),
                                    'dev', 'client0'], check=True)
        elif args.phase in ('hup', 'restart', 'crash-restart'):
            # Query before renewal: verifies restored publication, not publication
            # incidentally repaired by the first client packet after restart.
            pass
        elif args.phase == 'release':
            probe.send(clients[6], 7, mode='release')
            time.sleep(.15)
        elif args.phase == 'short-lease':
            clients[9]['lease_time'] = 1
            row = probe.one(clients[9], 'minimum-client-lease')
            assert dict(row['options'])[51] == '00000078', 'client minimum must be 120 seconds'
            # This client goes offline without a RELEASE and cannot renew.
            subprocess.run(['ip', 'addr', 'del', '%s/%d' % (clients[9]['address'], clients[9]['prefix']), 'dev', 'client0'], check=True)
        elif args.phase == 'reacquire':
            probe.dora([clients[9]], 'after-expiry')
            subprocess.run(['ip', 'addr', 'add', '%s/%d' % (clients[9]['address'], clients[9]['prefix']), 'dev', 'client0'], check=True)
        elif args.phase == 'names':
            for index, host, encoded, suffix in [(8, 'audit-fqdn-encoded', True, 'lan'),
                                                (9, 'audit-fqdn-ascii', False, 'lan'),
                                                (7, 'audit-fqdn-foreign', True, 'foreign')]:
                c = clients[index]
                c.update(name=host, fqdn=host + '.' + suffix, fqdn_encoded=encoded)
                probe.one(c, host)
            clients[4]['name'] = 'audit_camera'
            probe.one(clients[4], 'underscore-name')
            clients[5]['name'] = 'Audit-Case'
            probe.one(clients[5], 'mixed-case-name')
        names = sorted({c['name'] for c in clients} | {'audit-client-%02d' % n for n in range(10)})
        for host in names:
            for target, qtype in [(host, 1), (host + '.lan', 1), (host + '.lan', 28)]:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                    endpoint.settimeout(3)
                    endpoint.sendto(query(target, qtype), (args.server, 53))
                    reply, peer = endpoint.recvfrom(65535)
                assert peer == (args.server, 53)
                decoded = semantics(reply)
                (args.out / ('dns-%03d.reply' % len(result['dns']))).write_bytes(reply)
                result['dns'].append(decoded)
        for c in clients:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(3)
                endpoint.sendto(query(ipaddress.ip_address(c['address']).reverse_pointer, 12), (args.server, 53))
                reply, _ = endpoint.recvfrom(65535)
            result['dns'].append(semantics(reply))
        if args.phase in ('hup', 'restart', 'crash-restart', 'takeover'):
            for c in clients:
                if c['key'] != '06':
                    probe.one(c, args.phase + '-renew-' + c['key'])
    except Exception as error:
        result['errors'].append(repr(error))
    finally:
        observer_stop.set()
        if observer_thread:
            observer_thread.join(4)
            result['concurrent_dns_during_dhcp'] = {
                'queries': len(observer_latencies), 'timeout_seconds': 3,
                'max_seconds': max(observer_latencies, default=None)}
        probe.raw.close()
        save(args.state, clients)
        save(args.out / 'result.json', result)
    return bool(result['errors'])


def run(args):
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert os.geteuid() == 0 and 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    config = Path('/var/etc/dnsmasq.conf.cfg01411c')
    leases = Path('/tmp/dhcp.leases')
    if leases.exists():
        (args.out / 'captured-initial-leases').write_bytes(leases.read_bytes())
    leases.unlink(missing_ok=True)
    state = args.out / 'clients.json'
    clients = [{'key': '%02d' % n, 'mac': '02000000a1%02x' % n,
                'name': 'audit-client-%02d' % n,
                'client_id': ('01' + '02000000a1%02x' % n) if n % 2 == 0 else
                'ff0102030400010001aabbccdd02000000a1%02x' % n} for n in range(10)]
    clients += [{'key': '10', 'mac': '02000000a10a', 'name': 'wpad'},
                {'key': '11', 'mac': '02000000a10b', 'name': 'localhost'}]
    if args.takeover_from:
        assert 'private' in args.takeover_from.resolve().parts
        leases.write_bytes((args.takeover_from / 'release.leases').read_bytes())
        clients = json.loads((args.takeover_from / 'clients.json').read_text())
    save(state, clients)
    result = {'errors': [], 'phases': [], 'exits': [], 'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'source_sha': args.source_sha, 'clients': len(clients)}
    if args.takeover_from:
        result['takeover_leasefile_sha256'] = hashlib.sha256(leases.read_bytes()).hexdigest()
    from ubus_contract_diff import Fixture
    from m2_rootfs import image_elf_command
    busout = args.out / 'ubus'
    busout.mkdir()
    bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), busout)
    daemon = None
    logs = []
    router = os.environ['DNSMASQ_ROUTER_ADDRESS']
    router_mac = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'br-lan']))[0]['address'].replace(':', '')
    observer_args = []
    if args.concurrent_dns:
        topology = json.loads((Path(os.environ['DNSMASQ_NETWORK_EVIDENCE']) / 'topology.json').read_text())
        network = ipaddress.IPv4Interface(topology['router']).network
        ranges = []
        for line in config.read_text().splitlines():
            if line.startswith('dhcp-range='):
                addresses = []
                for value in line.split('=', 1)[1].split(','):
                    try:
                        addresses.append(ipaddress.IPv4Address(value))
                    except ipaddress.AddressValueError:
                        pass
                if len(addresses) >= 2:
                    ranges.append(addresses[:2])
        assert ranges, 'cannot select an observer outside the actual DHCP pools'
        observer = next(address for address in network.hosts() if str(address) != router
                        and not any(start <= address <= end for start, end in ranges))
        observer_args = ['--observer', str(observer), '--observer-prefix', str(network.prefixlen)]

    def start():
        log = (args.out / ('daemon-%d.log' % len(logs))).open('wb')
        logs.append(log)
        argv = image_elf_command(args.image_root, args.binary)
        process = subprocess.Popen(argv + ['-C', str(config), '-k', '-x', '/var/run/dnsmasq/dnsmasq.cfg01411c.pid'], stdout=log, stderr=log)
        deadline = time.monotonic() + 8
        while True:
            assert process.poll() is None and time.monotonic() < deadline, 'daemon startup failed'
            try:
                with socket.create_connection((router, 53), .1):
                    break
            except OSError:
                time.sleep(.02)
        # Startup's asynchronous lease/hosts publication must settle before DNS.
        time.sleep(.15)
        assert process.poll() is None, 'daemon exited after opening DNS listeners'
        return process

    try:
        bus.start_bus()
        daemon = start()
        phases = ('initial', 'names') if args.names_only else (
            ('initial', 'short-lease', 'expired', 'reacquire') if args.expiry_only else (
                'initial', 'lifecycle', 'release', 'hup', 'restart', 'crash-restart'))
        if args.takeover_from:
            phases = ('takeover',)
        for phase in phases:
            if phase == 'expired':
                row = next(line.split() for line in leases.read_text().splitlines()
                           if line.split()[1] == '02:00:00:00:a1:09')
                deadline = int(row[0]) + 2
                while time.time() < deadline:
                    assert daemon.poll() is None, 'daemon died during idle expiry'
                    time.sleep(min(1, deadline - time.time()))
                (args.out / 'expired-before-network.leases').write_bytes(leases.read_bytes())
                result['idle_expiry_removed_before_query'] = not any(
                    line.split()[1] == '02:00:00:00:a1:09' for line in leases.read_text().splitlines())
                assert result['idle_expiry_removed_before_query'], 'expired lease retained without traffic'
            if phase == 'hup':
                daemon.send_signal(signal.SIGHUP)
                time.sleep(.2)
            if phase in ('restart', 'crash-restart'):
                daemon.send_signal(signal.SIGTERM if phase == 'restart' else signal.SIGKILL)
                result['exits'].append(daemon.wait(5))
                daemon = start()
            out = args.out / phase
            argv = ['nsenter', '-t', os.environ['DNSMASQ_CLIENT_PID'], '-n', sys.executable,
                    str(Path(__file__).resolve()), '--mode', 'client', '--phase', phase,
                    '--state', str(state), '--server', router, '--router-mac', router_mac, '--out', str(out), *observer_args]
            process = subprocess.run(argv, capture_output=True, text=True, timeout=100)
            save(args.out / (phase + '-process.json'), {'exit': process.returncode, 'stderr': process.stderr, 'stdout': process.stdout})
            value = json.loads((out / 'result.json').read_text())
            rows = []
            if leases.exists():
                (args.out / (phase + '.leases')).write_bytes(leases.read_bytes())
                now = int(time.time())
                for line in leases.read_text().splitlines():
                    row = line.split()
                    if len(row) == 5:
                        rows.append({'mac': row[1], 'address': row[2], 'name': row[3], 'client_id': row[4],
                                     'remaining': int(row[0]) - now})
            value['leases'] = sorted(rows, key=lambda r: r['mac'])
            result['phases'].append(value)
            if process.returncode or value['errors']:
                raise AssertionError((phase, process.returncode, value['errors']))
        assert daemon.poll() is None, 'daemon died'
    except Exception as error:
        result['errors'].append(repr(error))
    finally:
        if daemon and daemon.poll() is None:
            daemon.terminate()
            try:
                result['exits'].append(daemon.wait(5))
            except subprocess.TimeoutExpired:
                daemon.kill()
                result['errors'].append('daemon required forced termination')
                result['exits'].append(daemon.wait(5))
        for log in logs:
            log.close()
        bus.close()
        save(args.out / 'result.json', result)
    print(json.dumps({'errors': result['errors'], 'phases': len(result['phases']),
                      'dhcp_replies': sum(len(p['dhcp']) for p in result['phases']),
                      'dns_queries': sum(len(p['dns']) for p in result['phases']), 'exits': result['exits']}))
    return bool(result['errors'])


def compare(args):
    """Emit only derived results: private addresses/lease rows stay private."""
    c = json.loads(args.c_result.read_text())
    rust = json.loads(args.rust_result.read_text())
    result = {'c_sha256': c['binary_sha256'], 'rust_sha256': rust['binary_sha256'],
              'source_sha': rust['source_sha'], 'config_sha256': c['config_sha256'],
              'input_sha256': {side: hashlib.sha256(path.read_bytes()).hexdigest()
                               for side, path in [('c', args.c_result), ('rust', args.rust_result)]},
              'phases': [], 'differences': [], 'harness_errors': c['errors'] + rust['errors'],
              'normalization': ['DHCP responses matched by transaction label; option order preserved',
                                'Full DHCP payload compared after masking validated renewal timer bytes only',
                                'Renew/rebind random T1/T2 compared by exact C shared-jitter rule',
                                'Lease relative-expiry differences bounded to five seconds'],
              'exit_codes': {'c': c['exits'], 'rust': rust['exits']}}
    if c['config_sha256'] != rust['config_sha256']:
        result['differences'].append('configuration identity')
    if 'takeover_leasefile_sha256' in c or 'takeover_leasefile_sha256' in rust:
        result['takeover_leasefile_sha256'] = {
            side: value.get('takeover_leasefile_sha256') for side, value in [('c', c), ('rust', rust)]}
        if c.get('takeover_leasefile_sha256') != rust.get('takeover_leasefile_sha256'):
            result['differences'].append('C takeover input identity')
    if len(c['phases']) != len(rust['phases']):
        result['differences'].append('phase count')
    for cp, rp in zip(c['phases'], rust['phases']):
        phase = {'name': cp['phase'], 'c_dhcp': len(cp['dhcp']), 'rust_dhcp': len(rp['dhcp']),
                 'c_dns': len(cp['dns']), 'rust_dns': len(rp['dns']),
                 'c_leases': len(cp['leases']), 'rust_leases': len(rp['leases']),
                 'renewal_jitter_pairs': 0, 'wire_pairs': 0, 'max_expiry_difference_seconds': 0,
                 'differences': []}
        if cp['phase'] != rp['phase']:
            phase['differences'].append('phase name')
        cm = {r['label']: r for r in cp['dhcp']}
        rm = {r['label']: r for r in rp['dhcp']}
        if cm.keys() != rm.keys():
            phase['differences'].append('DHCP transaction set')
        for label in cm.keys() & rm.keys():
            a, b = copy.deepcopy(cm[label]), copy.deepcopy(rm[label])
            randomized = a['ciaddr'] != '0.0.0.0' and a['type'] == 5 and 58 in dict(a['options'])
            if randomized:
                for side, row in [('c', a), ('rust', b)]:
                    opts = {code: int(value, 16) for code, value in row['options'] if code in (51, 58, 59)}
                    if opts.keys() != {51, 58, 59}:
                        phase['differences'].append(label + ': ' + side + ' missing timers')
                        continue
                    length, t1, t2 = opts[51], opts[58], opts[59]
                    fuzz = length // 2 - t1
                    if not (0 <= fuzz <= (length // 2) // 8 and (length * 7) // 8 - t2 == fuzz):
                        phase['differences'].append(label + ': ' + side + ' renewal jitter rule')
                    row['options'] = [[code, 'validated-random-timer' if code in (58, 59) else value]
                                      for code, value in row['options']]
                phase['renewal_jitter_pairs'] += 1
            if a != b:
                phase['differences'].append(label + ': DHCP semantics')
            payloads = []
            for source in (args.c_result, args.rust_result):
                payload = bytearray((source.parent / cp['phase'] / (label + '.reply')).read_bytes())
                if randomized:
                    offset = 240
                    while offset < len(payload):
                        code = payload[offset]
                        offset += 1
                        if code == 255:
                            break
                        if code == 0:
                            continue
                        length = payload[offset]
                        offset += 1
                        if code in (58, 59):
                            payload[offset:offset + length] = bytes(length)
                        offset += length
                payloads.append(payload)
            phase['wire_pairs'] += 1
            if payloads[0] != payloads[1]:
                phase['differences'].append(label + ': full DHCP payload')
        if cp['dns'] != rp['dns']:
            for index, (a, b) in enumerate(zip(cp['dns'], rp['dns'])):
                if a != b:
                    phase['differences'].append('DNS query index %d' % index)
            if len(cp['dns']) != len(rp['dns']):
                phase['differences'].append('DNS query count')
        if len(cp['leases']) != len(rp['leases']):
            phase['differences'].append('lease count')
        for a, b in zip(cp['leases'], rp['leases']):
            delta = abs(a['remaining'] - b['remaining'])
            phase['max_expiry_difference_seconds'] = max(phase['max_expiry_difference_seconds'], delta)
            if delta > 5:
                phase['differences'].append('lease expiration delta')
            if {k: v for k, v in a.items() if k != 'remaining'} != {k: v for k, v in b.items() if k != 'remaining'}:
                phase['differences'].append('lease identity/name/address')
        result['phases'].append(phase)
        if 'concurrent_dns_during_dhcp' in cp or 'concurrent_dns_during_dhcp' in rp:
            phase['concurrent_dns_during_dhcp'] = {
                side: value.get('concurrent_dns_during_dhcp') for side, value in [('c', cp), ('rust', rp)]}
        result['differences'].extend(cp['phase'] + ': ' + item for item in phase['differences'])
    if 'idle_expiry_removed_before_query' in c or 'idle_expiry_removed_before_query' in rust:
        result['idle_expiry_removed_before_query'] = {side: value.get('idle_expiry_removed_before_query')
                                                    for side, value in [('c', c), ('rust', rust)]}
        if result['idle_expiry_removed_before_query'] != {'c': True, 'rust': True}:
            result['differences'].append('idle lease expiration')
    args.out.mkdir(parents=True, exist_ok=True)
    save(args.out / 'comparison.json', result)
    print(json.dumps({'differences': len(result['differences']), 'harness_errors': len(result['harness_errors']),
                      'dhcp_pairs': sum(p['c_dhcp'] for p in result['phases']),
                      'dns_pairs': sum(p['c_dns'] for p in result['phases'])}))
    return bool(result['differences'] or result['harness_errors'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['run', 'client', 'compare'], default='run')
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--binary', type=Path)
    p.add_argument('--image-root', type=Path)
    p.add_argument('--reference-build', type=Path)
    p.add_argument('--source-sha')
    p.add_argument('--expiry-only', action='store_true')
    p.add_argument('--names-only', action='store_true')
    p.add_argument('--takeover-from', type=Path)
    p.add_argument('--concurrent-dns', action='store_true')
    p.add_argument('--observer')
    p.add_argument('--observer-prefix')
    p.add_argument('--phase')
    p.add_argument('--state', type=Path)
    p.add_argument('--server')
    p.add_argument('--router-mac')
    p.add_argument('--c-result', type=Path)
    p.add_argument('--rust-result', type=Path)
    args = p.parse_args()
    return {'run': run, 'client': client, 'compare': compare}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
