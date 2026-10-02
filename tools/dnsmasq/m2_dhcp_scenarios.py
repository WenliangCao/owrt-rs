#!/usr/bin/env python3
"""Frozen real-packet M2 DHCP scenarios, run only in disposable namespaces.

The same plan runs image C and Rust release inside m2_rootfs. Twenty macvlan
clients have independent MAC/IP identities. Packet and runtime data stay private.
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

from dhcp_boot_service_diff import options
from dns_service_probe import query, semantics
from m2_rootfs import command, prepare, process_identity

CONFIG = 'var/etc/dnsmasq.conf.cfg01411c'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mac(client):
    return f'02:00:00:4d:32:{client:02x}'


def freeze(args):
    source = (args.runtime_root / CONFIG).read_text()
    range_line = next(line for line in source.splitlines() if line.startswith('dhcp-range='))
    parts = range_line.split(',')
    first, last = map(ipaddress.IPv4Address, parts[1:3])
    network = ipaddress.IPv4Network(f'{first}/{parts[3]}', strict=False)
    address = lambda offset: str(first + offset)
    clients = {str(n): {'id': n, 'mac': mac(n), 'hostname': f'm2-client-{n:02}',
                        'address': address(n - 1)} for n in range(1, 25)}
    def event(action, client=None, **extra):
        return dict(action=action, **({'client': client} if client is not None else {}), **extra)
    actual = [event('dora', n) for n in range(1, 21)]
    actual += [event('snapshot', label='twenty', active=list(range(1, 21)))]
    actual += [event('dns', n, present=True) for n in range(1, 21)]
    actual += [event('renew', n) for n in range(1, 6)]
    actual += [event('rebind', n) for n in range(6, 11)]
    actual += [event('snapshot', label='renew-rebind', active=list(range(1, 21)))]
    actual += [event('release', n) for n in (19, 20)]
    actual += [event('decline', 18), event('snapshot', label='removed', active=list(range(1, 18)))]
    actual += [event('dns', n, present=False) for n in (18, 19, 20)]
    actual += [event('restart'), event('snapshot', label='recovered', active=list(range(1, 18)))]
    actual += [event('dns', n, present=True) for n in range(1, 18)]
    actual += [event('renew', 1), event('snapshot', label='recovered-renew', active=list(range(1, 18)))]
    static_clients = copy.deepcopy(clients)
    for n, offset, name in [(21, 140, 'm2-static'), (22, 141, 'm2-ethers-ip'), (23, 142, 'm2-ethers-name')]:
        static_clients[str(n)].update(address=address(offset), hostname=name)
    profiles = {
        'actual20': {'description': 'Unchanged captured config; 20 independent macvlan clients',
                     'clients': clients, 'events': actual},
        'static-ethers': {'description': 'Explicit synthetic static, ethers IP and ethers hosts-name overlays',
            'clients': static_clients,
            'config_append': f'dhcp-host={mac(21)},{address(140)},m2-static,12h\n',
            'ethers_append': f'{mac(22)} {address(141)}\n{mac(23)} m2-ethers-name\n',
            'hosts_append': f'{address(142)} m2-ethers-name\n',
            'events': [event('dora', n) for n in (21, 22, 23)] +
                      [event('snapshot', label='static', active=[21, 22, 23]), event('restart'),
                       event('snapshot', label='static-recovered', active=[21, 22, 23])] +
                      [event('dns', n, present=True) for n in (21, 22, 23)] +
                      [event('renew', 21), event('rebind', 22)]},
        'expiry120': {'description': 'Same rules, explicitly replace range lease duration with C minimum 120s; real clock wait',
            'clients': clients, 'range_replace': ','.join(parts[:-1] + ['120s']),
            'events': [event('dora', 1), event('snapshot', label='before-expiry', active=[1]),
                       event('dns', 1, present=True), event('wait-expiry'),
                       event('snapshot', label='expired-idle', active=[]), event('dns', 1, present=False)]},
        'ping-conflict': {'description': 'Same rules with explicit two-address pool; first address occupied by real kernel ICMP responder',
            'clients': {'24': dict(clients['24'], address=address(130))},
            'range_replace': ','.join([parts[0], address(130), address(131), *parts[3:]]),
            'conflict_address': address(130), 'expected_address': address(131),
            'events': [event('conflict-up'), event('dora', 24), event('snapshot', label='conflict-avoided', active=[24]),
                       event('dns', 24, present=True)]},
    }
    plan = {'version': 1, 'source_config_sha256': digest(args.runtime_root / CONFIG),
            'router_cidr': args.router_cidr, 'range': [str(first), str(last)],
            'network': str(network), 'profiles': profiles,
            'normalization': 'XID and epoch expiry excluded; expiry validated against ACK clock; renewal T1/T2 checked against C fuzz bounds; all other DHCP fields/options including order retained. DNS TTL validated against lease remaining time, then excluded. Lease row order excluded. Ping timing/count may vary; echo request and reply for occupied address mandatory.'}
    args.plan.parent.mkdir(parents=True, exist_ok=True)
    assert not args.plan.exists(), 'frozen plan already exists'
    save(args.plan, plan)
    print(json.dumps({'plan': str(args.plan), 'sha256': digest(args.plan), 'profiles': list(profiles)}))


def ip(*args, check=True):
    return subprocess.run(['ip', *args], check=check, capture_output=True, text=True)


def make_client(client):
    interface = f'm2c{client["id"]}'
    if ip('link', 'show', interface, check=False).returncode:
        ip('link', 'add', 'link', 'client0', 'name', interface, 'type', 'macvlan', 'mode', 'bridge')
        ip('link', 'set', interface, 'address', client['mac'])
        ip('link', 'set', interface, 'up')
    return interface


def request(kind, client, xid, server, action, address):
    data = bytearray(240)
    data[:3] = bytes([1, 1, 6])
    data[4:8] = struct.pack('!I', xid)
    if action in ('discover', 'select', 'rebind', 'decline'):
        data[10:12] = b'\x80\0'
    data[28:34] = bytes.fromhex(client['mac'].replace(':', ''))
    data[236:240] = bytes.fromhex('63825363')
    data.extend(bytes([53, 1, kind, 55, 9, 1, 3, 6, 12, 15, 28, 51, 58, 59]))
    hostname = client['hostname'].encode()
    if kind in (1, 3):
        data.extend(bytes([12, len(hostname)]) + hostname)
    if action in ('discover', 'select', 'decline'):
        data.extend(bytes([50, 4]) + socket.inet_aton(address))
    else:
        data[12:16] = socket.inet_aton(address)
    if action in ('select', 'release', 'decline'):
        data.extend(bytes([54, 4]) + socket.inet_aton(server))
    return bytes(data + b'\xff')


def receive(raw, xid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw.settimeout(deadline - time.monotonic())
        frame = raw.recv(65535)
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            continue
        offset = 14 + (frame[14] & 15) * 4
        source, destination, length = struct.unpack_from('!HHH', frame, offset)
        packet = frame[offset + 8:offset + length]
        if (source, destination) == (67, 68) and len(packet) >= 240 and packet[4:8] == struct.pack('!I', xid):
            return packet, frame
    raise socket.timeout()


def exchange(client, interface, action, address, server, out, xid):
    kind = {'discover': 1, 'select': 3, 'renew': 3, 'rebind': 3, 'decline': 4, 'release': 7}[action]
    data = request(kind, client, xid, server, action, address)
    (out / f'{action}.request').write_bytes(data)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        raw.bind((interface, 0))
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, 25, interface.encode() + b'\0')
        endpoint.bind((address if action in ('renew', 'rebind', 'release') else '0.0.0.0', 68))
        destination = server if action in ('renew', 'release') else '255.255.255.255'
        sent = time.time()
        endpoint.sendto(data, (destination, 67))
        if kind in (4, 7):
            try:
                answer, frame = receive(raw, xid, .4)
                (out / f'{action}.unexpected').write_bytes(frame)
                raise AssertionError('unexpected DECLINE/RELEASE response')
            except socket.timeout:
                return {'action': action, 'reply': None, 'sent': sent}
        answer, frame = receive(raw, xid, 8)
        received = time.time()
        (out / f'{action}.reply').write_bytes(answer)
        (out / f'{action}.ethernet').write_bytes(frame)
        decoded = options(answer)
        lookup = {code: bytes.fromhex(value) for code, value in decoded}
        assert answer[0] == 2 and lookup[53] == bytes([2 if kind == 1 else 5])
        assert socket.inet_ntoa(lookup[54]) == server
        offered = socket.inet_ntoa(answer[16:20])
        duration = int.from_bytes(lookup[51], 'big')
        t1, t2 = [int.from_bytes(lookup[code], 'big') for code in (58, 59)]
        fuzz = duration // 2 - t1
        assert t2 - t1 == duration * 7 // 8 - duration // 2
        assert (0 <= fuzz <= duration // 16) if action in ('renew', 'rebind') else fuzz == 0
        semantic = {'action': action, 'fixed': answer[:4].hex(), 'flags': answer[10:12].hex(),
                    'ciaddr': answer[12:16].hex(), 'address': offered, 'siaddr': answer[20:24].hex(),
                    'giaddr': answer[24:28].hex(), 'hardware': answer[28:44].hex(),
                    'options': [row for row in decoded if row[0] not in (58, 59)]}
        return {'semantic': semantic, 'timers': [t1, t2], 'lease_seconds': duration, 'sent': sent, 'received': received}


def client_worker(args):
    data = json.load(sys.stdin)
    event, client, server = data['event'], data['client'], data['server']
    interface = make_client(client)
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    action = event['action']
    if action == 'dns':
        result = []
        for host, kind in [(client['hostname'] + '.lan', 1), (ipaddress.ip_address(client['address']).reverse_pointer, 12)]:
            packet = query(host, kind)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(3)
                endpoint.setsockopt(socket.SOL_SOCKET, 25, interface.encode() + b'\0')
                endpoint.bind((client['address'], 0))
                endpoint.sendto(packet, (server, 53))
                answer, _ = endpoint.recvfrom(65535)
            (out / f'dns-{kind}.request').write_bytes(packet)
            (out / f'dns-{kind}.reply').write_bytes(answer)
            decoded = semantics(answer)
            records = [row for row in decoded['records'] if row['section'] == 'answer']
            for record in decoded['records']:
                assert 0 <= record['ttl'] <= data['lease_remaining'] + 2, record
            expected = client['address'] if kind == 1 else client['hostname'] + '.lan'
            assert any(row['type'] == kind and row['data'] == expected for row in records) == event['present'], decoded
            result.append(decoded)
        print(json.dumps({'dns': result}))
        return
    replies = []
    address = client['address']
    actions = ['discover', 'select'] if action == 'dora' else [action]
    for index, step in enumerate(actions):
        row = exchange(client, interface, step, address, server, out, 0x4d320000 + data['event_index'] * 4 + index)
        replies.append(row)
        if 'semantic' in row:
            address = row['semantic']['address']
    if action == 'dora':
        ip('addr', 'replace', f'{address}/{data["prefix"]}', 'dev', interface)
    print(json.dumps({'replies': replies, 'address': address}))


class Capture:
    def __init__(self, out):
        self.out, self.rows, self.stop = out, [], threading.Event()
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.socket.bind(('br-lan', 0))
        self.socket.settimeout(.1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                frame = self.socket.recv(65535)
            except socket.timeout:
                continue
            if len(frame) >= 42 and frame[23] == 1:
                index = len(self.rows)
                (self.out / f'icmp-{index:04}.ethernet').write_bytes(frame)
                offset = 14 + (frame[14] & 15) * 4
                self.rows.append({'type': frame[offset], 'source': socket.inet_ntoa(frame[26:30]),
                                  'destination': socket.inet_ntoa(frame[30:34]), 'time': time.time()})

    def close(self):
        self.stop.set()
        self.thread.join(1)
        self.socket.close()
        save(self.out / 'icmp.json', self.rows)


def lease_rows(path):
    return [dict(zip(['expiry', 'mac', 'address', 'hostname', 'clientid'], line.split()))
            for line in path.read_text().splitlines() if line.strip()]


def run(args):
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    plan = json.loads(args.plan.read_text())
    profile = copy.deepcopy(plan['profiles'][args.profile])
    assert digest(args.runtime_root / CONFIG) == plan['source_config_sha256']
    root = prepare(args.image_root, args.runtime_root, args.out, args.rust_binary)
    config = root / CONFIG
    original = config.read_text()
    if 'range_replace' in profile:
        original = '\n'.join(profile['range_replace'] if line.startswith('dhcp-range=') else line for line in original.split('\n'))
    config.write_text(original + profile.get('config_append', ''))
    for relative, key in [('etc/ethers', 'ethers_append'), ('etc/hosts', 'hosts_append')]:
        if key in profile:
            with (root / relative).open('a') as stream:
                stream.write('\n' + profile[key])
    leasefile = root / 'tmp/dhcp.leases'
    leasefile.write_text('')
    os.chown(leasefile, 453, 453)
    result = {'implementation': args.implementation, 'profile': args.profile, 'plan_sha256': digest(args.plan),
              'config_sha256': digest(config), 'events': [], 'errors': [], 'processes': [], 'stops': []}
    tool_names = ['m2_dhcp_scenarios.py', 'm2_dhcp_suite.py', 'm2_rootfs.py', 'actual_config_network.py',
                  'dhcp_boot_service_diff.py', 'dns_service_probe.py']
    tool_root = Path(__file__).resolve().parent
    result['tool_sha256'] = {name: digest(tool_root / name) for name in tool_names}
    archive = args.out / 'tools'
    archive.mkdir()
    for name in tool_names:
        (archive / name).write_bytes((tool_root / name).read_bytes())
    save(args.out / 'profile.json', profile)
    daemon = bus = capture = None
    logs = []
    acknowledgements = {}
    def start(binary, *argv):
        log = (args.out / f'process-{len(logs)}.log').open('wb')
        logs.append(log)
        return subprocess.Popen(command(root, binary, *argv), stdout=log, stderr=log)
    def metrics():
        response = subprocess.run(command(root, '/bin/ubus', 'call', 'dnsmasq', 'metrics'), capture_output=True, text=True, timeout=3)
        response.check_returncode()
        return json.loads(response.stdout)
    def start_daemon():
        process = start(args.implementation, '-k', '-C', '/' + CONFIG, '-x', '/var/run/dnsmasq/m2.pid')
        deadline = time.monotonic() + 8
        while True:
            assert process.poll() is None and time.monotonic() < deadline, 'daemon readiness'
            try:
                metrics()
                break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                time.sleep(.05)
        result['processes'].append(process_identity(root, process.pid))
        return process
    def stop_daemon():
        daemon.send_signal(signal.SIGTERM)
        code = daemon.wait(5)
        result['stops'].append({'exit': code, 'reaped': not Path(f'/proc/{daemon.pid}').exists(),
                                'pid_removed': not (root / 'var/run/dnsmasq/m2.pid').exists()})
        assert code == 0 and result['stops'][-1]['reaped'] and result['stops'][-1]['pid_removed']
    try:
        bus = start('/sbin/ubusd', '-s', '/var/run/ubus/ubus.sock')
        deadline = time.monotonic() + 5
        while not (root / 'var/run/ubus/ubus.sock').exists():
            assert bus.poll() is None and time.monotonic() < deadline
            time.sleep(.02)
        capture = Capture(args.out)
        daemon = start_daemon()
        result['initial_metrics'] = metrics()
        for index, event in enumerate(profile['events']):
            print(json.dumps({'profile': args.profile, 'implementation': args.implementation, 'index': index, **event}), flush=True)
            item = {'index': index, 'event': event, 'wall': time.time()}
            result['events'].append(item)
            action = event['action']
            if action == 'snapshot':
                metrics()
                rows = lease_rows(leasefile)
                expected = {profile['clients'][str(n)]['mac'] for n in event['active']}
                assert {row['mac'] for row in rows} == expected, (rows, expected)
                for row in rows:
                    client = next(value for value in profile['clients'].values() if value['mac'] == row['mac'])
                    assert row['address'] == client['address'] and row['hostname'] == client['hostname']
                    ack = acknowledgements[row['mac']]
                    assert int(ack['sent']) + ack['lease_seconds'] - 1 <= int(row['expiry']) <= int(ack['received']) + ack['lease_seconds'] + 1
                item['leases'] = rows
                item['metrics'] = metrics()
                (args.out / f'{index:03}-{event["label"]}.leases').write_bytes(leasefile.read_bytes())
            elif action == 'restart':
                before = leasefile.read_bytes()
                stop_daemon()
                daemon = start_daemon()
                after = leasefile.read_bytes()
                item['before'] = before.decode()
                item['after'] = after.decode()
                assert sorted(before.splitlines()) == sorted(after.splitlines()), 'restart changed durable lease rows'
            elif action == 'wait-expiry':
                expiry = max(int(row['expiry']) for row in lease_rows(leasefile))
                started = time.monotonic()
                delay = max(0, expiry + 2 - time.time())
                assert 110 < delay <= 123, delay
                time.sleep(delay)
                item['elapsed'] = time.monotonic() - started
                item['expiry'] = expiry
                assert not lease_rows(leasefile), 'lease did not expire during idle real-clock wait'
            elif action == 'conflict-up':
                response = subprocess.run(['nsenter', '-t', os.environ['DNSMASQ_CLIENT_PID'], '-n', 'ip', 'addr', 'add',
                                           profile['conflict_address'] + '/' + plan['network'].split('/')[1], 'dev', 'client0'], capture_output=True, text=True)
                response.check_returncode()
                check = subprocess.run(['ping', '-c', '1', '-W', '2', profile['conflict_address']], capture_output=True, text=True)
                item['ping'] = {'exit': check.returncode, 'stdout': check.stdout, 'stderr': check.stderr}
                check.check_returncode()
                item['capture_before_discover'] = len(capture.rows)
            else:
                client = profile['clients'][str(event['client'])]
                request_data = {'event': event, 'event_index': index, 'client': client,
                                'server': os.environ['DNSMASQ_ROUTER_ADDRESS'], 'prefix': plan['network'].split('/')[1]}
                if action == 'dns':
                    ack = acknowledgements[client['mac']]
                    request_data['lease_remaining'] = max(0, int(ack['received'] + ack['lease_seconds'] - time.time()))
                response = subprocess.run(['nsenter', '-t', os.environ['DNSMASQ_CLIENT_PID'], '-n', sys.executable,
                                           str(Path(__file__).resolve()), 'client', '--out', str(args.out / f'event-{index:03}')],
                                          input=json.dumps(request_data), capture_output=True, text=True, timeout=25)
                item['worker'] = {'exit': response.returncode, 'stdout': response.stdout, 'stderr': response.stderr}
                response.check_returncode()
                observed = json.loads(response.stdout)
                item['observed'] = observed
                if 'replies' in observed:
                    if action == 'dora':
                        expected_address = profile.get('expected_address', client['address'])
                        assert observed['address'] == expected_address, observed
                        client['address'] = observed['address']
                    for reply in observed['replies']:
                        if reply.get('semantic', {}).get('action') in ('select', 'renew', 'rebind'):
                            acknowledgements[client['mac']] = reply
                item['metrics'] = metrics()
            save(args.out / 'result.json', result)
        result['final_metrics'] = metrics()
        if args.profile == 'ping-conflict':
            start_index = result['events'][0]['capture_before_discover']
            trace = capture.rows[start_index:]
            conflict = profile['conflict_address']
            assert any(row['type'] == 8 and row['destination'] == conflict for row in trace), 'daemon conflict ping not observed'
            assert any(row['type'] == 0 and row['source'] == conflict for row in trace), 'daemon conflict echo reply not observed'
            result['conflict_ping_verified'] = True
    except Exception as error:
        result['errors'].append(repr(error))
    finally:
        if daemon and daemon.poll() is None:
            try:
                stop_daemon()
            except Exception as error:
                result['errors'].append(repr(error))
        if bus and bus.poll() is None:
            bus.terminate()
            bus.wait(5)
        if capture:
            capture.close()
        for log in logs:
            log.close()
        save(args.out / 'result.json', result)
    print(json.dumps({'profile': args.profile, 'implementation': args.implementation, 'errors': result['errors']}))
    return bool(result['errors'])


def comparable(result):
    rows = []
    for item in result['events']:
        value = {'event': item['event']}
        if 'observed' in item:
            observed = item['observed']
            if 'replies' in observed:
                value['dhcp'] = [row['semantic'] if 'semantic' in row else {'action': row['action'], 'reply': None}
                                 for row in observed['replies']]
            if 'dns' in observed:
                value['dns'] = copy.deepcopy(observed['dns'])
                for reply in value['dns']:
                    for record in reply['records']:
                        record.pop('ttl', None)
        if 'leases' in item:
            value['leases'] = sorted([{key: val for key, val in row.items() if key != 'expiry'} for row in item['leases']], key=lambda row: row['mac'])
        if 'metrics' in item:
            value['metrics'] = item['metrics']
        rows.append(value)
    return {'events': rows, 'initial_metrics': result.get('initial_metrics'), 'final_metrics': result.get('final_metrics'),
            'stops': result['stops'], 'conflict_ping_verified': result.get('conflict_ping_verified')}


def compare(args):
    c, rust = [json.loads(path.read_text()) for path in (args.c_result, args.rust_result)]
    assert c['implementation'] == 'c' and rust['implementation'] == 'rust'
    left, right = comparable(c), comparable(rust)
    errors = []
    if c['errors'] or rust['errors']:
        errors.append({'source_errors': [c['errors'], rust['errors']]})
    if c['plan_sha256'] != rust['plan_sha256'] or c['config_sha256'] != rust['config_sha256']:
        errors.append('input identity mismatch')
    if left != right:
        errors.append({'semantic_difference': {'c': left, 'rust': right}})
    # Calibrate the comparator with a missing event and a changed DHCP option.
    missing = copy.deepcopy(right)
    missing['events'] = missing['events'][:-1]
    assert left != missing
    changed = copy.deepcopy(left)
    first = next(event for event in changed['events'] if event.get('dhcp'))
    first['dhcp'][0]['options'].append([254, 'bad'])
    assert left != changed
    result = {'profile': c['profile'], 'errors': errors, 'negative_controls': ['missing-event', 'changed-option'],
              'c_result': str(args.c_result), 'rust_result': str(args.rust_result),
              'c_binary': [row['sha256'] for row in c['processes']], 'rust_binary': [row['sha256'] for row in rust['processes']]}
    save(args.out, result)
    print(json.dumps({'profile': result['profile'], 'error_count': len(errors)}))
    return bool(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    parser_freeze = modes.add_parser('freeze')
    parser_freeze.add_argument('--runtime-root', type=Path, required=True)
    parser_freeze.add_argument('--router-cidr', required=True)
    parser_freeze.add_argument('--plan', type=Path, required=True)
    parser_client = modes.add_parser('client')
    parser_client.add_argument('--out', type=Path, required=True)
    parser_run = modes.add_parser('run')
    for option in ('image-root', 'runtime-root', 'rust-binary', 'plan', 'out'):
        parser_run.add_argument('--' + option, type=Path, required=True)
    parser_run.add_argument('--implementation', choices=['c', 'rust'], required=True)
    parser_run.add_argument('--profile', required=True)
    parser_compare = modes.add_parser('compare')
    for option in ('c-result', 'rust-result', 'out'):
        parser_compare.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    return {'freeze': freeze, 'client': client_worker, 'run': run, 'compare': compare}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
