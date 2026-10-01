#!/usr/bin/env python3
"""Actual UCI config: one DHCP lease, leasefile, local A/PTR and upstream DNS.

Run inside the private rootfs/ubus fixture and actual_config_network.py. The
original config, interfaces, DNS/DHCP ports and resolver file stay intact.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from dhcp_boot_service_diff import options
from dns_service_probe import exact_read, name, query, read_name, rr, semantics


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def upstream(args):
    sockets, rows = [], []
    for line in args.resolv.read_text().splitlines():
        fields = line.split()
        if fields[:1] != ['nameserver']:
            continue
        address = ipaddress.ip_address(fields[1])
        endpoint = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        endpoint.bind((str(address), 53))
        sockets.append(endpoint)
    assert sockets, 'no actual resolvers'
    args.out.mkdir(parents=True)
    save_json(args.out / 'ready.json', [list(endpoint.getsockname()) for endpoint in sockets])
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        while True:
            ready, _, _ = select.select(sockets, [], [], .2)
            for endpoint in ready:
                packet, peer = endpoint.recvfrom(65535)
                host, end = read_name(packet, 12)
                kind, cls = struct.unpack_from('!HH', packet, end)
                assert host == 'northstar-upstream.example' and kind == 1 and cls == 1, (host, kind, cls)
                response = packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
                response += packet[12:end + 4] + rr(1, socket.inet_aton('8.8.4.4'), 120)
                rows.append({'name': host, 'type': kind, 'peer': list(peer)})
                (args.out / f'{len(rows):02}.request').write_bytes(packet)
                (args.out / f'{len(rows):02}.reply').write_bytes(response)
                save_json(args.out / 'queries.json', rows)
                endpoint.sendto(response, peer)
    finally:
        for endpoint in sockets:
            endpoint.close()


def dhcp_request(kind, xid, hardware, hostname, offered=None, server=None):
    packet = bytearray(240)
    packet[:3] = bytes([1, 1, 6])
    packet[4:8] = struct.pack('!I', xid)
    packet[10:12] = b'\x80\0'
    packet[28:34] = hardware
    packet[236:240] = bytes.fromhex('63825363')
    packet.extend(bytes([53, 1, kind, 55, 9, 1, 3, 6, 12, 15, 28, 51, 58, 59]))
    value = hostname.encode('ascii')
    packet.extend(bytes([12, len(value)]) + value)
    if offered is not None:
        packet.extend(bytes([50, 4]) + socket.inet_aton(offered))
    if server is not None:
        packet.extend(bytes([54, 4]) + socket.inet_aton(server))
    packet.append(255)
    return bytes(packet)


def receive_dhcp(raw, xid):
    deadline = time.monotonic() + 8
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('DHCP reply missing on client0')
        raw.settimeout(remaining)
        frame = raw.recv(65535)
        if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            continue
        header = (frame[14] & 15) * 4
        udp = 14 + header
        if header < 20 or len(frame) < udp + 8:
            continue
        source, destination, length = struct.unpack_from('!HHH', frame, udp)
        if (source, destination) != (67, 68) or length < 248 or len(frame) < udp + length:
            continue
        packet = frame[udp + 8:udp + length]
        if packet[4:8] == struct.pack('!I', xid):
            return packet, (socket.inet_ntoa(frame[26:30]), source), frame


def client(args):
    args.out.mkdir(parents=True)
    hardware = bytes.fromhex('020000003301')
    subprocess.run(['ip', 'link', 'set', 'client0', 'address', '02:00:00:00:33:01'], check=True)
    result = {'dhcp': [], 'dns': [], 'errors': []}
    try:
        # An unconfigured IPv4 interface cannot deliver the OFFER to an
        # ordinary UDP socket. Like udhcpc, receive DHCP from Ethernet until
        # ACK has established the address; DNS then uses ordinary UDP.
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            raw.bind(('client0', 0))
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, 25, b'client0\0')
            endpoint.bind(('0.0.0.0', 68))
            endpoint.settimeout(8)
            offered = server = None
            for kind, label, expected in [(1, 'offer', 2), (3, 'ack', 5)]:
                xid = 0x53310000 + kind
                packet = dhcp_request(kind, xid, hardware, args.hostname, offered, server)
                (args.out / f'{label}.request').write_bytes(packet)
                sent = time.time()
                endpoint.sendto(packet, ('255.255.255.255', 67))
                reply, peer, frame = receive_dhcp(raw, xid)
                received = time.time()
                (args.out / f'{label}.ethernet').write_bytes(frame)
                (args.out / f'{label}.reply').write_bytes(reply)
                decoded = options(reply)
                lookup = {code: bytes.fromhex(value) for code, value in decoded}
                assert reply[0] == 2 and reply[4:8] == packet[4:8]
                assert lookup[53] == bytes([expected]) and peer[1] == 67
                address = socket.inet_ntoa(reply[16:20])
                if offered is not None:
                    assert address == offered
                offered, server = address, socket.inet_ntoa(lookup[54])
                assert server == args.server
                result['dhcp'].append({'kind': label, 'fixed': reply[:4].hex(), 'flags': reply[10:12].hex(),
                    'ciaddr': reply[12:16].hex(), 'address': offered, 'siaddr': reply[20:24].hex(),
                    'giaddr': reply[24:28].hex(), 'hardware': reply[28:44].hex(), 'options': decoded})
                result['ack_window'] = [sent, received]
            result['lease_seconds'] = int.from_bytes(lookup[51], 'big')
            mask = socket.inet_ntoa(lookup[1])
            prefix = ipaddress.IPv4Network(f'0.0.0.0/{mask}').prefixlen
            subprocess.run(['ip', 'addr', 'add', f'{offered}/{prefix}', 'dev', 'client0'], check=True)
        targets = [(args.hostname + '.lan', 1), (args.hostname, 1),
                   (ipaddress.ip_address(offered).reverse_pointer, 12), ('northstar-upstream.example', 1)]
        for host, kind in targets:
            packet = query(host, kind)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(3)
                endpoint.sendto(packet, (args.server, 53))
                reply, peer = endpoint.recvfrom(65535)
            (args.out / f'dns-{len(result["dns"])+1}.request').write_bytes(packet)
            (args.out / f'dns-{len(result["dns"])+1}.reply').write_bytes(reply)
            decoded = semantics(reply)
            result['dns'].append(decoded)
            assert decoded['flags'] & 15 == 0 and peer == (args.server, 53)
            answers = [row for row in decoded['records'] if row['section'] == 'answer']
            if kind == 12:
                assert any(row['type'] == 12 and row['data'] == args.hostname + '.lan' for row in answers)
            else:
                expected = '8.8.4.4' if host == 'northstar-upstream.example' else offered
                assert any(row['type'] == 1 and row['data'] == expected for row in answers)
    except Exception as error:
        result['errors'].append(repr(error))
    save_json(args.out / 'result.json', result)
    return bool(result['errors'])


def run(args):
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    client_pid = os.environ['DNSMASQ_CLIENT_PID']
    upstream_pid = os.environ['DNSMASQ_UPSTREAM_PID']
    router = os.environ['DNSMASQ_ROUTER_ADDRESS']
    executable = str(Path(__file__).resolve())
    children, logs, errors = [], [], []
    result = {'errors': errors, 'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest()}
    bus = None
    try:
        from types import SimpleNamespace
        from ubus_contract_diff import Fixture
        bus_out = args.out / 'ubus'
        bus_out.mkdir()
        bus = Fixture(SimpleNamespace(reference_build=args.reference_build, compiler='/usr/bin/gcc'), bus_out)
        bus.start_bus()
        for label, command in [
            ('upstream', ['nsenter', '-t', upstream_pid, '-n', sys.executable, executable, '--mode', 'upstream',
                          '--out', str(args.out / 'upstream'), '--resolv', str(args.resolv)]),
            ('daemon', [str(args.binary.resolve()), '-C', str(args.config), '-k', '-x', str(args.pidfile)])]:
            if label == 'daemon':
                deadline = time.monotonic() + 5
                while not (args.out / 'upstream/ready.json').exists():
                    assert children[0].poll() is None and time.monotonic() < deadline, 'upstream startup'
                    time.sleep(.02)
            log = (args.out / f'{label}.log').open('wb')
            logs.append(log)
            children.append(subprocess.Popen(command, stdout=log, stderr=log))
        daemon = children[1]
        deadline = time.monotonic() + 8
        while True:
            assert daemon.poll() is None and time.monotonic() < deadline, 'daemon startup'
            try:
                with socket.create_connection((router, 53), .1):
                    break
            except OSError:
                time.sleep(.02)
        status = Path(f'/proc/{daemon.pid}/status').read_text()
        deadline = time.monotonic() + 5
        while not any(row.get('event') == 'lookup' for row in bus.client_call('lookup', path='dnsmasq')):
            assert daemon.poll() is None and time.monotonic() < deadline, 'ubus registration'
            time.sleep(.02)
        result['ubus_registered'] = True
        (args.out / 'daemon.status').write_text(status)
        credentials = {line.split(':', 1)[0]: line.split()[1:] for line in status.splitlines() if line.startswith(('Uid:', 'Gid:'))}
        assert credentials == {'Uid': ['453'] * 4, 'Gid': ['453'] * 4}, credentials
        result['credentials'] = credentials
        command = ['nsenter', '-t', client_pid, '-n', sys.executable, executable, '--mode', 'client',
                   '--out', str(args.out / 'client'), '--server', router, '--hostname', args.hostname]
        response = subprocess.run(command, capture_output=True, text=True, timeout=30)
        save_json(args.out / 'client-process.json', {'exit': response.returncode, 'stdout': response.stdout, 'stderr': response.stderr})
        client_path = args.out / 'client/result.json'
        client_result = json.loads(client_path.read_text()) if client_path.exists() else {}
        result['client'] = client_result
        response.check_returncode()
        leases = args.leasefile.read_bytes()
        (args.out / 'dhcp.leases').write_bytes(leases)
        rows = [line.split() for line in leases.splitlines()]
        matching = [row for row in rows if len(row) == 5 and row[1] == b'02:00:00:00:33:01']
        assert len(matching) == 1, 'completed client lease missing or duplicated'
        row = matching[0]
        assert row[2].decode() == client_result['dhcp'][-1]['address'] and row[3].decode() == args.hostname
        expiry = int(row[0])
        sent, received = client_result['ack_window']
        duration = client_result['lease_seconds']
        assert int(sent) + duration - 1 <= expiry <= int(received) + duration + 1, 'leasefile expiry'
        result['lease'] = [field.decode() for field in row[1:]]
        result['lease_expiry_valid'] = True
        result['upstream'] = json.loads((args.out / 'upstream/queries.json').read_text())
        assert len(result['upstream']) == 1, 'unexpected upstream forwarding'
    except Exception as error:
        errors.append(repr(error))
    finally:
        for process in reversed(children):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                errors.append('process required SIGKILL')
        result['exit_codes'] = [process.returncode for process in children]
        for log in logs:
            log.close()
        if bus is not None:
            bus.close()
            save_json(args.out / 'ubus/checks.json', bus.checks)
            errors.extend(check for check in bus.checks if not check['pass'])
    if args.reference and not errors:
        reference = json.loads(args.reference.read_text())
        for key in ['lease', 'lease_expiry_valid', 'exit_codes', 'credentials', 'ubus_registered']:
            if result[key] != reference[key]:
                errors.append({'field': key, 'reference': reference[key], 'actual': result[key]})
        for key in ['dhcp', 'dns', 'lease_seconds']:
            if result['client'][key] != reference['client'][key]:
                errors.append({'field': 'client.' + key, 'reference': reference['client'][key], 'actual': result['client'][key]})
    save_json(args.out / 'result.json', result)
    print(json.dumps({'errors': len(errors), 'dhcp': len(result.get('client', {}).get('dhcp', [])),
                      'dns': len(result.get('client', {}).get('dns', [])), 'leasefile': result.get('lease_expiry_valid', False)}))
    return bool(errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['run', 'client', 'upstream'], default='run')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--reference-build', type=Path)
    parser.add_argument('--config', type=Path, default=Path('/var/etc/dnsmasq.conf.cfg01411c'))
    parser.add_argument('--pidfile', type=Path, default=Path('/var/run/dnsmasq/dnsmasq.cfg01411c.pid'))
    parser.add_argument('--leasefile', type=Path, default=Path('/tmp/dhcp.leases'))
    parser.add_argument('--resolv', type=Path, default=Path('/tmp/resolv.conf.d/resolv.conf.auto'))
    parser.add_argument('--hostname', default='northstar-client')
    parser.add_argument('--server')
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    return {'run': run, 'client': client, 'upstream': upstream}[args.mode](args)


if __name__ == '__main__':
    raise SystemExit(main())
