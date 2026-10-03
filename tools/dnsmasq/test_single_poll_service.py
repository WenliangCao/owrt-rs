#!/usr/bin/env python3
"""Exact-image scheduling gate with one owned upstream silent for 10 seconds.

Use run_isolated.sh. The tool starts its own C/Rust daemons and creates a
private bridge/veth client; it accepts no target address. During one ordinary
TCP request, local UDP DNS and one DHCP DORA must each complete within 2 s.
All wire evidence, config and process identities remain under private/.
"""
from __future__ import annotations
import argparse
import contextlib
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
from dns_service_probe import exact_read, query, semantics
from m2_dhcp_scenarios import request, receive
from m2_rootfs import command, prepare, process_identity, sha256

HOLD_SECONDS = 10.0
ITEM_SECONDS = 2.0
SERVER = '10.77.0.1'
DNS_PORT = 15353
CLIENT = {'id': 1, 'mac': '02:00:00:4d:34:01', 'hostname': 'm4-single-owner', 'address': '10.77.0.10'}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def ip(*args):
    subprocess.run(['ip', *args], check=True, capture_output=True, text=True, timeout=3)


def stop(process):
    if process is None:
        return None
    forced = False
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(2)
    except subprocess.TimeoutExpired:
        forced = True
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(2)
    return {'pid': process.pid, 'returncode': process.returncode, 'forced': forced}


class Network:
    def __init__(self):
        self.client = None
        self.links = []

    def start(self):
        self.client = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'], start_new_session=True)
        deadline = time.monotonic() + 3
        while os.readlink(f'/proc/{self.client.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
            if self.client.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError('client namespace readiness')
            time.sleep(.01)
        self.exec('ip', 'link', 'set', 'lo', 'up')
        ip('link', 'add', 'br-lan', 'type', 'bridge')
        self.links.append('br-lan')
        ip('addr', 'add', SERVER + '/24', 'dev', 'br-lan')
        ip('link', 'set', 'br-lan', 'up')
        ip('link', 'add', 'lan-port', 'type', 'veth', 'peer', 'name', 'client0')
        self.links.append('lan-port')
        ip('link', 'set', 'lan-port', 'master', 'br-lan')
        ip('link', 'set', 'lan-port', 'up')
        ip('link', 'set', 'client0', 'netns', str(self.client.pid))
        self.exec('ip', 'link', 'set', 'client0', 'address', CLIENT['mac'])
        self.exec('ip', 'addr', 'add', '10.77.0.2/24', 'dev', 'client0')
        self.exec('ip', 'link', 'set', 'client0', 'up')

    def argv(self, *args):
        return ['nsenter', '-t', str(self.client.pid), '-n', *map(str, args)]

    def exec(self, *args):
        return subprocess.run(self.argv(*args), check=True, capture_output=True, text=True, timeout=3)

    def close(self):
        result = stop(self.client)
        for link in reversed(self.links):
            # Destroying the peer namespace can already remove its veth.
            present = subprocess.run(['ip', 'link', 'show', link], capture_output=True, timeout=3)
            if present.returncode == 0:
                ip('link', 'delete', link)
        return result


class DelayedUpstream:
    def __init__(self, out):
        self.out = out
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.received = threading.Event()
        self.cancel = threading.Event()
        self.row = {}
        self.connection = None
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        try:
            connection, _ = self.listener.accept()
            self.connection = connection
            with connection:
                connection.settimeout(3)
                size = struct.unpack('!H', exact_read(connection, 2))[0]
                packet = exact_read(connection, size)
                (self.out / 'upstream.request').write_bytes(packet)
                self.row['received_monotonic'] = time.monotonic()
                self.received.set()
                if self.cancel.wait(HOLD_SECONDS):
                    return
                # Both implementations use a ten-second TCP read timeout.
                # Closing after the silent interval avoids a success/timeout
                # race from injecting a reply at exactly that boundary.
                connection.shutdown(socket.SHUT_RDWR)
                self.row['closed_monotonic'] = time.monotonic()
                self.row['hold_seconds'] = self.row['closed_monotonic'] - self.row['received_monotonic']
        except Exception as error:
            if not self.cancel.is_set():
                self.row['error'] = repr(error)
        finally:
            save(self.out / 'upstream.json', self.row)

    def close(self):
        self.cancel.set()
        self.listener.close()
        if self.connection is not None:
            with contextlib.suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError('upstream did not stop')


def client(out):
    out.mkdir()
    result = {'udp': {}, 'dora': {}, 'passed': False}
    try:
        packet = query('local.test', ident=0x4411)
        (out / 'dns.request').write_bytes(packet)
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(ITEM_SECONDS)
            endpoint.sendto(packet, (SERVER, DNS_PORT))
            response, peer = endpoint.recvfrom(65535)
        finished = time.monotonic()
        decoded = semantics(response)
        (out / 'dns.reply').write_bytes(response)
        result['udp'] = {'started_monotonic': started, 'finished_monotonic': finished,
                         'seconds': finished - started, 'semantic': decoded, 'peer': list(peer)}
        assert finished - started < ITEM_SECONDS
        assert decoded['id'] == 0x4411 and decoded['flags'] & 15 == 0
        assert any(row['type'] == 1 and row['data'] == '192.0.2.7' for row in decoded['records'])
    except Exception as error:
        result['udp']['error'] = repr(error)
    try:
        rows = []
        started = time.monotonic()
        deadline = started + ITEM_SECONDS
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            raw.bind(('client0', 0))
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'client0\0')
            endpoint.bind(('0.0.0.0', 68))
            for kind, action, expected in [(1, 'discover', 2), (3, 'select', 5)]:
                xid = 0x44340000 + kind
                packet = request(kind, CLIENT, xid, SERVER, action, CLIENT['address'])
                (out / (action + '.request')).write_bytes(packet)
                endpoint.sendto(packet, ('255.255.255.255', 67))
                remaining = deadline - time.monotonic()
                assert remaining > 0, 'DORA deadline before response'
                response, ethernet = receive(raw, xid, remaining)
                (out / (action + '.reply')).write_bytes(response)
                (out / (action + '.ethernet')).write_bytes(ethernet)
                decoded = options(response)
                lookup = {code: bytes.fromhex(value) for code, value in decoded}
                assert lookup[53] == bytes([expected])
                assert lookup[54] == socket.inet_aton(SERVER)
                assert socket.inet_ntoa(response[16:20]) == CLIENT['address']
                rows.append({'action': action, 'fixed': response[:4].hex(), 'flags': response[10:12].hex(),
                             'address': socket.inet_ntoa(response[16:20]), 'options': decoded})
        finished = time.monotonic()
        result['dora'] = {'started_monotonic': started, 'finished_monotonic': finished,
                          'seconds': finished - started, 'semantic': rows}
        assert finished - started < ITEM_SECONDS
    except Exception as error:
        result['dora']['error'] = repr(error)
    result['passed'] = all('error' not in result[key] for key in ('udp', 'dora'))
    save(out / 'result.json', result)
    return int(not result['passed'])


def dns_ready(process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, 'daemon exited before readiness'
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(.1)
            endpoint.sendto(query('local.test'), ('127.0.0.1', DNS_PORT))
            try:
                endpoint.recv(65535)
                return
            except socket.timeout:
                pass
    raise AssertionError('daemon readiness deadline')


def run_side(args, root, network, side):
    out = args.out / side
    out.mkdir()
    row = {'side': side, 'passed': False}
    upstream = DelayedUpstream(out)
    daemon = probe = None
    log = None
    try:
        config = ('no-hosts\nno-resolv\nuser=root\ninterface=br-lan\n'
                  f'port={DNS_PORT}\nhost-record=local.test,192.0.2.7\n'
                  'dhcp-authoritative\nno-ping\ndhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,12h\n'
                  'dhcp-leasefile=/m2/owner.leases\npid-file=/m2/owner.pid\n'
                  f'server=127.0.0.1#{upstream.port}\n')
        (root / 'm2/owner.conf').write_text(config)
        (out / 'dnsmasq.conf').write_text(config)
        (root / 'm2/owner.leases').write_bytes(b'')
        log = (out / 'daemon.log').open('wb')
        daemon = subprocess.Popen(command(root, side, '-k', '-C', '/m2/owner.conf'),
                                  stdout=log, stderr=log, start_new_session=True)
        dns_ready(daemon)
        row['identity'] = process_identity(root, daemon.pid)
        probe = socket.create_connection(('127.0.0.1', DNS_PORT), timeout=3)
        packet = query('held.test', ident=0x4433)
        probe.sendall(struct.pack('!H', len(packet)) + packet)
        assert upstream.received.wait(3), 'upstream request missing'
        row['runtime'] = {
            'threads': len(list(Path(f'/proc/{daemon.pid}/task').iterdir())),
            'children': Path(f'/proc/{daemon.pid}/task/{daemon.pid}/children').read_text().split(),
        }
        response = subprocess.run(network.argv(sys.executable, Path(__file__).resolve(), '--client',
                                                '--out', out / 'client'),
                                  capture_output=True, text=True, timeout=7)
        save(out / 'client-process.json', {'returncode': response.returncode,
                                         'stdout': response.stdout, 'stderr': response.stderr})
        row['client'] = json.loads((out / 'client/result.json').read_text())
        # Complete the controlled upstream exchange even if the client gate
        # failed, retaining a full ten-second interval and bounded cleanup.
        probe.settimeout(HOLD_SECONDS + 2)
        size = struct.unpack('!H', exact_read(probe, 2))[0]
        response_packet = exact_read(probe, size)
        row['tcp'] = semantics(response_packet)
        (out / 'tcp.reply').write_bytes(response_packet)
        upstream.thread.join(1)
        row['upstream'] = dict(upstream.row)
        lease = (root / 'm2/owner.leases').read_bytes()
        (out / 'leases').write_bytes(lease)
        row['leases'] = [line.decode().split()[1:] for line in lease.splitlines()]
        end = row['upstream']['closed_monotonic']
        row['within_hold'] = all(value.get('finished_monotonic', end + 1) < end
                                 for value in row['client'].values() if isinstance(value, dict))
        row['passed'] = (row['client']['passed'] and row['within_hold']
                         and row['upstream']['hold_seconds'] >= HOLD_SECONDS
                         and row['tcp']['id'] == 0x4433 and row['tcp']['flags'] & 15 == 5
                         and len(row['leases']) == 1)
    except Exception as error:
        row['error'] = repr(error)
    finally:
        if probe is not None:
            probe.close()
        row['cleanup'] = stop(daemon)
        upstream.close()
        if log is not None:
            log.close()
        row['pidfile_removed'] = not (root / 'm2/owner.pid').exists()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            try:
                endpoint.bind(('0.0.0.0', 67))
                row['dhcp_port_released'] = True
            except OSError:
                row['dhcp_port_released'] = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.settimeout(.1)
            row['dns_port_released'] = endpoint.connect_ex(('127.0.0.1', DNS_PORT)) != 0
        if (not row['cleanup'] or row['cleanup']['forced'] or row['cleanup']['returncode'] != 0
                or not row['pidfile_removed'] or not row['dhcp_port_released'] or not row['dns_port_released']):
            row['passed'] = False
        save(out / 'result.json', row)
    return row


def normalized(row):
    return {'udp': row.get('client', {}).get('udp', {}).get('semantic'),
            'dora': row.get('client', {}).get('dora', {}).get('semantic'),
            'tcp': row.get('tcp'), 'leases': row.get('leases')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--client', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or os.geteuid() != 0:
        parser.error('run as root through run_isolated.sh')
    args.out = args.out.resolve()
    if 'private' not in args.out.parts:
        parser.error('evidence must be below private/')
    if args.client:
        return client(args.out)
    if not args.image_root or not args.rust:
        parser.error('--image-root and --rust are required')
    if sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        parser.error('start in a namespace containing only lo')
    args.out.mkdir(parents=True, exist_ok=False)
    plan = {'upstream_hold_seconds': HOLD_SECONDS, 'udp_deadline_seconds': ITEM_SECONDS,
            'dora_deadline_seconds': ITEM_SECONDS, 'clients': 1, 'no_ping': True,
            'upstream_end': 'close without reply after 10 seconds; C network-error REFUSED',
            'scope': 'single-owner TCP scheduling; ICMP coexistence is a separate gate',
            'tool_sha256': sha256(Path(__file__)), 'rust_sha256': sha256(args.rust)}
    save(args.out / 'plan.json', plan)
    network = Network()
    report = {'passed': False, 'plan': plan}
    try:
        root = prepare(args.image_root, None, args.out / 'rootfs-stage', args.rust)
        network.start()
        report['c'] = run_side(args, root, network, 'c')
        report['rust'] = run_side(args, root, network, 'rust')
        report['semantic_equal'] = normalized(report['c']) == normalized(report['rust'])
        report['passed'] = report['c']['passed'] and report['rust']['passed'] and report['semantic_equal']
    except Exception as error:
        report['error'] = repr(error)
    finally:
        try:
            report['network_cleanup'] = network.close()
        except Exception as error:
            report['network_cleanup_error'] = repr(error)
            report['passed'] = False
        report['remaining_interfaces'] = [name for _, name in socket.if_nameindex()]
        if sorted(report['remaining_interfaces']) != ['lo']:
            report['passed'] = False
        save(args.out / 'result.json', report)
    print(json.dumps({'passed': report['passed'], 'result': str(args.out / 'result.json')}))
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
