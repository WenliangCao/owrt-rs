#!/usr/bin/env python3
"""Compare DNS/TFTP progress during a real DHCP ICMP wait in the exact image.

Only run through run_isolated.sh. A newly created bridge/veth network delivers
the daemon's normal probe to an unconfigured address; no host replies. The
client must observe the outgoing Echo before starting 20 valid local DNS queries
and, with --with-tftp, a complete four-block download. Each must finish within
one second and before OFFER. This tests C dnsmasq.c::delay_dhcp, which services
DNS and TFTP while waiting; it does not send malformed or externally targeted
traffic. Raw observations and every failed run remain below private/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time

from dhcp_boot_service_diff import options
from dns_service_probe import query, semantics
from m2_dhcp_scenarios import request, receive
from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import CLIENT, DNS_PORT, SERVER, Network, dns_ready, ip, save, stop

SERVICE_SECONDS = 1.0
UDP_QUERIES = 20
PROBE_START_SECONDS = 2.0
OFFER_SECONDS = 8.0
DISCOVER_XID = 0x44350001
REQUEST_XID = 0x44350003
TFTP_FILE = bytes(range(256)) * 6 + b'x'


def observed_packet(frame):
    """Classify only this fixture's ordinary ICMP Echo and DHCP OFFER frames."""
    if len(frame) < 34 or frame[12:14] != b'\x08\x00' or frame[14] >> 4 != 4:
        return None
    header = (frame[14] & 15) * 4
    offset = 14 + header
    if header < 20 or len(frame) < offset + 8:
        return None
    if (frame[23] == 1 and frame[26:30] == socket.inet_aton(SERVER)
            and frame[30:34] == socket.inet_aton(CLIENT['address'])
            and frame[offset:offset + 2] == b'\x08\x00'):
        return ('echo', frame[offset:])
    if frame[23] != 17:
        return None
    source, destination, length = struct.unpack_from('!HHH', frame, offset)
    if (source, destination) != (67, 68) or length < 248 or offset + length > len(frame):
        return None
    packet = frame[offset + 8:offset + length]
    if packet[4:8] == struct.pack('!I', DISCOVER_XID):
        return ('offer', packet)
    return None


def dns_during_probe(out):
    started = time.monotonic()
    deadline = started + SERVICE_SECONDS
    rows = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        for index in range(UDP_QUERIES):
            ident = 0x4451 + index
            packet = query('local.test', ident=ident)
            label = f'dns-{index + 1:02}'
            (out / (label + '.request')).write_bytes(packet)
            row = {'id': ident, 'started_monotonic': time.monotonic()}
            rows.append(row)
            try:
                remaining = deadline - row['started_monotonic']
                assert remaining > 0, 'twenty-query deadline expired'
                endpoint.settimeout(remaining)
                endpoint.sendto(packet, (SERVER, DNS_PORT))
                response, peer = endpoint.recvfrom(65535)
                row['finished_monotonic'] = time.monotonic()
                (out / (label + '.reply')).write_bytes(response)
                decoded = semantics(response)
                assert peer == (SERVER, DNS_PORT)
                assert decoded['id'] == ident and decoded['flags'] & 15 == 0
                assert [record['data'] for record in decoded['records'] if record['type'] == 1] == ['192.0.2.7']
                row['semantic'] = decoded
            except Exception as error:
                row['error'] = repr(error)
                raise
            finally:
                save(out / 'dns-queries.json', rows)
    finished = time.monotonic()
    assert finished - started < SERVICE_SECONDS
    return {'started_monotonic': started, 'finished_monotonic': finished,
            'seconds': finished - started, 'queries': rows,
            'semantic': [row['semantic'] for row in rows]}


def tftp_during_probe(out):
    started = time.monotonic()
    deadline = started + SERVICE_SECONDS
    data, blocks = bytearray(), []
    rrq = b'\0\1probe.bin\0octet\0'
    (out / 'tftp-rrq').write_bytes(rrq)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.sendto(rrq, (SERVER, 69))
        expected, server = 1, None
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'complete TFTP download exceeded one second'
            endpoint.settimeout(remaining)
            packet, peer = endpoint.recvfrom(1024)
            (out / f'tftp-data-{expected}').write_bytes(packet)
            assert len(packet) >= 4 and packet[:2] == b'\0\3', 'expected normal TFTP DATA'
            assert peer[0] == SERVER and (server is None or peer == server)
            server = peer
            block = int.from_bytes(packet[2:4], 'big')
            assert block == expected and len(packet) <= 516
            data.extend(packet[4:])
            ack = struct.pack('!HH', 4, block)
            endpoint.sendto(ack, server)
            (out / f'tftp-ack-{expected}').write_bytes(ack)
            blocks.append({'block': block, 'bytes': len(packet) - 4})
            if len(packet) < 516:
                break
            expected += 1
    finished = time.monotonic()
    assert bytes(data) == TFTP_FILE and finished - started < SERVICE_SECONDS
    return {'started_monotonic': started, 'finished_monotonic': finished,
            'seconds': finished - started,
            'semantic': {'blocks': blocks, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}}


def dhcp_semantic(packet, expected):
    decoded = options(packet)
    lookup = {code: bytes.fromhex(value) for code, value in decoded}
    assert packet[0] == 2 and lookup[53] == bytes([expected])
    assert lookup[54] == socket.inet_aton(SERVER)
    assert socket.inet_ntoa(packet[16:20]) == CLIENT['address']
    return {'fixed': packet[:4].hex(), 'flags': packet[10:12].hex(),
            'address': socket.inet_ntoa(packet[16:20]), 'options': decoded}


def coexistence_passed(result, with_tftp):
    probe, dora = result.get('probe', {}), result.get('dora', {})
    if not probe.get('observed') or 'semantic' not in dora or result.get('error'):
        return False
    if len(result.get('udp', {}).get('semantic', [])) != UDP_QUERIES:
        return False
    began, offered = probe['observed_monotonic'], dora['offer_monotonic']
    for key in ['udp'] + (['tftp'] if with_tftp else []):
        row = result.get(key, {})
        if ('semantic' not in row or 'error' in row
                or not (began <= row['started_monotonic'] <= row['finished_monotonic'] < offered)
                or not 0 <= row['seconds'] < SERVICE_SECONDS):
            return False
    return result.get('capture_stopped') is True


def client(out, with_tftp):
    out.mkdir()
    result = {'passed': False, 'probe': {'observed': False}, 'udp': {}, 'dora': {}}
    if with_tftp:
        result['tftp'] = {}
    probe_seen, offer_seen, cancelled = threading.Event(), threading.Event(), threading.Event()
    observed, worker = {}, None
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        try:
            raw.bind(('client0', 0))
            raw.settimeout(.1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'client0\0')
            endpoint.bind(('0.0.0.0', 68))

            def capture():
                deadline = time.monotonic() + OFFER_SECONDS
                while not cancelled.is_set() and time.monotonic() < deadline:
                    try:
                        frame = raw.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError as error:
                        if not cancelled.is_set():
                            observed['error'] = repr(error)
                        return
                    received = time.monotonic()
                    kind = observed_packet(frame)
                    if kind is None:
                        continue
                    if kind[0] == 'echo' and not probe_seen.is_set():
                        (out / 'probe.ethernet').write_bytes(frame)
                        result['probe'] = {'observed': True, 'observed_monotonic': received}
                        probe_seen.set()
                    elif kind[0] == 'offer':
                        (out / 'offer.ethernet').write_bytes(frame)
                        (out / 'offer.reply').write_bytes(kind[1])
                        observed.update({'offer': kind[1], 'offer_monotonic': received})
                        offer_seen.set()
                        return

            worker = threading.Thread(target=capture)
            worker.start()
            discover = request(1, CLIENT, DISCOVER_XID, SERVER, 'discover', CLIENT['address'])
            (out / 'discover.request').write_bytes(discover)
            endpoint.sendto(discover, ('255.255.255.255', 67))
            assert probe_seen.wait(PROBE_START_SECONDS), 'real outgoing ICMP Echo was not observed'
            for label, operation in [('udp', dns_during_probe)] + ([('tftp', tftp_during_probe)] if with_tftp else []):
                try:
                    result[label] = operation(out)
                except Exception as error:
                    result[label] = {'error': repr(error)}
            assert offer_seen.wait(OFFER_SECONDS), 'DHCP OFFER was not observed'
            worker.join(1)
            assert not worker.is_alive(), 'capture did not finish after OFFER'
            offered = dhcp_semantic(observed['offer'], 2)
            selecting = request(3, CLIENT, REQUEST_XID, SERVER, 'select', CLIENT['address'])
            (out / 'select.request').write_bytes(selecting)
            endpoint.sendto(selecting, ('255.255.255.255', 67))
            ack, frame = receive(raw, REQUEST_XID, 2)
            (out / 'ack.reply').write_bytes(ack)
            (out / 'ack.ethernet').write_bytes(frame)
            result['dora'] = {'offer_monotonic': observed['offer_monotonic'],
                              'ack_monotonic': time.monotonic(),
                              'probe_wait_seconds': observed['offer_monotonic'] - result['probe']['observed_monotonic'],
                              'semantic': [offered, dhcp_semantic(ack, 5)]}
        except Exception as error:
            result['error'] = repr(error)
        finally:
            cancelled.set()
            if worker is not None:
                worker.join(1)
            result['capture_stopped'] = worker is None or not worker.is_alive()
            if observed.get('error'):
                result['capture_error'] = observed['error']
    result['passed'] = coexistence_passed(result, with_tftp) and not result.get('capture_error')
    save(out / 'result.json', result)
    return int(not result['passed'])


def run_side(args, root, network, side):
    out = args.out / side
    out.mkdir()
    row, daemon, log = {'side': side, 'passed': False}, None, None
    try:
        config = (f'no-hosts\nno-resolv\nuser=root\ninterface=br-lan\nport={DNS_PORT}\n'
                  'host-record=local.test,192.0.2.7\ndhcp-authoritative\n'
                  'dhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,12h\n'
                  'dhcp-leasefile=/m2/icmp.leases\npid-file=/m2/icmp.pid\n')
        if args.with_tftp:
            config += 'enable-tftp\ntftp-root=/m2/tftp\n'
            (root / 'm2/tftp').mkdir(exist_ok=True)
            (root / 'm2/tftp/probe.bin').write_bytes(TFTP_FILE)
        (root / 'm2/icmp.conf').write_text(config)
        (root / 'm2/icmp.leases').write_bytes(b'')
        (out / 'dnsmasq.conf').write_text(config)
        log = (out / 'daemon.log').open('wb')
        daemon = subprocess.Popen(command(root, side, '-k', '-C', '/m2/icmp.conf'),
                                  stdout=log, stderr=log, start_new_session=True)
        dns_ready(daemon)
        row['identity'] = process_identity(root, daemon.pid)
        argv = network.argv(sys.executable, Path(__file__).resolve(), '--client', '--out', out / 'client')
        if args.with_tftp:
            argv.append('--with-tftp')
        response = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        save(out / 'client-process.json', {'returncode': response.returncode,
                                         'stdout': response.stdout, 'stderr': response.stderr})
        row['client'] = json.loads((out / 'client/result.json').read_text())
        lease = (root / 'm2/icmp.leases').read_bytes()
        (out / 'leases').write_bytes(lease)
        row['leases'] = [line.decode().split()[1:] for line in lease.splitlines()]
        row['runtime'] = {'threads': len(list(Path(f'/proc/{daemon.pid}/task').iterdir())),
                          'children': Path(f'/proc/{daemon.pid}/task/{daemon.pid}/children').read_text().split()}
        row['passed'] = response.returncode == 0 and row['client']['passed'] and len(row['leases']) == 1
    except Exception as error:
        row['error'] = repr(error)
    finally:
        row['cleanup'] = stop(daemon)
        if log is not None:
            log.close()
        row['pidfile_removed'] = not (root / 'm2/icmp.pid').exists()
        for label, port in [('dhcp', 67), ('tftp', 69)]:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                try:
                    endpoint.bind(('0.0.0.0', port))
                    row[label + '_port_released'] = True
                except OSError:
                    row[label + '_port_released'] = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.settimeout(.1)
            row['dns_port_released'] = endpoint.connect_ex(('127.0.0.1', DNS_PORT)) != 0
        if (not row['cleanup'] or row['cleanup']['forced'] or row['cleanup']['returncode'] != 0
                or not all(row[key] for key in ('pidfile_removed', 'dhcp_port_released', 'tftp_port_released', 'dns_port_released'))):
            row['passed'] = False
        save(out / 'result.json', row)
    return row


def normalized(row):
    value = row.get('client', {})
    return {**{key: value.get(key, {}).get('semantic') for key in ('udp', 'tftp', 'dora')},
            'leases': row.get('leases')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--with-tftp', action='store_true')
    parser.add_argument('--client', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('run as root through run_isolated.sh')
    args.out = args.out.resolve()
    if 'private' not in args.out.parts:
        parser.error('evidence must be below private/')
    if args.client:
        return client(args.out, args.with_tftp)
    if not args.image_root or not args.rust:
        parser.error('--image-root and --rust are required')
    if sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        parser.error('start in a namespace containing only lo')
    args.out.mkdir(parents=True, exist_ok=False)
    plan = {'source_reference': 'dnsmasq 2.93 dnsmasq.c::delay_dhcp, DNS/TFTP during ICMP wait',
            'required': ['actual_icmp_echo', 'udp', 'dora'] + (['tftp_complete_download'] if args.with_tftp else []),
            'no_ping': False, 'service_deadline_seconds': SERVICE_SECONDS,
            'udp_queries': UDP_QUERIES,
            'service_must_finish_before_offer': True, 'tftp_bytes': len(TFTP_FILE) if args.with_tftp else None,
            'tool_sha256': sha256(Path(__file__)), 'rust_sha256': sha256(args.rust)}
    save(args.out / 'plan.json', plan)
    report, network = {'passed': False, 'plan': plan}, Network()
    try:
        root = prepare(args.image_root, None, args.out / 'rootfs-stage', args.rust)
        network.start()
        # Only the disposable client namespace is changed. The empty target
        # address is never configured, so its kernel must not echo the probe.
        network.exec('sysctl', '-qw', 'net.ipv4.ip_forward=0')
        ip('neigh', 'replace', CLIENT['address'], 'lladdr', CLIENT['mac'], 'dev', 'br-lan', 'nud', 'permanent')
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
