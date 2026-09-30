#!/usr/bin/env python3
"""Source-contract smoke for the Linux loopback DHCP daemon, never a C diff.

Use run_isolated.sh. Exercises real daemon ports in a private netns. Expected
network fields are fixed from dhcp.c context completion and rfc2131.c do_options;
independent C context/timer differential gates supply the underlying oracle.
Raw configuration and packets must stay below private/.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time


def request(kind, xid, ciaddr=b'\0'*4, options=b''):
    packet = bytearray(240)
    packet[:4] = bytes([1, 1, 6, 0])
    packet[4:8] = struct.pack('!I', xid)
    packet[10:12] = b'\x80\x00'
    packet[12:16] = ciaddr
    packet[28:34] = bytes([2, 0, 0, 0, 0, 1])
    packet[236:240] = bytes([99, 130, 83, 99])
    return bytes(packet) + bytes([53, 1, kind]) + options + b'\xff'


def decode(packet, xid):
    assert len(packet) >= 240 and packet[0] == 2
    assert struct.unpack('!I', packet[4:8])[0] == xid
    result = {}
    offset = 240
    while offset < len(packet):
        code = packet[offset]
        offset += 1
        if code == 255:
            return result
        if code == 0:
            continue
        size = packet[offset]
        offset += 1
        assert offset + size <= len(packet) and code not in result
        result[code] = packet[offset:offset + size]
        offset += size
    raise AssertionError('missing option END')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inject-error', action='store_true',
                        help='calibration: corrupt the first decoded lease TTL; must exit 1')
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('private Linux netns required')
    output = args.output.resolve()
    if 'private' not in output.parts:
        parser.error('output must be under private/')
    output.mkdir(parents=True, exist_ok=False)
    config = output / 'dnsmasq.conf'
    config.write_text('''no-resolv
no-hosts
listen-address=127.0.0.1
port=5300
dhcp-authoritative
dhcp-range=127.0.0.10,127.0.0.20,255.255.0.0,127.0.255.254,10m
dhcp-range=127.0.1.10,127.0.1.20,255.255.0.0,127.0.255.253,20m
''')
    summary = {'status': 'failed', 'checks_passed': 0, 'checks_failed': 0,
               'scope': 'Rust Linux daemon smoke; no C service-equivalence claim', 'replies': [],
               'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
               'config_sha256': hashlib.sha256(config.read_bytes()).hexdigest(),
               'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with (output / 'stderr.log').open('w') as log, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('0.0.0.0', 68))
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')  # Linux SO_BINDTODEVICE
        client.setsockopt(socket.IPPROTO_IP, 13, 1)  # Linux IP_RECVTOS
        client.settimeout(2)
        process = subprocess.Popen([str(args.binary.resolve()), '-C', str(config), '-k'], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                try:
                    with socket.create_connection(('127.0.0.1', 5300), .1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError('daemon startup timeout')
                    time.sleep(.02)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as duplicate:
                duplicate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    duplicate.bind(('0.0.0.0', 67))
                except OSError as error:
                    assert error.errno == errno.EADDRINUSE
                else:
                    raise AssertionError('default DHCP listener allowed a duplicate bind')
            summary['checks_passed'] += 1
            def exchange(kind, xid, ciaddr=b'\0'*4, options=b'', broadcast=False):
                destination = '255.255.255.255' if broadcast else '127.0.0.1'
                client.sendto(request(kind, xid, ciaddr, options), (destination, 67))
                packet, ancillary, flags, peer = client.recvmsg(65535, 1024)
                assert flags == 0
                tos = [data[0] for level, option, data in ancillary
                       if level == socket.IPPROTO_IP and option == socket.IP_TOS]
                assert tos == [0xc0], 'DHCP reply did not retain C network-control TOS'
                parsed = decode(packet, xid)
                if args.inject_error and not summary['replies']:
                    parsed[51] = struct.pack('!I', 1199)
                assert peer[1] == 67
                summary['replies'].append({'request': kind, 'packet': packet.hex(),
                                          'options': {code: value.hex() for code, value in parsed.items()}})
                return packet, parsed
            address = socket.inet_aton('127.0.1.15')
            wanted = bytes([50, 4]) + address
            prl = bytes([55, 2, 3, 6])
            packet, options = exchange(1, 1, options=wanted + prl, broadcast=True)
            assert options[53] == b'\x02' and packet[16:20] == address
            assert options[51] == struct.pack('!I', 1200)
            assert options[58] == struct.pack('!I', 600) and options[59] == struct.pack('!I', 1050)
            assert options[1] == socket.inet_aton('255.255.0.0')
            assert options[28] == socket.inet_aton('127.0.255.253')
            assert options[3] == socket.inet_aton('127.0.0.1') and 6 not in options
            summary['checks_passed'] += 1
            packet, options = exchange(3, 2, options=wanted + bytes([54, 4]) + socket.inet_aton('127.0.0.1') + prl, broadcast=True)
            assert options[53] == b'\x05' and packet[16:20] == address
            assert options[51] == struct.pack('!I', 1200) and options[28] == socket.inet_aton('127.0.255.253')
            assert options[58] == struct.pack('!I', 600) and options[59] == struct.pack('!I', 1050)
            summary['checks_passed'] += 1
            # INFORM uses ciaddr context, omits lease timers, and honors empty
            # PRL for router/DNS while always returning netmask/broadcast.
            packet, options = exchange(8, 3, address, bytes([55, 0]))
            assert options[53] == b'\x05' and options[1] == socket.inet_aton('255.255.0.0')
            assert options[28] == socket.inet_aton('127.0.255.253')
            assert all(code not in options for code in (3, 6, 51, 58, 59))
            summary['checks_passed'] += 1
            process.send_signal(signal.SIGTERM)
            assert process.wait(5) == 0
            # A new daemon must be able to reclaim both listener ports.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', 67))
            summary['checks_passed'] += 1
            summary['status'] = 'passed'
        except Exception as error:
            summary['error'] = repr(error)
            summary['checks_failed'] += 1
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(5)
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'replies'}))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
