#!/usr/bin/env python3
"""One exact-C UDP comparison for actual-config DHCP tag/network wiring.

Run under run_isolated.sh. Keeps requests, full replies, lease rows, failures
and declared no-reply observations in the private output directory.
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

from dhcp_boot_service_diff import options


def request(kind, name, ident, requested='127.0.0.40'):
    data = bytearray(240)
    data[:3] = bytes([1, 1, 6]); data[4:8] = struct.pack('!I', ident)
    data[28:34] = bytes([2, 0, 0, 0, 0, 1]); data[236:240] = bytes.fromhex('63825363')
    data.extend(bytes([53, 1, kind, 12, len(name)]) + name)
    if kind == 3:
        data.extend(bytes([50, 4]) + socket.inet_aton(requested))
        data.extend(bytes([54, 4]) + socket.inet_aton('127.0.0.1'))
    data.extend(bytes([55, 3, 1, 12, 15, 255]))
    return bytes(data)


def run(binary, folder, extra, names, excluded=False):
    folder.mkdir(); leases = folder / 'leases'; config = folder / 'config'
    base_host = '' if 'dhcp-host=' in extra else 'dhcp-host=02:00:00:00:00:01,127.0.0.40,600s\n'
    config.write_text('no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=5300\nno-ping\n'
        'dhcp-authoritative\ndomain=lan\ndhcp-range=set:lan,127.0.0.10,127.0.0.50,255.0.0.0,600s\n'
        + base_host + f'dhcp-leasefile={leases}\n' + extra)
    result = {'rows': [], 'status': 'failed'}; process = None
    with (folder / 'daemon.log').open('w') as log, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('0.0.0.0', 68)); client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0'); client.settimeout(.5)
        try:
            process = subprocess.Popen([str(binary), '-d', '-C', str(config)], stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'daemon exited during startup'
                try:
                    with socket.create_connection(('127.0.0.1', 5300), .03): break
                except OSError:
                    assert time.monotonic() < deadline, 'startup timeout'
                    time.sleep(.01)
            for index, (kind, name) in enumerate(names):
                packet = request(kind, name.encode(), 0xb100 + index)
                (folder / f'{index:02}.request').write_bytes(packet)
                client.sendto(packet, ('255.255.255.255', 67))
                try: response, peer = client.recvfrom(65535)
                except socket.timeout:
                    assert excluded, 'unexpected DHCP timeout'
                    result['rows'].append({'no_reply': True, 'leases': leases.read_text() if leases.exists() else ''})
                    continue
                assert not excluded, 'excluded interface replied'
                (folder / f'{index:02}.response').write_bytes(response)
                assert response[4:8] == packet[4:8]
                decoded = options(response)
                assert next(value for code, value in decoded if code == 53) == ('02' if kind == 1 else '05')
                lease_rows = []
                for line in leases.read_text().splitlines():
                    row = line.split(); expiry = int(row[0])
                    assert int(time.time()) + 598 <= expiry <= int(time.time()) + 601
                    row[0] = 'ack+600'; lease_rows.append(row)
                result['rows'].append({'reply': response.hex(), 'peer': list(peer), 'leases': lease_rows})
            result['status'] = 'ok'
        except Exception as error: result['error'] = repr(error)
        finally:
            if process is not None:
                if process.poll() is None: process.send_signal(signal.SIGTERM)
                try: process.wait(3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(3)
                result['exit'] = process.returncode
            (folder / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c', type=Path, required=True); parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    out = args.output.resolve(); assert 'private' in out.parts; out.mkdir(parents=True)
    rules = 'dhcp-name-match=set:bogus,bad-client\ndhcp-ignore-names=tag:bogus\n'
    cases = [
        ('name-retention', rules, [(1, 'normal'), (3, 'normal'), (3, 'bad-client')], False),
        ('ignored-new', rules, [(1, 'bad-client'), (3, 'bad-client')], False),
        ('range-name-only', 'dhcp-ignore-names=tag:lan\ndhcp-broadcast=tag:lan\n', [(1, 'normal'), (3, 'normal')], False),
        ('force-by-name', 'dhcp-name-match=set:needs-broadcast,force-client\ndhcp-broadcast=tag:needs-broadcast\n', [(1, 'force-client'), (3, 'force-client')], False),
        ('authoritative-name', rules + 'dhcp-host=02:00:00:00:00:01,127.0.0.40,configured\n', [(3, 'bad-client')], False),
        ('exact-full-name', 'dhcp-name-match=set:bogus,wpad\ndhcp-ignore-names=tag:bogus\n', [(3, 'wpad.lan')], False),
        ('excluded-interface', 'no-dhcp-interface=lo\n', [(1, 'normal'), (3, 'normal')], True),
    ]
    summary = {'planned': sum(len(events) for _, _, events, _ in cases), 'compared': 0, 'differences': [], 'failures': []}
    (out / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    for name, extra, events, excluded in cases:
        expected = run(args.c.resolve(), out / (name + '-c'), extra, events, excluded)
        actual = run(args.rust.resolve(), out / (name + '-rust'), extra, events, excluded)
        for side, result in [('c', expected), ('rust', actual)]:
            if result['status'] != 'ok': summary['failures'].append({'case': name, 'side': side, **result})
        for index, (left, right) in enumerate(zip(expected['rows'], actual['rows'])):
            summary['compared'] += 1
            if left != right: summary['differences'].append({'case': name, 'row': index, 'c': left, 'rust': right})
    summary['unexecuted'] = summary['planned'] - summary['compared']
    summary['binary_sha256'] = {side: hashlib.sha256(path.read_bytes()).hexdigest() for side, path in [('c', args.c), ('rust', args.rust)]}
    (out / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: len(value) if key in ('differences', 'failures') else value for key, value in summary.items()}))
    return int(bool(summary['differences'] or summary['failures'] or summary['unexecuted']))


if __name__ == '__main__': raise SystemExit(main())
