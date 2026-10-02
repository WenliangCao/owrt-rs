#!/usr/bin/env python3
"""Compare DHCP host-file/ethers merging at startup and SIGHUP against exact C.

Run through run_isolated.sh with --c, --rust and a fresh --out below private/.
Synthetic overlapping-address and distinct-address cases retain every request,
reply, configuration and daemon log. /etc is replaced only inside the private
mount namespace so neither the host's ethers file nor any router is changed.
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
from dhcp_reverse_lifecycle_diff import watch_reads, read_closed
from dns_udp_refusal_diff import verify_reference

CASES = [('merge-address', '127.0.0.40'), ('distinct-address-control', '127.0.0.41')]
STAGES = 2


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(binary, out, ethers_address):
    out.mkdir()
    bank = out / 'dhcp-hosts'
    bank.write_text('02:00:00:00:00:01,127.0.0.40,fixed,1200s\n')
    Path('/etc/ethers').write_text(f'02:00:00:00:00:02 {ethers_address}\n')
    (out / 'ethers').write_bytes(Path('/etc/ethers').read_bytes())
    config = out / 'config'
    config.write_text('no-hosts\nno-resolv\nno-ping\nleasefile-ro\n'
        'listen-address=127.0.0.1\nport=5300\nread-ethers\n'
        'dhcp-authoritative\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n'
        f'dhcp-hostsfile={bank}\ndhcp-leasefile={out / "leases"}\n')
    trace = {'rows': [], 'status': 'failed'}
    process = None
    marker = watch_reads(bank)
    try:
        with (out / 'daemon.log').open('w') as log, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(('0.0.0.0', 68))
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')
            client.settimeout(1)
            process = subprocess.Popen([str(binary), '-d', '-C', str(config)], stdout=log, stderr=log)
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'startup exit'
                try:
                    with socket.create_connection(('127.0.0.1', 5300), .03):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'startup timeout'
                    time.sleep(.01)
            assert read_closed(marker), 'host file not read at startup'
            for stage in range(STAGES):
                if stage:
                    process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 3
                    while not read_closed(marker):
                        assert process.poll() is None and time.monotonic() < deadline, 'reload timeout'
                        time.sleep(.01)
                request = bytearray(240)
                request[:3] = b'\x01\x01\x06'
                request[4:8] = struct.pack('!I', 0xa100 + stage)
                request[10:12] = b'\x80\0'
                request[28:34] = b'\x02\0\0\0\0\x02'
                request[236:240] = bytes.fromhex('63825363')
                request.extend(bytes([53, 1, 1, 55, 2, 12, 51, 255]))
                (out / f'{stage}.request').write_bytes(request)
                client.sendto(request, ('255.255.255.255', 67))
                response, peer = client.recvfrom(65535)
                assert response[:3] == b'\x02\x01\x06' and response[4:8] == request[4:8]
                (out / f'{stage}.response').write_bytes(response)
                trace['rows'].append({'stage': stage, 'wire': response.hex(), 'peer': list(peer),
                    'address': socket.inet_ntoa(response[16:20]), 'options': options(response)})
            trace['status'] = 'ok'
    except Exception as error:
        trace['error'] = repr(error)
    finally:
        os.close(marker)
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
            trace['exit'] = process.returncode
        (out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
    return trace


def compare(traces):
    """Pure comparison also permits replaying preserved traces without listeners."""
    report = {'planned': len(CASES) * STAGES, 'compared': 0, 'cases': [],
              'differences': [], 'failures': []}
    for label, address in CASES:
        sides = traces[label]
        for side in ('c', 'rust'):
            trace = sides[side]
            if trace['status'] != 'ok' or trace.get('exit') != 0 or len(trace['rows']) != STAGES:
                report['failures'].append({'case': label, 'side': side, **trace})
        for stage, (left, right) in enumerate(zip(sides['c']['rows'], sides['rust']['rows'])):
            report['compared'] += 1
            if left != right:
                report['differences'].append({'case': label, 'stage': stage, 'c': left, 'rust': right})
            lease_time = '000004b0' if label == 'merge-address' else '00000258'
            name = '6669786564' if label == 'merge-address' else None
            reference_options = dict(left['options'])
            if (left['stage'] != stage or left['address'] != address
                    or reference_options.get(53) != '02'
                    or reference_options.get(51) != lease_time
                    or reference_options.get(12) != name):
                report['failures'].append({'case': label, 'stage': stage,
                    'error': 'reference did not perform the configured OFFER', 'c': left})
        report['cases'].append({'case': label, 'c_rows': len(sides['c']['rows']),
                               'rust_rows': len(sides['rust']['rows'])})
    report['unexecuted'] = max(0, report['planned'] - report['compared'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c', type=Path, required=True)
    parser.add_argument('--c-identity', type=Path)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert os.geteuid() == 0 and sorted(name for _, name in socket.if_nameindex()) == ['lo']
    assert not Path('/etc/openwrt_release').exists()
    identity = verify_reference(args.c, args.c_identity)
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    etc_files = {name: Path('/etc', name).read_bytes() for name in ['passwd', 'group', 'nsswitch.conf']}
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'm1-dhcp-review', '/etc'], check=True)
    for name, content in etc_files.items():
        Path('/etc', name).write_bytes(content)
    traces = {}
    for label, address in CASES:
        traces[label] = {}
        for side, binary in [('c', args.c), ('rust', args.rust)]:
            traces[label][side] = run(binary.resolve(), out / f'{label}-{side}', address)
    report = compare(traces)
    report.update({'reference': identity, 'binary_sha256': {'c': digest(args.c), 'rust': digest(args.rust)},
                   'tool_sha256': digest(__file__)})
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value if key not in ('differences', 'failures') else len(value) for key, value in report.items()}))
    return int(bool(report['differences'] or report['failures'] or report['unexecuted']))


if __name__ == '__main__':
    raise SystemExit(main())
