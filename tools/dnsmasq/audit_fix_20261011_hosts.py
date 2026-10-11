#!/usr/bin/env python3
"""F07 exact-image bad-host diagnostics, syslog levels and retained DNS records.

Run through run_isolated.sh. The original fixture is copied byte-for-byte from
independent/dns_hosts_probe.py; this additionally observes syslog priority,
reloads, multiple errors, addn-hosts directories, --test, and startup DHCP naming.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

from audit_20261011_dhcp import packet, decode
from m2_rootfs import command, image_path, prepare, process_identity, sha256, STOCK_SHA256
from m5_logging import Receiver

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'docs/dnsmasq/audits/20261011/independent'))
from dns_hosts_probe import query, exchange

ORIGINAL = (b'\n#comment\n192.0.2.1 one.test\vvertical.test\fpage.test\rcarriage.test\n'
            b'192.0.2.2 nul.test\x00ignored.test after.test\n'
            b'192.0.2.3\x00invalid ignored.test\n'
            b'192.0.2.4 ' + b'a' * 100000 + b' next.test\n'
            b'#' + b'x' * 100000 + b'\n192.0.2.5 final.test')
MULTIPLE = (b'#comment\n192.0.2.7 \xff \x01 good.test\n'
            b'bad-address ignored.test \xff\n192.0.2.8 final.test \xff')
BASE = ['-C', '/dev/null', '--user=root', '--group=root', '--pid-file=',
        '--no-hosts', '--no-resolv', '--bind-interfaces', '--listen-address=127.0.0.1',
        '--port=15353', '--log-facility=local5', '--host-record=ready.test,192.0.2.123']


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def notices(raw):
    rows = []
    for record in raw:
        match = re.search(rb'^<(\d+)>.*?dnsmasq\[\d+\]: (.*)', record)
        if not match:
            continue
        text = match[2].decode().rstrip('\n')
        if text.startswith(('bad name at ', 'bad address at ', 'read /m2/')):
            rows.append({'priority': int(match[1]), 'message': text})
    return rows


def wait_read(proc, receiver, expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        receiver.drain()
        if sum(row['message'].startswith('read /m2/') for row in notices(receiver.raw)) >= expected:
            return
        if proc.poll() is not None:
            raise AssertionError('daemon exited before hosts completion')
        time.sleep(.01)
    raise AssertionError('no hosts completion notice')


def dhcp_request():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
        client.bind(('0.0.0.0', 68))
        client.settimeout(2)
        request = packet(3, 0x77110011, name='supplied-wrong')
        client.sendto(request, ('255.255.255.255', 67))
        reply = client.recv(4096)
    return {'request': request.hex(), 'reply': reply.hex(), 'decoded': decode(reply)}


def run(root, side, fixture, debug, out):
    out.mkdir()
    folder = image_path(root, '/m2/f07')
    folder.mkdir(exist_ok=True)
    hosts = folder / 'hosts with space'
    directory = fixture == 'directory'
    if directory:
        hosts = folder / 'directory' / 'hosts with space'
        hosts.parent.mkdir(exist_ok=True)
    payload = ORIGINAL if fixture in ('original', 'directory') else MULTIPLE
    if fixture == 'dhcp-initial':
        payload += b'\n127.0.0.30 authoritative.test\n'
    hosts.write_bytes(payload)
    lease = folder / 'leases'
    lease.unlink(missing_ok=True)
    configured = '/m2/f07/directory' if directory else '/m2/f07/hosts with space'
    actual = configured + '/hosts with space' if directory else configured
    argv = command(root, side, *BASE, '-d' if debug else '-k', '--addn-hosts=' + configured)
    if fixture == 'dhcp-initial':
        argv += ['--no-ping', '--dhcp-authoritative', '--domain=test', '--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,1h',
                 '--dhcp-host=02:00:00:00:00:01,127.0.0.30', '--dhcp-leasefile=/m2/f07/leases']
    receiver = Receiver(root, 'dgram')
    result = {'argv': argv, 'hosts_path': actual, 'payload_sha256': sha256(hosts), 'phases': []}
    with (out / 'stderr.log').open('wb') as log:
        proc = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            wait_read(proc, receiver, 1)
            result['identity'] = process_identity(root, proc.pid)
            for reload in (False, True):
                start = 0 if not reload else len(receiver.raw)
                if reload:
                    hosts.write_bytes(payload + b'\n192.0.2.66 reloaded.test\n')
                    proc.send_signal(signal.SIGHUP)
                    wait_read(proc, receiver, 2)
                names = ['final.test', 'next.test', 'one.test'] if fixture in ('original', 'directory') else ['good.test', 'final.test']
                if reload:
                    names.append('reloaded.test')
                answers = {name: {transport: exchange(query(name), transport == 'tcp')
                                  for transport in ('udp', 'tcp')} for name in names}
                receiver.drain()
                result['phases'].append({'reload': reload, 'notices': notices(receiver.raw[start:]),
                                         'answers': answers, 'alive': proc.poll() is None})
                if fixture == 'dhcp-initial' and not reload:
                    result['dhcp'] = dhcp_request()
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()
            receiver.drain()
            result['cleanup_exit'] = proc.returncode
            result['syslog_hex'] = [r.hex() for r in receiver.raw]
            receiver.close()
    save(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out / 'image', args.rust)
    result = {'rust_sha256': sha256(args.rust), 'c_sha256': STOCK_SHA256, 'cases': [], 'passed': False}
    for fixture in ('original', 'multiple', 'directory', 'dhcp-initial'):
        for debug in (False, True):
            ident = fixture + ('-debug' if debug else '-ordinary')
            row = {'id': ident, 'observed': {}}
            errors = []
            for side in ('c', 'rust'):
                obs = run(root, side, fixture, debug, args.out / (ident + '-' + side))
                row['observed'][side] = obs
                assert obs['identity']['sha256'] == (STOCK_SHA256 if side == 'c' else result['rust_sha256'])
                if obs['cleanup_exit'] != 0 or not all(p['alive'] for p in obs['phases']):
                    errors.append(side + ': unhealthy')
                expected_bad = [('bad name', 6)] if fixture in ('original', 'directory') else [('bad name', 2), ('bad name', 2), ('bad address', 3), ('bad name', 4)]
                for phase in obs['phases']:
                    bad = [r for r in phase['notices'] if r['message'].startswith('bad ')]
                    expected = [{'priority': 171, 'message': f'{kind} at {obs["hosts_path"]} line {line}'} for kind, line in expected_bad]
                    if bad != expected:
                        errors.append(side + ': bad-token diagnostics differ from C source contract')
                    if not phase['notices'] or phase['notices'][-1]['priority'] != 174 or sum(r['message'].startswith('read ') for r in phase['notices']) != 1:
                        errors.append(side + ': completion count/order/priority')
                    if any(len(wire) < 24 or wire[6:8] != '80' or wire[12:16] != '0001' for answers in phase['answers'].values() for wire in answers.values()):
                        errors.append(side + ': legal record missing')
            c, rust = row['observed']['c'], row['observed']['rust']
            if c['phases'] != rust['phases']:
                errors.append('C/R phase mismatch')
            if fixture == 'dhcp-initial':
                if c['dhcp']['decoded'] != rust['dhcp']['decoded'] or c['dhcp']['decoded']['message_type'] != 5 or not c['dhcp']['decoded']['hostname'].startswith('authoritative'):
                    errors.append('startup hosts/DHCP authoritative name mismatch')
            row.update(failures=errors, passed=not errors)
            result['cases'].append(row)
            save(args.out / 'result.json', result)
    # --test validates config syntax without opening the hosts file.
    control = {}
    for side in ('c', 'rust'):
        argv = command(root, side, *BASE, '--test', '--addn-hosts=/does/not/exist')
        proc = subprocess.run(argv, capture_output=True, timeout=3)
        control[side] = {'argv': argv, 'exit': proc.returncode, 'stderr': proc.stderr.decode()}
    result['syntax_only_control'] = control
    result['passed'] = all(r['passed'] for r in result['cases']) and all(r['exit'] == 0 and r['stderr'] == 'dnsmasq: syntax check OK.\n' for r in control.values())
    save(args.out / 'result.json', result)
    print(json.dumps({'passed': result['passed'], 'cases': len(result['cases']), 'failures': {r['id']: r['failures'] for r in result['cases'] if r['failures']}}, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
