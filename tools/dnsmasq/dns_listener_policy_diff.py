#!/usr/bin/env python3
"""Isolated listener policy, reply source and CNAME locality C/Rust checks.

Run C first, then pass its result.json as --reference. --compare-result reuses
saved observations without starting a service. Select the original source,
cname and union profiles to compare historical M1 probe results unchanged.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import query, name, read_name, rr, semantics, exact_read

# Request tuples: label, destination, name, TCP, connected UDP.
PROFILES = {
    'source': ('interface=lo\ncache-size=0\n', [
        ('source-local', '127.0.0.2', 'ready.test', False, False),
        ('source-forward', '127.0.0.2', 'forward.test', False, False),
        ('source-connected', '127.0.0.2', 'connected.test', False, True),
    ]),
    'cname': ('listen-address=127.0.0.1\nlocalise-queries\nno-round-robin\n'
              'host-record=multi.test,127.2.0.3\nhost-record=multi.test,192.0.2.3\n', [
        ('cname-direct', '127.0.0.1', 'multi.test', False, False),
        ('cname-first', '127.0.0.1', 'alias.test', False, False),
        ('cname-cached', '127.0.0.1', 'alias.test', False, False),
    ]),
    'union': ('interface=lo\nlisten-address=127.0.0.2\n', [
        ('union-explicit', '127.0.0.2', 'ready.test', False, False),
        ('union-interface-udp', '127.0.0.1', 'ready.test', False, False),
        ('union-interface-tcp', '127.0.0.1', 'ready.test', True, False),
    ]),
}
for profile, extra in [('listen-only', ''), ('listen-union', 'interface=lo\n')]:
    PROFILES[profile] = ('user=root\ngroup=root\nlisten-address=127.0.0.2\n' + extra, [
        (f'{profile}-{address}-{transport}', address, 'ready.test', transport == 'tcp', True)
        for address in ('127.0.0.2', '127.0.0.1') for transport in ('udp', 'tcp')
    ])
PROFILES['missing-static'] = ('user=root\ngroup=root\ninterface=missing123\nbind-interfaces\n', [])
PROFILES['missing-dynamic'] = ('user=root\ngroup=root\ninterface=missing123\nbind-dynamic\n', [
    ('missing-dynamic-loopback', '127.0.0.1', 'ready.test', False, True),
])


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected_cases(profiles):
    return [label for profile in profiles
            for label in [*(row[0] for row in PROFILES[profile][1]), profile + '-shutdown']]


def validate(result, profiles):
    failures = []
    if result.get('failures') != []:
        failures.append('saved run has failures or no failure inventory')
    labels = [row.get('case') for row in result.get('rows', [])]
    if labels != expected_cases(profiles):
        failures.append('missing, extra, duplicated or reordered observations')
    for row in result.get('rows', []):
        case = row.get('case', '')
        if case.endswith('-shutdown'):
            if row.get('exit') != (2 if case == 'missing-static-shutdown' else 0):
                failures.append(case + ': unexpected exit')
        elif case.startswith('listen-only-127.0.0.1-'):
            if 'error' not in row or 'reply' in row:
                failures.append(case + ': excluded address answered')
        elif 'reply' not in row or 'error' in row:
            failures.append(case + ': allowed query did not answer')
    return failures


def compare(actual, reference, profiles):
    failures = [{'side': side, 'error': failure} for side, value in
                [('actual', actual), ('reference', reference)] for failure in validate(value, profiles)]
    if not failures:
        failures.extend({'case': left['case'], 'reference': left, 'actual': right}
                        for left, right in zip(reference['rows'], actual['rows']) if left != right)
    return failures


def run(binary, out, profiles):
    rows, failures, runs, upstream_packets = [], [], [], []
    counts = collections.Counter()
    stop = threading.Event()
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.bind(('127.0.0.1', 15354))
    up.settimeout(.1)

    def upstream():
        try:
            while not stop.is_set():
                try:
                    packet, peer = up.recvfrom(65535)
                except socket.timeout:
                    continue
                host, end = read_name(packet, 12)
                counts[host] += 1
                data = (rr(5, name('multi.test')) + rr(1, bytes([127, 2, 0, 3]), owner=name('multi.test'))
                        if host == 'alias.test' else rr(1, bytes([8, 8, 4, 4])))
                response = packet[:2] + struct.pack('!5H', 0x8180, 1, 2 if host == 'alias.test' else 1, 0, 0)
                response += packet[12:end + 4] + data
                upstream_packets.append({'peer': list(peer), 'request': packet.hex(), 'reply': response.hex()})
                up.sendto(response, peer)
        except Exception as error:
            failures.append({'upstream': repr(error)})

    thread = threading.Thread(target=upstream)
    thread.start()

    def ask(case, dest, host, tcp, connected):
        packet = query(host)
        before = counts[host]
        row = {'case': case, 'destination': dest, 'host': host, 'tcp': tcp, 'connected': connected}
        (out / (case + '.request')).write_bytes(packet)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
                client.settimeout(.5)
                if tcp or connected:
                    client.connect((dest, 15353))
                if tcp:
                    client.sendall(struct.pack('!H', len(packet)) + packet)
                    response = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
                    peer = client.getpeername()
                elif connected:
                    client.send(packet)
                    response = client.recv(65535)
                    peer = client.getpeername()
                else:
                    client.sendto(packet, (dest, 15353))
                    response, peer = client.recvfrom(65535)
            (out / (case + '.reply')).write_bytes(response)
            row.update(peer=list(peer), reply=semantics(response))
        except OSError as error:
            row['error'] = repr(error)
        row['upstream'] = counts[host] - before
        rows.append(row)

    try:
        for profile in profiles:
            extra, schedule = PROFILES[profile]
            conf = out / (profile + '.conf')
            conf.write_text('port=15353\nno-resolv\nno-hosts\nserver=127.0.0.1#15354\n'
                            'host-record=ready.test,127.0.0.7\n' + extra)
            command = [str(binary), '-k', '-C', str(conf), '-x', str(out / 'pid')]
            record = {'profile': profile, 'command': command, 'config_sha256': digest(conf)}
            with (out / (profile + '.stdout')).open('wb') as stdout, (out / (profile + '.stderr')).open('wb') as stderr:
                daemon = subprocess.Popen(command, stdout=stdout, stderr=stderr)
                try:
                    time.sleep(.75 if profile.startswith('missing-') else .25)
                    record['startup_exit'] = daemon.poll()
                    expected = 2 if profile == 'missing-static' else None
                    if record['startup_exit'] != expected:
                        raise AssertionError(f'unexpected startup exit: {record["startup_exit"]}, expected {expected}')
                    for request in schedule:
                        ask(*request)
                except Exception as error:
                    failures.append({'profile': profile, 'error': repr(error)})
                finally:
                    if daemon.poll() is None:
                        daemon.send_signal(signal.SIGTERM)
                    try:
                        daemon.wait(3)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait()
                        failures.append({'profile': profile, 'error': 'shutdown required SIGKILL'})
            record['final_exit'] = daemon.returncode
            runs.append(record)
            rows.append({'case': profile + '-shutdown', 'exit': daemon.returncode})
    finally:
        stop.set()
        thread.join(2)
        if thread.is_alive():
            failures.append({'upstream': 'worker did not stop'})
        up.close()
        (out / 'upstream.json').write_text(json.dumps(upstream_packets, indent=2) + '\n')
    return {'binary': str(binary), 'binary_sha256': digest(binary), 'probe_sha256': digest(__file__),
            'profiles': profiles, 'rows': rows, 'failures': failures, 'runs': runs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--binary', type=Path)
    inputs.add_argument('--compare-result', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--profile', choices=PROFILES, action='append')
    args = parser.parse_args()
    profiles = args.profile or list(PROFILES)
    if len(set(profiles)) != len(profiles):
        parser.error('duplicate profiles')
    out = args.out.resolve()
    if 'private' not in out.parts:
        parser.error('evidence must be below private/')
    if args.compare_result and not args.reference:
        parser.error('--compare-result requires --reference')
    if args.binary and (os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or
                        [label for _, label in socket.if_nameindex()] != ['lo']):
        parser.error('requires run_isolated.sh with only loopback')
    out.mkdir(parents=True, exist_ok=False)
    if args.compare_result:
        result = json.loads(args.compare_result.read_text())
        result['saved_input'] = {'path': str(args.compare_result), 'sha256': digest(args.compare_result)}
    else:
        result = run(args.binary.resolve(), out, profiles)
    result['validation_errors'] = validate(result, profiles)
    result['differences'] = []
    if args.reference:
        result['reference'] = {'path': str(args.reference), 'sha256': digest(args.reference)}
        result['differences'] = compare(result, json.loads(args.reference.read_text()), profiles)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'rows': len(result.get('rows', [])), 'failures': result.get('failures'),
                      'validation_errors': result['validation_errors'], 'differences': len(result['differences'])}))
    return int(bool(result.get('failures') or result['validation_errors'] or result['differences']))


if __name__ == '__main__':
    raise SystemExit(main())
