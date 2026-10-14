#!/usr/bin/env python3
"""FIX5 four-way extended terminal audit, derived from FIX4 terminal_boundaries.py.
Original reproductions are run separately with that unmodified driver.

Run under tools/dnsmasq/run_isolated.sh. Every case starts a new daemon,
warms A through UDP or the same TCP connection, then queries the alias.
Raw replies, decoded semantics, upstream traffic and daemon health are retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

p = argparse.ArgumentParser()
for key in ('source', 'image', 'main', 'fix', 'out'):
    p.add_argument('--' + key, type=Path, required=True)
p.add_argument('--before', type=Path, required=True)
p.add_argument('--profiles', type=Path, required=True)
p.add_argument('--upstream-cnames', action='store_true')
p.add_argument('--host-anchor', action='store_true',
               help='Exercise the pre-existing Local CNAME helper using a configured target host')
p.add_argument('--only', help='Comma-separated profile names')
p.add_argument('--qtype', type=int)
p.add_argument('--upstream-ns', action='store_true',
               help='Return a legitimate authoritative NS answer to NS queries')
p.add_argument('--upstream-ns-target', choices=('query', 'target'), default='target')
a = p.parse_args()
sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
sys.path.insert(0, str(a.source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional'))
import audit_20261011_dns as w
from m2_rootfs import prepare, command, sha256
from wire_compare import canonical

assert os.getenv('DNSMASQ_TEST_ISOLATED') == '1'
a.out.mkdir(parents=True, exist_ok=False)
root = prepare(a.image, None, a.out, a.fix)
shutil.copy2(a.main, root / 'usr/sbin/dnsmasq-main')
shutil.copy2(a.before, root / 'usr/sbin/dnsmasq-before')


def reply(packet):
    end = w.question_end(packet)
    kind = struct.unpack_from('!H', packet, end - 4)[0]
    if a.upstream_cnames and kind == 255:
        return (packet[:2] + struct.pack('!5H', 0x8580, 1, 5, 0, 0)
                + packet[12:end] + w.rr(b'\xc0\x0c', 5, w.name('target.example'), ttl=300)
                + w.rr(w.name('target.example'), 5, w.name('other.example'), ttl=60) * 4)
    if a.upstream_ns and kind == 2:
        ns_target = w.name('alias.example' if a.upstream_ns_target == 'query' else 'target.example')
        return (packet[:2] + struct.pack('!5H', 0x8580, 1, 2, 0, 0)
                + packet[12:end] + w.rr(b'\xc0\x0c', 5, w.name('target.example'), ttl=300)
                + w.rr(w.name('target.example'), 2, ns_target, ttl=60))
    # A reachable upstream always returns an ordinary CNAME + A. This also
    # records whether an implementation wrongly forwards a local terminal.
    return (packet[:2] + struct.pack('!5H', 0x8180, 1, 2, 0, 0)
            + packet[12:end] + w.rr(b'\xc0\x0c', 5, w.name('target.example'), ttl=300)
            + w.rr(w.name('target.example'), 1, socket.inet_aton('192.0.2.77'), ttl=300))


def exchange(packet, protocol, connection=None):
    if connection is None:
        return w.request(packet, protocol)
    try:
        connection.sendall(struct.pack('!H', len(packet)) + packet)
        data = w.exact(connection, struct.unpack('!H', w.exact(connection, 2))[0])
        return {'status': 'reply', 'hex': data.hex(), 'header': list(struct.unpack('!6H', data[:12]))}
    except EOFError:
        return {'status': 'eof'}
    except socket.timeout:
        return {'status': 'timeout'}
    except OSError as error:
        return {'status': 'socket-error', 'errno': error.errno}


w.stub_reply = reply
stub = w.Stub()
base = ('port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\n'
        'no-round-robin\nlocal-ttl=60\ncache-size=150\nserver=127.0.0.1#15354\n'
        'host-record=ready.test,192.0.2.1\n')
profiles = json.loads(a.profiles.read_text())
if a.host_anchor:
    base += 'host-record=target.example,192.0.2.77\n'
if a.only:
    profiles = [profile for profile in profiles if profile[0] in a.only.split(',')]
assert profiles, 'No matching profiles'
result = {'identities': {key: sha256(path) for key, path in [
    ('c', root / 'usr/sbin/dnsmasq'), ('main', a.main), ('fix', a.fix),
    ('before', a.before), ('profiles', a.profiles), ('driver', Path(__file__)), ('canonical', a.source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional/wire_compare.py')]},
    'host_anchor': a.host_anchor, 'upstream_cnames': a.upstream_cnames, 'upstream_ns': a.upstream_ns,
    'upstream_ns_target': a.upstream_ns_target,
    'comparison': 'Same transport C only; compression and ordinary TTL normalized, original bytes retained.',
    'cases': []}
for profile, config, kinds in profiles:
    for debug in (False, True):
        for protocol in ('udp', 'tcp'):
            for kind in kinds:
                if a.qtype is not None and kind != a.qtype:
                    continue
                label = f'{profile}-debug{int(debug)}-{protocol}-{kind}'
                row = {'label': label, 'profile': profile, 'debug': debug, 'protocol': protocol,
                       'qtype': kind, 'query': w.query('alias.example', kind).hex(),
                       'warm_query': w.query('alias.example').hex(),
                       'config': base + config, 'sides': {}}
                (root / 'm2/dns.conf').write_text(base + config)
                for side, binary in [('c', 'c'), ('main', '/usr/sbin/dnsmasq-main'), ('before', '/usr/sbin/dnsmasq-before'), ('fix', 'rust')]:
                    conn = None
                    with (a.out / (label + '-' + side + '.log')).open('wb') as log:
                        proc = subprocess.Popen(command(root, binary, '-C', '/m2/dns.conf',
                            '-d' if debug else '-k', '--user=root', '--group=root', '--pid-file=',
                            '--log-facility=-'), stdout=log, stderr=log)
                        try:
                            for _ in range(100):
                                if proc.poll() is not None:
                                    raise RuntimeError(f'{label} {side} exited at startup')
                                if w.request(w.query('ready.test'), 'udp')['status'] == 'reply':
                                    break
                                time.sleep(.01)
                            if protocol == 'tcp':
                                conn = socket.create_connection(('127.0.0.1', 15353), .5)
                                conn.settimeout(.5)
                            start = len(stub.records)
                            warm = exchange(w.query('alias.example'), protocol, conn)
                            warm_upstream = stub.records[start:]
                            start = len(stub.records)
                            response = exchange(w.query('alias.example', kind), protocol, conn)
                            row['sides'][side] = {'warm': warm, 'warm_upstream': warm_upstream,
                                'response': response, 'canonical': canonical(response),
                                'upstream': stub.records[start:], 'alive': proc.poll() is None,
                                'started': time.time()}
                        finally:
                            if conn:
                                conn.close()
                            row['sides'][side]['health'] = w.request(w.query('ready.test'), 'udp')
                            proc.send_signal(signal.SIGTERM)
                            try:
                                proc.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                proc.wait()
                            row['sides'][side]['exit'] = proc.returncode
                c, main, fix = [row['sides'][side]['canonical'] for side in ('c', 'main', 'fix')]
                row['checks'] = {'main_equals_c': main == c, 'fix_equals_c': fix == c,
                                 'main_equals_fix': main == fix}
                row['checks']['before_equals_c'] = row['sides']['before']['canonical'] == c
                row['checks']['before_equals_fix'] = row['sides']['before']['canonical'] == fix
                result['cases'].append(row)
                (a.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({'label': label, **row['checks']}), flush=True)
stub.stop.set()
print(json.dumps({'completed': True, 'cases': len(result['cases'])}))
