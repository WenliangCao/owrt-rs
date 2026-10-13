#!/usr/bin/env python3
"""Independent exact-image C/main/fix audit; no transport waivers.

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


def reply(packet):
    end = w.question_end(packet)
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
profiles = [
    ('target-local', 'local=/target.example/\n', (6, 12, 15, 16, 28, 33, 255, 257)),
    ('target-literal', 'address=/target.example/192.0.2.4\n', (255,)),
    ('raw-ns-pointer', 'dns-rr=target.example,2,c00c\n', (2, 255)),
    ('raw-mx-pointer', 'dns-rr=target.example,15,000ac00c\n', (15, 255)),
    ('raw-ns-bad-pointer', 'dns-rr=target.example,2,c0ff\n', (2, 255)),
    ('raw-ns-name', 'dns-rr=target.example,2,026e73076578616d706c6500\n', (2, 255)),
    ('raw-cname-pointer', 'dns-rr=target.example,5,c00c\n', (255,)),
    ('raw-opaque', 'dns-rr=target.example,65401,abcdef\n', (65401, 255)),
]
result = {'identities': {key: sha256(path) for key, path in [
    ('c', root / 'usr/sbin/dnsmasq'), ('main', a.main), ('fix', a.fix),
    ('driver', Path(__file__)), ('canonical', a.source / 'docs/dnsmasq/audits/20261012/fix3_repairs/functional/wire_compare.py')]},
    'comparison': 'Same transport C only; compression and ordinary TTL normalized, original bytes retained.',
    'cases': []}
for profile, config, kinds in profiles:
    for debug in (False, True):
        for protocol in ('udp', 'tcp'):
            for kind in kinds:
                label = f'{profile}-debug{int(debug)}-{protocol}-{kind}'
                row = {'label': label, 'profile': profile, 'debug': debug, 'protocol': protocol,
                       'qtype': kind, 'config': base + config, 'sides': {}}
                (root / 'm2/dns.conf').write_text(base + config)
                for side, binary in [('c', 'c'), ('main', '/usr/sbin/dnsmasq-main'), ('fix', 'rust')]:
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
                                'health': w.request(w.query('ready.test'), 'udp')}
                        finally:
                            if conn:
                                conn.close()
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
                result['cases'].append(row)
                (a.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({'label': label, **row['checks']}), flush=True)
stub.stop.set()
print(json.dumps({'completed': True, 'cases': len(result['cases'])}))
