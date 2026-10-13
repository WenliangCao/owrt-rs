#!/usr/bin/env python3
"""Compare equal cache inputs through UDP and the same warmed TCP connection.

Reuse the third-review profile definitions and packet vectors verbatim. Each case
resets the parent cache by HUP, then warms through its tested transport. TCP warm
and test use the same connection, exercising ordinary fork snapshots and debug's
parent context. Compare complete DNS semantics, upstream counts, health and exits.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from wire_compare import canonical, common_udp_case, parity_checks


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def literal_profiles(path):
    tree = ast.parse(path.read_text())
    # The source's long-record entries use constant comprehensions; execute only
    # the profile assignment, which is frozen/hashes bound by the controller.
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(name, ast.Name) and name.id == 'profiles'
                              for name in node.targets))
    namespace = {}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), str(path), 'exec'),
         {'__builtins__': {'str': str, 'range': range}}, namespace)
    return namespace['profiles']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('tools', 'image-root', 'rust', 'matrix-source', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert os.getenv('DNSMASQ_TEST_ISOLATED') == '1'
    args.out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.tools))
    import audit_20261011_dns as wire
    from m2_rootfs import prepare, command, sha256
    root = prepare(args.image_root, None, args.out, args.rust)
    profiles = literal_profiles(args.matrix_source)
    assert len(profiles) == 14
    mode = 'positive'

    def reply(packet):
        end = wire.question_end(packet)
        terminal = wire.rr(wire.name('target.example'), 1, socket.inet_aton('192.0.2.77'), ttl=300)
        answer_count, authority_count, flags = 2, 0, 0x8180
        if mode == 'negative':
            terminal = wire.rr(wire.name('example'), 6, wire.name('ns.example')
                               + wire.name('hostmaster.example')
                               + struct.pack('!5I', 1, 60, 60, 60, 300), ttl=300)
            answer_count, authority_count, flags = 1, 1, 0x8183
        return (packet[:2] + struct.pack('!5H', flags, 1, answer_count, authority_count, 0)
                + packet[12:end] + wire.rr(b'\xc0\x0c', 5, wire.name('target.example'), ttl=300)
                + terminal)

    wire.stub_reply = reply
    stub = wire.Stub()
    base = ('port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\n'
            'no-round-robin\nlocal-ttl=60\ncache-size=150\nserver=127.0.0.1#15354\n'
            'host-record=ready.test,192.0.2.1\n')
    queries = [('seed', wire.query('alias.example'))]
    for kind in (1, 5, 6, 12, 15, 16, 28, 33, 255, 257):
        for flags, extra, label in ((0x100, b'', 'rd'), (0, b'', 'nord'),
                                    (0x100, wire.opt(ttl=0x8000), 'do')):
            queries.append((f'{kind}-{label}', wire.query('alias.example', kind,
                            flags=flags, extra=extra, ar=bool(extra))))
    result = {'identities': {'c': sha256(root / 'usr/sbin/dnsmasq'), 'rust': sha256(args.rust),
                            'driver': sha256(Path(__file__)), 'matrix_source': sha256(args.matrix_source)},
              'normalization': 'Compression layout and ordinary RR TTL only; OPT TTL retained',
              'profiles': [], 'failures': [], 'passed': False}

    def persistent(connection, packet):
        connection.sendall(struct.pack('!H', len(packet)) + packet)
        answer = wire.exact(connection, struct.unpack('!H', wire.exact(connection, 2))[0])
        return {'status': 'reply', 'hex': answer.hex(), 'header': list(struct.unpack('!6H', answer[:12])),
                'length': len(answer)}

    try:
        for debug in (False, True):
            for profile, config in profiles:
                for mode in ('positive', 'negative'):
                    label = f'{profile}-{mode}-debug{int(debug)}'
                    row = {'name': label, 'config': base + config, 'debug': debug,
                           'cases': {}, 'processes': {}}
                    (root / 'm2/dns.conf').write_text(row['config'])
                    for side in ('c', 'rust'):
                        with (args.out / (label + '-' + side + '.log')).open('wb') as log:
                            process = subprocess.Popen(command(root, side, '-C', '/m2/dns.conf',
                                '-d' if debug else '-k', '--user=root', '--group=root',
                                '--pid-file=', '--log-facility=-'), stdout=log, stderr=log)
                            try:
                                for _ in range(100):
                                    if process.poll() is not None:
                                        raise RuntimeError(f'{label} {side} startup exit {process.returncode}')
                                    if wire.request(wire.query('ready.test'), 'udp')['status'] == 'reply':
                                        break
                                    time.sleep(.01)
                                else:
                                    raise RuntimeError(f'{label} {side} not ready')
                                for query_label, packet in queries:
                                    case = row['cases'].setdefault(query_label, {'query': packet.hex()})
                                    observed = case.setdefault(side, {})
                                    for protocol in ('udp', 'tcp'):
                                        process.send_signal(signal.SIGHUP)
                                        time.sleep(.02)
                                        connection = None
                                        try:
                                            if protocol == 'tcp':
                                                connection = socket.create_connection(('127.0.0.1', 15353), .5)
                                                connection.settimeout(.5)
                                            def request(payload):
                                                return persistent(connection, payload) if connection else wire.request(payload, 'udp')
                                            before = len(stub.records)
                                            warm = request(wire.query('alias.example'))
                                            warm_count = len(stub.records) - before
                                            before = len(stub.records)
                                            response = request(packet)
                                            observed[protocol] = {'warm': warm, 'warm_upstream_count': warm_count,
                                                'response': response, 'canonical': canonical(response),
                                                'upstream': stub.records[before:]}
                                        finally:
                                            if connection:
                                                connection.close()
                                row['processes'][side] = {'alive': process.poll() is None,
                                    'health': wire.request(wire.query('ready.test'), 'udp')}
                            finally:
                                if process.poll() is None:
                                    process.send_signal(signal.SIGTERM)
                                try:
                                    process.wait(timeout=2)
                                except subprocess.TimeoutExpired:
                                    process.kill(); process.wait()
                                row['processes'].setdefault(side, {})['exit'] = process.returncode
                    for query_label, case in row['cases'].items():
                        checks = parity_checks(*(case[side][protocol]['response']
                                    for side, protocol in (('c', 'udp'), ('c', 'tcp'), ('rust', 'udp'), ('rust', 'tcp'))),
                                               common_udp=common_udp_case(f'{profile}-{mode}', query_label))
                        checks['warm_equal'] = all(canonical(case['c'][p]['warm']) == canonical(case['rust'][p]['warm'])
                                                   for p in ('udp', 'tcp'))
                        expected_tcp = 'udp' if common_udp_case(f'{profile}-{mode}', query_label) else 'tcp'
                        checks['upstream_equal'] = (len(case['c']['udp']['upstream']) == len(case['rust']['udp']['upstream'])
                            and len(case['c'][expected_tcp]['upstream']) == len(case['rust']['tcp']['upstream']))
                        case['declared_common_UDP_semantics'] = expected_tcp == 'udp'
                        checks['warm_upstream_equal'] = all(case['c'][p]['warm_upstream_count'] == case['rust'][p]['warm_upstream_count']
                                                            for p in ('udp', 'tcp'))
                        case['checks'] = checks
                        failed = [key for key, value in checks.items() if key != 'transport_size_difference' and not value]
                        if failed:
                            result['failures'].append({'profile': label, 'case': query_label, 'checks': failed})
                    for side, process in row['processes'].items():
                        if not process['alive'] or process['exit'] != 0 or process['health']['status'] != 'reply':
                            result['failures'].append({'profile': label, 'side': side, 'process': process})
                    result['profiles'].append(row)
                    save(args.out / 'result.json', result)
                    print(json.dumps({'profile': label, 'cases': len(row['cases']),
                                      'cumulative_failures': len(result['failures'])}), flush=True)
        result['case_count'] = sum(len(row['cases']) for row in result['profiles'])
        result['passed'] = len(result['profiles']) == 56 and result['case_count'] == 1736 and not result['failures']
        save(args.out / 'result.json', result)
    finally:
        stub.stop.set()
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
