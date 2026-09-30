#!/usr/bin/env python3
"""Isolated TCP socket differential against exact dnsmasq tcp_talk.

Build on Linux using --build-reference DIR; run the generated C/Rust probes
under run_isolated.sh using --binaries DIR. It checks upstream TCP packets,
connection reuse/failover/close effects and final owned-socket counts. This is
not a test of the full daemon's downstream envelope or cache integration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import threading
import time

from cache_answer_diff import packet
from local_answer_diff import REFERENCE_COPTS, rename_main, validate_reference_variant

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).parent
HASHES = {
    'forward.c': 'ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95',
    'dnsmasq.h': '318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(reference, out, cargo, rustc):
    objects = reference / 'dnsmasq'
    validate_reference_variant(objects)
    actual = {name: digest(objects / name) for name in HASHES}
    assert actual == HASHES, f'exact reference source mismatch: {actual}'
    renamed = rename_main(objects, out)
    linked = [p for p in sorted(objects.glob('*.o')) if p.name not in ('dnsmasq.o', 'forward.o', 'dnsmasq-renamed.o')]
    cc = ['cc', '-O2', '-g', *REFERENCE_COPTS, '-I' + str(objects), '-I' + str(reference / 'deps/include'),
          str(HERE / 'tcp_upstream_oracle.c'), *map(str, linked), str(renamed),
          '-L' + str(reference / 'deps/lib'), '-Wl,-rpath,' + str(reference / 'deps/lib'),
          '-lubus', '-lubox', '-o', str(out / 'oracle')]
    subprocess.run(cc, check=True)
    subprocess.run([cargo, 'build', '--manifest-path', str(ROOT / 'components/dnsmasq/Cargo.toml'), '--lib'], check=True)
    target = ROOT / 'components/dnsmasq/target/debug'
    subprocess.run([rustc, '--edition=2021', str(HERE / 'tcp_upstream_probe.rs'),
                    '--extern', 'dnsmasq_rs=' + str(target / 'libdnsmasq_rs.rlib'),
                    '-L', 'dependency=' + str(target / 'deps'), '-o', str(out / 'driver')], check=True)
    manifest = {'source_sha256': actual, 'copts': REFERENCE_COPTS,
                'driver_sha256': {name: digest(HERE / name) for name in ['tcp_upstream_oracle.c', 'tcp_upstream_probe.rs']},
                'rust_source_sha256': {name: digest(ROOT / 'components/dnsmasq/src/dns' / name) for name in ['tcp_upstream.rs', 'tcp_connect.rs', 'routing.rs', 'forward.rs', 'wire.rs']},
                'binary_sha256': {name: digest(out / name) for name in ['oracle', 'driver']}}
    (out / 'identity.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


def receive(stream, count, keep_partial=False):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            return bytes(result) if keep_partial else None
        result.extend(part)
    return bytes(result)


class Upstream:
    def __init__(self, actions, ipv6=False):
        refused = actions == ['refuse-connect']
        self.socket = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('::1' if ipv6 else '127.0.0.1', 0))
        if not refused:
            self.socket.listen()
        self.socket.settimeout(.05)
        self.port = self.socket.getsockname()[1]
        self.ipv6 = ipv6
        self.actions = [] if refused else list(actions)
        self.connected = []
        self.queries = []
        self.errors = []
        self.stopped = threading.Event()
        self.thread = None if refused else threading.Thread(target=self.run)
        if self.thread:
            self.thread.start()

    def run(self):
        try:
            while not self.stopped.is_set():
                try:
                    stream, _ = self.socket.accept()
                except socket.timeout:
                    continue
                connection = len(self.connected)
                self.connected.append({'closed': False})
                with stream:
                    stream.settimeout(15)
                    while not self.stopped.is_set():
                        prefix = receive(stream, 2)
                        if prefix is None:
                            self.connected[connection]['closed'] = True
                            break
                        announced = struct.unpack('!H', prefix)[0]
                        query = receive(stream, announced, keep_partial=True)
                        self.queries.append({'connection': connection, 'announced_length': announced, 'packet': query.hex(), 'complete': len(query) == announced})
                        if len(query) != announced or not query:
                            self.connected[connection]['closed'] = True
                            break
                        if not self.actions:
                            raise RuntimeError('unexpected extra query')
                        action = self.actions.pop(0)
                        if action == 'close':
                            self.connected[connection]['closed'] = True
                            break
                        if action == 'timeout':
                            # The client must close the timed-out connection.
                            assert stream.recv(1) == b''
                            self.connected[connection]['closed'] = True
                            break
                        reply = bytearray(query)
                        reply[2:4] = struct.pack('!H', 0x8180)
                        if action in ('refused', 'servfail'):
                            reply[3] |= 5 if action == 'refused' else 2
                        elif action == 'wrong-id':
                            reply[0] ^= 0x80
                        elif action == 'wrong-question':
                            reply[13] ^= 1
                        elif action == 'wrong-length-question':
                            reply[13] ^= 1
                            reply.append(0)
                        elif action == 'wrong-type':
                            reply[-4:-2] = struct.pack('!H', 28)
                        elif action == 'wrong-class':
                            reply[-2:] = struct.pack('!H', 3)
                        elif action == 'not-response':
                            reply[2] &= 0x7f
                        elif action == 'tc':
                            reply[2] |= 2
                        elif action == 'maximum':
                            reply[6:8] = struct.pack('!H', 1)
                            payload = bytes(65535 - len(reply) - 12)
                            reply += b'\xc0\x0c' + struct.pack('!HHIH', 65401, 1, 60, len(payload)) + payload
                        if action == 'zero':
                            stream.sendall(b'\0\0')
                            continue
                        frame = struct.pack('!H', len(reply)) + reply
                        if action == 'short-prefix':
                            stream.sendall(frame[:1])
                            self.connected[connection]['closed'] = True
                            break
                        if action == 'short-body':
                            stream.sendall(frame[:8])
                            self.connected[connection]['closed'] = True
                            break
                        if action == 'split':
                            for chunk in [frame[:1], frame[1:5], frame[5:]]:
                                stream.sendall(chunk)
                                time.sleep(.01)
                        else:
                            stream.sendall(frame)
        except Exception as error:
            self.errors.append(repr(error))

    def stop(self):
        # The probe has exited, so let readers observe its actual EOF before
        # stopping their accept loops. Never turn stopping into a fake close.
        until = time.monotonic() + 1
        while any(not connection['closed'] for connection in self.connected) and time.monotonic() < until:
            time.sleep(.005)
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=16)
        self.socket.close()
        assert not self.thread or not self.thread.is_alive(), 'upstream worker leaked'
        assert not self.errors, self.errors
        return {'connections': self.connected, 'queries': self.queries, 'unconsumed_actions': self.actions}


def scenarios():
    yield 'persistent', [['normal'] * 3], ['tcp.test'] * 3, False
    yield 'rcode-does-not-failover', [['servfail', 'refused'], []], ['tcp.test'] * 2, False
    yield 'fresh-eof-failover', [['close'], ['normal']], ['tcp.test'], False
    yield 'connect-refused', [['refuse-connect'], ['normal']], ['tcp.test'], False
    yield 'old-eof-reconnect-once', [['normal', 'close', 'close'], ['normal']], ['tcp.test'] * 2, False
    for action in ['wrong-question', 'wrong-length-question', 'wrong-type', 'wrong-class', 'not-response', 'zero', 'short-prefix', 'short-body']:
        yield action, [[action], ['normal']], ['tcp.test'], False
    for action in ['wrong-id', 'tc', 'maximum', 'split']:
        yield action, [[action]], ['tcp.test'], False
    yield 'all-failed', [['close'], ['close']], ['tcp.test'], False
    yield 'ipv6', [['normal']], ['tcp.test'], True
    yield 'domain-route', [['normal'], ['normal']], ['tcp.test', 'scoped.test'], False
    yield 'read-timeout', [['timeout'], ['normal']], ['tcp.test'], False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--build-reference', type=Path)
    parser.add_argument('--binaries', type=Path)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--case', action='append', help='run only named affected cases')
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'private').resolve()):
        parser.error('choose a new directory under ignored private/')
    out.mkdir(parents=True)
    if args.build_reference:
        build(args.build_reference, out, args.cargo, args.rustc)
        return 0
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        parser.error('run only inside the dedicated loopback-only test namespace')
    if not args.binaries:
        parser.error('--binaries is required for the differential')
    identity = json.loads((args.binaries / 'identity.json').read_text())
    assert identity['source_sha256'] == HASHES
    assert identity['binary_sha256'] == {name: digest(args.binaries / name) for name in ['oracle', 'driver']}
    results, errors = [], []
    for case, plans, names, ipv6 in scenarios():
        if args.case and case not in args.case:
            continue
        sides = {}
        queries = [packet(host, 1).hex() for host in names]
        for side in ['oracle', 'driver']:
            workers = [Upstream(actions, ipv6) for actions in plans]
            config = 'no-resolv\nno-hosts\nstrict-order\n'
            for i, worker in enumerate(workers):
                domain = '/scoped.test/' if case == 'domain-route' and i == 1 else ''
                config += f'server={domain}{"::1" if ipv6 else "127.0.0.1"}#{worker.port}\n'
            config_path = out / f'{case}.{side}.conf'
            config_path.write_text(config)
            started = time.monotonic()
            run = subprocess.run([str((args.binaries / side).resolve()), '-C', str(config_path)],
                                 input='\n'.join(queries) + '\n', text=True, capture_output=True, timeout=30)
            elapsed = time.monotonic() - started
            (out / f'{case}.{side}.stdout').write_text(run.stdout)
            (out / f'{case}.{side}.stderr').write_text(run.stderr)
            events = [worker.stop() for worker in workers]
            (out / f'{case}.{side}.events.json').write_text(json.dumps(events, indent=2) + '\n')
            rows = run.stdout.splitlines()
            assert run.returncode == 0 and len(rows) == len(queries) + 1, f'{case}/{side}: process/output calibration'
            assert rows[-1] == 'CLOSED 0', f'{case}/{side}: cleanup calibration'
            assert all(connection['closed'] for event in events for connection in event['connections']), f'{case}/{side}: open upstream connection'
            if case == 'persistent':
                assert all(row.startswith('1 ') and not row.endswith('NONE') for row in rows[:-1])
                assert len(events[0]['connections']) == 1 and len(events[0]['queries']) == 3
            if case == 'all-failed':
                assert rows[0] == '0 NONE' and all(len(event['queries']) == 1 for event in events)
            sides[side] = {'rows': rows, 'events': events, 'elapsed_seconds': elapsed}
        same = sides['oracle']['rows'] == sides['driver']['rows'] and sides['oracle']['events'] == sides['driver']['events']
        results.append({'case': case, 'queries': len(queries), 'matched': same, 'sides': sides})
        if not same:
            errors.append(case)
    assert results and (not args.case or set(args.case) == {case['case'] for case in results}), 'unknown or empty case selection'
    summary = {'cases': len(results), 'queries_per_side': sum(case['queries'] for case in results),
               'mismatches': errors, 'oracle': identity, 'results': results,
               'normalization': 'none: raw query/reply bytes, per-server connection/query order and closed/socket counts compare exactly; elapsed time is diagnostic only',
               'scope': 'isolated exact-C tcp_talk sockets; no complete tcp_request/downstream EDNS, address-policy, cache, daemon lifecycle or performance claim'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'results'}, indent=2))
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
