#!/usr/bin/env python3
"""Compare shared UDP cache/coalescing and reply socket identity with exact C.

Network namespace required; tests use loopback only, a one-record cache and a
controlled upstream. The C daemon supplies the comparison trace. All packets,
configuration and failures stay in a fresh ignored/private output directory.
"""
import argparse
import contextlib
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, query, read_name, rr, semantics

TTL = 120


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(.025)
        self.port = self.socket.getsockname()[1]
        self.events = []
        self.failures = []
        self.released = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        deferred = []
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                packet = None
            if packet is not None:
                try:
                    host, end = read_name(packet, 12)
                    self.events.append(host)
                    response = packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
                    response += packet[12:end+4] + rr(1, bytes([192, 0, 2, 7]), TTL)
                    if host == 'merge.test' and not self.released.is_set():
                        deferred.append((response, peer))
                    else:
                        self.socket.sendto(response, peer)
                except Exception as error:
                    self.failures.append(repr(error))
            if self.released.is_set():
                for response, peer in deferred:
                    self.socket.sendto(response, peer)
                deferred.clear()

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        assert not self.thread.is_alive() and not self.failures, self.failures


def exchange(destination, packet):
    with socket.socket(socket.AF_INET6 if ':' in destination[0] else socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(packet, destination)
        response, source = client.recvfrom(65535)
    return response, source[:2]


def run(binary, output, config, port, upstream):
    trace = {'status': 'failed', 'rows': []}
    first_event = len(upstream.events)
    upstream.released.clear()
    with (output / 'stderr.log').open('w') as log:
        process = subprocess.Popen([str(binary), '-C', str(config), '-d'], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                try:
                    with socket.create_connection(('127.0.0.1', port), .05):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError('readiness timeout')
                    time.sleep(.01)
            inserted = time.monotonic()
            def record(label, response, source, expected_id, first_insert):
                parsed = semantics(response)
                assert parsed['id'] == expected_id
                age = time.monotonic() - first_insert
                assert len(parsed['records']) == 1
                observed = parsed['records'][0]['ttl']
                assert TTL - math.ceil(age) <= observed <= TTL, 'TTL outside measured expiry interval'
                trace['rows'].append({'case': label, 'wire': response.hex(), 'reply': parsed,
                                      'source': source, 'elapsed_since_insert': age,
                                      'upstream': upstream.events[first_event:].copy()})
            for index, (host, destination) in enumerate([
                ('a.test', '127.0.0.1'), ('a.test', '127.0.0.2'), ('a.test', '::1'),
                ('b.test', '127.0.0.2'), ('a.test', '127.0.0.1'),
            ]):
                ident = 0x2a00 + index
                response, source = exchange((destination, port), query(host, ident=ident))
                assert source == (destination, port), 'reply used the wrong listener address'
                record(f'cache-{index}', response, source, ident, inserted)
            # Same question from three listeners while the upstream reply is
            # withheld. Every client must receive its own ID and source socket.
            with contextlib.ExitStack() as stack:
                clients = []
                started = time.monotonic()
                for index, host in enumerate(('127.0.0.1', '127.0.0.2', '::1')):
                    client = stack.enter_context(socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM))
                    client.settimeout(3)
                    ident = 0x2b00 + index
                    client.sendto(query('merge.test', ident=ident), (host, port))
                    clients.append((client, host, ident))
                time.sleep(.2)
                upstream.released.set()
                for index, (client, host, ident) in enumerate(clients):
                    response, source = client.recvfrom(65535)
                    assert source[:2] == (host, port), 'merged reply used the wrong listener address'
                    record(f'merged-{index}', response, source[:2], ident, started)
            process.send_signal(signal.SIGTERM)
            trace['exit'] = process.wait(5)
            assert trace['exit'] == 0
            trace['status'] = 'passed'
        except Exception as error:
            trace['error'] = repr(error)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(5)
            (output / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
    return trace


def normalized(trace):
    value = copy.deepcopy(trace)
    for row in value['rows']:
        row.pop('wire')
        row.pop('elapsed_since_insert')
        # Actual TTL is checked against the measured initial TTL and wall-time
        # interval in run(). Only whole-second elapsed-clock variance is allowed.
        row['reply']['records'][0]['ttl'] = {'initial': TTL, 'elapsed_checked': True}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    upstream = Upstream()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    config = out / 'dnsmasq.conf'
    config.write_text(f'''no-resolv
no-hosts
listen-address=127.0.0.1,127.0.0.2,::1
port={port}
cache-size=1
server=127.0.0.1#{upstream.port}
''')
    report = {'status': 'failed', 'checks_passed': 0, 'checks_failed': 0,
              'identity': {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest() for name in ('c', 'rust')}}
    try:
        traces = {}
        for name in ('c', 'rust'):
            work = out / name
            work.mkdir()
            traces[name] = run(getattr(args, name).resolve(), work, config, port, upstream)
        expected, actual = normalized(traces['c']), normalized(traces['rust'])
        assert expected['rows'][-1]['upstream'] == ['a.test', 'b.test', 'a.test', 'merge.test']
        assert len(expected['rows']) == len(actual['rows']) == 8
        changed = copy.deepcopy(expected)
        changed['rows'][1]['upstream'].append('a.test')
        wrong_socket = copy.deepcopy(expected)
        wrong_socket['rows'][-1]['source'] = ('127.0.0.1', port)
        assert expected == normalized(traces['c']) and changed != expected and wrong_socket != expected
        report['calibration'] = {'equal_passed': 1, 'controlled_failures_detected': 2}
        failed = [a['case'] for a, b in zip(expected['rows'], actual['rows']) if a != b]
        report.update(checks_passed=8-len(failed), checks_failed=len(failed), mismatches=failed,
                      status='passed' if not failed else 'failed')
    except Exception as error:
        report['error'] = repr(error)
        report['checks_failed'] = max(1, report['checks_failed'])
    finally:
        upstream.close()
        (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return int(report['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
