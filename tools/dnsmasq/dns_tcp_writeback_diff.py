#!/usr/bin/env python3
"""C-first real daemon TCP writeback buffering and ready-slot ordering gate.

Use run_isolated.sh. The C doctor's unchanged 100ms deadline is part of the
contract. Failed deadlines are retained, never retried by this tool.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

from dns_service_probe import query, read_name, semantics, exact_read
from dns_tcp_cache_diff import Product, Upstream, LISTEN
from dns_udp_refusal_diff import verify_reference
from ubus_contract_diff import BUS, OBJECT, digest, fields, read_json_lines

ROOT = Path(__file__).resolve().parents[2]


class Answers(Upstream):
    def __init__(self):
        self.answers = {}
        super().__init__()

    def answer(self, packet, transport):
        host, _ = read_name(packet, 12)
        self.generation = self.answers.get(host, 1)
        return super().answer(packet, transport)


class Service(Product):
    def __init__(self, args, out):
        super().__init__(args, out)
        self.upstream.close()
        self.upstream = Answers()

    def start_product(self, binary):
        super().start_product(binary)
        # No fixture setting changes C's 100ms doctor timeout or pipe transport.


class Subscriber:
    def __init__(self, fixture):
        self.fixture = fixture
        self.path = fixture.out / 'writeback-subscriber.log'
        self.control, remote = socket.socketpair()
        self.control.settimeout(2)
        with self.path.open('wb') as log:
            self.child = subprocess.Popen(
                [str(fixture.out / 'writeback-subscriber'), BUS, OBJECT, OBJECT + '.dns', str(remote.fileno())],
                stdout=log, stderr=subprocess.STDOUT, env=fixture.env, pass_fds=(remote.fileno(),))
        fixture.children.append(self.child)
        remote.close()
        self.expect(b'r')
        assert read_json_lines(self.path)[0]['status'] == 0
        fixture.metrics()  # Subscription-state barrier, before doctor request.

    def expect(self, value):
        actual = self.control.recv(1)
        assert actual == value, ('subscriber-control', value.hex(), actual.hex())

    def close(self):
        self.control.close()
        self.fixture.stop(self.child)


def build_subscriber(fixture):
    deps = fixture.args.reference_build / 'deps'
    command = ['cc', '-Wall', '-Wextra', '-Werror', '-O2', '-I' + str(deps / 'include'),
               str(ROOT / 'tools/dnsmasq/tcp_writeback_subscriber.c'), '-L' + str(deps / 'lib'),
               '-Wl,-rpath,' + str(deps / 'lib'), '-lubus', '-lubox', '-o', str(fixture.out / 'writeback-subscriber')]
    result = subprocess.run(command, capture_output=True, text=True, env=fixture.env)
    (fixture.out / 'subscriber-build.json').write_text(json.dumps(
        {'command': command, 'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    result.check_returncode()


def source_contract(build):
    anchors = {
        'dnsmasq.c': [(1304, 1309), (1936, 1957), (1994, 2003)],
        'cache.c': [(844, 855), (917, 923), (950, 985)],
        'forward.c': [(2770, 2780)],
        'ubus.c': [(398, 406)],
    }
    return {file: {'sha256': digest(build / 'dnsmasq' / file), 'anchors': [
        {'first': first, 'last': last, 'source': '\n'.join((build / 'dnsmasq' / file).read_text().splitlines()[first-1:last])}
        for first, last in ranges]} for file, ranges in anchors.items()}


def run(args, binary, out):
    out.mkdir()
    fixture = Service(args, out)
    connections = []
    subscriber = None
    rows, events = [], []
    sequence = 0
    resources = None

    def event(kind, **details):
        events.append({'event': kind, 'ns': time.monotonic_ns(), **details})

    def exchange(label, host, client=None, timeout=2):
        nonlocal sequence
        sequence += 1
        request = query(host, 1, 0x6100 + sequence)
        first = len(fixture.upstream.events)
        start = time.monotonic_ns()
        event('query-send', label=label, transport='tcp' if client else 'udp', request=request.hex())
        if client:
            client.settimeout(timeout)
            client.sendall(struct.pack('!H', len(request)) + request)
            response = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(timeout)
                udp.sendto(request, LISTEN)
                response = udp.recv(65535)
        event('query-reply', label=label, wire=response.hex())
        assert response[:2] == request[:2]
        row = {'label': label, 'response': semantics(response), 'upstream': copy.deepcopy(fixture.upstream.events[first:]),
               'request': request.hex(), 'wire': response.hex(), 'elapsed_ns': time.monotonic_ns() - start}
        rows.append(row)
        return row

    def connect(label):
        client = socket.create_connection(LISTEN, 2)
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        connections.append(client)
        metric = fixture.wait_metric('tcp_connections', len(connections))
        event('accepted', label=label, metrics=metric)
        return client

    def held(label, requests, close_children=False):
        before = fixture.metrics()
        doctor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        doctor.settimeout(2)
        request = query(label + '-doctor.test', 1, 0x7000 + len(rows))
        first = len(fixture.upstream.events)
        event('doctor-send', label=label, request=request.hex())
        doctor.sendto(request, LISTEN)
        subscriber.expect(b'n')
        start = time.monotonic_ns()
        event('doctor-held', label=label)
        try:
            for child, host, answer in requests:
                fixture.upstream.answers[host] = answer
                remaining = .075 - (time.monotonic_ns() - start) / 1e9
                assert remaining > 0, ('doctor-hold-deadline', label)
                exchange(label + '-child-' + str(answer), host, child, remaining)
            if close_children:
                for child in connections:
                    child.close()
                connections.clear()
                event('children-closed-before-release', label=label)
            elapsed = time.monotonic_ns() - start
            assert elapsed < 75_000_000, ('doctor-hold-deadline', label, elapsed)
            event('release-send', label=label, held_ns=elapsed)
            subscriber.control.sendall(b'r')
            subscriber.expect(b'q')
            subscriber.expect(b'm')
            response = doctor.recv(65535)
            event('doctor-reply', label=label, wire=response.hex())
            log = read_json_lines(subscriber.path)
            notice = [row for row in log if row['event'] == 'notify'][-1]
            released = [row for row in log if row['event'] == 'release'][-1]
            assert released['ns'] - notice['ns'] < 100_000_000, ('C-doctor-deadline', label, notice, released)
            complete = [row for row in log if row['event'] == 'metrics-complete'][-1]
            assert complete['status'] == 0
            wire = [row for row in log if row['event'] == 'metrics'][-1]['wire']
            during = {field['name']: field['value'] for field in fields(wire)}
            expected = dict(before)
            expected['dns_queries_forwarded'] += 1
            assert during == expected, ('queued-metrics-before-doctor-and-pipe-commit', label, expected, during)
            parsed = semantics(response)
            assert parsed['records'][0]['data'] == '192.0.2.250', ('doctor-100ms-timeout-or-rewrite', label, parsed)
            after = fixture.wait_metric('dns_cache_inserted', before['dns_cache_inserted'] + len(requests) + 1)
            rows.append({'label': label + '-held', 'before': before, 'during': during, 'after': after,
                         'request': request.hex(), 'wire': response.hex(), 'response': parsed,
                         'upstream': copy.deepcopy(fixture.upstream.events[first:]), 'held_ns': elapsed,
                         'subscriber_held_ns': released['ns'] - notice['ns']})
        finally:
            doctor.close()

    try:
        build_subscriber(fixture)
        fixture.start_bus()
        fixture.start_product(binary)
        first = connect('first-high-slot')
        exchange('prewarm-first', 'warm-first.test', first)
        fixture.wait_metric('dns_cache_inserted', 1)
        subscriber = Subscriber(fixture)
        held('two-buffered', [(first, 'buffer-one.test', 11), (first, 'buffer-two.test', 12)])
        exchange('buffer-one-parent-hit', 'buffer-one.test')
        exchange('buffer-two-parent-hit', 'buffer-two.test')
        second = connect('second-low-slot')
        exchange('prewarm-second', 'warm-second.test', second)
        fixture.wait_metric('dns_cache_inserted', 5)
        held('slot-order', [(first, 'shared.test', 21), (second, 'shared.test', 22)], close_children=True)
        closed = fixture.wait_metric('tcp_connections', 0)
        exchange('slot-order-parent-winner', 'shared.test')
        replacement = connect('replacement-after-drain')
        exchange('replacement-inherits-winner', 'shared.test', replacement)
        replacement.close()
        connections.clear()
        fixture.wait_metric('tcp_connections', 0)
        children = Path(f'/proc/{fixture.daemon.pid}/task/{fixture.daemon.pid}/children').read_text().split()
        assert not children, ('child-process-leak', children)
        subscriber.close()
        subscriber = None
        resources = {'closed_metrics': closed, 'children_after_close': children,
                     'parent_fds': len(list(Path(f'/proc/{fixture.daemon.pid}/fd').iterdir()))}
        assert not fixture.upstream.errors, fixture.upstream.errors
        return rows, resources
    finally:
        for client in connections:
            client.close()
        if subscriber:
            subscriber.close()
        fixture.stop(fixture.daemon)
        fixture.stop(fixture.bus)
        fixture.upstream.close()
        (out / 'trace.json').write_text(json.dumps({'rows': rows, 'events': events, 'resources': resources,
            'raw': fixture.raw, 'checks': fixture.checks, 'upstream': fixture.upstream.events,
            'upstream_errors': fixture.upstream.errors}, indent=2) + '\n')
        assert all(check['pass'] for check in fixture.checks), fixture.checks


def calibrate(rows):
    by_name = {row['label']: row for row in rows}
    assert len(rows) == 12, ('observation-count', len(rows))
    for label, answer in [('buffer-one-parent-hit', 11), ('buffer-two-parent-hit', 12),
                          ('slot-order-parent-winner', 21), ('replacement-inherits-winner', 21)]:
        row = by_name[label]
        assert not row['upstream'], (label, row['upstream'])
        assert row['response']['records'][0]['data'] == '192.0.2.' + str(answer), (label, row)
    for label in ['two-buffered-held', 'slot-order-held']:
        row = by_name[label]
        assert row['during']['dns_cache_inserted'] == row['before']['dns_cache_inserted']
        assert row['after']['dns_cache_inserted'] == row['before']['dns_cache_inserted'] + 3


def compare(expected, actual):
    failures = []
    if len(expected) != len(actual):
        return [{'observation-count': [len(expected), len(actual)]}]
    for left, right in zip(expected, actual):
        a, b = copy.deepcopy(left), copy.deepcopy(right)
        for row in (a, b):
            for key in ['wire', 'request', 'elapsed_ns', 'held_ns', 'subscriber_held_ns']:
                row.pop(key, None)
            # EOF and child reap ordering after all inserts is unconstrained.
            if 'after' in row and row['label'] == 'slot-order-held':
                row['after'].pop('tcp_connections')
        for c, r in zip(a['response']['records'], b['response']['records']):
            if c['type'] != 41 and abs(c['ttl'] - r['ttl']) <= 1:
                r['ttl'] = c['ttl']
        if a != b:
            failures.append({'label': left['label'], 'c': a, 'candidate': b})
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.reference_build = args.reference_build.resolve()
    out = args.out.resolve()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and [n for _, n in socket.if_nameindex()] == ['lo']
    assert out.is_relative_to(ROOT / 'private') and not out.exists()
    out.mkdir(parents=True)
    reference = args.reference_build / 'dnsmasq/dnsmasq'
    report = {'planned': 12, 'c_observations': 0, 'matched': None, 'failures': [],
              'reference': verify_reference(reference, None), 'tool_sha256': digest(Path(__file__)),
              'subscriber_sha256': digest(ROOT / 'tools/dnsmasq/tcp_writeback_subscriber.c'),
              'source_contract': source_contract(args.reference_build)}
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,noexec,mode=0755', 'tmpfs', '/run'], check=True)
    Path(BUS).parent.mkdir(parents=True)
    try:
        expected, resources = run(args, reference, out / 'c')
        calibrate(expected)
        report.update(c_observations=len(expected), c_resources=resources)
        assert not compare(expected, copy.deepcopy(expected))
        negative = []
        for label, field in [('two-buffered-held', 'during'), ('slot-order-parent-winner', 'response')]:
            bad = copy.deepcopy(expected)
            row = next(row for row in bad if row['label'] == label)
            if field == 'during':
                row[field]['dns_cache_inserted'] += 1
            else:
                row[field]['records'][0]['data'] = '192.0.2.22'
            assert len(compare(expected, bad)) == 1
            negative.append(label)
        report['negative_calibration'] = negative
        if args.rust:
            actual, resources = run(args, args.rust.resolve(), out / 'rust')
            calibrate(actual)
            failures = compare(expected, actual)
            report.update(matched=len(expected) - len(failures), failures=failures,
                          rust_resources=resources, rust_sha256=digest(args.rust))
    except Exception as error:
        report['failures'].append({'infrastructure_or_protocol': repr(error)})
    finally:
        subprocess.run(['umount', '/run'], check=True)
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'source_contract'}))
    return int(bool(report['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
