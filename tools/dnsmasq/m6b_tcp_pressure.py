#!/usr/bin/env python3
"""Exact-image TCP resource/lifecycle supplements; no performance conclusions.

Reuses the M5 image overlay, actual-process identity and controlled upstream.
Profiles are fixed before running. FD return is checked against each side's
own confirmed idle descriptors; PSS/RSS are observations, not equality gates.
Internal view/root/live-allocation counts are explicitly not observable here.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

import m5_dns_cache as driver


BIG_TEXT = ','.join('"' + 'x' * 255 + '"' for _ in range(192))
CASES = [
    {'case': 'm6b-tcp-100-query', 'mode': '100-query', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-half-frame', 'mode': 'half-frame', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-slow-write', 'mode': 'slow-write', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-slow-read', 'mode': 'slow-read', 'capacity': 150,
     'config': 'txt-record=large.pressure.test,' + BIG_TEXT},
    {'case': 'm6b-tcp-capacity-20-30', 'mode': 'capacity', 'capacity': 150,
     'config': 'max-tcp-connections=30\nlisten-address=192.0.2.2'},
    {'case': 'm6b-tcp-idle-pin-150', 'mode': 'idle-pin', 'capacity': 150,
     'initial_hosts': '198.51.100.7 hosts.pressure.test\n', 'config': 'addn-hosts=/m2/caller.hosts'},
    *[{'case': f'm6b-tcp-reconnect-{n}', 'mode': 'reconnect', 'capacity': n,
       'config': '', 'batches': 10, 'clients': 20} for n in [0, 150, 4096]],
]
for case in CASES:
    case['metrics'] = True
    case['samples_after_drain_seconds'] = [0, 1, 5, 15, 60]


def fd_set(pid):
    return {int(p.name): os.readlink(p) for p in (Path('/proc') / str(pid) / 'fd').iterdir()}


def family_sample(pid):
    parents = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            text = (path / 'stat').read_text()
            parents[int(path.name)] = int(text[text.rfind(')') + 2:].split()[1])
        except (FileNotFoundError, ProcessLookupError):
            pass
    members = {pid}
    while True:
        new = {child for child, parent in parents.items() if parent in members}
        if new <= members:
            break
        members |= new
    rows = []
    for member in sorted(members):
        path = Path('/proc') / str(member)
        try:
            status = dict(line.split(':', 1) for line in (path / 'status').read_text().splitlines() if ':' in line)
            smaps = dict(line.split(':', 1) for line in (path / 'smaps_rollup').read_text().splitlines() if ':' in line)
            rows.append({'pid': member, 'fds': fd_set(member), 'threads': int(status['Threads']),
                         'rss_kib': int(status['VmRSS'].split()[0]), 'pss_kib': int(smaps['Pss'].split()[0]),
                         'anonymous_kib': int(smaps['Anonymous'].split()[0])})
        except (FileNotFoundError, ProcessLookupError):
            if member == pid:
                raise
    return {'monotonic_ns': time.monotonic_ns(), 'members': rows, 'child_processes': len(rows) - 1,
            **{key: sum(r[key] for r in rows) for key in ['threads', 'rss_kib', 'pss_kib', 'anonymous_kib']},
            'fd_count': sum(len(r['fds']) for r in rows),
            'not_observed': ['view_count', 'pinned_root_versions', 'pending_transactions', 'live_requested_bytes']}


class Caller:
    def __init__(self, spec, port, upstream, folder, root):
        self.spec, self.port, self.upstream, self.folder, self.root = spec, port, upstream, folder, root
        self.pid = int((folder / 'pid').read_text())
        self.rows, self.clients, self.samples = [], [], []
        self.wire_id = 0x8000
        if self.metrics('idle-confirmed')['tcp_connections'] != 0:
            raise AssertionError('fixture starts with active clients')
        self.idle = fd_set(self.pid)

    def event(self, label, **fields):
        self.rows.append({'label': label, **fields})

    def metrics(self, label):
        run = subprocess.run(driver.command(self.root, '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}'), capture_output=True, timeout=2)
        (self.folder / (label + '.metrics.stdout')).write_bytes(run.stdout)
        (self.folder / (label + '.metrics.stderr')).write_bytes(run.stderr)
        if run.returncode:
            raise AssertionError('actual image UBus metrics failed')
        return json.loads(run.stdout)

    def gauge(self, wanted, label):
        until = time.monotonic() + 5
        observations = []
        while True:
            value = self.metrics(label + f'-{len(observations):03}')
            observations.append({'monotonic_ns': time.monotonic_ns(), 'value': value})
            (self.folder / (label + '.gauge.json')).write_text(json.dumps(observations, indent=2) + '\n')
            if value['tcp_connections'] == wanted:
                return value
            if time.monotonic() > until:
                raise AssertionError(('TCP gauge deadline', wanted, value))
            time.sleep(.01)

    def connect(self, address=driver.LISTEN, small_receive=False):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if small_receive:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        client.settimeout(3)
        client.bind((driver.CLIENT, 0))
        client.connect((address, self.port))
        self.clients.append(client)
        self.gauge(len(self.clients), 'accept-' + str(len(self.clients)))
        return client

    def request(self, host='health.cache.test', kind=1):
        self.wire_id += 1
        return driver.query(host, self.wire_id, kind)

    def capture(self, label, wire, reply):
        (self.folder / (label + '.query')).write_bytes(wire)
        if reply is not None:
            (self.folder / (label + '.reply')).write_bytes(reply)
        if reply is None or reply[:2] != wire[:2]:
            raise AssertionError('missing or wrong-ID reply: ' + label)
        parsed = driver.normalized(reply)
        if parsed.get('result') == 'timeout' or 'unparsed' in parsed:
            raise AssertionError('malformed reply: ' + label)
        question = driver.normalized(wire)['questions']
        if parsed.get('questions') != question or parsed.get('flags', 0) & 0x820f != 0x8000:
            raise AssertionError('wrong question/rcode/truncation: ' + label)
        host, kind, _ = question[0]
        answers = [r for r in parsed['records'] if r['section'] == 'answer']
        if kind == 16:
            wanted = (bytes([255]) + b'x' * 255).hex() * 192
            if len(answers) != 1 or answers[0]['type'] != 16 or answers[0]['data'] != wanted:
                raise AssertionError('large TXT contents differ')
        else:
            wanted = ['198.51.100.99'] if host == 'health.cache.test' else ['198.51.100.7' if label == 'old-hosts-at-140' else '198.51.100.9'] if host == 'hosts.pressure.test' else ['198.51.100.7', '198.51.100.8'] if 'q' in host.split('.')[0] and host.startswith('b') else ['198.51.100.7']
            if sorted(r['data'] for r in answers) != sorted(wanted) or any(r['type'] != 1 for r in answers):
                raise AssertionError('ordinary A contents differ: ' + label)
        if any(not 0 < r['ttl'] <= 600 for r in answers):
            raise AssertionError('resource witness TTL outside configured lifetime')
        self.event(label, query=driver.normalized(wire), reply=parsed)
        return parsed

    def query(self, label, client=None, host='health.cache.test', kind=1):
        wire = self.request(host, kind)
        return self.capture(label, wire, driver.exchange(self.port, wire, tcp=client is not None, connection=client))

    def sample(self, label):
        value = family_sample(self.pid)
        value['label'] = label
        self.samples.append(value)
        (self.folder / 'resources.json').write_text(json.dumps(self.samples, indent=2) + '\n')
        return value

    def confirm_warm_idle(self, label):
        self.gauge(0, label + '-gauge')
        if self.clients or family_sample(self.pid)['child_processes']:
            raise AssertionError('cannot establish idle while a client remains')
        self.idle = fd_set(self.pid)
        self.event(label, idle_fds=self.idle)

    def close(self, client):
        client.close()
        if client in self.clients:
            self.clients.remove(client)

    def drain(self, label):
        for client in list(self.clients):
            self.close(client)
        self.gauge(0, label + '-gauge')
        until, stable = time.monotonic() + 5, 0
        while True:
            snap = family_sample(self.pid)
            matched = fd_set(self.pid) == self.idle and snap['child_processes'] == 0
            stable = stable + 1 if matched else 0
            if stable == 3:
                break
            if time.monotonic() > until:
                raise AssertionError('FD/child stable drain failed')
            time.sleep(.02)
        self.event(label, tcp_connections=0, parent_fds_restored=True, children=0, stable_observations=stable)

    def after_drain(self):
        before = time.monotonic()
        for second in self.spec['samples_after_drain_seconds']:
            delay = before + second - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.sample('after-drain-' + str(second))


def schedule(spec, port, upstream, folder, root):
    fixture = Caller(spec, port, upstream, folder, root)
    mode = spec['mode']
    try:
        fixture.sample('idle')
        if mode == '100-query':
            client = fixture.connect()
            ignored = [b'abc', driver.query('health.cache.test', 0x7001, flags=0x8100)]
            for wire in ignored:
                client.sendall(struct.pack('!H', len(wire)) + wire)
            client.settimeout(.15)
            try:
                data = client.recv(1)
                raise AssertionError(('ignored frame produced reply/EOF', data.hex()))
            except socket.timeout:
                fixture.event('ignored-frames', count=2, no_reply=True)
            client.settimeout(3)
            for n in range(99):
                fixture.query(f'ordinary-{n:03}', client)
            fixture.event('before-hundredth', metrics=fixture.gauge(1, 'before-hundredth'))
            fixture.query('ordinary-099', client)
            if client.recv(1) != b'':
                raise AssertionError('100-query boundary did not close after full reply')
            fixture.event('hundredth-eof', replies=100, eof=True)
        elif mode == 'half-frame':
            for index, payload in enumerate([b'\x00', b'\x00\x20abc']):
                client = fixture.connect()
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                if client.recv(1) != b'':
                    raise AssertionError('partial frame produced a reply')
                fixture.event('half-frame-' + str(index), payload=payload.hex(), no_reply=True, eof=True)
                fixture.close(client)
                fixture.gauge(0, 'partial-drain-' + str(index))
        elif mode == 'slow-write':
            client = fixture.connect()
            wire = fixture.request()
            frame = struct.pack('!H', len(wire)) + wire
            for index, chunk in enumerate([frame[:1], frame[1:5]]):
                client.sendall(chunk)
                if select.select([client], [], [], .15)[0]:
                    raise AssertionError('reply before complete frame')
                fixture.query('parent-progress-' + str(index))
            client.sendall(frame[5:])
            reply = driver.exact_read(client, struct.unpack('!H', driver.exact_read(client, 2))[0])
            fixture.capture('slow-write-completed', wire, reply)
        elif mode == 'slow-read':
            client = fixture.connect(small_receive=True)
            requests = [fixture.request('large.pressure.test', 16) for _ in range(100)]
            client.sendall(b''.join(struct.pack('!H', len(wire)) + wire for wire in requests))
            time.sleep(5)
            state = fixture.metrics('paused-read')
            fixture.event('paused-read', metrics=state, receive_buffer=client.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                          queued_data_visible=bool(select.select([client], [], [], 0)[0]))
            if state['tcp_connections'] != 1:
                raise AssertionError('not covered: downstream write backpressure was not reached')
            fixture.sample('writer-held')
            fixture.query('parent-during-slow-read')
            for n, wire in enumerate(requests):
                reply = driver.exact_read(client, struct.unpack('!H', driver.exact_read(client, 2))[0])
                if len(reply) < 48_000:
                    raise AssertionError('large-response witness absent')
                fixture.capture('large-' + f'{n:03}', wire, reply)
            if client.recv(1) != b'':
                raise AssertionError('slow-read 100th reply did not lead to EOF')
        elif mode == 'capacity':
            for _ in range(20):
                fixture.connect()
            fixture.sample('twenty-active')
            for _ in range(10):
                fixture.connect('192.0.2.2')
            fixture.sample('thirty-active')
            queued = socket.create_connection(('192.0.2.2', port), timeout=3)
            queued.settimeout(.15)
            try:
                wire = fixture.request()
                queued.sendall(struct.pack('!H', len(wire)) + wire)
                try:
                    queued.recv(1)
                    raise AssertionError('over-limit connection replied or closed')
                except socket.timeout:
                    pass
                fixture.event('queued-at-limit', no_reply=True, metrics=fixture.gauge(30, 'at-limit'))
                fixture.query('parent-at-limit')
                fixture.query('existing-at-limit', fixture.clients[0])
                fixture.close(fixture.clients[0])
                queued.settimeout(3)
                reply = driver.exact_read(queued, struct.unpack('!H', driver.exact_read(queued, 2))[0])
                fixture.capture('queued-recovered', wire, reply)
            finally:
                queued.close()
        elif mode == 'idle-pin':
            seed = 'seed.pressure.test'
            fixture.query('seed-before-pin', host=seed)
            fixture.confirm_warm_idle('warmed-idle')
            client = fixture.connect()
            accepted = time.monotonic()
            for n in range(140):
                if n == 20:
                    (root / 'm2/caller.hosts').write_text('198.51.100.9 hosts.pressure.test\n')
                    driver.process_hup(folder)
                fixture.query('churn-' + f'{n:03}', host=f'churn{n}.pressure.test')
                delay = accepted + n + 1 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            fixture.query('old-cache-at-140', client, seed)
            fixture.query('old-hosts-at-140', client, 'hosts.pressure.test')
            fixture.query('parent-new-hosts', host='hosts.pressure.test')
            client.settimeout(20)
            if client.recv(1) != b'':
                raise AssertionError('150-second connection emitted unexpected data')
            elapsed = time.monotonic() - accepted
            if not 145 <= elapsed <= 160:
                raise AssertionError(('fixed lifetime witness differs', elapsed))
            fixture.event('fixed-lifetime', total_seconds=elapsed, recent_query_at_seconds=140, eof=True)
        elif mode == 'reconnect':
            for batch in range(spec['batches']):
                names = [f'b{batch}q{n:03}.pressure.test' for n in range(64)]
                for host in names:
                    upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336407'}, {'data': 'c6336408'}]}
                    fixture.query(f'b{batch}-seed-{names.index(host):03}', host=host)
                if batch == 0:
                    fixture.confirm_warm_idle('warmed-idle')
                for _ in range(spec['clients']):
                    fixture.connect()
                fixture.sample(f'b{batch}-twenty-active')
                for n in range(200):
                    fixture.query(f'b{batch}-parent-churn-{n:03}', host=f'b{batch}new{n}.pressure.test')
                for n, client in enumerate(fixture.clients):
                    fixture.query(f'b{batch}-child-{n:02}', client, names[n])
                fixture.drain(f'b{batch}-drained')
                fixture.sample(f'b{batch}-idle')
        else:
            raise ValueError('unknown frozen TCP resource mode')
        fixture.drain('final-drain')
        fixture.after_drain()
        return fixture.rows
    finally:
        for client in list(fixture.clients):
            fixture.close(client)


def run(args):
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('candidate identity differs')
    selected = [c for c in CASES if not args.profile or c['case'] in args.profile]
    if not selected:
        raise ValueError('unknown profile')
    original_network = driver.network
    def network():
        original_network()
        subprocess.run(['ip', 'addr', 'add', '192.0.2.2/24', 'dev', 'cache0'], check=True)
    driver.network, driver.schedule = network, schedule
    driver.SYNTAX.clear()
    driver.SCENARIOS[:] = copy.deepcopy(selected)
    args.only = '^m6b-tcp-'
    status = driver.run(args)
    out = args.out.resolve()
    (out / 'drivers/m6b_tcp_pressure.py').write_bytes(Path(__file__).read_bytes())
    (out / 'profile-plan.json').write_text(json.dumps(selected, indent=2) + '\n')
    report = {'scope': __doc__, 'side': args.side, 'candidate_sha256': args.expected_rust_sha,
              'driver_sha256': driver.sha256(__file__), 'profiles': [c['case'] for c in selected],
              'completed_without_fixture_errors': status == 0, 'qualified': False,
              'reason': 'requires paired raw validation; internal view/root/live-byte diagnostic remains separate'}
    (out / 'resource-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return status


def paired(args):
    all_rows, failures, resources = {'c': {}, 'rust': {}}, [], {}
    for side, folders in [('c', args.c), ('rust', args.rust)]:
        for folder in folders:
            report, rows = driver.comparison_rows(folder, side)
            receipt = json.loads((folder / 'resource-receipt.json').read_text())
            root = json.loads((folder / 'rootfs-identity.json').read_text())
            if (not receipt['completed_without_fixture_errors']
                    or receipt['driver_sha256'] != driver.sha256(__file__)
                    or report['c_sha256'] != driver.STOCK_SHA256):
                raise ValueError('different or incomplete resource fixture')
            expected = driver.STOCK_SHA256 if side == 'c' else receipt['candidate_sha256']
            for label, row in rows.items():
                if label in all_rows[side]:
                    raise ValueError('duplicate profile; never select a better run')
                if row['identity']['sha256'] != expected or row['identity']['root'] != root['root']:
                    raise ValueError('actual process is not the bound image/candidate')
                work = folder / label
                for obs in row['observations']:
                    if 'query' not in obs:
                        continue
                    for kind in ['query', 'reply']:
                        if driver.normalized((work / (obs['label'] + '.' + kind)).read_bytes()) != obs[kind]:
                            raise ValueError('raw wire/report differs')
                samples = json.loads((work / 'resources.json').read_text())
                after = {v['label']: v for v in samples if v['label'].startswith('after-drain-')}
                if set(after) != {'after-drain-' + str(n) for n in [0, 1, 5, 15, 60]}:
                    raise ValueError('incomplete fixed drain samples')
                for a, b in zip([0, 1, 5, 15], [1, 5, 15, 60]):
                    if after['after-drain-' + str(b)]['monotonic_ns'] - after['after-drain-' + str(a)]['monotonic_ns'] < (b - a) * 1e9 - 500_000_000:
                        raise ValueError('shortened drain wait')
                if any(v['child_processes'] != 0 for v in after.values()):
                    raise ValueError('child remains after stable drain')
                drained = [v for v in row['observations'] if v['label'].endswith('drained') or v['label'] == 'final-drain']
                if not drained or any(v.get('stable_observations') != 3 or not v.get('parent_fds_restored') for v in drained):
                    raise ValueError('missing stable FD return witness')
                resources.setdefault(label, {})[side] = {'samples': samples,
                    'rss_peak_kib': max(v['rss_kib'] for v in samples), 'pss_peak_kib': max(v['pss_kib'] for v in samples),
                    'not_observed': after['after-drain-60']['not_observed']}
                all_rows[side][label] = row
    expected = {c['case'] for c in CASES}
    missing = sorted(expected - (all_rows['c'].keys() & all_rows['rust'].keys()))
    for label in sorted(expected - set(missing)):
        def semantics(row):
            result = []
            for obs in row['observations']:
                if 'query' in obs:
                    value = {key: copy.deepcopy(obs[key]) for key in ['label', 'query', 'reply']}
                    # This resource supplement compares RR content/order and
                    # framing. Every TTL remains raw and must be within its
                    # configured600s bound; exact fixed-clock TTL is the
                    # separate full M5 S2 contract gate.
                    for record in value['reply']['records']:
                        if record['section'] == 'answer':
                            if not 0 < record['ttl'] <= 600:
                                raise ValueError('resource TTL outside bound')
                            record['ttl'] = 'bounded-resource-TTL; strict-S2-separate'
                    result.append(value)
                elif obs['label'] in ['ignored-frames', 'hundredth-eof'] or obs['label'].startswith('half-frame-'):
                    result.append(obs)
            return result
        if semantics(all_rows['c'][label]) != semantics(all_rows['rust'][label]):
            failures.append(label)
    result = {'scope': __doc__, 'complete_profiles': sorted(expected - set(missing)), 'missing_profiles': missing,
              'semantic_differences': failures, 'resources': resources, 'public_resource_gates_passed': not missing and not failures,
              'internal_balance_qualification': False,
              'reason': 'view/root/transaction/live-requested counts require the separate source-bound diagnostic; FD return is not object accounting',
              'qualified': False}
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'resources'}, indent=2))
    return int(not result['public_resource_gates_passed'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    emit = sub.add_parser('plan'); emit.add_argument('--out', type=Path, required=True)
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--side', choices=['c', 'rust'], required=True)
    execute.add_argument('--expected-rust-sha', required=True)
    execute.add_argument('--profile', action='append', choices=[c['case'] for c in CASES])
    compare = sub.add_parser('compare')
    compare.add_argument('--c', type=Path, action='append', required=True)
    compare.add_argument('--rust', type=Path, action='append', required=True)
    compare.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'plan':
        with args.out.open('x') as stream:
            json.dump({'profiles': CASES, 'scope': __doc__, 'executed': False}, stream, indent=2)
            stream.write('\n')
        return 0
    return paired(args) if args.action == 'compare' else run(args)


if __name__ == '__main__':
    raise SystemExit(main())
