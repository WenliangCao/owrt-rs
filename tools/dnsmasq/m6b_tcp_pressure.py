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
import re
from pathlib import Path
import select
import socket
import struct
import subprocess
import time
import threading

import m5_dns_cache as driver


BIG_TEXT = ','.join('"' + 'x' * 255 + '"' for _ in range(192))
CASES = [
    {'case': 'm6b-tcp-100-query', 'mode': '100-query', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-half-frame', 'mode': 'half-frame', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-rst-forward-import', 'mode': 'rst', 'capacity': 150, 'config': ''},
    {'case': 'm6b-tcp-upstream-eof', 'mode': 'upstream-eof', 'capacity': 150,
     'config': 'strict-order\nserver=127.0.0.3#15454\nserver=127.0.0.2#@UPSTREAM@'},
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
TOOLS = ['m6b_tcp_pressure.py', 'm5_dns_cache.py', 'm5_dns_cache.json',
         'm2_rootfs.py', 'm2_rootfs_image.py', 'dns_service_probe.py', 'run_isolated.sh']


def root_provenance(root):
    filesystem = root.get('filesystem', {})
    if (root.get('c_sha256') != driver.STOCK_SHA256 or filesystem.get('kind') != 'overlay'
            or filesystem.get('lower_read_only') is not True
            or not re.fullmatch('[0-9a-f]{64}', filesystem.get('base_manifest_sha256', ''))
            or not root.get('image_files')):
        raise ValueError('exact-image immutable rootfs provenance missing')
    for key in ['image_sha256', 'image_provenance_sha256']:
        if key not in root or root[key] is not None and not re.fullmatch('[0-9a-f]{64}', root[key]):
            raise ValueError('image provenance identity differs')
    return {key: root[key] for key in ['c_sha256', 'image_sha256', 'image_provenance_sha256', 'image_files']} | {
        'base_manifest_sha256': filesystem['base_manifest_sha256']}


def frozen_tools():
    return {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}




def fd_set(pid):
    return {p.name: os.readlink(p) for p in (Path('/proc') / str(pid) / 'fd').iterdir()}


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


class EofServers:
    """One bounded selector thread; close old/fresh primary q2, then fallback."""
    def __init__(self, port, fallback_port=15454, primary_address='127.0.0.2', fallback_address='127.0.0.3'):
        self.listeners, self.clients, self.events, self.errors = {}, {}, [], []
        self.stop = threading.Event()
        for role, address, number in [('primary', primary_address, port), ('fallback', fallback_address, fallback_port)]:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((address, number)); listener.listen(); listener.setblocking(False)
            except Exception:
                listener.close()
                for opened in self.listeners:
                    opened.close()
                raise
            self.listeners[listener] = role
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        opened = {'primary': 0, 'fallback': 0}
        while not self.stop.is_set():
            try:
                ready, _, _ = select.select([*self.listeners, *self.clients], [], [], .02)
                for stream in ready:
                    if stream in self.listeners:
                        client, _ = stream.accept(); client.setblocking(False)
                        role = self.listeners[stream]; opened[role] += 1
                        self.clients[client] = {'role': role, 'ordinal': opened[role], 'bytes': b''}
                        continue
                    state = self.clients[stream]
                    data = stream.recv(65535)
                    if not data:
                        self.clients.pop(stream); stream.close(); continue
                    state['bytes'] += data
                    while len(state['bytes']) >= 2:
                        size = struct.unpack('!H', state['bytes'][:2])[0]
                        if len(state['bytes']) < size + 2:
                            break
                        packet, state['bytes'] = state['bytes'][2:size + 2], state['bytes'][size + 2:]
                        host, end = driver.read_name(packet, 12)
                        self.events.append({'server': state['role'], 'connection': state['ordinal'],
                                            'host': host, 'query': driver.normalized(packet), 'wire': packet.hex()})
                        if state['role'] == 'primary' and host == 'second.pressure.test':
                            self.clients.pop(stream); stream.close(); break
                        data = socket.inet_aton('198.51.100.7' if state['role'] == 'primary' else '198.51.100.8')
                        reply = packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + packet[12:end + 4] + driver.rr(1, data, ttl=600)
                        stream.sendall(struct.pack('!H', len(reply)) + reply)
            except Exception as error:
                self.errors.append(repr(error)); break

    def close(self):
        self.stop.set(); self.thread.join(3)
        if self.thread.is_alive():
            raise AssertionError('EOF fixture thread did not stop')
        for stream in [*self.clients, *self.listeners]:
            stream.close()
        if self.errors:
            raise AssertionError(('EOF fixture error', self.errors))


class Caller:
    def __init__(self, spec, port, upstream, folder, root):
        self.spec, self.port, self.upstream, self.folder, self.root = spec, port, upstream, folder, root
        self.pid = int((folder / 'pid').read_text())
        self.rows, self.clients, self.samples = [], [], []
        self.wire_id = 0x8000
        self.accept_sequence = 0
        if self.metrics('idle-confirmed')['tcp_connections'] != 0:
            raise AssertionError('fixture starts with active clients')
        self.idle, self.idle_receipt = self.stable_idle('idle-confirmed')

    def event(self, label, **fields):
        self.rows.append({'label': label, **fields})

    def metrics(self, label):
        argv = driver.command(self.root, '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}')
        run = subprocess.run(argv, capture_output=True, timeout=2)
        (self.folder / (label + '.metrics.stdout')).write_bytes(run.stdout)
        (self.folder / (label + '.metrics.stderr')).write_bytes(run.stderr)
        (self.folder / (label + '.metrics.call.json')).write_text(json.dumps({
            'argv': argv, 'returncode': run.returncode, 'pid': self.pid,
            'stdout_sha256': hashlib.sha256(run.stdout).hexdigest(),
            'stderr_sha256': hashlib.sha256(run.stderr).hexdigest()}, indent=2) + '\n')
        if run.returncode:
            raise AssertionError('actual image UBus metrics failed')
        return json.loads(run.stdout)

    def gauge(self, wanted, label):
        until = time.monotonic() + 5
        observations = []
        while True:
            value = self.metrics(label + f'-{len(observations):03}')
            observations.append({'monotonic_ns': time.monotonic_ns(), 'wanted': wanted, 'value': value})
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
        self.accept_sequence += 1
        self.gauge(len(self.clients), 'accept-' + str(self.accept_sequence))
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
            wanted = ['198.51.100.99'] if host == 'health.cache.test' else ['198.51.100.8'] if host == 'second.pressure.test' else ['198.51.100.7' if label == 'old-hosts-at-140' else '198.51.100.9'] if host == 'hosts.pressure.test' else ['198.51.100.7', '198.51.100.8'] if 'q' in host.split('.')[0] and host.startswith('b') else ['198.51.100.7']
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

    def stable_idle(self, label):
        observations, until, previous, stable = [], time.monotonic() + 5, None, 0
        path = label + '.idle-fds.json'
        while True:
            try:
                snapshot = family_sample(self.pid)
                parent = next(row for row in snapshot['members'] if row['pid'] == self.pid)
                current = parent['fds']
                matched = snapshot['child_processes'] == 0 and snapshot['threads'] == 1 and current == previous
                stable = stable + 1 if matched else 1 if snapshot['child_processes'] == 0 and snapshot['threads'] == 1 else 0
                observations.append({'monotonic_ns': time.monotonic_ns(), 'snapshot': snapshot})
                previous = current
            except (FileNotFoundError, ProcessLookupError) as error:
                observations.append({'monotonic_ns': time.monotonic_ns(), 'snapshot': None, 'error': repr(error)})
                stable = 0
            (self.folder / path).write_text(json.dumps(observations, indent=2) + '\n')
            if stable == 3:
                return current, path
            if time.monotonic() > until:
                raise AssertionError('confirmed idle FD identities did not stabilize')
            time.sleep(.02)

    def confirm_warm_idle(self, label):
        self.gauge(0, label + '-gauge')
        if self.clients:
            raise AssertionError('cannot establish idle while a client remains')
        self.idle, self.idle_receipt = self.stable_idle(label)
        self.event(label, idle_fds=self.idle, baseline_receipt=self.idle_receipt)

    def close(self, client):
        client.close()
        if client in self.clients:
            self.clients.remove(client)

    def drain(self, label):
        for client in list(self.clients):
            self.close(client)
        self.gauge(0, label + '-gauge')
        until, stable, samples = time.monotonic() + 5, 0, []
        path = label + '.drain-samples.json'
        while True:
            try:
                snap = family_sample(self.pid)
                parent = next(row for row in snap['members'] if row['pid'] == self.pid)
                matched = parent['fds'] == self.idle and snap['child_processes'] == 0 and snap['threads'] == 1
                stable = stable + 1 if matched else 0
                samples.append({'monotonic_ns': time.monotonic_ns(), 'snapshot': snap})
            except (FileNotFoundError, ProcessLookupError) as error:
                samples.append({'monotonic_ns': time.monotonic_ns(), 'snapshot': None, 'error': repr(error)})
                stable = 0
            (self.folder / path).write_text(json.dumps(samples, indent=2) + '\n')
            if stable == 3:
                break
            if time.monotonic() > until:
                raise AssertionError('FD/child stable drain failed')
            time.sleep(.02)
        self.event(label, tcp_connections=0, parent_fds_restored=True, children=0, stable_observations=stable,
                   baseline_receipt=self.idle_receipt, drain_receipt=path, gauge_receipt=label + '-gauge.gauge.json')

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
        elif mode == 'rst':
            host = 'rst.pressure.test'
            upstream.plan[host] = {'ttl': 600, 'hold': True, 'answers': [{'data': 'c6336407'}]}
            client = fixture.connect()
            wire = fixture.request(host)
            client.sendall(struct.pack('!H', len(wire)) + wire)
            (folder / 'rst-client.query').write_bytes(wire)
            until = time.monotonic() + 3
            while not upstream.held:
                if time.monotonic() > until:
                    raise AssertionError('RST in-flight upstream witness not reached')
                time.sleep(.01)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            fixture.close(client)
            fixture.event('rst-before-release', request_reached_upstream=True, downstream_closed=True)
            fixture.query('parent-during-rst-hold')
            upstream.plan[host] = {'ttl': 600, 'answers': [{'data': 'c6336407'}]}
            upstream.release(host)
            until = time.monotonic() + 3
            values = []
            while True:
                value = fixture.metrics('rst-after-release-' + str(len(values)))
                values.append(value)
                (folder / 'rst-import-metric-witness.json').write_text(json.dumps(values, indent=2) + '\n')
                if value['dns_cache_inserted'] == 1:
                    if value['dns_cache_live_freed'] != 0:
                        raise AssertionError('RST import unexpectedly spilled a live record')
                    fixture.event('rst-imported-before-drop', dns_cache_inserted=1, dns_cache_live_freed=value['dns_cache_live_freed'])
                    break
                if time.monotonic() > until:
                    raise AssertionError('RST discarded the ordinary successful cache import')
                time.sleep(.01)
            fixture.query('parent-rst-import-hit', host=host)
            if [e['transport'] for e in upstream.events] != ['tcp']:
                raise AssertionError('RST imported answer was not a parent cache hit')
        elif mode == 'upstream-eof':
            port_number = upstream.port
            upstream.close()
            peer = EofServers(port_number)
            try:
                client = fixture.connect()
                fixture.query('old-connection-seed', client, 'first.pressure.test')
                fixture.query('old-and-fresh-eof-fallback', client, 'second.pressure.test')
                wanted = [('primary', 1, 'first.pressure.test'), ('primary', 1, 'second.pressure.test'),
                          ('primary', 2, 'second.pressure.test'), ('fallback', 1, 'second.pressure.test')]
                if [(e['server'], e['connection'], e['host']) for e in peer.events] != wanted:
                    raise AssertionError('actual EOF/reconnect/fallback schedule differs')
                (folder / 'upstream-eof-events.json').write_text(json.dumps(peer.events, indent=2) + '\n')
                fixture.query('parent-eof-import-hit', host='second.pressure.test')
            finally:
                peer.close()
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
    if not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('full frozen source binding required')
    frozen = frozen_tools()
    hashes = {name: driver.sha256(Path(__file__).with_name(name)) for name in TOOLS}
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
    for name, data in frozen.items():
        (out / 'drivers' / name).write_bytes(data)
    unchanged = frozen == frozen_tools()
    (out / 'profile-plan.json').write_text(json.dumps(selected, indent=2) + '\n')
    root = json.loads((out / 'rootfs-identity.json').read_text())
    report = {'scope': __doc__, 'side': args.side, 'candidate_sha256': args.expected_rust_sha,
              'source_commit': args.source_commit, 'tools': hashes, 'tools_unchanged': unchanged,
              'root_provenance': root_provenance(root),
              'source_binding_scope': 'caller-declared freeze; source-to-ELF build proof remains external',
              'driver_sha256': driver.sha256(__file__), 'profiles': [c['case'] for c in selected],
              'completed_without_fixture_errors': status == 0 and unchanged, 'qualified': False,
              'reason': 'requires paired raw validation; internal view/root/live-byte diagnostic remains separate'}
    (out / 'resource-receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return status or int(not unchanged)


def bound_candidate(report, receipt, root, wanted):
    if (not re.fullmatch('[0-9a-f]{64}', wanted) or receipt.get('candidate_sha256') != wanted
            or report.get('rust_sha256') != wanted or root.get('rust_sha256') != wanted
            or root.get('c_sha256') != driver.STOCK_SHA256):
        raise ValueError('every public resource profile must use the same frozen candidate/image')


def eof_inventory(folder):
    rows = json.loads((folder / 'upstream-eof-events.json').read_text())
    expected = [('primary', 1, 'first.pressure.test'), ('primary', 1, 'second.pressure.test'),
                ('primary', 2, 'second.pressure.test'), ('fallback', 1, 'second.pressure.test')]
    if [(row['server'], row['connection'], row['host']) for row in rows] != expected:
        raise ValueError('complete actual EOF inventory differs')
    for index, row in enumerate(rows):
        packet = bytes.fromhex(row['wire'])
        parsed = driver.normalized(packet)
        client = (folder / ('old-connection-seed.query' if index == 0 else 'old-and-fresh-eof-fallback.query')).read_bytes()
        if (parsed != row['query'] or parsed['questions'] != driver.normalized(client)['questions']
                or packet[:2] != client[:2]):
            raise ValueError('actual EOF wire/question/id differs')
    if len({row['wire'] for row in rows[1:]}) != 1:
        raise ValueError('EOF retry/fallback changed the pending query wire')


def metric_receipt(work, label, pid, root):
    stdout = work / (label + '.metrics.stdout')
    stderr = work / (label + '.metrics.stderr')
    call = json.loads((work / (label + '.metrics.call.json')).read_text())
    if (call.get('returncode') != 0 or call.get('pid') != pid
            or call.get('argv') != driver.command(Path(root), '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}')
            or call.get('stdout_sha256') != driver.sha256(stdout) or call.get('stderr_sha256') != driver.sha256(stderr)):
        raise ValueError('actual metric invocation/output differs')
    return json.loads(stdout.read_text())


def gauge_receipt(work, filename, pid, root, wanted=None):
    path = work / filename
    rows = json.loads(path.read_text())
    label = path.name.removesuffix('.gauge.json')
    if not rows or any(type(row.get('monotonic_ns')) is not int for row in rows):
        raise ValueError('actual gauge observations missing')
    target = rows[-1].get('wanted')
    if type(target) is not int or target < 0 or wanted is not None and target != wanted:
        raise ValueError('gauge target differs')
    if any(row.get('wanted') != target or metric_receipt(work, label + f'-{index:03}', pid, root) != row['value']
           for index, row in enumerate(rows)):
        raise ValueError('gauge/raw metrics differ')
    if rows[-1]['value']['tcp_connections'] != target:
        raise ValueError('gauge did not reach target')
    if any(b['monotonic_ns'] <= a['monotonic_ns'] for a, b in zip(rows, rows[1:])):
        raise ValueError('gauge observations not ordered')
    return rows


def stable_fd_receipt(work, filename, pid, expected=None):
    if Path(filename).name != filename:
        raise ValueError('FD receipt must be a fixed file in this profile')
    rows = json.loads((work / filename).read_text())
    tail = rows[-3:]
    if len(tail) != 3:
        raise ValueError('three actual stable FD samples missing')
    wanted = expected
    for row in tail:
        snapshot = row.get('snapshot')
        if not snapshot or snapshot.get('child_processes') != 0 or snapshot.get('threads') != 1:
            raise ValueError('idle parent/child/thread proof missing')
        parents = [member for member in snapshot['members'] if member['pid'] == pid]
        if len(parents) != 1 or len(snapshot['members']) != 1 or not parents[0]['fds']:
            raise ValueError('actual parent FD observation missing')
        if wanted is None:
            wanted = parents[0]['fds']
        if parents[0]['fds'] != wanted:
            raise ValueError('original idle FD identities not restored')
    if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
        raise ValueError('stable FD observations not separated')
    return wanted, tail[-1]['monotonic_ns']


def validate_profile(work, row, pid, root):
    gauges = list(work.glob('*.gauge.json'))
    if not gauges:
        raise ValueError('actual accept/drain gauges missing')
    for path in gauges:
        gauge_receipt(work, path.name, pid, root)
    for path in work.glob('*.metrics.stdout'):
        metric_receipt(work, path.name.removesuffix('.metrics.stdout'), pid, root)
    drained = [value for value in row['observations'] if value['label'].endswith('drained') or value['label'] == 'final-drain']
    if not drained or drained[-1]['label'] != 'final-drain':
        raise ValueError('final drain missing')
    final_idle, final_stamp = None, None
    for value in drained:
        if (value.get('stable_observations') != 3 or value.get('parent_fds_restored') is not True
                or value.get('tcp_connections') != 0 or value.get('children') != 0
                or value.get('drain_receipt') != value['label'] + '.drain-samples.json'
                or value.get('gauge_receipt') != value['label'] + '-gauge.gauge.json'):
            raise ValueError('drain claim differs')
        idle, stamp = stable_fd_receipt(work, value['baseline_receipt'], pid)
        _, final_stamp = stable_fd_receipt(work, value['drain_receipt'], pid, idle)
        gauge_receipt(work, value['gauge_receipt'], pid, root, 0)
        if stamp >= final_stamp:
            raise ValueError('drain preceded its confirmed idle baseline')
        final_idle = idle
    samples = json.loads((work / 'resources.json').read_text())
    labels = [value['label'] for value in samples if value['label'].startswith('after-drain-')]
    if labels != ['after-drain-' + str(n) for n in [0, 1, 5, 15, 60]]:
        raise ValueError('complete ordered fixed drain samples required')
    after = [value for value in samples if value['label'].startswith('after-drain-')]
    if after[0]['monotonic_ns'] < final_stamp:
        raise ValueError('after-drain sample preceded stable drain')
    for value in after:
        parents = [member for member in value['members'] if member['pid'] == pid]
        if (value['child_processes'] != 0 or value['threads'] != 1 or len(parents) != 1
                or len(value['members']) != 1 or parents[0]['fds'] != final_idle):
            raise ValueError('post-drain parent/FD balance differs')
    for a, b in zip(after, after[1:]):
        seconds = int(b['label'].split('-')[-1]) - int(a['label'].split('-')[-1])
        if b['monotonic_ns'] - a['monotonic_ns'] < seconds * 1e9 - 500_000_000:
            raise ValueError('shortened fixed drain wait')
    return samples


def paired(args):
    if args.out.exists() or not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('fresh comparison and full source binding required')
    all_rows, failures, resources, provenance = {'c': {}, 'rust': {}}, [], {}, None
    for side, folders in [('c', args.c), ('rust', args.rust)]:
        for folder in folders:
            report, rows = driver.comparison_rows(folder, side)
            receipt = json.loads((folder / 'resource-receipt.json').read_text())
            root = json.loads((folder / 'rootfs-identity.json').read_text())
            bound_candidate(report, receipt, root, args.expected_rust_sha)
            if (receipt.get('side') != side or receipt.get('source_commit') != args.source_commit
                    or receipt.get('tools_unchanged') is not True):
                raise ValueError('resource source/side/frozen tools differ')
            for name in TOOLS:
                digest = driver.sha256(Path(__file__).with_name(name))
                if receipt['tools'].get(name) != digest or driver.sha256(folder / 'drivers' / name) != digest:
                    raise ValueError('resource tool/dependency identity differs')
            selected = json.loads((folder / 'profile-plan.json').read_text())
            known = {case['case']: case for case in CASES}
            selected_ids = [case['case'] for case in selected]
            if (not selected_ids or len(selected_ids) != len(set(selected_ids))
                    or any(case != known.get(case['case']) for case in selected)
                    or receipt.get('profiles') != selected_ids or list(rows) != selected_ids
                    or [row['case'] for row in report['scenarios']] != selected_ids
                    or report.get('executed_cases') != selected_ids or report.get('syntax')):
                raise ValueError('frozen complete selected profile inventory differs')
            signature = root_provenance(root)
            if receipt.get('root_provenance') != signature or provenance is not None and signature != provenance:
                raise ValueError('resource C/R image provenance differs')
            provenance = signature
            if (not receipt['completed_without_fixture_errors']
                    or receipt['driver_sha256'] != driver.sha256(__file__)
                    or report['c_sha256'] != driver.STOCK_SHA256):
                raise ValueError('different or incomplete resource fixture')
            expected = driver.STOCK_SHA256 if side == 'c' else args.expected_rust_sha
            for label, row in rows.items():
                if label in all_rows[side]:
                    raise ValueError('duplicate profile; never select a better run')
                if row['identity']['sha256'] != expected or row['identity']['root'] != root['root']:
                    raise ValueError('actual process is not the bound image/candidate')
                work = folder / label
                if row.get('config') != known[label]['config']:
                    raise ValueError('actual profile configuration differs')
                if label == 'm6b-tcp-upstream-eof':
                    eof_inventory(work)
                for obs in row['observations']:
                    if 'query' not in obs:
                        continue
                    for kind in ['query', 'reply']:
                        if driver.normalized((work / (obs['label'] + '.' + kind)).read_bytes()) != obs[kind]:
                            raise ValueError('raw wire/report differs')
                samples = validate_profile(work, row, row['identity']['pid'], root['root'])
                after = {value['label']: value for value in samples if value['label'].startswith('after-drain-')}
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
    result = {'scope': __doc__, 'source_commit': args.source_commit, 'root_provenance': provenance,
              'candidate_sha256': args.expected_rust_sha, 'c_sha256': driver.STOCK_SHA256,
              'complete_profiles': sorted(expected - set(missing)), 'missing_profiles': missing,
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
    execute.add_argument('--source-commit', required=True)
    execute.add_argument('--profile', action='append', choices=[c['case'] for c in CASES])
    compare = sub.add_parser('compare')
    compare.add_argument('--c', type=Path, action='append', required=True)
    compare.add_argument('--rust', type=Path, action='append', required=True)
    compare.add_argument('--out', type=Path, required=True)
    compare.add_argument('--expected-rust-sha', required=True)
    compare.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    if args.action == 'plan':
        with args.out.open('x') as stream:
            json.dump({'profiles': CASES, 'scope': __doc__, 'executed': False}, stream, indent=2)
            stream.write('\n')
        return 0
    return paired(args) if args.action == 'compare' else run(args)


if __name__ == '__main__':
    raise SystemExit(main())
