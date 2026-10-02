#!/usr/bin/env python3
"""Functional DNS fixtures for M2; all listeners require run_isolated.sh."""
import copy
import ipaddress
import json
import math
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, query, read_name, rr, semantics
from m2_rootfs import command, image_path, process_identity

LISTEN = ('127.0.0.1', 15353)
UPSTREAM_PORT = 15354
OBJECT = 'm2.dns'


def response(packet, generation, transport):
    host, end = read_name(packet, 12)
    kind = struct.unpack_from('!H', packet, end)[0]
    ttl = 3 if host.startswith('expiry-') else 600
    flags, answers, authority = 0x8180, [], []
    if host == 'truncated.m2.test' and transport == 'udp':
        flags |= 0x200
    elif (host.startswith(('nx.', 'nodata.'))
          or host == 'expiry-negative.m2.test' and generation == 1):
        if not host.startswith('nodata.'):
            flags |= 3
        soa = name('ns.m2.test') + name('admin.m2.test') + struct.pack('!5I', 1, 60, 60, 600, ttl)
        authority = [rr(6, soa, ttl, name('m2.test'))]
    else:
        if kind == 1:
            value = ipaddress.ip_address(f'192.0.2.{generation}').packed
        elif kind == 28:
            value = ipaddress.ip_address(f'2001:db8::{generation}').packed
        elif kind == 12:
            value = name(f'ptr-target-{generation}.m2.test')
        else:
            value = b'\x01m'
        if host == 'alias.m2.test':
            answers = [rr(5, name('target.m2.test'), ttl), rr(kind, value, ttl, name('target.m2.test'))]
        else:
            answers = [rr(kind, value, ttl)]
    return packet[:2] + struct.pack('!5H', flags, 1, len(answers), len(authority), 0) + packet[12:end + 4] + b''.join(answers + authority)


class Upstream:
    def __init__(self, host, label):
        self.label = label
        self.mode = 'answer'
        self.generation = 1
        self.events, self.errors, self.workers, self.connections = [], [], [], []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((host, UPSTREAM_PORT))
        self.udp.settimeout(.05)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((host, UPSTREAM_PORT))
        self.tcp.listen()
        self.tcp.settimeout(.05)
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for thread in self.threads:
            thread.start()

    def configure(self, mode='answer', generation=1):
        with self.lock:
            self.mode, self.generation = mode, generation

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.events)

    def answer(self, packet, transport):
        with self.lock:
            mode, generation = self.mode, self.generation
        reply = None
        if mode == 'answer':
            reply = response(packet, generation, transport)
        elif mode in ('servfail', 'refused'):
            _, end = read_name(packet, 12)
            reply = packet[:2] + struct.pack('!5H', 0x8180 | (2 if mode == 'servfail' else 5), 1, 0, 0, 0) + packet[12:end + 4]
        event = {'time': time.monotonic(), 'server': self.label, 'transport': transport,
                 'query': packet.hex(), 'response': reply.hex() if reply else None,
                 'mode': mode, 'generation': generation}
        with self.lock:
            self.events.append(event)
        return reply, mode

    def udp_loop(self):
        while not self.stopped.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                reply, _ = self.answer(packet, 'udp')
                if reply is not None:
                    self.udp.sendto(reply, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def tcp_loop(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            self.connections.append(client)
            worker = threading.Thread(target=self.connection, args=(client,))
            self.workers.append(worker)
            worker.start()

    def connection(self, client):
        try:
            with client:
                client.settimeout(.2)
                while not self.stopped.is_set():
                    try:
                        prefix = exact_read(client, 2)
                    except socket.timeout:
                        continue
                    packet = exact_read(client, struct.unpack('!H', prefix)[0])
                    reply, mode = self.answer(packet, 'tcp')
                    if mode == 'close':
                        break
                    if reply is not None:
                        client.sendall(struct.pack('!H', len(reply)) + reply)
        except (ConnectionError, BrokenPipeError, ConnectionResetError):
            pass
        except OSError as error:
            if not self.stopped.is_set():
                self.errors.append(repr(error))

    def close(self):
        self.stopped.set()
        for client in self.connections:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in self.threads + self.workers:
            thread.join(2)
        self.udp.close()
        self.tcp.close()
        assert not any(thread.is_alive() for thread in self.threads + self.workers), 'upstream thread remained live'
        assert not self.errors, self.errors


def normalized_upstream(events):
    result = []
    for event in sorted(events, key=lambda event: event['time']):
        request = semantics(bytes.fromhex(event['query']))
        request['id'] = 0
        reply = semantics(bytes.fromhex(event['response'])) if event['response'] else None
        if reply:
            reply['id'] = 0
        result.append({key: event[key] for key in ('server', 'transport', 'mode', 'generation')}
                      | {'query': request, 'response': reply})
    return result


class Product:
    def __init__(self, root, side, out, servers=1):
        self.root, self.side, self.out = root, side, out
        out.mkdir()
        self.servers = [Upstream(f'127.0.0.{index + 2}', f'upstream-{index + 1}') for index in range(servers)]
        self.rows, self.ubus_calls, self.checks, self.udp_clients, self.tcp_clients = [], [], [], {}, {}
        self.seed_times = {}
        self.validate_ttl = True
        self.ident = 0x4000
        self.process = None
        self.bus = None

    def start(self):
        self.bus = subprocess.Popen(command(self.root, '/sbin/ubusd', '-s', '/run/ubus/ubus.sock'),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while not image_path(self.root, 'run/ubus/ubus.sock').exists():
            assert self.bus.poll() is None and time.monotonic() < deadline, 'ubusd readiness timeout'
            time.sleep(.01)
        profile = image_path(self.root, f'm2/{self.out.name}.conf')
        config = ('no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=15353\n'
                  'cache-size=4096\nlocal-ttl=120\nstrict-order\n'
                  'neg-ttl=3\n'
                  'host-record=desktop.home.test,192.0.2.10,2001:db8::10\n'
                  f'enable-ubus={OBJECT}\n')
        config += ''.join(f'server=127.0.0.{index + 2}#{UPSTREAM_PORT}\n' for index in range(len(self.servers)))
        profile.write_text(config)
        (self.out / 'config').write_text(config)
        with (self.out / 'daemon.log').open('w') as log:
            self.process = subprocess.Popen(command(self.root, self.side, '-k', '-C', f'/m2/{profile.name}'), stdout=log, stderr=log)
        self.wait_metrics(lambda _: True)
        self.started = time.monotonic()
        self.initial_metrics = self.metrics()
        (self.out / 'process-identity.json').write_text(json.dumps(process_identity(self.root, self.process.pid), indent=2) + '\n')

    def metrics(self):
        result = subprocess.run(command(self.root, '/bin/ubus', '-s', '/run/ubus/ubus.sock', 'call', OBJECT, 'metrics'), capture_output=True, text=True, timeout=3)
        self.ubus_calls.append({'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            return None
        return json.loads(result.stdout)

    def wait_metrics(self, predicate):
        end = time.monotonic() + 5
        while True:
            result = self.metrics()
            if result is not None and predicate(result):
                return result
            assert self.process.poll() is None and time.monotonic() < end, ('metrics readiness', result)
            time.sleep(.01)

    def connection(self, label, client=0):
        stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stream.settimeout(3)
        stream.bind((f'127.0.0.{50 + client}', 0))
        stream.connect(LISTEN)
        self.tcp_clients[label] = stream
        return stream

    def close_connection(self, label):
        self.tcp_clients.pop(label).close()

    def ask(self, label, host, kind=1, *, client=0, connection=None, fragmented=False,
            expect_reply=True, reuse=None, expected_upstream=None):
        packet = bytes.fromhex(reuse['queries'][0]) if reuse else query(host, kind, self.ident)
        if reuse is None:
            self.ident += 1
        return self.exchange(label, [packet], client, connection, fragmented, expect_reply, expected_upstream)

    def pipeline(self, label, questions, connection):
        packets = [query(host, kind, self.ident + index) for index, (host, kind) in enumerate(questions)]
        self.ident += len(packets)
        return self.exchange(label, packets, 0, connection, False, True, len(packets))

    def exchange(self, label, packets, client, connection, fragmented, expect_reply, expected_upstream):
        offsets = [len(server.snapshot()) for server in self.servers]
        began = time.monotonic()
        replies = []
        if connection is None:
            assert len(packets) == 1
            if client not in self.udp_clients:
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.bind((f'127.0.0.{50 + client}', 0))
                self.udp_clients[client] = udp
            udp = self.udp_clients[client]
            udp.settimeout(3 if expect_reply else .3)
            udp.sendto(packets[0], LISTEN)
            try:
                replies.append(udp.recv(65535))
            except socket.timeout:
                if expect_reply:
                    raise
        else:
            stream = self.tcp_clients[connection]
            framed = b''.join(struct.pack('!H', len(packet)) + packet for packet in packets)
            if fragmented:
                for piece in (framed[:1], framed[1:4], framed[4:]):
                    stream.sendall(piece)
                    time.sleep(.002)
            else:
                stream.sendall(framed)
            for _ in packets:
                replies.append(exact_read(stream, struct.unpack('!H', exact_read(stream, 2))[0]))
        events = [event for server, offset in zip(self.servers, offsets) for event in server.snapshot()[offset:]]
        decoded = [semantics(reply) for reply in replies]
        row = {'label': label, 'queries': [packet.hex() for packet in packets], 'responses': [reply.hex() for reply in replies],
               'semantic': decoded, 'transport': 'tcp' if connection else 'udp', 'client': client,
               'upstream_raw': events, 'upstream': normalized_upstream(events),
               'expect_reply': expect_reply, 'expected_upstream': expected_upstream,
               'elapsed': began - self.started, 'ttl_checks': []}
        self.rows.append(row)
        assert len(replies) == (len(packets) if expect_reply else 0), ('reply count', label)
        assert all(reply[:2] == packet[:2] for packet, reply in zip(packets, replies)), ('transaction association', label)
        if expected_upstream is not None:
            assert len(events) == expected_upstream, ('upstream count', label, len(events), expected_upstream)
        # Validate remaining TTL against the observed insertion clock, then let
        # comparison ignore at most the native integer-second clock boundary.
        for event in events:
            if event['response']:
                for record in semantics(bytes.fromhex(event['response']))['records']:
                    key = json.dumps({key: value for key, value in record.items() if key not in ('ttl', 'section')}, sort_keys=True)
                    self.seed_times[key] = (began, record['ttl'])
        for answer in decoded:
            for record in answer['records']:
                key = json.dumps({key: value for key, value in record.items() if key not in ('ttl', 'section')}, sort_keys=True)
                if key in self.seed_times:
                    seeded, ttl = self.seed_times[key]
                    age = max(0, began - seeded)
                    low, high = max(0, ttl - math.ceil(age) - 1), max(0, min(ttl, ttl - math.floor(age) + 1))
                    row['ttl_checks'].append({'ttl': record['ttl'], 'original': ttl, 'age': age,
                                              'low': low, 'high': high, 'pass': low <= record['ttl'] <= high})
        if self.validate_ttl:
            assert all(check['pass'] for check in row['ttl_checks']), ('TTL bound', label, row['ttl_checks'])
        return row

    def close(self):
        for stream in list(self.tcp_clients.values()) + list(self.udp_clients.values()):
            stream.close()
        self.tcp_clients.clear()
        self.udp_clients.clear()
        final = self.metrics() if self.process and self.process.poll() is None else None
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(3)
            self.checks.append({'name': 'daemon-normal-exit', 'pass': self.process.returncode == 0,
                                'exit': self.process.returncode})
        for server in self.servers:
            server.close()
        if self.bus is not None:
            if self.bus.poll() is None:
                self.bus.send_signal(signal.SIGTERM)
            try:
                self.bus.wait(3)
            except subprocess.TimeoutExpired:
                self.bus.kill()
                self.bus.wait(3)
        result = {'rows': self.rows, 'checks': self.checks, 'ubus': self.ubus_calls,
                  'initial_metrics': getattr(self, 'initial_metrics', None), 'final_metrics': final,
                  'upstream': [event for server in self.servers for event in server.snapshot()]}
        (self.out / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
        return result


def normalized_row(row):
    result = {key: copy.deepcopy(row[key]) for key in ('label', 'semantic', 'transport', 'client', 'upstream', 'expect_reply', 'expected_upstream')}
    for answer in result['semantic']:
        for record in answer['records']:
            # Raw TTL and independently checked elapsed bounds remain in trace.
            record['ttl'] = 'validated-remaining' if row['ttl_checks'] else record['ttl']
    return result
