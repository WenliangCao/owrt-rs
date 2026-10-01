#!/usr/bin/env python3
"""C-only cost diagnostic; workload and gates are frozen in C_COST_DIAGNOSTIC_V2.md.

All listeners/perf sessions run in the dedicated private namespace. Normal
latency samples and profile-only runs are separate. No Rust comparison is made.
"""
from __future__ import annotations

import argparse
import asyncio
import collections
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from dns_service_probe import name, read_name, rr, semantics

ROOT = Path(__file__).resolve().parents[2]
SEED = 0x293001
REFERENCE_SHA256 = 'bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431'
OPT = b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0)
EVENTS = 'task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults'


def now():
    return time.perf_counter_ns()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def percentiles(values):
    values = sorted(values)
    if not values:
        return {}
    result = {f'p{p}': values[min(len(values) - 1, math.ceil(len(values) * p / 100) - 1)] for p in [50, 95]}
    if len(values) >= 10000:
        result['p99'] = values[math.ceil(len(values) * .99) - 1]
    return result


def query_packet(host, qtype, ident):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 1) + name(host) + struct.pack('!HH', qtype, 1) + OPT


def response_packet(packet):
    host, end = read_name(packet, 12)
    qtype, qclass = struct.unpack_from('!HH', packet, end)
    if qclass != 1 or qtype not in [1, 28]:
        raise ValueError('unexpected upstream fixture query')
    if host == 'drop.cal.test':
        return None, host, qtype
    negative = host.startswith('neg-')
    body = b''
    if not negative:
        value = '198.18.0.99' if host == 'bad-data.cal.test' else '198.18.0.7'
        data = socket.inet_pton(socket.AF_INET, value) if qtype == 1 else socket.inet_pton(socket.AF_INET6, '3fff::7')
        body = rr(qtype, data, 120)
    header = packet[:2] + struct.pack('!5H', 0x8183 if negative else 0x8180, 1, 0 if negative else 1, 0, 1)
    return header + packet[12:end + 4] + body + OPT, host, qtype


class Fixture:
    def __init__(self):
        self.received = 0
        self.sent = 0
        self.negative = 0
        self.by_type = collections.Counter()
        self.delays = []
        self.failures = []
        self.connections = 0

    async def answer(self, packet):
        received = now()
        self.received += 1
        response, host, kind = response_packet(packet)
        self.negative += host.startswith('neg-')
        self.by_type[kind] += 1
        if response is None:
            return None
        await asyncio.sleep(.001)
        self.delays.append(now() - received)
        self.sent += 1
        return response

    async def tcp(self, reader, writer):
        self.connections += 1
        try:
            while True:
                prefix = await reader.readexactly(2)
                packet = await reader.readexactly(struct.unpack('!H', prefix)[0])
                response = await self.answer(packet)
                if response is not None:
                    writer.write(struct.pack('!H', len(response)) + response)
                    await writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception as error:
            self.failures.append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    def snapshot(self):
        return {'received': self.received, 'sent': self.sent, 'negative': self.negative,
                'by_type': dict(self.by_type), 'connections': self.connections,
                'delay_count': len(self.delays), 'failures': self.failures,
                'cpu_ns': time.process_time_ns()}


class Datagram(asyncio.DatagramProtocol):
    def __init__(self, fixture):
        self.fixture = fixture
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        async def send():
            try:
                response = await self.fixture.answer(data)
                if response is not None:
                    self.transport.sendto(response, peer)
            except Exception as error:
                self.fixture.failures.append(repr(error))
        asyncio.create_task(send())


async def upstream_role():
    loop = asyncio.get_running_loop()
    fixture = Fixture()
    udp4, _ = await loop.create_datagram_endpoint(lambda: Datagram(fixture), local_addr=('127.0.0.1', 0))
    port = udp4.get_extra_info('sockname')[1]
    udp6, _ = await loop.create_datagram_endpoint(lambda: Datagram(fixture), local_addr=('::1', port), family=socket.AF_INET6)
    tcp4 = await asyncio.start_server(fixture.tcp, '127.0.0.1', port)
    tcp6 = await asyncio.start_server(fixture.tcp, '::1', port, family=socket.AF_INET6)
    print(json.dumps({'ready': True, 'port': port, 'pid': os.getpid()}), flush=True)
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    while line := await reader.readline():
        command = json.loads(line)
        result = fixture.snapshot()
        if command['op'] == 'stop':
            result['delay_ns'] = fixture.delays
            print(json.dumps(result), flush=True)
            break
        print(json.dumps(result), flush=True)
    udp4.close()
    udp6.close()
    tcp4.close()
    tcp6.close()
    await tcp4.wait_closed()
    await tcp6.wait_closed()


def specification(scenario, phase, count):
    rng = random.Random(SEED)
    hot_count = 800 if scenario == 'hot' else 128
    hot_a = [i for i in range(hot_count) if i % 10 < 7]
    hot_aaaa = [i for i in range(hot_count) if i % 10 >= 7]
    if phase == 'calibration':
        return [('ok.cal.test', 1, False), ('ipv6.cal.test', 28, False),
                ('neg-cal.test', 1, True), ('bad-data.cal.test', 1, False), ('drop.cal.test', 1, False)]
    if phase == 'prefill':
        if scenario == 'hot':
            return [(f'hot-{i:04}.test', 1 if i % 10 < 7 else 28, False) for i in range(800)]
        if scenario == 'mixed':
            return ([(f'filler-{i:04}.test', 1, False) for i in range(808)]
                    + [(f'hot-{i:04}.test', 1 if i % 10 < 7 else 28, False) for i in range(128)]
                    + [(f'neg-{i:04}.test', 1, True) for i in range(64)])
        return []
    result = []
    for i in range(count):
        qtype = 1 if (i // 10 if scenario == 'mixed' else i) % 10 < 7 else 28
        if scenario == 'tcp':
            host, negative = f'{phase}-tcp-{i:06}.test', False
        elif scenario == 'mixed' and i % 10 == 9:
            host, negative = f'neg-{rng.randrange(64):04}.test', True
        elif scenario == 'mixed' and i % 10 >= 7:
            host, negative = f'{phase}-unique-{i:06}.test', False
        else:
            host, negative = f'hot-{rng.choice(hot_a if qtype == 1 else hot_aaaa):04}.test', False
        result.append((host, qtype, negative))
    return result


def validate(packet, spec, ident, minimum_ttl):
    host, qtype, negative = spec
    value = semantics(packet)
    if value['id'] != ident or value['flags'] != (0x8183 if negative else 0x8180):
        raise ValueError('id/flags/rcode')
    if value['questions'] != [[host, qtype, 1]]:
        raise ValueError('question')
    answers = [rr for rr in value['records'] if rr['section'] == 'answer']
    authority = [rr for rr in value['records'] if rr['section'] == 'authority']
    opt = [rr for rr in value['records'] if rr['section'] == 'additional']
    if authority or len(answers) != int(not negative) or len(opt) != 1:
        raise ValueError('sections')
    if opt[0]['type'] != 41 or opt[0]['class'] != 1232 or opt[0]['ttl'] != 0 or opt[0]['data'] != '':
        raise ValueError('EDNS')
    if negative:
        return None
    answer = answers[0]
    if answer['name'] != host or answer['type'] != qtype or answer['class'] != 1:
        raise ValueError('answer selection')
    if answer['data'] != ('198.18.0.7' if qtype == 1 else '3fff::7'):
        raise ValueError('address')
    if not minimum_ttl <= answer['ttl'] <= 120:
        raise ValueError('TTL')
    return answer['ttl']


async def client_run(prepared, command):
    specs, packets, config = prepared
    count, rate, workers = len(specs), config['rate'], config['workers']
    start = command['start_ns']
    cpu_before = time.process_time_ns()
    rows = [[i, start + i * 1_000_000_000 // rate, 0, 0, 0, 'not-sent', -1] for i in range(count)]
    errors, connects, closes = [], [], []
    loop = asyncio.get_running_loop()
    bound = start + 30_000_000_000
    async def worker(worker_id):
        sock = None
        reader = writer = None
        connection_queries = 0
        try:
            if config['scenario'] != 'tcp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect(('127.0.0.1', config['port']))
            for i in range(worker_id, count, workers):
                if now() >= bound:
                    break
                planned = rows[i][1]
                if now() < planned:
                    await asyncio.sleep((planned - now()) / 1e9)
                try:
                    if config['scenario'] == 'tcp' and writer is None:
                        before = now()
                        reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', config['port']), 2)
                        connects.append(now() - before)
                        connection_queries = 0
                    rows[i][2] = now()
                    if writer is not None:
                        writer.write(struct.pack('!H', len(packets[i])) + packets[i])
                        await writer.drain()
                        prefix = await asyncio.wait_for(reader.readexactly(2), 2)
                        reply = await asyncio.wait_for(reader.readexactly(struct.unpack('!H', prefix)[0]), 2)
                        connection_queries += 1
                    else:
                        await loop.sock_sendall(sock, packets[i])
                        reply = await asyncio.wait_for(loop.sock_recv(sock, 65535), 2)
                    rows[i][3] = now()
                    minimum = max(0, 120 - math.ceil((rows[i][3] - config['daemon_start_ns']) / 1e9))
                    ttl = validate(reply, specs[i], i & 65535, minimum)
                    rows[i][6] = -1 if ttl is None else ttl
                    rows[i][5] = 'success'
                except asyncio.TimeoutError:
                    rows[i][3] = now()
                    rows[i][5] = 'timeout'
                except Exception as error:
                    rows[i][3] = now()
                    rows[i][5] = 'error'
                    if len(errors) < 20:
                        errors.append({'query': i, 'error': repr(error)})
                rows[i][4] = now()
                if writer is not None and (connection_queries == 100 or rows[i][5] != 'success'):
                    before = now()
                    writer.close()
                    await writer.wait_closed()
                    closes.append(now() - before)
                    reader = writer = None
        finally:
            if sock is not None:
                sock.close()
            if writer is not None:
                before = now()
                writer.close()
                await writer.wait_closed()
                closes.append(now() - before)
    await asyncio.gather(*(worker(i) for i in range(workers)))
    end = now()
    cpu_after = time.process_time_ns()
    counts = collections.Counter(row[5] for row in rows)
    successful = [row for row in rows if row[5] == 'success']
    result = {'planned': count, 'sent': sum(row[2] != 0 for row in rows),
              'success': counts['success'], 'errors': counts['error'], 'timeouts': counts['timeout'],
              'not_sent': counts['not-sent'], 'start_ns': start, 'end_ns': end,
              'cpu_ns': cpu_after - cpu_before, 'errors_detail': errors,
              'actual_rtt_ns': percentiles([row[3] - row[2] for row in successful]),
              'planned_rtt_ns': percentiles([row[3] - row[1] for row in successful]),
              'send_lateness_ns': percentiles([row[2] - row[1] for row in successful]),
              'validation_ns': percentiles([row[4] - row[3] for row in successful]),
              'connect_count': len(connects), 'connect_ns': percentiles(connects),
              'close_count': len(closes), 'close_ns': percentiles(closes)}
    if command.get('output'):
        out = Path(command['output'])
        with (out / 'client-latencies.csv').open('w') as stream:
            writer = csv.writer(stream)
            writer.writerow(['index', 'planned_ns', 'sent_ns', 'received_ns', 'validated_ns', 'status', 'ttl'])
            writer.writerows(rows)
        write_json(out / 'connection-latencies.json', {'connect_ns': connects, 'close_ns': closes})
    return result


async def client_role():
    print(json.dumps({'ready': True, 'pid': os.getpid()}), flush=True)
    prepared = None
    for line in sys.stdin:
        command = json.loads(line)
        if command['op'] == 'stop':
            break
        if command['op'] == 'prepare':
            specs = specification(command['scenario'], command['phase'], command['count'])
            packets = [query_packet(host, qtype, i & 65535) for i, (host, qtype, _) in enumerate(specs)]
            corpus = b''.join(struct.pack('!H', len(packet)) + packet for packet in packets)
            if command.get('output'):
                Path(command['output'], 'corpus.bin').write_bytes(corpus)
            prepared = (specs, packets, command)
            print(json.dumps({'prepared': len(specs), 'corpus_sha256': hashlib.sha256(corpus).hexdigest()}), flush=True)
        elif command['op'] == 'run':
            result = await client_run(prepared, command)
            print(json.dumps(result), flush=True)
            if command.get('require_success') and not all_success(result):
                raise SystemExit(1)
        else:
            raise ValueError('unknown client command')


def read_proc(pid):
    text = Path(f'/proc/{pid}/stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    return {'pid': pid, 'state': fields[0], 'ppid': int(fields[1]), 'pgrp': int(fields[2]),
            'user_ticks': int(fields[11]), 'system_ticks': int(fields[12]),
            'child_user_ticks': int(fields[13]), 'child_system_ticks': int(fields[14]),
            'threads': int(fields[17]), 'start_ticks': int(fields[19])}


def group_members(group):
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            value = read_proc(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            continue
        if value['pgrp'] == group:
            result.append(value)
    return result


def tree_sample(group):
    values, vanished = [], 0
    for process in group_members(group):
        pid = process['pid']
        try:
            fields = {}
            if process['state'] != 'Z':
                for line in Path(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
                    key, _, value = line.partition(':')
                    if key in ['Rss', 'Pss', 'Private_Clean', 'Private_Dirty']:
                        fields[key] = int(value.split()[0]) * 1024
            process.update(rss=fields.get('Rss', 0), pss=fields.get('Pss', 0),
                           uss=fields.get('Private_Clean', 0) + fields.get('Private_Dirty', 0),
                           fds=len(list(Path(f'/proc/{pid}/fd').iterdir())))
            values.append(process)
        except (FileNotFoundError, ProcessLookupError):
            vanished += 1
    return {'time_ns': now(), 'processes': values, 'vanished_during_sample': vanished,
            'total': {key: sum(value[key] for value in values) for key in ['rss', 'pss', 'uss', 'fds', 'threads']},
            'process_count': len(values)}


class Sampler:
    def __init__(self, group):
        self.group = group
        self.rows = []
        self.errors = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.rows.append(tree_sample(self.group))
            except Exception as error:
                self.errors.append(repr(error))
            self.stop_event.wait(.05)

    def start(self):
        self.thread.start()

    def finish(self, path):
        self.stop_event.set()
        self.thread.join(5)
        if self.thread.is_alive() or self.errors:
            raise RuntimeError(f'resource sampler failed: {self.errors}')
        write_json(path, self.rows)
        return {key: max(row['total'][key] for row in self.rows) for key in ['rss', 'pss', 'uss', 'fds', 'threads']} | {
            'processes': max(row['process_count'] for row in self.rows),
            'samples': len(self.rows), 'vanished_during_samples': sum(row['vanished_during_sample'] for row in self.rows)}


class Rpc:
    def __init__(self, role, cpu, log):
        self.log = Path(log).open('w')
        self.process = subprocess.Popen(['taskset', '-c', str(cpu), 'prlimit', '--nofile=1024:1024', '--',
                                         sys.executable, str(Path(__file__).resolve()), '--role', role],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                        text=True, bufsize=1, start_new_session=True)
        self.ready = self.read(10)
        assert self.ready['ready']

    def read(self, timeout):
        if not select.select([self.process.stdout], [], [], timeout)[0]:
            raise TimeoutError('RPC worker did not return a complete result')
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f'RPC worker exited {self.process.poll()}')
        return json.loads(line)

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + '\n')
        self.process.stdin.flush()

    def call(self, value, timeout=45):
        self.send(value)
        return self.read(timeout)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        self.log.close()


class Perf:
    def __init__(self, pid, output, profile=False):
        self.output = output
        self.profile = profile
        self.closed = False
        self.controls = []
        self.control = output / 'perf-control'
        self.ack = output / 'perf-ack'
        os.mkfifo(self.control)
        os.mkfifo(self.ack)
        self.control_fd = os.open(self.control, os.O_RDWR)
        self.ack_fd = os.open(self.ack, os.O_RDWR | os.O_NONBLOCK)
        self.log = (output / 'perf.stderr').open('w')
        command = ['perf', 'record' if profile else 'stat', '-p', str(pid), '--delay=-1',
                   '--control', f'fifo:{self.control},{self.ack}']
        if profile:
            command += ['-F', '997', '--call-graph', 'dwarf', '-o', str(output / 'perf.data')]
        else:
            command += ['-x', ';', '--no-big-num', '-e', EVENTS, '-o', str(output / 'perf-stat.txt')]
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log)

    def command(self, value):
        sent = now()
        os.write(self.control_fd, (value + '\n').encode())
        if not select.select([self.ack_fd], [], [], 5)[0]:
            raise TimeoutError(f'perf did not acknowledge {value}')
        raw = os.read(self.ack_fd, 64)
        acknowledged = now()
        self.controls.append({'command': value, 'sent_ns': sent, 'acknowledged_ns': acknowledged, 'ack_hex': raw.hex()})
        # evlist__ctlfd_ack writes sizeof(ACK_TAG), including the C-string NUL.
        if raw.rstrip(b'\n\0') != b'ack':
            raise RuntimeError('invalid perf acknowledgement')
        return acknowledged

    def close(self):
        if self.closed:
            return
        interrupted = False
        if self.process.poll() is None:
            interrupted = True
            self.process.send_signal(signal.SIGINT)
            self.process.wait(10)
        self.log.close()
        os.close(self.control_fd)
        os.close(self.ack_fd)
        self.control.unlink()
        self.ack.unlink()
        self.closed = True
        write_json(self.output / 'perf-control.json', self.controls)
        if self.process.returncode not in ((0, 130, -signal.SIGINT) if interrupted else (0,)):
            raise RuntimeError(f'perf exited {self.process.returncode}')


def parse_perf(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(';')
        if len(fields) < 5 or fields[2] not in EVENTS.split(','):
            continue
        if fields[0].startswith('<'):
            raise RuntimeError('missing perf counter: ' + line)
        result[fields[2]] = {'value': float(fields[0]), 'unit': fields[1],
                             'event_runtime_ns': int(fields[3]), 'running_percent': float(fields[4])}
    if set(result) != set(EVENTS.split(',')):
        raise RuntimeError('incomplete perf counters')
    if any(event['running_percent'] < 99 for event in result.values()):
        raise RuntimeError('multiplexed/incomplete counter window')
    return result


def task_ns(counter):
    if counter['unit'] in ['msec', 'ms']:
        return counter['value'] * 1_000_000
    if counter['unit'] in ['', 'ns']:
        return counter['value']
    raise ValueError('unrecognized task-clock unit')


def cpu_ticks(process):
    return sum(process[key] for key in ['user_ticks', 'system_ticks', 'child_user_ticks', 'child_system_ticks'])


def wait_children(process):
    until = time.monotonic() + 5
    while time.monotonic() < until:
        assert process.poll() is None, 'C daemon exited'
        if len(group_members(process.pid)) == 1:
            time.sleep(.1)  # bounded parent cache-IPC drain, verified by final metrics
            return
        time.sleep(.01)
    raise RuntimeError('C children did not drain')


def cache_metrics(process, log):
    previous = len(log.read_text()) if log.exists() else 0
    process.send_signal(signal.SIGUSR1)
    until = time.monotonic() + 5
    while time.monotonic() < until:
        text = log.read_text()[previous:] if log.exists() else ''
        cache = re.search(r'cache size (\d+), (\d+)/(\d+) cache insertions', text)
        queries = re.search(r'queries forwarded (\d+), queries answered locally (\d+)', text)
        children = re.search(r'child processes for TCP requests: in use (\d+), highest since last SIGUSR1 (\d+), max allowed (\d+)', text)
        if cache and queries and children:
            return {'cache_size': int(cache[1]), 'live_freed': int(cache[2]), 'inserted': int(cache[3]),
                    'forwarded_parent': int(queries[1]), 'local_parent': int(queries[2]),
                    'tcp_active': int(children[1]), 'tcp_high_water_since_dump': int(children[2]), 'tcp_max': int(children[3])}
        if process.poll() is not None:
            raise RuntimeError('C exited before metrics')
        time.sleep(.01)
    raise RuntimeError('C metrics dump timed out')


def prepare_client(client, scenario, phase, count, rate, port, daemon_start, output=None):
    return client.call({'op': 'prepare', 'scenario': scenario, 'phase': phase, 'count': count, 'rate': rate,
                        'workers': 8 if scenario == 'tcp' and phase != 'prefill' else 32,
                        'port': port, 'daemon_start_ns': daemon_start, 'output': str(output) if output else None})


def run_client(client, output=None):
    return client.call({'op': 'run', 'start_ns': now() + 200_000_000,
                        'require_success': True, 'output': str(output) if output else None})


def all_success(result):
    return result['planned'] == result['sent'] == result['success'] and not (result['errors'] or result['timeouts'] or result['not_sent'])


def stop_group(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(5)
            raise RuntimeError('C shutdown exceeded 5 seconds')
    if group_members(process.pid):
        raise RuntimeError('C process group survived shutdown')
    assert process.returncode == 0, 'C exit was not successful'


def run_round(reference, directory, runtime_directory, scenario, cpus, profile=False, calibration=False):
    directory.mkdir()
    relative = directory.relative_to(runtime_directory[0])
    fixture_directory = runtime_directory[1] / relative
    upstream = client = daemon = perf = sampler = None
    result = {'status': 'failed', 'scenario': scenario, 'profile_only': profile}
    try:
        upstream = Rpc('upstream', cpus[1], directory / 'upstream.stderr')
        client = Rpc('client', cpus[2], directory / 'client.stderr')
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config_path = directory / 'dnsmasq.conf'
        config_path.write_text(f'''no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport={port}\ncache-size=1000\nedns-packet-max=1232\ndns-forward-max=150\nneg-ttl=30\nmax-tcp-connections=20\nstop-dns-rebind\nlog-facility={fixture_directory}/dnsmasq.log\nserver=127.0.0.1#{upstream.ready['port']}\n''')
        daemon_log = (directory / 'daemon.stderr').open('w')
        started = now()
        daemon = subprocess.Popen(['taskset', '-c', str(cpus[0]), 'prlimit', '--nofile=1024:1024', '--',
                                   str(reference), '-k', '-C', str(fixture_directory / 'dnsmasq.conf')],
                                  stdout=daemon_log, stderr=daemon_log, start_new_session=True)
        time.sleep(.15)
        assert daemon.poll() is None, 'C failed to start'
        result['config_sha256'] = digest(config_path)
        result['daemon_pid'] = daemon.pid
        result['dependency_pids'] = {'upstream': upstream.process.pid, 'client': client.process.pid, 'observer': os.getpid()}
        if calibration:
            result['corpus'] = prepare_client(client, 'hot', 'calibration', 5, 10, port, started, directory)
            result['client'] = run_client(client, directory)
            expected = result['client']
            assert (expected['planned'], expected['sent'], expected['success'], expected['errors'], expected['timeouts']) == (5, 5, 3, 1, 1), 'success/error/timeout calibration'
            result['deliberate_failure_exit_status'] = client.process.wait(5)
            assert result['deliberate_failure_exit_status'] == 1, 'failed load must exit nonzero'
            result['status'] = 'calibrated'
            return result
        if scenario != 'tcp':
            prepare_client(client, scenario, 'prefill', 0, 10000, port, started)
            assert all_success(run_client(client)), 'prefill failed'
        rate, count = (2000, 20000) if scenario == 'tcp' else (10000, 100000)
        prepare_client(client, scenario, 'warm', rate * 5, rate, port, started)
        result['warmup'] = run_client(client)
        assert all_success(result['warmup']), 'warmup failed'
        wait_children(daemon)
        metrics_before = cache_metrics(daemon, directory / 'dnsmasq.log')
        result['corpus'] = prepare_client(client, scenario, 'measure', count, rate, port, started, directory)
        upstream_before = upstream.call({'op': 'snapshot'})
        proc_before = read_proc(daemon.pid)
        observer_before = time.process_time_ns()
        perf = Perf(daemon.pid, directory, profile)
        sampler = Sampler(daemon.pid)
        sampler.start()
        enabled = perf.command('enable')
        result['client'] = run_client(client, directory)
        received_done = now()
        wait_children(daemon)
        drained = now()
        disabled = perf.command('disable')
        proc_after = read_proc(daemon.pid)
        result['sampled_peaks'] = sampler.finish(directory / 'resources.json')
        sampler = None
        perf.close()
        perf = None
        observer_after = time.process_time_ns()
        metrics_after = cache_metrics(daemon, directory / 'dnsmasq.log')
        upstream_after = upstream.call({'op': 'snapshot'})
        result.update(perf_enabled_ns=enabled, perf_disabled_ns=disabled,
                      drain_ns=drained - received_done, proc_before=proc_before, proc_after=proc_after,
                      metrics_before=metrics_before, metrics_after=metrics_after,
                      upstream_before=upstream_before, upstream_after=upstream_after,
                      observer_cpu_ns=observer_after-observer_before,
                      upstream_cpu_ns=upstream_after['cpu_ns']-upstream_before['cpu_ns'])
        result['upstream_queries'] = upstream_after['received'] - upstream_before['received']
        expected_upstream = 0 if scenario == 'hot' else 20000
        assert all_success(result['client']), 'formal success count failed'
        assert result['client']['send_lateness_ns']['p95'] < 5_000_000, 'generator schedule-lateness gate'
        assert result['upstream_queries'] == expected_upstream, 'upstream count differs from frozen cache/miss classes'
        if scenario == 'tcp':
            assert result['client']['connect_count'] == result['client']['close_count'] == 200, 'TCP connection count differs'
            assert upstream_after['connections'] - upstream_before['connections'] == 200, 'upstream TCP connection reuse differs'
        assert metrics_after['inserted'] - metrics_before['inserted'] == expected_upstream, 'cache IPC/insertion drain incomplete'
        assert upstream_after['failures'] == [], 'upstream fixture error'
        elapsed = max(10_000_000_000, result['client']['end_ns'] - result['client']['start_ns'])
        result['throughput_completed_per_second'] = result['client']['success'] * 1e9 / elapsed
        result['proc_cpu_ns'] = (cpu_ticks(proc_after) - cpu_ticks(proc_before)) * 1e9 / os.sysconf('SC_CLK_TCK')
        if not profile:
            result['perf'] = parse_perf(directory / 'perf-stat.txt')
            result['c_cpu_ns'] = task_ns(result['perf']['task-clock'])
            result['c_cpu_ns_per_completed'] = result['c_cpu_ns'] / result['client']['success']
            assert abs(result['c_cpu_ns'] - result['proc_cpu_ns']) <= max(50_000_000, .1 * result['c_cpu_ns']), 'perf/proc process-tree scope disagreement'
        else:
            with (directory / 'profile-self.txt').open('w') as report:
                subprocess.run(['perf', 'report', '-i', str(directory / 'perf.data'), '--stdio', '--no-children', '--sort', 'dso,symbol', '--percent-limit', '0.5'], stdout=report, stderr=subprocess.STDOUT, check=True)
        result['status'] = 'passed'
        return result
    except Exception as error:
        result['error'] = repr(error)
        return result
    finally:
        if sampler is not None:
            try:
                sampler.finish(directory / 'resources.json')
            except Exception as error:
                result['sampler_cleanup_error'] = repr(error)
        if perf is not None:
            try:
                perf.close()
            except Exception as error:
                result['perf_cleanup_error'] = repr(error)
        if daemon is not None:
            try:
                stop_group(daemon)
                daemon_log.close()
                result['daemon_shutdown'] = 'exited 0; process group empty'
            except Exception as error:
                result['status'] = 'failed'
                result['shutdown_error'] = repr(error)
        if client is not None:
            client.close()
        if upstream is not None:
            try:
                final = upstream.call({'op': 'stop'})
                write_json(directory / 'upstream-final.json', final)
            except Exception as error:
                result['status'] = 'failed'
                result['upstream_cleanup_error'] = repr(error)
            upstream.close()
        write_json(directory / 'result.json', result)


def cpu_calibration_role():
    print(json.dumps({'ready': True, 'pid': os.getpid()}), flush=True)
    for line in sys.stdin:
        command = json.loads(line)
        if command['op'] == 'stop':
            break
        before = time.process_time_ns()
        children = []
        for _ in range(2):
            child = os.fork()
            if child == 0:
                start = time.process_time_ns()
                value = 1
                while time.process_time_ns() - start < 100_000_000:
                    value = (value * 17 + 3) & 0xffffffff
                os._exit(0)
            pid, status, usage = os.wait4(child, 0)
            assert pid == child and status == 0
            children.append(round((usage.ru_utime + usage.ru_stime) * 1e9))
            time.sleep(.025)
        print(json.dumps({'child_cpu_ns': children, 'parent_cpu_ns': time.process_time_ns() - before}), flush=True)


def perf_calibration(out, cpu):
    out.mkdir()
    worker = Rpc('cpu-calibration', cpu, out / 'worker.stderr')
    perf = Perf(worker.process.pid, out)
    try:
        perf.command('enable')
        expected = worker.call({'op': 'run'})
        write_json(out / 'known-cpu.json', expected)
        perf.command('disable')
        perf.close()
        perf = None
        values = parse_perf(out / 'perf-stat.txt')
        measured = task_ns(values['task-clock'])
        known = sum(expected['child_cpu_ns']) + expected['parent_cpu_ns']
        assert len(expected['child_cpu_ns']) == 2 and all(value >= 100_000_000 for value in expected['child_cpu_ns'])
        assert .85 * known <= measured <= 1.25 * known, 'perf units/inheritance/window calibration failed'
        result = {'status': 'passed', 'known': expected, 'perf': values, 'known_total_ns': known,
                  'measured_ns': measured, 'scope': 'two children born after enable, including a later child, both exited before disable; parent startup excluded'}
        write_json(out / 'result.json', result)
        return result
    finally:
        if perf is not None:
            perf.close()
        worker.close()


def setup_namespace(out):
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or sorted(name for _, name in socket.if_nameindex()) != ['lo']:
        raise RuntimeError('run through the dedicated network/mount/PID namespace wrapper')
    if os.geteuid() != 0:
        raise RuntimeError('private namespace/perf owner must be root; do not change host perf policy')
    if out.exists() or not out.is_relative_to((ROOT / 'private').resolve()):
        raise RuntimeError('choose a new ignored private output directory')
    out.mkdir(parents=True)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'nosuid,nodev,noexec,mode=0755', 'tmpfs', '/run'], check=True)
    if Path('/var/run').resolve() != Path('/run'):
        raise RuntimeError('fixture requires /var/run to resolve to the private /run')
    fixture = Path('/run/private')
    fixture.mkdir()
    subprocess.run(['mount', '--bind', str(out), str(fixture)], check=True)
    return fixture


def reference_identity(reference, out):
    linked = subprocess.check_output(['ldd', str(reference)], text=True)
    (out / 'reference-ldd.txt').write_text(linked)
    dependencies = {}
    for line in linked.splitlines():
        fields = line.split()
        candidate = fields[2] if len(fields) >= 3 and fields[1] == '=>' else fields[0] if fields else ''
        if candidate.startswith('/') and Path(candidate).is_file():
            dependencies[candidate] = {'sha256': digest(candidate), 'bytes': Path(candidate).stat().st_size}
    base = reference.parent.parent
    for filename in ['compiler.txt', 'version.txt']:
        if (base / filename).exists():
            (out / ('reference-' + filename)).write_bytes((base / filename).read_bytes())
    return {'binary_sha256': digest(reference), 'binary_bytes': reference.stat().st_size,
            'dependencies': dependencies, 'copts': ['HAVE_UBUS', 'HAVE_POLL_H', 'NO_DHCP6', 'NO_AUTH', 'NO_IPSET', 'NO_ID'],
            'build_flags': '-O2 -g -Wall -W; existing native reference build, not target image ELF'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', choices=['upstream', 'client', 'cpu-calibration'])
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--calibration', type=Path, help='passed same-tool/same-plan calibration summary required before formal work')
    parser.add_argument('--mode', choices=['calibrate', 'measure', 'profile'], default='calibrate')
    parser.add_argument('--quiet-confirmed', action='store_true', help='operator has coordinated no build/test/agent load on the host')
    args = parser.parse_args()
    if args.role == 'upstream':
        asyncio.run(upstream_role())
        return 0
    if args.role == 'client':
        asyncio.run(client_role())
        return 0
    if args.role == 'cpu-calibration':
        cpu_calibration_role()
        return 0
    if not args.reference or not args.output:
        parser.error('--reference and --output are required')
    reference = args.reference.resolve()
    if digest(reference) != REFERENCE_SHA256:
        parser.error('exact native C reference binary identity differs')
    if args.mode != 'calibrate' and not args.quiet_confirmed:
        parser.error('coordinate a quiet host window before measuring')
    calibration = None
    if args.mode != 'calibrate':
        if not args.calibration:
            parser.error('--calibration is required before formal work')
        calibration = json.loads(args.calibration.read_text())
        if (calibration['status'] != 'passed'
                or calibration['tool_sha256'] != digest(Path(__file__))
                or calibration['plan_sha256'] != digest(ROOT / 'docs/dnsmasq/C_COST_DIAGNOSTIC_V2.md')
                or calibration['reference_sha256'] != REFERENCE_SHA256):
            parser.error('calibration is failed or belongs to a different tool/plan/reference')
    out = args.output.resolve()
    fixture = setup_namespace(out)
    cpus = sorted(os.sched_getaffinity(0))
    if len(cpus) < 4:
        raise RuntimeError('frozen diagnostic requires four available CPUs')
    cpus = cpus[:4]
    os.sched_setaffinity(0, {cpus[3]})
    summary = {'mode': args.mode, 'status': 'failed', 'rounds': [], 'scope': 'C-only diagnostic; not paired acceptance, a capacity ceiling or router performance',
               'reference_sha256': digest(reference), 'tool_sha256': digest(Path(__file__)),
               'plan_sha256': digest(ROOT / 'docs/dnsmasq/C_COST_DIAGNOSTIC_V2.md'),
               'affinity': {'c': cpus[0], 'upstream': cpus[1], 'client': cpus[2], 'observer': cpus[3]},
               'kernel': os.uname().release, 'architecture': os.uname().machine,
               'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
               'perf_version': subprocess.check_output(['perf', 'version'], text=True).strip(),
               'load_before': Path('/proc/loadavg').read_text().strip()}
    summary['reference_identity'] = reference_identity(reference, out)
    if calibration is not None:
        summary['calibration_sha256'] = digest(args.calibration)
    try:
        if args.mode == 'calibrate':
            summary['perf_calibration'] = perf_calibration(out / 'perf-calibration', cpus[0])
            result = run_round(reference, out / 'response-calibration', (out, fixture), 'hot', cpus, calibration=True)
            summary['rounds'].append(result)
            assert result['status'] == 'calibrated', 'response-counter calibration failed'
        else:
            # Fixed rotation; no window is selected after seeing measurements.
            order = [('hot', 'mixed', 'tcp'), ('mixed', 'tcp', 'hot'), ('tcp', 'hot', 'mixed')]
            if args.mode == 'profile':
                order = [order[0]]
            for round_number, scenarios in enumerate(order, 1):
                for scenario in scenarios:
                    result = run_round(reference, out / f'round-{round_number}-{scenario}',
                                       (out, fixture), scenario, cpus, args.mode == 'profile')
                    summary['rounds'].append(result)
                    # Keep failed windows and stop: do not substitute a faster
                    # or luckier window for a frozen measurement.
                    if result['status'] != 'passed':
                        raise RuntimeError(f'failed diagnostic window: {round_number}/{scenario}')
        summary['status'] = 'passed'
    except Exception as error:
        summary['error'] = repr(error)
    finally:
        summary['load_after'] = Path('/proc/loadavg').read_text().strip()
        write_json(out / 'summary.json', summary)
        subprocess.run(['umount', str(fixture)], check=True)
        subprocess.run(['umount', '/run'], check=True)
    print(json.dumps({key: value for key, value in summary.items() if key not in ['rounds', 'perf_calibration']}, indent=2))
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
