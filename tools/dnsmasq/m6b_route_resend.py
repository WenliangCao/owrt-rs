#!/usr/bin/env python3
"""Exact-image EVENT_NEWROUTE caller supplement, never a performance window.

Freeze before execution: one held UDP query, one kernel-created connected
route, exactly one identical resend, original source port, one client answer,
one forward action and stable idle FD restoration; repeat with no-poll.
Absence of a resend is recorded, then the original held packet is answered
to permit clean drain. That cleanup answer cannot satisfy the resend gate.
"""
import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import signal
import struct
import subprocess
import time

import m5_dns_cache as driver


CASES = [
    {'case': 'm6b-route-resend-poll', 'capacity': 0, 'metrics': True, 'config': ''},
    {'case': 'm6b-route-resend-no-poll', 'capacity': 0, 'metrics': True, 'config': 'no-poll'},
]
PLAN = {'profiles': CASES, 'scope': __doc__, 'kernel_route': '198.18.252.1/24 on private dummy m6broute',
        'upstream_hold_seconds': 0.2, 'resend_wait_seconds': 2, 'extra_reply_wait_seconds': 0.2,
        'idle_stable_observations': 3, 'idle_interval_seconds': 0.02, 'idle_deadline_seconds': 2,
        'dns_clients': 1, 'client_retries': 0, 'expected_upstream_packets': 2,
        'expected_forward_actions': 1, 'performance_qualification': False}
TOOLS = ['m6b_route_resend.py', 'm5_dns_cache.py', 'm5_dns_cache.json',
         'm2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh']

# The original two basic callers/PLAN remain strict and separately selectable.
# This independent batch witnesses each intervening consumer without a later
# UDP health request that could itself erase C's shared saved packet.
CLEAR_CASES = [
    {'case': 'm6b-route-clear-local-udp', 'action': 'local-udp', 'expected_upstream_packets': 1},
    {'case': 'm6b-route-clear-invalid-udp', 'action': 'invalid-udp', 'expected_upstream_packets': 1},
    {'case': 'm6b-route-clear-unmatched-upstream', 'action': 'unmatched-upstream', 'expected_upstream_packets': 1},
    {'case': 'm6b-route-clear-hup', 'action': 'hup', 'expected_upstream_packets': 1,
     'config': 'addn-hosts=/m2/caller.hosts', 'initial_hosts': '198.51.100.41 hup-one.route.test\n'},
    {'case': 'm6b-route-keep-bound-tcp-private', 'action': 'bound-tcp', 'expected_upstream_packets': 2},
    {'case': 'm6b-route-clear-debug-tcp-query', 'action': 'debug-tcp', 'expected_upstream_packets': 1,
     'debug': True, 'metrics': False, 'config': 'log-queries'},
]
for _case in CLEAR_CASES:
    _case.update(capacity=0)
    _case.setdefault('metrics', True)
    _case.setdefault('config', '')
CLEAR_PLAN = {
    'profiles': CLEAR_CASES, 'scope': 'ordinary shared-packet clear/private TCP retention callers',
    'kernel_route': PLAN['kernel_route'], 'upstream_hold_seconds': .2,
    'resend_wait_seconds': 2, 'extra_reply_wait_seconds': .2,
    'idle_stable_observations': 3, 'idle_interval_seconds': .02, 'idle_deadline_seconds': 2,
    'action_deadline_seconds': 2, 'consumer_stable_observations': 3, 'consumer_interval_seconds': .02,
    'consumer_counter': 'isolated /proc/net/snmp Udp InDatagrams',
    'hup_log_marker': 'read /m2/caller.hosts - 2 names',
    'dns_clients': 1, 'client_retries': 0, 'expected_forward_actions': 1,
    'source_contract': {'local-udp': 'forward.c:1628', 'invalid-udp': 'forward.c:1628',
                        'unmatched-upstream': 'forward.c:1169', 'hup': 'cache.c:1644',
                        'bound-tcp': 'dnsmasq.c:2065/2102-2197; child forward.c:2465',
                        'debug-tcp': 'forward.c:2465'},
    'debug_tcp_observation': {'ubus': 'disabled on both sides; C debug drops parent UBus',
        'forward_counter': 'log-queries exact forwarded route.resend.test to configured upstream',
        'source': 'dnsmasq.c:2187 drop_ubus_listeners; ubus.c:199-208; UBUs reference debug defect',
        'expected_forward_actions': 1, 'tcp_guard': 'live owned socket, client SHUT_WR/server EOF, exact held/idle FD restoration'},
    'performance_qualification': False,
    'open': ['server-record deletion; distinguish no-poll resolv from servers-file HUP',
             'wildcard accept pktinfo clear', 'two pending only last', 'all-servers last target',
             'repeated qualifying routes', 'fast-retry clear/re-save', 'loop probe clear'],
    'source_only': ['TFTP shared void* srv_save non-DNS alias; no unsafe pointer expectations'],
}
BATCHES = {'basic': (CASES, PLAN), 'clears': (CLEAR_CASES, CLEAR_PLAN)}


def profile_plan(spec):
    return CLEAR_PLAN if spec in CLEAR_CASES else PLAN


def udp_stats():
    lines = Path('/proc/net/snmp').read_text().splitlines()
    for index, line in enumerate(lines[:-1]):
        if line.startswith('Udp:') and lines[index + 1].startswith('Udp:'):
            names, values = line.split()[1:], lines[index + 1].split()[1:]
            return {name: int(value) for name, value in zip(names, values)}
    raise AssertionError('namespace UDP counters unavailable')


def consumer_barrier(folder, before, delta):
    samples, deadline = [], time.monotonic() + 2
    while True:
        now = udp_stats()
        samples.append({'monotonic_ns': time.monotonic_ns(), 'stats': now})
        save_json(folder / 'action-udp-samples.json', samples)
        if (now['InDatagrams'] > before['InDatagrams'] + delta
                or any(now[key] != before[key] for key in ['InErrors', 'RcvbufErrors'])):
            raise AssertionError('uncontrolled UDP consumption/error in action window')
        tail = samples[-3:]
        if len(tail) == 3 and all(row['stats']['InDatagrams'] == before['InDatagrams'] + delta for row in tail):
            return samples
        if time.monotonic() >= deadline:
            raise AssertionError('intervening UDP consumer was not witnessed')
        time.sleep(.02)


def health_correct(query, reply):
    value = driver.normalized(reply)
    return (reply[:2] == query[:2] and value['flags'] == 0x8580
            and value['questions'] == driver.normalized(query)['questions']
            and value['records'] == [
                {'section': 'answer', 'name': 'health.cache.test', 'type': 1, 'class': 1,
                 'ttl': 600, 'data': '198.51.100.99'},
                {'section': 'additional', 'name': '', 'type': 41, 'class': 1232, 'ttl': 0, 'data': ''}])


def forwarded_messages(raw):
    messages = []
    for line in raw.splitlines():
        match = re.search(rb'\bforwarded (\S+) to (\S+)\s*$', line)
        if match:
            messages.append({'host': match[1].decode('ascii'), 'upstream': match[2].decode('ascii')})
    return messages


def forward_log(root, folder, label):
    raw = (root / 'm2/cache.log').read_bytes()
    (folder / (label + '.forward.log')).write_bytes(raw)
    value = {'forward_actions': len(forwarded_messages(raw)), 'messages': forwarded_messages(raw)}
    save_json(folder / (label + '.forward.json'), value)
    return value


def tcp_rows(raw, fds, source, destination):
    owned = {target[8:-1]: number for number, target in fds.items() if target.startswith('socket:[')}
    def endpoint(value):
        address, port = value.split(':')
        return [socket.inet_ntoa(bytes.fromhex(address)[::-1]), int(port, 16)]
    rows = []
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10: raise ValueError('short TCP inventory row')
        local, peer, inode = endpoint(parts[1]), endpoint(parts[2]), parts[9]
        if inode in owned and local == destination and peer == source:
            rows.append({'fd': owned[inode], 'inode': inode, 'local': local, 'peer': peer,
                         'state': int(parts[3], 16)})
    return rows


def tcp_snapshot(pid, source, destination):
    fds = fd_set(pid)
    raw = (Path('/proc') / str(pid) / 'net/tcp').read_text()
    return {'monotonic_ns': time.monotonic_ns(), 'fds': fds, 'raw_tcp': raw,
            'rows': tcp_rows(raw, fds, source, destination)}


def stable_debug_tcp_live(pid, source, destination, folder, held):
    samples, deadline = [], time.monotonic() + 2
    while True:
        try:
            snapshot = tcp_snapshot(pid, source, destination)
        except FileNotFoundError:
            snapshot = {'monotonic_ns': time.monotonic_ns(), 'fds': None, 'rows': None, 'raw_tcp': ''}
        samples.append(snapshot); save_json(folder / 'action-debug-tcp-live-samples.json', samples)
        tail = samples[-3:]
        if len(tail) == 3 and all(item['fds'] == tail[0]['fds'] and item['rows'] == tail[0]['rows'] for item in tail):
            rows = snapshot['rows']
            if rows and len(rows) == 1 and rows[0]['state'] == 1:
                expected = {**held, rows[0]['fd']: 'socket:[' + rows[0]['inode'] + ']'}
                if snapshot['fds'] == expected:
                    save_json(folder / 'action-debug-tcp-live.json', snapshot)
                    return snapshot
        if time.monotonic() >= deadline: raise AssertionError('debug TCP established owned FD did not stabilize')
        time.sleep(.02)


def stable_debug_tcp_closed(pid, source, destination, folder, expected):
    samples, deadline = [], time.monotonic() + 2
    while True:
        try:
            snapshot = tcp_snapshot(pid, source, destination)
        except FileNotFoundError:
            snapshot = {'monotonic_ns': time.monotonic_ns(), 'fds': None, 'rows': None, 'raw_tcp': ''}
        samples.append(snapshot); save_json(folder / 'action-debug-tcp-samples.json', samples)
        tail = samples[-3:]
        if len(tail) == 3 and all(item['fds'] == expected and item['rows'] == [] for item in tail):
            return samples
        if time.monotonic() >= deadline: raise AssertionError('debug TCP owned socket/FD identities did not drain')
        time.sleep(.02)


def intervene(spec, port, upstream, folder, root, pid, held_client):
    action = spec['action']
    value = {'action': action, 'started_monotonic_ns': time.monotonic_ns()}
    before = udp_stats(); save_json(folder / 'action-udp-before.json', before)
    value['udp_before'] = before
    if action in ['local-udp', 'invalid-udp']:
        packet = driver.query('health.cache.test', 0x6e02) if action == 'local-udp' else b'\x00'
        (folder / 'action.query').write_bytes(packet)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.bind((driver.CLIENT, 0)); endpoint.connect((driver.LISTEN, port)); endpoint.settimeout(.2)
            value['client_source'] = list(endpoint.getsockname()); value['destination'] = list(endpoint.getpeername())
            endpoint.send(packet)
            try:
                reply = endpoint.recv(65535); (folder / 'action.reply').write_bytes(reply)
                if action != 'local-udp' or not health_correct(packet, reply):
                    raise AssertionError('intervening local/invalid UDP response differs')
            except socket.timeout:
                if action != 'invalid-udp':
                    raise AssertionError('intervening local UDP did not answer')
        value['udp_delta'] = 2 if action == 'local-udp' else 1
        consumer_barrier(folder, before, value['udp_delta'])
    elif action == 'unmatched-upstream':
        transport, endpoint, peer, packet = upstream.held[0]
        if transport != 'udp':
            raise AssertionError('unmatched reply requires original UDP endpoint')
        reply = upstream.answer(packet, transport, force=True)
        reply = (int.from_bytes(reply[:2], 'big') ^ 0x8000).to_bytes(2, 'big') + reply[2:]
        (folder / 'action.query').write_bytes(packet); (folder / 'action.upstream-packet').write_bytes(reply)
        value['upstream_source'] = list(endpoint.getsockname()); value['destination'] = list(peer)
        endpoint.sendto(reply, peer)
        value['udp_delta'] = 1
        consumer_barrier(folder, before, 1)
        held_client.settimeout(.2)
        try:
            wrong = held_client.recv(65535); (folder / 'action.unexpected-client-reply').write_bytes(wrong)
            raise AssertionError('unmatched upstream packet satisfied pending client')
        except socket.timeout:
            pass
        held_client.settimeout(2)
    elif action == 'hup':
        hosts = root / 'm2/caller.hosts'
        value['hosts_before'] = hosts.read_text()
        value['hosts_after'] = '198.51.100.41 hup-one.route.test\n198.51.100.42 hup-two.route.test\n'
        log = root / 'm2/cache.log'
        initial_log = log.read_bytes(); (folder / 'action-before.daemon.log').write_bytes(initial_log)
        marker = CLEAR_PLAN['hup_log_marker'].encode()
        if marker in initial_log:
            raise AssertionError('HUP witness marker already existed')
        hosts.write_text(value['hosts_after']); (folder / 'action-hosts').write_bytes(hosts.read_bytes())
        os.kill(pid, signal.SIGHUP)
        deadline = time.monotonic() + 2
        while True:
            output = log.read_bytes(); (folder / 'action-after.daemon.log').write_bytes(output)
            if output.startswith(initial_log) and marker in output[len(initial_log):]:
                break
            if time.monotonic() >= deadline:
                raise AssertionError('HUP hosts/cache completion log absent')
            time.sleep(.02)
        value['udp_delta'] = 0
        consumer_barrier(folder, before, 0)
    elif action in ['bound-tcp', 'debug-tcp']:
        packet = driver.query('health.cache.test', 0x6e02); (folder / 'action.query').write_bytes(packet)
        if action == 'debug-tcp':
            value['held_fds'] = stable_fds(pid, folder, 'action-held-before')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.bind((driver.CLIENT, 0)); endpoint.settimeout(2); endpoint.connect((driver.LISTEN, port))
            value['client_source'] = list(endpoint.getsockname()); value['destination'] = list(endpoint.getpeername())
            endpoint.sendall(struct.pack('!H', len(packet)) + packet)
            def exact(size):
                result = b''
                while len(result) < size:
                    piece = endpoint.recv(size - len(result))
                    if not piece: raise AssertionError('short TCP action response')
                    result += piece
                return result
            reply = exact(struct.unpack('!H', exact(2))[0]); (folder / 'action.reply').write_bytes(reply)
            if not health_correct(packet, reply):
                raise AssertionError('intervening TCP local answer differs')
            if action == 'debug-tcp':
                stable_debug_tcp_live(pid, value['client_source'], value['destination'], folder, value['held_fds'])
                value['shutdown_write_monotonic_ns'] = time.monotonic_ns()
                endpoint.shutdown(socket.SHUT_WR)
                eof = endpoint.recv(1); (folder / 'action-tcp-eof').write_bytes(eof)
                if eof != b'': raise AssertionError('debug TCP did not return terminal EOF')
                value['eof_monotonic_ns'] = time.monotonic_ns(); value['server_eof'] = True
        if action == 'debug-tcp':
            stable_debug_tcp_closed(pid, value['client_source'], value['destination'], folder, value['held_fds'])
        else:
            samples, deadline = [], time.monotonic() + 2
            while True:
                snapshot = metric(root, folder, f'action-tcp-{len(samples):03}')
                samples.append({'monotonic_ns': time.monotonic_ns(), 'metrics': snapshot})
                save_json(folder / 'action-tcp-samples.json', samples)
                if len(samples) >= 3 and all(item['metrics']['tcp_connections'] == 0 for item in samples[-3:]):
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError('TCP action client slot did not drain')
                time.sleep(.02)
        value['udp_delta'] = 0
        consumer_barrier(folder, before, 0)
    else:
        raise AssertionError('unfrozen intervening action')
    value['completed_monotonic_ns'] = time.monotonic_ns()
    save_json(folder / 'action-witness.json', value)
    return value


class TrackedUpstream(driver.Upstream):
    def __init__(self):
        self.received = []
        super().__init__()

    def answer(self, packet, transport, force=False):
        if not force:
            # Called by the inherited selector immediately after the actual
            # recv. Forced cleanup reply construction is not a received query.
            self.received.append({'sequence': len(self.received), 'transport': transport,
                                  'received_monotonic_ns': time.monotonic_ns(), 'wire': packet.hex()})
        return super().answer(packet, transport, force)


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def route_records(wire, peer):
    records, offset = [], 0
    while offset + 16 <= len(wire):
        length, kind, flags, seq, pid = struct.unpack_from('=IHHII', wire, offset)
        if length < 16 or offset + length > len(wire):
            raise ValueError('clipped netlink record')
        message = wire[offset:offset + length]
        qualifies = (peer[0] == 0 and pid == 0 and kind == 24 and length >= 28
                     and message[23] == 1 and message[22] == 253 and message[20] in [254, 255])
        attributes, at = [], 28
        if kind in [24, 25] and length >= 28:
            while at + 4 <= length:
                size, attr = struct.unpack_from('=HH', message, at)
                if size < 4 or at + size > length:
                    raise ValueError('clipped route attribute')
                attributes.append({'kind': attr, 'data': message[at + 4:at + size].hex()})
                at += (size + 3) & ~3
            if at != length:
                raise ValueError('unparsed route attribute tail')
        records.append({'length': length, 'kind': kind, 'flags': flags, 'sequence': seq,
                        'pid': pid, 'route': list(message[16:28]) if length >= 28 else [],
                        'attributes': attributes, 'qualifies': qualifies})
        offset += (length + 3) & ~3
    if offset != len(wire):
        raise ValueError('unparsed netlink tail')
    return records


def controlled_route(record):
    return (record['qualifies'] and record['route'][:2] == [2, 24]
            and any(attr == {'kind': 1, 'data': 'c612fc00'} for attr in record['attributes']))


def netlink_drain(endpoint, folder, label):
    rows, deadline = [], time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            wire, peer = endpoint.recvfrom(65535)
        except socket.timeout:
            break
        filename = f'{label}-{len(rows):03}.netlink'
        (folder / filename).write_bytes(wire)
        rows.append({'file': filename, 'peer': list(peer), 'observed_monotonic_ns': time.monotonic_ns(),
                     'records': route_records(wire, peer)})
        save_json(folder / (label + '.netlink.json'), rows)
    save_json(folder / (label + '.netlink.json'), rows)
    return rows


def metric(root, folder, label):
    argv = driver.command(root, '/bin/ubus', 'call', 'cache-metrics', 'metrics', '{}')
    result = subprocess.run(argv, capture_output=True, timeout=2)
    (folder / (label + '.metrics.stdout')).write_bytes(result.stdout)
    (folder / (label + '.metrics.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise AssertionError('exact-image UBus metric call failed')
    value = json.loads(result.stdout)
    return {'dns_queries_forwarded': value['dns_queries_forwarded'], 'tcp_connections': value['tcp_connections']}


def fd_set(pid):
    return {p.name: os.readlink(p) for p in (Path('/proc') / str(pid) / 'fd').iterdir()}


def stable_fds(pid, folder, label, expected=None):
    observations, deadline, stable, previous = [], time.monotonic() + 2, 0, None
    while True:
        try:
            current = fd_set(pid)
        except FileNotFoundError:
            current = None  # A transient interface-file FD may disappear.
        observations.append({'monotonic_ns': time.monotonic_ns(), 'fds': current})
        save_json(folder / (label + '.fds.json'), observations)
        matched = current is not None and current == (previous if expected is None else expected)
        stable = stable + 1 if matched else 1 if current is not None and expected is None else 0
        if stable == 3:
            return current
        if time.monotonic() >= deadline:
            raise AssertionError('idle FD identities did not stabilize/return')
        previous = current
        time.sleep(.02)


def held_packets(upstream, folder):
    rows = []
    for index, (transport, _, peer, packet) in enumerate(list(upstream.held)):
        filename = f'upstream-{index:03}.query'
        (folder / filename).write_bytes(packet)
        received = upstream.received[index]
        if received['wire'] != packet.hex() or received['transport'] != transport:
            raise AssertionError('received query/held inventory differs')
        rows.append({'file': filename, 'transport': transport, 'source': list(peer),
                     'received_monotonic_ns': received['received_monotonic_ns'],
                     'query': driver.normalized(packet)})
    save_json(folder / 'held-upstream.json', rows)
    return rows


def correct_answer(query, reply):
    parsed = driver.normalized(reply)
    if reply[:2] != query[:2] or parsed.get('questions') != driver.normalized(query)['questions']:
        return False
    if parsed.get('flags') != 0x8180:
        return False
    records = parsed.get('records', [])
    return records == [
        {'section': 'answer', 'name': 'route.resend.test', 'type': 1, 'class': 1,
         'ttl': 600, 'data': '198.51.100.7'},
        {'section': 'additional', 'name': '', 'type': 41, 'class': 1232, 'ttl': 0, 'data': ''},
    ]


def schedule(spec, port, upstream, folder, root):
    pid = int((folder / 'pid').read_text())
    witness = {'case': spec['case'], 'plan': profile_plan(spec), 'resend_observed': False, 'cleanup_answer': False}
    link_created = False
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as route, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        route.bind((0, 0x40 | 0x400)); route.settimeout(.2)
        client.bind((driver.CLIENT, 0)); client.settimeout(2)
        client.connect((driver.LISTEN, port))
        witness['dns_destination'] = list(client.getpeername())
        try:
            subprocess.run(['ip', 'link', 'add', 'm6broute', 'type', 'dummy'], check=True)
            link_created = True
            ipv6 = Path('/proc/sys/net/ipv6/conf/m6broute/disable_ipv6')
            if ipv6.exists():
                ipv6.write_text('1\n')
                if ipv6.read_text().strip() != '1':
                    raise AssertionError('new dummy IPv6 could not be disabled')
                witness['dummy_ipv6'] = 'disabled'
            else:
                witness['dummy_ipv6'] = 'not-present'
            subprocess.run(['ip', 'link', 'set', 'm6broute', 'up'], check=True)
            witness['bootstrap_netlink'] = netlink_drain(route, folder, 'bootstrap')
            # A real health reply after link setup is a daemon turn barrier,
            # before saved UDP state exists. No health traffic follows hold.
            health = driver.query('health.cache.test', 0x6e00)
            reply = driver.exchange(port, health)
            if reply is None or driver.normalized(reply)['records'][0]['data'] != '198.51.100.99':
                raise AssertionError('daemon setup barrier failed')
            witness['idle_fds'] = stable_fds(pid, folder, 'before')
            if spec.get('metrics'):
                witness['before_metrics'] = metric(root, folder, 'before')
            else:
                witness['before_forward_log'] = forward_log(root, folder, 'before')
            host = 'route.resend.test'
            upstream.plan[host] = {'hold': True, 'ttl': 600, 'answers': [{'data': 'c6336407'}]}
            query = driver.query(host, 0x6e01)
            (folder / 'client.query').write_bytes(query)
            client.send(query)
            deadline = time.monotonic() + 2
            while not upstream.held:
                if time.monotonic() >= deadline:
                    raise AssertionError('first query did not reach controlled upstream')
                time.sleep(.005)
            time.sleep(.2)
            first = held_packets(upstream, folder)
            if len(first) != 1:
                raise AssertionError('query retried before route; invalid caller fixture')
            witness['before_trigger'] = first
            if spec in CLEAR_CASES:
                witness['action'] = intervene(spec, port, upstream, folder, root, pid, client)
            witness['trigger_monotonic_ns'] = time.monotonic_ns()
            save_json(folder / 'caller-witness.json', witness)
            subprocess.run(['ip', 'addr', 'add', '198.18.252.1/24', 'dev', 'm6broute'], check=True)
            witness['trigger_netlink'] = netlink_drain(route, folder, 'trigger')
            if not any(controlled_route(record) for row in witness['trigger_netlink'] for record in row['records']):
                raise AssertionError('no qualifying kernel connected-route witness')
            witness['resend_wait_started_monotonic_ns'] = time.monotonic_ns()
            deadline = time.monotonic() + 2
            while len(upstream.held) < 2 and time.monotonic() < deadline:
                time.sleep(.005)
            witness['resend_wait_finished_monotonic_ns'] = time.monotonic_ns()
            witness['held_packets'] = held_packets(upstream, folder)
            witness['resend_observed'] = len(witness['held_packets']) == 2
            save_json(folder / 'caller-witness.json', witness)
            if not upstream.held:
                raise AssertionError('controlled held query vanished')
            # Missing resend is a retained defect, not a method failure. Reply
            # to its original packet only to release the pending transaction.
            witness['cleanup_answer'] = not witness['resend_observed']
            transport, endpoint, peer, packet = upstream.held[-1]
            if transport != 'udp':
                raise AssertionError('unexpected non-UDP caller')
            answer = upstream.answer(packet, transport, force=True)
            (folder / 'upstream.reply').write_bytes(answer)
            endpoint.sendto(answer, peer)
            upstream.held.clear()
            reply, source = client.recvfrom(65535)
            (folder / 'client.reply').write_bytes(reply)
            witness['reply_monotonic_ns'] = time.monotonic_ns()
            witness['reply_source'] = list(source)
            witness['correct_answer'] = correct_answer(query, reply)
            if not witness['correct_answer']:
                raise AssertionError('client answer is incorrect')
            client.settimeout(.2)
            try:
                extra, _ = client.recvfrom(65535)
                (folder / 'client.extra-reply').write_bytes(extra)
                raise AssertionError('more than one client reply')
            except socket.timeout:
                witness['one_client_reply'] = True
            if spec.get('metrics'):
                witness['after_metrics'] = metric(root, folder, 'after')
            else:
                witness['after_forward_log'] = forward_log(root, folder, 'after')
            witness['final_fds'] = stable_fds(pid, folder, 'after', witness['idle_fds'])
            witness['completed'] = True
            save_json(folder / 'caller-witness.json', witness)
            return [{'label': 'caller', 'query': driver.normalized(query), 'reply': driver.normalized(reply),
                     'resend_observed': witness['resend_observed'], 'cleanup_answer': witness['cleanup_answer']}]
        finally:
            save_json(folder / 'upstream-receipts.json', upstream.received)
            save_json(folder / 'caller-witness.json', witness)
            if link_created:
                subprocess.run(['ip', 'link', 'del', 'm6broute'], check=True)


def check_debug_forward_logs(folder, witness):
    config = (folder / 'config').read_text()
    server = [line for line in config.splitlines() if line.startswith('server=127.0.0.2#')]
    if len(server) != 1 or not server[0].split('#')[-1].isdigit():
        raise ValueError('debug forward-log unique upstream absent')
    target = '127.0.0.2#' + server[0].split('#')[-1]
    raw = [(folder / (label + '.forward.log')).read_bytes() for label in ['before', 'after']]
    if not raw[1].startswith(raw[0]): raise ValueError('debug forward log is not the same append-only file')
    for label, data, count in zip(['before', 'after'], raw, [0, 1]):
        messages = forwarded_messages(data)
        value = {'forward_actions': len(messages), 'messages': messages}
        if (witness.get(label + '_forward_log') != value
                or json.loads((folder / (label + '.forward.json')).read_text()) != value
                or len(messages) != count or any(message != {'host': 'route.resend.test', 'upstream': target} for message in messages)):
            raise ValueError('debug forwarded-log action counter differs from raw messages')
        if label + '_metrics' in witness or (folder / (label + '.metrics.stdout')).exists():
            raise ValueError('debug TCP fixture must not pretend released UBus is a counter')


def check_debug_tcp(folder, action):
    live = json.loads((folder / 'action-debug-tcp-live.json').read_text())
    source, destination, held = action['client_source'], action['destination'], action['held_fds']
    rows = tcp_rows(live['raw_tcp'], live['fds'], source, destination)
    if live['rows'] != rows or len(rows) != 1 or rows[0]['state'] != 1:
        raise ValueError('debug TCP live established owned socket absent')
    extra = {key: value for key, value in live['fds'].items() if key not in held}
    if (extra != {rows[0]['fd']: 'socket:[' + rows[0]['inode'] + ']'}
            or any(live['fds'].get(key) != value for key, value in held.items())):
        raise ValueError('debug TCP live FD identities differ from held transaction plus one client')
    if (action.get('server_eof') is not True or (folder / 'action-tcp-eof').read_bytes() != b''
            or not action['started_monotonic_ns'] <= live['monotonic_ns'] <= action['shutdown_write_monotonic_ns']
                <= action['eof_monotonic_ns'] <= action['completed_monotonic_ns']):
        raise ValueError('debug TCP half-close/terminal EOF/order witness absent')
    live_samples = json.loads((folder / 'action-debug-tcp-live-samples.json').read_text())
    tail = live_samples[-3:]
    if len(tail) != 3 or tail[-1] != live or any(item['fds'] != live['fds'] or item['rows'] != rows for item in tail):
        raise ValueError('debug TCP live socket/FD identities were not stable')
    for item in live_samples:
        if item['fds'] is not None and item['rows'] != tcp_rows(item['raw_tcp'], item['fds'], source, destination):
            raise ValueError('debug TCP live socket report/raw differs')
    if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
        raise ValueError('debug TCP live observations not separated')
    anchor = json.loads((folder / 'action-held-before.fds.json').read_text())
    samples = json.loads((folder / 'action-debug-tcp-samples.json').read_text())
    for label, observations in [('held-before', anchor), ('closed', samples)]:
        tail = observations[-3:]
        if len(tail) != 3 or any(item['fds'] != held for item in tail):
            raise ValueError('debug TCP exact held FD identities did not stabilize')
        if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
            raise ValueError('debug TCP stable observations not separated')
        if label == 'held-before' and any(not action['started_monotonic_ns'] <= item['monotonic_ns'] <= live['monotonic_ns'] for item in observations):
            raise ValueError('debug held anchor was not captured before the TCP action')
        if label == 'closed':
            if any(not action['eof_monotonic_ns'] <= item['monotonic_ns'] <= action['completed_monotonic_ns'] for item in observations):
                raise ValueError('debug TCP close samples outside actual EOF/action window')
            for item in observations:
                if item['fds'] is None: continue
                actual = tcp_rows(item['raw_tcp'], item['fds'], source, destination)
                if item['rows'] != actual: raise ValueError('debug TCP socket inventory/raw differs')
            if any(item['rows'] != [] for item in tail): raise ValueError('debug TCP owned socket did not close')
    if any(path.name.startswith('action-tcp-') and path.name.endswith('.metrics.stdout') for path in folder.iterdir()):
        raise ValueError('debug TCP must use actual socket/FD/EOF, not unavailable UBus')


def validate_case(folder, row, expected_sha, expected_plan=PLAN):
    """Recompute claims from raw wire/counters/fd identity, not report flags."""
    if row.get('failure') or row.get('exit') != 0 or row.get('upstream_errors'):
        raise ValueError('caller execution incomplete')
    if row.get('identity', {}).get('sha256') != expected_sha:
        raise ValueError('actual running ELF differs')
    witness = json.loads((folder / 'caller-witness.json').read_text())
    if witness.get('plan') != expected_plan or witness.get('case') != row['case'] or not witness.get('completed'):
        raise ValueError('unfrozen or incomplete caller')
    queries = witness['held_packets']
    if not queries or len(queries) > 2 or len(witness['before_trigger']) != 1:
        raise ValueError('invalid hold schedule')
    packets = [(folder / query['file']).read_bytes() for query in queries]
    if any(query['transport'] != 'udp' or driver.normalized(packet) != query['query']
           for query, packet in zip(queries, packets)):
        raise ValueError('saved upstream wire differs')
    events = row.get('upstream', [])
    if (len(events) != len(packets)
            or any(event.get('host') != 'route.resend.test' or event.get('transport') != 'udp'
                   or event.get('wire') != packet.hex() or event.get('query') != driver.normalized(packet)
                   for event, packet in zip(events, packets))):
        raise ValueError('complete actual upstream inventory differs')
    received = json.loads((folder / 'upstream-receipts.json').read_text())
    if (len(received) != len(packets)
            or any(item['sequence'] != index or item['transport'] != 'udp' or item['wire'] != packet.hex()
                   or item['received_monotonic_ns'] != queries[index]['received_monotonic_ns']
                   for index, (item, packet) in enumerate(zip(received, packets)))):
        raise ValueError('actual receive receipts differ')
    if witness['before_trigger'][0] != queries[0] or received[0]['received_monotonic_ns'] >= witness['trigger_monotonic_ns']:
        raise ValueError('first held packet did not precede route')
    if len(received) == 2 and received[1]['received_monotonic_ns'] < witness['trigger_monotonic_ns']:
        raise ValueError('second packet preceded route')
    if witness.get('dummy_ipv6') not in ['disabled', 'not-present']:
        raise ValueError('new dummy DAD contamination not excluded')
    raw_routes = []
    for record in witness['trigger_netlink']:
        parsed = route_records((folder / record['file']).read_bytes(), record['peer'])
        if parsed != record['records']:
            raise ValueError('netlink raw/report differs')
        raw_routes += parsed
    if not any(controlled_route(record) for record in raw_routes):
        raise ValueError('no actual qualifying kernel route')
    query, reply = (folder / 'client.query').read_bytes(), (folder / 'client.reply').read_bytes()
    if (driver.normalized(query)['questions'] != [['route.resend.test', 1, 1]]
            or any(driver.normalized(packet)['questions'] != driver.normalized(query)['questions'] for packet in packets)):
        raise ValueError('controlled held question differs')
    if not correct_answer(query, reply) or not witness.get('one_client_reply') or (folder / 'client.extra-reply').exists():
        raise ValueError('client completion differs')
    if witness.get('reply_source') != witness.get('dns_destination') or not witness.get('reply_source'):
        raise ValueError('client answer came from a different endpoint')
    if not witness['trigger_monotonic_ns'] <= witness['reply_monotonic_ns']:
        raise ValueError('response preceded route')
    debug_spec = next((spec for spec in CLEAR_CASES if spec['case'] == row['case'] and spec.get('debug')), None)
    if expected_plan == CLEAR_PLAN and debug_spec:
        check_debug_forward_logs(folder, witness)
    else:
        before, after = [json.loads((folder / f'{label}.metrics.stdout').read_bytes()) for label in ['before', 'after']]
        if any(value['tcp_connections'] != 0 for value in [before, after]):
            raise ValueError('unexpected TCP clients')
        if after['dns_queries_forwarded'] - before['dns_queries_forwarded'] != 1:
            raise ValueError('resend created an extra forward action')
    for label in ['before', 'after']:
        samples = json.loads((folder / (label + '.fds.json')).read_text())
        tail = samples[-3:]
        if len(tail) != 3 or any(item['fds'] != witness['idle_fds'] for item in tail):
            raise ValueError('stable original FD identities absent')
        if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
            raise ValueError('FD observations were not separated')
    observed = (len(packets) == 2 and packets[0] == packets[1]
                and queries[0]['source'] == queries[1]['source'])
    if witness['resend_observed'] != (len(packets) == 2) or witness['cleanup_answer'] != (len(packets) != 2):
        raise ValueError('cleanup masquerades as resend')
    return {'resend_contract_passed': observed, 'upstream_packets': len(packets),
            'same_wire': len(packets) == 2 and packets[0] == packets[1],
            'same_source_port': len(packets) == 2 and queries[0]['source'] == queries[1]['source'],
            'correct_client_answer': True, 'client_query': driver.normalized(query),
            'client_reply': driver.normalized(reply), 'forward_actions': 1, 'stable_idle_fds': True}


def validate_clear_case(folder, row, expected_sha):
    result = validate_case(folder, row, expected_sha, CLEAR_PLAN)
    spec = next((spec for spec in CLEAR_CASES if spec['case'] == row['case']), None)
    if spec is None:
        raise ValueError('unknown clear profile')
    witness = json.loads((folder / 'caller-witness.json').read_text())
    action = json.loads((folder / 'action-witness.json').read_text())
    if witness.get('action') != action or action.get('action') != spec['action']:
        raise ValueError('wrong intervening consumer')
    for label in ([] if spec.get('debug') else ['before', 'after']):
        raw = json.loads((folder / f'{label}.metrics.stdout').read_bytes())
        if witness.get(label + '_metrics') != {key: raw[key] for key in ['dns_queries_forwarded', 'tcp_connections']}:
            raise ValueError('action parent metrics claim differs from raw output')
    mode = '-d' if spec.get('debug') else '-k'
    argv = row['identity'].get('cmdline', '').split()
    if argv[-3:] != [mode, '-C', '/m2/cache.conf'] or ('-d' if mode == '-k' else '-k') in argv:
        raise ValueError('actual daemon private/debug mode differs')
    config = (folder / 'config').read_text()
    server_lines = [line for line in config.splitlines() if line.startswith('server=127.0.0.2#')]
    if len(server_lines) != 1 or not server_lines[0].split('#')[-1].isdigit():
        raise ValueError('unique frozen upstream absent')
    upstream_port = int(server_lines[0].split('#')[-1])
    if not 0 < upstream_port < 65536:
        raise ValueError('upstream port differs')
    port = witness['dns_destination'][1]
    expected_config = (f'port={port}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={driver.LISTEN}\n'
        f'server=127.0.0.2#{upstream_port}\ncache-size=0\nno-0x20-encode\n'
        'host-record=health.cache.test,198.51.100.99\nlocal-ttl=600\nuser=root\n'
        'pid-file=/m2/cache.pid\nlog-facility=/m2/cache.log\n' + spec['config'] + '\n'
        + ('enable-ubus=cache-metrics\n' if spec['metrics'] else ''))
    if config != expected_config:
        raise ValueError('actual private/bound/cache/TTL configuration differs')
    if spec['action'] in ['local-udp', 'invalid-udp', 'bound-tcp', 'debug-tcp']:
        if action.get('destination') != witness['dns_destination'] or action.get('client_source', [None])[0] != driver.CLIENT:
            raise ValueError('intervening client endpoint differs')
    if spec['action'] == 'unmatched-upstream' and action.get('upstream_source') != ['127.0.0.2', upstream_port]:
        raise ValueError('unmatched upstream sender differs from configured server')
    if not witness['held_packets'][0]['received_monotonic_ns'] < action['started_monotonic_ns'] <= action['completed_monotonic_ns'] < witness['trigger_monotonic_ns']:
        raise ValueError('action did not run strictly between hold and route')
    before = json.loads((folder / 'action-udp-before.json').read_text())
    samples = json.loads((folder / 'action-udp-samples.json').read_text())
    delta = {'local-udp': 2, 'invalid-udp': 1, 'unmatched-upstream': 1,
             'hup': 0, 'bound-tcp': 0, 'debug-tcp': 0}[spec['action']]
    if action.get('udp_before') != before or action.get('udp_delta') != delta:
        raise ValueError('action receive counter claim differs')
    if (len(samples) < 3 or any(not before['InDatagrams'] <= item['stats']['InDatagrams'] <= before['InDatagrams'] + delta
            or any(item['stats'][key] != before[key] for key in ['InErrors', 'RcvbufErrors']) for item in samples)):
        raise ValueError('uncontrolled or missing action receive samples')
    tail = samples[-3:]
    if any(item['stats']['InDatagrams'] != before['InDatagrams'] + delta for item in tail):
        raise ValueError('intervening datagram was not consumed')
    if any(b['monotonic_ns'] - a['monotonic_ns'] < 15_000_000 for a, b in zip(tail, tail[1:])):
        raise ValueError('consumer observations not separated')
    if any(not action['started_monotonic_ns'] <= item['monotonic_ns'] <= action['completed_monotonic_ns'] for item in samples):
        raise ValueError('consumer observations outside action window')
    if spec['action'] in ['local-udp', 'bound-tcp', 'debug-tcp']:
        query, reply = (folder / 'action.query').read_bytes(), (folder / 'action.reply').read_bytes()
        if driver.normalized(query)['questions'] != [['health.cache.test', 1, 1]] or not health_correct(query, reply):
            raise ValueError('local/TCP action answer differs')
    elif spec['action'] == 'invalid-udp':
        if (folder / 'action.query').read_bytes() != b'\x00' or (folder / 'action.reply').exists():
            raise ValueError('invalid action was not the frozen silently dropped datagram')
    elif spec['action'] == 'unmatched-upstream':
        packet = (folder / 'action.query').read_bytes()
        response = (folder / 'action.upstream-packet').read_bytes()
        if packet != (folder / witness['held_packets'][0]['file']).read_bytes() or not correct_answer(packet, packet[:2] + response[2:]):
            raise ValueError('unmatched packet was not derived from held query')
        if response[:2] != (int.from_bytes(packet[:2], 'big') ^ 0x8000).to_bytes(2, 'big'):
            raise ValueError('upstream packet ID matched or differed from frozen unmatched ID')
        if action.get('destination') != witness['held_packets'][0]['source'] or (folder / 'action.unexpected-client-reply').exists():
            raise ValueError('unmatched reply destination/client behavior differs')
    elif spec['action'] == 'hup':
        initial = (folder / 'action-before.daemon.log').read_bytes()
        final = (folder / 'action-after.daemon.log').read_bytes()
        marker = CLEAR_PLAN['hup_log_marker'].encode()
        if marker in initial or not final.startswith(initial) or marker not in final[len(initial):]:
            raise ValueError('HUP cache/hosts completion witness absent')
        if action.get('hosts_before') != spec['initial_hosts'] or (folder / 'action-hosts').read_text() != action.get('hosts_after'):
            raise ValueError('HUP input identity differs')
        if action['hosts_after'] != '198.51.100.41 hup-one.route.test\n198.51.100.42 hup-two.route.test\n':
            raise ValueError('HUP marker input changed')
    if spec['action'] == 'debug-tcp':
        check_debug_tcp(folder, action)
    if spec['action'] == 'bound-tcp':
        snapshots = json.loads((folder / 'action-tcp-samples.json').read_text())
        if len(snapshots) < 3 or any(item['metrics']['tcp_connections'] != 0 for item in snapshots[-3:]):
            raise ValueError('TCP private/shared caller did not drain')
        for index, item in enumerate(snapshots):
            raw = json.loads((folder / f'action-tcp-{index:03}.metrics.stdout').read_bytes())
            if item['metrics'] != {key: raw[key] for key in ['dns_queries_forwarded', 'tcp_connections']}:
                raise ValueError('TCP action raw metrics differ')
            if item['metrics']['dns_queries_forwarded'] != witness['before_metrics']['dns_queries_forwarded'] + 1:
                raise ValueError('TCP local caller created an upstream action')
    expected = spec['expected_upstream_packets']
    if expected == 1 and len(witness['held_packets']) == 1:
        if witness['resend_wait_finished_monotonic_ns'] - witness['resend_wait_started_monotonic_ns'] < 1_900_000_000:
            raise ValueError('absence of resend observed for too short a window')
    passed = result['upstream_packets'] == expected and (expected == 1 or result['resend_contract_passed'])
    return dict(result, caller_contract_passed=passed, expected_upstream_packets=expected,
                intervening_consumer=spec['action'],
                action_query=driver.normalized((folder / 'action.query').read_bytes()) if (folder / 'action.query').exists() else None,
                action_reply=driver.normalized((folder / 'action.reply').read_bytes()) if (folder / 'action.reply').exists() else None)


def validate_run(folder, side, expected_rust_sha, batch="basic"):
    profiles, plan = BATCHES[batch]
    report = json.loads((folder / 'result.json').read_text())
    receipt = json.loads((folder / 'route-receipt.json').read_text())
    root = json.loads((folder / 'rootfs-identity.json').read_text())
    if (report['side'] != side or report['c_sha256'] != driver.STOCK_SHA256 or receipt['plan'] != plan
            or report.get('rust_sha256') != expected_rust_sha or root.get('rust_sha256') != expected_rust_sha
            or root.get('c_sha256') != driver.STOCK_SHA256 or not receipt.get('tools_unchanged')):
        raise ValueError('reference/side/plan identity differs')
    for name in TOOLS:
        wanted = driver.sha256(Path(__file__).with_name(name))
        if receipt['tools'].get(name) != wanted or driver.sha256(folder / 'drivers' / name) != wanted:
            raise ValueError('frozen caller/dependency identity differs')
    expected = driver.STOCK_SHA256 if side == 'c' else report['rust_sha256']
    results = {}
    for row in report['scenarios']:
        if row['case'] in results or row['identity']['root'] != root['root']:
            raise ValueError('duplicate or wrong rootfs caller')
        validator = validate_case if batch == 'basic' else validate_clear_case
        results[row['case']] = validator(folder / row['case'], row, expected)
    if set(results) != {case['case'] for case in profiles} or report['failures']:
        raise ValueError('incomplete frozen caller set')
    return results


def run(args):
    if driver.sha256(args.rust) != args.expected_rust_sha:
        raise ValueError('candidate SHA differs')
    frozen = {name: Path(__file__).with_name(name).read_bytes() for name in TOOLS}
    tools = {name: hashlib.sha256(data).hexdigest() for name, data in frozen.items()}
    profiles, plan = BATCHES[args.batch]
    driver.SYNTAX.clear(); driver.SCENARIOS[:] = copy.deepcopy(profiles); driver.schedule = schedule
    driver.Upstream = TrackedUpstream
    args.only = '^m6b-route-'
    status = driver.run(args)
    out = args.out.resolve()
    for name in TOOLS:
        (out / 'drivers' / name).write_bytes(frozen[name])
    unchanged = all(driver.sha256(Path(__file__).with_name(name)) == tools[name] for name in TOOLS)
    save_json(out / 'route-receipt.json', {'plan': plan, 'tools': tools, 'run_status': status,
                                         'tools_unchanged': unchanged, 'scope': __doc__, 'performance_qualification': False})
    if not unchanged:
        raise ValueError('frozen tools changed during execution')
    if status:
        return status
    results = validate_run(out, args.side, args.expected_rust_sha, args.batch)
    save_json(out / 'route-validation.json', results)
    passed = all(row.get('caller_contract_passed', row['resend_contract_passed']) for row in results.values())
    print(json.dumps({'side': args.side, 'caller_contract_passed': passed, 'results': results}, indent=2))
    return int(not passed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    plan = sub.add_parser('plan'); plan.add_argument('--out', type=Path, required=True)
    plan.add_argument('--batch', choices=BATCHES, default='basic')
    execute = sub.add_parser('run')
    for name in ['image-root', 'rust', 'out']:
        execute.add_argument('--' + name, type=Path, required=True)
    execute.add_argument('--side', choices=['c', 'rust'], required=True)
    execute.add_argument('--expected-rust-sha', required=True)
    execute.add_argument('--batch', choices=BATCHES, default='basic')
    compare = sub.add_parser('compare')
    for name in ['c', 'rust', 'out']:
        compare.add_argument('--' + name, type=Path, required=True)
    compare.add_argument('--expected-rust-sha', required=True)
    compare.add_argument('--batch', choices=BATCHES, default='basic')
    args = parser.parse_args()
    if args.action == 'plan':
        with args.out.open('x') as stream:
            json.dump(BATCHES[args.batch][1], stream, indent=2); stream.write('\n')
        return 0
    if args.action == 'run':
        return run(args)
    left, right = validate_run(args.c, 'c', args.expected_rust_sha, args.batch), validate_run(args.rust, 'rust', args.expected_rust_sha, args.batch)
    roots = [json.loads((folder / 'rootfs-identity.json').read_text()) for folder in [args.c, args.rust]]
    for key in ['image_sha256', 'image_provenance_sha256']:
        if roots[0].get(key) != roots[1].get(key):
            raise ValueError('C/R image provenance differs')
    if roots[0]['filesystem']['base_manifest_sha256'] != roots[1]['filesystem']['base_manifest_sha256']:
        raise ValueError('C/R immutable image base differs')
    c_valid = all(row.get('caller_contract_passed', row['resend_contract_passed']) for row in left.values())
    different = [case for case in left if left[case] != right[case]]
    result = {'c_reference_contract_passed': c_valid, 'differences': different,
              'c': left, 'rust': right, 'caller_contract_passed': c_valid and not different,
              'performance_qualification': False}
    with args.out.open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    print(json.dumps(result, indent=2))
    return int(not result['caller_contract_passed'])


if __name__ == '__main__':
    raise SystemExit(main())
