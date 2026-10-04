#!/usr/bin/env python3
"""Behavior probes for the manifest-driven exact-image option matrix.

These are harness threads/sockets; the production daemon retains one poll owner.
Every random/timing normalization is named and validated before comparison.
"""
from __future__ import annotations

import copy
import socket
import struct
import time

from dns_service_probe import exact_read, name, read_name, semantics


def question_bytes(packet):
    _, end = read_name(packet, 12)
    return packet[12:end]


def question_packet(host, ident, kind=1):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack('!HH', kind, 1)


def case_layout(original, actual):
    """Keep random outcomes raw, compare only the C-defined allowed positions."""
    source = question_bytes(original)
    observed = question_bytes(actual)
    letters = 0
    changed = []
    valid = len(source) == len(observed)
    for index, (left, right) in enumerate(zip(source, observed)):
        is_letter = 65 <= left <= 90 or 97 <= left <= 122
        if is_letter:
            if left != right:
                valid &= left ^ right == 0x20
                changed.append(letters)
            letters += 1
        else:
            valid &= left == right
    return {'only_case_changes': valid, 'changed_letters': changed,
            'tail_unchanged': all(index < 32 for index in changed),
            'question': observed.hex()}


def receive(client, tcp=False):
    try:
        if tcp:
            return exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        return client.recv(65535)
    except socket.timeout:
        return None


def observe_casing(port, probe, ident, transport, upstream):
    hosts = probe.get('clients', [probe['name']])
    clients, requests, replies = [], [], []
    before = len(upstream.events)
    started = time.monotonic()
    try:
        for offset, host in enumerate(hosts):
            request = question_packet(host, ident + offset)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM)
            client.settimeout(.7)
            client.connect(('127.0.0.1', port))
            clients.append(client)
            requests.append(request)
            client.sendall(struct.pack('!H', len(request)) + request if transport == 'tcp' else request)
        for client in clients:
            replies.append(receive(client, transport == 'tcp'))
    finally:
        for client in clients:
            client.close()
    events = copy.deepcopy(upstream.events[before:])
    layout = [case_layout(requests[0], bytes.fromhex(event['wire'])) for event in events]
    semantic = []
    client_questions = []
    for request, response in zip(requests, replies):
        if response is not None:
            if response[:2] != request[:2]:
                raise AssertionError('wrong casing client ID')
            semantic.append(semantics(response))
            client_questions.append(question_bytes(response).hex())
        else:
            semantic.append(None)
            client_questions.append(None)
    return {'id': probe['id'] + ':' + transport, 'response': semantic,
            'client_questions': client_questions,
            'upstream': events, 'case_layout': layout,
            'raw': [p.hex() if p is not None else None for p in replies],
            'request': [p.hex() for p in requests], 'elapsed': time.monotonic() - started}


def casing_projection(row):
    row = copy.deepcopy(row)
    for key in ('raw', 'request', 'elapsed'):
        row.pop(key)
    for event in row['upstream']:
        event.pop('wire')
    for layout in row['case_layout']:
        layout.pop('question')
        layout.pop('changed_letters')
    return row


def casing_guards(rows, scenario):
    failures = []
    saw_randomization = False
    probes = {p['id']: p for p in scenario['probes']}
    for row in rows:
        probe_id, transport = row['id'].rsplit(':', 1)
        probe = probes[probe_id]
        encoded = scenario['encoding'] and transport == 'udp'
        for layout in row['case_layout']:
            if not layout['only_case_changes'] or not layout['tail_unchanged']:
                failures.append({'id': row['id'], 'bad_case_layout': layout})
            if not encoded and layout['changed_letters']:
                failures.append({'id': row['id'], 'unexpected_encoding': layout})
            if encoded and layout['changed_letters']:
                saw_randomization = True
        if not row['case_layout']:
            failures.append({'id': row['id'], 'missing_upstream': True})
        if len(row['response']) != len(probe.get('clients', [probe['name']])) or any(r is None for r in row['response']):
            failures.append({'id': row['id'], 'missing_reply': True})
        # The distinguishable wrong-case response address detects acceptance
        # even when a daemon rewrites the question case before delivery.
        expected_address = '8.8.4.4' if probe.get('spoof_case') and not encoded else '8.8.8.8'
        for response in row['response']:
            if response and [r['data'] for r in response['records'] if r['type'] == 1] != [expected_address]:
                failures.append({'id': row['id'], 'expected_address': expected_address, 'response': response})
        if probe.get('clients') and transport == 'udp' and len(row['upstream']) != 1:
            failures.append({'id': row['id'], 'coalesced_upstream_count': len(row['upstream'])})
        # Correct echo replies must preserve each client's original case,
        # including clients differing beyond the initial 32 encoding bits.
        if not probe.get('spoof_case'):
            wanted = [question_bytes(bytes.fromhex(p)).hex() for p in row['request']]
            if row['client_questions'] != wanted:
                failures.append({'id': row['id'], 'wrong_restored_question': row['client_questions'], 'expected': wanted})
    if scenario['encoding'] and not saw_randomization:
        failures.append({'no_randomization_in_enabled_profile': True})
    return failures


def controls():
    request = question_packet('AbCdEfGhIjKlMnOpQrStUvWxYz1234567890.abcdefghij.test', 1)
    response = request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + request[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([8, 8, 8, 8])
    probe = {'id': 'control', 'name': 'AbCdEfGhIjKlMnOpQrStUvWxYz1234567890.abcdefghij.test'}
    row = {'id': 'control:udp', 'response': [semantics(response)], 'client_questions': [question_bytes(request).hex()],
           'upstream': [{'name': probe['name'].lower(), 'type': 1, 'class': 1, 'transport': 'udp', 'wire': request.hex()}],
           'case_layout': [{'only_case_changes': True, 'tail_unchanged': True, 'changed_letters': [1], 'question': ''}],
           'raw': [response.hex()], 'request': [request.hex()], 'elapsed': 0}
    scenario = {'encoding': True, 'probes': [probe]}
    assert not casing_guards([row], scenario)
    found = {}
    for control in ['no-randomization', 'wrong-client-case', 'accept-wrong-case-reply', 'mutate-letter-after32', 'missing-row']:
        mutated = copy.deepcopy(row)
        if control == 'no-randomization': mutated['case_layout'][0]['changed_letters'] = []
        elif control == 'wrong-client-case': mutated['client_questions'][0] = '00'
        elif control == 'accept-wrong-case-reply': mutated['response'][0]['records'][0]['data'] = '8.8.4.4'
        elif control == 'mutate-letter-after32': mutated['case_layout'][0]['tail_unchanged'] = False
        elif control == 'missing-row': mutated['case_layout'] = []
        assert casing_guards([mutated], scenario), control
        found['casing-' + control] = 'detected'
    reply = {'status': 'reply', 'packet': {'records': [{'data': '8.8.8.8'}]}}
    good_cycle = {'cycle': 0, 'admitted': [reply], 'at_capacity': {'status': 'timeout'}, 'udp_at_capacity': reply, 'after_release': reply}
    capacity = {'id': 'capacity:capacity', 'response': [good_cycle, dict(good_cycle, cycle=1)]}
    capacity_scenario = {'probes': [{'id': 'capacity', 'limit': 1}]}
    assert not capacity_guards([capacity], capacity_scenario)
    for control in ['early-admission', 'lost-recovery', 'udp-starvation', 'missing-cycle', 'missing-admitted-client']:
        changed = copy.deepcopy(capacity)
        if control == 'early-admission': changed['response'][0]['at_capacity'] = reply
        elif control == 'lost-recovery': changed['response'][0]['after_release'] = {'status': 'timeout'}
        elif control == 'udp-starvation': changed['response'][0]['udp_at_capacity'] = {'status': 'timeout'}
        elif control == 'missing-cycle': changed['response'].pop()
        elif control == 'missing-admitted-client': changed['response'][0]['admitted'].clear()
        assert capacity_guards([changed], capacity_scenario), control
        found['capacity-' + control] = 'detected'
    return found


def socket_result(client, tcp=True):
    try:
        packet = receive(client, tcp)
        if packet is None:
            return {'status': 'timeout'}, None
        return {'status': 'reply', 'packet': semantics(packet)}, packet.hex()
    except (ConnectionError, OSError) as error:
        return {'status': 'closed', 'error': type(error).__name__}, None


def observe_capacity(port, probe, ident, transport, upstream):
    del transport, upstream
    cycles, raw, clients = [], [], []
    started = time.monotonic()
    addresses = ['127.0.0.1', '127.0.0.3']
    try:
        for cycle in range(2):
            active = []
            row = {'cycle': cycle, 'admitted': []}
            for index in range(probe['limit']):
                client = socket.create_connection((addresses[index % 2], port), timeout=2)
                client.settimeout(2)
                clients.append(client)
                active.append(client)
                packet = question_packet('capacity.matrix.test', ident + cycle * 20 + index)
                client.sendall(struct.pack('!H', len(packet)) + packet)
                result, wire = socket_result(client)
                row['admitted'].append(result)
                raw.append(wire)
            queued = socket.create_connection((addresses[1], port), timeout=2)
            queued.settimeout(.2)
            clients.append(queued)
            packet = question_packet('capacity.matrix.test', ident + cycle * 20 + 10)
            queued.sendall(struct.pack('!H', len(packet)) + packet)
            row['at_capacity'], wire = socket_result(queued)
            raw.append(wire)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(.5)
                udp.connect((addresses[0], port))
                udp.send(question_packet('capacity.matrix.test', ident + cycle * 20 + 11))
                row['udp_at_capacity'], wire = socket_result(udp, False)
                raw.append(wire)
            active[0].close()
            clients.remove(active[0])
            queued.settimeout(2)
            row['after_release'], wire = socket_result(queued)
            raw.append(wire)
            for client in active[1:] + [queued]:
                client.close()
                clients.remove(client)
            cycles.append(row)
    finally:
        for client in clients:
            client.close()
    return {'id': probe['id'] + ':capacity', 'response': cycles, 'upstream': [],
            'raw': raw, 'request': [], 'elapsed': time.monotonic() - started}


def capacity_guards(rows, scenario):
    failures = []
    probes = {p['id']: p for p in scenario['probes']}
    for row in rows:
        probe = probes[row['id'].split(':')[0]]
        if len(row['response']) != 2:
            failures.append({'id': row['id'], 'missing_fill_drain_cycle': True})
        for cycle in row['response']:
            if len(cycle['admitted']) != probe['limit']:
                failures.append({'id': row['id'], 'wrong_admitted_count': len(cycle['admitted'])})
            if cycle['at_capacity']['status'] != 'timeout':
                failures.append({'id': row['id'], 'cycle': cycle['cycle'], 'early_accept': cycle['at_capacity']})
            for result in cycle['admitted'] + [cycle['udp_at_capacity'], cycle['after_release']]:
                if result['status'] != 'reply' or [r['data'] for r in result.get('packet', {}).get('records', [])] != ['8.8.8.8']:
                    failures.append({'id': row['id'], 'cycle': cycle['cycle'], 'missing_valid_reply': result})
    return failures
