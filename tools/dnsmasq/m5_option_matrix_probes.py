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
    admission_case = {'probes': [{'id': 'outside6', 'source': '2001:db8:5::12', 'transports': ['udp'], 'admission': {'udp': 'drop'}}]}
    admission = {'id': 'outside6:udp', 'response': {'stage': 'receive', 'status': 'timeout', 'source_address': '2001:db8:5::12', 'reply': None}}
    assert not local_service_guards([admission], admission_case)
    wrong = copy.deepcopy(admission); wrong['response']['status'] = 'reply'
    assert local_service_guards([wrong], admission_case)
    found['admission-inverted-decision'] = 'detected'
    wrong = copy.deepcopy(admission); wrong['response']['source_address'] = '2001:db8:5::11'
    assert local_service_guards([wrong], admission_case)
    found['admission-wrong-source'] = 'detected'
    assert local_service_guards([], admission_case)
    found['admission-missing-ipv6-observation'] = 'detected'
    override_case = copy.deepcopy(admission_case); override_case['probes'][0]['admission']['udp'] = 'reply'
    assert local_service_guards([admission], override_case)
    found['admission-ignores-explicit-override'] = 'detected'
    timer_probe = {'id': 'timer', 'name': 'timer.test', 'interval_ms': 50, 'expected_queries': 3, 'reply_after': 3}
    timer_scenario = {'probes': [timer_probe]}
    timer_events = [{'name': 'timer.test', 'server': '127.0.0.2', 'monotonic': t, 'wire': '12340000'} for t in [1, 1.05, 1.15]]
    timer_row = {'id': 'timer:retry', 'upstream': timer_events, 'response': {'health': [reply['packet']], 'replies': [reply['packet']]}}
    assert not retry_guards([timer_row], timer_scenario)
    for control in ['missing-retry', 'retry-after-success', 'wrong-interval', 'changed-retry-packet', 'missing-success-reply']:
        changed = copy.deepcopy(timer_row)
        if control == 'missing-retry': changed['upstream'].pop()
        elif control == 'retry-after-success': changed['upstream'].append(dict(timer_events[-1], monotonic=1.35))
        elif control == 'wrong-interval': changed['upstream'][1]['monotonic'] += .3
        elif control == 'changed-retry-packet': changed['upstream'][1]['wire'] = '12340001'
        elif control == 'missing-success-reply': changed['response']['replies'].clear()
        assert retry_guards([changed], timer_scenario), control
        found['retry-' + control] = 'detected'
    queued_case = {'probes': [{'id': 'queued', 'source': '192.0.2.12', 'scheduling': 'queued', 'transports': ['tcp'], 'admission': {'tcp': 'close'}}]}
    queued_row = {'id': 'queued:tcp', 'response': {'stage': 'receive', 'status': 'closed', 'termination': 'reset', 'errno': 104, 'source_address': '192.0.2.12', 'queued_rx_bytes': 41, 'reply': None}}
    assert not local_service_guards([queued_row], queued_case)
    for control in ['EOF-with-queued-data', 'missing-kernel-queue-proof']:
        changed = copy.deepcopy(queued_row)
        if control == 'EOF-with-queued-data': changed['response']['termination'] = 'EOF'; changed['response']['errno'] = None
        else: changed['response']['queued_rx_bytes'] = 0
        assert local_service_guards([changed], queued_case), control
        found['admission-' + control] = 'detected'
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


class LocalTopology:
    """A client namespace prevents off-subnet sources becoming local addresses."""
    def __init__(self):
        import os
        import subprocess
        self.commands = []
        self.child = subprocess.Popen(['unshare', '--net', 'sleep', '3600'])
        self.before = sorted(name for _, name in socket.if_nameindex())
        deadline = time.monotonic() + 2
        while os.readlink('/proc/self/ns/net') == os.readlink(f'/proc/{self.child.pid}/ns/net'):
            if self.child.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('client namespace not created')
            time.sleep(.01)
        self.run(['ip', 'link', 'add', 'm5srv', 'type', 'veth', 'peer', 'name', 'm5cli'])
        self.run(['ip', 'link', 'set', 'm5cli', 'netns', str(self.child.pid)])
        self.run(['ip', 'addr', 'add', '192.0.2.10/31', 'dev', 'm5srv'])
        self.run(['ip', '-6', 'addr', 'add', '2001:db8:5::10/127', 'dev', 'm5srv', 'nodad'])
        self.run(['ip', 'link', 'set', 'm5srv', 'up'])
        self.client(['ip', 'link', 'set', 'lo', 'up'])
        self.client(['ip', 'addr', 'add', '192.0.2.11/31', 'dev', 'm5cli'])
        self.client(['ip', '-6', 'addr', 'add', '2001:db8:5::11/127', 'dev', 'm5cli', 'nodad'])
        self.client(['ip', 'link', 'set', 'm5cli', 'up'])
        for address in ['192.0.2.9', '192.0.2.12']:
            self.client(['ip', 'addr', 'add', address + '/32', 'dev', 'lo'])
            self.run(['ip', 'route', 'add', address + '/32', 'via', '192.0.2.11', 'dev', 'm5srv'])
        for address in ['2001:db8:5::f', '2001:db8:5::12']:
            self.client(['ip', '-6', 'addr', 'add', address + '/128', 'dev', 'lo', 'nodad'])
            self.run(['ip', '-6', 'route', 'add', address + '/128', 'via', '2001:db8:5::11', 'dev', 'm5srv'])
        self.inventory = {'server_netns': os.readlink('/proc/self/ns/net'),
                          'client_netns': os.readlink(f'/proc/{self.child.pid}/ns/net'),
                          'server_addresses': self.run(['ip', '-j', 'addr']),
                          'client_addresses': self.client(['ip', '-j', 'addr']),
                          'server_routes4': self.run(['ip', '-j', 'route']),
                          'server_routes6': self.run(['ip', '-j', '-6', 'route'])}

    def run(self, args):
        import subprocess
        self.commands.append(args)
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError({'command': args, 'stderr': result.stderr})
        return result.stdout

    def client(self, args):
        return self.run(['nsenter', '-t', str(self.child.pid), '-n', *args])

    def close(self):
        self.run(['ip', 'link', 'del', 'm5srv'])
        self.child.terminate()
        self.child.wait(timeout=3)
        current = sorted(name for _, name in socket.if_nameindex())
        if current != self.before:
            raise AssertionError({'interface_cleanup': current, 'expected': self.before})


def network_probe(spec):
    family = socket.AF_INET6 if ':' in spec['destination'] else socket.AF_INET
    tcp = spec['transport'] == 'tcp'
    request = question_packet('admission.matrix.test', spec['ident'])
    result = {'stage': 'connect', 'status': None, 'reply': None, 'raw': None,
              'source_address': None, 'errno': None}
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        if spec.get('source'):
            client.bind((spec['source'], 0))
        try:
            client.connect((spec['destination'], spec['port']))
            result['source_address'] = client.getsockname()[0]
            client.settimeout(2 if spec.get('queued') else .18)
            result['stage'] = 'receive'
            if spec.get('send_dns', True):
                client.sendall(struct.pack('!H', len(request)) + request if tcp else request)
            if spec.get('queued'):
                import json
                print(json.dumps({'queued': True, 'sent_bytes': len(request) + 2}), flush=True)
            response = receive(client, tcp)
            if response is None:
                result['status'] = 'timeout'
            else:
                result['status'] = 'reply'
                result['reply'] = semantics(response)
                result['raw'] = response.hex()
        except ConnectionRefusedError as error:
            result['status'] = 'refused'
            result['errno'] = error.errno
        except (ConnectionResetError, ConnectionError) as error:
            result['status'] = 'closed'
            result['errno'] = getattr(error, 'errno', None)
        except socket.timeout:
            result['status'] = 'timeout'
        except OSError as error:
            result['status'] = 'error'
            result['errno'] = error.errno
    return result


def observe_local_service(port, probe, ident, transport, topology):
    import json
    import sys
    from pathlib import Path
    spec = {'destination': probe['destination'], 'source': probe.get('source'),
            'port': port, 'transport': transport, 'ident': ident,
            'send_dns': probe.get('scheduling') != 'idle', 'queued': probe.get('scheduling') == 'queued'}
    queued_bytes = None
    if spec['queued']:
        result, queued_bytes = queued_network_probe(topology, spec)
    elif probe.get('remote'):
        result = json.loads(topology.client([sys.executable, str(Path(__file__).resolve()), '--network-probe', json.dumps(spec)]))
    else:
        result = network_probe(spec)
    raw = result.pop('raw')
    # Preserve and compare reset versus EOF; the controlled queued-byte probe
    # exposed shutdown(Both) as a real difference even with data pending.
    raw_errno = result['errno']
    if probe.get('scheduling'):
        result['termination'] = 'reset' if raw_errno == 104 else ('EOF' if result['status'] == 'closed' and raw_errno is None else result['status'])
        result['queued_rx_bytes'] = queued_bytes
    return {'id': probe['id'] + ':' + transport, 'response': result, 'upstream': [],
            'raw': {'reply': raw, 'errno': raw_errno}, 'request': spec, 'elapsed': 0}


def local_service_guards(rows, scenario):
    failures = []
    planned = [p['id'] + ':' + transport for p in scenario['probes'] for transport in p.get('transports', ['udp', 'tcp'])]
    if [row['id'] for row in rows] != planned:
        failures.append({'missing_admission_row': True})
    probes = {p['id']: p for p in scenario['probes']}
    for row in rows:
        probe_id, transport = row['id'].rsplit(':', 1)
        probe = probes[probe_id]
        actual = row['response']
        expected = probe.get('admission', {}).get(transport)
        if expected == 'reply':
            if actual['status'] != 'reply' or [r['data'] for r in (actual['reply'] or {}).get('records', [])] != ['8.8.8.8']:
                failures.append({'id': row['id'], 'expected_reply': actual})
        elif expected == 'drop' and actual['status'] != 'timeout':
            failures.append({'id': row['id'], 'expected_silent_drop': actual})
        elif expected == 'close' and (actual['stage'] != 'receive' or actual['status'] != 'closed'):
            failures.append({'id': row['id'], 'expected_accepted_then_closed': actual})
        elif expected == 'no-listener' and actual['status'] != 'refused':
            failures.append({'id': row['id'], 'expected_no_listener': actual})
        if probe.get('scheduling') and actual.get('termination') != ('reset' if probe['scheduling'] == 'queued' else 'EOF'):
            failures.append({'id': row['id'], 'wrong_termination_boundary': actual})
        if probe.get('scheduling') == 'queued' and (actual.get('errno') != 104 or (actual.get('queued_rx_bytes') or 0) < len(question_packet('admission.matrix.test', 0)) + 2):
            failures.append({'id': row['id'], 'missing_queued_reset_proof': actual})
        if probe.get('source') and actual['source_address'] not in (None, probe['source']):
            failures.append({'id': row['id'], 'wrong_source': actual['source_address']})
    return failures


def align_second():
    # C uses whole wall-clock seconds for the timeout and milliseconds for its
    # exponential schedule. Start both sides away from the truncation boundary.
    fraction = time.time() % 1
    delay = .15 - fraction
    if delay < 0:
        delay += 1
    time.sleep(delay)


def local_health(port, ident):
    out = []
    for tcp in [False, True]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
            client.settimeout(.4)
            client.connect(('127.0.0.1', port))
            packet = question_packet('retry-health.matrix.test', ident + int(tcp))
            client.sendall(struct.pack('!H', len(packet)) + packet if tcp else packet)
            packet = receive(client, tcp)
            out.append(semantics(packet) if packet is not None else None)
    return out


def observe_retry(port, probe, ident, transport, upstream):
    import subprocess
    del transport
    align_second()
    before = len(upstream.events)
    captured_before = len(upstream.captured)
    sources = [upstream] + ([upstream.alternate] if upstream.alternate else [])
    before_counts = [len(source.events) for source in sources]
    captured_total = sum(len(source.captured) for source in sources)
    started = time.monotonic()
    request = question_packet(probe['name'], ident)
    raws, output, routes = [], {}, []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(.02)
        client.connect(('127.0.0.1', port))
        client.send(request)
        while sum(len(source.captured) for source in sources) == captured_total:
            if time.monotonic() - started > .5:
                raise AssertionError('initial retry query not forwarded')
            time.sleep(.002)
        output['health'] = local_health(port, ident + 1)
        if probe.get('send_failure'):
            subprocess.run(['ip', 'addr', 'del', upstream.host + '/32', 'dev', 'lo'], check=True)
            try:
                lookup = subprocess.run(['ip', 'route', 'get', upstream.host], capture_output=True, text=True)
                routes.append({'phase': 'removed', 'exit': lookup.returncode, 'stderr': lookup.stderr, 'stdout': lookup.stdout})
                if lookup.returncode == 0:
                    raise AssertionError('removed upstream still has a route')
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
                    try:
                        check.sendto(b'route-check', (upstream.host, upstream.port))
                    except OSError as error:
                        output['route_send_errno'] = error.errno
                    else:
                        raise AssertionError('send to removed upstream unexpectedly succeeded')
                time.sleep(.25)
                output['health_during_failure'] = local_health(port, ident + 4)
            finally:
                subprocess.run(['ip', 'addr', 'add', upstream.host + '/32', 'dev', 'lo'], check=True)
            held, peer, answer = upstream.captured[captured_before]
            upstream.udp.sendto(answer, peer)
            client.settimeout(.18)
            late = receive(client)
            output['late_after_failure'] = semantics(late) if late is not None else None
            raws.append(late.hex() if late else None)
            recovery = question_packet('recovery.matrix.test', ident + 8)
            client.send(recovery)
            client.settimeout(.5)
            reply = receive(client)
            output['recovery'] = semantics(reply) if reply is not None else None
            raws.append(reply.hex() if reply else None)
            time.sleep(.1)
        else:
            replies = []
            deadline = started + probe['duration']
            while time.monotonic() < deadline:
                packet = receive(client)
                if packet is not None:
                    replies.append(semantics(packet))
                    raws.append(packet.hex())
            output['replies'] = replies
        events = copy.deepcopy([event for source, count in zip(sources, before_counts) for event in source.events[count:]])
        events.sort(key=lambda event: event.get('monotonic', 0))
    return {'id': probe['id'] + ':retry', 'response': output, 'upstream': events,
            'raw': {'replies': raws, 'routes': routes}, 'request': request.hex(),
            'elapsed': time.monotonic() - started}


def retry_projection(row):
    row = copy.deepcopy(row)
    for key in ['raw', 'request', 'elapsed']:
        row.pop(key)
    for event in row['upstream']:
        event['query_without_id'] = event.pop('wire')[4:]
        for key in ['monotonic', 'wall_time']:
            event.pop(key, None)
    row['upstream'].sort(key=lambda event: (event.get('server', ''), event['name']))
    return row


def retry_guards(rows, scenario):
    failures = []
    probes = {p['id']: p for p in scenario['probes']}
    for row in rows:
        probe = probes[row['id'].split(':')[0]]
        events = [e for e in row['upstream'] if e['name'] == probe['name'].lower()]
        if len(events) != probe['expected_queries']:
            failures.append({'id': row['id'], 'expected_queries': probe['expected_queries'], 'actual_queries': len(events)})
        if len({event['wire'] for event in events}) > 1:
            failures.append({'id': row['id'], 'retry_changed_packet_or_id': True})
        for server in {e.get('server') for e in events}:
            times = [e['monotonic'] for e in events if e.get('server') == server]
            for index, (left, right) in enumerate(zip(times, times[1:])):
                expected_interval = probe['interval_ms'] * (2 ** index) / 1000
                interval = right - left
                if not expected_interval - .012 <= interval <= expected_interval + .09:
                    failures.append({'id': row['id'], 'server': server, 'interval': interval, 'expected_interval': expected_interval})
        for phase in ['health', 'health_during_failure']:
            for response in row['response'].get(phase, []):
                if response is None or [r['data'] for r in response['records']] != ['8.8.8.8']:
                    failures.append({'id': row['id'], 'unresponsive_health': phase})
        if probe.get('send_failure'):
            if row['response'].get('route_send_errno') != 101:
                failures.append({'id': row['id'], 'missing_real_enetunreach': row['response'].get('route_send_errno')})
            if row['response']['late_after_failure'] is not None:
                failures.append({'id': row['id'], 'failed_retry_still_live': True})
            response = row['response']['recovery']
            if response is None or response['flags'] & 15 or not response['records']:
                failures.append({'id': row['id'], 'failed_recovery': response})
        elif probe.get('reply_after'):
            responses = row['response']['replies']
            if len(responses) != 1 or [r['data'] for r in responses[0]['records']] != ['8.8.8.8']:
                failures.append({'id': row['id'], 'wrong_success_reply': responses})
        elif row['response']['replies']:
            failures.append({'id': row['id'], 'blackhole_replied': row['response']['replies']})
    return failures


def queued_network_probe(topology, spec):
    import json
    import os
    from pathlib import Path
    import select
    import signal
    import subprocess
    import sys
    process = None
    os.kill(topology.daemon_pid, signal.SIGSTOP)
    try:
        process = subprocess.Popen(['nsenter', '-t', str(topology.child.pid), '-n', sys.executable,
                                    str(Path(__file__).resolve()), '--network-probe', json.dumps(spec)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if not select.select([process.stdout], [], [], 2)[0]:
            raise AssertionError('queued client did not connect/send')
        sent = json.loads(process.stdout.readline())
        if not sent.get('queued'):
            raise AssertionError({'queued_client': sent})
        deadline = time.monotonic() + 1
        queued_bytes = 0
        while time.monotonic() < deadline:
            for table in ['/proc/net/tcp', '/proc/net/tcp6']:
                for line in Path(table).read_text().splitlines()[1:]:
                    fields = line.split()
                    if int(fields[1].rsplit(':', 1)[1], 16) == spec['port'] and fields[3] == '01':
                        queued_bytes = max(queued_bytes, int(fields[4].split(':')[1], 16))
            if queued_bytes >= sent['sent_bytes']:
                break
            time.sleep(.005)
        if queued_bytes < sent['sent_bytes']:
            raise AssertionError({'missing_kernel_receive_queue': queued_bytes, 'sent': sent})
        os.kill(topology.daemon_pid, signal.SIGCONT)
        stdout, stderr = process.communicate(timeout=3)
        if process.returncode:
            raise AssertionError({'client_failure': stderr})
        return json.loads(stdout), queued_bytes
    finally:
        os.kill(topology.daemon_pid, signal.SIGCONT)
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=2)


if __name__ == '__main__':
    import json
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--network-probe':
        print(json.dumps(network_probe(json.loads(sys.argv[2]))))
    else:
        raise SystemExit('internal --network-probe JSON only')
