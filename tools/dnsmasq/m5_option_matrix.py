#!/usr/bin/env python3
"""Manifest-driven exact-image option gate; run under run_isolated.sh.

Every configuration compares --test exit/stdout/stderr, actual startup and
source-selected UDP/TCP behavior. C supplies expectations. The manifest is the
pre-implementation boundary checklist; a missing row can never qualify an option.
Raw evidence and failed runs remain below private/. No router is contacted.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, read_name, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
import m5_option_matrix_probes as probes_extra


def dump(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def rr(kind, data, owner=b'\xc0\x0c', ttl=120, cls=1):
    return owner + struct.pack('!HHIH', kind, cls, ttl, len(data)) + data


def query(probe, ident):
    host = probe['name']
    encoded = name(host) if host else b'\0'
    edns = probe.get('edns', False) or probe.get('do', False)
    flags = probe.get('query_flags', 0x100) | (0x10 if probe.get('cd') else 0) | (0x20 if probe.get('ad') else 0)
    packet = struct.pack('!6H', ident, flags, 1, 0, 0, int(edns))
    packet += encoded + struct.pack('!HH', probe.get('type', 1), probe.get('class', 1))
    if edns:
        packet += rr(41, b'', b'\0', 0x8000 if probe.get('do') else 0, probe.get('udp_size', 1232))
    return packet


def fixture_record(record):
    kind = record['type']
    owner = name(record['owner']) if 'owner' in record else b'\xc0\x0c'
    if 'address' in record:
        data = ipaddress.ip_address(record['address']).packed
    elif 'target' in record:
        data = name(record['target'])
    else:
        data = bytes.fromhex(record.get('hex', ''))
    declared = record.get('declared_length', len(data))
    return owner + struct.pack('!HHIH', kind, record.get('class', 1), record.get('ttl', 120), declared) + data


class Upstream:
    """Packet fixtures are input stimuli, never expected daemon responses."""
    def __init__(self, probes, host="127.0.0.2", port=0):
        self.probes = {(p['name'].lower(), p.get('type', 1)): p for p in probes}
        self.host = host
        self.captured = []
        self.family = socket.AF_INET6 if ':' in host else socket.AF_INET
        self.udp = socket.socket(self.family, socket.SOCK_DGRAM)
        self.udp.bind((host, port))
        self.port = self.udp.getsockname()[1]
        self.udp.settimeout(.05)
        self.tcp = socket.socket(self.family, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((host, self.port))
        self.tcp.listen()
        self.tcp.settimeout(.05)
        self.stop = threading.Event()
        self.events, self.errors = [], []
        self.threads = [threading.Thread(target=self.udp_loop), threading.Thread(target=self.tcp_loop)]
        for worker in self.threads:
            worker.start()

    def answer(self, packet, transport):
        host, end = read_name(packet, 12)
        kind, cls = struct.unpack_from('!HH', packet, end)
        self.events.append({'name': host, 'type': kind, 'class': cls, 'transport': transport,
                            'wire': packet.hex()})
        probe = self.probes.get((host, kind), {})
        if probe.get('responses'):
            count = sum(event['name'] == host and event['type'] == kind for event in self.events)
            probe = dict(probe, **probe['responses'][min(count - 1, len(probe['responses']) - 1)])
        if probe.get('timed'):
            self.events[-1]['monotonic'] = time.monotonic()
            self.events[-1]['wall_time'] = time.time()
            self.events[-1]['server'] = self.host
        value = probe.get('reply', '192.0.2.10' if kind == 1 else '2001:db8::10')
        record_kind = kind
        if kind == 12:
            data = name('upstream.matrix.test')
        elif kind in (1, 28):
            data = ipaddress.ip_address(value).packed
        elif kind == 16:
            data = b'\x06matrix'
        elif kind == 255:
            record_kind = 1
            data = ipaddress.ip_address('192.0.2.10').packed
        else:
            data = b'\x01x'
        owner = b'\xc0\x0c'
        records = []
        if probe.get('cname'):
            owner = name('target.matrix.test')
            records.append(rr(5, owner))
        records.append(rr(record_kind, data, owner, ttl=probe.get('reply_ttl', 120), cls=probe.get('reply_class', cls)))
        section_count = [len(records), 0, 0]
        if probe.get('sections') and kind == 1:
            records.extend([rr(1, data, name('ns.matrix.test')), rr(1, data, name('extra.matrix.test'))])
            section_count = [1, 1, 1]
        if 'records' in probe:
            records = []
            section_count = []
            for section in ['answer', 'authority', 'additional']:
                selected = [r for r in probe['records'] if r.get('section', 'answer') == section]
                section_count.append(len(selected))
                records.extend(fixture_record(record) for record in selected)
        if probe.get('echo_edns'):
            opt = next((r for r in semantics(packet)['records'] if r['type'] == 41), None)
            if opt is not None:
                records.append(rr(41, b'', b'\0', opt['ttl'] & 0x8000, 1232))
                section_count[2] += 1
        flags = probe.get('reply_flags', 0x8580) | probe.get('rcode', 0) | (0x200 if probe.get('tc') else 0)
        response = packet[:2] + struct.pack('!5H', flags, 1, *section_count) + packet[12:end + 4] + b''.join(records)
        self.events[-1]['reply_wire'] = response.hex()
        return response

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                response = self.answer(packet, 'udp')
                host, end = read_name(packet, 12)
                probe = self.probes.get((host, struct.unpack_from('!H', packet, end)[0]), {})
                self.captured.append((packet, peer, response))
                count = sum(event['name'] == host and event['transport'] == 'udp' for event in self.events)
                if probe.get('drop_all') or count < probe.get('reply_after', 1):
                    continue
                if probe.get('delay_ms'):
                    time.sleep(probe['delay_ms'] / 1000)
                if probe.get('spoof_case'):
                    wrong = bytearray(response)
                    for index in range(12, end):
                        if 65 <= wrong[index] <= 90 or 97 <= wrong[index] <= 122:
                            wrong[index] ^= 0x20
                            break
                    wrong[-4:] = bytes([8, 8, 4, 4])
                    self.udp.sendto(wrong, peer)
                    time.sleep(.025)
                self.udp.sendto(response, peer)
            except socket.timeout:
                continue
            except OSError:
                if not self.stop.is_set():
                    self.errors.append('UDP socket failure')
            except Exception as error:
                self.errors.append(repr(error))

    def tcp_loop(self):
        while not self.stop.is_set():
            try:
                client, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self.connection, args=(client,))
            self.threads.append(worker)
            worker.start()

    def connection(self, client):
        try:
            with client:
                client.settimeout(.5)
                while not self.stop.is_set():
                    packet = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
                    response = self.answer(packet, 'tcp')
                    host, end = read_name(packet, 12)
                    probe = self.probes.get((host, struct.unpack_from('!H', packet, end)[0]), {})
                    if probe.get('spoof_case'):
                        response = bytearray(response)
                        for index in range(12, end):
                            if 65 <= response[index] <= 90 or 97 <= response[index] <= 122:
                                response[index] ^= 0x20
                                break
                        response[-4:] = bytes([8, 8, 4, 4])
                    client.sendall(struct.pack('!H', len(response)) + response)
        except (ConnectionError, OSError):
            pass
        except Exception as error:
            self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.udp.close()
        self.tcp.close()
        for worker in self.threads:
            worker.join(2)
        if any(worker.is_alive() for worker in self.threads):
            raise AssertionError('upstream worker remains live')
        if self.errors:
            raise AssertionError(self.errors)


def observe(port, probe, ident, transport, upstream):
    if probe.get('sleep_before'):
        time.sleep(probe['sleep_before'])
    packet = query(probe, ident)
    before = len(upstream.events)
    started = time.monotonic()
    response = None
    transport_error = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM) as client:
        client.settimeout(.5)
        client.connect(('127.0.0.1', port))
        client.sendall(packet if transport == 'udp' else struct.pack('!H', len(packet)) + packet)
        try:
            response = client.recv(65535) if transport == 'udp' else exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        except socket.timeout:
            transport_error = {'kind': 'timeout', 'errno': None}
        except (ConnectionError, OSError) as error:
            transport_error = {'kind': type(error).__name__, 'errno': getattr(error, 'errno', None), 'message': str(error)}
    try:
        result = semantics(response) if response is not None else None
    except (ValueError, IndexError, struct.error) as error:
        result = {'id': int.from_bytes(response[:2], 'big'), 'flags': int.from_bytes(response[2:4], 'big'), 'malformed': str(error), 'wire_without_id': response[2:].hex()}
    if result is not None and result['id'] != ident:
        raise AssertionError('wrong client transaction ID')
    return {'id': probe['id'] + ':' + transport, 'response': result, 'transport_error': transport_error,
            'question_wire': (response[12:read_name(response, 12)[1] + 4].hex() if response is not None else None),
            'raw': response.hex() if response is not None else None,
            'request': packet.hex(), 'elapsed': time.monotonic() - started,
            'upstream': copy.deepcopy(upstream.events[before:])}


def descendants(root):
    live = []
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                if os.path.realpath(proc / 'root') == str(root):
                    live.append(int(proc.name))
            except (FileNotFoundError, PermissionError):
                pass
    return live


def run_side(root, side, scenario, folder):
    if scenario.get('adapter') == 'dhcp':
        import m5_option_matrix_dhcp
        return m5_option_matrix_dhcp.run_side(root, side, scenario, folder)
    folder.mkdir()
    topology = probes_extra.LocalTopology() if scenario.get('adapter') == 'local-service' else None
    isolated_address = scenario.get('upstream_address')
    if isolated_address:
        subprocess.run(['ip', 'addr', 'add', isolated_address + '/32', 'dev', 'lo'], check=True)
    upstream = Upstream(scenario['probes'], isolated_address or scenario.get('upstream_host', '127.0.0.2'), scenario.get('upstream_port', 0))
    alternate = Upstream(scenario['probes'], '127.0.0.3') if scenario.get('alternate_upstream') else None
    upstream.alternate = alternate
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    conf = (('' if scenario.get('resolv_nameserver') else 'no-resolv\n')
            + 'no-hosts\nno-round-robin\nuser=root\ngroup=root\n'
            + ('' if scenario.get('adapter') == 'casing' else 'no-0x20-encode\n')
            + ('' if scenario.get('listen_addresses') == [] else 'listen-address=' + ','.join(scenario.get('listen_addresses', ['127.0.0.1'])) + '\n')
            + f'port={port}\ncache-size={scenario.get("cache_size", 0)}\nlocal-ttl=120\n'
            f'pid-file=/m2/matrix.pid\n'
            + ('' if scenario.get('no_default_server') else f'server={upstream.host}#{upstream.port}\n')
            + 'addn-hosts=/m2/matrix.hosts\n'
            + (f'server=127.0.0.3#{alternate.port}\n' if alternate else '') + scenario['config'].replace('{upstream}', str(upstream.port)))
    (root / 'm2/matrix.conf').write_text(conf)
    (root / 'm2/matrix.hosts').write_text(scenario.get('hosts', ''))
    if scenario.get('resolv_nameserver'):
        resolv = 'nameserver ' + scenario['resolv_nameserver'] + '\n'
        (root / 'm2/matrix.resolv').write_text(resolv)
        (folder / 'resolv.conf').write_text(resolv)
    (folder / 'config').write_text(conf)
    (folder / 'hosts').write_text(scenario.get('hosts', ''))
    test = subprocess.run(command(root, side, '--test', '-C', '/m2/matrix.conf', *scenario.get('arguments', [])), capture_output=True, timeout=5)
    result = {'syntax': {'exit': test.returncode, 'stdout': test.stdout.decode(errors='replace'),
                          'stderr': test.stderr.decode(errors='replace')}, 'rows': []}
    process = None
    try:
        with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr:
            process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/matrix.conf', *scenario.get('arguments', [])),
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + 3
            while process.poll() is None:
                try:
                    if scenario.get('adapter') in ('capacity', 'local-service'):
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ready:
                            ready.settimeout(.05)
                            ready.connect((scenario.get('readiness_address', '127.0.0.1'), port))
                            ready.send(probes_extra.question_packet('admission.matrix.test' if topology else 'capacity.matrix.test', 0x2930))
                            ready.recv(4096)
                    else:
                        with socket.create_connection(('127.0.0.1', port), .05):
                            pass
                    result['startup'] = {'ready': True}
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        result['startup'] = {'ready': False, 'timeout': True}
                        break
                    time.sleep(.01)
            else:
                result['startup'] = {'ready': False, 'exit': process.returncode}
            if result['startup']['ready']:
                result['identity'] = process_identity(root, process.pid)
                if topology:
                    topology.daemon_pid = process.pid
                    if any(probe.get('scheduling') for probe in scenario['probes']):
                        warmup = {'source': '2001:db8:5::11', 'destination': '2001:db8:5::10', 'port': port, 'ident': 0x2931, 'transport': 'udp', 'receive_timeout': 1.5}
                        import sys
                        result['ipv6_network_warmup'] = json.loads(topology.client([sys.executable, str(Path(probes_extra.__file__).resolve()), '--network-probe', json.dumps(warmup)]))
                        if result['ipv6_network_warmup']['status'] != 'reply':
                            raise AssertionError('on-link IPv6 readiness failed')
                verify_identity(result['identity']['sha256'], sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs')))
                pairs = {}
                for index, probe in enumerate(scenario['probes']):
                    if probe.get('pair_start'):
                        fraction = time.time() % 1
                        if fraction > .55:
                            time.sleep(1.03 - fraction)
                        pairs[probe['pair_start']] = int(time.time())
                    for transport in probe.get('transports', ['udp', 'tcp']):
                        observer = {'casing': probes_extra.observe_casing, 'capacity': probes_extra.observe_capacity, 'retry': probes_extra.observe_retry}.get(scenario.get('adapter'), observe)
                        if topology:
                            result['rows'].append(probes_extra.observe_local_service(port, probe, 0x4100 + index * 4, transport, topology))
                        else:
                            result['rows'].append(observer(port, probe, 0x4100 + index * 4, transport, upstream))
                    if probe.get('pair_end') and pairs[probe['pair_end']] != int(time.time()):
                        raise AssertionError('cache seed/replay pair crossed a wall-clock second; exact TTL gate must rerun')
    finally:
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
                result['forced_kill'] = True
            result['exit'] = process.returncode
        upstream.close()
        if alternate:
            alternate.close()
        if isolated_address:
            subprocess.run(['ip', 'addr', 'del', isolated_address + '/32', 'dev', 'lo'], check=True)
        if topology:
            topology.close()
            dump(folder / 'network.json', {'inventory': topology.inventory, 'commands': topology.commands, 'cleanup': 'restored'})
        deadline = time.monotonic() + 2
        while descendants(root) and time.monotonic() < deadline:
            time.sleep(.02)
        result['cleanup'] = {'live_pids': descendants(root), 'pid_file': (root / 'm2/matrix.pid').exists()}
        result['startup']['stdout'] = (folder / 'stdout').read_text()
        result['startup']['stderr'] = (folder / 'stderr').read_text()
        dump(folder / 'observed.json', result)
    return result


def verify_identity(actual, expected):
    if actual != expected:
        raise AssertionError('running daemon ELF identity mismatch')


def normalized_text(text):
    # Only the executable identity prefix may differ. Never remove diagnostic
    # bodies, location/line numbers, missing output, or arbitrary startup logs.
    return text.replace('dnsmasq-rs:', 'dnsmasq:')


def compare(expected, actual, scenario):
    failures = []
    expected_exit = scenario.get('expected_test_exit', 0)
    if scenario.get('reference_defect'):
        import m5_option_matrix_dhcp
        return m5_option_matrix_dhcp.reference_difference(expected, actual, scenario)
    wanted_ready = scenario.get('expected_startup_exit', 0) == 0 and expected_exit == 0
    if 'expected_startup_exit' in scenario and expected['startup'].get('exit', 0) != scenario['expected_startup_exit']:
        failures.append({'phase': 'c-calibration', 'expected_startup_exit': scenario['expected_startup_exit'], 'actual': expected['startup']})
    if expected['syntax']['exit'] != expected_exit or expected['startup']['ready'] != wanted_ready:
        failures.append({'phase': 'c-calibration', 'expected_test_exit': expected_exit, 'syntax': expected['syntax'], 'startup': expected['startup']})
    for phase in ('syntax', 'startup'):
        a, b = copy.deepcopy(expected[phase]), copy.deepcopy(actual[phase])
        for data in (a, b):
            for stream in ('stdout', 'stderr'):
                data[stream] = normalized_text(data.get(stream, ''))
        if a != b:
            failures.append({'phase': phase, 'c': a, 'rust': b})
    planned = [p['id'] + ':' + t for p in scenario['probes'] for t in p.get('transports', ['udp', 'tcp'])]
    for side, observed in [('c', expected), ('rust', actual)]:
        if [r['id'] for r in observed['rows']] != planned:
            failures.append({'phase': 'coverage', 'side': side, 'expected': planned,
                             'actual': [r['id'] for r in observed['rows']]})
        if observed['cleanup'] != {'live_pids': [], 'pid_file': False}:
            failures.append({'phase': 'cleanup', 'side': side, 'actual': observed['cleanup']})
        if observed.get('forced_kill') or (observed['startup']['ready'] and observed['exit'] != 0):
            failures.append({'phase': 'shutdown', 'side': side, 'exit': observed['exit']})
    if scenario.get('adapter') == 'dhcp':
        import m5_option_matrix_dhcp
        failures.extend({'phase': 'c-dhcp-anchor', **failure} for failure in m5_option_matrix_dhcp.guards(expected['rows'], scenario))
    if scenario.get('adapter') == 'local-service':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'admission-guard', 'side': side, **failure} for failure in probes_extra.local_service_guards(observed['rows'], scenario))
    if scenario.get('adapter') == 'capacity':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'capacity-guard', 'side': side, **failure} for failure in probes_extra.capacity_guards(observed['rows'], scenario))
    if scenario.get('adapter') == 'retry':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'retry-guard', 'side': side, **failure} for failure in probes_extra.retry_guards(observed['rows'], scenario))
        for left, right in zip(expected['rows'], actual['rows']):
            a, b = probes_extra.retry_projection(left), probes_extra.retry_projection(right)
            if a != b:
                failures.append({'phase': 'runtime', 'id': left['id'], 'c': a, 'rust': b})
        return failures
    if scenario.get('adapter') == 'casing':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'casing-guard', 'side': side, **failure} for failure in probes_extra.casing_guards(observed['rows'], scenario))
        for left, right in zip(expected['rows'], actual['rows']):
            a, b = probes_extra.casing_projection(left), probes_extra.casing_projection(right)
            if a != b:
                failures.append({'phase': 'runtime', 'id': left['id'], 'c': a, 'rust': b})
        return failures
    for row in expected['rows']:
        probe_id, transport = row['id'].rsplit(':', 1)
        probe = next(p for p in scenario['probes'] if p['id'] == probe_id)
        # C-reference non-vacuity guards are derived from source call paths.
        if 'c_expect' in probe:
            wanted = probe['c_expect'].get(transport, 'response')
            if (row['response'] is None) != (wanted == 'timeout'):
                failures.append({'phase': 'c-calibration', 'id': row['id'], 'expected': wanted, 'c': row})
            if 'upstream_count' in probe['c_expect'] and len(row['upstream']) != probe['c_expect']['upstream_count']:
                failures.append({'phase': 'c-calibration', 'id': row['id'], 'expected_upstream_count': probe['c_expect']['upstream_count'], 'actual': len(row['upstream'])})
            if 'rcode' in probe['c_expect'] and (row['response'] is None or row['response'].get('flags', 0) & 15 != probe['c_expect']['rcode']):
                failures.append({'phase': 'c-calibration', 'id': row['id'], 'expected_rcode': probe['c_expect']['rcode'], 'c': row['response']})
            if 'answer_addresses' in probe['c_expect']:
                addresses = sorted(r['data'] for r in (row['response'] or {}).get('records', []) if r['section'] == 'answer' and r['type'] in (1, 28))
                if addresses != sorted(probe['c_expect']['answer_addresses']):
                    failures.append({'phase': 'c-calibration', 'id': row['id'], 'expected_addresses': probe['c_expect']['answer_addresses'], 'c_addresses': addresses})
    for left, right in zip(expected['rows'], actual['rows']):
        a, b = copy.deepcopy(left), copy.deepcopy(right)
        for row in (a, b):
            for key in ('raw', 'request', 'elapsed'):
                row.pop(key)
            for event in row['upstream']:
                wire = event.pop('wire')
                if scenario.get('strict_upstream_wire'):
                    event['query_without_id'] = wire[4:]
                event.pop('reply_wire', None)
        if a != b:
            failures.append({'phase': 'runtime', 'id': left['id'], 'c': a, 'rust': b})
    return failures


def self_test():
    case = {'probes': [{'id': 'required'}]}
    base = {'syntax': {'exit': 0, 'stdout': '', 'stderr': 'dnsmasq: syntax check OK.\n'},
            'startup': {'ready': True}, 'cleanup': {'live_pids': [], 'pid_file': False}, 'exit': 0,
            'rows': [{'id': 'required:' + t, 'raw': '', 'request': '', 'elapsed': 0,
                      'response': None, 'upstream': []} for t in ['udp', 'tcp']]}
    assert not compare(base, copy.deepcopy(base), case)
    controls = {}
    for key in ['missing-row', 'missing-syntax-output', 'wrong-syntax-exit', 'wrong-parser-output', 'startup-failure', 'runtime-change', 'leaked-process', 'leaked-pid']:
        changed = copy.deepcopy(base)
        if key == 'missing-row': changed['rows'].pop()
        elif key == 'missing-syntax-output': changed['syntax']['stderr'] = ''
        elif key == 'wrong-syntax-exit': changed['syntax']['exit'] = 1
        elif key == 'wrong-parser-output': changed['syntax']['stderr'] = 'dnsmasq: wrong error\n'
        elif key == 'startup-failure': changed['startup']['ready'] = False
        elif key == 'runtime-change': changed['rows'][0]['response'] = {'flags': 3}
        elif key == 'leaked-process': changed['cleanup']['live_pids'] = [123]
        elif key == 'leaked-pid': changed['cleanup']['pid_file'] = True
        assert compare(base, changed, case), key
        controls[key] = 'detected'
    rejected_case = {'probes': [], 'expected_test_exit': 1}
    rejected = {'syntax': {'exit': 1, 'stdout': '', 'stderr': '\ndnsmasq: error at line 1 of /m2/matrix.conf\n'},
                'startup': {'ready': False, 'exit': 1, 'stdout': '', 'stderr': '\ndnsmasq: error at line 1 of /m2/matrix.conf\n'},
                'cleanup': {'live_pids': [], 'pid_file': False}, 'exit': 1, 'rows': []}
    assert not compare(rejected, copy.deepcopy(rejected), rejected_case)
    changed = copy.deepcopy(rejected)
    changed['syntax']['stderr'] = '\ndnsmasq: wrong error at line 1 of /m2/matrix.conf\n'
    assert compare(rejected, changed, rejected_case)
    controls['same-rejection-code-wrong-error'] = 'detected'
    try:
        verify_identity('unexpected', STOCK_SHA256)
    except AssertionError:
        controls['wrong-running-identity'] = 'detected'
    else:
        raise AssertionError('identity calibration failed')
    causal_case = {'strict_upstream_wire': True, 'probes': [{'id': 'required', 'c_expect': {'rcode': 0, 'upstream_count': 1, 'answer_addresses': ['8.8.8.8']}}]}
    causal = copy.deepcopy(base)
    for row in causal['rows']:
        row['question_wire'] = '01610000010001'
        row['response'] = {'flags': 0x8180, 'records': [{'section': 'answer', 'type': 1, 'data': '8.8.8.8', 'ttl': 120}]}
        row['upstream'] = [{'wire': '0001abcd', 'reply_wire': '00010102'}]
    assert not compare(causal, copy.deepcopy(causal), causal_case)
    changed = copy.deepcopy(causal); changed['rows'][0]['upstream'][0]['wire'] = 'ffffabcd'
    assert not compare(causal, changed, causal_case), 'only random upstream transaction ID is ignored'
    for label in ['address', 'rcode', 'ttl', 'question-case', 'cache-causality', 'upstream-wire']:
        changed = copy.deepcopy(causal)
        row = changed['rows'][0]
        if label == 'address': row['response']['records'][0]['data'] = '8.8.4.4'
        elif label == 'rcode': row['response']['flags'] |= 3
        elif label == 'ttl': row['response']['records'][0]['ttl'] = 119
        elif label == 'question-case': row['question_wire'] = '01410000010001'
        elif label == 'cache-causality': row['upstream'].clear()
        elif label == 'upstream-wire': row['upstream'][0]['wire'] = '0001abcc'
        assert compare(causal, changed, causal_case), label
        controls['policy-' + label] = 'detected'
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit', required=False)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--manifest', type=Path, default=Path(__file__).with_suffix('.json'))
    parser.add_argument('--scenarios', help='comma-separated targeted subset; incomplete options remain open')
    parser.add_argument('--options', help='comma-separated subset; incomplete option coverage cannot close')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--reference-only', action='store_true', help='C baseline only; never qualifies an option')
    args = parser.parse_args()
    controls = {**self_test(), **probes_extra.controls()}
    if args.self_test:
        print(json.dumps(controls, sort_keys=True))
        return 0
    if not all([args.image_root, args.rust, args.output, args.rust_sha256, args.source_commit]):
        parser.error('--image-root --rust --rust-sha256 --source-commit --output required')
    if sha256(args.rust) != args.rust_sha256:
        raise ValueError('candidate SHA-256 mismatch')
    output = args.output.resolve()
    if 'private' not in output.parts or output.exists():
        raise ValueError('fresh private evidence path required')
    output.mkdir(parents=True)
    manifest = json.loads(args.manifest.read_text())
    if manifest.get('executable') is False:
        raise ValueError('source checklist is not executable yet')
    selected = args.options.split(',') if args.options else list(manifest['options'])
    if set(selected) - set(manifest['options']):
        raise ValueError('unknown selected option')
    scenarios = [s for s in manifest['scenarios'] if set(s['options']) & set(selected)]
    if args.scenarios:
        ids = args.scenarios.split(',')
        if set(ids) - {scenario['id'] for scenario in scenarios}:
            raise ValueError('unknown scenario or not part of selected options')
        scenarios = [scenario for scenario in scenarios if scenario['id'] in ids]
    dependencies = ['m2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh', 'm5_option_matrix_probes.py']
    if any(scenario.get('adapter') == 'dhcp' for scenario in scenarios):
        import m5_option_matrix_dhcp
        dependencies.extend(m5_option_matrix_dhcp.DEPENDENCIES)
        controls.update(m5_option_matrix_dhcp.controls())
    report = {'stock_sha256': STOCK_SHA256, 'rust_sha256': args.rust_sha256, 'source_commit': args.source_commit,
              'manifest_sha256': sha256(args.manifest), 'tool_sha256': sha256(Path(__file__)),
              'dependency_sha256': {filename: sha256(Path(__file__).with_name(filename)) for filename in dependencies},
              'normalization': ['executable stderr/stdout prefix dnsmasq-rs: -> dnsmasq:',
                                'upstream transaction ID removed; name/type/class/transport/count exact',
                                'casing: random bit patterns retained raw; compare allowed positions, enabled activity and exact client question bytes',
                                'local-service: connect/receive stage and errno, including TCP reset versus EOF, compare exactly; queued-byte timing proof retained',
                                'retry: raw clocks retained; exponential intervals checked within -12/+90ms; compare per-server traces to avoid receiver-thread scheduling order',
                                'DHCP: every reply byte except validated renewal T1/T2 fuzz and validated leasequery aging compares exactly; lease-file expiry is independently bounded to600s and lease order sorted; raw lease files retained',
                                'DHCP L2: destination MAC, IP source/destination and UDP ports exact; independent namespace source MAC and kernel IP ID/checksum retained in raw frames'],
              'strict_upstream_wire_scenarios': [scenario['id'] for scenario in scenarios if scenario.get('strict_upstream_wire')],
              'negative_controls': controls, 'reference_timings': manifest.get('reference_timing'), 'scenarios': [], 'options': {}, 'failures': []}
    frozen = output / 'driver'
    frozen.mkdir()
    for filename in [Path(__file__).name, *dependencies]:
        (frozen / filename).write_bytes(Path(__file__).with_name(filename).read_bytes())
    (frozen / args.manifest.name).write_bytes(args.manifest.read_bytes())
    dump(output / 'manifest.json', manifest)
    sides = ('c',) if args.reference_only else ('c', 'rust')
    report['reference_only'] = args.reference_only
    roots = {side: prepare(args.image_root, None, output / side, args.rust) for side in sides}
    for scenario in scenarios:
        folder = output / scenario['id']
        folder.mkdir()
        row = {'id': scenario['id'], 'options': scenario['options'], 'failures': []}
        try:
            observed = {side: run_side(roots[side], side, scenario, folder / side) for side in sides}
            if args.reference_only and scenario.get('reference_defect'):
                row['failures'] = m5_option_matrix_dhcp.reference_baseline(observed['c'])
            else:
                row['failures'] = compare(observed['c'], observed.get('rust', copy.deepcopy(observed['c'])), scenario)
            if scenario.get('reference_defect'):
                row['reference_difference'] = scenario['reference_defect']
            row['rows'] = len(observed['c']['rows'])
            row['syntax_rows'] = 1
        except Exception as error:
            row['failures'].append({'phase': 'infrastructure', 'error': repr(error)})
        report['scenarios'].append(row)
        dump(output / 'progress.json', report)
    for option in selected:
        required = manifest['options'][option]['scenarios']
        completed = {s['id']: s for s in report['scenarios'] if s['id'] in required}
        missing = sorted(set(required) - completed.keys())
        failed = [key for key, row in completed.items() if row['failures']]
        report['options'][option] = {'closed': not args.reference_only and manifest.get('qualification_ready', True) and not missing and not failed and manifest['options'][option].get('eligible_for_closure', True),
                                      'known_gaps': manifest['options'][option].get('known_gaps', []),
                                      'missing_scenarios': missing, 'failed_scenarios': failed,
                                      'checklist': [dict(boundary, checked=not args.reference_only and manifest.get('qualification_ready', True) and all(key in completed and not completed[key]['failures'] for key in boundary['required_scenarios'])) for boundary in manifest['options'][option]['checklist']]}
    report['failures'] = [dict(scenario=s['id'], **failure) for s in report['scenarios'] for failure in s['failures']]
    dump(output / 'result.json', report)
    print(json.dumps({'scenarios': len(scenarios), 'rows': sum(s.get('rows', 0) for s in report['scenarios']),
                      'closed': [k for k, v in report['options'].items() if v['closed']],
                      'failures': len(report['failures'])}, sort_keys=True))
    return int(bool(report['failures']) or (not args.reference_only and not all(v['closed'] for v in report['options'].values())))


if __name__ == '__main__':
    raise SystemExit(main())
