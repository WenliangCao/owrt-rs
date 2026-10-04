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
    packet = struct.pack('!6H', ident, 0x100, 1, 0, 0, int(probe.get('edns', False)))
    packet += encoded + struct.pack('!HH', probe.get('type', 1), probe.get('class', 1))
    if probe.get('edns'):
        packet += rr(41, b'', b'\0', 0, 1232)
    return packet


class Upstream:
    """Packet fixtures are input stimuli, never expected daemon responses."""
    def __init__(self, probes):
        self.probes = {(p['name'].lower(), p.get('type', 1)): p for p in probes}
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.2', 0))
        self.port = self.udp.getsockname()[1]
        self.udp.settimeout(.05)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(('127.0.0.2', self.port))
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
        value = probe.get('reply', '192.0.2.10' if kind == 1 else '2001:db8::10')
        record_kind = kind
        if kind == 12:
            data = name('upstream.matrix.test')
        elif kind in (1, 28):
            data = ipaddress.ip_address(value).packed
        elif kind == 16:
            data = b'\x06matrix'
        else:
            data = b'\x01x'
        owner = b'\xc0\x0c'
        records = []
        if probe.get('cname'):
            owner = name('target.matrix.test')
            records.append(rr(5, owner))
        records.append(rr(record_kind, data, owner, cls=cls))
        section_count = [len(records), 0, 0]
        if probe.get('sections') and kind == 1:
            records.extend([rr(1, data, name('ns.matrix.test')), rr(1, data, name('extra.matrix.test'))])
            section_count = [1, 1, 1]
        flags = 0x8580 | probe.get('rcode', 0) | (0x200 if probe.get('tc') else 0)
        return packet[:2] + struct.pack('!5H', flags, 1, *section_count) + packet[12:end + 4] + b''.join(records)

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                response = self.answer(packet, 'udp')
                host, end = read_name(packet, 12)
                probe = self.probes.get((host, struct.unpack_from('!H', packet, end)[0]), {})
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
    packet = query(probe, ident)
    before = len(upstream.events)
    started = time.monotonic()
    response = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM) as client:
        client.settimeout(.5)
        client.connect(('127.0.0.1', port))
        client.sendall(packet if transport == 'udp' else struct.pack('!H', len(packet)) + packet)
        try:
            response = client.recv(65535) if transport == 'udp' else exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        except socket.timeout:
            pass
    result = semantics(response) if response is not None else None
    if result is not None and result['id'] != ident:
        raise AssertionError('wrong client transaction ID')
    return {'id': probe['id'] + ':' + transport, 'response': result,
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
    folder.mkdir()
    topology = probes_extra.LocalTopology() if scenario.get('adapter') == 'local-service' else None
    upstream = Upstream(scenario['probes'])
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    conf = ('no-resolv\nno-hosts\nno-round-robin\nuser=root\ngroup=root\n'
            + ('' if scenario.get('adapter') == 'casing' else 'no-0x20-encode\n')
            + ('' if scenario.get('listen_addresses') == [] else 'listen-address=' + ','.join(scenario.get('listen_addresses', ['127.0.0.1'])) + '\n')
            + f'port={port}\ncache-size={scenario.get("cache_size", 0)}\nlocal-ttl=120\n'
            f'server=127.0.0.2#{upstream.port}\npid-file=/m2/matrix.pid\n'
            'addn-hosts=/m2/matrix.hosts\n' + scenario['config'].replace('{upstream}', str(upstream.port)))
    (root / 'm2/matrix.conf').write_text(conf)
    (root / 'm2/matrix.hosts').write_text(scenario.get('hosts', ''))
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
                verify_identity(result['identity']['sha256'], sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs')))
                for index, probe in enumerate(scenario['probes']):
                    for transport in probe.get('transports', ['udp', 'tcp']):
                        observer = {'casing': probes_extra.observe_casing, 'capacity': probes_extra.observe_capacity}.get(scenario.get('adapter'), observe)
                        if topology:
                            result['rows'].append(probes_extra.observe_local_service(port, probe, 0x4100 + index * 4, transport, topology))
                        else:
                            result['rows'].append(observer(port, probe, 0x4100 + index * 4, transport, upstream))
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
    if expected['syntax']['exit'] != expected_exit or expected['startup']['ready'] != (expected_exit == 0):
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
    if scenario.get('adapter') == 'local-service':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'admission-guard', 'side': side, **failure} for failure in probes_extra.local_service_guards(observed['rows'], scenario))
    if scenario.get('adapter') == 'capacity':
        for side, observed in [('c', expected), ('rust', actual)]:
            failures.extend({'phase': 'capacity-guard', 'side': side, **failure} for failure in probes_extra.capacity_guards(observed['rows'], scenario))
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
                event.pop('wire')  # randomized upstream ID/source port are not behavior
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
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit', required=False)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--manifest', type=Path, default=Path(__file__).with_suffix('.json'))
    parser.add_argument('--options', help='comma-separated subset; incomplete option coverage cannot close')
    parser.add_argument('--self-test', action='store_true')
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
    selected = args.options.split(',') if args.options else list(manifest['options'])
    if set(selected) - set(manifest['options']):
        raise ValueError('unknown selected option')
    scenarios = [s for s in manifest['scenarios'] if set(s['options']) & set(selected)]
    report = {'stock_sha256': STOCK_SHA256, 'rust_sha256': args.rust_sha256, 'source_commit': args.source_commit,
              'manifest_sha256': sha256(args.manifest), 'tool_sha256': sha256(Path(__file__)),
              'dependency_sha256': {filename: sha256(Path(__file__).with_name(filename)) for filename in ['m2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh', 'm5_option_matrix_probes.py']},
              'normalization': ['executable stderr/stdout prefix dnsmasq-rs: -> dnsmasq:',
                                'upstream transaction ID removed; name/type/class/transport/count exact'],
              'negative_controls': controls, 'scenarios': [], 'options': {}, 'failures': []}
    dump(output / 'manifest.json', manifest)
    roots = {side: prepare(args.image_root, None, output / side, args.rust) for side in ('c', 'rust')}
    for scenario in scenarios:
        folder = output / scenario['id']
        folder.mkdir()
        row = {'id': scenario['id'], 'options': scenario['options'], 'failures': []}
        try:
            observed = {side: run_side(roots[side], side, scenario, folder / side) for side in ('c', 'rust')}
            row['failures'] = compare(observed['c'], observed['rust'], scenario)
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
        report['options'][option] = {'closed': not missing and not failed,
                                      'missing_scenarios': missing, 'failed_scenarios': failed,
                                      'checklist': [dict(boundary, checked=all(key in completed and not completed[key]['failures'] for key in boundary['required_scenarios'])) for boundary in manifest['options'][option]['checklist']]}
    report['failures'] = [dict(scenario=s['id'], **failure) for s in report['scenarios'] for failure in s['failures']]
    dump(output / 'result.json', report)
    print(json.dumps({'scenarios': len(scenarios), 'rows': sum(s.get('rows', 0) for s in report['scenarios']),
                      'closed': [k for k, v in report['options'].items() if v['closed']],
                      'failures': len(report['failures'])}, sort_keys=True))
    return int(bool(report['failures']) or not all(v['closed'] for v in report['options'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
