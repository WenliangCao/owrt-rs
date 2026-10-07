#!/usr/bin/env python3
"""Small exact-image HUP plus queued UDP/TCP caller gate; run in run_isolated.sh."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import time

import m5_dns_files as family


def pending_hup(status):
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    return any(int(fields.get(key, '0').strip(), 16) & 1 for key in ('SigPnd', 'ShdPnd'))


def queued_socket(table, inodes, port, transport):
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or int(fields[1].split(':')[1], 16) != port:
            continue
        if fields[9] not in inodes or (transport == 'tcp' and fields[3] != '0A'):
            continue
        if int(fields[4].split(':')[1], 16) > 0:
            return {'inode': fields[9], 'local': fields[1], 'state': fields[3],
                    'tx_rx_queue': fields[4], 'raw': line}
    return None


def owned_queue(pid, port, transport):
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    return queued_socket(Path(f'/proc/{pid}/net/{transport}').read_text(), inodes, port, transport)


def same_wake_exchange(root, side, original, port, action, ident, transport, upstreams, connections):
    if not action.get('same_wake'):
        return original(port, action, ident, transport, upstreams, connections)
    pid = int((root / 'm2/files.pid').read_text())
    expected = family.sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))
    if family.process_identity(root, pid)['sha256'] != expected:
        raise AssertionError('same-wake owner identity mismatch')
    packet = family.query(action, ident)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM)
    started, paused, response, error = time.monotonic(), False, None, None
    proof = {}
    try:
        os.kill(pid, signal.SIGSTOP)
        paused = True
        family.await_predicate(lambda: '\nState:\tT' in Path(f'/proc/{pid}/status').read_text(),
                               'same-wake owner did not stop')
        family.put(root, action['reload_path'], action['reload_text'], {})
        os.kill(pid, signal.SIGHUP)
        client.settimeout(1)
        client.connect(('127.0.0.1', port))
        client.sendall(packet if transport == 'udp' else struct.pack('!H', len(packet)) + packet)
        proof['queued_socket'] = family.await_predicate(lambda: owned_queue(pid, port, transport),
                                                       'request was not queued on owned listener')
        status = Path(f'/proc/{pid}/status').read_text()
        if '\nState:\tT' not in status or not pending_hup(status):
            raise AssertionError('owner must remain stopped with HUP pending before resume')
        proof.update(owner_pid=pid, transport=transport, hup_pending=True, stopped_status=status,
                     snapshot_rule='TCP connection is queued but not accepted before SIGCONT')
        os.kill(pid, signal.SIGCONT)
        paused = False
        try:
            response = client.recv(65535) if transport == 'udp' else family.exact_read(
                client, struct.unpack('!H', family.exact_read(client, 2))[0])
        except (OSError, EOFError) as problem:
            error = {'kind': type(problem).__name__, 'errno': getattr(problem, 'errno', None)}
    finally:
        if paused:
            os.kill(pid, signal.SIGCONT)
        client.close()
    parsed = family.semantics(response) if response else None
    if parsed and parsed['id'] != ident:
        raise AssertionError('same-wake reply transaction identity mismatch')
    return {'id': action['id'] + ':' + transport, 'response': parsed, 'error': error,
            'request': packet.hex(), 'reply': response.hex() if response else None,
            'elapsed': time.monotonic() - started, 'cache': False, 'upstreams': [],
            'same_wake_proof': proof}


def projection(row):
    parsed = row.get('response')
    return {'rcode': parsed['flags'] & 15 if parsed else None,
            'qr': bool(parsed['flags'] & 0x8000) if parsed else False,
            'questions': parsed['questions'] if parsed else [],
            'addresses': [record['data'] for record in parsed['records'] if record['type'] == 1]
                         if parsed else [], 'error': row.get('error')}


def scenarios():
    definitions = [
        ('hosts', {'hosts': '192.0.2.42 samewake.files.test\n'}, False,
         'no-resolv\nbind-interfaces\naddn-hosts=/m2/files/hosts\n', 42, 43,
         'hosts', '192.0.2.43 samewake.files.test\n'),
        ('resolv', {'resolv': 'nameserver 127.0.0.2\n'}, True,
         'bind-interfaces\nno-poll\n', 11, 12,
         'resolv', 'nameserver 127.0.0.3\n'),
        ('servers', {'servers': 'server=/samewake.files.test/127.0.0.2\n'}, False,
         'no-resolv\nbind-interfaces\nservers-file=/m2/files/servers\n', 11, 12,
         'servers', 'server=/samewake.files.test/127.0.0.3\n'),
    ]
    result = []
    for source, files, default_resolv, config, old, new, path, text in definitions:
        for transport in ('udp', 'tcp'):
            ident = 'same-wake-' + ('' if source == 'hosts' else source + '-') + transport
            result.append({'id': ident, 'source': source, 'checks': ['EVENT_RELOAD before DNS dispatch'],
                'files': files, 'default_resolv': default_resolv, 'cache_size': 0, 'config': config,
                'expected_addresses': [old, new, new],
                'actions': [family.probe('before', 'samewake.files.test', transports=['udp']),
                            family.probe('same-wake', 'samewake.files.test', transports=[transport],
                                         same_wake=True, reload_path=path, reload_text=text),
                            family.probe('after', 'samewake.files.test', transports=['udp'])]})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        table = 'header\n0: 0100007F:3BF9 00000000:0000 0A 00000000:00000001 00:0 0000 0 0 42\n'
        assert queued_socket(table, {'42'}, 15353, 'tcp')
        assert queued_socket(table, {'43'}, 15353, 'tcp') is None
        assert queued_socket(table.replace('00000001', '00000000'), {'42'}, 15353, 'tcp') is None
        assert queued_socket(table.replace(' 0A ', ' 01 '), {'42'}, 15353, 'tcp') is None
        assert pending_hup('SigPnd:\t0000000000000001\nShdPnd:\t0\n')
        assert not pending_hup('SigPnd:\t0000000000000002\nShdPnd:\t0\n')
        assert projection({'response': {'flags': 0x8000, 'questions': [], 'records': []}})['qr']
        cases = scenarios()
        assert len(cases) == 6 and len({case['id'] for case in cases}) == 6
        assert all(case['actions'][1]['reload_path'] in case['files'] for case in cases)
        print(json.dumps({'ownership_queue_signal_response_and_scenario_controls': 9, 'scenarios': 6, 'passed': True}))
        return 0
    if not all((args.image_root, args.rust, args.rust_sha256, args.source_commit, args.output)):
        parser.error('image, candidate identity, source and output required')
    if args.output.exists() or 'private' not in args.output.resolve().parts:
        parser.error('fresh private output required')
    if family.sha256(args.rust) != args.rust_sha256:
        raise ValueError('candidate ELF SHA mismatch')
    args.output.mkdir(parents=True)
    report = {'scope': 'functional same-wake HUP caller; no performance qualification',
              'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'stock_sha256': family.STOCK_SHA256, 'driver_sha256': family.sha256(Path(__file__)),
              'family_sha256': family.sha256(Path(family.__file__)), 'cases': [], 'failures': []}
    original = family.exchange
    roots = {side: family.prepare(args.image_root, None, args.output / side, args.rust)
             for side in ('c', 'rust')}
    family.dump(args.output / 'result.json', report)
    try:
        for case in scenarios():
            folder = args.output / case['id']; folder.mkdir()
            observed = {}
            for side, root in roots.items():
                family.exchange = lambda *values, root=root, side=side: same_wake_exchange(root, side, original, *values)
                observed[side] = family.run_side(root, side, case, folder / side)
            row = {'id': case['id'], 'observed': observed, 'failures': []}
            for side in ('c', 'rust'):
                value = observed[side]
                if not value.get('startup', {}).get('ready') or value.get('forced_kill') or value['exit'] != 0:
                    row['failures'].append({'phase': 'startup/exit', 'side': side})
                if value.get('cleanup', {}).get('live_pids') or value.get('cleanup', {}).get('pid_file'):
                    row['failures'].append({'phase': 'cleanup', 'side': side})
                if len(value['rows']) != 3:
                    row['failures'].append({'phase': 'missing-rows', 'side': side, 'rows': len(value['rows'])})
                expected = case['expected_addresses']
                for answer, last in zip(value['rows'], expected):
                    actual = projection(answer)
                    wanted = {'rcode': 0, 'qr': True, 'questions': [['samewake.files.test', 1, 1]],
                              'addresses': [f'192.0.2.{last}'], 'error': None}
                    if actual != wanted:
                        row['failures'].append({'phase': 'answer', 'side': side, 'id': answer['id'],
                                                'expected': wanted, 'actual': actual})
            for left, right in zip(observed['c']['rows'], observed['rust']['rows']):
                if left['response'] != right['response'] or left['error'] != right['error']:
                    row['failures'].append({'phase': 'full-response-pair', 'id': left['id'],
                                            'c': left['response'], 'rust': right['response']})
            report['cases'].append(row)
            report['failures'].extend(row['failures'])
            family.dump(args.output / 'result.json', report)
    except Exception as error:
        report['failures'].append({'phase': 'fixture', 'error': repr(error)})
        report['passed'] = False
        family.dump(args.output / 'result.json', report)
        raise
    finally:
        family.exchange = original
    report['passed'] = len(report['cases']) == len(scenarios()) and not report['failures']
    family.dump(args.output / 'result.json', report)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
