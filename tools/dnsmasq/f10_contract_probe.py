#!/usr/bin/env python3
"""Finite exact-image F10 order/PTR/source-transition contract probe.

Run under run_isolated.sh. C is the reference; baseline Rust differences are
recorded, and --require-match makes those differences fail candidate acceptance.
This intentionally does not repeat the large rolling or memory-budget gates.
"""
import argparse
import collections
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time

from audit_20261011_dhcp import decode, packet
from dns_service_probe import exact_read, query, semantics
from f10_contract_check import check as check_contract
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, process_identity, sha256


ADDRESS = ('127.0.0.1', 15353)
SIX = ('192.0.2.2 old.test\n192.0.2.1 x.test\n'
       '192.0.3.186 a.test\n192.0.3.185 a.test\n'
       '192.0.2.1 y.test\n192.0.2.2 y.test\n')
FIRST, TAIL = SIX.rsplit('192.0.2.1 y.test\n', 1)
TAIL = '192.0.2.1 y.test\n' + TAIL
V6 = ('2001:db8::2 old6.test\n2001:db8::1 x6.test\n'
      '2001:db8:1::186 a6.test\n2001:db8:1::185 a6.test\n'
      '2001:db8::1 y6.test\n2001:db8::2 y6.test\n'
      '2001:db8::3 y6.test\n2001:db8::2 y6.test\n')
THREE = ('192.0.2.11 tri.test alias.test\n192.0.2.12 tri.test\n'
         '192.0.2.13 tri.test\n192.0.2.12 tri.test\n')
V6_COLLISION = ('2001:db8::2 old6.test\n2001:db8::1 x6.test\n'
                '2001:db8::bc a6.test\n2001:db8::bb a6.test\n'
                '2001:db8::1 y6.test\n2001:db8::2 y6.test\n')
LONG_X = '.'.join(('x' * 63, 'p' * 63, 'q' * 63, 'r' * 60))
LONG_Y = '.'.join(('y' * 63, 's' * 63, 't' * 63, 'u' * 60))
CASES = ('six-addn', 'six-default', 'six-host-record', 'six-hostsdir-initial',
         'split-addn-bulk', 'ipv6-three-duplicate', 'no-round-robin',
         'mixed-sources', 'hostsdir-transitions', 'leases-dhcp', 'udp-truncation',
         'ipv6-repeated-ptr', 'ptr-truncation')


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def exchange(name, kind=1, client=None):
    request = query(name, kind, 0x3412)
    if client is None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(2)
            endpoint.sendto(request, ADDRESS)
            reply = endpoint.recv(65535)
    else:
        client.sendall(struct.pack('!H', len(request)) + request)
        reply = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
    parsed = semantics(reply)
    assert parsed['id'] == 0x3412 and parsed['questions'] == [[name, kind, 1]]
    return {'request_wire': request.hex(), 'response_wire': reply.hex(),
            'semantics': parsed, 'response_bytes': len(reply),
            'truncated': bool(parsed['flags'] & 0x200), 'rcode': parsed['flags'] & 15,
            'answer_order': [rr['data'] for rr in parsed['records'] if rr['section'] == 'answer']}


def connect():
    client = socket.create_connection(ADDRESS, 2)
    client.settimeout(2)
    # Materialize the TCP child's snapshot without touching the tested names.
    assert exchange('ready.test', client=client)['answer_order'] == ['192.0.2.41']
    return client


def wait_answer(process, name, expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        assert process.poll() is None, 'service exited before marker'
        try:
            if exchange(name)['answer_order'] == expected:
                return
        except (OSError, ConnectionError):
            pass
        time.sleep(.02)
    raise TimeoutError(f'marker {name}: expected {expected}')


def configure(root, case):
    data = root / 'm2' / case
    data.mkdir()
    folder = data / 'hostsdir'
    folder.mkdir()
    default = image_path(root, 'etc/hosts')
    default.write_text('')
    files = {}
    options = ['--no-hosts']

    def put(name, value):
        path = data / name
        path.write_text(value)
        files[str(path.relative_to(root))] = value
        return '/' + str(path.relative_to(root))

    def addn(name, value):
        options.append('--addn-hosts=' + put(name, value))

    if case == 'six-default':
        options = []
        default.write_text(SIX)
        files['etc/hosts'] = SIX
    elif case == 'six-host-record':
        options += ['--host-record=' + ','.join(line.split()[1:] + line.split()[:1])
                    for line in SIX.splitlines()]
    elif case == 'split-addn-bulk':
        addn('first', FIRST)
        addn('tail', TAIL)
    elif case in ('six-hostsdir-initial', 'hostsdir-transitions'):
        put('hostsdir/first', SIX if case.endswith('initial') else FIRST)
        options.append('--hostsdir=/' + str(folder.relative_to(root)))
    elif case == 'mixed-sources':
        options = ['--host-record=x.test,192.0.2.1']
        default.write_text('192.0.2.2 old.test\n')
        files['etc/hosts'] = default.read_text()
        addn('addn', '192.0.3.186 a.test\n192.0.3.185 a.test\n')
        put('hostsdir/tail', TAIL)
        options.append('--hostsdir=/' + str(folder.relative_to(root)))
    elif case in ('ipv6-three-duplicate', 'no-round-robin'):
        addn('hosts', SIX + V6 + THREE)
        if case == 'no-round-robin':
            options.append('--no-round-robin')
    elif case == 'udp-truncation':
        addn('hosts', ''.join(f'192.0.2.{i} wide.test\n' for i in range(1, 49)))
    elif case == 'ptr-truncation':
        addn('hosts', SIX.replace('x.test', LONG_X).replace('y.test', LONG_Y))
    elif case == 'ipv6-repeated-ptr':
        addn('hosts', V6_COLLISION)
    else:
        addn('hosts', SIX)
    if case == 'leases-dhcp':
        put('leases', '0 02:00:00:00:00:02 127.0.0.31 restored *\n')
        options += ['--no-ping', '--dhcp-authoritative', '--domain=test', '--dhcp-ttl=37',
                    '--dhcp-range=127.0.0.30,127.0.0.31,255.0.0.0,1h',
                    '--dhcp-host=02:00:00:00:00:01,127.0.0.30,lease',
                    '--dhcp-leasefile=/' + str((data / 'leases').relative_to(root))]
    return data, options, files


def run_case(root, args, case):
    out = args.output / case
    out.mkdir()
    data, options, files = configure(root, case)
    config = ['-k', '--conf-file=', '--no-resolv', '--user=root', '--group=root',
              '--listen-address=127.0.0.1', '--bind-interfaces', '--port=15353',
              '--pid-file=/m2/pid', '--host-record=ready.test,192.0.2.41',
              '--cache-size=1000', '--edns-packet-max=1232', '--local-ttl=37',
              '--log-queries', '--log-facility=/' + str((data / 'daemon.log').relative_to(root)),
              *options]
    argv = command(root, args.implementation, *config)
    row = {'case': case, 'argv': argv, 'initial_files': files,
           'observations': [], 'mutations': [], 'completed': False}
    write(out / 'result.json', row)
    held = None
    with (out / 'stderr.log').open('wb') as log:
        process = subprocess.Popen(argv, stdout=log, stderr=log, start_new_session=True)
        try:
            wait_answer(process, 'ready.test', ['192.0.2.41'])
            identity = process_identity(root, process.pid)
            assert identity['sha256'] == args.expected_sha256
            write(out / 'process-identity.json', identity)
            row['process_sha256'] = identity['sha256']

            def observe(label, name, kind=1, client=None):
                row['observations'].append({'label': label, 'transport': 'tcp' if client else 'udp',
                    'name': name, 'type': kind, **exchange(name, kind, client)})
                write(out / 'result.json', row)

            def cycle(label, client=None, name='y.test', kind=1, addresses=('192.0.2.1', '192.0.2.2')):
                # Preserve the original six-line counterexample's PTR/A order.
                for phase in ('before', 'after'):
                    if phase == 'after':
                        for index in range(6):
                            observe(f'{label}-forward-{index}', name, kind, client)
                    for address in addresses:
                        for index in range(2):
                            observe(f'{label}-ptr-{phase}-{address}-{index}',
                                    ipaddress.ip_address(address).reverse_pointer, 12, client)

            def snapshots(phase):
                for label, client in ((phase + '-udp', None), (phase + '-old', held)):
                    cycle(label, client)
                with connect() as new:
                    cycle(phase + '-new', new)

            if case == 'hostsdir-transitions':
                held = connect()
                snapshots('initial')
                target = data / 'hostsdir/tail'
                for phase, content, marker, expected in (
                    ('create', TAIL + '192.0.2.60 generation1.test\n', 'generation1.test', ['192.0.2.60']),
                    ('replace', '192.0.2.3 y.test\n192.0.2.4 y.test\n192.0.2.61 generation2.test\n',
                     'generation2.test', ['192.0.2.61']),
                    ('delete', None, 'generation2.test', []),
                    ('recreate', TAIL + '192.0.2.62 generation3.test\n',
                     'generation3.test', ['192.0.2.62'])):
                    if content is None:
                        target.unlink()
                    else:
                        replacement = data / 'replacement'
                        replacement.write_text(content)
                        replacement.replace(target)
                    row['mutations'].append({'phase': phase, 'content': content, 'signal': None})
                    wait_answer(process, marker, expected)
                    snapshots(phase)
                # Reload the same six rows after the incremental insertion path.
                # With no file change, a bounded small-fixture settle precedes
                # the independent UDP/new/held snapshot observations.
                process.send_signal(signal.SIGHUP)
                time.sleep(.25)
                row['mutations'].append({'phase': 'hup', 'content': None,
                                         'signal': 'SIGHUP', 'settle_seconds': .25})
                snapshots('hup')
            elif case in ('udp-truncation', 'ptr-truncation'):
                name, kind, count = (('wide.test', 1, 48) if case == 'udp-truncation'
                                     else ('1.2.0.192.in-addr.arpa', 12, 2))
                held = connect()
                observe('udp-truncated-1', name, kind)
                observe('held-tcp-after-udp', name, kind, held)
                with connect() as new:
                    observe('new-tcp-after-udp', name, kind, new)
                observe('udp-truncated-2', name, kind)
                observe('held-tcp-again', name, kind, held)
                row['truncation_checks'] = {
                    'udp_tc': all(r['truncated'] for r in row['observations'] if r['transport'] == 'udp'),
                    'tcp_complete': all(not r['truncated'] and len(r['answer_order']) == count
                                        for r in row['observations'] if r['transport'] == 'tcp')}
                if case == 'ptr-truncation':
                    row['truncation_checks']['udp_whole_rrset_omitted'] = all(
                        not r['answer_order'] for r in row['observations'] if r['transport'] == 'udp')
                if args.implementation == 'c':
                    assert all(row['truncation_checks'].values()), row['truncation_checks']
            elif case == 'ipv6-repeated-ptr':
                cycle('udp-v6', name='y6.test', kind=28, addresses=('2001:db8::1', '2001:db8::2'))
                with connect() as client:
                    cycle('tcp-v6', client, 'y6.test', 28, ('2001:db8::1', '2001:db8::2'))
            else:
                cycle('udp')
                with connect() as client:
                    cycle('tcp', client)
                if case in ('ipv6-three-duplicate', 'no-round-robin'):
                    for name, kind, addresses in (
                        ('tri.test', 1, ('192.0.2.11', '192.0.2.12', '192.0.2.13')),
                        ('y6.test', 28, ('2001:db8::1', '2001:db8::2', '2001:db8::3'))):
                        cycle('udp-' + name, name=name, kind=kind, addresses=addresses)
                        with connect() as client:
                            cycle('tcp-' + name, client, name, kind, addresses)
                if case == 'leases-dhcp':
                    for name, address in (('restored.test', '127.0.0.31'),):
                        observe('restored-lease-a', name)
                        observe('restored-lease-ptr', ipaddress.ip_address(address).reverse_pointer, 12)
                    request = packet(3, 0x74131001, name='lease')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
                        client.bind(('0.0.0.0', 68))
                        client.settimeout(2)
                        client.sendto(request, ('255.255.255.255', 67))
                        reply = client.recv(4096)
                    row['dhcp'] = {'request_wire': request.hex(), 'reply_wire': reply.hex(), 'decoded': decode(reply)}
                    assert row['dhcp']['decoded']['message_type'] == 5
                    wait_answer(process, 'lease.test', ['127.0.0.30'])
                    observe('live-lease-a', 'lease.test')
                    observe('live-lease-ptr', '30.0.0.127.in-addr.arpa', 12)
                    cycle('after-dhcp')
                    row['leases'] = (data / 'leases').read_text()
            row['ready_after'] = exchange('ready.test')['answer_order']
            assert row['ready_after'] == ['192.0.2.41']
            row['exit_before_cleanup'] = process.poll()
            assert row['exit_before_cleanup'] is None
            row['completed'] = True
        except Exception as error:
            row['error'] = repr(error)
        finally:
            if held is not None:
                held.close()
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                row['forced_cleanup'] = True
            row['exit'] = process.returncode
            if (data / 'daemon.log').exists():
                shutil.copy2(data / 'daemon.log', out / 'daemon.log')
            write(out / 'result.json', row)
    return row


def compare(reference, actual):
    differences = []
    references = {row['case']: row for row in reference['cases']}
    for after in actual['cases']:
        before = references[after['case']]
        expected, observed = before['observations'], after['observations']
        if len(expected) != len(observed):
            differences.append({'case': after['case'], 'kind': 'observation-count',
                                'c': len(expected), 'rust': len(observed)})
        for left, right in zip(expected, observed):
            assert left['label'] == right['label']
            if left['semantics'] != right['semantics']:
                # Preserve ordered records and raw wires. Sorting is used only
                # to classify a difference, never to replace either observation.
                c_set, actual_set = (dict(row['semantics']) for row in (left, right))
                for value in (c_set, actual_set):
                    value['records'] = sorted(json.dumps(rr, sort_keys=True) for rr in value['records'])
                kind = 'rrset-ttl-count-or-header'
                if c_set == actual_set:
                    kind = 'ptr-order-only' if left['type'] == 12 else 'forward-order-only'
                differences.append({'case': after['case'], 'label': right['label'],
                    'kind': kind, 'c': left['semantics'], 'rust': right['semantics']})
        if before.get('dhcp', {}).get('decoded') != after.get('dhcp', {}).get('decoded'):
            differences.append({'case': after['case'], 'kind': 'dhcp-decoded',
                'c': before.get('dhcp', {}).get('decoded'), 'rust': after.get('dhcp', {}).get('decoded')})
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--implementation', choices=('c', 'rust'), required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--require-match', action='store_true',
                        help='Require full ordered semantic equality, including PTR owner order.')
    parser.add_argument('--ptr-order-manifest', type=Path,
                        help='Explicit C/C evidence for exact PTR states and complete query sequences.')
    parser.add_argument('--require-contract', action='store_true',
                        help='Fail unqualified differences; PTR order is strict unless explicitly evidenced.')
    parser.add_argument('--case', action='append', choices=CASES,
                        help='Run only the named case; repeat to select several.')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    binary = args.image_root / 'usr/sbin/dnsmasq' if args.implementation == 'c' else args.rust
    assert sha256(binary) == args.expected_sha256
    assert not (args.require_match or args.require_contract or args.ptr_order_manifest) or args.reference
    args.output.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.output / 'stage', args.rust)
    selected = [case for case in CASES if not args.case or case in args.case]
    result = {'implementation': args.implementation, 'binary_sha256': args.expected_sha256,
              'driver_sha256': sha256(__file__), 'cases': [], 'case_count': len(selected)}
    for case in selected:
        result['cases'].append(run_case(root, args, case))
        write(args.output / 'result.json', result)
        print(case, result['cases'][-1]['completed'], result['cases'][-1].get('error'), flush=True)
    result['errors'] = [row['case'] for row in result['cases'] if not row['completed'] or row['exit'] != 0]
    if args.reference:
        reference = json.loads(args.reference.read_text())
        assert reference['binary_sha256'] == STOCK_SHA256 and not reference['errors']
        result['reference_sha256'] = sha256(args.reference)
        result['differences'] = compare(reference, result)
        result['matches_c'] = not result['differences'] and not result['errors']
        result['difference_counts'] = dict(collections.Counter(row['kind'] for row in result['differences']))
        manifest = json.loads(args.ptr_order_manifest.read_text()) if args.ptr_order_manifest else None
        result['contract_check'] = check_contract(reference, result, manifest, expected_cases=selected)
        if args.ptr_order_manifest:
            result['ptr_order_manifest_sha256'] = sha256(args.ptr_order_manifest)
    write(args.output / 'result.json', result)
    return int(bool(result['errors'] or (args.require_match and not result['matches_c'])
                    or (args.require_contract and not result['contract_check']['passed'])))


if __name__ == '__main__':
    raise SystemExit(main())
