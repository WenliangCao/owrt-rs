#!/usr/bin/env python3
"""Actual DHCP logging callers using the qualified PXE/relay/leasequery fixtures.

Run only through run_isolated.sh. Raw DHCP notices compare byte-for-byte after
PID removal; the existing family evaluators independently check wire, manifest,
service health and cleanup. Infinite restored leases avoid timer normalization
in the logging contract. Original packet observations and logs are retained.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import sys

import m5_leasequery as leasequery
import m5_pxe as pxe
import m5_relay as relay
from m2_rootfs import STOCK_SHA256, prepare, sha256
from test_single_poll_service import Network


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def modes(profile, field):
    rows = []
    for mode, switches in [('ordinary', []), ('quiet', ['quiet-dhcp']),
                           ('detail', ['log-dhcp']), ('quiet-detail', ['quiet-dhcp', 'log-dhcp'])]:
        row = copy.deepcopy(profile)
        row['name'] += '-' + mode
        row[field].extend((["log-facility=-"] if 'acl' not in row else []) + switches)
        rows.append(row)
    return rows


def pxe_profiles():
    available = {row['name']: row for row in pxe.profiles()}
    rows = []
    for name, indices in [('legacy-proxy', [0, 1, 2, 3]), ('boot-item', [0, 1, 5]),
                          ('ignored-proxy', [0])]:
        row = copy.deepcopy(available[name])
        row['cases'] = [row['cases'][index] for index in indices]
        row['options'].append('dhcp-reply-delay=0')
        rows.extend(modes(row, 'options'))
    for name in ['efi-proxy', 'pxe-options', 'proxy-option-overload',
                 'ordinary-option-overload', 'no-override-default', 'no-override-enabled',
                 'bootp-static', 'bootp-denied']:
        row = copy.deepcopy(available[name])
        row['options'].extend(['log-facility=-', 'log-dhcp'])
        row['name'] += '-detail'
        rows.append(row)
    template = copy.deepcopy(available['dynamic-pxe'])
    template['options'] = ['log-facility=-', 'log-dhcp']
    template['expect4011'] = False
    template['cases'] = [copy.deepcopy(template['cases'][0])]
    def packet_case(name, wire, reply=True):
        row = copy.deepcopy(template['cases'][0]);row.update(name=name, request=wire.hex(), reply=reply)
        return row
    request = lambda kind=1, extra=b'': pxe.request(kind=kind, arch=None, vendor=b'ordinary', extra=extra)
    for suffix, name in [('plain', b'Client.Logging'), ('encoded', b'\x06Client\x07Logging\0')]:
        row = copy.deepcopy(template);row['name'] = 'client-fqdn-' + suffix + '-detail'
        fqdn = bytes([4 if suffix == 'encoded' else 0, 0, 0]) + name
        row['cases'] = [packet_case('fqdn', request(extra=pxe.option(81, fqdn)))]
        rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'warning-leased-static-detail'
    row['initial_leases'] = '0 02:00:00:4d:35:99 10.77.0.10 occupant *\n'
    rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'warning-router-static-detail';row['static_host'] = False
    row['options'].append('dhcp-host=02:00:00:4d:35:03,10.77.0.1')
    rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'warning-declined-static-detail'
    fields = pxe.option(50, socket.inet_aton('10.77.0.10')) + pxe.option(54, socket.inet_aton(pxe.SERVER))
    row['cases'] = [packet_case('commit', request(3, fields)), packet_case('decline', request(4, fields), False),
                    packet_case('discover-after-decline', request())]
    rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'warning-no-range-detail'
    row['range_value'] = '192.0.2.10,192.0.2.20,255.255.255.0,600s'
    row['cases'][0]['reply'] = False
    rows.append(row)
    row = copy.deepcopy(available['legacy-proxy']);row['name'] = 'pxe-menu-too-large-detail'
    row['options'] = ['log-facility=-', 'log-dhcp', 'pxe-service=0,' + 'A' * 200 + ',first',
                      'pxe-service=0,' + 'B' * 200 + ',second']
    row['cases'] = row['cases'][:1];rows.append(row)
    enterprise = ['vi-encap:1234,1,' + 'a' * 240, 'vi-encap:1234,2,' + 'b' * 20]
    row = copy.deepcopy(available['legacy-proxy']);row['name'] = 'pxe-enterprise-overflow-detail'
    row['options'].extend(['log-facility=-', 'log-dhcp', *['dhcp-option-pxe=' + option for option in enterprise]])
    row['cases'] = row['cases'][:1];rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'ordinary-enterprise-overflow-detail'
    row['options'].extend('dhcp-option=' + option for option in enterprise)
    row['cases'] = [packet_case('enterprise', pxe.request(arch=None, vendor=b'ordinary', prl=bytes([125])))];rows.append(row)
    row = copy.deepcopy(template);row['name'] = 'ordinary-option-exhaustion-detail'
    row['options'].extend('dhcp-option-force=' + str(code) + ',' + chr(65 + code - 220) * 200 for code in range(220, 240))
    rows.append(row)
    return rows


def leasequery_profiles():
    available = {row['name']: row for row in leasequery.scenarios()}
    rows = []
    for name in ['allowed', 'denied']:
        row = copy.deepcopy(available[name]);row.setdefault('config', [])
        if name == 'allowed': row['queries'] = row['queries'][:4]
        rows.extend(modes(row, 'config'))
    for name in ['stored-tags', 'request-tags', 'configured', 'capacity']:
        row = copy.deepcopy(available[name]);row.setdefault('config', []).append('log-dhcp')
        row['name'] += '-detail';rows.append(row)
    row = copy.deepcopy(available['allowed']);row['name'] = 'leasequery-enterprise-overflow-detail'
    row['config'] = ['log-dhcp', 'dhcp-option=vi-encap:1234,1,' + 'a' * 240,
                     'dhcp-option=vi-encap:1234,2,' + 'b' * 20]
    row['queries'] = [copy.deepcopy(row['queries'][2])]
    row['queries'][0]['packet'] = leasequery.request(0x8001, ciaddr=leasequery.RANGE_START, prl=bytes([125]))
    rows.append(row)
    return rows


def relay_profiles():
    available = {row['name']: row for row in relay.scenarios()}
    rows = []
    for name in ['relay-multi', 'relay-broadcast', 'split-literal']:
        row = copy.deepcopy(available[name]);rows.extend(modes(row, 'config'))
    return rows


def notices(path):
    raw = path.read_bytes().decode('ascii', errors='backslashreplace')
    lines = [re.sub(r'\[[0-9]+\]', '[<PID>]', line, count=1)
             for line in raw.splitlines() if line.startswith('dnsmasq-dhcp')]
    return lines


def compare_logs(left, right):
    return [] if left == right else [{'kind': 'DHCP-notices', 'expected': left, 'actual': right}]


def relay_channels(packets):
    return sorted(packets, key=lambda packet: tuple(packet['destination']))


def controls():
    baseline = ['dnsmasq-dhcp[<PID>]: 7 DHCPLEASEQUERY(br-lan) 10.77.0.10 02:00:4d:35:01:01 from 10.77.0.2',
                'dnsmasq-dhcp[<PID>]: 7 DHCPLEASEACTIVE(br-lan) 10.77.0.10 02:00:4d:35:01:01 active',
                'dnsmasq-dhcp[<PID>]: 7 sent size:  1 option: 53 message-type  13']
    variants = {'missing-notice': baseline[1:], 'notice-order': list(reversed(baseline)),
                'quiet-routine-leak': baseline + ['dnsmasq-dhcp[<PID>]: DHCPACK(br-lan) client'],
                'missing-error-source': [line.replace('from 10.77.0.2', '') for line in baseline],
                'MAC': [line.replace('01:01', '01:02') for line in baseline],
                'status': [line.replace('DHCPLEASEACTIVE', 'DHCPLEASEUNKNOWN') for line in baseline],
                'sent-option': [line.replace('  13', '  12') for line in baseline],
                'XID': [line.replace(': 7 ', ': 8 ') for line in baseline]}
    result = {name: bool(compare_logs(baseline, changed)) for name, changed in variants.items()}
    packets = [{'destination': ['10.78.0.2', port], 'source': ['10.77.0.1', 67], 'packet': payload}
               for port, payload in [(67, 'aa'), (1067, 'bb'), (67, 'cc')]]
    assert relay_channels(packets) == relay_channels([packets[1], packets[0], packets[2]])
    for name, field, value in [('packet', 'packet', 'dd'), ('source', 'source', ['10.77.0.9', 67]),
                               ('destination', 'destination', ['10.78.0.2', 9999])]:
        changed = copy.deepcopy(packets);changed[0][field] = value
        result['UDP-channel-' + name] = relay_channels(packets) != relay_channels(changed)
    result['UDP-channel-count'] = relay_channels(packets) != relay_channels(packets[1:])
    result['UDP-channel-order'] = relay_channels(packets) != relay_channels([packets[2], packets[1], packets[0]])
    assert all(result.values()) and not compare_logs(baseline, baseline)
    return result


def main(args):
    controls_result = controls()
    if args.self_test:
        print(json.dumps(controls_result, sort_keys=True));return 0
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise SystemExit('run only through run_isolated.sh')
    if sha256(args.rust) != args.rust_sha256: raise SystemExit('candidate identity mismatch')
    out = args.output.resolve()
    if out.exists() or 'private' not in out.parts: raise SystemExit('fresh private output required')
    out.mkdir(parents=True)
    driver = out/'driver';driver.mkdir()
    tool_dir = Path(__file__).resolve().parent
    for path in tool_dir.glob('*.py'): shutil.copy2(path, driver/path.name)
    root = prepare(args.image_root, None, out, args.rust)
    result = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'c_sha256': STOCK_SHA256, 'elf_bytes': args.rust.stat().st_size,
              'driver_sha256': sha256(__file__), 'negative_controls': controls_result, 'scenarios': [], 'failures': []}
    for scope, corpus in [('pxe', pxe_profiles()), ('leasequery', leasequery_profiles()), ('relay', relay_profiles())]:
        if scope not in args.scopes.split(','): continue
        if args.profiles: corpus = [row for row in corpus if row['name'] in args.profiles.split(',')]
        else: corpus = [row for row in corpus if not any(word in row['name'] for word in ['too-large', 'enterprise-overflow', 'option-exhaustion'])]
        rows = [];cleanup = {};client = server = network = None
        try:
            if scope == 'leasequery': network = Network();network.start()
            else:
                client = pxe.Peer('client0', relay.DOWN, relay.CLIENT)
                if scope == 'relay': server = relay.Peer('server0', relay.UP, relay.SERVER)
            for profile in corpus:
                case = {'id': 'dhcp-callers-' + scope + '-' + profile['name'], 'options': ['log-dhcp'], 'failures': []}
                logs = {}
                for side in ['c', 'rust']:
                    destination = out/(scope + '-' + profile['name'] + '-' + side)
                    if scope == 'pxe': row = pxe.run_profile(root, side, profile, client, server, destination)
                    elif scope == 'relay': row = relay.run_profile(root, side, profile, client, server, destination)
                    else:
                        leases = leasequery.lease_file(0, profile.get('vendor'))
                        row = leasequery.run_profile(root, network, side, profile, leases, destination)
                    rows.append(row);logs[side] = notices(destination/'daemon.log')
                    if row.get('identity', {}).get('sha256') != (STOCK_SHA256 if side == 'c' else args.rust_sha256):
                        case['failures'].append({'kind': 'running-identity', 'side': side})
                text = '\n'.join(logs['c'])
                detail = 'log-dhcp' in profile.get('options', profile.get('config', []))
                quiet = 'quiet-dhcp' in profile.get('options', profile.get('config', []))
                required = []
                if scope == 'relay' and detail: required.append('DHCP relay at 10.77.0.1 -> ')
                if scope == 'leasequery':
                    if profile['name'].startswith('denied-'): required.append('leasequery from 10.77.0.2 not permitted')
                    else:
                        required.append('DHCPLEASEQUERY(br-lan)')
                        if detail or not quiet: required.append('DHCPLEASEACTIVE(br-lan)')
                        if detail: required.extend(['sent size:', 'option: 53', 'tags: '])
                if scope == 'pxe':
                    if profile['name'].startswith('warning-leased'): required.append('not using configured address 10.77.0.10 because it is leased to 02:00:00:4d:35:99')
                    elif profile['name'].startswith('warning-router'): required.append('not using configured address 10.77.0.1 because it is in use by the server or relay')
                    elif profile['name'].startswith('warning-declined'): required.append('not using configured address 10.77.0.10 because it was previously declined')
                    elif profile['name'].startswith('warning-no-range'): required.append('no address range available for DHCP request via client0')
                    elif profile['name'].startswith('client-fqdn'): required.append('client provides name: Client.Logging')
                    elif profile['name'].startswith('boot-item'): required.append('PXE BIS not supported')
                    elif profile['name'].startswith('pxe-menu-too-large'): required.append('PXE menu too large')
                    elif 'enterprise-overflow' in profile['name']: required.append('cannot send RFC3925 option: too many options for enterprise number 1234')
                    elif 'option-exhaustion' in profile['name']: required.append('no space left in packet')
                    if detail and not profile['name'].startswith('warning-no-range'):
                        required.append('available DHCP ')
                        if not profile['name'].startswith('bootp-denied'): required.append('tags: ')
                for message in required:
                    if message not in text: case['failures'].append({'kind': 'C-actual-producer', 'missing': message, 'actual': logs['c']})
                case['failures'].extend(compare_logs(logs['c'], logs['rust']))
                case['notice_counts'] = {side: len(value) for side, value in logs.items()}
                result['scenarios'].append(case);save(out/'progress.json', result)
                print(json.dumps({'scenario': case['id'], 'failures': len(case['failures']), 'notices': case['notice_counts']}), flush=True)
        finally:
            if network: cleanup = leasequery.close_network(network)
            if client: cleanup['client'] = client.close()
            if server: cleanup['server'] = server.close()
        if scope == 'leasequery': errors = leasequery.evaluate(rows, corpus, cleanup)
        elif scope == 'pxe': errors = pxe.evaluate(rows, corpus, ['c', 'rust'])
        else:
            evaluation_rows = copy.deepcopy(rows)
            for row in evaluation_rows:
                if not row['profile'].startswith('relay-multi-'): continue
                # The peer drains distinct UDP sockets in select readiness
                # order, which changes between C runs. Preserve every byte,
                # endpoint and within-channel order, and compare channels.
                for packet_case in row['cases']:
                    packet_case['observed']['upstream'] = relay_channels(packet_case['observed']['upstream'])
            errors = relay.evaluate(evaluation_rows, corpus, ['c', 'rust'])
        if scope != 'leasequery':
            for name, item in cleanup.items():
                if item.get('actor_exit') != 0 or item.get('namespace', {}).get('forced'): errors.append(name + ': namespace cleanup')
        save(out/(scope+'-wire-evaluation.json'), {'failures': errors, 'cleanup': cleanup,
             'peer_order_policy': 'relay-multi only: stable destination-channel comparison; raw UDP socket readiness order retained; every packet/source/destination/count stays compared'})
        result['failures'].extend({'scope': scope, 'kind': 'independent-wire-health-cleanup', 'error': error} for error in errors)
    result['failures'].extend(dict(case=row['id'], **failure) for row in result['scenarios'] for failure in row['failures'])
    if not result['scenarios']: result['failures'].append({'kind': 'missing-scenarios'})
    save(out/'result.json', result)
    print(json.dumps({'scenarios': len(result['scenarios']), 'failures': len(result['failures'])}))
    return int(bool(result['failures']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path);parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256');parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path);parser.add_argument('--scopes', default='pxe,leasequery,relay')
    parser.add_argument('--profiles');parser.add_argument('--self-test', action='store_true')
    raise SystemExit(main(parser.parse_args()))
