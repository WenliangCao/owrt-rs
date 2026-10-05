#!/usr/bin/env python3
"""DHCP probes for the generic matrix, using existing M5/M2 packet helpers."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import exact_read, query, read_name, semantics
from m2_rootfs import command, process_identity, sha256
from test_single_poll_service import Network, stop
from m2_dhcp_scenarios import make_client, receive as receive_frame
from m5_dhcp_tags_options import request, options, comparable_reply, lease_rows, primary_options
from m5_leasequery import run_client as leasequery_client

DEPENDENCIES = ['m5_option_matrix_dhcp.py', 'test_single_poll_service.py', 'm2_dhcp_scenarios.py',
                'm5_dhcp_tags_options.py', 'm5_leasequery.py', 'dhcp_boot_service_diff.py', 'dns_udp_refusal_diff.py']
SERVER = '10.77.0.1'


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def mac(number):
    return f'02:00:4d:35:44:{number:02x}'


def wire_event(event, leases):
    event = copy.deepcopy(event)
    number = event.get('client', 1)
    assigned = leases.get(str(number), '10.77.0.10')
    address = event.get('address', assigned)
    if address == 'assigned': address = assigned
    event['address'] = address
    packet = dict(event.get('packet', {}))
    action = event.get('action', 'select')
    packet.update(kind={'discover': 1, 'select': 3, 'init-reboot': 3, 'renew': 3,
                        'rebind': 3, 'release': 7, 'decline': 4, 'leasequery': 10, 'bootp': 0}[action],
                  mac=mac(number).replace(':', ''), flags=event.get('flags', 0),
                  maximum=1500, prl=event.get('prl', [1, 3, 6, 12, 15, 51, 54, 58, 59]))
    server = event.get('server', SERVER)
    if action == 'select': packet.update(address=address, server_id=event.get('server_id', server))
    elif action == 'init-reboot': packet.update(address=address, server_id=None)
    elif action in ('renew', 'rebind'):
        packet.update(ciaddr=address, requested_address=False, server_id=None, renew=True)
    elif action == 'release':
        packet.update(ciaddr=address)
        packet.setdefault('extra', []).append([54, socket.inet_aton(server).hex()])
    elif action == 'decline':
        packet.setdefault('extra', []).extend([[50, socket.inet_aton(address).hex()], [54, socket.inet_aton(server).hex()]])
    elif action == 'leasequery': packet.update(ciaddr=address, giaddr='10.77.0.2', flags=0)
    event['packet'] = packet
    return event


def client_worker(spec):
    event = spec['event']
    if event.get('action') == 'tftp':
        target = event.get('server', SERVER)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(.4)
            endpoint.sendto(b'\0\1probe.bin\0octet\0', (target, 69))
            try:
                packet, peer = endpoint.recvfrom(65535)
                if packet[:2] == b'\0\3': endpoint.sendto(b'\0\4' + packet[2:4], peer)
                return {'reply': packet.hex(), 'source_ip': peer[0]}
            except socket.timeout: return {'reply': None}
    number = event.get('client', 1)
    if event.get('guest'):
        interface = 'client1'
    else:
        interface = make_client({'id': number, 'mac': mac(number)})
    address = event['packet'].get('ciaddr', '0.0.0.0')
    if address != '0.0.0.0':
        subprocess.run(['ip', 'addr', 'replace', address + '/24', 'dev', interface], check=True)
    packet = request(event['packet'], spec['xid'])
    destination = event.get('destination', event.get('server', SERVER) if event.get('action') in ('renew', 'release') else '255.255.255.255')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        raw.bind((interface, 0))
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
        endpoint.bind((address if address != '0.0.0.0' else '0.0.0.0', 68))
        sent = time.time()
        endpoint.sendto(packet, (destination, 67))
        try:
            response, frame = receive_frame(raw, spec['xid'], event.get('timeout', .4))
        except socket.timeout:
            return {'request': packet.hex(), 'reply': None, 'sent': sent, 'received': time.time()}
    offset = 14 + (frame[14] & 15) * 4
    sport, dport = struct.unpack_from('!HH', frame, offset)
    return {'request': packet.hex(), 'reply': response.hex(), 'ethernet': frame.hex(),
            'sent': sent, 'received': time.time(), 'destination': {
                'ethernet': frame[:6].hex(), 'source_ip': socket.inet_ntoa(frame[26:30]),
                'address': socket.inet_ntoa(frame[30:34]), 'source_port': sport, 'port': dport}}


def setup_network(scenario):
    network = Network()
    network.start()
    # Multiple macvlan clients share this namespace. Without arp_ignore=1, a
    # previously configured client can answer ARP for another client's lease.
    network.exec('sysctl', '-qw', 'net.ipv4.conf.all.arp_ignore=1', 'net.ipv4.conf.default.arp_ignore=1')
    for address in scenario.get('server_aliases', []):
        subprocess.run(['ip', 'addr', 'add', address + '/24', 'dev', 'br-lan'], check=True)
    if scenario.get('two_interfaces'):
        for args in [['link', 'add', 'br-guest', 'type', 'bridge'],
                     ['addr', 'add', '10.78.0.1/24', 'dev', 'br-guest'], ['link', 'set', 'br-guest', 'up'],
                     ['link', 'add', 'guest-port', 'type', 'veth', 'peer', 'name', 'client1'],
                     ['link', 'set', 'guest-port', 'master', 'br-guest'], ['link', 'set', 'guest-port', 'up'],
                     ['link', 'set', 'client1', 'netns', str(network.client.pid)]]:
            subprocess.run(['ip', *args], check=True)
        network.links.extend(['br-guest', 'guest-port'])
        network.exec('ip', 'link', 'set', 'client1', 'address', mac(2))
        network.exec('ip', 'addr', 'add', '10.78.0.2/24', 'dev', 'client1')
        network.exec('ip', 'link', 'set', 'client1', 'up')
    return network


def config(scenario):
    lines = ['no-hosts', 'no-resolv', 'no-0x20-encode', 'user=root', 'group=root', 'port=15353',
             'interface=br-lan', 'no-ping', 'host-record=matrix.ready,8.8.8.8',
             'dhcp-leasefile=/m2/family.leases', 'pid-file=/m2/matrix.pid']
    lines += scenario.get('ranges', ['dhcp-range=set:range,10.77.0.10,10.77.0.14,255.255.255.0,600s'])
    if scenario.get('two_interfaces'):
        lines += ['interface=br-guest', 'dhcp-range=10.78.0.10,10.78.0.14,255.255.255.0,600s']
    return '\n'.join(lines) + '\n' + scenario.get('config', '')


def dns_health(address='127.0.0.1'):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.25)
        packet = query('matrix.ready', ident=0x2930)
        endpoint.sendto(packet, (address, 15353))
        return semantics(endpoint.recv(4096))


def dns_probe(event, ident, seed_epoch):
    if 'at_seed_age' in event:
        # Both daemons must answer in the same relative integer second. This
        # makes lease-ceiling TTL exact, without accepting a TTL range.
        wanted = seed_epoch + event['at_seed_age']
        remaining = wanted + .2 - time.time()
        if remaining > 0:
            time.sleep(remaining)
        if int(time.time()) != wanted:
            raise AssertionError('missed scheduled DNS second')
    packet = query(event['name'], event.get('type', 1), ident)
    observations, raw = {}, {}
    for transport in ['udp', 'tcp']:
        sent = time.time()
        if transport == 'udp':
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(1)
                endpoint.sendto(packet, ('127.0.0.1', 15353))
                response, peer = endpoint.recvfrom(65535)
        else:
            with socket.create_connection(('127.0.0.1', 15353), 1) as endpoint:
                endpoint.sendall(struct.pack('!H', len(packet)) + packet)
                response = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
                peer = endpoint.getpeername()
        received = time.time()
        if response[:2] != packet[:2]:
            raise AssertionError('DNS client transaction changed')
        if 'at_seed_age' in event and not (int(sent) == int(received) == wanted):
            raise AssertionError('DNS observation crossed scheduled second')
        observations[transport] = semantics(response)
        observations[transport]['question_wire'] = response[12:read_name(response, 12)[1] + 4].hex()
        raw[transport] = {'request': packet.hex(), 'reply': response.hex(),
                          'sent': sent, 'received': received, 'peer': list(peer),
                          'seed_epoch': seed_epoch}
    return {'dns': observations}, raw


def run_side(root, side, scenario, folder):
    folder.mkdir()
    text = config(scenario)
    (root / 'm2/matrix.conf').write_text(text)
    (folder / 'config').write_text(text)
    for name in ['family.leases', 'matrix.pid']:
        (root / 'm2' / name).unlink(missing_ok=True)
    seed_epoch = int(time.time())
    if scenario.get('seed_leases'):
        seed = scenario['seed_leases'].replace('{expiry}', str(seed_epoch + 600)).replace('{expired}', str(seed_epoch - 100))
        (root / 'm2/family.leases').write_text(seed)
        (folder / 'seed.leases').write_text(seed)
    if scenario.get('tftp'):
        (root / 'm2/tftp').mkdir(exist_ok=True)
        (root / 'm2/tftp/probe.bin').write_bytes(b'matrix-tftp')
    if scenario.get('helper_tags'):
        script = root/'m2/tag-script'
        script.write_text('#!/bin/sh\nprintf "%s|%s\\n" "$1" "$DNSMASQ_TAGS" >> /m2/tag-events\n')
        script.chmod(0o755)
        (root/'m2/tag-events').unlink(missing_ok=True)
        text += 'dhcp-script=/m2/tag-script\n'
        (root/'m2/matrix.conf').write_text(text)
        (folder/'config').write_text(text)
    syntax = subprocess.run(command(root, side, '--test', '-C', '/m2/matrix.conf'), capture_output=True, text=True, timeout=5)
    result = {'syntax': {'exit': syntax.returncode, 'stdout': syntax.stdout, 'stderr': syntax.stderr},
              'startup': {'ready': False}, 'rows': [], 'exit': None,
              'cleanup': {'live_pids': [], 'pid_file': False}}
    if scenario.get('syntax_only'):
        result['startup']['skipped'] = 'source NULL-predicate boundary; runtime intentionally not invoked'
        result['config_line'] = len(text.splitlines())
        write_json(folder / 'observed.json', result)
        return result
    network, process = None, None
    try:
        network = setup_network(scenario)
        if scenario.get('wait_for_address_ready'):
            # These cases test exclusion on established interfaces. Retain
            # initial DAD failure separately in the listener-family evidence.
            deadline = time.monotonic() + 5
            while True:
                addresses = json.loads(subprocess.check_output(['ip', '-j', '-6', 'addr', 'show']))
                if not any('tentative' in address.get('flags', []) or address.get('tentative')
                           for interface in addresses for address in interface.get('addr_info', [])):
                    break
                if time.monotonic() >= deadline: raise AssertionError('interface DAD did not complete')
                time.sleep(.02)
        write_json(folder / 'network.json', {'server': json.loads(subprocess.check_output(['ip', '-j', 'addr'])),
                   'client': json.loads(network.exec('ip', '-j', 'addr').stdout),
                   'client_arp_ignore': network.exec('sysctl', '-n', 'net.ipv4.conf.all.arp_ignore').stdout.strip()})
        with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr:
            def start():
                proc = subprocess.Popen(command(root, side, '-k', '-C', '/m2/matrix.conf'),
                                        stdout=stdout, stderr=stderr, start_new_session=True)
                deadline = time.monotonic() + 3
                while proc.poll() is None and time.monotonic() < deadline:
                    try:
                        health = dns_health()
                        if [r['data'] for r in health['records']] != ['8.8.8.8']: raise AssertionError('readiness reply wrong')
                        return proc, {'ready': True}
                    except socket.timeout: time.sleep(.01)
                return proc, {'ready': False, 'exit': proc.poll()}
            process, result['startup'] = start()
            if result['startup']['ready']:
                result['identity'] = process_identity(root, process.pid)
                expected = sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))
                if result['identity']['sha256'] != expected: raise AssertionError('wrong DHCP daemon identity')
                assigned = {}
                for index, original in enumerate(scenario['probes']):
                    event = copy.deepcopy(original)
                    row = {'id': event['id'] + ':dhcp', 'response': None, 'raw': None, 'request': None, 'elapsed': 0, 'upstream': []}
                    if event.get('action') == 'restart':
                        stopped = stop(process)
                        for old, new in event.get('replace_config', []):
                            text = text.replace(old, new)
                        (root / 'm2/matrix.conf').write_text(text)
                        (folder / f'{index:03}.config').write_text(text)
                        process, ready = start()
                        if stopped['returncode'] != 0 or stopped['forced'] or not ready['ready']: raise AssertionError('restart failed')
                        row['response'] = {'restarted': True}
                    elif event.get('action') == 'snapshot':
                        row['response'] = {'snapshot': True}
                    elif event.get('action') == 'hup':
                        process.send_signal(signal.SIGHUP)
                        time.sleep(.05)
                        row['response'] = {'hup': True}
                    elif event.get('action') == 'dns':
                        row['response'], row['raw'] = dns_probe(event, 0xd400 + index, seed_epoch)
                    elif event.get('action') == 'leasequery':
                        event = wire_event(event, assigned)
                        time.sleep(1.05)
                        raw = leasequery_client(network, request(event['packet'], 0xd400 + index), folder / f'{index:03}-leasequery')
                        response = bytes.fromhex(raw['reply']) if raw['reply'] else None
                        row['raw'] = raw
                        row['response'] = decode(response, event, None)
                    else:
                        if event.get('action') != 'tftp': event = wire_event(event, assigned)
                        output = network.exec(sys.executable, str(Path(__file__).resolve()), '--client', json.dumps({'event': event, 'xid': 0xd400 + index}))
                        raw = json.loads(output.stdout)
                        row['raw'] = raw
                        row['request'] = raw.get('request')
                        if event.get('action') == 'tftp':
                            row['response'] = {'tftp': raw['reply']}
                        else:
                            response = bytes.fromhex(raw['reply']) if raw['reply'] else None
                            row['response'] = decode(response, event, raw.get('destination'))
                            if response and row['response']['status'] in (2, 5):
                                assigned[str(event.get('client', 1))] = socket.inet_ntoa(response[16:20])
                    leases, normalized = lease_rows(root)
                    (folder / f'{index:03}.leases').write_text(leases)
                    row['leases'] = normalized
                    row['health'] = dns_health()
                    if scenario.get('two_interfaces'):
                        row['guest_dns_health'] = dns_health('10.78.0.1')
                    if scenario.get('helper_tags'):
                        expected_count = len(event.get('expect', {}).get('helper_marks', []))
                        deadline = time.monotonic() + 2
                        while True:
                            log = root/'m2/tag-events'
                            helper = log.read_text().splitlines() if log.exists() else []
                            if len(helper) >= expected_count: break
                            if time.monotonic() >= deadline: raise AssertionError('missing helper tag events')
                            time.sleep(.01)
                        row['helper_tags'] = helper
                    result['rows'].append(row)
    finally:
        if process is not None:
            outcome = stop(process)
            result['exit'] = process.returncode
            result['forced_kill'] = outcome['forced']
            if Path(f'/proc/{process.pid}').exists(): result['cleanup']['live_pids'].append(process.pid)
        if network:
            result['network_cleanup'] = network.close()
            cleanup = result['network_cleanup']
            if cleanup['forced'] or cleanup['returncode'] != -signal.SIGTERM:
                result['cleanup']['network_error'] = cleanup
            if Path(f'/proc/{network.client.pid}').exists(): result['cleanup']['live_pids'].append(network.client.pid)
        if sorted(name for _, name in socket.if_nameindex()) != ['lo']:
            result['cleanup']['interfaces_left'] = [name for _, name in socket.if_nameindex()]
        result['cleanup']['pid_file'] = (root / 'm2/matrix.pid').exists()
        result['startup']['stdout'] = (folder / 'stdout').read_text() if (folder / 'stdout').exists() else ''
        result['startup']['stderr'] = (folder / 'stderr').read_text() if (folder / 'stderr').exists() else ''
        write_json(folder / 'observed.json', result)
    return result


def decode(response, event, destination):
    if response is None: return None
    decoded = {code: bytes.fromhex(value) for code, value in options(response)}
    kind = decoded.get(53,b'\0')[0]
    normalized_event = copy.deepcopy(event['packet'])
    if kind != 5: normalized_event.pop('renew', None)
    comparable = comparable_reply(response, normalized_event)
    return {'wire': comparable, 'status': kind,
            'server_id': socket.inet_ntoa(decoded[54]) if 54 in decoded else None,
            'message': decoded.get(56, b'').decode(errors='backslashreplace'), 'flags': int.from_bytes(response[10:12], 'big'),
            'address': socket.inet_ntoa(response[16:20]), 'destination': destination}


def guards(rows, scenario):
    failures = []
    for row, event in zip(rows, scenario['probes']):
        expected = event.get('expect', {})
        response = row['response']
        if 'status' in expected:
            actual = response.get('status') if response else None
            if actual != expected['status']: failures.append({'id': row['id'], 'expected_status': expected['status'], 'actual': actual})
        for key in ['flags', 'address', 'server_id', 'message']:
            if key in expected and (response is None or response[key] != expected[key]):
                failures.append({'id': row['id'], 'field': key, 'expected': expected[key], 'actual': response})
        if 'helper_marks' in expected:
            helper = row.get('helper_tags', [])
            if len(helper) != len(expected['helper_marks']):
                failures.append({'id': row['id'], 'missing_helper': helper})
            for line, mark in zip(helper, expected['helper_marks']):
                action, tags = line.split('|', 1)
                if action != mark[0] or mark[1] not in tags.split():
                    failures.append({'id': row['id'], 'wrong_helper_tag': line, 'expected': mark})
        if 'option_values' in expected:
            wire = (response or {}).get('wire')
            values = {str(code): value for code, value in options(bytes.fromhex(wire))} if wire else {}
            for code, wanted in expected['option_values'].items():
                if values.get(code) != wanted:
                    failures.append({'id': row['id'], 'option': code, 'expected': wanted, 'actual': values.get(code)})
        if 'destination' in expected and (response is None or response['destination']['address'] != expected['destination']):
            failures.append({'id': row['id'], 'expected_destination': expected['destination'], 'actual': response})
        if 'leases' in expected and len(row['leases']) != expected['leases']:
            failures.append({'id': row['id'], 'expected_lease_count': expected['leases'], 'actual': row['leases']})
        for key, column in [('lease_names', 3), ('lease_ids', 4)]:
            if key not in expected:
                continue
            actual = {lease[2]: lease[column] for lease in row.get('leases', [])}
            if actual != expected[key]:
                failures.append({'id': row['id'], 'field': key, 'expected': expected[key], 'actual': actual})
        replies = (response or {}).get('dns', {})
        if event.get('action') == 'dns' and set(replies) != {'udp', 'tcp'}:
            failures.append({'id': row['id'], 'missing_dns_transport': sorted(replies)})
        for transport, reply in replies.items():
            answers = [record for record in reply['records'] if record['section'] == 'answer']
            for key, actual in [('answers', [record['data'] for record in answers]),
                                ('rcode', reply['flags'] & 15),
                                ('ttl', [record['ttl'] for record in answers])]:
                wanted = expected.get(key)
                if key == 'ttl' and wanted is not None:
                    wanted = [wanted] * len(answers)
                if wanted is not None and actual != wanted:
                    failures.append({'id': row['id'], 'transport': transport,
                                     'field': key, 'expected': wanted, 'actual': actual})
        if 'tftp' in expected and (
            ((response or {}).get('tftp') != (b'\0\3\0\1matrix-tftp').hex()) if expected['tftp']
            else (response or {}).get('tftp') is not None):
            failures.append({'id': row['id'], 'expected_tftp': expected['tftp'], 'actual': response})
    return failures


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--client':
        print(json.dumps(client_worker(json.loads(sys.argv[2]))))
    else:
        raise SystemExit('internal --client JSON only')


def reference_baseline(observed):
    expected = {'exit': 0, 'stdout': '', 'stderr': 'dnsmasq: syntax check OK.\n'}
    errors = []
    if observed['syntax'] != expected: errors.append({'phase': 'reference-defect', 'c_syntax': observed['syntax']})
    if observed['startup'].get('ready') or observed['rows']:
        errors.append({'phase': 'reference-defect', 'unsafe_runtime_was_executed': True})
    return errors


def reference_difference(expected, actual, scenario):
    errors = reference_baseline(expected)
    directive = scenario['config'].strip()
    if directive not in ('dhcp-broadcast=', 'dhcp-broadcast=tag:', 'dhcp-broadcast=net:'):
        return errors + [{'phase': 'reference-defect', 'not_allowlisted': directive}]
    wanted = {'exit': 1, 'stdout': '', 'stderr': f'\ndnsmasq: empty DHCP tag predicate at line {actual["config_line"]} of /m2/matrix.conf\n'}
    observed = copy.deepcopy(actual['syntax'])
    observed['stderr'] = observed['stderr'].replace('dnsmasq-rs:', 'dnsmasq:')
    if observed != wanted: errors.append({'phase': 'reference-defect', 'rust_syntax': observed, 'expected': wanted})
    if actual['startup'].get('ready') or actual['rows']:
        errors.append({'phase': 'reference-defect', 'unsafe_runtime_was_executed': True})
    return errors


def controls():
    event = {'id': 'control', 'expect': {'status': 5, 'flags': 0, 'address': '10.77.0.10', 'destination': '10.77.0.10', 'server_id': SERVER, 'message': 'wrong network', 'leases': 1}}
    row = {'id': 'control:dhcp', 'response': {'status': 5, 'flags': 0, 'address': '10.77.0.10', 'destination': {'address': '10.77.0.10'}, 'server_id': SERVER, 'message': 'wrong network'}, 'leases': [['lease']]}
    assert not guards([row], {'probes': [event]})
    result = {}
    for key in ['status', 'flags', 'address', 'destination', 'server_id', 'message', 'leases']:
        bad = copy.deepcopy(row)
        if key == 'leases': bad['leases'] = []
        elif key == 'destination': bad['response']['destination']['address'] = '255.255.255.255'
        else: bad['response'][key] = None
        assert guards([bad], {'probes': [event]}), key
        result['dhcp-' + key] = 'detected'
    for allowed in (False, True):
        event = {'id': 'tftp-control', 'expect': {'tftp': allowed}}
        row = {'id': 'tftp-control:dhcp', 'response': {'tftp': (b'\0\3\0\1matrix-tftp').hex() if allowed else None}}
        assert not guards([row], {'probes': [event]})
        row['response']['tftp'] = (b'\0\3\0\1wrong-file').hex()
        assert guards([row], {'probes': [event]})
        result['dhcp-tftp-' + ('wrong-payload' if allowed else 'unexpected-reply')] = 'detected'
    event = {'id': 'lease-id-control', 'expect': {'lease_ids': {'10.77.0.10': '01:ab'}}}
    row = {'id': 'lease-id-control:dhcp', 'response': None, 'leases': [['infinite', 'mac', '10.77.0.10', 'host', '01:ab']]}
    assert not guards([row], {'probes': [event]})
    row['leases'][0][4] = '*'
    assert guards([row], {'probes': [event]})
    result['dhcp-restored-client-id-lost'] = 'detected'
    event = {'id': 'dns-control', 'action': 'dns', 'expect': {'answers': ['10.77.0.10'], 'ttl': 597}}
    reply = {'flags': 0x8180, 'records': [{'section': 'answer', 'data': '10.77.0.10', 'ttl': 597}]}
    row = {'id': 'dns-control:dhcp', 'response': {'dns': {'udp': copy.deepcopy(reply), 'tcp': copy.deepcopy(reply)}}}
    assert not guards([row], {'probes': [event]})
    for label in ['ttl', 'data', 'missing-transport']:
        bad = copy.deepcopy(row)
        if label == 'missing-transport':
            bad['response']['dns'].pop('tcp')
        else:
            bad['response']['dns']['udp']['records'][0][label] = 0
        assert guards([bad], {'probes': [event]})
        result['dhcp-dns-' + label] = 'detected'
    packet = bytearray(240)
    packet[236:240] = bytes.fromhex('63825363')
    packet += bytes([224, 1, 2, 255])
    event = {'id': 'tag-control', 'expect': {'option_values': {'224': '02', '225': None}}}
    row = {'id': 'tag-control:dhcp', 'response': {'wire': packet.hex()}}
    assert not guards([row], {'probes': [event]})
    row['response']['wire'] = (packet[:242] + bytes([1, 255])).hex()
    assert guards([row], {'probes': [event]})
    result['dhcp-derived-option-value'] = 'detected'
    c = {'syntax': {'exit': 0, 'stdout': '', 'stderr': 'dnsmasq: syntax check OK.\n'}, 'startup': {'ready': False}, 'rows': []}
    rust = {'syntax': {'exit': 1, 'stdout': '', 'stderr': '\ndnsmasq: empty DHCP tag predicate at line 1 of /m2/matrix.conf\n'}, 'startup': {'ready': False}, 'rows': [], 'config_line': 1}
    assert not reference_difference(c, rust, {'config': 'dhcp-broadcast=tag:\n'})
    bad = copy.deepcopy(rust);bad['syntax']['exit'] = 0
    assert reference_difference(c, bad, {'config': 'dhcp-broadcast=tag:\n'})
    result['dhcp-unsafe-predicate-accepted'] = 'detected'
    assert reference_difference(c, rust, {'config': 'dhcp-broadcast=tag:ordinary\n'})
    result['dhcp-reference-classification-not-blanket'] = 'detected'
    return result
