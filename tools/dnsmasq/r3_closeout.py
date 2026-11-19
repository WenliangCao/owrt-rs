#!/usr/bin/env python3
"""Focused DNS closeout stimuli; run only inside run_isolated.sh on Linux.

The existing image harness owns disposable overlays and service cleanup. Each
case records fresh C/base/candidate outputs; this driver never reads old results
or operates a router. Timing fields from the shared harness are not verdicts.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

import m5_dhcp_files as bank
import m5_dhcp_tags_options as dhcp_wire
import m5_dns_files as files
import m5_option_matrix as matrix
import m5_option_matrix_dhcp as dhcp
from dns_service_probe import exact_read, name, read_name
from m2_rootfs import prepare, sha256


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def wire_cases():
    def case(ident, config, probes, cache=64):
        return dict(id=ident, config=config, probes=probes, cache_size=cache)

    soa = name('ns.test') + name('hostmaster.test') + struct.pack('!5I', 1, 60, 60, 3600, 60)
    rows = []
    for flags, do in [(0x100, False), (0, False), (0x100, True)]:
        rows.append(case('6324-flags-' + str(flags) + '-' + str(do),
            'cname=alias.test,middle.test\n', [
                dict(id='seed', name='middle.test', transports=['udp'], records=[
                    dict(type=5, target='terminal.test'),
                    dict(type=1, owner='terminal.test', address='192.0.2.44')]),
                dict(id='alias', name='alias.test', query_flags=flags, do=do),
                dict(id='cname', name='alias.test', type=5, query_flags=flags, do=do),
                dict(id='multiple-questions', name='alias.test', multiple=True)]))
    for rcode in [0, 3]:
        rows.append(case('6324-negative-' + str(rcode), 'cname=alias.test,terminal.test\n', [
            dict(id='seed', name='terminal.test', rcode=rcode, transports=['udp'], records=[
                dict(type=6, owner='test', hex=soa.hex(), section='authority')]),
            dict(id='alias', name='alias.test')]))
    for stale in ['', 'use-stale-cache=2\n']:
        rows.append(case('6324-expiry-' + str(bool(stale)), 'cname=alias.test,terminal.test\n' + stale, [
            dict(id='seed', name='terminal.test', reply_ttl=1, transports=['udp']),
            dict(id='expired', name='alias.test', sleep_before=2, settle=True)]))
    rows.append(case('6324-ten-hop', ''.join(f'cname=a{i}.test,a{i+1}.test\n' for i in range(10)), [
        dict(id='seed', name='a10.test', transports=['udp']), dict(id='alias', name='a0.test')]))
    rows.append(case('6324-filter-counterexample',
        'filter-A\ninterface-name=terminal.test,absent0\nuse-stale-cache=1\n', [
            dict(id='seed', name='alias.test', rcode=3, transports=['udp'], records=[
                dict(type=5, target='terminal.test', ttl=60),
                dict(type=6, owner='test', hex=soa.hex(), ttl=1, section='authority')]),
            dict(id='expired', name='alias.test', rcode=3, sleep_before=3, records=[
                dict(type=5, target='terminal.test', ttl=60),
                dict(type=6, owner='test', hex=soa.hex(), ttl=1, section='authority')])]))
    # Separate focused replay of the old 294 expiry counterexample. This is
    # deliberately independent of the configured-alias acceptance stimulus.
    for filtered in [False, True]:
        records = [dict(type=5, target='terminal.test', ttl=60),
                   dict(type=6, owner='test', hex=soa.hex(), ttl=1, section='authority')]
        probes = [dict(id='seed', name='alias.test', rcode=3, records=records,
                       transports=['udp'])]
        for index, (flags, do) in enumerate([(0x100, False), (0, False), (0x100, True)]):
            probes.append(dict(id='expired-' + str(flags) + '-' + str(do),
                name='alias.test', rcode=3, records=records, query_flags=flags,
                do=do, edns=True, sleep_before=3 if index == 0 else 0))
        rows.append(case('negative-expiry-' + str(filtered),
            ('filter-A\n' if filtered else '') +
            'interface-name=terminal.test,absent0\nuse-stale-cache=1\n', probes))
    rows.append(case('9a646297', 'log-queries\nuse-stale-cache=1\n', [
        dict(id='initial-chain', name='alias1.test', transports=['udp'], records=[
            dict(type=5, target='alias2.test', ttl=1),
            dict(type=5, owner='alias2.test', target='terminal.test', ttl=1),
            dict(type=1, owner='terminal.test', address='192.0.2.45', ttl=1)]),
        dict(id='refresh-first', name='alias1.test', type=5, transports=['udp'], records=[
            dict(type=5, target='alias2.test', ttl=60)]),
        dict(id='evict', name='conflict.test', sleep_before=3, transports=['udp']),
        dict(id='replay', name='alias1.test', records=[
            dict(type=5, target='alias2.test'),
            dict(type=5, owner='alias2.test', target='terminal.test'),
            dict(type=1, owner='terminal.test', address='192.0.2.45')])], cache=3))
    rows.append(case('tcp65536', 'filter-A\n', [
        dict(id='frame-' + str(length), name='caller.test', edns=True,
             frame_length=length, transports=['tcp']) for length in [65529, 65530, 65535]]))
    return rows


def install_wire_hooks():
    original_query, original_answer, original_observe = matrix.query, matrix.Upstream.answer, matrix.observe

    def query(probe, ident):
        packet = original_query(probe, ident)
        if probe.get('multiple'):
            end = read_name(packet, 12)[1] + 4
            packet = packet[:4] + b'\0\2' + packet[6:end] + packet[12:end] + packet[end:]
        return packet

    def answer(upstream, packet, transport):
        host, end = read_name(packet, 12)
        kind = struct.unpack_from('!H', packet, end)[0]
        probe = upstream.probes.get((host, kind), {})
        if not probe.get('frame_length'):
            return original_answer(upstream, packet, transport)
        length = probe['frame_length']
        response = packet[:2] + struct.pack('!5H', 0x8180, 1, 3, 0, 1) + packet[12:end + 4]
        pointer = struct.pack('!H', 0xc000 | len(response))
        response += matrix.rr(1, bytes([192, 0, 2, 1]), name('target.test'), 60)
        response += matrix.rr(2, pointer, pointer, 60)
        remaining, txt = length - len(response) - 12 - 11, bytearray()
        while remaining:
            count = min(remaining - 1, 255)
            txt += bytes([count]) + b'a' * count
            remaining -= count + 1
        response += matrix.rr(16, bytes(txt), b'\xc0\x0c', 60)
        response += matrix.rr(41, b'', b'\0', 0, 1232)
        assert len(response) == length
        upstream.events.append({'name': host, 'type': kind, 'class': 1, 'transport': transport,
                                'wire': packet.hex(), 'reply_wire': response.hex()})
        return response

    def observe(port, probe, ident, transport, upstream):
        upstream.probes[(probe['name'], probe.get('type', 1))] = probe
        if not probe.get('frame_length'):
            before = len(upstream.events)
            result = original_observe(port, probe, ident, transport, upstream)
            if probe.get('settle'):
                time.sleep(.1)
                result['upstream'] = copy.deepcopy(upstream.events[before:])
            return result
        # The three probes share a name; choose the current length explicitly.
        upstream.probes[(probe['name'], 1)] = probe
        packet, prefix, body, error = query(probe, ident), None, b'', None
        with socket.create_connection(('127.0.0.1', port), .5) as client:
            client.settimeout(.5)
            client.sendall(struct.pack('!H', len(packet)) + packet)
            try:
                prefix = int.from_bytes(exact_read(client, 2), 'big')
                body = exact_read(client, prefix) if prefix else client.recv(65536)
            except (OSError, ConnectionError) as exception:
                error = type(exception).__name__
        return dict(id=probe['id'], response=dict(prefix=prefix, body_length=len(body)),
                    raw=body.hex(), request=packet.hex(), transport_error=error, upstream=[])

    matrix.query, matrix.Upstream.answer, matrix.observe = query, answer, observe


def wire_facts(result):
    rows = []
    for row in result['rows']:
        response = copy.deepcopy(row['response'])
        if response:
            response.pop('id', None)
            for record in response.get('records', []):
                record.pop('ttl', None)
        rows.append(dict(id=row['id'], response=response, error=row['transport_error'], upstream=len(row['upstream'])))
    return rows


def file_case(ident):
    if ident == '7746362e':
        return dict(id=ident, checks=[], files={'resolv': 'nameserver 127.0.0.2\n',
            'servers': 'server=/files.test/127.0.0.2\n'}, config='servers-file=/m2/files/servers\nfast-dns-retry=100,500\n', actions=[
            dict(op='start-udp', id='held', name='pending.files.test'),
            files.write('servers', 'server=/new.test/127.0.0.2\n'), files.signal_reload(),
            dict(op='pause', seconds=.25), dict(op='inject', id='held', server=0),
            dict(op='receive-udp', id='late', pending='held'), files.probe('fresh', 'fresh.new.test')])
    if ident == '805c2463':
        row = copy.deepcopy(next(c for c in files.scenarios() if c['id'] == 'pending-cancel-fd-recovery'))
        row['id'] = ident
        row['config'] = 'query-port=40053\n'
        row['files']['resolv'] = 'nameserver 127.0.0.2\nnameserver 127.0.0.3\n'
        row['actions'][0]['upstream_count'] = 2
        row['config'] += 'all-servers\n'
        row['actions'] += [files.write('resolv', 'nameserver 127.0.0.2\n'), files.probe('recovered')]
        return row
    return dict(id=ident, checks=[], files={'resolv': 'nameserver 127.0.0.2\n',
        'servers': 'server=/file.test/127.0.0.4\n'}, config='servers-file=/m2/files/servers\n',
        sys_files={'/etc/resolv.conf': 'nameserver 127.0.0.5\n'}, actions=[
            files.write('servers', 'server=/file.test/endpoint.test\n'), files.signal_reload(),
            files.write('resolv', 'nameserver 127.0.0.3\n', atomic=True, release_lookup=True),
            files.probe('file-after', 'a.file.test'), files.probe('resolver-after')])


def hostname_lookup_fixture():
    waiting, release, stop = threading.Event(), threading.Event(), threading.Event()
    endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    endpoint.bind(('127.0.0.5', 53))
    endpoint.settimeout(.05)
    observations = []

    def worker():
        while not stop.is_set():
            try:
                packet, peer = endpoint.recvfrom(2048)
            except socket.timeout:
                continue
            host, end = read_name(packet, 12)
            observations.append(dict(name=host, request=packet.hex()))
            waiting.set()
            if not release.wait(3):
                continue
            kind = struct.unpack_from('!H', packet, end)[0]
            records = matrix.rr(1, socket.inet_aton('127.0.0.4')) if kind == 1 else b''
            response = packet[:2] + struct.pack('!5H', 0x8180, 1, int(bool(records)), 0, 0) + packet[12:end+4] + records
            endpoint.sendto(response, peer)

    thread = threading.Thread(target=worker)
    thread.start()
    original = files.put

    def put(root, relative, value, opened):
        if isinstance(value, dict) and value.get('release_lookup'):
            assert waiting.wait(3), 'hostname resolver was not reached'
            original(root, relative, value, opened)
            release.set()
        else:
            original(root, relative, value, opened)
    files.put = put

    def close():
        files.put = original
        release.set()
        stop.set()
        thread.join(4)
        endpoint.close()
    return observations, close


def bank_case(ident):
    if ident == '52c71105':
        return dict(name=ident, helper=True, config='dhcp-optsdir={base}/opts\n',
            files={'opts/seed': '224,old\n'}, events=[
                dict(op='packet', label='lease', kind=3, address='127.0.0.30'),
                dict(op='fifo-reload', path='opts/live', text='224,new\n'),
                dict(op='packet', label='after', kind=8, ciaddr='127.0.0.40', prl=[224]), dict(op='snapshot')])
    return dict(name=ident, helper=True, config='dhcp-optsfile={base}/opts\n',
        files={'opts': '224,old\n'}, events=[
            dict(op='snapshot'),
            dict(op='fifo-reload', path='opts', text='224,new\n', expire=True), dict(op='snapshot')])


def install_bank_hook():
    original_install = bank.install

    def install(root, scenario):
        folder = original_install(root, scenario)
        if scenario['name'] == 'dac49f3f':
            (root/'m2/family.leases').write_text(
                f'{int(time.time()) + 2} 02:00:00:00:00:09 127.0.0.29 expiring *\n')
        return folder
    bank.install = install

    def fifo(root, side, folder, event, process, endpoint, out, index):
        path = folder/event['path']
        path.unlink(missing_ok=True)
        os.mkfifo(path)
        # Open a reader through the real owner before opening the FIFO writer.
        # A second HUP below then arrives during the pending read.
        process.send_signal(signal.SIGHUP)
        writer = bank.fifo_writer(path)
        try:
            os.write(writer, event['text'].encode())
            if not event.get('expire'):
                # Live options are already pending when HUP requests scripts.
                process.send_signal(signal.SIGHUP)
            else:
                expiry = int((root/'m2/family.leases').read_text().split()[0])
                while int(time.time()) <= expiry:
                    time.sleep(.05)
                process.send_signal(signal.SIGALRM)
            # The owner must defer DHCP until EOF, then service the next input.
        finally:
            os.close(writer)
            path.unlink()
            path.write_text(event['text'])
        time.sleep(.3)
        return dict(alive=process.poll() is None, after_eof=bank.health())
    bank.fifo_reload = fifo


def selecting_case(root, side, out):
    """Two real primary addresses plus a wide overlapping tagged context."""
    from m2_rootfs import command, process_identity
    out.mkdir()
    for filename in ['selecting.leases', 'selecting.pid']:
        (root/'m2'/filename).unlink(missing_ok=True)
    primary = socket.inet_ntoa(bytes([192, 0, 1, 1]))
    relay = subprocess.Popen(['unshare', '--net', 'sh', '-c',
        'echo ready; exec sleep 90'], stdout=subprocess.PIPE, text=True)
    assert relay.stdout.readline().strip() == 'ready'
    relay_command = ['nsenter', '--net=/proc/' + str(relay.pid) + '/ns/net']
    subprocess.run(['ip', 'link', 'add', 'r3dns0', 'type', 'veth',
                    'peer', 'name', 'r3relay0'], check=True)
    subprocess.run(['ip', 'link', 'set', 'r3relay0', 'netns', str(relay.pid)], check=True)
    for address in [primary + '/24', '192.0.2.2/24']:
        subprocess.run(['ip', 'addr', 'add', address, 'dev', 'r3dns0'], check=True)
    subprocess.run(['ip', 'link', 'set', 'r3dns0', 'up'], check=True)
    for arguments in [['link', 'set', 'lo', 'up'],
                      ['link', 'set', 'r3relay0', 'up'],
                      ['addr', 'add', '192.0.2.254/24', 'dev', 'r3relay0'],
                      ['route', 'add', primary + '/32', 'dev', 'r3relay0']]:
        subprocess.run([*relay_command, 'ip', *arguments], check=True)
    config = ('no-hosts\nno-resolv\nuser=root\ngroup=root\nport=15353\ninterface=r3dns0\ninterface=lo\nno-ping\n'
        'host-record=health.test,192.0.2.7\ndhcp-authoritative\n'
        'dhcp-range=set:primary,192.0.2.10,192.0.2.20,255.255.0.0,600\n'
        'dhcp-range=set:secondary,192.0.2.10,192.0.2.20,255.255.255.0,600\n'
        'shared-network=192.0.2.254,192.0.2.1\ndhcp-ignore-names=tag:secondary\n'
        'dhcp-leasefile=/m2/selecting.leases\npid-file=/m2/selecting.pid\nlog-dhcp\n')
    (root/'m2/selecting.conf').write_text(config)
    (out/'config').write_text(config)
    log = (out/'daemon.log').open('wb')
    process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/selecting.conf'), stdout=log, stderr=log)
    result = dict(requests=[], topology=subprocess.check_output(['ip', '-j', 'addr'], text=True))
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                bank.health(); break
            except OSError:
                assert process.poll() is None, 'startup exit'
                time.sleep(.01)
        result['identity'] = process_identity(root, process.pid)
        # The relay owns port 67 in a separate namespace from the DHCP server.
        for n, override in enumerate([False, True]):
                event = dict(kind=3, address='192.0.2.15', server_id='192.0.2.2',
                    giaddr='192.0.2.254', prl=[12, 54], extra=[[12, b'override-host'.hex()]] +
                    ([[82, bytes([11, 4, 192, 0, 2, 2]).hex()]] if override else []))
                request = dhcp_wire.request(event, 0x63140000 + n)
                client = '''import json,socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
 endpoint.bind(('192.0.2.254',67));endpoint.settimeout(.6)
 endpoint.sendto(bytes.fromhex(sys.argv[1]),(sys.argv[2],67))
 try:
  response,peer=endpoint.recvfrom(4096)
 except socket.timeout:
  response,peer=None,None
 print(json.dumps(dict(response=response.hex() if response else None,peer=peer)))
'''
                observed = json.loads(subprocess.check_output(
                    [*relay_command, 'python3', '-c', client, request.hex(), primary], text=True))
                time.sleep(.05)
                leases = root/'m2/selecting.leases'
                result['requests'].append(dict(override=override, request=request.hex(),
                    response=observed['response'], peer=observed['peer'],
                    leases=leases.read_text() if leases.exists() else ''))
    finally:
        process.terminate(); process.wait(3); log.close(); result['exit'] = process.returncode
        subprocess.run(['ip', 'link', 'del', 'r3dns0'], check=True)
        relay.terminate(); relay.wait(3)
    save(out/'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--only', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--sides', nargs='+', choices=['base', 'candidate', 'isolated6324', 'd2', 'fix'])
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    out = args.output or args.scratch/'private'/args.only
    out.mkdir(parents=True, exist_ok=False)
    sides = args.sides or (['base', 'candidate', 'isolated6324'] if args.only == '6324' else ['base', 'candidate'])
    roots = {side: prepare(args.image_root, None, out/('image-'+side), args.scratch/'bin'/(side+'-image')) for side in sides}
    roots['c'] = prepare(args.image_root, None, out/'image-c',
                         args.scratch/'bin'/(sides[0]+'-image'))
    report = dict(case=args.only, rows=[], binary_sha256={s: sha256(args.scratch/'bin'/(s+'-image')) for s in sides})
    if args.only in ['6324', '9a646297', 'tcp65536', 'negative-expiry']:
        install_wire_hooks()
        cases = [c for c in wire_cases() if c['id'].startswith(args.only)]
        for case in cases:
            folder = out/case['id']; folder.mkdir()
            row = dict(id=case['id'], observations={}, facts={})
            for side in ['c', *sides]:
                observed = matrix.run_side(roots[side], 'c' if side == 'c' else 'rust', case, folder/side)
                row['observations'][side], row['facts'][side] = observed, wire_facts(observed)
            report['rows'].append(row); save(out/'result.json', report)
            print(case['id'], {s: row['facts'][s] == row['facts']['c'] for s in sides}, flush=True)
    elif args.only in ['805c2463', '7746362e', '05c560f1']:
        for side in ['c', *sides]:
            observations, close = hostname_lookup_fixture() if args.only == '05c560f1' else ([], lambda: None)
            try:
                observed = files.run_side(roots[side], 'c' if side == 'c' else 'rust', file_case(args.only), out/side)
                report['rows'].append(dict(side=side, observed=observed, resolver=observations))
            finally:
                close()
            save(out/'result.json', report)
            print(args.only, side, observed.get('exit'), observed.get('error'), flush=True)
    elif args.only in ['52c71105', 'dac49f3f']:
        install_bank_hook()
        for side in ['c', *sides]:
            observed = bank.run_side(roots[side], 'c' if side == 'c' else 'rust', bank_case(args.only), out/side)
            report['rows'].append(dict(side=side, observed=observed)); save(out/'result.json', report)
            print(args.only, side, observed.get('exit'), observed.get('error'), flush=True)
    elif args.only == '64fd2a2c':
        for side in ['c', *sides]:
            observed = selecting_case(roots[side], 'c' if side == 'c' else 'rust', out/side)
            report['rows'].append(dict(side=side, observed=observed)); save(out/'result.json', report)
            print(args.only, side, observed.get('exit'), flush=True)
    elif args.only == 'dhcp-duplicates':
        scenario = dict(name=args.only, config='dhcp-authoritative\ndhcp-rapid-commit\n'
            'dhcp-option=51,300\ndhcp-option=53,5b\ndhcp-option=54,192.0.2.99\n'
            'dhcp-option=option:rapid-commit\ndhcp-option=encap:54,1,2b\n', files={}, events=[
                dict(op='packet', label='offer', kind=1, prl=[51, 53, 54, 80]),
                dict(op='packet', label='ack', kind=3, address='127.0.0.30', prl=[51, 53, 54, 80]),
                dict(op='packet', label='rapid', kind=1, mac='020000000002', prl=[51, 53, 54, 80], extra=[[80, '']])])
        for side in ['c', *sides]:
            expected = copy.deepcopy(scenario)
            if side != 'c':
                for event in expected['events']:
                    event['no_reply'] = True
            observed = bank.run_side(roots[side], 'c' if side == 'c' else 'rust', expected, out/side)
            report['rows'].append(dict(side=side, observed=observed)); save(out/'result.json', report)
            print(args.only, side, observed.get('exit'), observed.get('error'), flush=True)
    else:
        raise ValueError('unknown experiment')
    save(out/'result.json', report)


if __name__ == '__main__':
    main()
