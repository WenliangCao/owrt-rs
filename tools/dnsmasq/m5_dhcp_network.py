#!/usr/bin/env python3
"""Ordinary DHCP network callers against the exact image in isolated namespaces.

The frozen manifest is the coverage gate. Selected/reference calibrations and
unimplemented callers never qualify an option; all raw failures are retained.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from dhcp_lease_lifecycle import packet
from dhcp_daemon_smoke import decode
from m2_rootfs import command, prepare, process_identity, sha256
from m5_helper import Side, capture, normalized
from dns_service_probe import query as dns_query, semantics as dns_semantics
from m5_pxe import request as pxe_request

HERE = Path(__file__).resolve().parent
IMAGE = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def required(plan, family):
    return {case for boundary in plan['boundaries'] if boundary['option'] == family for case in boundary['required_cases']}


def proxy_specs():
    return [
        dict(case='proxy-all-relays', config=['dhcp-proxy'], expected='127.0.0.2'),
        dict(case='proxy-address-match', config=['dhcp-proxy=127.0.0.2'], expected='127.0.0.2'),
        dict(case='proxy-address-miss', config=['dhcp-proxy=127.0.0.3'], expected='127.0.0.1'),
        dict(case='proxy-multiple-addresses', config=['dhcp-proxy=127.0.0.3,127.0.0.2'], expected='127.0.0.2'),
        dict(case='proxy-repeat-then-bare', config=['dhcp-proxy=127.0.0.3', 'dhcp-proxy'], expected='127.0.0.1'),
        dict(case='proxy-direct-no-override', config=['dhcp-proxy'], expected='127.0.0.1', giaddr='0.0.0.0'),
        dict(case='proxy-agent-override-wins', config=['dhcp-proxy'], expected='127.0.0.3', agent='127.0.0.3'),
        dict(case='proxy-agent-zero', config=['dhcp-proxy'], expected='127.0.0.2', agent='0.0.0.0'),
        dict(case='proxy-offer-ack', config=['dhcp-proxy'], expected='127.0.0.2', ack=True),
        dict(case='proxy-inform', config=['dhcp-proxy'], expected='127.0.0.2', kind=8),
        dict(case='proxy-relay-source-extension', config=['dhcp-proxy'], expected='127.0.0.1', giaddr='255.255.255.255'),
    ]


def shared_specs():
    return [
        dict(case='shared-local-address', config=['shared-network=127.0.0.1,198.18.0.1']),
        dict(case='shared-local-interface', config=['shared-network=lo,198.18.0.1']),
        dict(case='shared-unmatched', config=['shared-network=127.0.0.9,198.18.0.1'], no_reply=True),
        dict(case='shared-no-default-router', config=['shared-network=lo,198.18.0.1'], no_router=True),
        dict(case='shared-explicit-router', config=['shared-network=lo,198.18.0.1', 'dhcp-option=3,198.18.0.254'], router='198.18.0.254'),
        dict(case='shared-broadcast', config=['shared-network=lo,198.18.0.1'], broadcast='198.18.0.255'),
        dict(case='shared-duplicate-link', config=['shared-network=lo,198.18.0.1', 'shared-network=127.0.0.1,198.18.0.1']),
        dict(case='shared-context-order', config=['shared-network=lo,198.18.0.1', 'shared-network=lo,198.18.1.1', 'dhcp-sequential-ip'], second_range=True, address='198.18.0.10', requested=False),
        dict(case='shared-secondary-enumeration', config=['shared-network=127.0.0.3,198.18.0.1'], secondary=True, expected='127.0.0.3'),
        dict(case='shared-interface-index-fixed', config=['shared-network=nwshare,198.18.0.1'], index_fixed=True, expected='198.19.0.1'),
        dict(case='shared-relay-address', config=['shared-network=127.0.0.2,198.18.0.1'], relay=True),
        dict(case='shared-relay-subnet-selector', config=['shared-network=127.0.0.2,198.18.0.1'], relay=True, subnet='203.0.113.1'),
        dict(case='shared-interface-not-relay', config=['shared-network=lo,198.18.0.1'], relay=True, no_reply=True),
        dict(case='shared-direct-renewal', config=[], kind=3, renew=True),
    ]


def shared_exchange(endpoint, folder, spec, xid):
    kind = spec.get('kind', 1)
    requested = spec.get('requested', True)
    address = spec.get('address', '198.18.0.10')
    request = bytearray(packet(kind, xid, 1, address if requested else None, False))
    # Include broadcast explicitly in the PRL so context completion is visible.
    offset = request.index(bytes([55, 6]), 240)
    request[offset + 1] = 7
    request[offset + 2:offset + 2] = bytes([28])
    if spec.get('relay'):
        request[24:28] = socket.inet_aton('127.0.0.2')
    if spec.get('subnet'):
        request[-1:] = bytes([118, 4]) + socket.inet_aton(spec['subnet']) + b'\xff'
    (folder / f'{xid}.request').write_bytes(request)
    endpoint.sendto(request, ('127.0.0.1', 67))
    if spec.get('no_reply'):
        endpoint.settimeout(.5)
        try:
            reply = endpoint.recv(16384)
        except socket.timeout:
            return dict(kind=kind, wire=None)
        raise AssertionError('unmatched shared network produced an OFFER: ' + reply.hex())
    reply, peer = endpoint.recvfrom(16384)
    (folder / f'{xid}.reply').write_bytes(reply)
    values = decode(reply, xid)
    assert values[53] == bytes([2 if kind == 1 else 5]), 'shared context OFFER/ACK'
    assert values[54] == socket.inet_aton(spec.get('expected', '127.0.0.1')), 'selected shared context server ID'
    assert reply[16:20] == socket.inet_aton(address), 'shared context allocation/order'
    if spec.get('no_router'): assert 3 not in values, 'shared context invented a default router'
    if spec.get('router'): assert values[3] == socket.inet_aton(spec['router']), 'explicit shared router option'
    if spec.get('broadcast'): assert values[28] == socket.inet_aton(spec['broadcast']), 'shared context broadcast'
    if spec.get('renew'):
        from m5_dhcp_tags_options import comparable_reply
        wire = comparable_reply(reply, dict(kind=3, renew=True, requested_address=False, server_id=None, ciaddr=address))
    else:
        wire = reply.hex()
    return dict(kind=kind, wire=wire, peer=list(peer))


def shared_case(root, side, out, spec):
    folder = out / spec['case']; folder.mkdir()
    runner = Side(root, side, folder, spec['case'], ['bind-interfaces', *spec['config']])
    config = runner.config.read_text().replace('dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m',
        'dhcp-range=198.18.0.10,198.18.0.20,255.255.255.0,10m')
    if spec.get('second_range'):
        config += 'dhcp-range=198.18.1.10,198.18.1.20,255.255.255.0,10m\n'
    runner.config.write_text(config)
    if spec.get('secondary'):
        subprocess.run(['ip', 'addr', 'add', '127.0.0.3/8', 'dev', 'lo'], check=True)
    if spec.get('renew'):
        subprocess.run(['ip', 'link', 'add', 'nwclient', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'link', 'set', 'nwclient', 'up'], check=True)
        subprocess.run(['ip', 'addr', 'add', '198.18.0.10/24', 'dev', 'nwclient'], check=True)
    if spec.get('index_fixed'):
        subprocess.run(['ip', 'link', 'add', 'nwshare', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'link', 'set', 'nwshare', 'up'], check=True)
        subprocess.run(['ip', 'addr', 'add', '198.19.0.1/24', 'dev', 'nwshare'], check=True)
    try:
        runner.start()
        save(folder / 'identity.json', process_identity(root, runner.process.pid))
        if spec.get('renew'):
            runner.client.close()
            runner.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            runner.client.bind(('198.18.0.10', 68)); runner.client.settimeout(3)
        endpoint = runner.client
        if spec.get('relay'):
            endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            endpoint.bind(('127.0.0.2', 67)); endpoint.settimeout(3)
        try:
            packets = [shared_exchange(endpoint, folder, spec, 0x7910)]
            if spec.get('index_fixed'):
                subprocess.run(['ip', 'link', 'del', 'nwshare'], check=True)
                subprocess.run(['ip', 'link', 'add', 'nwshare', 'type', 'dummy'], check=True)
                subprocess.run(['ip', 'link', 'set', 'nwshare', 'up'], check=True)
                subprocess.run(['ip', 'addr', 'add', '198.19.0.1/24', 'dev', 'nwshare'], check=True)
                packets.append(shared_exchange(endpoint, folder, {**spec, 'no_reply':True}, 0x7911))
            assert runner.dns(), 'DNS remains healthy after shared caller'
            return dict(case=spec['case'], packets=packets)
        finally:
            if endpoint is not runner.client: endpoint.close()
    finally:
        cleanup = runner.stop(); save(folder / 'cleanup.json', cleanup)
        if spec.get('secondary'):
            subprocess.run(['ip', 'addr', 'del', '127.0.0.3/8', 'dev', 'lo'], check=True)
        if spec.get('index_fixed'):
            subprocess.run(['ip', 'link', 'del', 'nwshare'], check=True)
        if spec.get('renew'):
            subprocess.run(['ip', 'link', 'del', 'nwclient'], check=True)
        assert cleanup['exit'] == 0 and not cleanup['forced'] and not cleanup['remaining'], 'shared service cleanup'


def ip(*args):
    subprocess.run(['ip', *map(str, args)], check=True, capture_output=True)


def bridge_specs():
    return [
        dict(case='bridge-exact-alias', bridges=['nwmaster,nwport']),
        dict(case='bridge-wildcard-alias', bridges=['nwmaster,nwp*']),
        dict(case='bridge-multiple-aliases', bridges=['nwmaster,other,nwport']),
        dict(case='bridge-repeated-master', bridges=['nwmaster,other', 'nwmaster,nwport']),
        dict(case='bridge-later-master', bridges=['nwmaster,nwport', 'nwsecond,nwport'], second=True, expected='198.18.0.2'),
        dict(case='bridge-unmatched', bridges=['nwmaster,other'], no_reply=True),
        dict(case='bridge-master-missing', bridges=['unknown,nwport'], no_reply=True, warning=True),
        dict(case='bridge-master-added', bridges=['nwmaster,nwport'], added=True),
        dict(case='bridge-interface-policy', bridges=['nwmaster,nwport'], no_reply=True, extra=['except-interface=nwmaster']),
        dict(case='bridge-original-reply-interface', bridges=['nwmaster,nwport'], unicast=True),
        dict(case='bridge-helper-effective-interface', bridges=['nwmaster,nwport'], ack=True),
    ]


def create_master(name, address):
    ip('link', 'add', name, 'type', 'dummy')
    ip('link', 'set', name, 'up')
    ip('addr', 'add', address + '/24', 'dev', name)


def checksum(data):
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16: value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def bridge_exchange(endpoint, folder, spec, xid, kind=1, no_reply=False):
    address = '198.18.0.10'
    request = bytearray(packet(kind, xid, 1, address, kind == 3))
    hardware = bytes.fromhex('020000009401')
    request[28:34] = hardware
    if spec.get('unicast'): request[10:12] = b'\0\0'
    if kind == 3:
        offset = request.index(bytes([54, 4]), 240) + 2
        request[offset:offset + 4] = socket.inet_aton(spec.get('expected', '198.18.0.1'))
    udp = struct.pack('!HHHH', 68, 67, len(request) + 8, 0) + request
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20, xid & 0xffff, 0, 64, 17, 0, b'\0'*4, b'\xff'*4))
    header[10:12] = struct.pack('!H', checksum(header))
    frame = b'\xff'*6 + hardware + b'\x08\0' + header + udp
    (folder / f'{xid}.request').write_bytes(frame)
    endpoint.send(frame)
    deadline = time.monotonic() + (.5 if no_reply else 3)
    while time.monotonic() < deadline:
        endpoint.settimeout(deadline - time.monotonic())
        try: received = endpoint.recv(65535)
        except socket.timeout:
            if no_reply: return dict(kind=kind, wire=None)
            raise
        if len(received) < 282 or received[12:14] != b'\x08\0' or received[23] != 17: continue
        offset = 14 + (received[14] & 15) * 4
        source, destination, size = struct.unpack_from('!HHH', received, offset)
        reply = received[offset + 8:offset + size]
        if (source, destination) != (67, 68) or len(reply) < 240 or reply[4:8] != struct.pack('!I', xid): continue
        if no_reply: raise AssertionError('unmatched bridge request received a reply')
        values = decode(reply, xid)
        assert values[53] == bytes([2 if kind == 1 else 5]), 'bridge OFFER/ACK'
        assert reply[16:20] == socket.inet_aton(address), 'bridge master context allocation'
        assert values[54] == socket.inet_aton(spec.get('expected', '198.18.0.1')), 'effective bridge master server ID'
        (folder / f'{xid}.reply-frame').write_bytes(received)
        (folder / f'{xid}.reply').write_bytes(reply)
        if spec.get('unicast'):
            assert received[:6] == hardware, 'original physical alias ARP MAC/output interface'
        return dict(kind=kind, wire=reply.hex(), physical_interface='nwpeer')
    raise AssertionError('bridge exchange deadline')


def bridge_case(root, side, out, spec):
    folder = out / spec['case']; folder.mkdir()
    ip('link', 'add', 'nwport', 'type', 'veth', 'peer', 'name', 'nwpeer')
    ip('link', 'set', 'nwport', 'up'); ip('link', 'set', 'nwpeer', 'up')
    if not spec.get('added'): create_master('nwmaster', '198.18.0.1')
    if spec.get('second'): create_master('nwsecond', '198.18.0.2')
    if spec.get('unicast'): ip('route', 'add', '198.18.0.10/32', 'dev', 'nwport', 'scope', 'link')
    flags = ['bind-interfaces', *['bridge-interface='+value for value in spec['bridges']], *spec.get('extra', [])]
    runner = Side(root, side, folder, spec['case'], flags)
    config = runner.config.read_text().replace('listen-address=127.0.0.1\n', '').replace('dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', 'dhcp-range=198.18.0.10,198.18.0.20,255.255.255.0,10m')
    runner.config.write_text(config)
    (folder / 'config').write_text(config)
    try:
        runner.start()
        save(folder / 'identity.json', process_identity(root, runner.process.pid))
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as endpoint:
            endpoint.bind(('nwpeer', 0))
            packets = []
            if spec.get('added'):
                packets.append(bridge_exchange(endpoint, folder, spec, 0x7920, no_reply=True))
                create_master('nwmaster', '198.18.0.1')
            packets.append(bridge_exchange(endpoint, folder, spec, 0x7921, no_reply=spec.get('no_reply', False)))
            if spec.get('ack'):
                packets.append(bridge_exchange(endpoint, folder, spec, 0x7922, kind=3))
                deadline = time.monotonic() + 2
                while not capture(runner.events) and time.monotonic() < deadline: time.sleep(.01)
                records = capture(runner.events)
                save(folder / 'helper-records.json', normalized(records, runner.start_epoch, time.time()))
                assert records and bytes.fromhex(records[0]['env']['DNSMASQ_INTERFACE']) == b'nwmaster', 'actual helper effective bridge interface'
            if spec.get('unicast'):
                observed = subprocess.run(['ip', '-j', 'neigh', 'show', 'dev', 'nwport'], check=True, capture_output=True).stdout
                (folder / 'physical-neighbors.json').write_bytes(observed)
                assert any(row.get('dst') == '198.18.0.10' and row.get('lladdr') == '02:00:00:00:94:01' for row in json.loads(observed)), 'ARP entry used the logical master instead of received physical alias'
            if spec.get('warning'):
                runner.log.flush()
                logged = (folder / (side+'-'+spec['case']+'.log')).read_bytes()
                assert b'unknown interface unknown in bridge-interface' in logged, 'runtime missing master warning'
        assert runner.dns(), 'DNS progresses after bridge caller'
        return dict(case=spec['case'], packets=packets)
    finally:
        cleanup = runner.stop(); save(folder / 'cleanup.json', cleanup)
        for name in ['nwport', 'nwmaster', 'nwsecond']:
            subprocess.run(['ip', 'link', 'del', name], capture_output=True)
        assert cleanup['exit'] == 0 and not cleanup['forced'] and not cleanup['remaining'], 'bridge service cleanup'


def delay_specs():
    mac = 'dhcp-mac=set:slow,02:00:00:00:00:01'
    return [
        dict(case='delay-zero', config=['dhcp-reply-delay=0'], delayed=False),
        dict(case='delay-global', config=['dhcp-reply-delay=1'], delayed=True),
        dict(case='delay-tag-match', config=[mac, 'dhcp-reply-delay=tag:slow,1'], delayed=True),
        dict(case='delay-tag-miss', config=['dhcp-reply-delay=tag:slow,1'], delayed=False),
        dict(case='delay-negated-tag', config=['dhcp-reply-delay=tag:!fast,1'], delayed=True),
        dict(case='delay-tag-before-fallback', config=[mac, 'dhcp-reply-delay=tag:slow,1', 'dhcp-reply-delay=0'], delayed=True),
        dict(case='delay-range-tag', config=['dhcp-range=set:slow,127.0.0.10,127.0.0.20,255.0.0.0,10m', 'dhcp-reply-delay=tag:slow,1'], delayed=True),
        dict(case='delay-tag-if', config=[mac, 'tag-if=tag:slow,set:derived', 'dhcp-reply-delay=tag:derived,1'], delayed=True),
        dict(case='delay-request-ack-bypass', config=['dhcp-reply-delay=1'], delayed=True, ack=True),
        dict(case='delay-inform-bypass', config=['dhcp-reply-delay=1'], delayed=False, kind=8),
        dict(case='delay-bootp-bypass', config=['dhcp-reply-delay=1', 'dhcp-host=02:00:00:00:00:01,127.0.0.10,client1,10m'], delayed=False, kind=0),
        dict(case='delay-rapid-commit', config=['dhcp-reply-delay=1', 'dhcp-rapid-commit'], delayed=True, rapid=True),
        dict(case='delay-proxy-offer', config=['dhcp-reply-delay=1', 'pxe-service=x86PC,Network boot,boot'], delayed=True, proxy=True),
        dict(case='delay-proxy-ack', config=['dhcp-reply-delay=1', 'pxe-service=x86PC,Network boot,boot'], delayed=True, proxy=True, kind=3),
        dict(case='delay-dns-tftp-progress', config=['dhcp-reply-delay=1'], delayed=True, progress=True),
        dict(case='delay-queued-dhcp-term', config=['dhcp-reply-delay=1'], delayed=True, term=True),
    ]


def delay_packet(spec, xid, kind=None):
    kind = spec.get('kind', 1) if kind is None else kind
    if spec.get('proxy'):
        request = bytearray(pxe_request(kind=kind, ciaddr='127.0.0.10' if kind == 3 else '0.0.0.0'))
        request[4:8] = struct.pack('!I', xid)
    else:
        request = bytearray(packet(kind, xid, 1, None if kind == 0 else '127.0.0.10', kind == 3))
    if spec.get('rapid'): request[-1:] = b'\x50\0\xff'
    return request


def lease_dns(folder, label):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.4)
        request = dns_query('client1.lan')
        endpoint.sendto(request, ('127.0.0.1', 15353))
        reply = endpoint.recv(4096)
        (folder / (label+'.dns.request')).write_bytes(request)
        (folder / (label+'.dns.reply')).write_bytes(reply)
        return [row['data'] for row in dns_semantics(reply)['records'] if row['section'] == 'answer' and row['type'] == 1]


def delay_exchange(runner, folder, spec, xid=0x7930, kind=None):
    request = delay_packet(spec, xid, kind)
    endpoint = runner.client
    (folder / f'{xid}.request').write_bytes(request)
    start = time.monotonic()
    endpoint.sendto(request, ('127.0.0.1', 67))
    controls = {}
    if spec.get('rapid'):
        time.sleep(.1)
        controls['lease_before_commit'] = lease_dns(folder, 'before-rapid')
        assert controls['lease_before_commit'] == [], 'rapid commit published its lease while C is still in reply delay'
    if spec.get('progress'):
        before = time.monotonic()
        for _ in range(5): assert runner.dns(), 'DNS blocked behind DHCP delay'
        controls['dns_progress'] = True
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tftp:
            tftp.settimeout(.4)
            tftp.sendto(b'\0\1evidence\0octet\0', ('127.0.0.1', 69))
            reply, peer = tftp.recvfrom(4096)
            assert reply == b'\0\3\0\1delay-evidence', 'TFTP did not progress inside the DHCP delay'
            (folder / 'during-delay.tftp.reply').write_bytes(reply)
            tftp.sendto(b'\0\4\0\1', peer)
        assert time.monotonic() - before < .75, 'services progressed only after DHCP delay'
        controls['tftp_progress'] = True
    if spec.get('term'):
        import signal
        deadline = time.monotonic() + .5
        log = folder / (runner.side+'-'+runner.name+'.log')
        while b'reply delay: 1' not in log.read_bytes() and time.monotonic() < deadline: time.sleep(.005)
        assert b'reply delay: 1' in log.read_bytes(), 'TERM control requires an actually entered delay'
        second = packet(1, xid+1, 2, '127.0.0.11')
        (folder / 'queued-second.request').write_bytes(second)
        endpoint.sendto(second, ('127.0.0.1', 67))
        os.kill(runner.process.pid, signal.SIGTERM)
        time.sleep(.1)
        assert runner.process.poll() is None, 'reply delay consumed TERM before finishing its borrowed DHCP packet'
        controls['parent_alive_during_delay'] = True
    reply, peer = endpoint.recvfrom(16384)
    elapsed = time.monotonic() - start
    (folder / f'{xid}.reply').write_bytes(reply)
    save(folder / f'{xid}.timing.json', dict(elapsed=elapsed, peer=list(peer)))
    values = decode(reply, xid)
    original_kind = spec.get('kind', 1) if kind is None else kind
    if original_kind == 0:
        assert 53 not in values, 'BOOTP delay bypass reply became DHCP'
    else:
        assert values[53] == bytes([5 if spec.get('rapid') or original_kind != 1 else 2]), 'delayed DHCP reply kind'
    delayed = spec['delayed'] if kind is None else False
    assert .75 <= elapsed < 2.8 if delayed else elapsed < .5, 'actual reply delay interval/caller gate'
    if spec.get('rapid'):
        controls['lease_after_commit'] = lease_dns(folder, 'after-rapid')
        assert controls['lease_after_commit'] == ['127.0.0.10'], 'rapid lease commit never reached DNS'
    if spec.get('term'):
        assert runner.process.wait(3) == 0, 'TERM after delayed response'
        endpoint.settimeout(.25)
        try:
            second = endpoint.recv(16384)
        except socket.timeout:
            controls['second_dhcp_deferred'] = True
        else:
            raise AssertionError('queued DHCP request ran before pending TERM: '+second.hex())
    return dict(kind=original_kind, wire=reply.hex(), delayed=delayed, controls=controls)


def delay_case(root, side, out, spec):
    folder = out / spec['case']; folder.mkdir()
    runner = Side(root, side, folder, spec['case'], ['bind-interfaces', *spec['config']])
    if spec.get('proxy'):
        config = runner.config.read_text().replace('dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', 'dhcp-range=127.0.0.0,proxy,255.0.0.0')
        runner.config.write_text(config)
    if spec.get('progress'):
        data = runner.folder / 'tftp'; data.mkdir()
        (data / 'evidence').write_bytes(b'delay-evidence')
        runner.config.write_text(runner.config.read_text()+'enable-tftp\ntftp-root='+runner.inside+'/tftp\n')
    (folder / 'config').write_text(runner.config.read_text())
    try:
        runner.start()
        save(folder / 'identity.json', process_identity(root, runner.process.pid))
        packets = [delay_exchange(runner, folder, spec)]
        if spec.get('ack'): packets.append(delay_exchange(runner, folder, spec, 0x7932, kind=3))
        return dict(case=spec['case'], packets=packets)
    finally:
        cleanup = runner.stop(); save(folder / 'cleanup.json', cleanup)
        assert cleanup['exit'] == 0 and not cleanup['forced'] and not cleanup['remaining'], 'reply delay cleanup'


def exchange(endpoint, runner, folder, spec, kind=1, xid=0x7901):
    request = bytearray(packet(kind, xid, 1, '127.0.0.10', kind == 3))
    request[24:28] = socket.inet_aton(spec.get('giaddr', '127.0.0.2'))
    if kind == 3:
        # Replace the selecting server-id with the observed OFFER policy.
        position = request.index(bytes([54, 4]), 240) + 2
        request[position:position + 4] = socket.inet_aton(spec['expected'])
    if spec.get('agent') is not None:
        request[-1:] = bytes([82, 6, 11, 4]) + socket.inet_aton(spec['agent']) + b'\xff'
    (folder / f'{kind}.request').write_bytes(request)
    start = time.monotonic()
    endpoint.sendto(request, ('127.0.0.1', 67))
    reply, peer = endpoint.recvfrom(16384)
    elapsed = time.monotonic() - start
    values = decode(reply, xid)
    assert values[53] == bytes([2 if kind == 1 else 5]), 'actual OFFER/ACK/INFORM response'
    assert values[54] == socket.inet_aton(spec['expected']), 'actual server identifier override'
    (folder / f'{kind}.reply').write_bytes(reply)
    save(folder / f'{kind}.timing.json', dict(elapsed=elapsed, peer=list(peer)))
    return dict(kind=kind, wire=reply.hex(), peer=list(peer))


def proxy_case(root, side, out, spec):
    folder = out / spec['case']; folder.mkdir()
    runner = Side(root, side, folder, spec['case'], ['bind-interfaces', *spec['config']])
    save(folder / 'config.json', dict(lines=runner.config.read_text().splitlines()))
    try:
        runner.start()
        save(folder / 'identity.json', process_identity(root, runner.process.pid))
        direct = spec.get('giaddr') == '0.0.0.0'
        endpoint = runner.client if direct else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if not direct:
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            endpoint.bind(('127.0.0.2', 67)); endpoint.settimeout(3)
        try:
            packets = [exchange(endpoint, runner, folder, spec, spec.get('kind', 1))]
            if spec.get('ack'):
                packets.append(exchange(endpoint, runner, folder, spec, 3, 0x7902))
                leases = runner.leasefile.read_bytes()
                (folder / 'accepted-lease.raw').write_bytes(leases)
                assert b'02:00:00:00:00:01 127.0.0.10 client1' in leases, 'actual accepted proxy ACK lease'
            return dict(case=spec['case'], packets=packets)
        finally:
            if not direct: endpoint.close()
    finally:
        cleanup = runner.stop(); save(folder / 'cleanup.json', cleanup)
        assert cleanup['exit'] == 0 and not cleanup['forced'] and not cleanup['remaining'], 'service cleanup'


def run_side(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1', 'run_isolated.sh required'
    args.out.mkdir(parents=True, exist_ok=False)
    plan = json.loads((HERE / 'm5_dhcp_network.json').read_text())
    save(args.out / 'plan.json', plan)
    root = prepare(args.image_root, None, args.out / 'filesystem', args.rust)
    rows, failures = [], []
    syntaxes = {
        'dhcp-proxy': [('proxy-syntax-file', ['dhcp-proxy=127.0.0.2,127.0.0.3'], []),
                       ('proxy-syntax-cli', [], ['--dhcp-proxy=127.0.0.2'])],
        'dhcp-reply-delay': [('delay-syntax-file', ['dhcp-reply-delay=tag:slow,1'], []),
                             ('delay-syntax-cli', [], ['--dhcp-reply-delay=1']),
                             ('delay-syntax-repeat', ['dhcp-reply-delay=2', 'dhcp-reply-delay=0'], [])],
        'bridge-interface': [('bridge-syntax-file', ['bridge-interface=master,port*'], []),
                             ('bridge-syntax-cli', [], ['--bridge-interface=master,port*'])],
        'shared-network': [('shared-syntax-address', ['shared-network=127.0.0.1,198.18.0.1'], []),
                           ('shared-syntax-interface', ['shared-network=lo,198.18.0.1'], []),
                           ('shared-syntax-cli', [], ['--shared-network=lo,198.18.0.1'])],
    }
    for label, lines, flags in syntaxes.get(args.family, []):
        folder = args.out / label; folder.mkdir()
        (root / 'm2/network.conf').write_text('\n'.join(lines) + '\n')
        result = subprocess.run(command(root, args.side, '--test', '-C', '/m2/network.conf', *flags), capture_output=True, timeout=4)
        (folder / 'stdout').write_bytes(result.stdout); (folder / 'stderr').write_bytes(result.stderr)
        if result.returncode:
            failures.append(dict(case=label, error='ordinary syntax rejected', exit=result.returncode))
        rows.append(dict(case=label, exit=result.returncode, stdout=result.stdout.hex(), stderr=result.stderr.replace(b'dnsmasq-rs', b'dnsmasq').hex()))
    specs, run_case = (proxy_specs(), proxy_case) if args.family == 'dhcp-proxy' else (shared_specs(), shared_case) if args.family == 'shared-network' else (bridge_specs(), bridge_case) if args.family == 'bridge-interface' else (delay_specs(), delay_case) if args.family == 'dhcp-reply-delay' else ([], None)
    for spec in specs:
        try:
            rows.append(run_case(root, args.side, args.out, spec))
        except Exception as error:
            failed = dict(case=spec['case'], error=repr(error)); failures.append(failed)
            save(args.out / spec['case'] / 'failure.json', failed)
    needed = required(plan, args.family)
    result = dict(side=args.side, family=args.family, rows=rows, failures=failures,
                  missing=sorted(needed - {row['case'] for row in rows}), qualified=False,
                  binary_sha256=sha256(args.image_root / 'usr/sbin/dnsmasq' if args.side == 'c' else args.rust))
    save(args.out / 'result.json', result)
    print(json.dumps(dict(side=args.side, executed=len(rows), missing=len(result['missing']), failures=failures)))
    return bool(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--side', choices=['c', 'rust', 'both'], default='both')
    parser.add_argument('--family', choices=['dhcp-proxy', 'bridge-interface', 'shared-network', 'dhcp-reply-delay'], required=True)
    args = parser.parse_args()
    if args.side != 'both': return run_side(args)
    args.out.mkdir(parents=True, exist_ok=False)
    exits = {}
    for side in ['c', 'rust']:
        with (args.out / (side + '.launch.log')).open('wb') as output:
            exits[side] = subprocess.run(['sh', str(HERE / 'run_isolated.sh'), sys.executable, __file__, '--side', side,
                '--family', args.family, '--image-root', str(args.image_root), '--rust', str(args.rust), '--out', str(args.out / side)], stdout=output, stderr=output).returncode
    reports = [json.loads((args.out / side / 'result.json').read_text()) for side in ['c', 'rust']]
    failures = []
    if any(exits.values()) or any(report['failures'] for report in reports): failures.append(dict(exits=exits, sides=[report['failures'] for report in reports]))
    if reports[0]['rows'] != reports[1]['rows']: failures.append(dict(error='ordinary exact-image observation difference', c=reports[0]['rows'], rust=reports[1]['rows']))
    controls = []
    if not failures:
        for label in ['missing-case', 'wrong-server-id', 'wrong-packet', 'fixture-failure']:
            mutant = copy.deepcopy(reports[1])
            if label == 'missing-case': mutant['rows'].pop()
            elif label == 'fixture-failure': mutant['failures'].append(dict(injected=True))
            else:
                observed = next(row for row in mutant['rows'] if row.get('packets'))['packets'][0]
                wire = bytearray.fromhex(observed['wire'])
                if label == 'wrong-server-id':
                    offset = wire.index(bytes([54, 4]), 240) + 2
                    wire[offset:offset + 4] = socket.inet_aton('127.0.0.99')
                else:
                    wire[24] ^= 1
                observed['wire'] = wire.hex()
            controls.append(dict(case=label, rejected=mutant['rows'] != reports[0]['rows'] or bool(mutant['failures'])))
    qualified = not failures and not any(report['missing'] for report in reports) and len(controls) == 4 and all(control['rejected'] for control in controls)
    save(args.out / 'result.json', dict(family=args.family, qualified=qualified, failures=failures, controls=controls,
         missing={report['side']:report['missing'] for report in reports}, binary_sha256=sha256(args.rust)))
    print(json.dumps(dict(family=args.family, qualified=qualified, paired=len(reports[0]['rows']), failures=len(failures))))
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
