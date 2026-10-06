#!/usr/bin/env python3
"""TFTP family comparison against the exact image ELF in disposable namespaces.

Run through run_isolated.sh. Fixed private bridge/veth endpoints only; the tool
accepts no network target. It reuses the M2 image-root and process cleanup tools.
Raw replies and every unsuccessful run stay in evidence/M5/tftp. The directed
parser cases are bounded corruptions of an ordinary local read request; no
real-file traversal, out-of-bounds C reproductions or external services are used.
Optional reference witnesses use only tiny synthetic files inside the fixture;
they are separately classified and never relax the normal comparator.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import resource
import socket
import struct
import subprocess
import sys
import time

from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import Network, SERVER, CLIENT, ip, save, stop

V6_SERVER = 'fd42:77::1'
V6_CLIENT = 'fd42:77::2'
ROOT = '/m2/tftp'
MAC = CLIENT['mac'].replace(':', '-')
LEASE_MAC = '02:00:00:4d:34:fe'
CAPTURE = '''#!/bin/sh
printf '%s|%s|%s|%s\\n' "$1" "$2" "$3" "$4" >> /m2/tftp-events
'''


def scenarios():
    base = 'enable-tftp\ntftp-root=' + ROOT + '/global\n'
    cases = [
        dict(name='ordinary-dual-stack', config=base, requests=[{}, {'v6': True}, {'mode': 'netascii'}]),
        dict(name='dedicated-interface', config=base.replace('enable-tftp\n', 'enable-tftp=br-lan\n'), requests=[{}, {'v6': True}]),
        dict(name='excluded-interface', config=base.replace('enable-tftp\n', 'enable-tftp=absent0\n'), requests=[{'silent': True}, {'v6': True, 'silent': True}]),
        dict(name='interface-root-earliest', config=base+'tftp-root='+ROOT+'/first,br-lan\ntftp-root='+ROOT+'/last,br-lan\n', requests=[{}, {'v6': True}]),
        dict(name='unique-ip', config=base+'tftp-unique-root=ip\n', requests=[{}, {'v6': True}]),
        dict(name='unique-mac', config=base+'tftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='unique-ip-and-mac', config=base+'tftp-unique-root=ip\ntftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='unique-missing-fallback', config=base.replace('/global', '/first')+'tftp-unique-root=ip\ntftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='lowercase', config=base+'tftp-lowercase\n', requests=[{'filename': 'BOOT.BIN'}]),
        dict(name='secure-ownership', config=base+'tftp-secure\n', requests=[{'filename': 'owned.bin'}, {'filename': 'root.bin'}]),
        dict(name='negotiation-mtu', config=base+'tftp-mtu=1200\n', requests=[{'options': {'blksize': '2000', 'tsize': '0', 'timeout': '2', 'windowsize': '1'}}, {'v6': True, 'options': {'blksize': '2000'}}]),
        dict(name='no-blocksize', config=base+'tftp-no-blocksize\n', requests=[{'options': {'blksize': '128', 'tsize': '0'}}]),
        dict(name='single-port', binding='', config=base+'tftp-single-port\n', requests=[{'single': True}, {'single': True, 'v6': True}]),
        dict(name='port-range', config=base+'tftp-port-range=35000,35003\n', requests=[{'range': [35000, 35003]}, {'range': [35000, 35003], 'v6': True}]),
        dict(name='missing-root-fails', config=base.replace('/global', '/missing'), requests=[], startup_failure=True),
        dict(name='missing-root-no-fail', config=base.replace('/global', '/missing')+'tftp-no-fail\n', requests=[{}]),
        dict(name='sighup-live-transfer', config=base, requests=[{'hold': True}]),
        dict(name='directed-parser-corpus', config=base, requests=[{'corpus': True}]),
        dict(name='unique-mac-lease-preferred', config=base+'tftp-unique-root=mac\n', lease_mac=LEASE_MAC, requests=[{}]),
        dict(name='unique-mac-nonether-lease-fallback', config=base+'tftp-unique-root=mac\n', lease_mac='06-'+LEASE_MAC, requests=[{}]),
        dict(name='completion-script-once', config=base+'dhcp-script=/m2/tftp-capture\n', callbacks=2,
             requests=[{'duplicate_final_ack': True}, {'v6': True}]),
        dict(name='incomplete-script-not-called', config=base+'dhcp-script=/m2/tftp-capture\n', callbacks=0,
             requests=[{'abort': True}, {'abandon': True}, {'filename': 'absent.bin', 'error': True}]),
        dict(name='final-ack-timeout-script-once', config=base+'dhcp-script=/m2/tftp-capture\n', callbacks=1,
             callback_wait=125, requests=[{'abandon': True}, {'filename': 'owned.bin', 'abandon': True}]),
        dict(name='no-fail-bind-error', config=base+'tftp-no-fail\n', bind_blocker=True,
             requests=[], startup_failure=True),
    ]
    for single in (False, True):
        for maximum in (0, 1):
            cases.append(dict(name=f'capacity-{"single" if single else "dedicated"}-{maximum}',
                              config=base+f'tftp-max={maximum}\n'+('tftp-single-port\n' if single else ''),
                              binding='' if single else 'bind-interfaces\n',
                              requests=[{'capacity': maximum if single else maximum+1, 'single': single}]))
    cases.extend([
        dict(name='capacity-dedicated-fd40', config=base, nofile=40,
             requests=[{'capacity': 6, 'single': False}]),
        dict(name='capacity-single-fd40', config=base+'tftp-single-port\n', binding='', nofile=40,
             requests=[{'capacity': 0, 'single': True}]),
    ])
    return cases


# Source-derived checklist is recorded in plan.json before any daemon starts.
# Deliberate reference differences are not normal-case equivalence passes.
REFERENCE_SOURCE = {
    'path': 'dnsmasq-2.93/src/tftp.c',
    'sha256': 'a6971bf4ce77c0ca4c7ebf0194a2ee9c2ad702b1b8a882d46de87c6c6f5e63f3',
}
REFERENCE_FILES = {'boot.bin': b'synthetic boot\n', 'alternate.bin': b'synthetic alternate\n'}
REFERENCE_CHECKLIST = [
    {'id': 'fresh-data', 'source': 'tftp.c:247-277,305-309,963-971,1020-1022',
     'boundary': 'Two ordinary same-peer RRQs replace the active transfer; C caches old DATA, Rust sends the requested tiny alternate file.',
     'scenarios': ['reference-single-replace-v4', 'reference-single-replace-v6']},
    {'id': 'file-release', 'source': 'tftp.c:260-263,305-309,588-610,1029-1039',
     'boundary': 'After final ACK and queue drain C retains the old synthetic boot FD; Rust retains no fixture FD.',
     'scenarios': ['reference-single-replace-v4', 'reference-single-replace-v6']},
    {'id': 'parent-component', 'source': 'tftp.c:432-439,487-498,547-556',
     'boundary': 'A harmless ..safe/../boot.bin path stays within synthetic root; first textual /.. match misses its later parent component in C; Rust rejects.',
     'scenarios': ['reference-root-parent-component']},
    {'id': 'bound-ipv4-source', 'source': 'tftp.c:63-66,100-119,198-201,320,522',
     'boundary': 'Bound IPv4 single-port reads uninitialized addra. Undefined reference behavior is excluded, not reproduced or accepted as an expectation.',
     'status': 'excluded-undefined-behavior',
     'prior_witness': 'docs/dnsmasq/TFTP_SINGLE_PORT_PHASE.md; private/dnsmasq-rewrite/tftp-listener-tid-20260930/run-06/'},
    {'id': 'zero-block-mtu', 'source': 'tftp.c:385-395,930-933,964,976-977,1022',
     'boundary': 'Configured MTU32/52 negotiates zero block size; C emits repeated empty DATA for a nonempty file. Rust rejects the unusable transfer; both retain healthy owner and release the fixture FD.',
     'scenarios': ['reference-zero-block-v4', 'reference-zero-block-v6']},
]


def reference_configuration(root, args):
    """Only --test executes for configured values outside C's int domain."""
    rows=[]
    values=[('max-signed-overflow','tftp-max=2147483648'),
            ('max-zero-wrap','tftp-max=4294967296'),
            ('mtu-signed-overflow','tftp-mtu=2147483648'),
            ('mtu-zero-wrap','tftp-mtu=4294967296'),
            ('port-zero-wrap','tftp-port-range=4294967296,0'),
            ('port-one-wrap','tftp-port-range=4294967297,1')]
    for name,text in values:
        folder=args.out/('syntax-'+name);folder.mkdir()
        (root/'m2/tftp-syntax.conf').write_text(text+'\n');(folder/'config').write_text(text+'\n')
        row=dict(case=name,runtime_executed=False)
        for side in ['c','rust']:
            result=subprocess.run(command(root,side,'--test','-C','/m2/tftp-syntax.conf'),capture_output=True,timeout=3)
            (folder/(side+'.stdout')).write_bytes(result.stdout);(folder/(side+'.stderr')).write_bytes(result.stderr)
            row[side]=dict(exit=result.returncode,stdout=result.stdout.hex(),stderr=result.stderr.hex())
        assert row['c']['exit']==0 and row['rust']['exit']==1,'exact bounded syntax refusal'
        assert row['c']['stderr']==b'dnsmasq: syntax check OK.\n'.hex(),'C syntax witness'
        assert b'integer exceeds defined C int range' in bytes.fromhex(row['rust']['stderr']),'candidate precise range diagnostic'
        rows.append(row)
    save(args.out/'configuration-differences.json',rows)
    return rows


def reference_scenarios():
    base = 'enable-tftp\ntftp-root=' + ROOT + '/reference\n'
    cases = [dict(name='reference-single-replace-'+version, binding='',
                  config=base+'tftp-single-port\n', reference_difference='single-replacement',
                  requests=[{'replacement': True, 'v6': v6}], fixture_fds=True)
             for version, v6 in [('v4', False), ('v6', True)]]
    cases.append(dict(name='reference-root-parent-component', config=base,
                      reference_difference='parent-component',
                      requests=[{'filename': '..safe/../boot.bin'}]))
    for version,v6,mtu in [('v4',False,32),('v6',True,52)]:
        cases.append(dict(name='reference-zero-block-'+version,config=base+'tftp-mtu='+str(mtu)+'\n',
                          reference_difference='zero-block',fixture_fds=True,
                          requests=[{'zero_block':True,'v6':v6}]))
    return cases


def zero_block(item, out):
    target=(V6_SERVER if item.get('v6') else SERVER,69)
    with socket.socket(socket.AF_INET6 if item.get('v6') else socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(2);request=read_request({'filename':'boot.bin','options':{'blksize':'512'}})
        (out/'request.bin').write_bytes(request);endpoint.sendto(request,target)
        packet,peer=endpoint.recvfrom(2048);packets=[packet.hex()];(out/'reply-0.bin').write_bytes(packet)
        assert peer[0]==target[0] and peer[1]!=69,'dedicated zero-block source'
        if packet[:2]==b'\0\5':
            expected=b'\0\5\0\4unsupported request from '+(V6_CLIENT if item.get('v6') else CLIENT['address']).encode()+b'\0'
            assert packet==expected,'exact bounded zero-block refusal wire'
            return dict(kind='zero-block-refusal',packets=packets,source='dedicated')
        assert packet==b'\0\6blksize\x000\0','C zero-block OACK'
        for block in [1,2]:
            endpoint.sendto(struct.pack('!HH',4,block-1),peer)
            packet,current=endpoint.recvfrom(2048);assert current==peer and packet==struct.pack('!HH',3,block),'C nonempty file makes no progress'
            packets.append(packet.hex());(out/('reply-'+str(block)+'.bin')).write_bytes(packet)
        endpoint.sendto(b'\0\5\0\0bounded-zero-block-abort\0',peer)
        return dict(kind='zero-block-stalled',packets=packets,source='dedicated')


def replacement(item, out):
    """Exactly two ordinary reads, same peer, tiny synthetic files only."""
    target = (V6_SERVER if item.get('v6') else SERVER, 69)
    with socket.socket(socket.AF_INET6 if item.get('v6') else socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(3)
        packets = []
        for index, name in enumerate(REFERENCE_FILES):
            request = read_request({'filename': name})
            (out/f'request-{index}.bin').write_bytes(request)
            endpoint.sendto(request, target)
            packet, peer = endpoint.recvfrom(1024)
            (out/f'reply-{index}.bin').write_bytes(packet)
            if peer[0] != target[0] or peer[1] != 69 or packet[:4] != b'\0\3\0\1':
                raise AssertionError('replacement expected single-port first DATA')
            packets.append(packet.hex())
        endpoint.sendto(b'\0\4\0\1', peer)
        return {'kind': 'replacement', 'packets': packets, 'source': 'single'}


def fixture_fds(pid):
    # Paths are from the disposable fixture only; no host file contents read.
    found = []
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        marker = ROOT + '/reference/'
        if marker in target:
            found.append(target[target.index(marker):])
    return sorted(found)


def reference_pair(c, rust, scenario):
    """Accept only the exact bounded reference pair; missing evidence fails."""
    for result in (c, rust):
        if (result.get('failure') or result.get('started') is not True
                or result.get('alive_after') is not True or result.get('threads') != 1
                or result.get('pid_removed') is not True
                or result.get('cleanup', {}).get('forced') is not False
                or result.get('cleanup', {}).get('returncode') != 0
                or 'client_cleanup' not in result or result['client_cleanup'] is not None):
            return False
    if scenario['reference_difference'] == 'single-replacement':
        boot = (b'\0\3\0\1' + REFERENCE_FILES['boot.bin']).hex()
        alternate = (b'\0\3\0\1' + REFERENCE_FILES['alternate.bin']).hex()
        for result, second, remainder in [(c, boot, [ROOT+'/reference/boot.bin']), (rust, alternate, [])]:
            if result.get('requests') != [{'kind': 'replacement', 'packets': [boot, second], 'source': 'single'}]:
                return False
            if result.get('fixture_fds_before') != [] or result.get('fixture_fds_after') != remainder:
                return False
        return True
    if scenario['reference_difference']=='zero-block':
        peer=V6_CLIENT if scenario['requests'][0].get('v6') else CLIENT['address']
        error=(b'\0\5\0\4unsupported request from '+peer.encode()+b'\0').hex()
        return (c.get('requests')==[dict(kind='zero-block-stalled',packets=[b'\0\6blksize\x000\0'.hex(),b'\0\3\0\1'.hex(),b'\0\3\0\2'.hex()],source='dedicated')]
                and rust.get('requests')==[dict(kind='zero-block-refusal',packets=[error],source='dedicated')]
                and all(row.get('fixture_fds_before')==[] and row.get('fixture_fds_after')==[] for row in [c,rust]))
    data = REFERENCE_FILES['boot.bin']
    return (c.get('requests') == [{'kind': 'data', 'bytes': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest(),
                                 'source': 'dedicated', 'options': {}, 'blocks': 1}]
            and rust.get('requests') == [{'kind': 'error', 'code': 2, 'source': 'dedicated'}])


def reference_controls(c, rust, scenario):
    controls = {}
    for side, original in [('c', c), ('rust', rust)]:
        for name in ('missing-requests', 'wrong-payload', 'wrong-fds', 'missing-fds', 'missing-cleanup', 'missing-client-cleanup'):
            negative = copy.deepcopy(original)
            if name == 'missing-requests': negative.pop('requests', None)
            elif name == 'wrong-payload': negative['requests'] = [{'kind': 'corrupt'}]
            elif name in ('wrong-fds', 'missing-fds'):
                if scenario['reference_difference'] not in ['single-replacement','zero-block']: continue
                if name == 'wrong-fds': negative['fixture_fds_after'] = ['unexpected-fd']
                else: negative.pop('fixture_fds_after', None)
            elif name == 'missing-client-cleanup': negative.pop('client_cleanup', None)
            else: negative.pop('cleanup', None)
            controls[side+'-'+name] = not reference_pair(negative if side == 'c' else c,
                                                       negative if side == 'rust' else rust, scenario)
    return controls


def read_request(item):
    packet = bytearray(b'\0\1')
    for text in [item.get('filename', 'boot.bin'), item.get('mode', 'octet')]:
        packet.extend(text.encode()); packet.append(0)
    for name, value in item.get('options', {}).items():
        packet.extend(name.encode()+b'\0'+value.encode()+b'\0')
    return bytes(packet)


def corpus():
    normal = read_request({})
    # Truncated benign read, invalid mode, bounded option numeric/terminator
    # cases and unrelated opcodes. All paths remain the fixture's boot.bin.
    packets = [normal[:n] for n in range(0, len(normal))]
    packets += [b'\0\1boot.bin\0unknown\0', b'\0\2boot.bin\0octet\0',
                b'\0\7boot.bin\0octet\0', b'\0\4\0\1',
                normal+b'blksize\0', normal+b'blksize\0bad\0',
                normal+b'timeout\00\0', normal+b'windowsize\01\0']
    return packets


def fetch(item, out):
    family = socket.AF_INET6 if item.get('v6') else socket.AF_INET
    target = (V6_SERVER if item.get('v6') else SERVER, 69)
    result = {'kind': 'silent'}
    payload, records, options = bytearray(), [], {}
    with socket.socket(family, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.65 if item.get('silent') else 3)
        request = read_request(item)
        (out/'request.bin').write_bytes(request)
        endpoint.sendto(request, target)
        expected, blocksize, transfer = 1, 512, None
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            try:
                packet, peer = endpoint.recvfrom(65535)
            except socket.timeout:
                if not records:
                    return result
                raise
            (out/f'reply-{len(records):03}.bin').write_bytes(packet)
            if len(packet) < 2:
                raise AssertionError('short TFTP reply')
            opcode = int.from_bytes(packet[:2], 'big')
            if transfer is None:
                transfer = peer
            if peer != transfer or peer[0] != target[0]:
                raise AssertionError('TFTP source changed')
            source = 'single' if peer[1] == 69 else 'dedicated'
            if item.get('range'):
                source = 'range' if item['range'][0] <= peer[1] <= item['range'][1] else 'outside-range'
            records.append({'opcode': opcode, 'length': len(packet)})
            if opcode == 5:
                return {'kind': 'error', 'code': int.from_bytes(packet[2:4], 'big'), 'source': source}
            if opcode == 6:
                fields = packet[2:].split(b'\0')
                if fields[-1] != b'' or len(fields) % 2 != 1:
                    raise AssertionError('malformed OACK')
                options = {fields[i].decode(): fields[i+1].decode() for i in range(0, len(fields)-1, 2)}
                blocksize = int(options.get('blksize', 512))
                endpoint.sendto(b'\0\4\0\0', peer)
                continue
            if opcode != 3 or len(packet) < 4:
                raise AssertionError('expected DATA')
            block = int.from_bytes(packet[2:4], 'big')
            if block != expected:
                if block == ((expected-1) & 0xffff):
                    endpoint.sendto(struct.pack('!HH', 4, block), peer)
                    continue
                raise AssertionError('out of order DATA')
            payload.extend(packet[4:])
            if item.get('abort') or item.get('abandon'):
                if item.get('abort'):
                    endpoint.sendto(b'\0\5\0\0client-abort\0', peer)
                return {'kind': 'aborted' if item.get('abort') else 'incomplete', 'source': source}
            if item.get('hold') and block == 1:
                (out/'hold-ready').write_text('ready\n')
                until = time.monotonic()+3
                while not (out/'hold-release').exists() and time.monotonic() < until:
                    time.sleep(.01)
                if not (out/'hold-release').exists():
                    raise AssertionError('SIGHUP driver did not release')
            endpoint.sendto(struct.pack('!HH', 4, block), peer)
            expected = (expected+1) & 0xffff
            if len(packet)-4 < blocksize:
                if item.get('duplicate_final_ack'):
                    for _ in range(2):
                        endpoint.sendto(struct.pack('!HH', 4, block), peer)
                return {'kind': 'data', 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                        'source': source, 'options': options, 'blocks': expected-1}
        raise AssertionError('TFTP transfer deadline')


def capacity(item, out):
    """Hold only ordinary reads to show C's limit and release recovery."""
    endpoints, transfers = [], []
    admitted = item['capacity']
    try:
        for index in range(admitted+1):
            v6 = index % 2 == 1
            endpoint = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
            endpoint.settimeout(.3)
            endpoints.append(endpoint)
            endpoint.sendto(read_request({}), (V6_SERVER if v6 else SERVER, 69))
            if index < admitted:
                packet, peer = endpoint.recvfrom(2048)
                (out/f'admitted-{index}.bin').write_bytes(packet)
                if packet[:4] != b'\0\3\0\1':
                    raise AssertionError('capacity fixture expected first DATA')
                if (peer[1] == 69) != bool(item.get('single')):
                    raise AssertionError('capacity source port mode')
                transfers.append((endpoint, peer))
            else:
                try:
                    endpoint.recvfrom(2048)
                except socket.timeout:
                    blocked = True
                else:
                    raise AssertionError('transfer admitted above capacity')
        recovered = False
        if transfers:
            first, peer = transfers.pop(0)
            first.sendto(b'\0\5\0\0client-abort\0', peer)
            endpoint = endpoints[-1]
            endpoint.settimeout(3)
            # Dedicated mode leaves the RRQ queued in the kernel. Single-port
            # mode must consume/drop it while still servicing existing ACKs.
            if item.get('single'):
                time.sleep(.1)
                endpoint.sendto(read_request({}), (V6_SERVER if admitted % 2 else SERVER, 69))
            packet, peer = endpoint.recvfrom(2048)
            (out/'recovered.bin').write_bytes(packet)
            recovered = packet[:4] == b'\0\3\0\1'
            transfers.append((endpoint, peer))
        return {'kind': 'capacity', 'admitted': admitted, 'blocked': blocked, 'recovered': recovered}
    finally:
        for endpoint, peer in transfers:
            endpoint.sendto(b'\0\5\0\0client-abort\0', peer)
        for endpoint in endpoints:
            endpoint.close()


def client(args):
    item = json.loads(args.request)
    args.out.mkdir(parents=True, exist_ok=True)
    result = {}
    try:
        if item.get('replacement'):
            result = replacement(item, args.out)
        elif item.get('zero_block'):
            result = zero_block(item, args.out)
        elif 'capacity' in item:
            result = capacity(item, args.out)
        elif item.get('corpus'):
            result = {'kind': 'corpus', 'rows': []}
            for index, packet in enumerate(corpus()):
                (args.out/f'corpus-{index:03}.bin').write_bytes(packet)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                    endpoint.settimeout(.1)
                    endpoint.sendto(packet, (SERVER, 69))
                    try:
                        reply, _ = endpoint.recvfrom(65535)
                        (args.out/f'corpus-{index:03}.reply').write_bytes(reply)
                        row = {'opcode': int.from_bytes(reply[:2], 'big')}
                        if reply[:2] == b'\0\5': row['code'] = int.from_bytes(reply[2:4], 'big')
                        # Ordinary ERROR aborts any transfer created by a
                        # valid prefix; malformed traffic never fills capacity.
                        if reply[:2] in (b'\0\3', b'\0\6'):
                            endpoint.sendto(b'\0\5\0\0done\0', _)
                    except socket.timeout:
                        row = {'silent': True}
                    result['rows'].append(row)
            # A valid transfer after the corpus confirms the daemon remains live.
            good = args.out/'valid-after'; good.mkdir()
            result['valid_after'] = fetch({}, good)
        else:
            result = fetch(item, args.out)
    except Exception as error:
        result['failure'] = repr(error)
    save(args.out/'result.json', result)
    return int('failure' in result)


def files(root):
    run = root/'run/dnsmasq'; run.mkdir(exist_ok=True); os.chown(run,453,453)
    base = root/'m2/tftp'
    variants = {'global': b'global\n'*220, 'first': b'first\r\n'*210, 'last': b'last\n'*260,
                'global/10.77.0.2': b'ip4\n'*320, 'global/'+V6_CLIENT: b'ip6\n'*320,
                'global/'+MAC: b'mac\n'*320,
                'global/'+LEASE_MAC.replace(':', '-'): b'lease-mac\n'*170,
                'global/10.77.0.2/'+MAC: b'ip4mac\n'*220,
                'global/'+V6_CLIENT+'/'+MAC: b'ip6mac\n'*220}
    for directory, data in variants.items():
        path = base/directory; path.mkdir(parents=True, exist_ok=True)
        (path/'boot.bin').write_bytes(data)
        (path/'boot.bin').chmod(0o644)
    reference = base/'reference'; (reference/'..safe').mkdir(parents=True, exist_ok=True)
    for name, data in REFERENCE_FILES.items():
        path = reference/name; path.write_bytes(data); path.chmod(0o644)
    for name, owner in [('owned.bin',453), ('root.bin',0)]:
        path = base/'global'/name; path.write_bytes(b'ownership\n'); path.chmod(0o644); os.chown(path, owner, owner)


def run_side(root, binary, scenario, out, network):
    out.mkdir()
    config = 'port=0\nno-resolv\nno-hosts\n'+scenario.get('binding','bind-interfaces\n')+'interface=br-lan\nuser=dnsmasq\ngroup=dnsmasq\npid-file=/run/dnsmasq/m5-tftp.pid\n'+scenario['config']
    (root/'run/dnsmasq/m5-tftp.pid').unlink(missing_ok=True)
    (root/'m2/tftp.conf').write_text(config)
    (out/'dnsmasq.conf').write_text(config)
    lease_path = root/'m2/tftp.leases'
    lease_path.unlink(missing_ok=True)
    if scenario.get('lease_mac'):
        config += 'dhcp-range=10.77.0.10,10.77.0.20,255.255.255.0,10m\nno-ping\ndhcp-leasefile=/m2/tftp.leases\n'
        lease_path.write_text('0 '+scenario['lease_mac']+' 10.77.0.2 stored *\n')
        os.chown(lease_path, 453, 453)
    script = root/'m2/tftp-capture'
    script.write_text(CAPTURE); script.chmod(0o755)
    trace = root/'m2/tftp-events'; trace.write_bytes(b''); trace.chmod(0o666)
    (root/'m2/tftp.conf').write_text(config)
    (out/'dnsmasq.conf').write_text(config)
    result, process, client_process, blocker = {'requests': []}, None, None, None
    try:
        if scenario.get('bind_blocker'):
            blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            blocker.bind(('0.0.0.0', 69))
        with (out/'daemon.log').open('w') as log:
            def limits():
                if 'nofile' in scenario:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (scenario['nofile'], scenario['nofile']))
            process = subprocess.Popen(command(root,binary,'-k','-C','/m2/tftp.conf'), stdout=log,stderr=log,
                                       start_new_session=True, preexec_fn=limits)
            time.sleep(.25)
            result['started'] = process.poll() is None
            if not result['started']:
                result['exit'] = process.returncode
                return result
            result['identity'] = process_identity(root,process.pid)
            if scenario.get('fixture_fds'):
                result['fixture_fds_before'] = fixture_fds(process.pid)
            for index, item in enumerate(scenario['requests']):
                request_out=out/f'request-{index:02}'
                argv=network.argv(sys.executable,Path(__file__).resolve(),'--client','--request',json.dumps(item),'--out',request_out)
                client_process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                if item.get('hold'):
                    deadline=time.monotonic()+4
                    while not (request_out/'hold-ready').exists() and time.monotonic()<deadline and client_process.poll() is None:
                        time.sleep(.01)
                    if not (request_out/'hold-ready').exists(): raise AssertionError('live transfer did not reach hold')
                    os.kill(process.pid,signal.SIGHUP)
                    time.sleep(.05)
                    (request_out/'hold-release').write_text('release\n')
                stdout,stderr=client_process.communicate(timeout=12)
                (out/f'client-{index:02}.log').write_bytes(stdout+stderr)
                if client_process.returncode:
                    raise AssertionError(f'client exit {client_process.returncode}')
                row=json.loads((request_out/'result.json').read_text()); result['requests'].append(row)
                client_process=None
            if 'callbacks' in scenario:
                deadline = time.monotonic()+scenario.get('callback_wait', 3)
                while len(trace.read_text().splitlines()) < scenario['callbacks'] and time.monotonic() < deadline:
                    time.sleep(.05)
                time.sleep(.15)
                raw = trace.read_bytes(); (out/'callback-trace').write_bytes(raw)
                result['callbacks'] = [line.split('|') for line in raw.decode().splitlines()]
            if scenario.get('fixture_fds'):
                time.sleep(.25)  # bounded final ACK/script queue drain
                result['fixture_fds_after'] = fixture_fds(process.pid)
            result['alive_after']=process.poll() is None
            result['threads']=len(list(Path(f'/proc/{process.pid}/task').iterdir()))
    except Exception as error:
        result['failure']=repr(error)
    finally:
        if blocker is not None: blocker.close()
        result['client_cleanup']=stop(client_process)
        result['cleanup']=stop(process)
        result['pid_removed']=not (root/'run/dnsmasq/m5-tftp.pid').exists()
        save(out/'result.json',result)
    return result


def executed(result, scenario):
    if 'failure' in result or result.get('started') == scenario.get('startup_failure', False):
        return False
    if not result['started']:
        return True
    if not result.get('alive_after') or result.get('threads') != 1 or not result.get('pid_removed'):
        return False
    if result.get('cleanup', {}).get('forced'):
        return False
    if len(result['requests']) != len(scenario['requests']):
        return False
    if 'callbacks' in scenario and len(result.get('callbacks', [])) != scenario['callbacks']:
        return False
    for item, row in zip(scenario['requests'], result['requests']):
        if 'capacity' in item:
            if row != {'kind': 'capacity', 'admitted': item['capacity'], 'blocked': True, 'recovered': item['capacity'] > 0}:
                return False
            continue
        kind = 'silent' if item.get('silent') else 'corpus' if item.get('corpus') else 'data'
        if item.get('abort'): kind = 'aborted'
        if item.get('abandon'): kind = 'incomplete'
        if item.get('error'): kind = 'error'
        if scenario['name'] == 'missing-root-no-fail' or scenario['name'] == 'secure-ownership' and item.get('filename') == 'root.bin':
            kind = 'error'
        if row.get('kind') != kind:
            return False
        if kind == 'corpus' and row.get('valid_after', {}).get('kind') != 'data':
            return False
    return True


def semantic(result):
    if not result.get('started'):
        return {'started': False, 'exit': result.get('exit')}
    return {key:result.get(key) for key in ['started','requests','callbacks','alive_after','threads','pid_removed','failure']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path)
    parser.add_argument('--rust-binary',type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--case',action='append',default=[])
    parser.add_argument('--sides',choices=['c','both'],default='both')
    parser.add_argument('--client',action='store_true')
    parser.add_argument('--request')
    parser.add_argument('--write-corpus',action='store_true')
    parser.add_argument('--reference-differences',action='store_true')
    args=parser.parse_args()
    if args.client:return client(args)
    if args.write_corpus:
        if 'private' not in args.out.resolve().parts: raise SystemExit('corpus must remain private')
        args.out.mkdir(parents=True,exist_ok=True)
        for index, packet in enumerate([read_request({}), read_request({'mode':'netascii'}), read_request({'options':{'blksize':'1468','tsize':'0','timeout':'2','windowsize':'4'}}), *corpus()]):
            (args.out/f'seed-{index:03}').write_bytes(packet)
        return 0
    if os.environ.get('DNSMASQ_TEST_ISOLATED')!='1' or os.geteuid()!=0:raise SystemExit('run_isolated.sh required')
    if not args.image_root or not args.rust_binary or not args.source_commit:raise SystemExit('image, Rust ELF and source commit required')
    args.out.mkdir(parents=True,exist_ok=False)
    available = scenarios() + (reference_scenarios() if args.reference_differences else [])
    selected=[item for item in available if not args.case or item['name'] in args.case]
    if args.case and len(selected)!=len(set(args.case)):raise SystemExit('unknown or duplicate scenario')
    save(args.out/'plan.json',{'scenarios':selected,'source_commit':args.source_commit,'rust_sha256':sha256(args.rust_binary),'tool_sha256':sha256(__file__),'deadline_seconds':12,'reference':'image-elf'})
    if args.reference_differences:
        save(args.out/'reference-plan.json', {'source': REFERENCE_SOURCE, 'checklist': REFERENCE_CHECKLIST,
                                            'scope': 'synthetic fixture only; wildcard single-port; no undefined-behavior reproduction'})
    network=Network();report={'passed':False,'rows':[],'failures':[], 'reference_differences': [], 'configuration_differences': []}
    try:
        root=prepare(args.image_root,None,args.out/'image',args.rust_binary)
        files(root)
        if args.reference_differences:report['configuration_differences']=reference_configuration(root,args)
        network.start()
        ip('addr','add',V6_SERVER+'/64','dev','br-lan','nodad')
        network.exec('ip','addr','add',V6_CLIENT+'/64','dev','client0','nodad')
        ip('neigh','replace','10.77.0.2','lladdr',CLIENT['mac'],'nud','permanent','dev','br-lan')
        ip('-6','neigh','replace',V6_CLIENT,'lladdr',CLIENT['mac'],'nud','permanent','dev','br-lan')
        for scenario in selected:
            folder=args.out/scenario['name'];folder.mkdir()
            row={'scenario':scenario['name']}
            for side in ['c'] if args.sides=='c' else ['c','rust']:
                row[side]=run_side(root,side,scenario,folder/side,network)
            if scenario.get('reference_difference'):
                row['equal'] = args.sides == 'both' and semantic(row['c']) == semantic(row['rust'])
                row['classified'] = args.sides == 'both' and reference_pair(row['c'], row['rust'], scenario)
                row['negative_controls'] = reference_controls(row['c'], row['rust'], scenario) if args.sides == 'both' else {}
                row['negative_control_detected'] = bool(row['negative_controls']) and all(row['negative_controls'].values())
                row['disposition'] = 'retain fresh Rust bytes and complete release' if scenario['reference_difference'] == 'single-replacement' else 'retain Rust parent-component rejection'
                report['reference_differences'].append(row); save(args.out/'result.json', report)
                continue
            if args.sides=='both':
                row['equal']=semantic(row['c'])==semantic(row['rust'])
                if row['c'].get('pid_removed') != row['rust'].get('pid_removed'):
                    row['side_effect_difference']={'pid_removed':{'c':row['c'].get('pid_removed'),'rust':row['rust'].get('pid_removed')},'scope':'startup failure PID residue; retained for explicit review'}
                negative=copy.deepcopy(row['rust'])
                if negative.get('requests'):
                    negative['requests'][0]={'kind':'wrong-response'}
                else:
                    negative['exit']=(negative.get('exit') or 0)+1
                controls={'wire-or-startup': semantic(row['c'])!=semantic(negative)}
                if 'callbacks' in scenario:
                    negative=copy.deepcopy(row['rust'])
                    negative.setdefault('callbacks', []).append(['unexpected-callback'])
                    controls['callback-count']=semantic(row['c'])!=semantic(negative)
                row['negative_controls']=controls
                row['negative_control_detected']=all(controls.values())
            row['executed']=all(executed(row[side], scenario) for side in (['c'] if args.sides=='c' else ['c','rust']))
            report['rows'].append(row);save(args.out/'result.json',report)
        report['passed']=args.sides=='both' and bool(selected) and all(row['executed'] and row['equal'] and row['negative_control_detected'] for row in report['rows']) and all(row['classified'] and row['negative_control_detected'] for row in report['reference_differences'])
        if args.reference_differences:
            classified = {row['scenario'] for row in report['reference_differences'] if row['classified']}
            report['reference_checklist'] = []
            for item in REFERENCE_CHECKLIST:
                check = dict(item)
                if 'scenarios' in check:
                    check['status'] = 'checked' if set(check['scenarios']) <= classified else 'not-covered'
                report['reference_checklist'].append(check)
    except Exception as error:
        report['failures'].append(repr(error))
    finally:
        try:
            try:
                report['network_cleanup'] = network.close()
            except subprocess.CalledProcessError as error:
                # The veth can disappear after Network.close checks it because
                # stopping the client namespace releases its peer asynchronously.
                if (error.cmd[:3] != ['ip', 'link', 'delete']
                        or len(error.cmd) != 4
                        or any(name == error.cmd[3] for _, name in socket.if_nameindex())):
                    raise
                report['cleanup_disappearance_race'] = error.cmd[3]
                report['network_cleanup'] = network.close()
        except Exception as error:
            report['failures'].append('network cleanup: '+repr(error))
            report['passed'] = False
        report['remaining_interfaces']=[name for _,name in socket.if_nameindex()]
        if sorted(report['remaining_interfaces'])!=['lo']:report['passed']=False
        save(args.out/'result.json',report)
    print(json.dumps({'passed':report['passed'],'result':str(args.out/'result.json')}))
    return int(not report['passed']) if args.sides=='both' else int(bool(report['failures']) or not all(row['executed'] for row in report['rows']))


if __name__=='__main__':raise SystemExit(main())
