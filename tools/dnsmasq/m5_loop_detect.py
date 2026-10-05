#!/usr/bin/env python3
"""Ordinary loop.c callers, executed only in the exact-image isolated rootfs."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import answer, query, read_name, semantics, exact_read
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def cases():
    baseline = [
        dict(id='disabled', enabled=False),
        dict(id='healthy', enabled=True),
        dict(id='returned', enabled=True, reflect=True),
        dict(id='returned-hup', enabled=True, reflect=True, hup=True),
        dict(id='healthy-hup', enabled=True, hup=True),
        dict(id='wrong-type', enabled=True, reflect=True, mutation='type'),
        dict(id='wrong-uid', enabled=True, reflect=True, mutation='uid'),
        dict(id='wrong-suffix', enabled=True, reflect=True, mutation='suffix'),
        dict(id='fixed-port', enabled=True, fixed_port=True),
        dict(id='returned-fixed-port', enabled=True, fixed_port=True, reflect=True),
        dict(id='source-port', enabled=True, source_port=True),
        dict(id='domain-only', enabled=True, domain=True),
        dict(id='dotless-only', enabled=True, dotless=True),
    ]
    mutations = [dict(id=label, enabled=True, reflect=True, mutation=mutation)
                 for label, mutation in [('wrong-length','length'),('wrong-hex','hex'),
                    ('upper-uid','upper-uid'),('upper-suffix','upper-suffix'),
                    ('no-rd','no-rd'),('cd','cd'),('ad','ad'),('do','do'),
                    ('class-any','class-any'),('class-ch','class-ch'),
                    ('opcode-other','opcode'),('nonzero-answer','answer'),
                    ('qr-response','qr'),('truncated','truncated'),
                    ('multi-question','multi-question'),('non-dot-separator','separator')]]
    banks = [dict(id=label, enabled=True, file=mode, hup=hup, expected_probes=count)
             for label, mode, hup, count in [('file-init-success','success',False,5),
                ('file-init-missing','missing',False,2),('file-init-empty','empty',False,3),
                ('file-init-partial','partial',False,5),('file-hup-success','success',True,9),
                ('file-hup-missing','missing',True,3),('file-hup-delete','delete',True,7),
                ('file-hup-same-uid','success',True,9),('file-hup-changed','changed',True,9)]]
    routing = [dict(id=label,enabled=True,rules=rules,expected_probes=count)
        for label,rules,count in [('wildcard-domain',['/*.loop.test/127.0.0.2#15970'],0),
          ('wildcard-any',['/*/127.0.0.2#15970'],1),('explicit-default',['/#/127.0.0.2#15970'],1),
          ('mixed-global-domain',['127.0.0.2#15970','/other.test/127.0.0.3#15971'],1),
          ('duplicate-global',['127.0.0.2#15970']*2,2),
          ('port-limit1',['127.0.0.2#15970']*5,5),('port-limit2',['127.0.0.2#15970']*5,5),
          ('port-limit3',['127.0.0.2#15970']*5,5),('one-port',['127.0.0.2#15970']*5,5)]]
    for row in routing:
        if row['id'].startswith('port-limit'):row['port_limit']=int(row['id'][-1])
        if row['id']=='one-port':row['one_port']=True
    resolvers = [dict(id=label,enabled=True,resolv=mode,no_poll=no_poll,hup=hup,expected_probes=count)
        for label,mode,no_poll,hup,count in [('resolv-poll-init','success',False,False,3),
          ('resolv-poll-change','changed',False,False,5),('resolv-poll-empty-recovery','recovery',False,False,5),
          ('resolv-poll-delete','delete',False,False,3),('resolv-poll-hup','success',False,True,3),
          ('resolv-no-poll-init','success',True,False,3),('resolv-no-poll-change','changed',True,True,5),
          ('resolv-no-poll-empty','empty',True,True,4),('resolv-no-poll-missing','missing',True,True,3)]]
    extra = [dict(id='flag-plain',enabled=True),dict(id='flag-repeat',enabled=True,repeat=True),
        dict(id='flag-argument',enabled=True,syntax_only=True),
        dict(id='duplicate-return',enabled=True,reflect=True,duplicate=True),
        dict(id='file-stale-probe',enabled=True,file='success',hup=True,stale_probe=True,expected_probes=9),
        dict(id='file-repeated-hup',enabled=True,file='success',hup=True,hup_count=3,expected_probes=17),
        dict(id='fixed-port-recheck',enabled=True,file='success',hup=True,fixed_port=True,expected_probes=7),
        dict(id='source-port-recheck',enabled=True,file='success',hup=True,source_port=True,expected_probes=8),
        dict(id='zero-server',enabled=True,rules=['0.0.0.0#15970'],zero=True,expected_probes=1),
        dict(id='repeated-check-fds',enabled=True,file='success',hup=True,hup_count=4,expected_probes=21),
        dict(id='probe-port-released',enabled=True,one_port=True,rebind_probe_port=True),
        dict(id='blocked-port-initial',enabled=True,one_port=True,block_port=True,expected_probes=0),
        dict(id='source-bind-busy',enabled=True,source_port=True,block_port=True,expected_probes=0)]
    extra += [dict(id='returned-tcp',enabled=True,tcp_probe=True),
        dict(id='tcp-before-disable',enabled=True,tcp_before=True),
        dict(id='tcp-after-disable',enabled=True,reflect=True,tcp_after=True),
        dict(id='source-interface-missing',enabled=True,rules=['127.0.0.2#15970@loop-missing0'],expected_probes=0),
        dict(id='mixed-source-parameters',enabled=True,v6=True,rules=['127.0.0.2#15970','127.0.0.2#15970@127.0.0.1','::1#15970'],expected_probes=3)]
    extra += [dict(id='active-forward-detect',enabled=True,active=True,detect_active=True,one_port=True),
        dict(id='active-forward-recheck',enabled=True,active=True,file='missing',hup=True,one_port=True,expected_probes=3),
        dict(id='stop-active',enabled=True,active=True,stop_active=True,one_port=True),
        dict(id='blocked-port-recheck',enabled=True,file='missing',hup=True,one_port=True,block_after=True,reflect=True,expected_probes=2),
        dict(id='query-log-return',enabled=True,reflect=True,query_log=True),
        dict(id='dump-return',enabled=True,reflect=True,dump=True),
        dict(id='local-server',enabled=True,local=True,rules=['127.0.0.1#15370'],expected_probes=1)]
    extra += [dict(id='dns-dhcp-tftp',enabled=True,concurrent=True),
        dict(id='active-recheck-dhcp-tftp',enabled=True,concurrent=True,active=True,file='missing',hup=True,one_port=True,expected_probes=3),
        dict(id='dns-off-concurrent',enabled=True,concurrent=True,dns_off=True,expected_probes=0),
        dict(id='disabled-dns-dhcp-tftp',enabled=False,concurrent=True,dns_off=True,expected_probes=0)]
    return baseline + mutations + banks + routing + resolvers + extra + [dict(id='healthy-v6', enabled=True, v6=True),
             dict(id='healthy-mixed',enabled=True,v6=True,rules=['127.0.0.2#15970','::1#15970'],expected_probes=2),
             dict(id='domain-v6',enabled=True,v6=True,domain=True),
             dict(id='disabled-hup',enabled=False,hup=True),dict(id='no-resolv-hup',enabled=True,hup=True)]


def wait(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(.01)
    raise AssertionError('ordinary caller timed out')


class Upstream:
    def __init__(self, case):
        self.case, self.events, self.errors = case, [], []
        self.held=[]
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.2', 15970))
        self.socket.settimeout(.05)
        self.sockets = [self.socket]
        if case.get('file') or any('127.0.0.3' in row for row in case.get('rules',[])):
            extra = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            extra.bind(('127.0.0.3',15971));self.sockets.append(extra)
        if case.get('resolv'):
            for address in ['127.0.0.2','127.0.0.3']:
                extra=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);extra.bind((address,53));self.sockets.append(extra)
        if case.get('zero'):
            extra=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);extra.bind(('127.0.0.1',15970));self.sockets.append(extra)
        if case.get('v6'):
            extra = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
            extra.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            extra.bind(('::1',15970));self.sockets.append(extra)
        for stream in self.sockets:
            stream.setsockopt(socket.SOL_SOCKET,35,1)  # Linux SO_TIMESTAMPNS.
        self.capture=None
        if case.get('local'):
            self.capture=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(3));self.capture.bind(('lo',0))
        self.tcp=[];self.clients=[];self.buffers={}
        for stream in self.sockets:
            listener=socket.socket(stream.family,socket.SOCK_STREAM)
            if stream.family==socket.AF_INET6:listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            listener.bind(stream.getsockname());listener.listen(8);self.tcp.append(listener)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                ready,_,_ = select.select(self.sockets+self.tcp+self.clients+([self.capture] if self.capture else []),[],[],.05)
                if not ready:continue
                stream=ready[0]
                if stream is self.capture:
                    raw,link=stream.recvfrom(65535)
                    if link[2]!=4 or not raw or raw[0]>>4!=4 or raw[9]!=17:continue
                    at=(raw[0]&15)*4
                    sport,dport,length=struct.unpack_from('!HHH',raw,at)
                    if dport!=15370:continue
                    packet=raw[at+8:at+length]
                    if len(packet)!=31 or packet[2:12]!=bytes.fromhex('01000001000000000000'):continue
                    name,end=read_name(packet,12)
                    if not re.fullmatch('[0-9a-f]{8}\\.test',name):continue
                    self.events.append(dict(probe=True,name=name,type=16,peer=[socket.inet_ntoa(raw[12:16]),sport],destination=[socket.inet_ntoa(raw[16:20]),dport],wire=packet.hex(),semantics=semantics(packet),transport='udp',received_realtime_ns=time.time_ns()))
                    continue
                if stream in self.tcp:
                    conn,_=stream.accept();conn.setblocking(False);self.clients.append(conn);self.buffers[conn]=b'';continue
                transport='udp';ancillary=[]
                if stream in self.clients:
                    chunk=stream.recv(65535)
                    if not chunk:self.clients.remove(stream);del self.buffers[stream];stream.close();continue
                    self.buffers[stream]+=chunk
                    if len(self.buffers[stream])<2:continue
                    size=struct.unpack_from('!H',self.buffers[stream])[0]
                    if len(self.buffers[stream])<size+2:continue
                    packet=self.buffers[stream][2:size+2];self.buffers[stream]=self.buffers[stream][size+2:];peer=stream.getpeername();transport='tcp'
                else:packet,ancillary,_,peer = stream.recvmsg(65535,128)
                received = time.time_ns()
                for level,kind,data in ancillary:
                    if level==socket.SOL_SOCKET and kind==35 and len(data)>=16:
                        seconds,nanos=struct.unpack('@qq',data[:16]);received=seconds*1_000_000_000+nanos
                if packet[2] & 0x80:
                    continue  # Actual replies to invalid reflected probes are not upstream queries.
                name, end = read_name(packet, 12)
                kind = struct.unpack_from('!H', packet, end)[0]
                probe = transport=='udp' and bool(re.fullmatch('[0-9a-f]{8}\\.test', name)) and kind == 16 and packet[2:12] == bytes.fromhex('01000001000000000000')
                self.events.append(dict(probe=probe, name=name, type=kind, peer=list(peer),destination=list(stream.getsockname()),
                                        wire=packet.hex(), semantics=semantics(packet),transport=transport,received_realtime_ns=received))
                if probe:
                    if self.case.get('reflect'):
                        reflected = bytearray(packet)
                        mutation = self.case.get('mutation')
                        if mutation == 'type': reflected[end:end + 2] = b'\0\x12'
                        if mutation == 'uid': reflected[13:21] = b'ffffffff' if name[:8] != 'ffffffff' else b'00000000'
                        if mutation == 'suffix': reflected[22:26] = b'test'[:-1] + b'x'
                        if mutation == 'length': reflected[12:22] = b'\x07'+reflected[13:20]+b'\x04'
                        if mutation == 'hex': reflected[13] = ord('g')
                        if mutation == 'upper-uid': reflected[13:21] = reflected[13:21].upper()
                        if mutation == 'upper-suffix': reflected[22:26] = b'TEST'
                        if mutation == 'no-rd': reflected[2] &= 0xfe
                        if mutation == 'cd': reflected[3] |= 0x10
                        if mutation == 'ad': reflected[3] |= 0x20
                        if mutation == 'do':
                            reflected[11] = 1;reflected.extend(bytes.fromhex('00002904d0000080000000'))
                        if mutation == 'class-any': reflected[end+2:end+4] = b'\0\xff'
                        if mutation == 'class-ch': reflected[end+2:end+4] = b'\0\x03'
                        if mutation == 'opcode': reflected[2] |= 8
                        if mutation == 'answer': reflected[7] = 1
                        if mutation == 'qr': reflected[2] |= 0x80
                        if mutation == 'truncated': reflected = reflected[:10]
                        if mutation == 'multi-question': reflected[5] = 2
                        if mutation == 'separator': reflected[12:22] = b'\x0d'+reflected[13:21]+b'x'
                        stream.sendto(reflected, ('::1' if stream.family==socket.AF_INET6 else '127.0.0.1', 15370))
                else:
                    if self.case.get('active') and name=='held.loop.test':
                        self.held.append((stream,peer,packet,transport));continue
                    reply=answer(packet)
                    if transport=='tcp':stream.sendall(struct.pack('!H',len(reply))+reply)
                    else:stream.sendto(reply, peer)
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set(): self.errors.append(repr(error))
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        for stream in self.sockets+self.tcp+self.clients:stream.close()
        if self.capture:self.capture.close()
        if self.thread.is_alive() or self.errors:
            raise AssertionError(self.errors or 'upstream fixture thread leaked')

    def release(self):
        for stream,peer,packet,transport in self.held:
            reply=answer(packet)
            if transport=='tcp':stream.sendall(struct.pack('!H',len(reply))+reply)
            else:stream.sendto(reply,peer)
        self.held.clear()


def dns(request=None,tcp=False,connection=None):
    request = request or query('ready.loop.test', 1, 0x5151)
    client=connection or socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    try:
        client.settimeout(.5)
        if tcp:
            if connection is None:client.connect(('127.0.0.1',15370))
            client.sendall(struct.pack('!H',len(request))+request)
        else:client.sendto(request, ('127.0.0.1', 15370))
        try:
            reply = exact_read(client,struct.unpack('!H',exact_read(client,2))[0]) if tcp else client.recv(65535)
        except socket.timeout:
            return {'reply': None, 'wire': None}
    finally:
        if connection is None:client.close()
    value = semantics(reply)
    assert value['id'] == struct.unpack('!H',request[:2])[0]
    return {'reply': value, 'wire': reply.hex()}


def resources(pid):
    return {'threads': len(list(Path(f'/proc/{pid}/task').iterdir())),
            'fds': len(list(Path(f'/proc/{pid}/fd').iterdir()))}


def concurrent_health():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(1);client.bind(('192.0.2.42',68))
        body=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,0x61626364,0,0,
            socket.inet_aton('192.0.2.42'),b'\0'*4,b'\0'*4,b'\0'*4,b'\x02\x00\x00\x00\x00\x42'+b'\0'*10,b'\0'*64,b'\0'*128)
        packet=body+bytes.fromhex('638253633501033204c000022a')+b'\x0c\x04loop\xff'
        client.sendto(packet,('192.0.2.1',67));reply=client.recv(2048)
        assert reply[4:8]==packet[4:8] and socket.inet_ntoa(reply[16:20])=='192.0.2.42'
        fields={};at=240
        while at<len(reply):
            code=reply[at];at+=1
            if code==255:break
            if code==0:continue
            size=reply[at];at+=1;fields[code]=reply[at:at+size];at+=size
        assert fields.get(53)==b'\x05'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(1);client.sendto(b'\0\x01health\0octet\0',('127.0.0.1',69));data,peer=client.recvfrom(2048)
        assert data==b'\0\x03\0\x01loop-health\n';client.sendto(b'\0\x04\0\x01',peer)
    return {'dhcp_ack':5,'address':'192.0.2.42','tftp_data':data.hex()}


def dump_packets(path):
    data=path.read_bytes();assert len(data)>=24
    endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>';rows=[];at=24
    while at<len(data):
        _,_,size,original=struct.unpack_from(endian+'4I',data,at);at+=16
        packet=data[at:at+size];at+=size;assert size==original
        version=packet[0]>>4
        offset=(packet[0]&15)*4 if version==4 else 40
        proto=packet[9] if version==4 else packet[6]
        if proto!=17:continue
        sport,dport,length=struct.unpack_from('!3H',packet,offset)
        rows.append({'source_port':sport,'destination_port':dport,'message':semantics(packet[offset+8:offset+length])})
    return rows


def run(root, side, case, folder):
    folder.mkdir()
    inside = '/m2/loop-' + case['id']
    work = root / inside.lstrip('/')
    work.mkdir()
    server = '::1#15970' if case.get('v6') else '127.0.0.2#15970'
    if case.get('source_port'): server += '@127.0.0.1#15570'
    if case.get('domain'): server = '/loop.test/' + server
    if case.get('dotless'): server = '//' + server
    config = ['no-resolv', 'no-hosts', 'no-0x20-encode', 'user=root', 'group=root',
              'listen-address=127.0.0.1,::1' if case.get('v6') else 'listen-address=127.0.0.1', 'port=15370', 'cache-size=0', 'server=' + server,
              'pid-file=' + inside + '/pid', 'log-facility=' + inside + '/log']
    if case['enabled']: config.append('dns-loop-detect')
    if case.get('repeat'):config.append('dns-loop-detect')
    if case.get('syntax_only'):config[-1]='dns-loop-detect=1'
    if case.get('fixed_port'): config.append('query-port=15570')
    if case.get('rules'):
        config=[line for line in config if not line.startswith('server=')]
        config += ['server='+row for row in case['rules']]
    if case.get('port_limit'):config.append('port-limit='+str(case['port_limit']))
    if case.get('one_port'):config += ['min-port=15570','max-port=15570']
    if case.get('query_log'):config.append('log-queries=extra')
    if case.get('dump'):config += ['dumpfile='+inside+'/capture.pcap','dumpmask=0xffff']
    if case.get('dns_off'):config=[line if not line.startswith('port=') else 'port=0' for line in config]
    if case.get('concurrent'):
        (work/'tftp').mkdir();(work/'tftp/health').write_bytes(b'loop-health\n')
        config += ['listen-address=192.0.2.1','dhcp-range=192.0.2.40,192.0.2.60,255.255.255.0,120s',
            'dhcp-authoritative','no-ping','dhcp-leasefile='+inside+'/leases','enable-tftp','tftp-root='+inside+'/tftp']
    if case.get('resolv'):
        config.remove('no-resolv');config.append('resolv-file='+inside+'/resolv')
        if case.get('no_poll'):config.append('no-poll')
        if case['resolv']!='missing':(work/'resolv').write_text('nameserver 127.0.0.3\n')
    if case.get('file'):
        config.append('servers-file='+inside+'/servers')
        if case['file']!='missing':
            (work/'servers').write_text('' if case['file']=='empty' else 'server=127.0.0.3#15971\n'+('invalid-key=1\n' if case['file']=='partial' else ''))
    (work / 'config').write_text('\n'.join(config) + '\n')
    (folder / 'config').write_text((work / 'config').read_text())
    syntax = subprocess.run(command(root, side, '--test', '-C', inside + '/config'), capture_output=True, timeout=3)
    result = {'syntax': dict(exit=syntax.returncode, stdout=syntax.stdout.decode(), stderr=syntax.stderr.decode()), 'observations': []}
    if case.get('syntax_only'):
        result['syntax_only']=True;save(folder/'observed.json',result);return result
    blocked=None
    if case.get('block_port'):
        blocked=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);blocked.bind(('127.0.0.1',15570))
    upstream = Upstream(case)
    process = None
    pending=None
    try:
        with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr:
            process = subprocess.Popen(command(root, side, '-k', '-C', inside + '/config'), stdout=stdout, stderr=stderr)
            wait(lambda: (work / 'pid').exists() or process.poll() is not None)
            assert process.poll() is None, 'startup failed'
            result['identity'] = process_identity(root, process.pid)
            time.sleep(.15)
            result['resources'] = resources(process.pid)
            result['observations'].append(dns())
            if case.get('active'):
                pending=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);pending.settimeout(.5)
                pending.sendto(query('held.loop.test',1,0x6161),('127.0.0.1',15370));wait(lambda:bool(upstream.held))
                result['active_resources']=resources(process.pid)
                if case.get('detect_active'):
                    upstream.socket.sendto(bytes.fromhex(next(event['wire'] for event in upstream.events if event['probe'])),('127.0.0.1',15370));time.sleep(.1)
                    result['observations'].append(dns())
            if case.get('block_after'):
                blocked=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);blocked.bind(('127.0.0.1',15570))
            if case.get('tcp_probe'):
                packet=bytes.fromhex(next(event['wire'] for event in upstream.events if event['probe']))
                result['observations'].append(dns(packet,tcp=True));result['observations'].append(dns())
            if case.get('tcp_after'):result['observations'].append(dns(tcp=True))
            if case.get('tcp_before'):
                packet=bytes.fromhex(next(event['wire'] for event in upstream.events if event['probe']))
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
                    client.connect(('127.0.0.1',15370));result['observations'].append(dns(tcp=True,connection=client))
                    upstream.socket.sendto(packet,('127.0.0.1',15370));time.sleep(.1)
                    result['observations'].append(dns(tcp=True,connection=client));result['observations'].append(dns())
            old_probe=next((event for event in upstream.events if event['probe'] and event['destination'][:2]==['127.0.0.3',15971]),None)
            if case.get('duplicate'):
                upstream.socket.sendto(bytes.fromhex(next(event['wire'] for event in upstream.events if event['probe'])),('127.0.0.1',15370))
                time.sleep(.1);result['observations'].append(dns())
            if case.get('rebind_probe_port'):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as available:available.bind(('127.0.0.1',15570))
                result['probe_port_released']=True
            if case.get('resolv') in ('changed','empty','delete','recovery'):
                initial=len([event for event in upstream.events if event['probe']])
                mode=case['resolv']
                if mode=='delete':(work/'resolv').unlink()
                else:
                    (work/'resolv-new').write_text('nameserver 127.0.0.2\n' if mode=='changed' else '')
                    (work/'resolv-new').replace(work/'resolv')
                if not case.get('no_poll'):
                    if mode=='changed':wait(lambda:len([e for e in upstream.events if e['probe']])>=initial+2)
                    elif mode=='recovery':
                        wait(lambda:'no servers found' in (work/'log').read_text())
                        (work/'resolv-new').write_text('nameserver 127.0.0.3\n');(work/'resolv-new').replace(work/'resolv')
                        wait(lambda:len([e for e in upstream.events if e['probe']])>=initial+2)
                    else:time.sleep(.25)
                result['observations'].append(dns())
            if case.get('hup'):
                if case.get('file')=='delete':(work/'servers').unlink()
                elif case.get('file')=='changed':(work/'servers').write_text('server=127.0.0.2#15970\n')
                for _ in range(case.get('hup_count',1)):
                    process.send_signal(signal.SIGHUP);time.sleep(.15);result['observations'].append(dns())
                if case.get('stale_probe'):
                    assert old_probe is not None
                    upstream.socket.sendto(bytes.fromhex(old_probe['wire']),('127.0.0.1',15370))
                    time.sleep(.1);result['observations'].append(dns())
                result['after_hup_resources'] = resources(process.pid)
            if pending is not None and not case.get('stop_active'):
                if case.get('concurrent'):result['concurrent']=concurrent_health()
                upstream.release()
                try:reply=pending.recv(65535)
                except socket.timeout:reply=None
                if reply is not None:assert reply[:2]==b'aa'
                result['active_reply']=semantics(reply) if reply is not None else None
                time.sleep(.05);result['released_resources']=resources(process.pid)
            if case.get('concurrent') and 'concurrent' not in result:result['concurrent']=concurrent_health()
            time.sleep(.05)  # Drain queries already emitted before snapshotting.
            events=sorted(upstream.events,key=lambda event:event['received_realtime_ns'])
            result['probes'] = copy.deepcopy([event for event in events if event['probe']])
            result['ordinary_upstream'] = copy.deepcopy([event for event in events if not event['probe']])
            result['logs'] = [line[line.index('NOT using nameserver'):] if 'NOT using nameserver' in line else line[line.index('using nameserver'):]
                              for line in (work / 'log').read_text().splitlines() if 'using nameserver' in line]
            if case.get('query_log'):
                result['query_logs']=[line.split(' dnsmasq',1)[-1].split(': ',1)[-1] for line in (work/'log').read_text().splitlines() if 'query[' in line or 'forwarded ' in line]
                assert not any(re.search('[0-9a-f]{8}\\.test',line) for line in result['query_logs'])
            if case.get('dump'):
                result['dump_packets']=dump_packets(work/'capture.pcap')
                assert any(row['message']['questions'][0][1]==16 for row in result['dump_packets'])
    finally:
        if process is not None:
            if process.poll() is None: process.send_signal(signal.SIGTERM)
            process.wait(timeout=3)
            result['exit'] = process.returncode
        upstream.close()
        if pending is not None:pending.close()
        if blocked is not None:blocked.close()
        result['cleanup'] = {'pid_file': (work / 'pid').exists(), 'live_pids': []}
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    if os.path.realpath(proc / 'root') == str(root): result['cleanup']['live_pids'].append(int(proc.name))
                except (FileNotFoundError, PermissionError): pass
        result['stderr'] = (folder / 'stderr').read_text()
        save(folder / 'observed.json', result)
    return result


def projection(value):
    result = copy.deepcopy(value)
    for key in ['identity', 'stderr', 'resources', 'after_hup_resources']:
        result.pop(key, None)
    result['syntax']['stderr'] = result['syntax']['stderr'].replace('dnsmasq-rs:', 'dnsmasq:')
    uids={};ports={};derived={};result['uid_shape']=[];result['probe_port_shape']=[]
    for probe in result['probes']:
        derived[probe['name'][:7]+'.test']='<short-uid>.test'
        derived['g'+probe['name'][1:]]='<nonhex-uid>.test'
    for probe in result['probes']:
        probe.pop('wire')
        probe.pop('received_realtime_ns',None)
        uids.setdefault(probe['name'],len(uids));result['uid_shape'].append(uids[probe['name']])
        source=tuple(probe['peer']);ports.setdefault(source,len(ports));result['probe_port_shape'].append(ports[source])
        probe['name'] = '<uid>.test'
        probe['peer'][1] = '<random-port>' if probe['peer'][1] != 15570 else 15570
        probe['semantics']['id'] = '<random-id>'
        probe['semantics']['questions'][0][0] = '<uid>.test'
    for event in result['ordinary_upstream']:
        event.pop('wire')
        event.pop('received_realtime_ns',None)
        if event['name'] in derived:
            event['name']=derived[event['name']]
            event['semantics']['questions'][0][0]=event['name']
        elif re.fullmatch('[0-9a-f]{8}\\.(test|tesx)', event['name']):
            suffix = event['name'].split('.')[1]
            event['name'] = '<uid>.' + suffix
            event['semantics']['questions'][0][0] = '<uid>.' + suffix
        event['peer'][1] = '<random-port>' if event['peer'][1] != 15570 else 15570
        event['semantics']['id'] = '<random-id>'
    for observation in result['observations']:
        observation.pop('wire',None)
        reply=observation.get('reply')
        if reply and reply.get('questions') and re.fullmatch('[0-9a-f]{8}\\.test',reply['questions'][0][0]):
            reply['id']='<probe-id>';reply['questions'][0][0]='<uid>.test'
            for record in reply.get('records',[]):
                if re.fullmatch('[0-9a-f]{8}\\.test',record['name']):record['name']='<uid>.test'
    return result


def compare(c, rust, case):
    errors = []
    if case.get('syntax_only'):
        left=copy.deepcopy(c);right=copy.deepcopy(rust)
        for value in [left,right]:value['syntax']['stderr']=value['syntax']['stderr'].replace('dnsmasq-rs:','dnsmasq:')
        return [] if left==right and left['syntax']['exit']==1 else [dict(kind='syntax-difference',c=left,rust=right)]
    expected_probes = case.get('expected_probes',1 if case['enabled'] and not any(case.get(key) for key in ['domain', 'dotless', 'fixed_port', 'source_port']) else 0)
    for side, value in [('c', c), ('rust', rust)]:
        if len(value['probes']) != expected_probes: errors.append(dict(side=side, kind='probe-count', expected=expected_probes, actual=len(value['probes'])))
        for probe in value['probes']:
            if probe['semantics']['flags'] != 0x0100 or probe['semantics']['questions'][0][1:] != [16, 1] or probe['semantics']['records']:
                errors.append(dict(side=side, kind='probe-wire'))
            if case.get('fixed_port') or case.get('source_port'):
                if probe['peer'] != ['127.0.0.1', 15570]: errors.append(dict(side=side, kind='source-contract', actual=probe['peer']))
        if value['probes'] and not any(case.get(k) for k in ('file','resolv','rules')) and any(p['name'] != value['probes'][0]['name'] for p in value['probes']): errors.append(dict(side=side, kind='unstable-uid'))
        if value['resources']['threads'] != 1: errors.append(dict(side=side, kind='extra-thread'))
        if value.get('after_hup_resources') != value['resources'] and case.get('hup'): errors.append(dict(side=side, kind='hup-resource-leak'))
        if value['cleanup'] != {'pid_file': False, 'live_pids': []} or value['exit'] != 0: errors.append(dict(side=side, kind='cleanup'))
    if projection(c) != projection(rust): errors.append(dict(kind='paired-difference', c=projection(c), rust=projection(rust)))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['image-root', 'rust', 'output']: parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--scenarios')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1': parser.error('isolated root required')
    if sha256(args.rust) != args.rust_sha256: parser.error('candidate identity mismatch')
    if any(case.get('concurrent') for case in cases() if not args.scenarios or case['id'] in args.scenarios.split(',')):
        subprocess.run(['ip','link','add','cache0','type','dummy'],check=True);subprocess.run(['ip','link','set','cache0','up'],check=True)
        for address in ['192.0.2.1/24','192.0.2.42/24']:subprocess.run(['ip','addr','add',address,'dev','cache0'],check=True)
    if args.output.exists() or 'private' not in args.output.resolve().parts: parser.error('fresh private output required')
    args.output.mkdir(parents=True)
    roots = {side: prepare(args.image_root, None, args.output / side, args.rust) for side in ['c', 'rust']}
    selected = [case for case in cases() if not args.scenarios or case['id'] in args.scenarios.split(',')]
    report = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256, 'c_sha256': STOCK_SHA256,
              'driver_sha256': sha256(Path(__file__)), 'manifest_sha256':sha256(Path(__file__).with_suffix('.json')), 'cases': [], 'failures': []}
    driver = args.output / 'driver'; driver.mkdir()
    for name in ['m5_loop_detect.py','m5_loop_detect.json', 'dns_service_probe.py', 'm2_rootfs.py', 'run_isolated.sh']:
        (driver / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    for case in selected:
        folder = args.output / case['id']; folder.mkdir()
        row = {'id': case['id'], 'failures': []}
        try:
            values = {side: run(root, side, case, folder / side) for side, root in roots.items()}
            row['failures'] = compare(values['c'], values['rust'], case)
        except Exception as error: row['failures'].append(dict(kind='infrastructure', error=repr(error)))
        report['cases'].append(row); save(args.output / 'progress.json', report)
    report['failures'] = [dict(case=row['id'], **f) for row in report['cases'] for f in row['failures']]
    report['qualified'] = False  # This first schedule is not the full family closure.
    manifest=json.loads(Path(__file__).with_suffix('.json').read_text())
    required={label for boundary in manifest['boundaries'] for label in boundary['required_cases']}
    report['required_count']=len(required);report['missing_required_cases']=sorted(required-{row['id'] for row in report['cases']})
    report['ordinary_schedule_passed'] = not report['failures'] and not report['missing_required_cases']
    save(args.output / 'result.json', report)
    print(json.dumps({'cases': len(selected), 'failures': len(report['failures']), 'qualified': report['qualified']}))
    return int(bool(report['failures']))


if __name__ == '__main__': raise SystemExit(main())
