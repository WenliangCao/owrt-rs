#!/usr/bin/env python3
"""Ordinary dumpfile/dumpmask black-box PCAP evidence in disposable namespaces.

Only the frozen full manifest can qualify. PCAP payloads must match independent
network witnesses; raw timestamps, packets, logs and failures remain private.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from dns_service_probe import query, exact_read, answer
from m2_rootfs import command, prepare, process_identity, sha256
from m5_helper import Side, children

HERE = Path(__file__).resolve().parent
SERVER, CLIENT = 10553, 10554
UPSTREAM, QUERY_PORT = 10561, 10560


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!'+str(len(data)//2)+'H', data))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return total


def pcap(data, start, end):
    assert len(data) >= 24, 'complete PCAP global header'
    magic, major, minor, zone, sigfigs, snaplen, network = struct.unpack_from('=IHHIIII', data)
    assert magic == 0xa1b2c3d4, 'native image PCAP magic'
    position, records = 24, []
    while position < len(data):
        assert position+16 <= len(data), 'complete record header'
        sec, usec, included, original = struct.unpack_from('=IIII', data, position)
        assert start-1 <= sec <= end+1 and 0 <= usec < 1_000_000, 'real wall-clock timestamp'
        assert included == original and position+16+included <= len(data), 'complete untruncated record'
        packet = data[position+16:position+16+included]
        position += 16+included
        family = packet[0] >> 4
        if family == 4:
            assert len(packet) >= 28 and packet[0] == 0x45 and packet[8] == 64 and packet[9] == 17, 'C raw IPv4 UDP header'
            assert struct.unpack_from('!H',packet,2)[0] == len(packet) and checksum(packet[:20]) == 0xffff, 'IPv4 length/checksum'
            source, destination = socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])
            offset=20; pseudo=packet[12:20]+b'\0\x11'+struct.pack('!H',len(packet)-20)
        else:
            assert family == 6 and len(packet) >= 48 and packet[6:8] == b'\x11\x40', 'C raw IPv6 UDP header'
            assert struct.unpack_from('!H',packet,4)[0] == len(packet)-40, 'IPv6 payload length'
            source, destination = socket.inet_ntop(10,packet[8:24]), socket.inet_ntop(10,packet[24:40])
            offset=40; pseudo=packet[8:40]+struct.pack('!I',len(packet)-40)+b'\0\0\0\x11'
        sport,dport,length,_=struct.unpack_from('!HHHH',packet,offset)
        assert length == len(packet)-offset and checksum(pseudo+packet[offset:]) == 0xffff, 'UDP length/checksum'
        records.append(dict(wire=packet.hex(),source=source,destination=destination,sport=sport,dport=dport,payload=packet[offset+8:].hex()))
    return dict(header=dict(magic=magic,version=[major,minor],zone=zone,sigfigs=sigfigs,snaplen=snaplen,network=network),records=records)


class Upstream:
    def __init__(self, ipv6):
        family=socket.AF_INET6 if ipv6 else socket.AF_INET
        self.address='::1' if ipv6 else '127.0.0.2'
        self.udp=socket.socket(family,socket.SOCK_DGRAM)
        self.tcp=socket.socket(family,socket.SOCK_STREAM)
        self.udp.bind((self.address,UPSTREAM));self.udp.settimeout(.05)
        self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.tcp.bind((self.address,UPSTREAM));self.tcp.listen();self.tcp.settimeout(.05)
        self.stopped=False;self.events=[];self.errors=[]
        self.threads=[threading.Thread(target=self.run,args=(tcp,),daemon=True) for tcp in [False,True]]
        for thread in self.threads:thread.start()
    def run(self,tcp):
        endpoint=self.tcp if tcp else self.udp
        while not self.stopped:
            try:
                if tcp:
                    connection,peer=endpoint.accept()
                    with connection:
                        connection.settimeout(2)
                        request=exact_read(connection,struct.unpack('!H',exact_read(connection,2))[0])
                        response=answer(request)
                        self.events.append(dict(request=request.hex(),reply=response.hex(),tcp=True,peer=list(peer)))
                        connection.sendall(struct.pack('!H',len(response))+response)
                else:
                    request,peer=endpoint.recvfrom(65535);response=answer(request)
                    self.events.append(dict(request=request.hex(),reply=response.hex(),tcp=False,peer=list(peer)))
                    endpoint.sendto(response,peer)
            except socket.timeout:continue
            except OSError:
                if not self.stopped:self.errors.append('upstream socket failure')
            except Exception as error:self.errors.append(repr(error))
    def close(self):
        self.stopped=True;self.udp.close();self.tcp.close()
        for thread in self.threads:thread.join(2)
        assert not self.errors,self.errors


def canonical_record(row,identifier):
    packet=bytearray.fromhex(row['wire']);offset=20 if packet[0]>>4==4 else 40
    packet[offset+8:offset+10]=identifier
    packet[offset+6:offset+8]=b'\0\0'
    if offset==20:pseudo=packet[12:20]+b'\0\x11'+struct.pack('!H',len(packet)-20)
    else:pseudo=packet[8:40]+struct.pack('!I',len(packet)-40)+b'\0\0\0\x11'
    total=checksum(pseudo+packet[offset:]);value=0xffff if total==0xffff else (~total)&0xffff
    packet[offset+6:offset+8]=struct.pack('!H',value)
    row['wire']=packet.hex();row['payload']=packet[offset+8:].hex()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try: process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();raise AssertionError('forced service cleanup')
    assert process.returncode == 0, 'ordinary TERM exit'


def profiles():
    rows=[
        dict(case='dhcp-dora',dhcp=True),dict(case='dhcp-mask-zero',dhcp=True,mask='0'),
        dict(case='dhcp-relay-forward',dhcp=True,relay='forward'),dict(case='dhcp-relay-reply',dhcp=True,relay='reply'),
        dict(case='extra-dhcp-no-display-id',dhcp=True,extra=['log-queries=extra'],display=True),
        dict(case='cross-family-shared-writer',dhcp=True,cross=True,mask='-1'),
        dict(case='tftp-v4-data',tftp='data'),dict(case='tftp-v6-data',tftp='data',ipv6=True),
        dict(case='tftp-oack-data',tftp='oack'),dict(case='tftp-error-reply',tftp='error'),
        dict(case='tftp-client-abort',tftp='abort'),dict(case='tftp-retransmit',tftp='retransmit'),
        dict(case='tftp-mask-zero',tftp='data',mask='0'),
        dict(case='extra-tftp-no-display-id',tftp='data',extra=['log-queries=extra'],display=True),
        dict(case='upstream-v4-all',exchange=True,upstream=True),
        dict(case='upstream-v6-all',exchange=True,upstream=True,ipv6=True),
        dict(case='mask-up-query',exchange=True,upstream=True,mask='4'),
        dict(case='mask-up-reply',exchange=True,upstream=True,mask='8'),
        dict(case='cached-second-query',exchange=True,upstream=True,copies=2),
        dict(case='tcp-forward-no-capture',exchange=True,upstream=True,tcp=True),
        dict(case='extra-local-display-id',exchange=True,extra=['log-queries=extra'],display=True),
        dict(case='extra-forward-display-id',exchange=True,upstream=True,extra=['log-queries=extra'],display=True),
        dict(case='header-create'), dict(case='header-user-nobody',extra=['user=nobody','group=nogroup']),
        dict(case='header-edns-max',extra=['edns-packet-max=1500']), dict(case='fifo-header',fifo=True),
        dict(case='dns-v4-local',exchange=True),dict(case='dns-v6-local',exchange=True,ipv6=True),
        dict(case='dns-v4-odd-length',exchange=True,name='odd.dump.test'),
        dict(case='mask-zero',exchange=True,mask='0'),dict(case='mask-query',exchange=True,mask='1'),
        dict(case='mask-reply',exchange=True,mask='2'),dict(case='mask-unrelated',exchange=True,mask='0x2000'),
        dict(case='mask-decimal',exchange=True,mask='3'),dict(case='mask-hex',exchange=True,mask='0x3'),
        dict(case='mask-octal',exchange=True,mask='03'),dict(case='mask-negative',exchange=True,mask='-1'),
        dict(case='mask-empty',exchange=True,mask=''),dict(case='mask-no-file',exchange=True,no_file=True,mask='3'),
        dict(case='empty-file-disables',exchange=True,empty_file=True),
        dict(case='tcp-local-no-capture',exchange=True,tcp=True),dict(case='regular-term-cleanup',exchange=True),
        dict(case='fifo-term-cleanup',exchange=True,fifo=True),dict(case='record-count-order',exchange=True,copies=2),
        dict(case='append-record-count',exchange=True,restart=True),dict(case='append-count-logging',exchange=True,restart=True),
        dict(case='append-header-retained',seed_header=True,exchange=True),
        dict(case='bad-magic',bad='magic',expect='bad header in /m2/dump.pcap'),
        dict(case='short-header',bad='short',expect='cannot access /m2/dump.pcap'),
        dict(case='missing-parent',path='/m2/absent/dump.pcap',expect='cannot create /m2/absent/dump.pcap'),
        dict(case='directory-path',directory=True,expect='cannot access /m2/dump.pcap'),
    ]
    return rows


def collect(root, file, reader):
    if reader is None: return file.read_bytes() if file.exists() and file.is_file() else b''
    result=bytearray()
    while True:
        try: part=os.read(reader,65536)
        except BlockingIOError: break
        if not part: break
        result.extend(part)
    return bytes(result)


def exchange(spec, folder, serial):
    family=socket.AF_INET6 if spec.get('ipv6') else socket.AF_INET
    kind=socket.SOCK_STREAM if spec.get('tcp') else socket.SOCK_DGRAM
    address='::1' if spec.get('ipv6') else '127.0.0.1'
    with socket.socket(family,kind) as endpoint:
        endpoint.settimeout(2)
        if kind==socket.SOCK_STREAM: endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        endpoint.bind((address,CLIENT));endpoint.connect((address,SERVER))
        request=query(spec.get('name','forward.dump.test' if spec.get('upstream') else 'dump.test'),1,0x7800+serial)
        endpoint.sendall(struct.pack('!H',len(request))+request if kind==socket.SOCK_STREAM else request)
        response=exact_read(endpoint,struct.unpack('!H',exact_read(endpoint,2))[0]) if kind==socket.SOCK_STREAM else endpoint.recv(4096)
    assert response[:2] == request[:2], 'actual network reply identity'
    (folder/f'{serial}.request').write_bytes(request);(folder/f'{serial}.reply').write_bytes(response)
    return [request.hex(),response.hex()]


def tftp_exchange(spec,folder):
    ipv6=spec.get('ipv6',False);address='::1' if ipv6 else '127.0.0.1'
    records=[]
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.bind((address,CLIENT));endpoint.settimeout(2)
        def send(packet,peer):
            endpoint.sendto(packet,peer);records.append(dict(sport=CLIENT,dport=peer[1],payload=packet.hex()))
        def receive():
            packet,peer=endpoint.recvfrom(4096);records.append(dict(sport=peer[1],dport=CLIENT,payload=packet.hex()));return packet,peer
        request=b'\0\1'+(b'absent' if spec['tftp']=='error' else b'evidence')+b'\0octet\0'
        if spec['tftp'] in ['oack','retransmit']:request+=b'timeout\0'+b'1\0'
        send(request,(address,69));packet,peer=receive()
        if spec['tftp']=='error':assert packet[:4]==b'\0\5\0\1','actual TFTP error reply'
        elif spec['tftp']=='abort':
            assert packet==b'\0\3\0\1pcap-evidence','TFTP DATA before abort'
            send(b'\0\5\0\0fixture abort\0',peer)
        elif spec['tftp']=='retransmit':
            assert packet==b'\0\6timeout\0'+b'1\0','held OACK'
            repeated,repeated_peer=receive();assert repeated==packet and repeated_peer==peer,'actual identical retransmission'
            send(b'\0\5\0\0fixture complete\0',peer)
        else:
            if spec['tftp']=='oack':
                assert packet==b'\0\6timeout\0'+b'1\0','actual OACK'
                send(b'\0\4\0\0',peer);packet,peer=receive()
            assert packet==b'\0\3\0\1pcap-evidence','actual TFTP DATA'
            send(b'\0\4\0\1',peer)
    save(folder/'tftp-witnesses.json',records)
    time.sleep(.05)
    return records


def start_side_without_health(runner):
    runner.log=(runner.out/(runner.side+'-'+runner.name+'.log')).open('wb')
    runner.process=subprocess.Popen(command(runner.root,runner.side,'-k','-C',runner.inside+'/config'),
        env=runner.env,stdout=runner.log,stderr=runner.log,start_new_session=True)
    deadline=time.monotonic()+3
    while not (runner.folder/'pid').exists() and time.monotonic()<deadline:
        assert runner.process.poll() is None,'DHCP dump startup';time.sleep(.005)
    assert (runner.folder/'pid').exists(),'DHCP dump readiness'
    runner.client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    runner.client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    runner.client.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'lo\0')
    runner.client.bind(('0.0.0.0',68));runner.client.settimeout(2)
    runner.descendants.update(children(runner.process.pid))


def dhcp_case(args,root,spec):
    label=spec['case'];folder=args.out/label;folder.mkdir()
    file=root/'m2/dump.pcap';file.unlink(missing_ok=True)
    flags=['bind-interfaces','dumpfile=/m2/dump.pcap','dumpmask='+spec.get('mask','0x1000'),*spec.get('extra',[])]
    if spec.get('relay'):flags += ['dhcp-relay=127.0.0.1,127.0.0.2']
    if spec.get('cross'):flags += ['enable-tftp','tftp-root=/m2/tftp','tftp-port-range=10690,10690']
    runner=Side(root,args.side,folder,label,flags)
    (folder/'config').write_text(runner.config.read_text())
    if spec.get('cross'):
        data=root/'m2/tftp';data.mkdir(exist_ok=True);(data/'evidence').write_bytes(b'pcap-evidence')
    start=time.time();witness=[];relay=None
    try:
        start_side_without_health(runner)
        save(folder/'identity.json',process_identity(root,runner.process.pid))
        if spec.get('cross'):
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
                endpoint.bind(('127.0.0.1',CLIENT));endpoint.settimeout(2)
                request=query('helper.test',1,0x7810);endpoint.sendto(request,('127.0.0.1',15353));reply=endpoint.recv(4096)
                witness += [dict(sport=CLIENT,dport=15353,payload=request.hex()),dict(sport=15353,dport=CLIENT,payload=reply.hex())]
        if spec.get('relay'):
            from dhcp_lease_lifecycle import packet as dhcp_packet
            relay=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            relay.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);relay.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
            relay.bind(('127.0.0.2',67));relay.settimeout(2)
            request=dhcp_packet(1,0x7820,1,'127.0.0.10')
            runner.client.sendto(request,('255.255.255.255',67))
            deadline=time.monotonic()+2
            while True:
                relay.settimeout(max(.01,deadline-time.monotonic()))
                forwarded,peer=relay.recvfrom(16384)
                if forwarded[3]==1 and forwarded[24:28]==socket.inet_aton('127.0.0.1'):break
            (folder/'relay-client.request').write_bytes(request);(folder/'relay-forwarded.request').write_bytes(forwarded)
            witness += [dict(sport=68,dport=67,payload=request.hex()),dict(sport=67,dport=67,payload=forwarded.hex())]
            if spec['relay']=='reply':
                response=bytearray(forwarded);response[0]=2;response[16:20]=socket.inet_aton('127.0.0.10')
                offset=response.index(bytes([53,1]),240)+2;response[offset]=2
                relay.sendto(response,('127.0.0.1',67));returned=runner.client.recv(16384)
                (folder/'relay-server.reply').write_bytes(response);(folder/'relay-client.reply').write_bytes(returned)
                witness += [dict(sport=67,dport=67,payload=response.hex()),dict(sport=67,dport=68,payload=returned.hex())]
        else:
            runner.dora()
            for index in [1,2]:
                base=folder/(runner.side+'-'+runner.name+'-'+str(index))
                witness += [dict(sport=68,dport=67,payload=Path(str(base)+'.request').read_bytes().hex()),
                            dict(sport=67,dport=68,payload=Path(str(base)+'.reply').read_bytes().hex())]
        if spec.get('cross'):witness += tftp_exchange(dict(tftp='data'),folder)
        time.sleep(.05)
        observed=pcap(file.read_bytes(),start,time.time());save(folder/'pcap.json',observed);save(folder/'transport-witnesses.json',witness)
        mask=int(spec.get('mask','0x1000'),0)
        expected=witness if mask else []
        assert [{key:row[key] for key in ['sport','dport','payload']} for row in observed['records']]==expected,'actual DHCP/relay/shared-writer independent witnesses'
        runner.log.flush();logged=(folder/(runner.side+'-'+runner.name+'.log')).read_text()
        events=re.findall(r'dumping packet (\d+) mask 0x([0-9a-f]+)',logged)
        assert [int(row[0]) for row in events]==list(range(1,len(expected)+1)),'DHCP/shared writer counter order'
        result=dict(case=label,pcap=observed,events=events)
        if spec.get('display'):
            prefixes=re.findall(r'(?:^|\n)[^\n]*?: (\d+) dumping packet (\d+) mask 0x([0-9a-f]+)',logged)
            assert prefixes==[],'DHCP high mask emitted a DNS display identifier';result['display_events']=prefixes
        return result
    finally:
        if relay:relay.close()
        cleanup=runner.stop();save(folder/'cleanup.json',cleanup)
        assert cleanup['exit']==0 and not cleanup['forced'] and not cleanup['remaining'],'DHCP dump cleanup'


def case(args,root,spec):
    label=spec['case'];folder=args.out/label;folder.mkdir()
    path=spec.get('path','/m2/dump.pcap');file=root/path.lstrip('/')
    if file.exists():
        if file.is_dir(): file.rmdir()
        else: file.unlink()
    if spec.get('fifo'): os.mkfifo(file,0o600)
    if spec.get('directory'): file.mkdir()
    if spec.get('bad')=='short':file.write_bytes(b'bad')
    if spec.get('bad')=='magic':file.write_bytes(bytes(24))
    if spec.get('seed_header'):file.write_bytes(struct.pack('=IHHIIII',0xa1b2c3d4,2,4,0,0,2000,101))
    reader=os.open(file,os.O_RDONLY|os.O_NONBLOCK) if spec.get('fifo') else None
    config=['port='+str(SERVER),'no-hosts','no-resolv','bind-interfaces','listen-address=127.0.0.1,::1','user=root','group=root',
        'pid-file=/m2/dump.pid','log-facility=-','host-record=dump.test,192.0.2.80','host-record=odd.dump.test,192.0.2.81']
    if not spec.get('no_file'):config += ['dumpfile='+('' if spec.get('empty_file') else path)]
    if 'mask' in spec:config += ['dumpmask='+spec['mask']]
    extras=spec.get('extra',[])
    for key in ['user=', 'group=']:
        if any(value.startswith(key) for value in extras):config=[value for value in config if not value.startswith(key)]
    config += extras
    upstream=Upstream(spec.get('ipv6',False)) if spec.get('upstream') else None
    if upstream:config += ['server='+upstream.address+'#'+str(UPSTREAM),'query-port='+str(QUERY_PORT)]
    if spec.get('tftp'):
        data=root/'m2/tftp';data.mkdir(exist_ok=True);(data/'evidence').write_bytes(b'pcap-evidence')
        config += ['enable-tftp','tftp-root=/m2/tftp','tftp-port-range=10690,10690']
    (root/'m2/dump.conf').write_text('\n'.join(config)+'\n');(folder/'config').write_text('\n'.join(config)+'\n')
    process=None;captured=b'';witness=[];start=time.time();events=[];display_events=[];transport_witness=[]
    try:
        for phase in range(2 if spec.get('restart') else 1):
            (root/'m2/dump.pid').unlink(missing_ok=True)
            with (folder/f'{phase}.log').open('wb') as log:
                process=subprocess.Popen(command(root,args.side,'-k','-C','/m2/dump.conf'),stdout=log,stderr=log)
                if spec.get('expect'):
                    status=process.wait(3);logged=(folder/f'{phase}.log').read_bytes()
                    assert status==3 and spec['expect'].encode() in logged,'C dump startup error class/message'
                    return dict(case=label,exit=status,diagnostic=logged.replace(b'dnsmasq-rs',b'dnsmasq').hex())
                deadline=time.monotonic()+3
                while not (root/'m2/dump.pid').exists() and time.monotonic()<deadline:
                    assert process.poll() is None,'startup died';time.sleep(.005)
                assert (root/'m2/dump.pid').exists(),'startup readiness'
                save(folder/f'{phase}.identity.json',process_identity(root,process.pid))
                if spec.get('tftp'):transport_witness += tftp_exchange(spec,folder)
                if spec.get('exchange'):
                    for index in range(spec.get('copies',1)):witness += exchange(spec,folder,phase*10+index)
                time.sleep(.05)
                captured += collect(root,file,reader) if reader is not None else b''
                stop(process)
                logged=(folder/f'{phase}.log').read_text()
                events += re.findall(r'dumping packet (\d+) mask 0x([0-9a-f]+)',logged)
                display_events += re.findall(r'(?:^|\n)[^\n]*?: (\d+) dumping packet (\d+) mask 0x([0-9a-f]+)',logged)
                assert not Path('/proc/'+str(process.pid)).exists(),'dump descriptor/process cleanup'
        if reader is None:captured=collect(root,file,reader)
        (folder/'dump.raw').write_bytes(captured)
        if spec.get('no_file') or spec.get('empty_file'):
            assert not captured,'disabled dump produced a PCAP file'
            observed=None
        else:
            observed=pcap(captured,start,time.time())
            save(folder/'pcap.json',observed)
            if not spec.get('seed_header'):
                assert observed['header']==dict(magic=0xa1b2c3d4,version=[2,4],zone=0,sigfigs=0,snaplen=1700 if 'edns-packet-max=1500' in spec.get('extra',[]) else 1432,network=101),'exact image file header'
            expected=[]
            value=spec.get('mask','-1') or '0'
            unsigned=value.lstrip('+-')
            mask=int(value,16 if unsigned.lower().startswith('0x') else 8 if len(unsigned)>1 and unsigned.startswith('0') else 10)
            forwards=[event for event in upstream.events if not event['tcp']] if upstream else []
            save(folder/'upstream-witnesses.json',upstream.events if upstream else [])
            if upstream:assert len(upstream.events)==1,'actual forwarding/cache caller count'
            cursor=0
            for index in range(0,len(witness),2):
                identifier=bytes.fromhex(witness[index])[:2]
                streams=[(1,witness[index])]
                if forwards and index==0:
                    streams += [(4,forwards[0]['request']),(8,forwards[0]['reply'])]
                streams += [(2,witness[index+1])]
                for flag,payload in streams:
                    if not spec.get('tcp') and mask&flag:
                        row=observed['records'][cursor]
                        assert row['payload']==payload,'PCAP payload must match actual client/upstream witness before ID normalization'
                        if flag in [4,8]:canonical_record(row,identifier)
                        expected.append(row['payload']);cursor+=1
            for witness_packet in transport_witness:
                if mask&0x8000:
                    row=observed['records'][cursor]
                    assert {key:row[key] for key in ['sport','dport','payload']}==witness_packet,'actual TFTP witness/caller capture'
                    expected.append(row['payload']);cursor+=1
            assert cursor==len(observed['records']),'PCAP exact caller record count'
            assert [int(row[0]) for row in events]==list(range(1,len(expected)+1)),'record count/order/logging'
            if label in ['header-create','header-user-nobody']:
                info=file.stat();assert info.st_mode&0o777==0o600 and info.st_uid==0,'startup create permission/owner before daemon privilege drop'
        result=dict(case=label,pcap=observed,events=events)
        if spec.get('display'):result['display_events']=display_events
        return result
    finally:
        if process is not None and process.poll() is None:stop(process)
        if reader is not None:os.close(reader)
        if upstream:upstream.close()
        if file.exists() and file.is_dir():file.rmdir()


def run_side(args):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','run_isolated.sh required'
    args.out.mkdir(parents=True,exist_ok=False)
    plan=json.loads((HERE/'m5_dump.json').read_text());save(args.out/'plan.json',plan)
    root=prepare(args.image_root,None,args.out/'filesystem',args.rust)
    rows=[];failures=[];selected=re.compile(args.select or '.')
    syntaxes=[('syntax-file',['dumpfile=/m2/pcap','dumpmask=0x3'],[],0),('syntax-cli',[],['--dumpfile=/m2/pcap','--dumpmask=3'],0),
              ('syntax-repeat-file',['dumpmask=1','dumpmask=2'],[],1),('syntax-repeat-cli',[],['--dumpmask=1','--dumpmask=2'],1)]
    for label,lines,flags,expected in syntaxes:
        if not selected.search(label):continue
        folder=args.out/label;folder.mkdir();(root/'m2/dump.conf').write_text('\n'.join(lines)+'\n')
        result=subprocess.run(command(root,args.side,'--test','-C','/m2/dump.conf',*flags),capture_output=True,timeout=3)
        (folder/'stdout').write_bytes(result.stdout);(folder/'stderr').write_bytes(result.stderr)
        if result.returncode!=expected:failures.append(dict(case=label,error='C syntax exit differs',exit=result.returncode))
        rows.append(dict(case=label,exit=result.returncode,stdout=result.stdout.hex(),stderr=result.stderr.replace(b'dnsmasq-rs',b'dnsmasq').hex()))
    for spec in profiles():
        if not selected.search(spec['case']):continue
        try:rows.append(dhcp_case(args,root,spec) if spec.get('dhcp') else case(args,root,spec))
        except Exception as error:
            failed=dict(case=spec['case'],error=repr(error));failures.append(failed);save(args.out/spec['case']/'failure.json',failed)
    needed={label for group in plan['boundaries'] for label in group['required_cases']}
    result=dict(side=args.side,rows=rows,failures=failures,missing=sorted(needed-{row['case'] for row in rows}),qualified=False,
        binary_sha256=sha256(args.image_root/'usr/sbin/dnsmasq' if args.side=='c' else args.rust),selected=args.select)
    save(args.out/'result.json',result);print(json.dumps(dict(side=args.side,executed=len(rows),missing=len(result['missing']),failures=failures)))
    return bool(failures)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both');parser.add_argument('--select')
    args=parser.parse_args()
    if args.side!='both':return run_side(args)
    args.out.mkdir(parents=True,exist_ok=False);exits={}
    for side in ['c','rust']:
        with (args.out/(side+'.launch.log')).open('wb') as log:
            argv=['sh',str(HERE/'run_isolated.sh'),sys.executable,__file__,'--side',side,'--image-root',str(args.image_root),'--rust',str(args.rust),'--out',str(args.out/side)]
            if args.select:argv+=['--select',args.select]
            exits[side]=subprocess.run(argv,stdout=log,stderr=log).returncode
    reports=[json.loads((args.out/side/'result.json').read_text()) for side in ['c','rust']]
    failures=[]
    if any(exits.values()) or any(row['failures'] for row in reports):failures.append(dict(exits=exits,sides=[row['failures'] for row in reports]))
    if reports[0]['rows']!=reports[1]['rows']:failures.append(dict(error='exact-image observation difference',c=reports[0]['rows'],rust=reports[1]['rows']))
    controls=[]
    if not failures:
        for label in ['missing-case','wrong-header','wrong-payload','fixture-failure']:
            mutant=copy.deepcopy(reports[1])
            if label=='missing-case':mutant['rows'].pop()
            elif label=='fixture-failure':mutant['failures'].append(dict(injected=True))
            else:
                target=next(row for row in mutant['rows'] if row.get('pcap') and row['pcap']['records'])
                if label=='wrong-header':target['pcap']['header']['snaplen']+=1
                else:target['pcap']['records'][0]['payload']='00'
            controls.append(dict(case=label,rejected=bool(mutant['failures']) or mutant['rows']!=reports[0]['rows']))
    qualified=not args.select and not failures and not any(row['missing'] for row in reports) and len(controls)==4 and all(row['rejected'] for row in controls)
    save(args.out/'result.json',dict(qualified=qualified,failures=failures,controls=controls,missing={row['side']:row['missing'] for row in reports},binary_sha256=sha256(args.rust)))
    print(json.dumps(dict(paired=len(reports[0]['rows']),failures=len(failures),qualified=qualified)))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
