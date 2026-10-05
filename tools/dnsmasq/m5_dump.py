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
import time

from dns_service_probe import query, exact_read
from m2_rootfs import command, prepare, process_identity, sha256

HERE = Path(__file__).resolve().parent
SERVER, CLIENT = 10553, 10554


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


def stop(process):
    if process.poll() is None:
        process.terminate()
        try: process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();raise AssertionError('forced service cleanup')
    assert process.returncode == 0, 'ordinary TERM exit'


def profiles():
    rows=[
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
        request=query(spec.get('name','dump.test'),1,0x7800+serial)
        endpoint.sendall(struct.pack('!H',len(request))+request if kind==socket.SOCK_STREAM else request)
        response=exact_read(endpoint,struct.unpack('!H',exact_read(endpoint,2))[0]) if kind==socket.SOCK_STREAM else endpoint.recv(4096)
    assert response[:2] == request[:2], 'actual network reply identity'
    (folder/f'{serial}.request').write_bytes(request);(folder/f'{serial}.reply').write_bytes(response)
    return [request.hex(),response.hex()]


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
    if spec.get('seed_header'):file.write_bytes(struct.pack('=IHHIIII',0xa1b2c3d4,7,8,9,10,2000,101))
    reader=os.open(file,os.O_RDONLY|os.O_NONBLOCK) if spec.get('fifo') else None
    config=['port='+str(SERVER),'no-hosts','no-resolv','bind-interfaces','listen-address=127.0.0.1,::1','user=root','group=root',
        'pid-file=/m2/dump.pid','log-facility=-','host-record=dump.test,192.0.2.80','host-record=odd.dump.test,192.0.2.81']
    if not spec.get('no_file'):config += ['dumpfile='+('' if spec.get('empty_file') else path)]
    if 'mask' in spec:config += ['dumpmask='+spec['mask']]
    config += spec.get('extra',[])
    (root/'m2/dump.conf').write_text('\n'.join(config)+'\n');(folder/'config').write_text('\n'.join(config)+'\n')
    process=None;captured=b'';witness=[];start=time.time();events=[]
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
                if spec.get('exchange'):
                    for index in range(spec.get('copies',1)):witness += exchange(spec,folder,phase*10+index)
                time.sleep(.05)
                captured += collect(root,file,reader) if reader is not None else b''
                stop(process)
                logged=(folder/f'{phase}.log').read_text()
                events += re.findall(r'dumping packet (\d+) mask 0x([0-9a-f]+)',logged)
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
            mask=int(spec.get('mask','-1') or '0',0)
            for index,payload in enumerate(witness):
                if not spec.get('tcp') and mask & (1 if index%2==0 else 2):expected.append(payload)
            assert [row['payload'] for row in observed['records']]==expected,'PCAP payload/order independent network witnesses'
            assert [int(row[0]) for row in events]==list(range(1,len(expected)+1)),'record count/order/logging'
            if spec.get('header-user-nobody') or label in ['header-create','header-user-nobody']:
                info=file.stat();assert info.st_mode&0o777==0o600 and info.st_uid==0,'startup create permission/owner before daemon privilege drop'
        return dict(case=label,pcap=observed,events=events)
    finally:
        if process is not None and process.poll() is None:stop(process)
        if reader is not None:os.close(reader)
        if file.exists() and file.is_dir():file.rmdir()


def run_side(args):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','run_isolated.sh required'
    args.out.mkdir(parents=True,exist_ok=False)
    plan=json.loads((HERE/'m5_dump.json').read_text());save(args.out/'plan.json',plan)
    root=prepare(args.image_root,None,args.out/'filesystem',args.rust)
    rows=[];failures=[]
    syntaxes=[('syntax-file',['dumpfile=/m2/pcap','dumpmask=0x3'],[],0),('syntax-cli',[],['--dumpfile=/m2/pcap','--dumpmask=3'],0),
              ('syntax-repeat-file',['dumpmask=1','dumpmask=2'],[],1),('syntax-repeat-cli',[],['--dumpmask=1','--dumpmask=2'],1)]
    for label,lines,flags,expected in syntaxes:
        folder=args.out/label;folder.mkdir();(root/'m2/dump.conf').write_text('\n'.join(lines)+'\n')
        result=subprocess.run(command(root,args.side,'--test','-C','/m2/dump.conf',*flags),capture_output=True,timeout=3)
        (folder/'stdout').write_bytes(result.stdout);(folder/'stderr').write_bytes(result.stderr)
        if result.returncode!=expected:failures.append(dict(case=label,error='C syntax exit differs',exit=result.returncode))
        rows.append(dict(case=label,exit=result.returncode,stdout=result.stdout.hex(),stderr=result.stderr.replace(b'dnsmasq-rs',b'dnsmasq').hex()))
    for spec in profiles():
        try:rows.append(case(args,root,spec))
        except Exception as error:
            failed=dict(case=spec['case'],error=repr(error));failures.append(failed);save(args.out/spec['case']/'failure.json',failed)
    needed={label for group in plan['boundaries'] for label in group['required_cases']}
    result=dict(side=args.side,rows=rows,failures=failures,missing=sorted(needed-{row['case'] for row in rows}),qualified=False,
        binary_sha256=sha256(args.image_root/'usr/sbin/dnsmasq' if args.side=='c' else args.rust))
    save(args.out/'result.json',result);print(json.dumps(dict(side=args.side,executed=len(rows),missing=len(result['missing']),failures=failures)))
    return bool(failures)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both')
    args=parser.parse_args()
    if args.side!='both':return run_side(args)
    args.out.mkdir(parents=True,exist_ok=False);exits={}
    for side in ['c','rust']:
        with (args.out/(side+'.launch.log')).open('wb') as log:
            exits[side]=subprocess.run(['sh',str(HERE/'run_isolated.sh'),sys.executable,__file__,'--side',side,'--image-root',str(args.image_root),'--rust',str(args.rust),'--out',str(args.out/side)],stdout=log,stderr=log).returncode
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
    qualified=not failures and not any(row['missing'] for row in reports) and len(controls)==4 and all(row['rejected'] for row in controls)
    save(args.out/'result.json',dict(qualified=qualified,failures=failures,controls=controls,missing={row['side']:row['missing'] for row in reports},binary_sha256=sha256(args.rust)))
    print(json.dumps(dict(paired=len(reports[0]['rows']),failures=len(failures),qualified=qualified)))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
