#!/usr/bin/env python3
"""One EDNS family driver: exact image C supplies expectations, never Rust.

Each side must run through run_isolated.sh. Raw packets, rootfs overlay and
identity belong to private evidence. A partial run reports its missing required
cases and can never qualify the family. compare is read-only and runs locally.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import ipaddress
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
from dns_service_probe import exact_read, name, read_name, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256

MAC = bytes.fromhex('021122aabbcc')
CLIENT4, LISTEN4 = '192.0.2.17', '192.0.2.1'
CLIENT6, LISTEN6 = '2001:db8::17', '2001:db8::1'
CODES = {'mac':65001, 'device':65073, 'cpe':65074, 'ecs':8, 'umbrella':20292}

def tlv(code, data): return struct.pack('!HH', code, len(data)) + data

def rr(kind, data=b'', owner=b'\0', cls=1, ttl=0):
    return owner + struct.pack('!HHIH', kind, cls, ttl, len(data)) + data

def opt(data=b'', size=1232, ttl=0, owner=b'\0'):
    return rr(41, data, owner, size, ttl)

def query(host, ident=0x6200, *, opts=None, size=1232, ttl=0, kind=1, cls=1,
          additional=None, trailing=b'', flags=0x100):
    records = [] if opts is None else [opt(opts, size, ttl)]
    if additional is not None: records = additional
    return struct.pack('!6H', ident, flags, 1, 0, 0, len(records)) + name(host) + struct.pack('!HH', kind, cls) + b''.join(records) + trailing

def records(packet):
    _, _, qd, an, ns, ar = struct.unpack_from('!6H', packet)
    pos = 12
    for _ in range(qd): _, pos = read_name(packet, pos); pos += 4
    found=[]
    for section,count in [('answer',an),('authority',ns),('additional',ar)]:
        for _ in range(count):
            start=pos; _,fixed=read_name(packet,pos)
            kind,cls,ttl,length=struct.unpack_from('!HHIH',packet,fixed)
            pos=fixed+10+length
            if pos>len(packet): raise ValueError('truncated RR')
            found.append((section,kind,cls,ttl,packet[fixed+10:pos],start,fixed,pos))
    return found

def options(packet):
    opts=[r for r in records(packet) if r[0]=='additional' and r[1]==41]
    return opts[-1] if opts else None

def norm(packet):
    if packet is None: return {'result':'timeout'}
    try:
        value=semantics(packet); value['id']=0
        for record in value['records']:
            if record['type']!=41: record['ttl']=0
        value['bytes']=len(packet)
        return value
    except (ValueError,IndexError,struct.error) as error:
        return {'malformed':type(error).__name__, 'wire':b'\0\0'+packet[2:] if len(packet)>=2 else packet, 'bytes':len(packet)}

def serial(value):
    if isinstance(value,bytes): return value.hex()
    if isinstance(value,dict): return {k:serial(v) for k,v in value.items()}
    if isinstance(value,list): return [serial(v) for v in value]
    return value

# Grammar rows intentionally include C wrapping and malformed input boundaries.
SYNTAX = [
 ('raw-no-arg','add-mac'),('base64','add-mac=base64'),('text','add-mac=text'),
 ('raw-plus-text','add-mac\nadd-mac=text'),('base64-plus-text','add-mac=base64\nadd-mac=text'),
 ('mac-empty','add-mac='),('mac-invalid','add-mac=hex'),('mac-quoted','add-mac="text"'),
 ('ecs-no-arg','add-subnet'),('ecs-zero','add-subnet=0,0'),('ecs-v4-only','add-subnet=24'),
 ('ecs-v4-v6','add-subnet=24,56'),('ecs-fixed-v4','add-subnet=198.51.100.255/25'),
 ('ecs-fixed-v6','add-subnet=0,2001:db8:1234::ffff/65'),
 ('ecs-cross-family','add-subnet=2001:db8::ff/64,198.51.100.255/24'),
 ('ecs-empty','add-subnet='),('ecs-empty-second','add-subnet=24,'),
 ('ecs-extra-comma','add-subnet=24,56,32'),('ecs-invalid-number','add-subnet=-1,56'),
 ('ecs-invalid-address','add-subnet=not-an-address/24'),('ecs-u8-wrap','add-subnet=256,256'),
 ('ecs-atoi-wrap','add-subnet=4294967296,4294967296'),
 ('ecs-mask-overread-v4','add-subnet=33'),('ecs-mask-overread-v6','add-subnet=0,129'),
 ('cpe-no-arg','add-cpe-id'),('cpe-empty','add-cpe-id='),('cpe-text','add-cpe-id=router'),
 ('cpe-quoted-binary','add-cpe-id="one,two:three four"'),('cpe-repeat','add-cpe-id=one\nadd-cpe-id=two'),
 ('umbrella-no-arg','umbrella'),('umbrella-all','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456'),
 ('umbrella-zero','umbrella=orgid:0,deviceid:0000000000000000,assetid:0'),
 ('umbrella-repeat','umbrella=orgid:123\numbrella=assetid:456'),
 ('umbrella-max-u32','umbrella=orgid:4294967295,assetid:4294967295'),
 ('umbrella-overflow','umbrella=orgid:4294967296'),('umbrella-bad-device','umbrella=deviceid:001122aabbccddfg'),
 ('umbrella-invalid','umbrella=unknown:1'),('umbrella-empty-value','umbrella=orgid:'),
 ('umbrella-misplaced-marker','umbrella=xorgid:1'),
 ('max-default',''),('max-0','edns-packet-max=0'),('max-511','edns-packet-max=511'),
 ('max-512','edns-packet-max=512'),('max-65535','edns-packet-max=65535'),
 ('max-65536','edns-packet-max=65536'),('max-atoi-wrap','edns-packet-max=4294967296'),
 ('max-invalid','edns-packet-max=-1'),
]

# A scenario owns an actual packet/action, not just a boundary label.
PROFILES={}
def case(profile, directive, label, **kw):
    p=PROFILES.setdefault(profile,{'directive':directive,'cases':[]})
    assert p['directive']==directive
    p['cases'].append({'case':label,**kw})

for mode,directive in [('raw','add-mac'),('text','add-mac=text'),('base64','add-mac=base64')]:
    case(mode,directive,f'{mode}-ipv4',opts=b'')
case('raw','add-mac','raw-ipv6',ipv6=True,opts=b'')
case('raw','add-mac','raw-unknown',source='192.0.2.18',opts=b'')
case('both','add-mac\nadd-mac=text','raw-and-text',opts=b'')
case('text-wins','add-mac=base64\nadd-mac=text','text-wins',opts=b'')
for profile,directive,label,opts in [
 ('strip','strip-mac','strip-both-codes',tlv(65001,b'oldmac')+tlv(65073,b'oldtext')+tlv(123,b'other')),
 ('strip','strip-mac','strip-no-opt',None),
 ('raw','add-mac','mac-preserve-existing',tlv(65001,b'oldmac')),
 ('raw-strip','add-mac\nstrip-mac','mac-replace-existing',tlv(65001,b'oldmac')),
 ('raw-strip','add-mac\nstrip-mac','mac-missing-strip',tlv(65001,b'oldmac')+tlv(65073,b'oldtext')),
 ('text','add-mac=text','text-preserve-existing',tlv(65073,b'oldtext')),
 ('text-strip','add-mac=text\nstrip-mac','text-replace-existing',tlv(65073,b'oldtext')),
 ('strip','strip-mac','strip-empty-terminal',tlv(65001,b'')),
]: case(profile,directive,label,opts=opts,**({'source':'192.0.2.18'} if label=='mac-missing-strip' else {}))
for label,ipv6,profile,directive in [
 ('ecs-v4-24',False,'ecs','add-subnet=24,56'),('ecs-v6-56',True,'ecs','add-subnet=24,56'),
 ('ecs-v4-nonbyte',False,'ecs-nonbyte','add-subnet=25,65'),('ecs-v6-nonbyte',True,'ecs-nonbyte','add-subnet=25,65'),
 ('ecs-zero-wire',False,'ecs-zero','add-subnet=0,0'),('ecs-unset-family-zero',True,'ecs-v4','add-subnet=24'),
 ('ecs-fixed-wire',False,'ecs-fixed','add-subnet=198.51.100.255/25,2001:db8:1234::ffff/65'),
 ('ecs-cross-family-wire',False,'ecs-cross','add-subnet=2001:db8::ffff/65,198.51.100.255/25'),
]: case(profile,directive,label,ipv6=ipv6,opts=b'')
OLD_ECS=tlv(8,struct.pack('!HBB',1,24,0)+bytes.fromhex('cb0071'))
for profile,directive,label,data in [
 ('ecs','add-subnet=24,56','ecs-preserve-existing',OLD_ECS),
 ('ecs-strip','add-subnet=24,56\nstrip-subnet','ecs-replace-existing',OLD_ECS),
 ('strip-ecs','strip-subnet','ecs-strip-existing',OLD_ECS+tlv(123,b'other')),
 ('strip-ecs','strip-subnet','ecs-strip-no-opt',None),
 ('cpe','add-cpe-id=router','cpe-add',None),('cpe','add-cpe-id=router','cpe-replace',tlv(65074,b'old')),
 ('cpe-empty','add-cpe-id=','cpe-zero-length',b''),
 ('cpe-binary','add-cpe-id="one,two:three four"','cpe-binary',b''),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','umbrella-v4',b''),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','umbrella-v6',b''),
 ('umbrella-org','umbrella=orgid:123','umbrella-org-only',None),
 ('umbrella-zero','umbrella=orgid:0,deviceid:0000000000000000,assetid:0','umbrella-device-zero',None),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','umbrella-field-order',None),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','umbrella-replace',tlv(20292,b'old')),
]: case(profile,directive,label,opts=data,ipv6=label=='umbrella-v6')
# Existing OPT layout and malformed options exercise add_pseudoheader's exact loop.
for label,kw in [
 ('opt-final',{'opts':tlv(123,b'other')}),
 ('opt-nonfinal',{'additional':[opt(tlv(123,b'other')),rr(16,b'\x04tail',name('tail.edns.test'))]}),
 ('opt-multiple',{'additional':[opt(tlv(65074,b'one')),opt(tlv(65074,b'two'))]}),
 ('opt-owner-compressed',{'additional':[opt(tlv(123,b'other'),owner=b'\xc0\x0c')]}),
 ('opt-relocate-pointer',{'additional':[opt(tlv(123,b'other')),rr(5,name('alias.edns.test'),name('tail.edns.test'))]}),
 ('opt-duplicate-code',{'opts':tlv(65074,b'one')+tlv(65074,b'two')+tlv(123,b'tail')}),
 ('opt-malformed-tlv',{'opts':b'\x00\x7b\x00\xffbad'}),
 ('opt-terminal-zero',{'opts':tlv(65074,b'')}),
 ('opt-trailing-three',{'opts':tlv(123,b'other')+b'\x01\x02\x03'}),
 ('opt-packet-tail',{'opts':b'','trailing':b'\xff\xfe\xfd'}),
 ('opt-preserve-ttl-flags',{'opts':b'','ttl':0x01014001}),
]: case('cpe','add-cpe-id=router',label,**kw)
for label,kw in [
 ('signed-tkey-in',{'kind':249,'cls':1}),('unsigned-tkey-other-class',{'kind':249,'cls':255}),
 ('signed-tsig-last-any',{'additional':[opt(),rr(250,b'opaque',cls=255)]}),
 ('unsigned-tsig-nonlast',{'additional':[rr(250,b'opaque',cls=255),opt()]}),
 ('unsigned-tsig-other-class',{'additional':[opt(),rr(250,b'opaque',cls=1)]}),
 ('signed-no-opt',{'additional':[rr(250,b'opaque',cls=255)]}),
 ('signed-existing-opt',{'additional':[opt(OLD_ECS),rr(250,b'opaque',cls=255)]}),
]: case('cpe','add-cpe-id=router',label,**kw)

class Upstream:
    """Test-only selector thread, bounded shutdown; product stays single poll."""
    def __init__(self):
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.udp.bind(('127.0.0.2',0))
        self.port=self.udp.getsockname()[1]
        self.tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM); self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.tcp.bind(('127.0.0.2',self.port));self.tcp.listen(20)
        self.events=[];self.errors=[];self.stop=threading.Event();self.connections=[]
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def reply(self,packet,transport):
        host,end=read_name(packet,12);question=packet[12:end+4];kind=struct.unpack_from('!H',packet,end)[0]
        found=options(packet);self.events.append({'host':host,'transport':transport,'query':serial(norm(packet)),'wire':packet.hex()})
        data=ipaddress.ip_address('198.51.100.7').packed if kind==1 else b'\x04test'
        body=rr(kind,data,b'\xc0\x0c',1,600)
        opts=opt(found[4],1232,found[3]) if found else b''
        return packet[:2]+struct.pack('!5H',0x8180,1,1,0,int(bool(opts)))+question+body+opts
    def run(self):
        buffers={}
        while not self.stop.is_set():
            try:ready,_,_=select.select([self.udp,self.tcp,*self.connections],[],[],.05)
            except (ValueError,OSError):break
            for fd in ready:
                try:
                    if fd is self.udp:
                        packet,peer=fd.recvfrom(65535);fd.sendto(self.reply(packet,'udp'),peer)
                    elif fd is self.tcp:
                        conn,_=fd.accept();conn.setblocking(False);self.connections.append(conn);buffers[conn]=b''
                    else:
                        data=fd.recv(65535)
                        if not data:self.connections.remove(fd);buffers.pop(fd);fd.close();continue
                        buffers[fd]+=data
                        while len(buffers[fd])>=2 and len(buffers[fd])>=2+struct.unpack_from('!H',buffers[fd])[0]:
                            length=struct.unpack_from('!H',buffers[fd])[0];packet=buffers[fd][2:2+length];buffers[fd]=buffers[fd][2+length:]
                            response=self.reply(packet,'tcp');fd.sendall(struct.pack('!H',len(response))+response)
                except Exception as error:self.errors.append(repr(error))
    def close(self):
        self.stop.set();self.thread.join(2)
        for fd in [self.udp,self.tcp,*self.connections]:fd.close()
        if self.thread.is_alive():raise RuntimeError('upstream test thread leaked')

def network():
    if sorted(n for _,n in socket.if_nameindex())!=['lo']:raise ValueError('fresh loopback-only namespace required')
    subprocess.run(['ip','link','add','edns0','type','dummy'],check=True)
    subprocess.run(['ip','link','set','edns0','up'],check=True)
    for address in [LISTEN4+'/24',CLIENT4+'/24','192.0.2.18/24',LISTEN6+'/64',CLIENT6+'/64']:
        subprocess.run(['ip','addr','add',address,'dev','edns0','nodad'],check=True)
    for address in [CLIENT4,CLIENT6]:
        subprocess.run(['ip','neigh','replace',address,'lladdr',':'.join(f'{v:02x}' for v in MAC),'nud','permanent','dev','edns0'],check=True)

def exchange(port,packet,tcp=False,ipv6=False,source=None):
    family=socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as conn:
        conn.settimeout(.7);conn.bind((source or (CLIENT6 if ipv6 else CLIENT4),0));conn.connect((LISTEN6 if ipv6 else LISTEN4,port))
        try:
            if tcp:
                conn.sendall(struct.pack('!H',len(packet))+packet);return exact_read(conn,struct.unpack('!H',exact_read(conn,2))[0])
            conn.send(packet);return conn.recv(65535)
        except (socket.timeout,ConnectionError,ConnectionResetError):return None

def diagnostics(data):
    text=data.decode('utf-8','surrogateescape')
    return re.sub(r'dnsmasq(?:-rs)?: ?', '', text).strip()

def run(args):
    if os.geteuid()!=0 or os.environ.get('DNSMASQ_TEST_ISOLATED')!='1':raise ValueError('run through run_isolated.sh')
    network();out=args.out.resolve()
    if out.exists() or 'private' not in out.parts:raise ValueError('fresh private output required')
    out.mkdir(parents=True);root=prepare(args.image_root,None,out,args.rust)
    report={'side':args.side,'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'syntax':[],'profiles':[],'executed_cases':[],'failures':[]}
    pattern=re.compile(args.only or '.')
    for label,directive in SYNTAX:
        if not pattern.search(label):continue
        config=directive+'\n';(root/'m2/edns-syntax.conf').write_text(config)
        result=subprocess.run(command(root,args.side,'--test','-C','/m2/edns-syntax.conf'),capture_output=True,timeout=4)
        (out/f'syntax-{label}.conf').write_text(config);(out/f'syntax-{label}.stderr').write_bytes(result.stderr)
        report['syntax'].append({'case':label,'exit':result.returncode,'stdout':diagnostics(result.stdout),'stderr':diagnostics(result.stderr)})
        report['executed_cases'].append(label)
    for profile,spec in PROFILES.items():
        active=[row for row in spec['cases'] if pattern.search(row['case'])]
        if not active:continue
        folder=out/profile;folder.mkdir();upstream=Upstream()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:reserve.bind((LISTEN4,0));port=reserve.getsockname()[1]
        config=f'port={port}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={LISTEN4},{LISTEN6}\nserver=127.0.0.2#{upstream.port}\ncache-size=100\nlocal-ttl=600\nhost-record=local.edns.test,198.51.100.10\nuser=root\npid-file=/m2/edns.pid\nlog-facility=/m2/edns.log\n'+spec['directive']+'\n'
        (root/'m2/edns.conf').write_text(config);(folder/'config').write_text(config)
        trace={'profile':profile,'directive':spec['directive'],'rows':[],'upstream':[],'exit':None}
        log=(folder/'stderr').open('wb');process=None
        try:
            process=subprocess.Popen(command(root,args.side,'-k','-C','/m2/edns.conf'),stdout=log,stderr=log,start_new_session=True)
            for _ in range(300):
                if process.poll() is not None:raise RuntimeError(f'daemon startup exit {process.returncode}')
                if (root/'m2/edns.pid').exists():break
                time.sleep(.01)
            else:raise RuntimeError('daemon pid readiness timeout')
            trace['identity']=process_identity(root,process.pid)
            for index,row in enumerate(active):
                label=row['case'];params={k:v for k,v in row.items() if k not in ('case','tcp','ipv6','source')}
                packet=query(label+'.edns.test',0x6200+index,**params)
                reply=exchange(port,packet,row.get('tcp',False),row.get('ipv6',False),row.get('source'))
                (folder/f'{label}.query').write_bytes(packet)
                if reply is not None:(folder/f'{label}.reply').write_bytes(reply)
                trace['rows'].append({'case':label,'query':serial(norm(packet)),'reply':serial(norm(reply)),'upstream_after':len(upstream.events)})
                report['executed_cases'].append(label)
        except Exception as error:
            trace['failure']=repr(error);report['failures'].append({'profile':profile,'error':repr(error)})
        finally:
            if process is not None:
                if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(4)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(3)
                trace['exit']=process.returncode
            upstream.close();log.close();trace['upstream']=copy.deepcopy(upstream.events);trace['upstream_errors']=upstream.errors
            if (root/'m2/edns.pid').exists():(root/'m2/edns.pid').unlink()
            if (root/'m2/edns.log').exists():(folder/'daemon.log').write_bytes((root/'m2/edns.log').read_bytes());(root/'m2/edns.log').unlink()
        (folder/'trace.json').write_text(json.dumps(trace,indent=2)+'\n');report['profiles'].append(trace)
    manifest=json.loads(Path(__file__).with_suffix('.json').read_text());required={c for b in manifest['boundaries'] for c in b['required_cases']}
    report['missing_required_cases']=sorted(required-set(report['executed_cases']));report['required_count']=len(required)
    report['driver_sha256']=sha256(__file__);report['manifest_sha256']=sha256(Path(__file__).with_suffix('.json'))
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'side':args.side,'executed':len(report['executed_cases']),'missing':len(report['missing_required_cases']),'failures':report['failures']}))
    return 1 if report['failures'] else 0

def compare(args):
    left=json.loads((args.c/'result.json').read_text());right=json.loads((args.candidate/'result.json').read_text())
    diffs=[]
    if left['executed_cases']!=right['executed_cases']:diffs.append({'kind':'executed-case-map','c':left['executed_cases'],'rust':right['executed_cases']})
    for a,b in zip(left['syntax'],right['syntax']):
        if a!=b:diffs.append({'kind':'syntax','c':a,'rust':b})
    for a,b in zip(left['profiles'],right['profiles']):
        if a['rows']!=b['rows']:diffs.append({'kind':'rows','profile':a['profile'],'c':a['rows'],'rust':b['rows']})
        an=[{k:v for k,v in e.items() if k!='wire'} for e in a['upstream']];bn=[{k:v for k,v in e.items() if k!='wire'} for e in b['upstream']]
        if an!=bn:diffs.append({'kind':'upstream','profile':a['profile'],'c':an,'rust':bn})
        for side,t in [('c',a),('rust',b)]:
            if t['exit']!=0 or t.get('failure') or t['upstream_errors']:diffs.append({'kind':'lifecycle','profile':a['profile'],'side':side,'trace':t})
    result={'c_identity':left['c_sha256'],'candidate_identity':right['rust_sha256'],'executed':len(left['executed_cases']),'missing':left['missing_required_cases'],'differences':diffs,'qualified':not diffs and not left['missing_required_cases'] and not right['missing_required_cases']}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'differences':len(diffs),'qualified':result['qualified'],'executed':result['executed'],'missing':len(result['missing'])}))
    return int(bool(diffs))

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('run');p.add_argument('--side',choices=['c','rust'],required=True);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--only')
    p=sub.add_parser('compare');p.add_argument('--c',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();raise SystemExit(run(args) if args.action=='run' else compare(args))
if __name__=='__main__':main()
