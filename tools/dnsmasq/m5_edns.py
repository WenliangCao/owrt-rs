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
import sys
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

# Cache and forwarding-table behavior are measured by repeated packets and
# actual upstream event counts, not inferred from the emitted option bytes.
for profile,directive,label,kw in [
 ('ordinary','','cache-client-ecs-nonzero',{'opts':OLD_ECS}),
 ('ordinary','','cache-client-ecs-zero',{'opts':tlv(8,b'\0\x01\0\0')}),
 ('ordinary','','cache-client-ecs-malformed',{'opts':b'\0\x08\0\xffbad'}),
 ('ecs','add-subnet=24,56','cache-dynamic-ecs',{'opts':b''}),
 ('ecs-fixed','add-subnet=198.51.100.255/25,2001:db8:1234::ffff/65','cache-fixed-ecs',{'opts':b''}),
 ('ecs-zero','add-subnet=0,0','cache-zero-ecs',{'opts':b''}),
 ('raw','add-mac','cache-mac-known',{'opts':b''}),
 ('raw','add-mac','cache-mac-unknown',{'opts':b'','source':'192.0.2.18'}),
 ('strip-ecs','strip-subnet','cache-strip-ecs',{'opts':OLD_ECS}),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','cache-umbrella',{'opts':b''}),
 ('cpe','add-cpe-id=router','cache-cpe',{'opts':b''}),
 ('mac-ecs-fixed','add-mac\nadd-subnet=198.51.100.0/24','cache-ecs-overrides-mac',{'opts':b''}),
 ('umbrella-ecs-zero','umbrella\nadd-subnet=0,0','cache-ecs-overrides-umbrella',{'opts':b''}),
 ('ecs','add-subnet=24,56','cache-local-retained',{'opts':b'','host':'local.edns.test'}),
 ('ecs','add-subnet=24,56','cache-rd-unmodified',{'opts':b'','flags':0}),
 ('cpe','add-cpe-id=router','cpe-stays-cacheable',{'opts':b''}),
 ('raw','add-mac','signed-policy-cacheable',{'kind':249,'cls':1}),
]: case(profile,directive,label,repeat=2,**kw)
for profile,directive,label,kw in [
 ('ordinary','','coalesce-ordinary',{'opts':b''}),
 ('cpe','add-cpe-id=router','coalesce-cpe',{'opts':b''}),
 ('ordinary','','coalesce-client-ecs',{'opts':OLD_ECS}),
 ('ecs','add-subnet=24,56','coalesce-dynamic-ecs',{'opts':b''}),
 ('ecs-fixed','add-subnet=198.51.100.255/25,2001:db8:1234::ffff/65','coalesce-fixed-ecs',{'opts':b''}),
 ('raw','add-mac','coalesce-mac',{'opts':b''}),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','coalesce-umbrella',{'opts':b''}),
 ('ecs','add-subnet=24,56','coalesce-same-source-uncacheable',{'opts':b'','same_socket':True}),
]: case(profile,directive,label,coalesce=True,**kw)
for label,reply in [
 ('reply-ecs-valid','echo'),('reply-ecs-scope-any','scope'),('reply-ecs-bad-family','family'),
 ('reply-ecs-bad-mask','mask'),('reply-ecs-bad-length','length'),('reply-ecs-bad-address','address'),
 ('reply-ecs-absent','absent'),('reply-ecs-malformed-tlv','malformed'),
 ('reply-ecs-duplicate-mismatch','duplicate'),('reply-ecs-check-before-strip','address'),
 ('reply-ecs-check-signed','signed-address'),('reply-ecs-udp-remains-pending','mismatch-then-valid'),
 ('reply-ecs-tcp-local-fallback','address'),
]: case('ecs','add-subnet=24,56',label,opts=None if label=='reply-ecs-check-before-strip' else b'',response=reply,tcp=label=='reply-ecs-tcp-local-fallback')
case('ecs-fixed','add-subnet=198.51.100.255/25,2001:db8:1234::ffff/65','reply-ecs-fixed-check',opts=b'',response='scope')
for label,kw in [
 ('capacity-new-exact',{'target_size':491}),('capacity-new-minus-one',{'target_size':492}),
 ('capacity-existing-exact',{'target_size':502,'opts':b''}),
 ('capacity-existing-minus-one',{'target_size':503,'opts':b''}),
 ('capacity-nonlast-insufficient',{'target_size':503,'nonfinal':True,'opts':b''}),
]: case('cpe-max512','add-cpe-id=router\nedns-packet-max=512',label,**kw)
case('strip-max512','strip-mac\nedns-packet-max=512','capacity-strip-truncate',opts=tlv(65001,b'oldmac')+b'abc',target_size=503)
case('max512','edns-packet-max=512','capacity-empty-opt-reserve-four',target_size=501)
case('ecs-max512','add-subnet=24\nedns-packet-max=512','capacity-policy-no-room-cacheable',target_size=510,repeat=2)
for label,kw in [
 ('udp-original-opt-envelope',{'opts':None}),
 ('udp-decorated-local-envelope',{'opts':None,'host':'local.edns.test'}),
 ('tcp-added-opt-retained',{'opts':None,'tcp':True}),
]: case('cpe','add-cpe-id=router',label,**kw)
case('ordinary','','tcp-no-policy-no-opt',tcp=True)
case('ordinary','','tcp-cache-read',opts=b'',transports=['udp','tcp'])
case('ordinary','','tcp-cache-write',opts=b'',transports=['tcp','udp'])
# Unsafe C reads remain actual runtime cases, with raw outputs retained.
case('ecs-mask33','add-subnet=33','ecs-mask-overread-v4-wire',opts=b'')
case('ecs-mask129','add-subnet=0,129','ecs-mask-overread-v6-wire',opts=b'',ipv6=True)
case('ecs-wrap','add-subnet=256,256','ecs-u8-wrap-wire',opts=b'')
case('cpe','add-cpe-id=router','opt-malformed-rr',additional=[opt(),b'\0\0\x10\0\x01\0\0\0\0\0\xffbad'])

for profile,directive,label in [
 ('ecs32','add-subnet=32,128','coalesce-ecs-distinct-ip'),
 ('raw','add-mac','coalesce-mac-distinct-ip'),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','coalesce-umbrella-distinct-ip'),
]: case(profile,directive,label,opts=b'',coalesce=True,sources=[CLIENT4,'192.0.2.19'],response='client-keyed')

for profile,directive,label in [
 ('ecs32','add-subnet=32,128','coalesce-ecs-distinct-ip-independent'),
 ('raw','add-mac','coalesce-mac-distinct-ip-independent'),
 ('umbrella','umbrella=orgid:123,deviceid:001122aabbccddff,assetid:456','coalesce-umbrella-distinct-ip-independent'),
]: case(profile,directive,label,opts=b'',repeat=2,sources=[CLIENT4,'192.0.2.19'],response='client-keyed')
for label,kw in [
 ('max-udp-receive-drop',{'target_size':513}),
 ('max-client-below-512',{'opts':b'','size':1}),
 ('max-client-above-config',{'opts':b'','size':65535}),
 ('max-tcp-receive-capacity',{'target_size':778,'tcp':True}),
 ('max-tcp-response-large',{'tcp':True,'response':'large'}),
 ('max-udp-upstream-truncate',{'opts':b'','response':'large'}),
 ('max-udp-tc-fallback',{'opts':b'','response':'tc-large','transports':['udp','tcp']}),
]: case('max512','edns-packet-max=512',label,**kw)
case('max512-local','edns-packet-max=512\n'+'\n'.join('host-record=large.local.edns.test,198.51.100.'+str(v) for v in range(1,65)),'max-udp-local-truncate',host='large.local.edns.test',opts=b'')
for label,action in [
 ('tcp-connection-mac-snapshot','connection-change'),
 ('tcp-new-connection-refresh','negative-new-connection'),
 ('tcp-neighbor-nonlazy','negative-new-connection'),
 ('udp-neighbor-negative-lazy','negative-udp'),
 ('udp-neighbor-90-refresh','negative-90'),
 ('neighbor-negative-lazy-before-90','negative-udp'),
 ('neighbor-negative-nonlazy-accept','negative-new-connection'),
 ('neighbor-positive-retained-before-90','positive-change'),
]: case('neighbor-'+label,'add-mac',label,opts=b'',action=action)

for label, directive, length, mode, tcp in [
 ('raw-length-one','add-mac',1,'complete',False),
 ('raw-length-sixteen','add-mac',16,'complete',False),
 ('raw-length-seventeen','add-mac',17,'complete',False),
 ('text-nonsix','add-mac=text',1,'complete',False),
 ('neighbor-over16-ignored','add-mac',17,'complete',False),
 ('neighbor-ip-not-interface','add-mac',6,'complete',False),
 ('neighbor-valid-complete-dump','add-mac',6,'complete',False),
 ('neighbor-invalid-partial-dump','add-mac',6,'partial-error',False),
 ('neighbor-dump-error-progress','add-mac',6,'error',False),
 ('neighbor-udp-query-park-resume','add-mac',6,'complete',False),
 ('neighbor-tcp-accept-park-snapshot','add-mac',6,'complete',True),
]: case('inject-'+label,directive,label,opts=b'',inject=mode,mac_length=length,tcp=tcp)

class Upstream:
    """Test-only selector thread, bounded shutdown; product stays single poll."""
    def __init__(self):
        self.behaviors={}; self.delayed=[]
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.udp.bind(('127.0.0.2',0))
        self.port=self.udp.getsockname()[1]
        self.tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM); self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.tcp.bind(('127.0.0.2',self.port));self.tcp.listen(20)
        self.events=[];self.errors=[];self.stop=threading.Event();self.connections=[]
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def reply(self,packet,transport):
        host,end=read_name(packet,12);question=packet[12:end+4];kind=struct.unpack_from('!H',packet,end)[0]
        try:found=options(packet)
        except (ValueError,IndexError,struct.error):found=None
        self.events.append({'host':host,'transport':transport,'query':serial(norm(packet)),'wire':packet.hex()})
        data=ipaddress.ip_address('198.51.100.7').packed if kind==1 else b'\x04test'
        body=rr(kind,data,b'\xc0\x0c',1,600)
        data=found[4] if found else b''
        behavior=self.behaviors.get(host.split('.')[0],{}).get('response','echo')
        extra=b''
        if found and behavior not in ('echo','mismatch-then-valid'):
            parts=[];at=0
            while at+4<=len(data):
                code,size=struct.unpack_from('!HH',data,at);value=data[at+4:at+4+size];at+=4+size
                if code==8:
                    changed=bytearray(value)
                    if behavior=='absent':continue
                    if behavior=='scope' and len(changed)>=4:changed[3]=255
                    if behavior=='family' and len(changed)>=2:changed[1]^=3
                    if behavior=='mask' and len(changed)>=3:changed[2]^=1
                    if behavior=='length':changed=changed[:-1]
                    if behavior in ('address','signed-address','duplicate') and len(changed)>4:changed[-1]^=1
                    if behavior=='duplicate':parts.append(tlv(code,value))
                    value=bytes(changed)
                parts.append(tlv(code,value))
            data=b''.join(parts)
            if behavior=='malformed':data=b'\0\x08\0\xffbad'
            if behavior=='signed-address':extra=rr(250,b'opaque',cls=255)
        opts=opt(data,1232,found[3]) if found else b''
        if behavior=='client-keyed':
            at=0;tag=0
            while at+4<=len(data):
                code,size=struct.unpack_from('!HH',data,at);value=data[at+4:at+4+size];at+=4+size
                if code==8 and size>=8:tag=value[-1]
                elif code==65001 and value:tag=value[-1]
                elif code==20292 and b'\0\x10' in value:
                    where=value.index(b'\0\x10');tag=value[where+5]
            body=rr(kind,ipaddress.ip_address('198.51.100.'+str(tag)).packed,b'\xc0\x0c',1,600)
        flags=0x8380 if behavior=='tc-large' and transport=='udp' else 0x8180
        count=1
        if behavior in ('large','tc-large'):
            body=rr(16,b'\xff'+b'X'*255+b'\xff'+b'Y'*255+b'\x7f'+b'Z'*127,b'\xc0\x0c',1,600)
        answer=packet[:2]+struct.pack('!5H',flags,1,count,0,int(bool(opts))+int(bool(extra)))+question+body+opts+extra
        return answer
    def run(self):
        buffers={}
        while not self.stop.is_set():
            for deadline,fd,peer,response in self.delayed[:]:
                if time.monotonic()>=deadline:
                    fd.sendto(response,peer);self.delayed.remove((deadline,fd,peer,response))
            try:ready,_,_=select.select([self.udp,self.tcp,*self.connections],[],[],.02)
            except (ValueError,OSError):break
            for fd in ready:
                try:
                    if fd is self.udp:
                        packet,peer=fd.recvfrom(65535);response=self.reply(packet,'udp');host=read_name(packet,12)[0]
                        behavior=self.behaviors.get(host.split('.')[0],{})
                        if behavior.get('coalesce'):
                            self.delayed.append((time.monotonic()+.15,fd,peer,response))
                        elif behavior.get('response')=='mismatch-then-valid':
                            bad=bytearray(response);found=options(response)
                            if found and found[4]:bad[found[7]-1]^=1
                            fd.sendto(bytes(bad),peer);self.delayed.append((time.monotonic()+.15,fd,peer,response))
                        else:fd.sendto(response,peer)
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
    for address in [LISTEN4+'/24',CLIENT4+'/24','192.0.2.18/24','192.0.2.19/24',LISTEN6+'/64',CLIENT6+'/64']:
        subprocess.run(['ip','addr','add',address,'dev','edns0',*(['nodad'] if ':' in address else [])],check=True)
    for address in [CLIENT4,CLIENT6,'192.0.2.19']:
        subprocess.run(['ip','neigh','replace',address,'lladdr',':'.join(f'{v:02x}' for v in (bytes.fromhex('025566aabbdd') if address=='192.0.2.19' else MAC)),'nud','permanent','dev','edns0'],check=True)

def exchange(port,packet,tcp=False,ipv6=False,source=None):
    family=socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as conn:
        conn.settimeout(.7);conn.bind((source or (CLIENT6 if ipv6 else CLIENT4),0));conn.connect((LISTEN6 if ipv6 else LISTEN4,port))
        try:
            if tcp:
                conn.sendall(struct.pack('!H',len(packet))+packet);return exact_read(conn,struct.unpack('!H',exact_read(conn,2))[0])
            conn.send(packet);return conn.recv(65535)
        except (socket.timeout,ConnectionError,ConnectionResetError):return None

def packet_for(row,index):
    excluded={'action','inject','mac_length','sources','case','tcp','ipv6','source','repeat','host','coalesce','same_socket','response','transports','target_size','nonfinal'}
    params={k:v for k,v in row.items() if k not in excluded}
    host=row.get('host',row['case']+'.edns.test')
    packet=query(host,0x6200+index,**params)
    if 'target_size' not in row:return packet
    target=row['target_size']
    base=query(host,0x6200+index)
    if row.get('opts') is not None:
        # One padding TLV keeps the existing OPT scanner on a complete option.
        other=rr(16,b'\x04tail',name('tail.edns.test')) if row.get('nonfinal') else b''
        size=target-len(base)-11-4-len(params.get('opts',b''))-len(other)
        opts=params.get('opts',b'')+tlv(123,b'p'*size)
        return query(host,0x6200+index,additional=[opt(opts),*([other] if other else [])])
    size=target-len(base)-11
    return query(host,0x6200+index,additional=[rr(16,b'p'*size)])

def coalesce_exchange(port,packet,row):
    sockets=[];results=[];witness=[]
    try:
        for index in range(2):
            if index and row.get('same_socket'):conn=sockets[0]
            else:
                conn=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);conn.settimeout(.7)
                conn.bind((row.get('sources',[CLIENT4,CLIENT4])[index],0));conn.connect((LISTEN4,port));sockets.append(conn)
            wire=packet if row.get('same_socket') else struct.pack('!H',0x6300+index)+packet[2:]
            conn.send(wire);witness.append({'source':conn.getsockname(),'wire':wire.hex()})
        for index in range(2):
            try:results.append(norm(sockets[0 if row.get('same_socket') else index].recv(65535)))
            except socket.timeout:results.append(norm(None))
    finally:
        for conn in sockets:conn.close()
    return serial(results),witness

def set_neighbor(address,mac=None):
    if mac is None:
        subprocess.run(['ip','neigh','del',address,'dev','edns0'],capture_output=True)
    else:
        subprocess.run(['ip','neigh','replace',address,'lladdr',':'.join(f'{v:02x}' for v in mac),'nud','permanent','dev','edns0'],check=True)

def neighbor_schedule(port,packet,row):
    action=row['action'];results=[];witness=[]
    if action=='connection-change':
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as conn:
            conn.settimeout(2);conn.bind((CLIENT4,0));conn.connect((LISTEN4,port))
            for index in range(2):
                wire=struct.pack('!H',0x6400+index)+packet[2:]
                conn.sendall(struct.pack('!H',len(wire))+wire)
                reply=exact_read(conn,struct.unpack('!H',exact_read(conn,2))[0]);results.append(serial(norm(reply)))
                if index==0:set_neighbor(CLIENT4,bytes.fromhex('025566aabbdd'))
        set_neighbor(CLIENT4,MAC)
    elif action=='positive-change':
        results.append(serial(norm(exchange(port,packet))))
        set_neighbor(CLIENT4,bytes.fromhex('025566aabbdd'))
        results.append(serial(norm(exchange(port,struct.pack('!H',0x6401)+packet[2:]))))
        set_neighbor(CLIENT4,MAC)
    else:
        address='192.0.2.18';set_neighbor(address)
        first_tcp=action=='negative-new-connection'
        results.append(serial(norm(exchange(port,packet,first_tcp,source=address))))
        set_neighbor(address,bytes.fromhex('025566aabbdd'))
        if action=='negative-90':
            start=time.monotonic();next_health=start;health=[]
            while time.monotonic()-start<91:
                if time.monotonic()>=next_health:
                    wire=query('local.edns.test',0x6500+len(health))
                    answer=exchange(port,wire,source=CLIENT4)
                    if answer is None:raise AssertionError('DNS progress lost during 90s neighbor refresh window')
                    health.append(serial(norm(answer)));next_health+=5
                    print(json.dumps({'case':row['case'],'elapsed':round(time.monotonic()-start,1),'health':len(health)}),flush=True)
                time.sleep(.05)
            witness.append({'real_wait_seconds':time.monotonic()-start,'health_packets':health})
        results.append(serial(norm(exchange(port,struct.pack('!H',0x6401)+packet[2:],first_tcp,source=address))))
        set_neighbor(address)
    return results,witness

def diagnostics(data):
    text=data.decode('utf-8','surrogateescape')
    return re.sub(r'dnsmasq(?:-rs)?: ?', '', text).strip()

def start_netlink_fixture(pid, folder, row):
    output=folder/(row['case']+'.netlink.json')
    log=(folder/(row['case']+'.netlink.stderr')).open('wb')
    tracer=subprocess.Popen([sys.executable,str(Path(__file__).with_name('m5_edns_netlink.py')),
                             '--pid',str(pid),'--out',str(output),'--mode',row['inject'],
                             '--length',str(row.get('mac_length',6))],stdout=log,stderr=log)
    deadline=time.monotonic()+4
    while not output.with_suffix('.ready').exists():
        if tracer.poll() is not None or time.monotonic()>deadline:
            tracer.kill();tracer.wait();log.close()
            raise AssertionError('netlink tracer failed to attach; inspect retained stderr')
        time.sleep(.01)
    return tracer,log,output

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
                label=row['case'];packet=packet_for(row,index);upstream.behaviors[label]=row
                (folder/f'{label}.query').write_bytes(packet)
                before=len(upstream.events);replies=[]
                fixture=start_netlink_fixture(process.pid,folder,row) if row.get('inject') else None
                if row.get('action'):
                    replies,witness=neighbor_schedule(port,packet,row)
                    trace.setdefault('action_witness',[]).append({'case':label,'witness':witness})
                elif row.get('coalesce'):
                    replies,witness=coalesce_exchange(port,packet,row)
                    trace.setdefault('client_witness',[]).append({'case':label,'clients':witness})
                else:
                    transports=row.get('transports',[('tcp' if row.get('tcp') else 'udp')]*row.get('repeat',1))
                    for step,transport in enumerate(transports):
                        wire=struct.pack('!H',0x6200+index+step)+packet[2:]
                        reply=exchange(port,wire,transport=='tcp',row.get('ipv6',False),row.get('sources',[row.get('source')]*len(transports))[step])
                        if reply is not None:(folder/f'{label}-{step}.reply').write_bytes(reply)
                        replies.append(serial(norm(reply)))
                if fixture:
                    tracer,tracer_log,tracer_output=fixture
                    try:tracer.wait(4)
                    except subprocess.TimeoutExpired:tracer.kill();tracer.wait();raise AssertionError('netlink injection did not complete')
                    finally:tracer_log.close()
                    proof=json.loads(tracer_output.read_text())
                    if tracer.returncode or not proof['injected']:raise AssertionError('required netlink injection unproven')
                    trace.setdefault('injection_witness',[]).append({'case':label,'proof':proof})
                    health=exchange(port,query('local.edns.test',0x6600+index))
                    if health is None:raise AssertionError('DNS health failed after neighbor fixture')
                    trace.setdefault('health_witness',[]).append({'case':label,'reply':serial(norm(health))})
                trace['rows'].append({'case':label,'query':serial(norm(packet)),'replies':replies,'upstream_delta':len(upstream.events)-before})
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
    report['netlink_driver_sha256']=sha256(Path(__file__).with_name('m5_edns_netlink.py'))
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
