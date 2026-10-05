#!/usr/bin/env python3
"""Single exact-image DNS cache family driver; incomplete runs cannot qualify.

Run each side in a fresh run_isolated.sh namespace. Test upstream I/O uses one
bounded selector thread; production continues to use its single poll owner.
The original image C supplies all expectations. Raw evidence stays private.
"""
from __future__ import annotations
import argparse
import copy
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
from dns_service_probe import exact_read, name as ascii_name, read_name, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256

LISTEN, CLIENT = '192.0.2.1', '192.0.2.17'
LEASE_CLIENT = '192.0.2.42'
ZONE = 'cache.test'


def name(value):
    return ascii_name(value) if value else b'\0'


def rr(kind, data, owner=b'\xc0\x0c', ttl=600, cls=1, rdlen=None):
    return owner + struct.pack('!HHIH', kind, cls, ttl, len(data) if rdlen is None else rdlen) + data


def query(host, ident, kind=1, flags=0x100, cls=1, do=False, opts=b'', opt_ttl=0, signed=False, extra=False, size=1232):
    records=[] if opts is None else [rr(41, opts, b'\0', opt_ttl | (0x8000 if do else 0), size)]
    if extra:records.append(rr(16,b'\x01x',name('extra.cache.test')))
    if signed:records.append(rr(250,b'opaque',b'\0',0,255))
    return struct.pack('!6H', ident, flags, 1, 0, 0, len(records)) + name(host) + struct.pack('!HH', kind, cls) + b''.join(records)


def normalized(packet):
    if packet is None:return {'result':'timeout'}
    try:
        result=semantics(packet);result['id']=0;result['bytes']=len(packet)
        return result
    except (ValueError,IndexError,struct.error,UnicodeError) as error:
        return {'unparsed':type(error).__name__,'bytes':len(packet),'wire':(b'\0\0'+packet[2:]).hex()}


SYNTAX=[]
for option in ['min-cache-ttl','max-cache-ttl','max-ttl','neg-ttl','dns-forward-max']:
    for suffix,value in [('missing',None),('empty',''),('zero','0'),('one','1'),('ordinary','60'),
                         ('max-int','2147483647'),('signed-wrap','2147483648'),('u32-wrap','4294967296'),
                         ('long-decimal-wrap','18446744073709551617'),('negative','-1'),('nondigit','x'),('quoted','"60"')]:
        SYNTAX.append({'case':option+'-'+suffix,'config':option+('='+value if value is not None else '')+'\n'})
    SYNTAX.append({'case':option+'-file-duplicate','config':option+'=10\n'+option+'=20\n'})
    SYNTAX.append({'case':option+'-cli-file-override','config':option+'=10\n','args':['--'+option+'=20']})
for suffix,value in [('name','TXT'),('casefold','tXt'),('numeric','16'),('comma','TXT,NS'),('repeat','TXT\ncache-rr=NS'),
                     ('empty',''),('missing',None),('invalid-name','NOT_A_TYPE'),('negative','-1'),('zero','0'),
                     ('65535','65535'),('u16-wrap','65536'),('int-wrap','2147483648'),('atoi-zero-wrap','4294967296'),
                     ('comma-empty-tail','TXT,'),('quoted-comma','"TXT,NS"')]:
    SYNTAX.append({'case':'rr-'+suffix,'config':'cache-rr'+('='+value if value is not None else '')+'\n'})
SYNTAX.append({'case':'rr-cli-file-repeat','config':'cache-rr=TXT\n','args':['--cache-rr=NS']})
for suffix,value in [('no-arg',None),('empty',''),('zero','0'),('positive','3'),('default-86400','86400'),
                     ('negative','-1'),('signed-wrap-rejected','2147483648'),('atoi-zero-wrap','4294967296')]:
    SYNTAX.append({'case':'stale-'+suffix,'config':'use-stale-cache'+('='+value if value is not None else '')+'\n'})
SYNTAX.extend([{'case':'stale-file-duplicate','config':'use-stale-cache=3\nuse-stale-cache=4\n'},
               {'case':'stale-cli-file-override','config':'use-stale-cache=3\n','args':['--use-stale-cache=4']}])
for option in ['no-negcache','proxy-dnssec','no-round-robin']:
    for suffix,value in [('plain',option),('repeat',option+'\n'+option),('unexpected-argument',option+'=1')]:
        SYNTAX.append({'case':option+'-'+suffix,'config':value+'\n'})


SCENARIOS=[]
def case(label,config='',**fields):
    SCENARIOS.append({'case':label,'config':config,**fields})


# Each scenario is a schedule of real packets/actions. Further source-frozen
# scenarios are added here before qualification; missing labels remain visible.
for label,kind,config in [('extract-a',1,''),('extract-aaaa',28,''),('extract-srv-default',33,''),
                          ('extract-ptr-generic-default',12,''),('extract-txt-unselected',16,''),
                          ('extract-txt-selected',16,'cache-rr=TXT'),('extract-any-selector',99,'cache-rr=ANY'),
                          ('extract-qtype-any-no-positive',255,'cache-rr=ANY'),('extract-qtype-zero-selected',0,'cache-rr=0'),
                          ('extract-qtype-zero-any',0,'cache-rr=ANY'),('extract-cname-query-no-cache',5,'cache-rr=ANY')]:
    case(label,config,kind=kind)
for label,fields in [('extract-upstream-ra-zero',{'response_flags':0x8100}),
                      ('extract-query-cd',{'flags':0x110}),('extract-upstream-cd',{'response_flags':0x8190}),
                      ('extract-ad-default',{'response_flags':0x81a0}),('extract-ad-proxy',{'config':'proxy-dnssec','response_flags':0x81a0}),
                      ('extract-ch-class',{'cls':3}),('extract-any-class',{'cls':255}),
                      ('extract-tc-no-cache',{'response_flags':0x8380}),('extract-servfail-no-cache',{'response_flags':0x8182,'answers':[]})]:
    case(label,**fields)
for label,config in [('negative-nxdomain-a',''),('negative-no-negcache-nxdomain','no-negcache'),
                     ('negative-no-soa-fallback','neg-ttl=60'),('negative-soa-beats-fallback','neg-ttl=60')]:
    case(label,config,response_flags=0x8183,answers=[],soa=label not in ('negative-no-soa-fallback',))
for label,config in [('negative-nodata-a',''),('negative-no-negcache-nodata','no-negcache'),
                     ('negative-soa-zero-ttl',''),('negative-soa-zero-minimum',''),('negative-no-soa-no-fallback','')]:
    case(label,config,answers=[],soa=label!='negative-no-soa-no-fallback',soa_ttl=0 if label=='negative-soa-zero-ttl' else 600,
         soa_minimum=0 if label=='negative-soa-zero-minimum' else 300)
for label,host in [('ptr-ipv4','17.2.0.192.in-addr.arpa'),('ptr-ipv6',ipaddress.ip_address('2001:db8::17').reverse_pointer),
                   ('ptr-partial-v4','2.0.192.in-addr.arpa'),('ptr-v4-octet-wrap','273.2.0.192.in-addr.arpa'),
                   ('ptr-ip6-int',ipaddress.ip_address('2001:db8::17').reverse_pointer.replace('.arpa','.int'))]:
    case(label,kind=12,host=host)
for option in ['min-cache-ttl','max-cache-ttl','max-ttl']:
    for suffix,kind,fields in [('a',1,{}),('aaaa',28,{}),('generic',16,{}),
                              ('reverse4',12,{'host':'17.2.0.192.in-addr.arpa'}),
                              ('reverse6',12,{'host':ipaddress.ip_address('2001:db8::17').reverse_pointer}),
                              ('nxdomain',1,{'response_flags':0x8183,'answers':[],'soa':True}),
                              ('nodata',1,{'answers':[],'soa':True}),('zero-ttl',1,{'ttl':0}),
                              ('wrapped-runtime',1,{})]:
        config=option+'='+('4294967295' if suffix=='wrapped-runtime' else ('900' if option=='min-cache-ttl' else '300'))
        case(option+'-'+suffix,config+'\ncache-rr=ANY',kind=kind,**fields)
case('ttl-max-then-min','min-cache-ttl=900\nmax-cache-ttl=300')
case('ttl-wire-max-before-cache-min','max-ttl=200\nmin-cache-ttl=900')
case('ttl-min-zero-enables-soa','min-cache-ttl=30',answers=[],soa=True,soa_ttl=0,soa_minimum=0)
case('forward-zero-start','dns-forward-max=0',action='startup')
case('forward-zero-local','dns-forward-max=0',host='health.cache.test')
case('forward-zero-udp-refused','dns-forward-max=0')
case('forward-zero-tcp','dns-forward-max=0',transports=['tcp','tcp'])
case('tcp-accept-clock-fixed-ttl',action='tcp-clock',ttl=20)
case('tcp-parent-udp-new-record',action='tcp-parent-new')
case('tcp-parent-udp-replaces-record',action='tcp-parent-replace')
case('tcp-current-connection-inserts',action='tcp-current')
case('tcp-child-import-visible-parent',transports=['tcp','udp'])
case('tcp-debug-clock',action='tcp-clock',ttl=20,debug=True)
case('tcp-debug-live-cache',action='tcp-current',debug=True)

for label,fields in [('extract-opcode-other',{'flags':0x900}),
                      ('extract-refused-recovery',{'response_flags':0x8185,'answers':[],
                                                  'response_next':{'response_flags':0x8180,'answers':[{'data':'c6336407'}]}}),
                      ('extract-extended-rcode',{'response_opt_ttl':0x01000000}),
                      ('extract-nocache-ecs',{'config':'add-subnet=24,56'}),
                      ('extract-fixed-ecs-cacheable',{'config':'add-subnet=198.51.100.0/24'}),
                      ('extract-signed-query',{'signed':True}),('extract-signed-reply',{'response_signed':True}),
                      ('extract-opt-version',{'opt_ttl':0x00010000}),('extract-opt-flags',{'opt_ttl':0x40}),
                      ('extract-multiple-additional',{'extra':True})]:case(label,**fields)

DESCRIPTORS={2:'ns',3:'md',4:'mf',6:'soa',7:'mb',8:'mg',9:'mr',12:'ptr-generic',14:'minfo',15:'mx',17:'rp',
             18:'afsdb',21:'rt',24:'sig',26:'px',30:'nxt',36:'kx',33:'srv',39:'dname'}
for kind,label in DESCRIPTORS.items():case('generic-'+label,'cache-rr=ANY',kind=kind)
for kind,label in [(16,'txt'),(35,'naptr-opaque'),(257,'caa'),(64,'svcb-opaque'),(65,'https-opaque'),
                   (43,'ds'),(48,'dnskey'),(46,'rrsig-opaque'),(65000,'unknown')]:
    case('generic-'+label,'cache-rr=ANY',kind=kind)
for label,kind,data in [('generic-empty',65000,b''),('generic-inline-13',65000,b'x'*13),
                        ('generic-block-14',65000,b'x'*14),('generic-fixed-prefix-short',15,b'\x00'),
                        ('generic-trailing-data',12,name('target.cache.test')+b'\x00\x01')]:
    case(label,'cache-rr=ANY',kind=kind,answers=[{'kind':kind,'data':data.hex()}])
case('generic-mixed-inline-block','cache-rr=ANY',kind=65000,answers=[{'data':(b'x'*13).hex()},{'data':(b'y'*14).hex()}])
case('generic-compressed-owner','cache-rr=ANY',kind=16)
case('generic-compressed-rdata','cache-rr=ANY',kind=12,answers=[{'data':'c00c'}])
case('generic-binary-name','cache-rr=ANY',kind=12,answers=[{'data':b'\x04\xffA\x00Z\0'.hex()}])
case('generic-name-past-rdlen','cache-rr=ANY',kind=15,answers=[{'data':(b'\x00\x01'+name('target.cache.test')).hex(),'rdlen':2}])
case('generic-rdata-past-packet','cache-rr=ANY',kind=65000,opts=None,answers=[{'data':'0102','rdlen':200}])
for label,fields in [('generic-large-udp-truncate',{'size':512}),
                      ('generic-large-tcp-cache',{'transports':['udp','tcp']}),
                      ('generic-large-tcp-opt512',{'transports':['udp','tcp'],'size':512}),
                      ('generic-large-tcp-noopt',{'transports':['tcp','tcp'],'opts':None})]:
    case(label,'cache-rr=ANY',kind=65000,answers=[{'data':(b'x'*650).hex()}],**fields)

for kind,label in [(28,'aaaa'),(16,'txt'),(255,'any'),(0,'zero')]:
    case('negative-nxdomain-'+label,response_flags=0x8183,answers=[],soa=True,kind=kind)
for kind,label,config,host in [(28,'aaaa','',None),(16,'txt-selected','cache-rr=TXT',None),
                              (16,'txt-unselected','',None),(33,'srv','',None),(12,'generic-ptr','',None),
                              (12,'address-ptr','','17.2.0.192.in-addr.arpa')]:
    fields={'host':host} if host else {};case('negative-nodata-'+label,config,kind=kind,answers=[],soa=True,**fields)
for label,fields in [('negative-soa-minimum-less',{'soa_minimum':30}),('negative-soa-ttl-less',{'soa_ttl':30}),
                      ('negative-soa-unrelated',{'soa_owner':'other.test'}),('negative-soa-root',{'soa_owner':''}),
                      ('negative-soa-suffix-not-label-boundary',{'soa_owner':'ache.test'}),
                      ('negative-soa-case-mismatch',{'soa_owner':'CaChE.TeSt'})]:
    case(label,answers=[],soa=True,**fields)
case('negative-cname-soa-order',answers=[{'kind':5,'data':name('target.cache.test').hex()}],soa=True)
case('negative-cname-no-soa','neg-ttl=60',answers=[{'kind':5,'data':name('target.cache.test').hex()}])
case('negative-no-negcache-cname-positive-prefix','no-negcache',answers=[{'kind':5,'data':name('target.cache.test').hex()}],soa=True)
case('negative-bogus-no-negcache-bypass','no-negcache\nbogus-nxdomain=198.51.100.7')
case('negative-bogus-cd-bypass','bogus-nxdomain=198.51.100.7',flags=0x110)
case('negative-local-known-nodata','host-record=negative-local-known-nodata.cache.test,198.51.100.10',kind=16,response_flags=0x8183,answers=[],soa=True)
case('negative-filter-keeps-positive','filter-rr=TXT\ncache-rr=TXT',kind=16)

for option in ['min-cache-ttl','max-cache-ttl','max-ttl']:
    config=option+'='+('900' if option=='min-cache-ttl' else '300')+'\ncache-rr=ANY'
    for suffix,fields in [('cname-chain',{'action':'cname'}),('soa-authority',{'answers':[],'soa':True}),
                          ('no-soa-fallback',{'answers':[],'config':config+'\nneg-ttl=600'}),
                          ('local-immune',{'host':'health.cache.test'}),
                          ('live-unrelated-owner',{'answers':[{'data':'c6336407','owner':'other.cache.test'}]}),
                          ('live-unrelated-type',{'answers':[{'kind':16,'data':'0178'}]}),
                          ('live-other-class',{'answers':[{'data':'c6336407','cls':3}]}),
                          ('tcp-import',{'transports':['tcp','udp']})]:
        fields=copy.deepcopy(fields);selected=fields.pop('config',config);case(option+'-'+suffix,selected,**fields)
case('ttl-max-zero-disables','max-ttl=0\nmax-cache-ttl=0')
case('ttl-all-options-forward','max-ttl=100\nmax-cache-ttl=300\nmin-cache-ttl=900')
case('ttl-all-options-reverse','max-ttl=100\nmax-cache-ttl=300\nmin-cache-ttl=900',kind=12,host='17.2.0.192.in-addr.arpa')
case('ttl-all-options-negative','max-ttl=100\nmax-cache-ttl=300\nmin-cache-ttl=900\nneg-ttl=1200',answers=[],soa=True)

for kind_name,kind,fields in [('a',1,{}),('aaaa',28,{}),('generic',16,{}),
                            ('reverse',12,{'host':'17.2.0.192.in-addr.arpa'}),
                            ('negative',1,{'answers':[],'soa':True}),('cname',1,{'action':'cname'})]:
    for flag in ['rd-off','ad-request','do-request','cd-request','proxy-ad','proxy-cd-ad']:
        config='cache-rr=ANY'+('\nproxy-dnssec' if flag.startswith('proxy-') else '')
        case('metadata-'+kind_name+'-'+flag,config,kind=kind,
             flags={'rd-off':0,'ad-request':0x120,'do-request':0x100,'cd-request':0x110,'proxy-ad':0x120,'proxy-cd-ad':0x130}[flag],
             do=flag=='do-request',response_flags=0x81a0,**fields)
case('metadata-local-ad',host='health.cache.test',flags=0x120)
case('metadata-local-do',host='health.cache.test',do=True)
case('metadata-reply-signed-ad',response_flags=0x81a0,response_signed=True)
case('metadata-cached-soa-ad','proxy-dnssec',response_flags=0x81a0,answers=[],soa=True,flags=0x120)
for label,action in [('tcp-parent-lease-added','lease-added'),('tcp-parent-lease-renamed','lease-renamed'),
                      ('tcp-parent-lease-released','lease-released'),('tcp-existing-lease-ttl','lease-ttl')]:
    case(label,'dhcp-range=192.0.2.40,192.0.2.60,255.255.255.0,120s\n'
         'dhcp-authoritative\nno-ping\ndhcp-leasefile=/m2/cache.leases\ndomain=cache.test\ndhcp-ttl=120',action=action)


def default_rdata(kind):
    if kind==1:return ipaddress.ip_address('198.51.100.7').packed
    if kind==28:return ipaddress.ip_address('2001:db8:100::7').packed
    if kind in (2,3,4,5,7,8,9,12,30,39):return name('target.cache.test')
    if kind==33:return struct.pack('!3H',0,0,8080)+name('target.cache.test')
    if kind in (14,17):return name('mail.cache.test')+name('admin.cache.test')
    if kind in (15,18,21,36):return struct.pack('!H',10)+name('target.cache.test')
    if kind==24:return b'\0'*18+name('signer.cache.test')+b'signature'
    if kind==26:return struct.pack('!H',10)+name('first.cache.test')+name('second.cache.test')
    if kind==6:return name('ns.cache.test')+name('hostmaster.cache.test')+struct.pack('!5I',1,60,60,600,300)
    if kind==16:return b'\x05hello'
    return b'\x01\x02\x03\x04'


class Upstream:
    def __init__(self):
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(('127.0.0.2',0))
        self.port=self.udp.getsockname()[1];self.tcp=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.tcp.bind(('127.0.0.2',self.port));self.tcp.listen(20)
        self.events=[];self.errors=[];self.plan={};self.clients=[];self.stop=threading.Event()
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def answer(self,packet,transport):
        host,end=read_name(packet,12);kind,cls=struct.unpack_from('!HH',packet,end);spec=copy.deepcopy(self.plan.get(host,{}))
        self.events.append({'host':host,'transport':transport,'query':normalized(packet),'wire':packet.hex()})
        answer_spec=spec.get('answers',[{'kind':kind,'data':default_rdata(kind).hex()}]);answers=[]
        for record in answer_spec:
            answers.append(rr(record.get('kind',kind),bytes.fromhex(record['data']),
                              name(record['owner']) if 'owner' in record else b'\xc0\x0c',
                              record.get('ttl',spec.get('ttl',600)),record.get('cls',1),record.get('rdlen')))
        authority=[]
        if spec.get('soa'):
            body=name('ns.cache.test')+name('hostmaster.cache.test')+struct.pack('!5I',1,60,60,600,spec.get('soa_minimum',300))
            authority.append(rr(6,body,name(spec.get('soa_owner',ZONE)),spec.get('soa_ttl',600)))
        additional=[]
        try:
            message=semantics(packet)
            for record in message['records']:
                if record['type']==41:
                    additional.append(rr(41,bytes.fromhex(record['data']),b'\0',spec.get('response_opt_ttl',record['ttl']),1232))
        except (ValueError,IndexError,struct.error,UnicodeError):pass
        if spec.get('response_signed'):additional.append(rr(250,b'opaque',b'\0',0,255))
        if spec.get('response_next'):self.plan[host]=dict(spec,**spec['response_next']);self.plan[host].pop('response_next')
        return packet[:2]+struct.pack('!5H',spec.get('response_flags',0x8180),1,len(answers),len(authority),len(additional))+packet[12:end+4]+b''.join(answers+authority+additional)
    def run(self):
        buffers={}
        while not self.stop.is_set():
            try:ready,_,_=select.select([self.udp,self.tcp,*self.clients],[],[],.02)
            except (ValueError,OSError):break
            for stream in ready:
                try:
                    if stream is self.udp:
                        packet,peer=stream.recvfrom(65535);stream.sendto(self.answer(packet,'udp'),peer)
                    elif stream is self.tcp:
                        conn,_=stream.accept();conn.setblocking(False);self.clients.append(conn);buffers[conn]=b''
                    else:
                        data=stream.recv(65535)
                        if not data:self.clients.remove(stream);buffers.pop(stream);stream.close();continue
                        buffers[stream]+=data
                        while len(buffers[stream])>=2:
                            length=struct.unpack_from('!H',buffers[stream])[0]
                            if len(buffers[stream])<length+2:break
                            packet=buffers[stream][2:length+2];buffers[stream]=buffers[stream][length+2:]
                            response=self.answer(packet,'tcp');stream.sendall(struct.pack('!H',len(response))+response)
                except Exception as error:self.errors.append(repr(error))
    def close(self):
        self.stop.set();self.thread.join(2)
        for stream in [self.udp,self.tcp,*self.clients]:stream.close()
        if self.thread.is_alive():raise AssertionError('fixture selector thread leaked')


def network():
    if sorted(label for _,label in socket.if_nameindex())!=['lo']:raise ValueError('fresh isolated namespace required')
    subprocess.run(['ip','link','add','cache0','type','dummy'],check=True);subprocess.run(['ip','link','set','cache0','up'],check=True)
    for address in [LISTEN+'/24',CLIENT+'/24',LEASE_CLIENT+'/24']:
        subprocess.run(['ip','addr','add',address,'dev','cache0'],check=True)


def lease_exchange(folder,label,kind=3,hostname='leaseold',server=None):
    ident=0x64000000+len(list(folder.glob('*.dhcp.query')))
    packet=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,ident,0,0,
                       socket.inet_aton(LEASE_CLIENT),b'\0'*4,b'\0'*4,b'\0'*4,
                       bytes.fromhex('020000000042')+b'\0'*10,b'\0'*64,b'\0'*128)
    packet+=b'\x63\x82\x53\x63'+bytes([53,1,kind])
    if hostname:packet+=bytes([12,len(hostname)])+hostname.encode()
    if server:packet+=bytes([54,4])+socket.inet_aton(server)
    packet+=b'\xff';packet=packet.ljust(300,b'\0')
    (folder/(label+'.dhcp.query')).write_bytes(packet)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(2);client.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        client.bind((LEASE_CLIENT,68));client.sendto(packet,(LISTEN,67))
        if kind==7:return {'sent_release':True,'server':server}
        reply,_=client.recvfrom(4096)
    (folder/(label+'.dhcp.reply')).write_bytes(reply)
    if len(reply)<240 or struct.unpack_from('!I',reply,4)[0]!=ident:raise AssertionError('DHCP identity mismatch')
    options={};at=240
    while at<len(reply):
        code=reply[at];at+=1
        if code==255:break
        if code==0:continue
        size=reply[at];at+=1;options[code]=reply[at:at+size];at+=size
    if options.get(53)!=b'\x05':raise AssertionError('positive DHCP ACK required, got '+repr(options.get(53)))
    return {'message':5,'address':socket.inet_ntoa(reply[16:20]),'server':socket.inet_ntoa(options[54]),
            'lease_seconds':struct.unpack('!I',options[51])[0]}


def exchange(port,packet,tcp=False,connection=None):
    own=connection is None;stream=connection or socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    try:
        if own:stream.settimeout(.8);stream.bind((CLIENT,0));stream.connect((LISTEN,port))
        if tcp:
            stream.sendall(struct.pack('!H',len(packet))+packet);return exact_read(stream,struct.unpack('!H',exact_read(stream,2))[0])
        stream.send(packet);return stream.recv(65535)
    except (socket.timeout,ConnectionError,ConnectionResetError):return None
    finally:
        if own:stream.close()


def schedule(spec,port,upstream,folder):
    host=spec.get('host',spec['case']+'.'+ZONE);upstream.plan[host]=spec;observations=[]
    def packet(label,target=host,tcp=False,connection=None,step=0):
        wire=query(target,0x5200+step,spec.get('kind',1),spec.get('flags',0x100),spec.get('cls',1),spec.get('do',False),
                   spec.get('opts',b''),spec.get('opt_ttl',0),spec.get('signed',False),spec.get('extra',False),spec.get('size',1232))
        started=time.monotonic();reply=exchange(port,wire,tcp,connection)
        (folder/(label+'.query')).write_bytes(wire)
        if reply is not None:(folder/(label+'.reply')).write_bytes(reply)
        observations.append({'label':label,'query':normalized(wire),'reply':normalized(reply),'elapsed_seconds':time.monotonic()-started})
    action=spec.get('action')
    if action=='cname':
        upstream.plan[host]=dict(spec,answers=[{'kind':5,'data':name('target.cache.test').hex()},
                                               {'kind':spec.get('kind',1),'owner':'target.cache.test','data':default_rdata(spec.get('kind',1)).hex()}])
    if action=='startup':return observations
    if action and action.startswith('lease-'):
        witnesses=[];old='leaseold.cache.test';new='leasenew.cache.test';lease=None
        if action!='lease-added':
            lease=lease_exchange(folder,'seed');witnesses.append(lease);time.sleep(.05)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as conn:
            conn.settimeout(2);conn.bind((CLIENT,0));conn.connect((LISTEN,port))
            packet('accepted-health','health.cache.test',True,conn)
            if action=='lease-added':
                lease=lease_exchange(folder,'add');witnesses.append(lease);time.sleep(.05)
                packet('parent-new',old);packet('child-new',old,True,conn)
            elif action=='lease-renamed':
                witnesses.append(lease_exchange(folder,'rename',hostname='leasenew'));time.sleep(.05)
                packet('parent-old',old);packet('parent-renamed',new)
                packet('child-old',old,True,conn);packet('child-renamed',new,True,conn)
            elif action=='lease-released':
                witnesses.append(lease_exchange(folder,'release',7,'',lease['server']));time.sleep(.1)
                packet('parent-released',old);packet('child-old',old,True,conn)
            else:
                packet('lease-first',old,True,conn);time.sleep(3.2);packet('lease-after-wait',old,True,conn)
        (folder/'lease-witness.json').write_text(json.dumps(witnesses,indent=2)+'\n')
        return observations
    if action and action.startswith('tcp-'):
        if action=='tcp-parent-replace':packet('seed')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as conn:
            conn.settimeout(2);conn.bind((CLIENT,0));conn.connect((LISTEN,port))
            packet('accepted-health','health.cache.test',True,conn)
            if action=='tcp-clock':
                packet('first',tcp=True,connection=conn);time.sleep(3.2);packet('after-wait',tcp=True,connection=conn,step=1)
            elif action in ('tcp-parent-new','tcp-parent-replace'):
                if action=='tcp-parent-replace':upstream.plan[host]=dict(spec,answers=[{'kind':1,'data':'c6336408'}]);process_hup(folder)
                packet('parent-udp');packet('child-after-parent',tcp=True,connection=conn,step=1)
            else:
                packet('child-first',tcp=True,connection=conn);packet('child-second',tcp=True,connection=conn,step=1)
    else:
        for index,transport in enumerate(spec.get('transports',['udp','udp'])):
            packet('query-'+str(index),tcp=transport=='tcp',step=index)
    return observations


def process_hup(folder):
    # The schedule stores the actual process pid outside chroot; no host
    # daemon, firmware or physical router is addressed.
    os.kill(int((folder/'pid').read_text()),signal.SIGHUP);time.sleep(.1)


def diagnostic(data):
    return re.sub(r'dnsmasq(?:-rs)?: ?', '',data.decode('utf-8','surrogateescape')).strip()


def run(args):
    if os.geteuid()!=0 or os.environ.get('DNSMASQ_TEST_ISOLATED')!='1':raise ValueError('run through run_isolated.sh')
    network();out=args.out.resolve()
    if out.exists() or 'private' not in out.parts:raise ValueError('fresh private evidence output required')
    out.mkdir(parents=True);root=prepare(args.image_root,None,out,args.rust)
    drivers=out/'drivers';drivers.mkdir()
    for filename in ['m5_dns_cache.py','m5_dns_cache.json']:(drivers/filename).write_bytes(Path(__file__).with_name(filename).read_bytes())
    manifest=json.loads((drivers/'m5_dns_cache.json').read_text());pattern=re.compile(args.only or '.')
    report={'side':args.side,'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'syntax':[],'scenarios':[],'executed_cases':[],'failures':[]}
    capabilities=subprocess.run(command(root,args.side,'--version'),capture_output=True,timeout=4)
    (out/'capabilities.stdout').write_bytes(capabilities.stdout);(out/'capabilities.stderr').write_bytes(capabilities.stderr)
    for row in SYNTAX:
        if not pattern.search(row['case']):continue
        config=root/'m2/cache-syntax.conf';config.write_text(row['config'])
        result=subprocess.run(command(root,args.side,'--test','-C','/m2/cache-syntax.conf',*row.get('args',[])),capture_output=True,timeout=4)
        label=row['case'];(out/(label+'.conf')).write_text(row['config']);(out/(label+'.stderr')).write_bytes(result.stderr)
        report['syntax'].append({'case':label,'exit':result.returncode,'stdout':diagnostic(result.stdout),'stderr':diagnostic(result.stderr)})
        report['executed_cases'].append(label)
    for spec in SCENARIOS:
        if not pattern.search(spec['case']):continue
        label=spec['case'];folder=out/label;folder.mkdir();upstream=Upstream()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:reserve.bind((LISTEN,0));port=reserve.getsockname()[1]
        config=(f'port={port}\nno-resolv\nno-hosts\nbind-interfaces\nlisten-address={LISTEN}\n'
                f'server=127.0.0.2#{upstream.port}\ncache-size=100\nno-0x20-encode\n'
                'host-record=health.cache.test,198.51.100.99\nlocal-ttl=600\nuser=root\n'
                'pid-file=/m2/cache.pid\nlog-facility=/m2/cache.log\n'+spec['config']+'\n')
        (folder/'config').write_text(config);(root/'m2/cache.conf').write_text(config)
        trace={'case':label,'config':spec['config'],'observations':[],'exit':None};process=None
        log=(folder/'stderr').open('wb')
        try:
            process=subprocess.Popen(command(root,args.side,'-d' if spec.get('debug') else '-k','-C','/m2/cache.conf'),stdout=log,stderr=log,start_new_session=True)
            for _ in range(300):
                if process.poll() is not None:raise RuntimeError('daemon startup exit '+str(process.returncode))
                if (root/'m2/cache.pid').exists():break
                if spec.get('debug') and exchange(port,query('health.cache.test',0x5900)) is not None:break
                time.sleep(.01)
            else:raise AssertionError('startup pid readiness deadline')
            trace['identity']=process_identity(root,process.pid);(folder/'pid').write_text(str(process.pid))
            trace['observations']=schedule(spec,port,upstream,folder);report['executed_cases'].append(label)
        except Exception as error:trace['failure']=repr(error);report['failures'].append({'case':label,'error':repr(error)})
        finally:
            if process is not None:
                if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(4)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(2)
                trace['exit']=process.returncode
            upstream.close();log.close();trace['upstream']=copy.deepcopy(upstream.events);trace['upstream_errors']=upstream.errors
            if (root/'m2/cache.pid').exists():(root/'m2/cache.pid').unlink()
            if (root/'m2/cache.log').exists():(folder/'daemon.log').write_bytes((root/'m2/cache.log').read_bytes());(root/'m2/cache.log').unlink()
        (folder/'trace.json').write_text(json.dumps(trace,indent=2)+'\n');report['scenarios'].append(trace)
    required={label for b in manifest['boundaries'] for label in b['required_cases']}
    report['required_count']=len(required);report['missing_required_cases']=sorted(required-set(report['executed_cases']))
    report['driver_sha256']=sha256(drivers/'m5_dns_cache.py');report['manifest_sha256']=sha256(drivers/'m5_dns_cache.json')
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'side':args.side,'executed':len(report['executed_cases']),'missing':len(report['missing_required_cases']),'failures':report['failures']}))
    return int(bool(report['failures']))


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('run');p.add_argument('--side',choices=['c','rust'],required=True);p.add_argument('--image-root',type=Path,required=True)
    p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--only')
    p=sub.add_parser('qualify-dhcp-caller');p.add_argument('--c',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();raise SystemExit(run(args) if args.action=='run' else qualify_dhcp_caller(args))


DHCP_CALLERS=['tcp-parent-lease-added','tcp-parent-lease-renamed','tcp-parent-lease-released','tcp-existing-lease-ttl']

def dhcp_caller_guard(c,r):
    if c.get('side')!='c' or c.get('c_sha256')!=STOCK_SHA256 or r.get('side')!='rust':return False
    if not re.fullmatch('[0-9a-f]{64}',r.get('rust_sha256','')):return False
    cm={s['case']:s for s in c['scenarios']};rm={s['case']:s for s in r['scenarios']}
    for label in DHCP_CALLERS:
        if label not in cm or label not in rm:return False
        left,right=cm[label],rm[label]
        for row in [left,right]:
            if row.get('failure') or row['exit']!=0 or row['upstream_errors']:return False
        a=[{k:copy.deepcopy(v) for k,v in row.items() if k!='elapsed_seconds'} for row in left['observations']]
        b=[{k:copy.deepcopy(v) for k,v in row.items() if k!='elapsed_seconds'} for row in right['observations']]
        if label=='tcp-existing-lease-ttl':
            first=[]
            for rows in [a,b]:
                early=next(row for row in rows if row['label']=='lease-first')['reply']['records'][0]['ttl']
                late=next(row for row in rows if row['label']=='lease-after-wait')['reply']['records'][0]['ttl']
                if early!=late or early not in (119,120):return False
                first.append(early)
                for row in rows:
                    if row['label'].startswith('lease-'):row['reply']['records'][0]['ttl']='fixed-accepted-remaining'
            if abs(first[0]-first[1])>1:return False
        if a!=b or len(left['upstream'])!=len(right['upstream']):return False
    return True

def qualify_dhcp_caller(args):
    c=json.loads((args.c/'result.json').read_text());r=json.loads((args.candidate/'result.json').read_text())
    qualified=dhcp_caller_guard(c,r);controls=[]
    if qualified:
        for label in DHCP_CALLERS:
            for side,folder,report in [('c',args.c,c),('rust',args.candidate,r)]:
                proof=json.loads((folder/label/'lease-witness.json').read_text())
                if not proof or any(row.get('message')!=5 or row.get('address')!=LEASE_CLIENT or row.get('lease_seconds')!=120
                                    for row in proof if not row.get('sent_release')):qualified=False
        for mode in ['lease-added','lease-renamed','lease-released','ttl-decay','ttl-unbounded','missing-case','bad-identity']:
            wrong=copy.deepcopy(r);rows={s['case']:s for s in wrong['scenarios']}
            if mode.startswith('lease-'):
                label='tcp-parent-'+mode
                observation=next(v for v in rows[label]['observations'] if v['label'].startswith('child-'))
                observation['reply']['records'][0]['data']='203.0.113.99'
            elif mode.startswith('ttl-'):
                observation=next(v for v in rows['tcp-existing-lease-ttl']['observations'] if v['label']=='lease-after-wait')
                observation['reply']['records'][0]['ttl']=117 if mode=='ttl-decay' else 999
            elif mode=='missing-case':wrong['scenarios']=[v for v in wrong['scenarios'] if v['case']!=DHCP_CALLERS[0]]
            else:wrong['rust_sha256']=''
            rejected=not dhcp_caller_guard(c,wrong);controls.append({'control':mode,'rejected':rejected})
            qualified &= rejected
    result={'scope':'dhcp-ttl reopened existing TCP caller boundaries; ordinary DHCP qualification retained by delivery ledger',
            'qualified':qualified,'cases':DHCP_CALLERS,'candidate_sha256':r['rust_sha256'],'c_sha256':c['c_sha256'],
            'negative_controls':controls,'full_cache_family_qualified':False,
            'timing_guard':'Each side first TTL 119..120 must stay EXACTLY unchanged after real 3.2s; ACK-to-accept may cross one integer second. All other fields/upstream counts exact.',
            'qualifier_sha256':sha256(__file__)}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'dhcp_caller_qualified':qualified,'negative_controls':len(controls)}));return int(not qualified)
if __name__=='__main__':main()
