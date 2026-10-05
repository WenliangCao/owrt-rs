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
# Reverse records use the IP as lookup/conflict key, independently of the
# target's forward name. Preserve the full RR order from the image C.
PTR4='17.2.0.192.in-addr.arpa'
for label,host in [('ptr-v4-extra-label','99.17.2.0.192.in-addr.arpa'),
                   ('ptr-v4-atoi-wrap','4294967313.2.0.192.in-addr.arpa'),
                   ('ptr-partial-v6','1.0.0.0.ip6.arpa'),
                   ('ptr-ipv6-legacy-bitstring',r'\[x20010db8000000000000000000000017/128].ip6.int'),
                   ('ptr-invalid-arpa-generic','nondigit.2.0.192.in-addr.arpa')]:
    case(label,kind=12,host=host)
for label,fields in [('ptr-class-other',{'cls':3}),
                      ('ptr-owner-other',{'answers':[{'data':name('target.cache.test').hex(),'owner':'other.cache.test'}]}),
                      ('ptr-malformed-target',{'answers':[{'data':'c0ff'}]}),
                      ('ptr-target-past-rdlen-bounded',{'opts':None,'answers':[{'data':name('target.cache.test').hex(),'rdlen':1}]}),
                      ('ptr-unrelated-trailing-malformed',{'opts':None,'answers':[{'data':name('target.cache.test').hex()},
                                              {'kind':16,'data':'0178','rdlen':200,'owner':'other.cache.test'}]}),
                      ('ptr-negative-nodata',{'answers':[],'soa':True,'soa_owner':'in-addr.arpa'}),
                      ('ptr-negative-nxdomain',{'answers':[],'soa':True,'soa_owner':'in-addr.arpa','response_flags':0x8183}),
                      ('ptr-filter-compose',{'config':'filter-rr=PTR'}),
                      ('ptr-tcp-child-import',{'transports':['tcp','udp']}),
                      ('ptr-cname-generic-fallback',{'answers':[{'kind':5,'data':name('target.cache.test').hex()},
                                             {'kind':12,'data':name('terminal.cache.test').hex(),'owner':'target.cache.test'}]}),
                      ('ptr-multiple-targets',{'transports':['udp','udp','udp'],'answers':[{'data':name('first.cache.test').hex()},
                                                        {'data':name('second.cache.test').hex()},
                                                        {'data':name('third.cache.test').hex()}]}),
                      ('ptr-reverse-bucket-order',{'answers':[{'data':name('a.cache.test').hex()},
                                                            {'data':name('b.cache.test').hex()},
                                                            {'data':name('a.cache.test').hex(),'ttl':300}],
                                                  'transports':['udp','udp','udp']})]:
    case(label,kind=12,host=PTR4,**fields)
for label,fields in [('ptr-address-alias-key',{'action':'ptr-alias'}),
                      ('ptr-two-addresses-same-target',{'action':'ptr-two'}),
                      ('ptr-reverse-no-forward-alias',{'action':'ptr-forward'}),
                      ('ptr-forward-independent-same-name',{'action':'ptr-forward-independent'}),
                      ('ptr-replace-address-rrset',{'action':'ptr-replace'}),
                      ('ptr-negative-cross-qtype',{'action':'ptr-negative','answers':[],'soa':True,'soa_owner':'in-addr.arpa','response_flags':0x8183}),
                      ('ptr-expiry-refresh',{'action':'expired-stale','ttl':1}),
                      ('ptr-stale-refresh',{'action':'expired-stale','ttl':1,'config':'use-stale-cache=0'})]:
    case(label,kind=12,host=PTR4,**fields)
case('ptr-static-host-precedence','host-record=static.cache.test,192.0.2.17',kind=12,host=PTR4)
case('ptr-dhcp-precedence','dhcp-range=192.0.2.40,192.0.2.60,255.255.255.0,120s\ndhcp-authoritative\nno-ping\ndhcp-leasefile=/m2/cache.leases\ndomain=cache.test',kind=12,host='42.2.0.192.in-addr.arpa',action='ptr-lease')
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

# Calibrate dynamic cached CNAME terminals independently of configured UID0
# aliases. The upstream terminal is deliberately different from the interface.
for label,config in [('cache-cname-interface-present','interface-name=target.cache.test,cache0/4'),
                      ('cache-cname-interface-empty','interface-name=target.cache.test,missing0/4')]:
    case(label,config,action='cname')

DESCRIPTORS={2:'ns',3:'md',4:'mf',6:'soa',7:'mb',8:'mg',9:'mr',12:'ptr-generic',14:'minfo',15:'mx',17:'rp',
             18:'afsdb',21:'rt',24:'sig',26:'px',30:'nxt',36:'kx',33:'srv',39:'dname'}
for kind,label in DESCRIPTORS.items():case('generic-'+label,'cache-rr=ANY',kind=kind)
for kind,label in [(16,'txt'),(35,'naptr-opaque'),(257,'caa'),(64,'svcb-opaque'),(65,'https-opaque'),
                   (43,'ds'),(48,'dnskey'),(46,'rrsig-opaque'),(65000,'unknown')]:
    case('generic-'+label,'cache-rr=ANY',kind=kind)
case('metadata-dnskey-generic-stale','cache-rr=ANY\nuse-stale-cache=0',kind=48,ttl=1,action='expired-stale')
case('metadata-ds-generic-stale','cache-rr=ANY\nuse-stale-cache=0',kind=43,ttl=1,action='expired-stale')
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
case('generic-expanded-u16-overflow','cache-rr=ANY',kind=6,host='.'.join(['x'*63]*3+['y'*61]),transports=['tcp','tcp'],answers=[{'data':(b'\xc0\x0c'*2+b'x'*65200).hex()}])
case('generic-malformed-prefix-effects','cache-rr=ANY',kind=15,action='malformed-prefix')
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
# Each insertion/error case observes actual parent cache/forward counters
# through the image ubusd and public dnsmasq metrics method.
def sequence_case(label,steps,config='',**fields):
    case(label,config,action='sequence',steps=steps,metrics=True,**fields)
SEED={'label':'seed'}
FORCE={'label':'forced-insert','do':True}
PROBE={'label':'probe'}
RECOVERY={'plan':{'answers':[{'data':'c6336409'}]}}
for label,incoming,config in [
    ('order-rrset-replace',[{'data':'c6336408'},{'data':'c6336409'}],''),
    ('order-cname-replaces-types',[{'kind':5,'data':name('target.cache.test').hex()},
                                 {'kind':1,'data':'c6336408','owner':'target.cache.test'}],''),
    ('order-zero-ttl-prefix-abort',[{'data':'c6336408'},{'data':'c6336409','ttl':0}],''),
    ('order-late-malformed-prefix-abort',[{'data':'c6336408'},{'data':'0102','rdlen':200}],''),
    ('order-late-rebind-prefix-abort',[{'data':'08080808'},{'data':'0a000001'}],'stop-dns-rebind')]:
    if label=='order-late-rebind-prefix-abort':
        sequence_case(label,[SEED,{'plan':{'answers':incoming}},FORCE,{'plan':{'answers':[{'data':'08080809'}]}},PROBE,{'label':'recovery-hit'}],config,answers=[{'data':'08080807'}])
    else:
        sequence_case(label,[SEED,{'plan':{'answers':incoming}},FORCE,RECOVERY,PROBE,{'label':'recovery-hit'}],config)
sequence_case('order-cd-deletes-old',[SEED,{'plan':{'answers':[{'data':'c6336408'}]}},
    {'label':'extract-only','do':True,'flags':0x110},RECOVERY,PROBE,{'label':'recovery-hit'}])
sequence_case('order-a-aaaa-coexist',[SEED,{'plan':{'answers':[{'kind':28,'data':ipaddress.ip_address('2001:db8::8').packed.hex()}]}},
    {'label':'seed-aaaa','kind':28},PROBE,{'label':'aaaa-probe','kind':28}])
sequence_case('order-generic-types-coexist',[SEED,{'plan':{'answers':[{'kind':15,'data':(b'\x00\x0a'+name('target.cache.test')).hex()}]}},
    {'label':'seed-mx','kind':15},PROBE,{'label':'mx-probe','kind':15}],config='cache-rr=ANY',kind=16)
sequence_case('order-positive-negative-replace',[SEED,{'plan':{'answers':[]}},FORCE,PROBE,
    RECOVERY,{'label':'force-positive','do':True},{'label':'positive-hit'}],config='neg-ttl=60')
sequence_case('order-nxdomain-type-conflicts',[SEED,{'plan':{'answers':[],'response_flags':0x8183}},FORCE,
    PROBE,{'label':'txt-negative','kind':16}],config='neg-ttl=60')
sequence_case('order-clear-hup',[SEED,{'hup':True},RECOVERY,PROBE,{'label':'recovery-hit'}])
for capacity,label,fields in [(0,'order-capacity0',{}),
                              (1,'order-capacity1-chain',{'answers':[{'kind':5,'data':name('target.cache.test').hex()},
                                           {'kind':1,'data':'c6336407','owner':'target.cache.test'}]}),
                              (1,'order-capacity1-negative-soa',{'answers':[],'soa':True})]:
    sequence_case(label,[SEED,PROBE],capacity=capacity,**fields)
for length,label,capacity in [(74,'order-long-name74',100),(75,'order-long-name75',100),
                              (75,'order-long-name-quota0',1)]:
    host='x'*60+'.'+'y'*(length-61)
    sequence_case(label,[SEED,PROBE],host=host,capacity=capacity)
sequence_case('order-ecs-no-cache-deletes-old',[SEED,{'plan':{'answers':[{'data':'c6336408'}]}},
    {'label':'extract-only','do':True,'opts':bytes.fromhex('0008000700011800c63364')},RECOVERY,PROBE,{'label':'recovery-hit'}])
sequence_case('order-non-in-after-aborted-pending',[SEED,{'plan':{'answers':[{'data':'c6336408'},{'data':'c6336409','ttl':0}]}},FORCE,
    RECOVERY,{'label':'class-other','cls':3},PROBE,{'label':'recovery-hit'}])
for label,address,config in [('order-local-same-address','c6336408','host-record=target.cache.test,198.51.100.8,120'),
                              ('order-local-different-address-abort','c6336409','host-record=target.cache.test,198.51.100.8,120'),
                              ('order-local-cname-abort','c6336408','cname=target.cache.test,health.cache.test'),
                              ('order-cname-target-local','c6336408','host-record=target.cache.test,198.51.100.8,120')]:
    sequence_case(label,[SEED,{'plan':{'answers':[{'kind':5,'data':name('target.cache.test').hex()},
                  {'kind':1,'owner':'target.cache.test','data':address}]}},FORCE,PROBE,PROBE],config)
CHAIN_BASE='chain.cache.test'
for length in [10,11]:
    owners=['order-cname'+str(length)+'.cache.test']+[str(i)+'.'+CHAIN_BASE for i in range(1,length+1)]
    answers=[{'kind':5,'owner':owner,'data':name(owners[index+1]).hex()} for index,owner in enumerate(owners[:-1])]
    answers.append({'kind':1,'owner':owners[-1],'data':'c6336407'})
    sequence_case('order-cname'+str(length),[SEED,PROBE],answers=answers)
sequence_case('order-cname-loop',[SEED,PROBE],answers=[{'kind':5,'data':name('loop.cache.test').hex()},
    {'kind':5,'owner':'loop.cache.test','data':name('order-cname-loop.cache.test').hex()}])
sequence_case('order-cname-unresolved',[SEED,PROBE],answers=[{'kind':5,'data':name('unresolved.cache.test').hex()}])
for label,capacity in [('order-cname-target-generation-preserve',8),('order-cname-target-slot-reuse-invalidates',2)]:
    cname_answers=[{'kind':5,'data':name('target.cache.test').hex()},
                   {'kind':1,'owner':'target.cache.test','data':'c6336407'}]
    if capacity==8:
        steps=[SEED,{'plan':{'answers':[{'data':'c6336408'}]},'target':'target.cache.test'},
               {'label':'target-replaced','target':'target.cache.test','do':True},PROBE,{'label':'alias-repeat'}]
    else:
        steps=[SEED,{'label':'pressure','target':'pressure.cache.test'},PROBE,{'label':'alias-repeat'}]
    sequence_case(label,steps,capacity=capacity,answers=cname_answers)
sequence_case('order-recovery-after-abort',[SEED,{'plan':{'answers':[{'data':'c6336408'},{'data':'c6336409','ttl':0}]}},
    FORCE,RECOVERY,PROBE,{'label':'recovery-repeat'}],capacity=2)
sequence_case('order-capacity-live-rrset-eviction',[SEED,{'label':'other','target':'other.cache.test'},
    {'label':'new-name','target':'new.cache.test'},PROBE,{'label':'new-probe','target':'new.cache.test'}],
    capacity=3,answers=[{'data':'c6336407'},{'data':'c6336408'}])
sequence_case('order-expired-reclaim-before-live',[SEED,{'plan':{'ttl':600},'target':'live.cache.test'},{'label':'live','target':'live.cache.test'},
    {'sleep':2.2},{'label':'new','target':'new.cache.test'},{'label':'live-retained','target':'live.cache.test'},PROBE],capacity=2,ttl=1)
sequence_case('order-reverse-global-expired-scan',[SEED,{'sleep':2.2},{'label':'reverse','target':PTR4,'kind':12},
    {'label':'new-long','target':'z'*60+'.'+'q'*14},{'label':'new-long-hit','target':'z'*60+'.'+'q'*14}],
    capacity=10,ttl=1,host='x'*60+'.'+'y'*14)
sequence_case('order-reverse-forward-share-capacity',[{'label':'reverse','target':PTR4,'kind':12},
    {'label':'forward','target':'forward.cache.test'},{'label':'reverse-probe','target':PTR4,'kind':12}],capacity=1)
sequence_case('order-long-name-quota-reuse',[SEED,{'label':'other-long','target':'z'*60+'.'+'q'*14},
    {'label':'replace-long','do':True},PROBE],capacity=10,host='x'*60+'.'+'y'*14)

for option in ['min-cache-ttl','max-cache-ttl','max-ttl']:
    config=option+'='+('3' if option!='max-ttl' else '1')
    ttl=1 if option=='min-cache-ttl' else 600
    steps=[SEED]
    if option!='max-ttl':steps += [{'sleep':1.2},{'label':'retained-before-expiry'},{'sleep':3.2}]
    else:steps += [{'sleep':2.2}]
    steps += [{'plan':{'answers':[{'data':'c6336408'}]}},{'label':'expired-refetch'},{'label':'refreshed-hit'}]
    sequence_case(option+'-expiry-recovery',steps,config,ttl=ttl)
SOA_RDATA=name('ns.cache.test')+name('hostmaster.cache.test')+__import__('struct').pack('!5I',1,60,60,600,300)
for label,soa_ttl in [('negative-soa-replaced',30),('negative-soa-expired',1)]:
    steps=[SEED,{'plan':{'answers':[{'kind':6,'data':SOA_RDATA.hex(),'ttl':soa_ttl}],'soa':False},'target':ZONE},
           {'label':'soa-replaced','target':ZONE,'kind':6,'do':True}]
    if soa_ttl==1:steps.append({'sleep':2.2})
    steps += [PROBE,{'label':'negative-repeat'}]
    sequence_case(label,steps,'cache-rr=SOA',answers=[],soa=True)
sequence_case('negative-explicit-soa-positive-share',[SEED,{'label':'positive-soa','target':ZONE,'kind':6},PROBE],
              'cache-rr=SOA',answers=[],soa=True)
sequence_case('negative-soa-evicted',[SEED,{'plan':{'answers':[],'soa':False,'response_flags':0x8182}},
    {'label':'promote-negative-do','do':True},{'label':'pressure','target':'pressure.cache.test'},PROBE],
    answers=[],soa=True,capacity=2)
sequence_case('negative-first-soa-selection',[SEED,PROBE],answers=[],authority_records=[
    {'kind':6,'owner':ZONE,'data':SOA_RDATA.hex(),'ttl':20},
    {'kind':6,'owner':ZONE,'data':SOA_RDATA.hex(),'ttl':600}])
sequence_case('negative-malformed-soa',[SEED,PROBE],'neg-ttl=60',answers=[],authority_records=[
    {'kind':6,'owner':ZONE,'data':'0102','ttl':600}])

sequence_case('ttl-cname-target-independent-expiry',[SEED,{'sleep':2.2},
    {'label':'target-retained','target':'target.cache.test'},PROBE],answers=[
    {'kind':5,'data':name('target.cache.test').hex(),'ttl':1},
    {'kind':1,'owner':'target.cache.test','data':'c6336407','ttl':600}])
for label in ['ttl-expiry-exact-second','ttl-stale-strict-after-expiry','stale-equal-expiry-zero-not-stale']:
    case(label,'use-stale-cache=0',ttl=0,action='tcp-zero-clock')

# Round-robin is a forward lookup effect. Reverse queries never rotate.
for shape,kind in [('a',1),('aaaa',28),('generic',16),('reverse',12),('hosts',1)]:
    for disabled in [False,True]:
        label='round-'+shape+('-disabled' if disabled else '-default')
        host=PTR4 if shape=='reverse' else label+'.cache.test'
        config=('no-round-robin\n' if disabled else '')+('cache-rr=ANY\n' if shape=='generic' else '')
        fields={}
        if shape=='hosts':config+='\n'.join('host-record='+host+',198.51.100.'+str(value) for value in [7,8,9])
        elif shape=='a':fields['answers']=[{'data':ipaddress.ip_address('198.51.100.'+str(value)).packed.hex()} for value in [7,8,9]]
        elif shape=='aaaa':fields['answers']=[{'data':ipaddress.ip_address('2001:db8::'+str(value)).packed.hex()} for value in [7,8,9]]
        elif shape=='generic':fields['answers']=[{'data':bytes([1,value]).hex()} for value in [97,98,99]]
        else:fields['answers']=[{'data':name(value+'.cache.test').hex()} for value in ['first','second','third']]
        case(label,config,kind=kind,host=host,action='round-five',**fields)
for label,fields in [('round-insert-order',{}),('round-do-miss-effects',{'miss':'do'}),
                      ('round-rd-off-effects',{'miss':'rd'}),('round-expired-entry-removal',{'expires':True}),
                      ('round-cname-prefix-lookups',{'cname':True})]:
    case(label,action='round-five',answers=[{'data':'c6336407'},{'data':'c6336408'},{'data':'c6336409'}],**fields)
for disabled in [False,True]:
    case('round-mixed-generic-'+('disabled' if disabled else 'default'),
         'cache-rr=ANY'+('\nno-round-robin' if disabled else ''),kind=16,action='round-five',mixed=True,
         answers=[{'data':'0161'},{'data':'0162'},{'data':'0163'}])
case('round-tcp-snapshot-vs-parent',action='round-snapshot',answers=[{'data':'c6336407'},{'data':'c6336408'},{'data':'c6336409'}])

# Real expiry/refetch schedules, each retaining seed/stale/refresh wire and
# monotonic timestamps. DNS/TCP refresh starts from a newly accepted view.
STALE_SHAPES=[('a',1,{}),('aaaa',28,{}),('generic',16,{'config':'cache-rr=TXT'}),
              ('cname',1,{'shape':'cname'}),('reverse',12,{'host':PTR4}),
              ('negative',1,{'shape':'negative','answers':[],'response_flags':0x8183,'soa':True,'soa_ttl':1,'soa_minimum':1})]
for shape,kind,shape_fields in STALE_SHAPES:
    for mode in ['udp-refresh','tcp-refresh','rd-off','do-on','do-off','finite-expired','forever']:
        fields=copy.deepcopy(shape_fields);extra=fields.pop('config','')
        config=('use-stale-cache=3' if mode=='finite-expired' else 'use-stale-cache=0')+'\n'+extra
        case('stale-'+shape+'-'+mode,config,kind=kind,ttl=1,action='stale-schedule',mode=mode,**fields)
for label,fields in [('stale-default',{}),('stale-no-opt-no-ede',{'opts':None}),
                      ('stale-client-opt-ede3',{}),('stale-upstream-failure-retains',{'refresh_error':True}),
                      ('stale-filter-ede-precedence',{'config':'filter-A'}),
                      ('stale-hup-clears',{'clear_hup':True}),
                      ('stale-tcp-refresh-import',{'mode':'tcp-refresh'}),
                      ('stale-tcp-eof-before-refresh',{'mode':'tcp-refresh'}),
                      ('stale-background-no-second-reply',{'double_read':True})]:
    fields=copy.deepcopy(fields);extra=fields.pop('config','');mode=fields.pop('mode','udp-refresh')
    case(label,('use-stale-cache' if label=='stale-default' else 'use-stale-cache=0')+'\n'+extra,
         ttl=1,action='stale-schedule',mode=mode,**fields)

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
        for record in spec.get('authority_records',[]):
            authority.append(rr(record.get('kind',6),bytes.fromhex(record['data']),name(record.get('owner',ZONE)),
                                record.get('ttl',600),record.get('cls',1),record.get('rdlen')))
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
        client.bind((LEASE_CLIENT,68));sent=time.monotonic_ns();client.sendto(packet,(LISTEN,67))
        if kind==7:return {'label':label,'sent_release':True,'server':server,'sent_monotonic_ns':sent,'completed_monotonic_ns':time.monotonic_ns()}
        reply,_=client.recvfrom(4096);completed=time.monotonic_ns()
    (folder/(label+'.dhcp.reply')).write_bytes(reply)
    if len(reply)<240 or struct.unpack_from('!I',reply,4)[0]!=ident:raise AssertionError('DHCP identity mismatch')
    options={};at=240
    while at<len(reply):
        code=reply[at];at+=1
        if code==255:break
        if code==0:continue
        size=reply[at];at+=1;options[code]=reply[at:at+size];at+=size
    if options.get(53)!=b'\x05':raise AssertionError('positive DHCP ACK required, got '+repr(options.get(53)))
    return {'label':label,'message':5,'address':socket.inet_ntoa(reply[16:20]),'server':socket.inet_ntoa(options[54]),
            'lease_seconds':struct.unpack('!I',options[51])[0],'sent_monotonic_ns':sent,'completed_monotonic_ns':completed}


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


def schedule(spec,port,upstream,folder,root):
    host=spec.get('host',spec['case']+'.'+ZONE);upstream.plan[host]=spec;observations=[]
    def cache_metrics(label):
        result=subprocess.run(command(root,'/bin/ubus','call','cache-metrics','metrics','{}'),capture_output=True,timeout=2)
        (folder/(label+'.metrics.stdout')).write_bytes(result.stdout);(folder/(label+'.metrics.stderr')).write_bytes(result.stderr)
        if result.returncode:raise AssertionError('cache metrics response failed '+str(result.returncode))
        all_metrics=json.loads(result.stdout)
        return {key:all_metrics[key] for key in ['dns_cache_inserted','dns_cache_live_freed','dns_queries_forwarded','dns_local_answered','dns_stale_answered']}
    def packet(label,target=host,tcp=False,connection=None,step=0,**overrides):
        fields=dict(spec,**overrides)
        wire=query(target,0x5200+step,fields.get('kind',1),fields.get('flags',0x100),fields.get('cls',1),fields.get('do',False),
                   fields.get('opts',b''),fields.get('opt_ttl',0),fields.get('signed',False),fields.get('extra',False),fields.get('size',1232))
        started=time.monotonic_ns();reply=exchange(port,wire,tcp,connection);completed=time.monotonic_ns()
        (folder/(label+'.query')).write_bytes(wire)
        if reply is not None:(folder/(label+'.reply')).write_bytes(reply)
        observations.append({'label':label,'query':normalized(wire),'reply':normalized(reply),'elapsed_seconds':(completed-started)/1e9,'sent_monotonic_ns':started,'completed_monotonic_ns':completed})
        if spec.get('metrics'):observations[-1]['metrics']=cache_metrics(label)
    action=spec.get('action')
    if action=='cname':
        upstream.plan[host]=dict(spec,answers=[{'kind':5,'data':name('target.cache.test').hex()},
                                               {'kind':spec.get('kind',1),'owner':'target.cache.test','data':default_rdata(spec.get('kind',1)).hex()}])
    if action=='startup':return observations
    if action=='sequence':
        for index,command_spec in enumerate(spec['steps']):
            command_spec=copy.deepcopy(command_spec)
            if 'plan' in command_spec:
                upstream.plan[command_spec.get('target',host)]=dict(spec,**command_spec['plan'])
            elif 'sleep' in command_spec:time.sleep(command_spec['sleep'])
            elif command_spec.get('hup'):process_hup(folder)
            else:
                label=command_spec.pop('label','step-'+str(index));target=command_spec.pop('target',host)
                packet(label,target,step=index,**command_spec)
        return observations
    if action in ('round-five','round-snapshot'):
        if spec.get('cname'):
            upstream.plan[host]=dict(spec,answers=[{'kind':5,'data':name('round-target.cache.test').hex()}]
                       +[dict(row,owner='round-target.cache.test') for row in spec['answers']])
        if spec.get('expires'):
            upstream.plan[host]=dict(spec,answers=[dict(row,ttl=1 if index==0 else 600) for index,row in enumerate(spec['answers'])])
        packet('seed')
        if spec.get('expires'):time.sleep(2.2)
        if spec.get('mixed'):
            upstream.plan[host]=dict(spec,answers=[{'data':(bytes([0,value])+name('target.cache.test')).hex()} for value in [10,20]])
            packet('seed-other-type',kind=15)
        if spec.get('miss'):
            upstream.plan[host]=dict(spec,response_flags=0x8182,answers=[])
            packet('ineligible-miss',**({'do':True} if spec['miss']=='do' else {'flags':0}))
        if action=='round-snapshot':
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as conn:
                conn.settimeout(2);conn.bind((CLIENT,0));conn.connect((LISTEN,port))
                packet('accepted-health','health.cache.test',True,conn,kind=1)
                for index in range(3):
                    packet('parent-'+str(index));packet('child-'+str(index),tcp=True,connection=conn)
        else:
            for index in range(5):packet('round-'+str(index))
        return observations
    if action=='tcp-zero-clock':
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as conn:
            conn.settimeout(2);conn.bind((CLIENT,0));conn.connect((LISTEN,port))
            packet('child-zero-first',tcp=True,connection=conn)
            time.sleep(2.2);packet('child-equal-expiry',tcp=True,connection=conn)
            upstream.plan[host]=dict(spec,ttl=600,answers=[{'data':'c6336408'}])
            packet('parent-after-expiry');time.sleep(.1);packet('parent-refreshed')
        return observations
    if action=='stale-schedule':
        shape=spec.get('shape')
        if shape=='cname':
            upstream.plan[host]=dict(spec,answers=[{'kind':5,'data':name('target.cache.test').hex()},
                                          {'kind':1,'data':'c6336407','owner':'target.cache.test'}])
        packet('seed');time.sleep(5.2 if spec['mode']=='finite-expired' else 2.2)
        if spec.get('clear_hup'):process_hup(folder)
        fresh=dict(spec,ttl=600,soa_ttl=600,soa_minimum=600)
        kind=spec.get('kind',1)
        if shape=='cname':fresh['answers']=[{'kind':5,'data':name('target.cache.test').hex()},
                                          {'kind':1,'data':'c6336408','owner':'target.cache.test'}]
        elif shape!='negative':
            data={1:'c6336408',28:ipaddress.ip_address('2001:db8:100::8').packed.hex(),16:b'\x05newxx'.hex(),12:name('fresh.cache.test').hex()}[kind]
            fresh['answers']=[{'data':data}]
        if spec.get('refresh_error'):fresh.update(response_flags=0x8182,answers=[],soa=False)
        upstream.plan[host]=fresh
        overrides={'flags':0} if spec['mode']=='rd-off' else {'do':True} if spec['mode']=='do-on' else {}
        if spec.get('double_read'):
            wire=query(host,0x5201,kind)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
                stream.settimeout(.8);stream.bind((CLIENT,0));stream.connect((LISTEN,port));started=time.monotonic_ns()
                stream.send(wire);reply=stream.recv(65535);completed=time.monotonic_ns()
                (folder/'expired.query').write_bytes(wire);(folder/'expired.reply').write_bytes(reply)
                observations.append({'label':'expired','query':normalized(wire),'reply':normalized(reply),
                                     'sent_monotonic_ns':started,'completed_monotonic_ns':completed,'elapsed_seconds':(completed-started)/1e9})
                try:second=stream.recv(65535)
                except socket.timeout:second=None
                if second is not None:(folder/'background-second.reply').write_bytes(second)
                observations.append({'label':'background-second-reply','reply':normalized(second)})
        else:packet('expired',tcp=spec['mode']=='tcp-refresh',**overrides)
        time.sleep(.1)
        packet('after-refresh')
        if spec.get('refresh_error'):time.sleep(.15)
        return observations
    if action=='expired-stale':
        packet('seed');time.sleep(2.2)
        upstream.plan[host]=dict(spec,ttl=600,answers=[{'data':name('refreshed.cache.test').hex() if spec.get('kind')==12 else '11121314'}])
        packet('expired-stale');time.sleep(.1);packet('refreshed')
        return observations
    if action=='malformed-prefix':
        packet('seed')
        upstream.plan[host]=dict(spec,answers=[{'data':(b'\x00\x02'+name('changed.cache.test')).hex()},
                                               {'data':'0002c0ff'}])
        packet('malformed-cd',flags=0x110,do=True)
        upstream.plan[host]=dict(spec,answers=[{'data':(b'\x00\x03'+name('recovered.cache.test')).hex()}])
        packet('old-probe');packet('recovery-hit')
        return observations
    if action and action.startswith('ptr-'):
        packet('seed')
        if action=='ptr-lease':
            proof=lease_exchange(folder,'lease');(folder/'lease-witness.json').write_text(json.dumps([proof],indent=2)+'\n')
            packet('after-lease');packet('lease-forward','leaseold.cache.test',kind=1);packet('reverse-repeat')
        elif action=='ptr-alias':
            packet('same-ip-alias','273.2.0.192.in-addr.arpa')
        elif action=='ptr-two':
            other='18.2.0.192.in-addr.arpa';upstream.plan[other]=dict(spec)
            packet('other-ip',other);packet('first-ip');packet('second-ip',other)
        elif action in ('ptr-forward','ptr-forward-independent'):
            target='target.cache.test'
            upstream.plan[target]=dict(kind=1)
            if action=='ptr-forward-independent':packet('seed-forward',target,kind=1)
            packet('forward-target',target,kind=1);packet('reverse-retained')
        elif action=='ptr-negative':
            packet('other-qtype',kind=28);packet('ptr-negative-hit')
        elif action=='ptr-replace':
            upstream.plan[host]=dict(spec,answers=[{'data':name('changed.cache.test').hex()}])
            packet('replace-forced',do=True);packet('new-rrset');packet('new-rrset-repeat')
        return observations
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
    selected=[spec for spec in SCENARIOS if re.compile(args.only or '.').search(spec['case'])]
    bus=None;bus_log=None
    if any(spec.get('metrics') for spec in selected):
        bus_log=(out/'ubusd.log').open('wb')
        bus=subprocess.Popen(command(root,'/sbin/ubusd'),stdout=bus_log,stderr=bus_log,start_new_session=True)
        deadline=time.monotonic()+4
        while subprocess.run(command(root,'/bin/ubus','list'),capture_output=True,timeout=1).returncode:
            if bus.poll() is not None or time.monotonic()>=deadline:raise AssertionError('image ubusd startup failed')
            time.sleep(.01)
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
                f'server=127.0.0.2#{upstream.port}\ncache-size={spec.get("capacity",100)}\nno-0x20-encode\n'
                'host-record=health.cache.test,198.51.100.99\nlocal-ttl=600\nuser=root\n'
                'pid-file=/m2/cache.pid\nlog-facility=/m2/cache.log\n'+spec['config']+'\n'
                +('enable-ubus=cache-metrics\n' if spec.get('metrics') else ''))
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
            trace['observations']=schedule(spec,port,upstream,folder,root);report['executed_cases'].append(label)
            if (folder/'lease-witness.json').exists():trace['lease_witness']=json.loads((folder/'lease-witness.json').read_text())
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
    if bus is not None:
        os.killpg(bus.pid,signal.SIGTERM);bus.wait(2);bus_log.close()
    print(json.dumps({'side':args.side,'executed':len(report['executed_cases']),'missing':len(report['missing_required_cases']),'failures':report['failures']}))
    return int(bool(report['failures']))


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('run');p.add_argument('--side',choices=['c','rust'],required=True);p.add_argument('--image-root',type=Path,required=True)
    p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--only')
    p=sub.add_parser('qualify-dhcp-caller');p.add_argument('--c',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p=sub.add_parser('compare');p.add_argument('--c',type=Path,action='append',required=True);p.add_argument('--candidate',type=Path,action='append',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--boundaries',default='')
    args=parser.parse_args();raise SystemExit(run(args) if args.action=='run' else qualify_dhcp_caller(args) if args.action=='qualify-dhcp-caller' else compare_family(args))


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
            proofs=row.get('lease_witness',[])
            expected={'tcp-parent-lease-added':['add'],'tcp-parent-lease-renamed':['seed','rename'],
                      'tcp-parent-lease-released':['seed','release'],'tcp-existing-lease-ttl':['seed']}[label]
            if [proof.get('label') for proof in proofs]!=expected:return False
            for proof in proofs:
                if not isinstance(proof.get('sent_monotonic_ns'),int) or not isinstance(proof.get('completed_monotonic_ns'),int):return False
                if proof['completed_monotonic_ns']<proof['sent_monotonic_ns']:return False
                if proof.get('label')=='release':
                    if proof.get('sent_release') is not True:return False
                elif proof.get('message')!=5 or proof.get('address')!=LEASE_CLIENT or proof.get('lease_seconds')!=120:return False
            for observation in row['observations']:
                if not isinstance(observation.get('sent_monotonic_ns'),int) or not isinstance(observation.get('completed_monotonic_ns'),int):return False
                if observation['completed_monotonic_ns']<observation['sent_monotonic_ns']:return False
            if label=='tcp-existing-lease-ttl':
                early=next(v for v in row['observations'] if v['label']=='lease-first')
                late=next(v for v in row['observations'] if v['label']=='lease-after-wait')
                if late['sent_monotonic_ns']-early['completed_monotonic_ns']<3_200_000_000:return False
        a=[{k:copy.deepcopy(v) for k,v in row.items() if k not in ('elapsed_seconds','sent_monotonic_ns','completed_monotonic_ns')} for row in left['observations']]
        b=[{k:copy.deepcopy(v) for k,v in row.items() if k not in ('elapsed_seconds','sent_monotonic_ns','completed_monotonic_ns')} for row in right['observations']]
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
                case_report=next(row for row in report['scenarios'] if row['case']==label)
                if proof!=case_report.get('lease_witness'):qualified=False
        for mode in ['lease-added','lease-renamed','lease-released','ttl-decay','ttl-unbounded','missing-case','bad-identity','missing-witness','short-wait']:
            wrong=copy.deepcopy(r);rows={s['case']:s for s in wrong['scenarios']}
            if mode.startswith('lease-'):
                label='tcp-parent-'+mode
                observation=next(v for v in rows[label]['observations'] if v['label'].startswith('child-'))
                observation['reply']['records'][0]['data']='203.0.113.99'
            elif mode.startswith('ttl-'):
                observation=next(v for v in rows['tcp-existing-lease-ttl']['observations'] if v['label']=='lease-after-wait')
                observation['reply']['records'][0]['ttl']=117 if mode=='ttl-decay' else 999
            elif mode=='missing-witness':rows[DHCP_CALLERS[0]].pop('lease_witness')
            elif mode=='short-wait':
                first=next(v for v in rows['tcp-existing-lease-ttl']['observations'] if v['label']=='lease-first')
                late=next(v for v in rows['tcp-existing-lease-ttl']['observations'] if v['label']=='lease-after-wait')
                late['sent_monotonic_ns']=first['completed_monotonic_ns']+3_000_000_000
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

CLOCK_KEYS={'elapsed_seconds','sent_monotonic_ns','completed_monotonic_ns'}
REVERSE_ORDER_CASES={'ptr-multiple-targets','ptr-reverse-bucket-order','round-reverse-default','round-reverse-disabled'}


def comparison_rows(folder,side):
    report=json.loads((folder/'result.json').read_text())
    if report.get('manifest_sha256')!=sha256(Path(__file__).with_suffix('.json')):
        raise ValueError('different frozen source contract')
    if sha256(folder/'drivers/m5_dns_cache.py')!=report.get('driver_sha256'):
        raise ValueError('saved driver identity mismatch')
    if report.get('side')!=side or report.get('c_sha256')!=STOCK_SHA256:
        raise ValueError('invalid report reference identity')
    if side=='rust' and not re.fullmatch('[0-9a-f]{64}',report.get('rust_sha256','')):
        raise ValueError('missing candidate identity')
    rows={}
    for row in report['syntax']:rows[row['case']]=row
    for row in report['scenarios']:
        if row.get('failure') or row['exit']!=0 or row['upstream_errors']:
            raise ValueError('case did not complete: '+row['case'])
        for observation in row['observations']:
            if observation.get('reply',{}).get('result')=='timeout':continue
            query=folder/row['case']/(observation['label']+'.query')
            reply=folder/row['case']/(observation['label']+'.reply')
            if query.exists() and reply.exists() and query.read_bytes()[:2]!=reply.read_bytes()[:2]:
                raise ValueError('client reply ID mismatch: '+row['case']+'/'+observation['label'])
        rows[row['case']]=row
    return report,rows


def canonical_observations(row,reverse_order=False):
    observations=[{key:copy.deepcopy(value) for key,value in obs.items() if key not in CLOCK_KEYS}
                  for obs in row['observations']]
    labels={obs['label']:obs for obs in row['observations']}
    for obs in observations:
        # A newly refreshed TTL600 RR may lose one whole second between the
        # actual receive/insert and this real100ms client followup. Only this
        # explicit stage/configured TTL is admitted; staleTTL0 remains exact.
        if obs['label'] in ('after-refresh','refreshed','parent-refreshed'):
            previous=labels.get('expired',labels.get('expired-stale',labels.get('parent-after-expiry')))
            current=labels[obs['label']]
            if previous and 100_000_000 <= current['sent_monotonic_ns']-previous['completed_monotonic_ns'] < 900_000_000:
                for rr in obs['reply'].get('records',[]):
                    if rr['section'] in ('answer','authority') and rr['ttl'] in (599,600):rr['ttl']='fresh600-within-one-second'
        # These two source-frozen expiry schedules observe integer-second
        # TTLs across a measured1.2s/2.2s interval. Preserve their exact allowed
        # ranges and all non-TTL data; no other replay TTL is normalized.
        if obs['label']=='retained-before-expiry' and row['case'] in ('min-cache-ttl-expiry-recovery','max-cache-ttl-expiry-recovery'):
            seed=labels.get('seed');current=labels[obs['label']]
            if seed and 1_200_000_000 <= current['sent_monotonic_ns']-seed['completed_monotonic_ns'] < 1_900_000_000:
                for rr in obs['reply'].get('records',[]):
                    if rr['section']=='answer' and rr['ttl'] in (1,2):rr['ttl']='remaining-of-cache-ttl3-after-real1.2s'
        if obs['label']=='target-retained' and row['case']=='ttl-cname-target-independent-expiry':
            seed=labels.get('seed');current=labels[obs['label']]
            if seed and 2_200_000_000 <= current['sent_monotonic_ns']-seed['completed_monotonic_ns'] < 2_900_000_000:
                for rr in obs['reply'].get('records',[]):
                    if rr['section']=='answer' and rr['ttl'] in (597,598):rr['ttl']='remaining-of-target-ttl600-after-real2.2s'
        if reverse_order:
            records=obs['reply'].get('records',[])
            answers=[rr for rr in records if rr['section']=='answer']
            if answers and all(rr['type']==12 for rr in answers) and obs['label'] not in ('seed','query-0'):
                # This admission is enabled only after independent image C
                # invocations prove executable-address hash order variation.
                rest=[rr for rr in records if rr['section']!='answer']
                obs['reply']['records']=sorted(answers,key=lambda rr:json.dumps(rr,sort_keys=True))+rest
    return observations


def reverse_stable(row):
    signatures=[]
    for obs in row['observations']:
        if obs['label'] in ('seed','query-0'):continue
        answers=[rr for rr in obs['reply'].get('records',[]) if rr['section']=='answer']
        if answers and all(rr['type']==12 for rr in answers):
            signatures.append([(rr['name'],rr['type'],rr['class'],rr['data']) for rr in answers])
    return bool(signatures) and all(value==signatures[0] for value in signatures)


def real_expiry_witness(row):
    labels={obs['label']:obs for obs in row['observations']}
    if 'child-zero-first' in labels and 'child-equal-expiry' in labels:
        if labels['child-equal-expiry'].get('sent_monotonic_ns',0)-labels['child-zero-first'].get('completed_monotonic_ns',0)<2_200_000_000:return False
    if not row['case'].startswith(('stale-','ptr-stale-refresh','ptr-expiry-refresh','metadata-dnskey-generic-stale','metadata-ds-generic-stale')):return True
    labels={obs['label']:obs for obs in row['observations']}
    expired=labels.get('expired',labels.get('expired-stale'))
    seed=labels.get('seed')
    if not expired or not seed:return True
    wait=5_200_000_000 if row['case'].endswith('finite-expired') else 2_200_000_000
    return expired.get('sent_monotonic_ns',0)-seed.get('completed_monotonic_ns',0)>=wait


def case_equal(c,r,reverse_variation=False):
    if 'observations' not in c:return c==r
    if c.get('config')!=r.get('config'):return False
    if not real_expiry_witness(c) or not real_expiry_witness(r):return False
    if len(c['upstream'])!=len(r['upstream']):return False
    upstream=lambda row:[{k:v for k,v in event.items() if k!='wire'} for event in row['upstream']]
    if upstream(c)!=upstream(r):return False
    if reverse_variation and (not reverse_stable(c) or not reverse_stable(r)):return False
    return canonical_observations(c,reverse_variation)==canonical_observations(r,reverse_variation)


def compare_family(args):
    c_rows={};c_versions={};r_rows={};candidate_shas=set();identities=[]
    for side,folders in [('c',args.c),('rust',args.candidate)]:
        for folder in folders:
            report,rows=comparison_rows(folder,side)
            identities.append({'side':side,'path':str(folder),'report_sha256':sha256(folder/'result.json'),
                               'driver_sha256':report['driver_sha256'],'manifest_sha256':report['manifest_sha256'],
                               'candidate_sha256':report['rust_sha256']})
            if side=='c':
                c_rows.update(rows)
                for label,row in rows.items():c_versions.setdefault(label,[]).append(row)
            else:r_rows.update(rows);candidate_shas.add(report['rust_sha256'])
    if len(candidate_shas)!=1:raise ValueError('one candidate ELF identity required')
    manifest=json.loads(Path(__file__).with_suffix('.json').read_text())
    selected=set(args.boundaries.split(',')) if args.boundaries else {b['id'] for b in manifest['boundaries']}
    boundaries=[b for b in manifest['boundaries'] if b['id'] in selected]
    required={label for b in boundaries for label in b['required_cases']}
    if not boundaries or {b['id'] for b in boundaries}!=selected:raise ValueError('unknown boundary ID')
    missing=sorted(required-(c_rows.keys()&r_rows.keys()));passed=[];different=[];variations=[];controls=[]
    for label in sorted(required&(c_rows.keys()&r_rows.keys())):
        c,r=c_rows[label],r_rows[label];variation=False
        if label in REVERSE_ORDER_CASES:
            versions=c_versions.get(label,[])
            variation=any(canonical_observations(a,True)==canonical_observations(b,True)
                          and canonical_observations(a)!=canonical_observations(b)
                          and reverse_stable(a) and reverse_stable(b)
                          for index,a in enumerate(versions) for b in versions[index+1:])
            if variation:variations.append(label)
        if case_equal(c,r,variation):passed.append(label)
        else:different.append({'case':label,'c':canonical_observations(c),'rust':canonical_observations(r),
                               'c_upstream':len(c.get('upstream',[])),'rust_upstream':len(r.get('upstream',[]))})
    for label in passed:
        c,r=c_rows[label],r_rows[label]
        if 'observations' not in r:continue
        for mode in ['upstream-count','reply-flags','reply-ttl-unbounded','missing-observation','shortened-expiry-wait']:
            wrong=copy.deepcopy(r)
            if mode=='upstream-count':wrong['upstream'].append(copy.deepcopy(wrong['upstream'][0]) if wrong['upstream'] else {})
            elif mode=='reply-flags':
                reply=next((obs['reply'] for obs in wrong['observations'] if 'flags' in obs.get('reply',{})),None)
                if reply is None:continue
                reply['flags']^=0x0400
            elif mode=='reply-ttl-unbounded':
                rr=next((rr for obs in wrong['observations'] for rr in obs.get('reply',{}).get('records',[]) if rr['section'] in ('answer','authority')),None)
                if rr is None:continue
                rr['ttl']=999999
            elif mode=='shortened-expiry-wait':
                labels={obs['label']:obs for obs in wrong['observations']}
                expired=labels.get('expired',labels.get('expired-stale'))
                if not expired or 'seed' not in labels or not wrong['case'].startswith(('stale-','ptr-stale-refresh','ptr-expiry-refresh')):continue
                expired['sent_monotonic_ns']=labels['seed']['completed_monotonic_ns']+200_000_000
            else:wrong['observations'].pop()
            controls.append({'case':label,'control':mode,'rejected':not case_equal(c,wrong,label in variations)})
    result={'candidate_sha256':next(iter(candidate_shas)),'boundaries':[b['id'] for b in boundaries],
            'required_count':len(required),'missing_required_cases':missing,'passed_cases':passed,
            'differences':different,'reference_reverse_order_variation':variations,'negative_controls':controls,
            'qualified':not missing and not different and all(x['rejected'] for x in controls),
            'full_cache_family_qualified':len(boundaries)==len(manifest['boundaries']) and not missing and not different and all(x['rejected'] for x in controls),
            'reports':identities,'comparator_sha256':sha256(__file__)}
    args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'required':len(required),'passed':len(passed),'missing':len(missing),'different':len(different),
                      'negative_controls':len(controls),'qualified':result['qualified']}))
    return int(bool(different) or not all(x['rejected'] for x in controls))

if __name__=='__main__':main()
