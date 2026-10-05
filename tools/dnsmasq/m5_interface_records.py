#!/usr/bin/env python3
"""Exact-image interface/domain/synthetic/hostsdir family, isolated namespaces.

C-only calibration never qualifies an option. Every eventual frozen required
row needs concrete paired observations, complete identities and cleanup.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import ipaddress
import json
import os
import platform
from pathlib import Path
import resource
import re
import signal
import socket
import struct
import shutil
import subprocess
import sys
import time
import traceback

from m2_rootfs import STOCK_SHA256, command, image_path, prepare, sha256
import m5_dns_endpoints as endpoints
import m5_dns_files as files


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def syntax_cases():
    cases=[]
    def add(ident, text, checks, **extra):
        cases.append(dict(id=ident,config=text,checks=checks.split(),**extra))
    for option in ('interface-name','dynamic-host'):
        values=[('ordinary','name.records.test,m5ir0'),('empty',''),('only-name','name.records.test'),
            ('empty-name',',m5ir0'),('empty-interface','name.records.test,'),
            ('family4','name.records.test,m5ir0/4'),('family6','name.records.test,m5ir0/6'),
            ('family0','name.records.test,m5ir0/0'),('family-empty','name.records.test,m5ir0/'),
            ('double-family','name.records.test,m5ir0/4/6'),('extra','name.records.test,m5ir0,ignored'),
            ('proto4','name.records.test,192.0.2.7,m5ir0'),
            ('proto6','name.records.test,2001:db8::7,m5ir0'),
            ('proto-both','name.records.test,192.0.2.7,2001:db8::7,m5ir0'),
            ('proto-repeat','name.records.test,192.0.2.7,192.0.2.8,m5ir0'),
            ('proto-family4','name.records.test,192.0.2.7,m5ir0/4'),
            ('proto-no-interface','name.records.test,192.0.2.7'),
            ('proto-empty-interface','name.records.test,192.0.2.7,'),
            ('scope-proto','name.records.test,fe80::7%m5ir0,m5ir0'),
            ('quoted-full','"name.records.test,m5ir0"'),
            ('quoted-interface','name.records.test,"m5ir0/4"'),
            ('canonical-case','NAME.RECORDS.TEST.,m5ir0'),
            ('name-bad','bad..records.test,m5ir0'),
            ('wildcard-interface','name.records.test,m5ir*'),
            ('interface15','name.records.test,abcdefghijklmno'),
            ('interface16','name.records.test,abcdefghijklmnop')]
        for label,value in values:
            add(option+'-'+label,option+'='+value+'\n','IF-GRAM')
    for option in ('interface-name','dynamic-host'):
        prefix='name.records.test,'+('192.0.2.7,' if option=='dynamic-host' else '')
        for label,value in [('binary','x\x01.records.test'),('nonascii','é.records.test'),('label63','x'*63+'.test'),('label64','x'*64+'.test'),('name253','.'.join(['a'*63]*3+['a'*61])),('name254','.'.join(['a'*63]*3+['a'*62]))]:
            add(option+'-name-'+label,option+'='+value+','+('192.0.2.7,' if option=='dynamic-host' else '')+'m5ir0\n','IF-GRAM')
        add(option+'-long-target',option+'='+prefix+'abcdefghijklmnopqrstuvw\n','IF-GRAM')
        add(option+'-quoted-comma',option+'=name.records.test,'+('192.0.2.7,' if option=='dynamic-host' else '')+'"m5ir0,tail"\n','IF-GRAM')
        add(option+'-repeated',option+'='+prefix+'m5ir0\n'+option+'='+prefix+'m5ir1\n','IF-GRAM')
    for option in ('domain','domain-suffix'):
        values=[('default','records.test'),('empty',''),('canonical','RECORDS.TEST.'),
            ('bad-name','bad..records.test'),('single4','records.test,192.0.2.7'),
            ('range4','records.test,192.0.2.7,192.0.2.9'),
            ('inverted4','records.test,192.0.2.9,192.0.2.7'),
            ('single6','records.test,2001:db8::7'),('range6','records.test,2001:db8::7,2001:db8::9'),
            ('inverted6','records.test,2001:db8::9,2001:db8::7'),
            ('mixed','records.test,192.0.2.7,2001:db8::7'),
            ('interface','records.test,m5ir0'),('empty-selector','records.test,'),
            ('interface-extra','records.test,m5ir0,ignored'),
            ('range-local','records.test,192.0.2.7,192.0.2.9,local'),
            ('prefix-local','records.test,192.0.2.7/24,local'),
            ('prefix-local0','records.test,192.0.2.7/0,local'),
            ('prefix-bad-local','records.test,192.0.2.7/24,bad'),
            ('quoted','"records.test,192.0.2.7/24"')]
        values += [('prefix4-'+str(width),'records.test,192.0.2.7/'+str(width)) for width in (0,1,24,31,32,33)]
        values += [('prefix6-'+str(width),'records.test,2001:db8::7/'+str(width)) for width in (0,1,63,64,65,127,128,129)]
        values += [('prefix-'+label,'records.test,192.0.2.7/'+value) for label,value in [('empty',''),('text','bad'),('negative','-1'),('wrap','4294967296')]]
        for label,value in values: add(option+'-'+label,option+'='+value+'\n','DOM-GRAM')
        for label,text in [('search','search discovered.records.test extra.test\n'),
            ('keyword','domain ignored.records.test\n'),('case','Search ignored.records.test\n'),
            ('invalid-first','search bad..name good.records.test\nsearch discovered.records.test\n'),
            ('none','nameserver 127.0.0.2\n')]:
            add(option+'-resolv-'+label,option+'=#\nresolv-file=/m2/records-resolv\n','DOM-RESOLV',
                no_resolv=False,files={'records-resolv':text})
        add(option+'-resolv-no-resolv',option+'=#\n','DOM-RESOLV')
        add(option+'-resolv-missing',option+'=#\nresolv-file=/m2/missing\n','DOM-RESOLV',no_resolv=False)
        add(option+'-resolv-literal-fallback',option+'=literal.records.test\n'+option+'=#\nresolv-file=/m2/records-resolv\n',
            'DOM-RESOLV',no_resolv=False,files={'records-resolv':'nameserver 127.0.0.2\n'})
        for label,text in [('latch-later-literal',option+'=#\n'+option+'=literal.records.test\n'),
            ('literal-then-latch',option+'=literal.records.test\n'+option+'=#\n')]:
            add(option+'-resolv-'+label,text+'resolv-file=/m2/records-resolv\n','DOM-RESOLV',
                no_resolv=False,files={'records-resolv':'search chosen.records.test\n'})
        for label,text in [('empty-search','search\n'),('quoted','search "chosen.records.test" second.records.test\n'),
            ('comment','search #comment ignored.records.test\n'),('partial-last','search chosen.records.test'),
            ('invalid-only','search bad..name ignored.records.test\n'),('whitespace',' \tsearch\tchosen.records.test\r\n')]:
            add(option+'-resolv-'+label,option+'=#\nresolv-file=/m2/records-resolv\n','DOM-RESOLV',
                no_resolv=False,files={'records-resolv':text})
        add(option+'-resolv-multiple',option+'=#\nresolv-file=/m2/records-resolv\nresolv-file=/m2/second-resolv\n',
            'DOM-RESOLV',no_resolv=False,files={'records-resolv':'search chosen.records.test\n','second-resolv':'search second.records.test\n'})
        add(option+'-resolv-port-zero',option+'=#\nport=0\nresolv-file=/m2/records-resolv\n',
            'DOM-RESOLV',no_resolv=False,files={'records-resolv':'search chosen.records.test\n'})
        for fault in ('open-denied','read-empty-eio','read-partial-eio'):
            add(option+'-resolv-'+fault,option+'=#\nresolv-file=/m2/records-resolv\n',
                'DOM-RESOLV',no_resolv=False,files={'records-resolv':'search chosen.records.test'},resolver_fault=fault)
        add(option+'-resolv-fifo',option+'=#\nresolv-file=/m2/records-resolv\n','DOM-RESOLV',
            no_resolv=False,files={'records-resolv':''},resolver_fifo=True)
        for label,value in [('interface15','abcdefghijklmno'),('interface16','abcdefghijklmnop'),
            ('interface-long','abcdefghijklmnopqrstuv'),('wildcard','m5ir*'),('quoted-selector','"m5ir0,ignored"')]:
            add(option+'-'+label,option+'=chosen.records.test,'+value+'\n','DOM-GRAM')
        add(option+'-default-repeated',option+'=first.records.test\n'+option+'=second.records.test\n','DOM-GRAM')
    add('domain-short-alias','', 'DOM-GRAM',argv=['-s','chosen.records.test'])
    values=[('missing-range','records.test'),('empty',''),('interface','records.test,m5ir0'),
        ('single4','records.test,192.0.2.7'),('range4','records.test,192.0.2.7,192.0.2.9'),
        ('inverted4','records.test,192.0.2.9,192.0.2.7'),
        ('single6','records.test,2001:db8::7'),('range6','records.test,2001:db8::7,2001:db8::9'),
        ('prefix4','records.test,192.0.2.7/24,prefix'),
        ('index4','records.test,192.0.2.7,192.0.2.9,prefix*'),
        ('prefix6','records.test,2001:db8::7/64,prefix'),
        ('index6','records.test,2001:db8::7/64,prefix*'),
        ('index6-small','records.test,2001:db8::7/63,prefix*'),
        ('index6-range','records.test,2001:db8::7,2001:db8::9,prefix*'),
        ('extra','records.test,192.0.2.7,192.0.2.9,prefix,ignored')]
    for width in (24,25):values.append(('cidr4-limit'+str(width),'records.test,192.0.2.7/24,'+'p'*width))
    for width in (17,18):values.append(('cidr6-limit'+str(width),'records.test,2001:db8::7/64,'+'p'*width))
    for width in (47,48):values.append(('range-limit'+str(width),'records.test,192.0.2.7,192.0.2.9,'+'p'*width))
    for label,value in values:add('synth-'+label,'synth-domain='+value+'\n','SYN-GRAM')
    for label,value in [('root',',192.0.2.7,192.0.2.9'),('quoted','"records.test,192.0.2.7,192.0.2.9"'),
        ('quoted-range','records.test,"192.0.2.7/24,p"'),('quoted-star','records.test,192.0.2.7,192.0.2.9,"p*"'),
        ('embedded-star','records.test,192.0.2.7,192.0.2.9,p*x'),('double-star','records.test,192.0.2.7,192.0.2.9,p**'),
        ('empty-prefix','records.test,192.0.2.7,192.0.2.9,'),('case','RECORDS.TEST.,192.0.2.7,192.0.2.9,P*')]:
        add('synth-'+label,'synth-domain='+value+'\n','SYN-GRAM')
    for family,address,widths in [(4,'192.0.2.7',(0,1,24,31,32,33)),(6,'2001:db8::7',(0,1,63,64,65,127,128,129))]:
        for width in widths:
            add('synth-width-'+str(family)+'-'+str(width),'synth-domain=records.test,'+address+'/'+str(width)+'\n','SYN-GRAM')
    for label,value in [('empty',''),('text','bad'),('negative','-1'),('wrap','4294967296'),('int-overflow','4294967295')]:
        add('synth-width-'+label,'synth-domain=records.test,192.0.2.7/'+value+'\n','SYN-GRAM')
    for label,value in [('ordinary','/m2/hosts-dir'),('relative','hosts-dir'),('empty',''),('quoted','"/m2/hosts dir"'),('duplicate','/m2/hosts-dir\nhostsdir=/m2/hosts-dir')]:
        add('hostsdir-'+label,'hostsdir='+value+'\n','HDIR-GRAM')
    return cases


def service_cases():
    cases=[]
    primary={'name':'m5ir0','addresses':['198.18.91.9/24','2001:db8:91::9/64','fe80::9/64']}
    def probes(names):
        return [files.probe('q'+str(i),name,type=kind) for i,(name,kind) in enumerate(names)]
    def add(ident,config,names,checks,**extra):
        actions=extra.pop('actions',probes(names))
        cases.append(dict(id=ident,config='no-resolv\nserver=127.0.0.2\n'+config,checks=checks.split(),
            files=extra.pop('files',{}),sys_files={},default_resolv=extra.pop('default_resolv',False),strict_order=True,
            no_upstream=True,negative_names=extra.pop('negative_names',[a['name'] for a in actions if a.get('op')=='query']),actions=actions,**extra))
    targets=[('address','m5ir0'),('family4','m5ir0/4'),('family6','m5ir0/6'),('missing','missing_ir'),('wildcard','m5ir*')]
    for label,target in targets:
        add('interface-'+label,'interface-name=iface.records.test,'+target+'\n',
            [('iface.records.test',1),('iface.records.test',28),('iface.records.test',255),
             ('iface.records.test',16),('records.test',1),('child.iface.records.test',1),
             (ipaddress.ip_address('198.18.91.9').reverse_pointer,12),
             (ipaddress.ip_address('2001:db8:91::9').reverse_pointer,12),
             (ipaddress.ip_address('fe80::9').reverse_pointer,12)],
            'IF-ENUM IF-FWD IF-PTR IF-EXIST IF-FLAGS',topology=[primary])
    for width in (0,1,16,24,31,32):
        source=ipaddress.ip_address('198.18.91.9');prototype=ipaddress.ip_address('1.2.3.7')
        mask=((1<<32)-1)^((1<<(32-width))-1) if width else 0
        composed=ipaddress.ip_address((int(source)&mask)|(int(prototype)&~mask&((1<<32)-1)))
        add('dynamic-v4-prefix-'+str(width),'dynamic-host=proto.records.test,1.2.3.7,m5ir0\n',
            [('proto.records.test',1),('proto.records.test',28),(composed.reverse_pointer,12)],
            'DH-COMPOSE IF-PTR',topology=[{'name':'m5ir0','addresses':[str(source)+'/'+str(width)]}])
    for width in (0,1,63,64,65,127,128):
        source=ipaddress.ip_address('2001:db8:91:1000::9');prototype=ipaddress.ip_address('fdaa:bbbb:cccc:dddd:eeee:ffff:1234:7')
        mask=((1<<128)-1)^((1<<(128-width))-1) if width else 0
        composed=ipaddress.ip_address((int(source)&mask)|(int(prototype)&~mask&((1<<128)-1)))
        add('dynamic-v6-prefix-'+str(width),'dynamic-host=proto.records.test,'+str(prototype)+',m5ir0\n',
            [('proto.records.test',28),('proto.records.test',1),(composed.reverse_pointer,12)],
            'DH-COMPOSE IF-PTR',topology=[{'name':'m5ir0','addresses':[str(source)+'/'+str(width)]}])
    add('interface-root-name','interface-name=,m5ir0\n',[('',1),('',28),('9.91.18.198.in-addr.arpa',12)],'IF-GRAM IF-EXIST',topology=[primary])
    add('interface-without-address','interface-name=iface.records.test,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28),('records.test',16)],'IF-ENUM IF-EXIST',topology=[{'name':'m5ir0','addresses':[]}])
    add('interface-host-precedence','interface-name=iface.records.test,m5ir0\nhost-record=iface.records.test,192.0.2.99,2001:db8:ffff::99\n',
        [('iface.records.test',1),('iface.records.test',28),('iface.records.test',255)],'IF-FWD',topology=[primary])
    add('interface-empty-host-interception','interface-name=iface.records.test,missing_ir\nhost-record=iface.records.test,192.0.2.99,2001:db8:ffff::99\n',
        [('iface.records.test',1),('iface.records.test',28)],'IF-FWD IF-EXIST')
    add('interface-two-declarations','interface-name=iface.records.test,m5ir0\ninterface-name=iface.records.test,m5ir1\n',
        [('iface.records.test',1),('iface.records.test',28),('iface.records.test',255)],'IF-ENUM IF-FWD',
        topology=[primary,{'name':'m5ir1','addresses':['198.18.92.9/24','2001:db8:92::9/64']}])
    add('interface-ptr-precedence','interface-name=first.records.test,m5ir0\ninterface-name=second.records.test,m5ir0\n'
        'ptr-record=9.91.18.198.in-addr.arpa,explicit.records.test\nhost-record=host.records.test,198.18.91.9\n',
        [('9.91.18.198.in-addr.arpa',12),('first.records.test',1),('second.records.test',1)],'IF-PTR',topology=[primary])
    for label,middle in [('adjacent',''),('separated','interface-name=middle.records.test,missing_ir\n')]:
        add('interface-ptr-family-'+label,'interface-name=first.records.test,m5ir0/6\n'+middle+
            'interface-name=second.records.test,m5ir0/4\n', [('9.91.18.198.in-addr.arpa',12)],'IF-PTR',topology=[primary])
    add('interface-cname','interface-name=iface.records.test,m5ir0\ncname=alias.records.test,iface.records.test\n',
        [('alias.records.test',1),('alias.records.test',28)],'IF-FWD',topology=[primary])
    add('interface-cache-bypass-empty','interface-name=empty.records.test,missing_ir\n',
        [('empty.records.test',1),('empty.records.test',1)],'IF-FWD IF-EXIST',cache_size=16)
    for option in ('domain','domain-suffix'):
        for label,selector in [('prefix4','192.0.2.7/24'),('prefix4zero','192.0.2.7/0'),
            ('range4','192.0.2.7,192.0.2.9'),('single6','2001:db8::7'),
            ('range6','2001:db8::7,2001:db8::9'),('prefix6','2001:db8::7/64'),('interface','m5ir0')]:
            add(option+'-'+label,option+'=chosen.records.test,'+selector+'\n'+option+'=fallback.records.test\n'
                'expand-hosts\naddn-hosts=/m2/files/hosts\n',
                [('v4.chosen.records.test',1),('v4.fallback.records.test',1),
                 ('v6.chosen.records.test',28),('v6.fallback.records.test',28),
                 ('outside.chosen.records.test',28),('outside.fallback.records.test',28)],
                'DOM4 DOM6 DOM-IF DOM-CALLER',topology=[primary],
                files={'hosts':'192.0.2.7 v4\n2001:db8::7 v6\n2001:db8:ffff::7 outside\n'})
    def domain_hosts(ident,config,addresses,**extra):
        names=[];text=''
        for index,address in enumerate(addresses):
            host='host'+str(index);kind=1 if ipaddress.ip_address(address).version==4 else 28
            text+=address+' '+host+'\n'
            for suffix in ('chosen.records.test','second.records.test','fallback.records.test'):
                names.append((host+'.'+suffix,kind))
        add(ident,config+'expand-hosts\naddn-hosts=/m2/files/hosts\n',names,
            'DOM4 DOM6 DOM-IF DOM-CALLER',files={'hosts':text},**extra)
    for option in ('domain','domain-suffix'):
        fallback=option+'=fallback.records.test\n'
        domain_hosts(option+'-default-last',option+'=chosen.records.test\n'+fallback,
            ['192.0.2.7','2001:db8::7'])
        domain_hosts(option+'-search-latch-later-literal',option+'=#\n'+fallback+'resolv-file=/m2/files/domain-resolv\n',
            ['192.0.2.7','2001:db8::7'])
        cases[-1]['config']=cases[-1]['config'].replace('no-resolv\n','')
        cases[-1]['files']['domain-resolv']='search chosen.records.test\n'
        v4=['192.0.2.6','192.0.2.7','192.0.2.8','192.0.2.9','192.0.2.10','198.51.100.7']
        for label,selector in [('single4','192.0.2.7'),('range4','192.0.2.7,192.0.2.9'),
            ('inverted4','192.0.2.9,192.0.2.7'),('empty-selector','')]:
            domain_hosts(option+'-bounds-'+label,fallback+option+'=chosen.records.test,'+selector+'\n',
                v4+(['0.0.0.0'] if not selector else []))
        for width in (0,1,24,31,32):
            domain_hosts(option+'-bounds-prefix4-'+str(width),fallback+option+'=chosen.records.test,192.0.2.7/'+str(width)+'\n',v4)
        domain_hosts(option+'-overlap4',fallback+option+'=chosen.records.test,192.0.2.7,192.0.2.9\n'+
            option+'=second.records.test,192.0.2.8,192.0.2.10\n',v4)
        v6=['2001:db8::6','2001:db8::7','2001:db8::8','2001:db8::9','2001:db8::a','2001:db8:ffff::7','fd00::7']
        for width in (0,1,63,64,65,127,128):
            domain_hosts(option+'-bounds-prefix6-'+str(width),fallback+option+'=chosen.records.test,2001:db8::7/'+str(width)+'\n',v6)
        for label,selector in [('single6','2001:db8::7'),('range6','2001:db8::7,2001:db8::9'),
            ('inverted6','2001:db8::9,2001:db8::7'),('cross6','2001:db8::7,2001:db8:ffff::9')]:
            domain_hosts(option+'-bounds-'+label,fallback+option+'=chosen.records.test,'+selector+'\n',v6)
        domain_hosts(option+'-overlap6',fallback+option+'=chosen.records.test,2001:db8::7/64\n'+
            option+'=second.records.test,2001:db8::8/127\n',v6)
        inside=['198.18.91.77','198.18.92.77','2001:db8:91::77','2001:db8:92::77','fe80::77']
        for label,selector,topology in [('interface','m5ir0',[primary]),('wildcard','m5ir*',[primary]),
            ('missing','missing_ir',[primary]),('empty','m5ir0',[{'name':'m5ir0','addresses':[]}]),
            ('down','m5ir0',[primary]),
            ('unselected','m5ir0',[primary])]:
            domain_hosts(option+'-inside-'+label,fallback+option+'=chosen.records.test,'+selector+'\n'+
                ('interface=lo\n' if label=='unselected' else ''),inside,topology=topology)
            if label=='down':cases[-1]['initial_kernel_commands']=[['ip','link','set','m5ir0','down']]
        domain_hosts(option+'-inside-alias',fallback+option+'=chosen.records.test,m5ir0:1\n',inside,
            topology=[{'name':'m5ir0','addresses':['198.18.91.9/24']}],
            initial_kernel_commands=[['ip','addr','add','198.18.92.9/24','dev','m5ir0','label','m5ir0:1']])
        domain_hosts(option+'-inside-overlap',fallback+option+'=chosen.records.test,m5ir0\n'+
            option+'=second.records.test,m5ir1\n',inside,topology=[primary,{'name':'m5ir1','addresses':['198.18.91.10/24','2001:db8:91::10/64']}])
        for label,search in [('first','search chosen.records.test ignored.records.test\n'),
            ('case','Search ignored.records.test\nsearch chosen.records.test\n'),
            ('invalid-recover','search bad..name ignored.records.test\nsearch chosen.records.test\n'),
            ('whitespace','\t search\tchosen.records.test\r\n'),
            ('literal-nosearch','nameserver 127.0.0.2\n')]:
            prefix=fallback if label=='literal-nosearch' else ''
            domain_hosts(option+'-search-'+label,prefix+option+'=#\nresolv-file=/m2/files/domain-resolv\n',
                ['192.0.2.7','2001:db8::7'],default_resolv=False)
            cases[-1]['config']=cases[-1]['config'].replace('no-resolv\n','')
            cases[-1]['files']['domain-resolv']=search
        add(option+'-search-srv',option+'=#\nresolv-file=/m2/files/domain-resolv\nsrv-host=_svc._tcp,target.records.test,1234\n',
            [('_svc._tcp.chosen.records.test',33),('_svc._tcp',33)],'DOM-RESOLV DOM-CALLER',
            files={'domain-resolv':'search chosen.records.test\n'})
        cases[-1]['config']=cases[-1]['config'].replace('no-resolv\n','')
    for label,text in [('literal4','192.0.2.7,192.0.2.9'),('index4','192.0.2.7,192.0.2.9,p*'),
        ('literal6','2001:db8::7/64'),('explicit6','2001:db8::7,2001:db8::9'),('index6','2001:db8::7/64,p*')]:
        add('synth-'+label,'synth-domain=synthetic.records.test,'+text+'\n',
            [('192-0-2-7.synthetic.records.test',1),('192-0-2-10.synthetic.records.test',1),
             ('p0.synthetic.records.test',1),('p2.synthetic.records.test',1),('p3.synthetic.records.test',1),
             ('2001-db8--7.synthetic.records.test',28),('p7.synthetic.records.test',28),
             (ipaddress.ip_address('192.0.2.7').reverse_pointer,12),
             (ipaddress.ip_address('2001:db8::7').reverse_pointer,12),
             (ipaddress.ip_address('2001:db8:ffff::7').reverse_pointer,12)],'SYN-FWD SYN-PTR')
    add('hostsdir-basic','hostsdir=/m2/files/dir\n',
        [('directory.records.test',1),('9.91.18.198.in-addr.arpa',12)],'HDIR-INIT HDIR-EVENT',
        files={'dir/one':'198.18.91.9 directory.records.test\n'},
        actions=[files.probe('initial','directory.records.test'),files.write('dir/one','198.18.91.10 directory.records.test\n'),
            files.probe('changed','directory.records.test'),{'op':'unlink','path':'dir/one'},files.probe('removed','directory.records.test')])
    hosts_config='hostsdir=/m2/files/dir\n'
    for label,config in [('repeated',hosts_config+hosts_config),('relative','hostsdir=m2/files/dir\n'),
        ('quoted','hostsdir="/m2/files/dir"\n')]:
        add('hostsdir-'+label,config,[('one.records.test',1),('alias.records.test',1),('v6.records.test',28),
            ('7.2.0.192.in-addr.arpa',12)],'HDIR-GRAM HDIR-INIT',
            files={'dir/one':'192.0.2.7 one.records.test alias.records.test\n2001:db8::7 v6.records.test\n'})
    add('hostsdir-name-filters',hosts_config,[('visible.records.test',1),('dot.records.test',1),('tilde.records.test',1),('hash.records.test',1)],
        'HDIR-INIT HDIR-EVENT',files={'dir/one':'192.0.2.7 visible.records.test\n','dir/.hidden':'192.0.2.8 dot.records.test\n',
            'dir/backup~':'192.0.2.9 tilde.records.test\n','dir/#temp#':'192.0.2.10 hash.records.test\n'},actions=[
                files.probe('initial','visible.records.test'),files.probe('dot','dot.records.test'),files.probe('tilde','tilde.records.test'),files.probe('hash','hash.records.test'),
                files.write('dir/.hidden','192.0.2.88 dot.records.test\n'),files.probe('dot-close','dot.records.test'),
                {'op':'unlink','path':'dir/backup~'},files.probe('tilde-delete','tilde.records.test')])
    add('hostsdir-regular-only',hosts_config,[('regular.records.test',1),('symlink.records.test',1),('subdirectory.records.test',1)],
        'HDIR-INIT',files={'outside':'192.0.2.8 symlink.records.test\n','dir/one':'192.0.2.7 regular.records.test\n',
            'dir/symlink':{'symlink':'../outside'},'dir/subdirectory/nested':'192.0.2.9 subdirectory.records.test\n',
            'dir/fifo':{'initial_kind':'fifo'},'dir/socket':{'initial_kind':'socket'},'dir/device':{'initial_kind':'device'},
            'dir/dangling':{'symlink':'missing'},'dir/loop':{'symlink':'loop'}})
    add('hostsdir-identical-loser',hosts_config,[],'HDIR-SOURCE HDIR-EVENT',
        files={'dir/one':'192.0.2.7 same.records.test\n','dir/two':'192.0.2.7 same.records.test\n'},actions=[
            files.probe('initial','same.records.test'),{'op':'unlink','path':'dir/one'},files.probe('winner-removed','same.records.test'),
            files.probe('ancestor-after-remove','records.test'),files.signal_reload(),files.probe('hup-survivor','same.records.test')])
    add('hostsdir-ptr-loser',hosts_config,[],'HDIR-SOURCE HDIR-EVENT',
        files={'dir/one':'192.0.2.7 first.records.test\n','dir/two':'192.0.2.7 second.records.test\n'},actions=[
            files.probe('initial','7.2.0.192.in-addr.arpa',type=12),{'op':'unlink','path':'dir/one'},
            files.probe('loser-forward','second.records.test'),files.probe('ptr-not-promoted','7.2.0.192.in-addr.arpa',type=12),
            files.write('dir/two','192.0.2.7 second.records.test\n'),files.probe('rewrite-promotes','7.2.0.192.in-addr.arpa',type=12)])
    add('hostsdir-open-create-move',hosts_config,[],'HDIR-EVENT HDIR-SOURCE',files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[
        files.probe('initial','one.records.test'),files.write('dir/new','192.0.2.8 new.records.test\n',hold_open=True),
        files.probe('create-not-close','new.records.test'),{'op':'close-file','path':'dir/new'},files.probe('closed','new.records.test'),
        {'op':'rename','path':'dir/one','to':'away'},files.probe('moved-away-stale','one.records.test'),
        {'op':'rename','path':'away','to':'dir/moved'},files.probe('moved-in','one.records.test'),
        {'op':'unlink','path':'dir/moved'},files.probe('old-uid-remains','one.records.test'),files.signal_reload(),files.probe('hup-drops-old-uid','one.records.test')])
    add('hostsdir-atomic-stable-uid',hosts_config,[],'HDIR-EVENT HDIR-SOURCE',files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[
        files.probe('initial','one.records.test'),files.write('staged','192.0.2.8 one.records.test\n'),
        {'op':'rename','path':'staged','to':'dir/one'},
        files.probe('atomic','one.records.test'),{'op':'unlink','path':'dir/one'},files.probe('deleted','one.records.test'),
        files.write('dir/one','192.0.2.9 one.records.test\n'),files.probe('recreated','one.records.test')])
    add('hostsdir-tcp-view',hosts_config,[],'HDIR-CALLER',files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[
        dict(op='connect',id='held'),files.probe('child-old','one.records.test',transports=['held']),
        files.write('dir/one','192.0.2.8 one.records.test\n'),files.probe('parent-new','one.records.test',transports=['udp']),
        files.probe('child-stays-old','one.records.test',transports=['held']),files.probe('fresh-child','one.records.test',transports=['tcp']),
        dict(op='disconnect',id='held')])
    add('hostsdir-visible-temp-source-guard',hosts_config+'log-facility=-\n',[],'HDIR-SOURCE HDIR-EVENT',
        files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[files.probe('initial','one.records.test'),
            files.write('dir/temp-one','192.0.2.8 one.records.test\n'),
            dict(op='write',path='read-barrier',text='',hosts_read_barrier='/m2/files/dir/temp-one'),
            files.probe('temp-read-before-rename','one.records.test'),
            {'op':'rename','path':'dir/temp-one','to':'dir/one'},files.probe('target-skips-duplicate','one.records.test'),
            {'op':'unlink','path':'dir/one'},files.probe('temp-uid-retained','one.records.test'),
            files.write('dir/one','192.0.2.9 one.records.test\n'),files.probe('temp-plus-recreated','one.records.test')])
    for label,config,contents in [('missing','hostsdir=/m2/files/missing\n',{}),
        ('not-directory','hostsdir=/m2/files/plain\n',{'plain':'not a directory'}),('empty-path','hostsdir=\n',{})]:
        add('hostsdir-'+label,config+'log-facility=-\n',[('ready.files.test',1)],'HDIR-GRAM HDIR-INIT',files=contents)
    add('hostsdir-unprivileged',hosts_config+'log-facility=-\n',[('readable.records.test',1),('denied.records.test',1)],
        'HDIR-INIT',user='nobody',group='nogroup',files={'dir/readable':{'text':'192.0.2.7 readable.records.test\n','mode':0o644},
            'dir/denied':{'text':'192.0.2.8 denied.records.test\n','mode':0o600}})
    add('hostsdir-watch-denied',hosts_config+'log-facility=-\n',[('ready.files.test',1)],'HDIR-INIT',user='nobody',group='nogroup',
        files={'dir':{'initial_kind':'directory','mode':0o000}})
    add('hostsdir-opendir-denied-hup',hosts_config+'log-facility=-\n',[],'HDIR-INIT HDIR-SOURCE',user='nobody',group='nogroup',
        files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[files.probe('initial','one.records.test'),
            dict(op='write',path='directory-mode',text='',hosts_mode=0o000),files.signal_reload(),files.probe('hup-denied','one.records.test'),
            dict(op='write',path='directory-mode',text='',hosts_mode=0o755),files.signal_reload(),files.probe('hup-recovered','one.records.test')])
    add('hostsdir-port-zero',hosts_config,[],'HDIR-GRAM',dns_disabled=True,
        files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[files.write('dir/one','192.0.2.8 one.records.test\n')])
    add('hostsdir-multiple','hostsdir=/m2/files/first\nhostsdir=/m2/files/second\n',
        [('one.records.test',1),('two.records.test',1),('7.2.0.192.in-addr.arpa',12)],'HDIR-GRAM HDIR-INIT HDIR-SOURCE',
        files={'first/one':'192.0.2.7 one.records.test\n','second/two':'192.0.2.7 two.records.test\n'})
    add('hostsdir-malformed',hosts_config+'local-ttl=77\nlog-facility=-\n',
        [('good.records.test',1),('partial.records.test',28),('records.test',16)],'HDIR-INIT HDIR-SOURCE',
        files={'dir/one':'not-an-address skipped.records.test\n192.0.2.7 bad..name good.records.test\n2001:db8::8 partial.records.test'})
    add('hostsdir-coexist',hosts_config+'addn-hosts=/m2/files/additional\nhost-record=explicit.records.test,192.0.2.10\n',[],
        'HDIR-SOURCE',system_hosts=True,files={'dir/one':'192.0.2.7 directory.records.test\n','additional':'192.0.2.8 additional.records.test\n'},actions=[
            files.probe('directory','directory.records.test'),files.probe('additional','additional.records.test'),files.probe('explicit','explicit.records.test'),
            files.probe('system','system.records.test'),
            {'op':'unlink','path':'dir/one'},files.probe('directory-removed','directory.records.test'),
            files.probe('additional-retained','additional.records.test'),files.probe('explicit-retained','explicit.records.test'),files.probe('system-retained','system.records.test')])
    cases[-1]['sys_files']={'/etc/hosts':'192.0.2.11 system.records.test\n'}
    add('hostsdir-cname-expand',hosts_config+'domain=records.test\nexpand-hosts\ncname=alias.records.test,one.records.test\n',[],
        'HDIR-INIT HDIR-SOURCE',files={'dir/one':'192.0.2.7 one\n'},actions=[files.probe('initial','alias.records.test'),
            files.write('dir/one','192.0.2.8 one\n'),files.probe('changed','alias.records.test'),
            {'op':'unlink','path':'dir/one'},files.probe('removed','alias.records.test')])
    add('hostsdir-rotation',hosts_config+'local-ttl=77\n',[],'HDIR-INIT HDIR-SOURCE',round_robin=True,
        files={'dir/one':'192.0.2.7 many.records.test\n192.0.2.8 many.records.test\n2001:db8::7 many.records.test\n'},actions=[
            *[files.probe('rotation-'+str(i),'many.records.test') for i in range(4)],
            files.write('dir/one','192.0.2.9 many.records.test\n192.0.2.10 many.records.test\n'),
            *[files.probe('changed-'+str(i),'many.records.test') for i in range(3)]])
    add('hostsdir-watch-removed',hosts_config,[],'HDIR-EVENT HDIR-SOURCE',files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[
        files.probe('initial','one.records.test'),{'op':'unlink','path':'dir/one'},{'op':'rmdir','path':'dir'},
        files.write('dir/two','192.0.2.8 two.records.test\n'),files.probe('recreated-not-watched','two.records.test'),
        files.signal_reload(),files.probe('hup-scans-survivor','two.records.test'),
        files.write('dir/two','192.0.2.9 two.records.test\n'),files.probe('still-not-watched','two.records.test')])
    add('hostsdir-symlink-retarget',hosts_config,[],'HDIR-GRAM HDIR-INIT HDIR-EVENT',
        files={'real-one/one':'192.0.2.7 one.records.test\n','real-two/one':'192.0.2.8 one.records.test\n','dir':{'symlink':'real-one'}},actions=[
            files.probe('initial','one.records.test'),{'op':'symlink','path':'dir','target':'real-two'},files.probe('retarget-no-event','one.records.test'),
            files.write('real-two/one','192.0.2.9 one.records.test\n'),files.probe('new-target-unwatched','one.records.test'),
            files.write('real-one/one','192.0.2.10 one.records.test\n'),files.probe('old-watch-reads-current-path','one.records.test')])
    add('hostsdir-runtime-directory',hosts_config,[],'HDIR-EVENT',files={'dir/one':'192.0.2.7 one.records.test\n','staged-directory/item':'unused'},actions=[
        files.probe('initial','one.records.test'),{'op':'unlink','path':'dir/one'},
        {'op':'rename','path':'staged-directory','to':'dir/one'},files.probe('directory-replaces-source','one.records.test')])
    add('hostsdir-dhcp-name-effects',hosts_config+'domain=records.test\ninterface=lo\nno-ping\n'
        'dhcp-range=127.0.0.40,127.0.0.60,255.0.0.0,600\ndhcp-leasefile=/m2/files/leases\ndhcp-script=/m2/files/helper.sh\n',[],
        'HDIR-CALLER',files={'dir/one':'127.0.0.40 fromhosts.records.test\n','leases':
            '4102444800 02:00:00:00:00:01 127.0.0.40 original *\n',
            'helper.sh':{'text':'#!/bin/sh\necho "$1|$2|$3|$4" >>/m2/files/helper.log\n','mode':0o755}},actions=[
                files.probe('initial','fromhosts.records.test'),{'op':'helper-events','id':'initial-helper'},
                files.write('dir/one','127.0.0.40 updated.records.test\n'),files.probe('changed','updated.records.test'),
                {'op':'helper-events','id':'changed-helper'},{'op':'unlink','path':'dir/one'},files.probe('lease-name-retained','updated.records.test'),
                {'op':'helper-events','id':'removed-helper'}])
    for mode in ('fifo','partial-eio','shutdown'):
        add('hostsdir-runtime-'+mode,hosts_config+('log-facility=-\n' if mode!='shutdown' else ''),[],
            'HDIR-EVENT HDIR-CALLER',files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[
                files.probe('initial','one.records.test'),dict(op='write',path='hosts-stream',text='',
                    hosts_stream=mode,stream_text='192.0.2.8 one.records.test\n192.0.2.9 partial.records.test'),
                *([] if mode=='shutdown' else [files.probe('completed','one.records.test'),files.probe('partial-final','partial.records.test')])])
    add('hostsdir-runtime-emfile',hosts_config+'local=/records.test/\nlog-facility=-\n',[],'HDIR-EVENT HDIR-CALLER',
        files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[files.probe('initial','one.records.test'),
            {'op':'fd-limit','limit':'first-free'},files.write('dir/one','192.0.2.8 one.records.test\n'),
            files.probe('open-failed-source-removed','one.records.test',transports=['udp']),files.probe('owner-still-healthy','ready.files.test',transports=['udp']),
            {'op':'fd-limit','restore':True},files.write('dir/one','192.0.2.9 one.records.test\n'),files.probe('recovered','one.records.test')])
    add('hostsdir-large-owner',hosts_config+'log-facility=-\n',[],'HDIR-EVENT HDIR-CALLER',
        files={'dir/one':'192.0.2.7 one.records.test\n'},actions=[files.probe('initial','one.records.test'),
            dict(op='write',path='hosts-large',text='',hosts_large=1024*1024),files.probe('new-source','one.records.test')])
    def kernel(argv):return dict(op='write',path='kernel-action',text='',kernel_command=argv)
    def state(label):return dict(op='write',path='interface-state',text='',interface_state=label)
    v4only={'name':'m5ir0','addresses':['198.18.91.9/24']}
    for label,mask,commands in [
        ('deprecated',0x20,[['ip','-6','addr','add','2001:db8:99::9/64','dev','m5ir0','nodad','valid_lft','600','preferred_lft','0']]),
        ('temporary',0x1,[['sysctl','-q','-w','net.ipv6.conf.m5ir0.use_tempaddr=2'],
            ['ip','-6','addr','add','2001:db8:99::9/64','dev','m5ir0','mngtmpaddr','nodad','valid_lft','600','preferred_lft','300']]),
        ('tentative',0x40,[['ip','link','del','m5ir0'],['ip','link','add','m5ir0','type','veth','peer','name','m5peer0'],
            ['ip','link','set','m5ir0','up'],['ip','link','set','m5peer0','up'],
            ['sysctl','-q','-w','net.ipv6.neigh.m5ir0.retrans_time_ms=3000','net.ipv6.conf.m5ir0.dad_transmits=1'],
            ['ip','-6','addr','add','2001:db8:99::9/64','dev','m5ir0']])]:
        domain_hosts('domain-interface-flag-'+label,'domain=fallback.records.test\ndomain=chosen.records.test,m5ir0\n',
            ['2001:db8:99::77','2001:db8:98::77'],topology=[v4only],initial_kernel_commands=commands,
            initial_flag={'prefix':'2001:db8:99::/64','mask':mask})
    for label,prefix,inside,outside in [('v4','192.0.2.199/25','192.0.2.200','192.0.2.7'),
        ('v6','2001:db8::7/65','2001:db8::8','2001:db8:0:0:8000::7')]:
        add('domain-local-prefix-'+label,'domain=chosen.records.test,'+prefix+',local\n',
            [('unknown.chosen.records.test',1),(ipaddress.ip_address(inside).reverse_pointer,12),
             (ipaddress.ip_address(outside).reverse_pointer,12)],'DOM4 DOM6 DOM-CALLER')
    for option in ('domain','domain-suffix'):
        def suffix_probes(label,host='newnet'):
            return [files.probe(label+'-'+suffix,host+'.'+suffix+'.records.test',type=28 if host=='new6' else 1,transports=['udp'])
                for suffix in ('chosen','fallback')]
        base_domain=option+'=fallback.records.test\n'+option+'=chosen.records.test,m5ir0\nexpand-hosts\naddn-hosts=/m2/files/hosts\n'
        contents='198.18.92.77 newnet\n2001:db8:92::77 new6\n'
        add(option+'-interface-publication',base_domain,[],'DOM-IF DOM-CALLER',topology=[primary],files={'hosts':contents},actions=[
            *suffix_probes('initial'),kernel(['ip','addr','add','198.18.92.9/24','dev','m5ir0']),
            kernel(['ip','-6','addr','add','2001:db8:92::9/64','dev','m5ir0','nodad']),state('added-subnets'),
            files.probe('unknown','unknown.records.test',transports=['udp']),files.signal_reload(),*suffix_probes('hup-old'),
            dict(op='connect',id='enumerator'),files.probe('tcp-enum','ready.files.test',transports=['enumerator']),
            dict(op='disconnect',id='enumerator'),*suffix_probes('old-host-generation'),files.signal_reload(),
            *suffix_probes('reread'),*suffix_probes('reread6','new6')])
        add(option+'-hostsdir-current-publication',base_domain.replace('addn-hosts=/m2/files/hosts','hostsdir=/m2/files/dir'),[],
            'DOM-IF DOM-CALLER',topology=[primary],files={'dir/one':'198.18.92.77 newnet\n'},actions=[
                *suffix_probes('initial'),kernel(['ip','addr','add','198.18.92.9/24','dev','m5ir0']),
                files.write('dir/one','198.18.92.77 newnet\n'),*suffix_probes('old-published-domain'),
                dict(op='connect',id='enumerator'),files.probe('enum','ready.files.test',transports=['enumerator']),
                dict(op='disconnect',id='enumerator'),*suffix_probes('retained-host-generation'),
                files.write('dir/one','198.18.92.77 newnet\n'),*suffix_probes('current-domain-read')])
        add(option+'-resolver-no-reread',option+'=#\nresolv-file=/m2/files/domain-resolv\nexpand-hosts\naddn-hosts=/m2/files/hosts\n',[],
            'DOM-RESOLV DOM-CALLER',files={'domain-resolv':'search chosen.records.test\n','hosts':'192.0.2.7 short\n'},actions=[
                files.probe('initial','short.chosen.records.test'),files.write('domain-resolv','search second.records.test\n'),
                files.probe('notify-old','short.chosen.records.test'),files.signal_reload(),
                files.probe('hup-old','short.chosen.records.test'),files.probe('new-search-not-used','short.second.records.test')])
        cases[-1]['config']=cases[-1]['config'].replace('no-resolv\n','')
        add(option+'-startup-lease-interface',base_domain+'no-ping\ndhcp-range=198.18.91.2,198.18.91.100,255.255.255.0,600\n'
            'dhcp-leasefile=/m2/files/leases\n',
            [('leased.chosen.records.test',1),('leased.fallback.records.test',1),('20.91.18.198.in-addr.arpa',12)],
            'DOM-CALLER',topology=[primary],files={'hosts':'198.18.91.77 local\n','leases':'4102444800 02:00:00:91:00:20 198.18.91.20 leased *\n'})
        lease_config=option+'=fallback.records.test\n'+option+'=chosen.records.test,lo\ninterface=lo\nno-ping\n'
        lease_config+='dhcp-range=127.0.0.40,127.0.0.60,255.0.0.0,600\ndhcp-leasefile=/m2/files/leases\n'
        for disabled in (False,True):
            add(option+'-new-lease-'+('port0' if disabled else 'dns'),lease_config,[],
                'DOM-CALLER',dns_disabled=disabled,files={'leases':''},actions=[
                    dict(op='write',path='domain-dhcp',text='',domain_dhcp={'label':'first','hostname':'client','domain':'chosen.records.test'}),
                    dict(op='write',path='domain-dhcp',text='',domain_dhcp={'label':'changed','hostname':'changed','domain':'chosen.records.test'}),
                    *([] if disabled else [files.probe('first-old','client.chosen.records.test'),files.probe('new-name','changed.chosen.records.test'),
                        files.probe('reverse','40.0.0.127.in-addr.arpa',type=12)])])
    def mutation_probes(label,address):return [files.probe(label+'-aaaa','iface.records.test',type=28),files.probe(label+'-ptr',ipaddress.ip_address(address).reverse_pointer,type=12)]
    add('interface-flag-deprecated','interface-name=iface.records.test,m5ir0\n',[],
        'IF-FLAGS',topology=[v4only],actions=[kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0','nodad','valid_lft','600','preferred_lft','0']),state('deprecated'),*mutation_probes('deprecated','2001:db8:91::9')])
    privacy=[kernel(['sysctl','-q','-w','net.ipv6.conf.m5ir0.use_tempaddr=2']),
        kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0','mngtmpaddr','nodad','valid_lft','600','preferred_lft','300']),
        state('privacy')]
    add('interface-flag-temporary','interface-name=iface.records.test,m5ir0\n',[],
        'IF-FLAGS IF-PTR',topology=[v4only],actions=[*privacy,*mutation_probes('public','2001:db8:91::9'),files.probe('temporary-ptr','temporary-placeholder.records.test',type=12,temporary_ptr=True)])
    add('dynamic-privacy-duplicate','dynamic-host=iface.records.test,2001:db8::7,m5ir0\n',[],
        'DH-COMPOSE IF-FLAGS',topology=[v4only],actions=[*privacy,*mutation_probes('duplicate','2001:db8:91::7')])
    dad=[kernel(['ip','link','del','m5ir0']),kernel(['ip','link','add','m5ir0','type','veth','peer','name','m5peer0']),
        kernel(['ip','link','set','m5ir0','up']),kernel(['ip','link','set','m5peer0','up']),
        kernel(['sysctl','-q','-w','net.ipv6.neigh.m5ir0.retrans_time_ms=3000','net.ipv6.conf.m5ir0.dad_transmits=1']),
        kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0']),state('tentative')]
    add('interface-flag-dad-completion','interface-name=iface.records.test,m5ir0\n',[],
        'IF-FLAGS IF-CALLER',topology=[v4only],actions=[*dad,*mutation_probes('tentative','2001:db8:91::9'),
            dict(op='write',path='kernel-state',text='',kernel_wait={'address':'2001:db8:91::9','mask':0x40,'set':False}),
            state('completed'),*mutation_probes('completed','2001:db8:91::9')])
    add('interface-udp-ptr-refresh','interface-name=iface.records.test,m5ir0\n',[],
        'IF-CALLER IF-PTR',topology=[primary],actions=[files.probe('before','iface.records.test'),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),state('added'),
            files.probe('ptr-before-forward','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('forward-refresh','iface.records.test',transports=['udp']),
            files.probe('ptr-after-forward','10.91.18.198.in-addr.arpa',type=12,transports=['udp'])])
    add('interface-tcp-inherited','interface-name=iface.records.test,m5ir0\n',[],
        'IF-CALLER',topology=[primary],actions=[dict(op='connect',id='held'),files.probe('child-before','iface.records.test',transports=['held']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),state('added'),
            files.probe('parent-after','iface.records.test',transports=['udp']),files.probe('child-after','iface.records.test',transports=['held']),
            files.probe('fresh','iface.records.test',transports=['tcp']),dict(op='disconnect',id='held')])
    # Every profile below reaches a named source boundary; mappings stay open
    # until the exact C observations and paired candidate evidence are present.
    full=[('iface.records.test',1),('iface.records.test',28),('iface.records.test',255),
          ('9.91.18.198.in-addr.arpa',12),(ipaddress.ip_address('2001:db8:91::9').reverse_pointer,12)]
    for label,config in [('excluded','except-interface=m5ir0\n'),('unselected','interface=lo\n'),('bound','bind-interfaces\n')]:
        add('interface-enum-'+label,'interface-name=iface.records.test,m5ir0\n'+config,full,'IF-ENUM',topology=[primary])
    add('interface-down','interface-name=iface.records.test,m5ir0\n',[],'IF-ENUM',topology=[primary],
        actions=[kernel(['ip','link','set','m5ir0','down']),state('down'),*probes(full)])
    for label,target in [('real','m5ir0'),('alias','m5ir0:1')]:
        add('interface-label-'+label,'interface-name=iface.records.test,'+target+'\n',[],'IF-ENUM',topology=[primary],
            actions=[kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0','label','m5ir0:1']),state('labelled'),
                     *probes([('iface.records.test',1),('9.91.18.198.in-addr.arpa',12),('10.91.18.198.in-addr.arpa',12)])])
    for width in (15,16,23):
        add('interface-exact-target-'+str(width),'interface-name=iface.records.test,'+'abcdefghijklmno'[:width]+('pqrstuvw'[:width-15] if width>15 else '')+'\n',
            [('iface.records.test',1)],'IF-GRAM IF-ENUM',topology=[{'name':'abcdefghijklmno','addresses':['198.18.91.9/24']}])
    add('interface-enum-many','interface-name=iface.records.test,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28),('iface.records.test',255)],'IF-ENUM IF-FWD',
        topology=[{'name':'m5ir0','addresses':['198.18.91.9/24','198.18.91.10/24','2001:db8:91::9/64','2001:db8:91::10/64']}])
    for ttl in (0,77):
        add('interface-ttl-'+str(ttl),'interface-name=iface.records.test,m5ir0\nlocal-ttl='+str(ttl)+'\n',full,'IF-FWD',topology=[primary])
    bit_probes=[files.probe('kind'+str(kind)+'-class'+str(cls)+'-rd'+str(rd)+'-do'+str(dnssec)+'-cd'+str(cd),
            'iface.records.test',type=kind,**{'class':cls,'query_flags':256 if rd else 0,'do':dnssec,'cd':cd})
        for kind in (1,28,255,16) for cls,rd,dnssec,cd in ((1,False,False,False),(1,True,True,True),(255,True,False,False),(3,True,False,False))]
    add('interface-wire-bits','interface-name=iface.records.test,m5ir0\n',[],'IF-FWD',topology=[primary],actions=bit_probes)
    add('interface-truncation','interface-name=iface.records.test,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28),('iface.records.test',255)],'IF-FWD',
        topology=[{'name':'m5ir0','addresses':['198.18.91.'+str(i)+'/24' for i in range(1,90)]+['2001:db8:91::'+str(i)+'/64' for i in range(1,60)]}])
    for label,tail in [('chain','cname=a.records.test,b.records.test\ncname=b.records.test,iface.records.test\n'),
                       ('loop','cname=a.records.test,b.records.test\ncname=b.records.test,a.records.test\n')]:
        add('interface-cname-'+label,'interface-name=iface.records.test,m5ir0\n'+tail,[('a.records.test',1),('a.records.test',28)],'IF-FWD',topology=[primary])
    add('interface-existence','interface-name=IFACE.RECORDS.TEST.,missing_ir\n',
        [('iface.records.test',1),('IFACE.RECORDS.TEST',28),('records.test',16),('test',1),('',16),
         ('child.iface.records.test',1),('notrecords.test',1),('other.test',1),('ace.records.test',1)],'IF-EXIST')
    add('interface-dotless','interface-name=short,missing_ir\ndomain-needed\n',[('short',1),('unknown',1)],'IF-EXIST')
    add('interface-loopback','interface-name=iface.records.test,lo\n',
        [('iface.records.test',1),('iface.records.test',28),('1.0.0.127.in-addr.arpa',12),
         (ipaddress.ip_address('::1').reverse_pointer,12)],'IF-FLAGS')
    multi={'name':'m5ir0','addresses':['198.18.91.9/24','198.18.92.9/24','2001:db8:91::9/64','fd91::9/64']}
    local_actions=[files.probe('same4','iface.records.test',destination='198.18.91.9'),
                   files.probe('absent4','iface.records.test',destination='127.0.0.1'),
                   files.probe('same6','iface.records.test',type=28,destination='198.18.91.9')]
    add('interface-localisation','interface-name=iface.records.test,m5ir0\nlocalise-queries\n',[],'IF-FWD',
        topology=[multi],listen=None,actions=local_actions)
    add('dynamic-multi-subnets','dynamic-host=iface.records.test,192.0.2.7,2001:db8::7,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28),('7.91.18.198.in-addr.arpa',12),
         ('7.92.18.198.in-addr.arpa',12),(ipaddress.ip_address('fd91::7').reverse_pointer,12)],'DH-COMPOSE',topology=[multi])
    add('dynamic-last-prototype','dynamic-host=iface.records.test,192.0.2.7,192.0.2.8,2001:db8::7,2001:db8::8,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28),('8.91.18.198.in-addr.arpa',12)],'DH-COMPOSE IF-GRAM',topology=[primary])
    add('dynamic-two-declarations','dynamic-host=iface.records.test,192.0.2.7,m5ir0\ndynamic-host=iface.records.test,192.0.2.8,m5ir1\n',
        [('iface.records.test',1),('7.91.18.198.in-addr.arpa',12),('8.92.18.198.in-addr.arpa',12)],'DH-COMPOSE',
        topology=[primary,{'name':'m5ir1','addresses':['198.18.92.9/24']}])
    add('dynamic-missing','dynamic-host=iface.records.test,192.0.2.7,2001:db8::7,missing_ir\n',
        [('iface.records.test',1),('iface.records.test',28),('records.test',16)],'DH-COMPOSE IF-EXIST')
    add('dynamic-wrong-family','dynamic-host=iface.records.test,2001:db8::7,m5ir0\n',
        [('iface.records.test',1),('iface.records.test',28)],'DH-COMPOSE',topology=[v4only])
    add('dynamic-down','dynamic-host=iface.records.test,192.0.2.7,m5ir0\n',[],'DH-COMPOSE',topology=[v4only],
        actions=[kernel(['ip','link','set','m5ir0','down']),state('down'),files.probe('down','iface.records.test')])
    add('dynamic-ptr-prototype-skip','dynamic-host=first.records.test,2001:db8::7,m5ir0\ndynamic-host=second.records.test,192.0.2.7,m5ir0\n',
        [('7.91.18.198.in-addr.arpa',12),(ipaddress.ip_address('2001:db8:91::7').reverse_pointer,12)],'IF-PTR',topology=[primary])
    add('dynamic-ptr-overlap','dynamic-host=first.records.test,192.0.2.7,m5ir0\ndynamic-host=second.records.test,192.0.2.7,m5ir0\n',
        [('7.91.18.198.in-addr.arpa',12)],'IF-PTR DH-COMPOSE',topology=[primary])
    add('interface-ptr-any','interface-name=iface.records.test,m5ir0\n',
        [('9.91.18.198.in-addr.arpa',255),(ipaddress.ip_address('2001:db8:91::9').reverse_pointer,255),
         ('1.2.in-addr.arpa',12),('999.91.18.198.in-addr.arpa',12),('wrong.in-addr.arpa',12),
         ('unrelated.records.test',12)],'IF-PTR',topology=[primary])
    for label,config in [('ordinary',''),('bind-dynamic','bind-dynamic\n'),('local-service-net','local-service=net\n'),
                         ('local-service-host','local-service=host\n'),('acl-disables','local-service=net\ninterface=lo\n')]:
        actions=[files.probe('initial','iface.records.test',transports=['udp']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),state('added'),
            files.probe('unknown-name','unrelated.records.test',transports=['udp']),
            files.probe('unknown-type','iface.records.test',type=16,transports=['udp']),
            files.probe('before-hup','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),files.signal_reload(),
            files.probe('after-hup','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('refresh','iface.records.test',transports=['udp']),
            files.probe('after-forward','10.91.18.198.in-addr.arpa',type=12,transports=['udp'])]
        add('interface-caller-'+label,'interface-name=iface.records.test,m5ir0\n'+config,[],'IF-CALLER',
            topology=[primary],listen=None if label=='local-service-net' else '127.0.0.1',actions=actions)
    add('interface-caller-server-file','interface-name=iface.records.test,m5ir0\nservers-file=/m2/files/servers\n',[],
        'IF-CALLER',topology=[primary],files={'servers':'server=127.0.0.2\n'},actions=[
            files.probe('initial','iface.records.test',transports=['udp']),kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),
            files.write('servers','server=127.0.0.3\n'),files.signal_reload(),
            files.probe('after-file','10.91.18.198.in-addr.arpa',type=12,transports=['udp'])])
    add('interface-tcp-removed-cname','interface-name=iface.records.test,m5ir0\ncname=alias.records.test,iface.records.test\n',[],
        'IF-CALLER IF-FWD',topology=[primary],actions=[dict(op='connect',id='held'),
            files.probe('child-before','alias.records.test',transports=['held']),kernel(['ip','addr','del','198.18.91.9/24','dev','m5ir0']),
            files.probe('parent','iface.records.test',transports=['udp']),files.probe('child-after','alias.records.test',transports=['held']),
            files.probe('new-child','alias.records.test',transports=['tcp']),dict(op='disconnect',id='held')])
    add('interface-recreate','interface-name=iface.records.test,m5ir0\n',[],'IF-ENUM',topology=[primary],actions=[
        files.probe('before','iface.records.test'),kernel(['ip','link','del','m5ir0']),files.probe('removed','iface.records.test'),
        kernel(['ip','link','add','m5ir0','type','dummy']),kernel(['ip','link','set','m5ir0','up']),
        kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),state('recreated'),files.probe('recreated','iface.records.test')])
    add('interface-expiry','interface-name=iface.records.test,m5ir0\n',[],'IF-FLAGS',topology=[v4only],actions=[
        kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0','nodad','valid_lft','2','preferred_lft','1']),
        state('valid'),*mutation_probes('valid','2001:db8:91::9'),dict(op='pause',seconds=2.2),state('expired'),
        *mutation_probes('expired','2001:db8:91::9')])
    add('interface-flag-optimistic','interface-name=iface.records.test,m5ir0\n',[],'IF-FLAGS',topology=[v4only],actions=[
        *dad[:-1],kernel(['ip','-6','addr','change','2001:db8:91::9/64','dev','m5ir0','optimistic']),state('optimistic'),
        *mutation_probes('optimistic','2001:db8:91::9')])
    failed_dad=[*dad[:5],kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5peer0','nodad']),
                kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0']),
                dict(op='write',path='dad-failure',text='',kernel_wait={'address':'2001:db8:91::9','mask':0x08,'set':True}),state('dadfailed')]
    add('interface-flag-dad-failure','interface-name=iface.records.test,m5ir0\n',[],'IF-FLAGS',topology=[v4only],
        actions=[*failed_dad,*mutation_probes('failed','2001:db8:91::9')])
    combined=[*dad[:5],kernel(['sysctl','-q','-w','net.ipv6.conf.m5ir0.use_tempaddr=2']),
        kernel(['ip','-6','addr','add','2001:db8:91::9/64','dev','m5ir0','mngtmpaddr','nodad','valid_lft','600','preferred_lft','300']),
        dict(op='write',path='temporary-flags',text='',kernel_temporary={'mask':0x41,'preferred_lft':0}),state('combined')]
    add('interface-flag-combined','interface-name=iface.records.test,m5ir0\n',[],'IF-FLAGS',topology=[v4only],
        actions=[*combined,files.probe('forward','iface.records.test',type=28),files.probe('temporary-ptr','placeholder.test',type=12,temporary_ptr=True)])
    add('dynamic-privacy-order','dynamic-host=iface.records.test,2001:db8::7,m5ir0\n',[],'DH-COMPOSE IF-FLAGS',topology=[v4only],
        actions=[*privacy,files.probe('privacy-first','iface.records.test',type=28),
            kernel(['ip','-6','addr','add','2001:db8:91::10/64','dev','m5ir0','nodad']),state('permanent-first'),
            files.probe('permanent-first','iface.records.test',type=28),(files.probe('derived-ptr',ipaddress.ip_address('2001:db8:91::7').reverse_pointer,type=12))])
    add('dynamic-alias','dynamic-host=iface.records.test,192.0.2.7,m5ir0:1\n',[],'DH-COMPOSE IF-ENUM',topology=[v4only],
        actions=[kernel(['ip','addr','add','198.18.92.9/24','dev','m5ir0','label','m5ir0:1']),state('alias'),
            files.probe('forward','iface.records.test'),files.probe('reverse','7.92.18.198.in-addr.arpa',type=12)])
    add('interface-lease-priority','interface-name=iface.records.test,m5ir0\ndomain=records.test\nno-ping\n'
        'dhcp-range=198.18.91.2,198.18.91.100,255.255.255.0,600\ndhcp-leasefile=/m2/files/leases\n',
        [('9.91.18.198.in-addr.arpa',12),('lease.records.test',1),('iface.records.test',1)],'IF-PTR IF-CALLER',topology=[v4only],
        files={'leases':'4102444800 02:00:00:91:00:09 198.18.91.9 lease *\n'})
    add('interface-cache-positive-empty','interface-name=iface.records.test,missing_ir\n',
        [('iface.records.test',1),('iface.records.test',1)],'IF-FWD',cache_size=16,negative_names=[])
    add('interface-ptr-cache-priority','interface-name=iface.records.test,m5ir0\ncache-rr=PTR\n',[],'IF-PTR IF-FWD',
        topology=[v4only],cache_size=16,negative_names=[],actions=[files.probe('warm','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('cache','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),files.probe('enum','iface.records.test',transports=['udp']),
            files.probe('interface','10.91.18.198.in-addr.arpa',type=12,transports=['udp'])])
    for label,interface in [('present','m5ir0'),('empty','missing_ir')]:
        add('interface-cached-cname-'+label,'interface-name=iface.records.test,'+interface+'\n',[],'IF-FWD IF-CALLER',
            topology=[primary],cache_size=16,negative_names=[],upstream_fixtures=[{'name':'cached-alias.records.test','type':1,
                'records':[{'type':5,'target':'iface.records.test'},{'type':1,'owner':'iface.records.test','address':'198.51.100.7'}]}],
            actions=[files.probe('warm','cached-alias.records.test',transports=['udp']),
                kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),
                files.probe('cached-terminal','cached-alias.records.test',transports=['udp'],cache=True,local_address_ttl=0 if label=='present' else None),
                files.probe('fresh-child','cached-alias.records.test',transports=['tcp'],cache=True,local_address_ttl=0 if label=='present' else None)])
    add('interface-synth-ptr-precedence','interface-name=iface.records.test,m5ir0\nsynth-domain=synthetic.records.test,198.18.91.0/24\n',
        [('9.91.18.198.in-addr.arpa',12),('10.91.18.198.in-addr.arpa',12)],'IF-PTR SYN-PTR',topology=[primary])
    add('interface-synth-forward-intercept','interface-name=198-18-91-9.synthetic.records.test,missing_ir\nsynth-domain=synthetic.records.test,198.18.91.0/24\n',
        [('198-18-91-9.synthetic.records.test',1),('198-18-91-9.synthetic.records.test',28),('198-18-91-9.synthetic.records.test',16)],'IF-FWD IF-EXIST SYN-FWD')
    add('interface-synth-name-exists','interface-name=iface.records.test,missing_ir\nsynth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\n',
        [('192-0-2-7.synthetic.records.test',28),('192-0-2-7.synthetic.records.test',16),('synthetic.records.test',1),
         ('child.192-0-2-7.synthetic.records.test',1)],'IF-EXIST SYN-FWD')
    full6='2001-0db8-0000-0000-0000-0000-0000-0007.synthetic.records.test'
    for label,range_text in [('single4','192.0.2.7'),('range4','192.0.2.7,192.0.2.9'),('prefix4','192.0.2.7/24'),
          ('single6','2001:db8::7'),('range6','2001:db8::7,2001:db8::9'),('prefix6','2001:db8::7/64'),
          ('prefix6-small','2001:db8::7/63'),('inverted','192.0.2.9,192.0.2.7')]:
        add('synth-service-'+label,'synth-domain=synthetic.records.test,'+range_text+'\n',
            [('192-0-2-6.synthetic.records.test',1),('192-0-2-7.synthetic.records.test',1),('192-0-2-9.synthetic.records.test',1),
             ('192-0-2-10.synthetic.records.test',1),(full6,28),('2001-db8--7.synthetic.records.test',28),
             ('fd00--7.synthetic.records.test',28),('192-0-2-7.synthetic.records.test',255),
             ('7.2.0.192.in-addr.arpa',12),(ipaddress.ip_address('2001:db8::7').reverse_pointer,12),
             (ipaddress.ip_address('fd00::7').reverse_pointer,12)],'SYN-FWD SYN-PTR')
    for label,text in [('index4','192.0.2.7,192.0.2.9,p*'),('index6','2001:db8::7/64,p*'),
        ('index6-128','2001:db8::7/128,p*'),('prefix-literal','192.0.2.7,192.0.2.9,Pre'),
        ('empty-index','192.0.2.7,192.0.2.9,*'),('embedded-star','192.0.2.7,192.0.2.9,p*x'),
        ('double-star','192.0.2.7,192.0.2.9,p**')]:
        add('synth-service-'+label,'synth-domain=synthetic.records.test,'+text+'\n',
            [('p0.synthetic.records.test',1),('p2.synthetic.records.test',1),('p3.synthetic.records.test',1),
             ('p.synthetic.records.test',1),('p0002.synthetic.records.test',1),('p4294967296.synthetic.records.test',1),
             ('p18446744073709551616.synthetic.records.test',28),('p9223372036854775808.synthetic.records.test',28),
             ('p18446744073709551615.synthetic.records.test',28),('Pre192-0-2-7.synthetic.records.test',1),
             ('pre192-0-2-7.SYNTHETIC.records.test',1),('p0.synthetic.records.test',255),
             ('7.2.0.192.in-addr.arpa',12),(ipaddress.ip_address('2001:db8::7').reverse_pointer,12)],'SYN-FWD SYN-PTR')
    add('synth-index-dual-any','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9,p*\nsynth-domain=synthetic.records.test,2001:db8::7/64,p*\n',
        [('p0.synthetic.records.test',255),('p0.synthetic.records.test',1),('p0.synthetic.records.test',28)],'SYN-FWD')
    add('synth-record-any','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\ntxt-record=192-0-2-7.synthetic.records.test,test\n',
        [('192-0-2-7.synthetic.records.test',255)],'SYN-FWD')
    for ttl in (0,77):
        actions=[files.probe('bits-'+str(kind)+'-'+str(cls)+'-'+str(rd)+'-'+str(do),'192-0-2-7.synthetic.records.test',
                  type=kind,**{'class':cls,'query_flags':256 if rd else 0,'do':do,'cd':do})
            for kind in (1,28,255,16) for cls,rd,do in [(1,True,False),(1,False,False),(1,True,True),(3,True,False),(255,True,False)]]
        add('synth-bits-ttl-'+str(ttl),'synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\nlocal-ttl='+str(ttl)+'\n',[],
            'SYN-FWD SYN-PTR',actions=actions)
    add('synth-overlap-forward','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9,p*\n'
        'synth-domain=synthetic.records.test,192.0.2.8,192.0.2.10,p*\n',
        [('p0.synthetic.records.test',1),('p2.synthetic.records.test',1),('8.2.0.192.in-addr.arpa',12)],'SYN-FWD SYN-PTR')
    add('synth-lease-precedence','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\ndomain=synthetic.records.test\nno-ping\n'
        'dhcp-range=192.0.2.2,192.0.2.100,255.255.255.0,600\ndhcp-leasefile=/m2/files/leases\n',
        [('192-0-2-7.synthetic.records.test',1),('7.2.0.192.in-addr.arpa',12)],'SYN-FWD SYN-PTR',
        topology=[{'name':'m5ir0','addresses':['192.0.2.1/24']}],files={'leases':
            '4102444800 02:00:00:91:00:07 192.0.2.7 leased *\n4102444800 02:00:00:91:00:99 192.0.2.99 192-0-2-7 *\n'})
    add('synth-cache-reverse-precedence','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\n',[],'SYN-PTR',cache_size=16,negative_names=[],
        upstream_fixtures=[{'name':'upstream.records.test','type':1,'reply':'192.0.2.7'}],actions=[
            files.probe('warm','upstream.records.test',transports=['udp']),
            files.probe('reverse','7.2.0.192.in-addr.arpa',type=12,cache=True),
            files.probe('unrelated','8.2.0.192.in-addr.arpa',type=12)])
    import m5_option_matrix as matrix
    soa_hex=(matrix.name('ns.synthetic.records.test')+matrix.name('hostmaster.synthetic.records.test')+struct.pack('!5I',1,60,60,3600,120)).hex()
    for label,rcode,records in [('positive',0,[{'type':1,'owner':'192-0-2-7.synthetic.records.test','address':'198.51.100.7'}]),
                               ('negative',3,[{'type':6,'owner':'synthetic.records.test','hex':soa_hex,'section':'authority'}])]:
        add('synth-cache-forward-'+label,'synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\n',[],'SYN-FWD',cache_size=16,negative_names=[],
            upstream_fixtures=[{'name':'alias.records.test','type':1,'rcode':rcode,'records':
                [{'type':5,'target':'192-0-2-7.synthetic.records.test'},*records]}],actions=[
                files.probe('warm','alias.records.test',transports=['udp']),
                files.probe('terminal','192-0-2-7.synthetic.records.test',cache=True),
                files.probe('cached-alias','alias.records.test',cache=True)])
    for label,interface in [('present','m5ir0'),('empty','missing_ir')]:
        add('interface-cached-cname-negative-'+label,'interface-name=iface.records.test,'+interface+'\n',[],'IF-FWD',
            topology=[primary],cache_size=16,negative_names=[],upstream_fixtures=[{'name':'negative-alias.records.test','type':1,'rcode':3,
                'records':[{'type':5,'target':'iface.records.test'}, {'type':6,'owner':'records.test',
                    'hex':(matrix.name('ns.records.test')+matrix.name('hostmaster.records.test')+struct.pack('!5I',1,60,60,3600,120)).hex(),'section':'authority'}]}],
            actions=[files.probe('warm','negative-alias.records.test',transports=['udp']),
                files.probe('terminal','iface.records.test',cache=True),
                files.probe('cached-alias','negative-alias.records.test',cache=True)])
    for label,rcode in [('nodata',0),('nxdomain',3)]:
        add('synth-reverse-negative-'+label,'synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\n',[],'SYN-PTR',
            cache_size=16,negative_names=[],upstream_fixtures=[{'name':'10.2.0.192.in-addr.arpa','type':12,'rcode':rcode,
                'records':[{'type':5,'target':'7.2.0.192.in-addr.arpa'}, {'type':6,'owner':'2.0.192.in-addr.arpa',
                    'hex':(matrix.name('ns.records.test')+matrix.name('hostmaster.records.test')+struct.pack('!5I',1,60,60,3600,120)).hex(),'section':'authority'}]}],
            actions=[files.probe('warm','10.2.0.192.in-addr.arpa',type=12,transports=['udp']),
                files.probe('synthetic','7.2.0.192.in-addr.arpa',type=12,cache=True),
                files.probe('cached-alias','10.2.0.192.in-addr.arpa',type=12,cache=True)])
    reverse_bits=[files.probe('reverse-'+str(kind)+'-'+str(cls)+'-'+str(rd)+'-'+str(do),'7.2.0.192.in-addr.arpa',type=kind,
            **{'class':cls,'query_flags':256 if rd else 0,'do':do,'cd':do})
        for kind in (12,255) for cls,rd,do in [(1,True,False),(1,False,False),(1,True,True),(3,True,False),(255,True,False)]]
    add('synth-reverse-bits','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9\nlocal-ttl=77\n',[],'SYN-PTR',actions=reverse_bits+
        [files.probe('bad-arpa','invalid.in-addr.arpa',type=12),files.probe('nonarpa','nonarpa.records.test',type=12)])
    add('synth-tcp-snapshot','synth-domain=synthetic.records.test,192.0.2.7,192.0.2.9,p*\nlocal-ttl=77\n',[],
        'SYN-PTR',actions=[dict(op='connect',id='held'),files.probe('child','p0.synthetic.records.test',transports=['held']),
            files.signal_reload(),files.probe('child-after','7.2.0.192.in-addr.arpa',type=12,transports=['held']),
            files.probe('parent','7.2.0.192.in-addr.arpa',type=12,transports=['udp']),dict(op='disconnect',id='held')])
    add('synth-precedence','synth-domain=one.records.test,192.0.2.7,192.0.2.9\nsynth-domain=two.records.test,192.0.2.8,192.0.2.10\n'
        'host-record=192-0-2-7.one.records.test,192.0.2.99\nptr-record=8.2.0.192.in-addr.arpa,explicit.records.test\nbogus-priv\n',
        [('192-0-2-7.one.records.test',1),('7.2.0.192.in-addr.arpa',12),('8.2.0.192.in-addr.arpa',12),
         ('9.2.0.192.in-addr.arpa',12),('10.2.0.192.in-addr.arpa',12),('11.2.0.192.in-addr.arpa',12)],'SYN-FWD SYN-PTR')
    add('interface-debug-parent-blocking','interface-name=iface.records.test,m5ir0\n',[],'IF-CALLER',topology=[primary],debug=True,
        debug_blocking_reference=True,actions=[dict(op='connect',id='held'),
            files.probe('debug-before','iface.records.test',transports=['held']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),state('debug-added'),
            files.probe('debug-parent','iface.records.test',transports=['udp']),
            files.probe('debug-child-after','iface.records.test',transports=['held']),
            dict(op='disconnect',id='held'),files.probe('debug-fresh','iface.records.test')])
    add('interface-enum-same-cycle','interface-name=iface.records.test,m5ir0\n',[],'IF-CALLER',topology=[primary],
        actions=[dict(op='write',path='same-cycle',text='',enumeration_cycle=True)])
    add('interface-enum-event-same-cycle','interface-name=iface.records.test,m5ir0\nbind-dynamic\n',[],'IF-CALLER',topology=[primary],
        actions=[dict(op='write',path='same-cycle',text='',enumeration_cycle=True,cycle_new_address='198.18.91.10/24')])
    add('interface-tcp-inherited-flags','interface-name=iface.records.test,m5ir0\n',[],'IF-CALLER IF-FLAGS',topology=[v4only],
        actions=[*dad,dict(op='connect',id='held'),files.probe('child-tentative','iface.records.test',type=28,transports=['held']),
            dict(op='write',path='dad-complete',text='',kernel_wait={'address':'2001:db8:91::9','mask':0x40,'set':False}),state('completed'),
            files.probe('parent-complete','iface.records.test',type=28,transports=['udp']),
            files.probe('child-old-flags','iface.records.test',type=28,transports=['held']),
            files.probe('fresh-flags','iface.records.test',type=28,transports=['tcp']),dict(op='disconnect',id='held')])
    add('interface-enum-allocation-reference','interface-name=iface.records.test,m5ir0\n',[],'IF-CALLER',topology=[{'name':'m5ir0','addresses':['198.18.91.9/24','2001:db8:91::9/64']}],
        actions=[files.probe('initial','iface.records.test',transports=['udp']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),
            kernel(['ip','-6','addr','add','2001:db8:91::10/64','dev','m5ir0','nodad']),
            dict(op='write',path='remove-linklocal',text='',kernel_remove_linklocal=True),state('allocation-input'),
            dict(op='write',path='allocation-fault',text='',allocation_fault=True),
            files.probe('faulted','iface.records.test',transports=['udp']),
            files.probe('ptr-old4','9.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('ptr-new4','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('ptr-new6',ipaddress.ip_address('2001:db8:91::10').reverse_pointer,type=12,transports=['udp']),
            files.probe('recovered','iface.records.test',transports=['udp'])])
    for stage in ('before-clear','empty','partial'):
        add('interface-enum-fault-'+stage,'interface-name=iface.records.test,m5ir0\n',[],
            'IF-CALLER',topology=[primary],actions=[files.probe('initial','iface.records.test',transports=['udp']),
            kernel(['ip','addr','add','198.18.91.10/24','dev','m5ir0']),
            dict(op='write',path='enum-fault',text='',enumeration_fault=stage),
            files.probe('faulted','iface.records.test',transports=['udp']),
            files.probe('ptr-old','9.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('ptr-new','10.91.18.198.in-addr.arpa',type=12,transports=['udp']),
            files.probe('ptr-v6',ipaddress.ip_address('2001:db8:91::9').reverse_pointer,type=12,transports=['udp']),
            files.probe('recovered','iface.records.test',transports=['udp'])])
    return cases


def run_service_side(root,side,case,out):
    states=[];dynamic=[];tracers=[];domain_dhcp=[]
    local_sockets=[]
    initial_commands_applied=False
    original_put=files.put;original_exchange=files.exchange;original_upstream=files.FileUpstream;original_command=files.command
    def owner_command(root,side,*args):
        if (case.get('round_robin') or case.get('system_hosts')) and (root/'m2/files.conf').exists():
            path=root/'m2/files.conf';text=path.read_text()
            if case.get('round_robin'):text=text.replace('no-round-robin\n','')
            if case.get('system_hosts'):text=text.replace('no-hosts\n','')
            path.write_text(text)
            (out/'config').write_text(text)
        return original_command(root,side,*args)
    class PreparedUpstream(original_upstream):
        def __init__(self,fixtures,*args):
            fixtures={(row['name'],row['type']):row for row in fixtures}
            fixtures.update({(row['name'],row['type']):row for row in case.get('upstream_fixtures',[])})
            super().__init__(list(fixtures.values()),*args)
    files.FileUpstream=PreparedUpstream
    def record(label):
        states.append({'label':label,'at':time.monotonic(),'addresses':json.loads(subprocess.check_output(['ip','-j','address','show'],text=True)),
            'ipv6_flags':Path('/proc/net/if_inet6').read_text()})
    def put(root,path,value,opened):
        nonlocal initial_commands_applied
        if not initial_commands_applied:
            for argv in case.get('initial_kernel_commands',[]):subprocess.run(argv,check=True)
            if case.get('initial_flag'):
                files.await_predicate(lambda:initial_flag_matches(Path('/proc/net/if_inet6').read_text(),case['initial_flag']),
                    'actual domain-source IPv6 flag before startup')
            initial_commands_applied=True
        if isinstance(value,dict) and value.get('hosts_large'):
            import threading
            pid=int((root/'m2/files.pid').read_text());port=int(re.search(r'^port=(\d+)$',(root/'m2/files.conf').read_text(),re.M).group(1))
            target=root/'m2/files/dir/one';length=value['hosts_large'];body=(b'#'+b'x'*126+b'\n')*(length//128)+b'192.0.2.8 one.records.test\n'
            samples=[];stop=threading.Event();offset=len((out/'stderr').read_text())
            def sampler():
                while not stop.is_set():
                    active=bool(files.open_file_fds(pid,'/m2/files/dir/one'));health=files.local_health(port,0x3300+len(samples)%512)
                    samples.append(dict(health,file_active=active,file_still_active=bool(files.open_file_fds(pid,'/m2/files/dir/one'))));time.sleep(.001)
            worker=threading.Thread(target=sampler);worker.start()
            try:
                target.write_bytes(body)
                files.await_predicate(lambda:'read /m2/files/dir/one - 1 names' in (out/'stderr').read_text()[offset:],'bounded hosts source completed',seconds=8)
            finally:stop.set();worker.join(2)
            if worker.is_alive() or not samples or not all(row['healthy'] for row in samples):raise AssertionError('hosts large-file owner health failed')
            active_health=sum(row['healthy'] and row['file_active'] and row['file_still_active'] for row in samples)
            if side=='rust' and not active_health:raise AssertionError('no Rust DNS progress while hosts file stayed open')
            states.append({'label':'hosts-large','bytes':len(body),'sha256':sha256(target),'samples':samples,'healthy_while_open':active_health})
            return
        if isinstance(value,dict) and value.get('hosts_stream'):
            pid=int((root/'m2/files.pid').read_text());target=root/'m2/files/dir/one';staged=root/'m2/files/staged-fifo'
            os.mkfifo(staged);staged.replace(target)
            writer=None
            def attach():
                nonlocal writer
                try:writer=os.open(target,os.O_WRONLY|os.O_NONBLOCK);return True
                except OSError as error:
                    if error.errno!=errno.ENXIO:raise
                    return False
            files.await_predicate(attach,'actual hostsdir FIFO reader opened')
            descriptors=files.await_predicate(lambda:files.open_file_fds(pid,'/m2/files/dir/one'),'actual hostsdir stream read FD')
            mode=value['hosts_stream'];evidence={'label':'hosts-stream','mode':mode,'read_fds':descriptors}
            tracer=None
            try:
                if mode=='partial-eio':
                    trace_path=out/'hosts-read-error.json'
                    tracer=subprocess.Popen([sys.executable,str(Path(__file__).with_name('m5_dns_files.py')),'--trace-read-error',str(pid),str(descriptors[0]['fd']),str(trace_path)])
                    files.await_predicate(lambda:Path(str(trace_path)+'.ready').exists() or tracer.poll() is not None,'hosts read fault attached')
                    if tracer.poll() is not None:raise AssertionError('hosts read fault attach failed')
                    os.write(writer,value['stream_text'].encode())
                    files.await_predicate(lambda:trace_path.exists() or tracer.poll() is not None,'hosts successful prefix read')
                    if tracer.poll() is None:os.write(writer,b'never-consumed')
                    if tracer.wait(5)!=0:raise AssertionError('hosts read EIO tracer failed')
                    evidence['fault']=json.loads(trace_path.read_text())
                    if not evidence['fault']['injected'] or not any(row['result']>0 for row in evidence['fault']['reads']):raise AssertionError('actual hosts partial EIO missing')
                else:
                    port=int(re.search(r'^port=(\d+)$',(root/'m2/files.conf').read_text(),re.M).group(1))
                    evidence['health']=files.local_health(port)
                    if evidence['health']['healthy']!=(side=='rust'):raise AssertionError('C blocking / Rust hostsdir owner progress missing')
                    if mode=='shutdown':
                        os.kill(pid,signal.SIGTERM)
                        if side=='rust':files.await_predicate(lambda:not Path('/proc',str(pid),'exe').exists(),'Rust hosts stream shutdown before writer release')
                        else:time.sleep(.05)
                        evidence['terminated_before_release']=not Path('/proc',str(pid),'exe').exists()
                    else:os.write(writer,value['stream_text'].encode())
            finally:
                # Move the FIFO out before close: CLOSE_WRITE on a FIFO which
                # stays watched makes C reopen it and block on a second writer.
                target.rename(root/'m2/files/completed-fifo')
                os.close(writer)
                if tracer and tracer.poll() is None:tracer.kill();tracer.wait()
            states.append(evidence)
            return
        if isinstance(value,dict) and 'hosts_read_barrier' in value:
            marker='read '+value['hosts_read_barrier']+' - 1 names'
            files.await_predicate(lambda:marker in (out/'stderr').read_text(),'hosts source read completion before rename')
            states.append({'label':'hosts-read-barrier','path':value['hosts_read_barrier'],
                'matching_lines':[line for line in (out/'stderr').read_text().splitlines() if marker in line]})
            return
        if isinstance(value,dict) and 'initial_kind' in value:
            target=image_path(root,'/m2/files/'+path,follow_leaf=False);target.parent.mkdir(parents=True,exist_ok=True)
            if value['initial_kind']=='fifo':os.mkfifo(target)
            elif value['initial_kind']=='directory':target.mkdir();os.chmod(target,value.get('mode',0o755))
            elif value['initial_kind']=='socket':
                endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                directory=os.open(target.parent,os.O_PATH|os.O_DIRECTORY)
                try:endpoint.bind('/proc/self/fd/'+str(directory)+'/'+target.name)
                finally:os.close(directory)
                local_sockets.append(endpoint)
            elif value['initial_kind']=='device':
                import stat
                os.mknod(target,stat.S_IFCHR|0o600,os.makedev(1,3))
            else:raise AssertionError('unknown nonregular initial fixture')
            return
        if isinstance(value,dict) and 'hosts_mode' in value:
            os.chmod(root/'m2/files/dir',value['hosts_mode']);record('actual-hosts-directory-mode');return
        if isinstance(value,dict) and 'domain_dhcp' in value:
            item=value['domain_dhcp'];xid=0xd5930000+len(domain_dhcp)
            spec={'kind':3,'address':'127.0.0.40','prl':[12,15,51,54],
                'extra':[(12,item['hostname'].encode().hex())]}
            request=files.dhcp_wire.request(spec,xid)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.bind(('0.0.0.0',68));client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
                client.setsockopt(socket.SOL_SOCKET,25,b'lo\0')
                response,peer,foreign,drained=files.dhcp_wire.receive(client,request,('127.0.0.1',67),timeout=1)
            if response is None:raise AssertionError('domain DHCP ACK missing')
            options={code:bytes.fromhex(value) for code,value in files.dhcp_wire.options(response)}
            if options.get(53)!=b'\x05' or options.get(15)!=item['domain'].encode():raise AssertionError('DHCP address domain not consumed')
            if options.get(12)!=item['hostname'].encode():raise AssertionError('DHCP hostname update missing')
            domain_dhcp.append({'label':item['label'],'request':request.hex(),'reply':response.hex(),
                'domain':options[15].decode(),'hostname':options[12].decode(),'address':socket.inet_ntoa(response[16:20])})
            return
        if isinstance(value,dict) and 'enumeration_cycle' in value:
            pid=int((root/'m2/files.pid').read_text());path=out/'same-cycle.json'
            tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-enumeration',str(pid),side,'count',str(path)])
            clients=[]
            try:
                files.await_predicate(lambda:Path(str(path)+'.ready').exists() or tracer.poll() is not None,'enum count attach')
                if tracer.poll() is not None:raise AssertionError('enum count attach failed')
                if value.get('cycle_new_address'):
                    subprocess.run(['ip','addr','add',value['cycle_new_address'],'dev','m5ir0'],check=True)
                    record('cycle-address-queued')
                port=15353;packet=files.query(files.probe('cycle','iface.records.test'),0x7341)
                udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.settimeout(3);clients.append(udp)
                udp.connect(('127.0.0.1',port));udp.sendall(packet)
                tcp=socket.create_connection(('127.0.0.1',port),1);tcp.settimeout(3);clients.append(tcp)
                tcp.sendall(struct.pack('!H',len(packet))+packet)
                frozen=Path('/proc/'+str(pid)+'/status').read_text()
                if 'tracing stop' not in frozen:raise AssertionError('both queued transports were not held before one select cycle')
                Path(str(path)+'.go').write_text('both queued\n')
                replies=[udp.recv(65535),files.exact_read(tcp,struct.unpack('!H',files.exact_read(tcp,2))[0])]
                for reply in replies:
                    parsed=files.semantics(reply)
                    wanted=['198.18.91.10','198.18.91.9'] if value.get('cycle_new_address') else ['198.18.91.9']
                    if parsed['id']!=0x7341 or [r['data'] for r in parsed['records'] if r['type']==1]!=wanted:
                        raise AssertionError('same-cycle local packet guard failed')
                Path(str(path)+'.stop').write_text('both received\n')
                if tracer.wait(5)!=0:raise AssertionError('enum count exit')
                evidence=json.loads(path.read_text());requests=[r for r in evidence['events'] if r['phase']=='request']
                families=[r['dump_family'] for r in requests]
                if not families or families!=[10,2]*(len(families)//2):raise AssertionError('incomplete ordered enumeration in parent cycles')
                cycles=[r['cycle'] for r in requests if r['dump_family']==10]
                if len(cycles)!=len(set(cycles)):raise AssertionError('more than one enumeration within an actual parent poll cycle')
                if not evidence.get('polls'):raise AssertionError('actual parent poll boundary witness missing')
                states.append({'label':'same-cycle','frozen_status':frozen,'requests':requests,'replies':[r.hex() for r in replies],
                    'completed':evidence.get('completed',False)})
            finally:
                for client in clients:client.close()
                if tracer.poll() is None:tracer.kill();tracer.wait()
            return
        if isinstance(value,dict) and 'allocation_fault' in value:
            pid=int((root/'m2/files.pid').read_text());path=out/'allocation-fault.json'
            if side=='c':
                symbols=subprocess.check_output(['readelf','-Ds',str(image_path(root,'/lib/libc.so'))],text=True)
                offset=int(re.search(r'^\s*\d+:\s+([0-9a-f]+).*\bcalloc\s*$',symbols,re.M)[1],16)
                kind,size='calloc',40
            else:
                if not case.get('allocator_map'):raise AssertionError('actual Rust allocator map required')
                symbols=Path(case['allocator_map']).read_text()
                offset=int(re.search(r'^\s*0x([0-9a-f]+)\s+realloc\s*$',symbols,re.M)[1],16)
                kind,size='realloc',384
            (out/'allocator-symbols').write_text(symbols)
            tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-interface-allocation',str(pid),str(size),kind,str(offset),str(path)])
            files.await_predicate(lambda:Path(str(path)+'.ready').exists() or tracer.poll() is not None,'allocation breakpoint attach')
            if tracer.poll() is not None:raise AssertionError('allocation breakpoint attach failed')
            tracers.append((tracer,path));return
        if isinstance(value,dict) and 'enumeration_fault' in value:
            pid=int((root/'m2/files.pid').read_text());path=out/('fault-'+value['enumeration_fault']+'.json')
            tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-enumeration',str(pid),side,value['enumeration_fault'],str(path)])
            files.await_predicate(lambda:Path(str(path)+'.ready').exists() or tracer.poll() is not None,'enumeration fault attach')
            if tracer.poll() is not None:raise AssertionError('enumeration fault tracer exited')
            tracers.append((tracer,path));return
        if isinstance(value,dict) and 'kernel_remove_linklocal' in value:
            addresses=json.loads(subprocess.check_output(['ip','-j','-6','addr','show','dev','m5ir0'],text=True))
            for interface in addresses:
                for address in interface['addr_info']:
                    if ipaddress.ip_address(address['local']).is_link_local:
                        subprocess.run(['ip','-6','addr','del',address['local']+'/'+str(address['prefixlen']),'dev','m5ir0'],check=True)
            return
        if isinstance(value,dict) and 'kernel_temporary' in value:
            expected=value['kernel_temporary'];deadline=time.monotonic()+12
            while True:
                raw=json.loads(subprocess.check_output(['ip','-j','-6','addr','show','dev','m5ir0'],text=True))
                temporary=next((a for interface in raw for a in interface['addr_info'] if a.get('temporary')),None)
                flag=None
                if temporary is not None:
                    key=ipaddress.ip_address(temporary['local']).packed.hex()
                    flag=next((int(parts[4],16) for line in Path('/proc/net/if_inet6').read_text().splitlines()
                        if (parts:=line.split())[0]==key),None)
                if flag is not None and flag&expected['mask']==expected['mask']:break
                if time.monotonic()>deadline:raise AssertionError('temporary combined kernel flags were not witnessed')
                time.sleep(.01)
            subprocess.run(['ip','-6','addr','change',temporary['local']+'/'+str(temporary['prefixlen']),'dev','m5ir0',
                'valid_lft','600','preferred_lft',str(expected['preferred_lft'])],check=True)
            record('temporary-changed')
            actual=next((int(parts[4],16) for line in Path('/proc/net/if_inet6').read_text().splitlines()
                if (parts:=line.split())[0]==key),None)
            if actual is None or actual&0x61!=0x61:raise AssertionError('actual temporary/tentative/deprecated combination missing')
            return
        if isinstance(value,dict) and 'kernel_command' in value:
            subprocess.run(value['kernel_command'],check=True)
            return
        if isinstance(value,dict) and 'interface_state' in value:
            record(value['interface_state']);return
        if isinstance(value,dict) and 'kernel_wait' in value:
            expected=value['kernel_wait'];address=ipaddress.ip_address(expected['address']).packed.hex()
            deadline=time.monotonic()+12;samples=[]
            while True:
                flags=next((int(fields[4],16) for line in Path('/proc/net/if_inet6').read_text().splitlines()
                    if (fields:=line.split())[0]==address),None)
                samples.append(flags)
                if flags is not None and bool(flags&expected['mask'])==expected['set']:break
                if time.monotonic()>deadline:raise AssertionError('kernel address state transition not observed')
                time.sleep(.02)
            states.append({'label':'state-transition','expected':expected,'samples':samples,'at':time.monotonic()});return
        return original_put(root,path,value,opened)
    def exchange(port,action,*args):
        if action.get('temporary_ptr'):
            raw=json.loads(subprocess.check_output(['ip','-j','-6','address','show','dev','m5ir0'],text=True))
            temporary=next((address['local'] for interface in raw for address in interface['addr_info'] if address.get('temporary')),None)
            if temporary is None:raise AssertionError('actual temporary IPv6 address was not created')
            action=dict(action,name=ipaddress.ip_address(temporary).reverse_pointer)
            dynamic.append({'id':action['id'],'transport':args[1],'address':temporary,'name':action['name'],'kernel':raw})
        if action.get('destination'):
            ident,transport,upstreams,connections=args
            packet=files.query(action,ident);before=[len(u.events) for u in upstreams]
            started=time.monotonic();response=None;error=None
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as client:
                client.settimeout(.5);client.connect((action['destination'],port))
                try:
                    client.sendall(packet if transport=='udp' else struct.pack('!H',len(packet))+packet)
                    response=client.recv(65535) if transport=='udp' else files.exact_read(client,struct.unpack('!H',files.exact_read(client,2))[0])
                except (OSError,EOFError) as problem:error={'kind':type(problem).__name__,'errno':getattr(problem,'errno',None)}
            return {'id':action['id']+':'+transport,'response':files.semantics(response) if response else None,'error':error,
                'request':packet.hex(),'reply':response.hex() if response else None,'elapsed':time.monotonic()-started,'cache':False,
                'upstreams':[{'server':u.host,'events':copy.deepcopy(u.events[n:])} for u,n in zip(upstreams,before)]}
        row=original_exchange(port,action,*args)
        if action['id']=='ready' and row.get('response') and not any(state['label']=='initial-kernel' for state in states):
            record('initial-kernel')
        if action['id']=='ready' and case.get('dns_disabled') and (root/'m2/files.pid').exists() and not any(state['label']=='initial-kernel' for state in states):
            record('initial-kernel')
        if action['id']=='faulted':
            for tracer,path in tracers:
                if tracer.wait(5)!=0:raise AssertionError('enumeration fault injection failed')
                evidence=json.loads(path.read_text())
                if not evidence.get('injected'):raise AssertionError('enumeration failure was not witnessed')
        return row
    files.put=put;files.exchange=exchange;files.command=owner_command
    try:result=endpoints.run_service_side(root,side,case,out)
    finally:
        files.put=original_put;files.exchange=original_exchange;files.FileUpstream=original_upstream;files.command=original_command
        for tracer,path in tracers:
            if tracer.poll() is None:tracer.kill();tracer.wait()
            if path.exists():states.append({'label':'enumeration-fault','evidence':json.loads(path.read_text())})
        for endpoint in local_sockets:endpoint.close()
        subprocess.run(['ip','link','del','m5peer0'],capture_output=True)
    result['interface_states']=states;result['dynamic_queries']=dynamic;result['domain_dhcp']=domain_dhcp
    save(out/'observed.json',result)
    return result


def comparable_service(observed):
    result=copy.deepcopy(observed)
    # Each side's kernel chooses a different privacy address. Validate the raw
    # query against that actual temporary address before substituting its name.
    for dynamic in observed.get('dynamic_queries',[]):
        for row in result['rows']:
            if row['id']==dynamic['id']+':'+dynamic['transport']:
                response=row.get('response')
                if not response or response['questions'][0][0]!=dynamic['name'] or not any(record['type']==12 for record in response['records']):
                    raise AssertionError('actual privacy-address PTR answer missing')
                response['questions'][0][0]='actual-temporary-address'
                for record in response['records']:
                    if record['name']==dynamic['name']:record['name']='actual-temporary-address'
    return result


def witness_errors(observed,side,case):
    errors=[]
    wanted=not (case['id']=='interface-cname-loop')
    if observed.get('startup',{}).get('ready')!=wanted:errors.append('source-calibrated startup outcome missing')
    if wanted:
        identity=observed.get('identity',{})
        if identity.get('threads')!=1 or not isinstance(identity.get('uid'),int) or identity.get('uid')!=identity.get('expected_uid'):
            errors.append('single owner or runtime identity witness missing')
        if not any(state['label']=='initial-kernel' for state in observed.get('interface_states',[])):
            errors.append('initial actual kernel address/flag witness missing')
        if case.get('initial_flag') and not any(state['label']=='initial-kernel' and initial_flag_matches(state['ipv6_flags'],case['initial_flag']) for state in observed.get('interface_states',[])):
            errors.append('actual flagged domain source witness missing')
    for action in case['actions']:
        if action.get('hosts_stream'):
            mode=action['hosts_stream'];proof=next((state for state in observed.get('interface_states',[]) if state['label']=='hosts-stream' and state['mode']==mode),None)
            if not proof or not proof.get('read_fds'):errors.append('actual hostsdir stream read FD witness missing')
            elif mode=='partial-eio':
                fault=proof.get('fault',{})
                if not fault.get('injected') or not any(row['result']>0 for row in fault.get('reads',[])) or not any(row.get('injected') and row['result']==-errno.EIO for row in fault.get('reads',[])):
                    errors.append('actual hostsdir consumed-prefix/EIO witness missing')
            elif proof.get('health',{}).get('healthy')!=(side=='rust') or (mode=='shutdown' and proof.get('terminated_before_release')!=(side=='rust')):
                errors.append('hostsdir C blocking/Rust owner progress or shutdown witness missing')
        if action.get('domain_dhcp'):
            wanted=action['domain_dhcp']
            actual=next((row for row in observed.get('domain_dhcp',[]) if row['label']==wanted['label']),None)
            if not actual or actual['domain']!=wanted['domain'] or actual['hostname']!=wanted['hostname'] or actual['address']!='127.0.0.40':
                errors.append('actual DHCP address-domain/name consumer witness missing')
        if action.get('local_address_ttl') is not None:
            rows=[row for row in observed['rows'] if row['id'].startswith(action['id']+':')]
            if not rows or any(record['ttl']!=action['local_address_ttl'] for row in rows for record in (row.get('response') or {}).get('records',[]) if record['type'] in (1,28)):
                errors.append('local interface TTL changed under dynamic CNAME clock tolerance')
        if action.get('allocation_fault'):
            report=next((state['evidence'] for state in observed.get('interface_states',[])
                if state['label']=='enumeration-fault' and state['evidence'].get('symbol')),None)
            symbol,size=('calloc',40) if side=='c' else ('realloc',384)
            if not report or not report.get('injected') or report.get('symbol')!=symbol or report.get('required_size')!=size or \
                not any(call.get('size')==size and call.get('returned')==0 and call.get('pc')==report['address'] for call in report.get('calls',[])):
                errors.append('actual pinned allocator call/NULL-return witness missing')
    return errors


def initial_flag_matches(text,wanted):
    network=ipaddress.ip_network(wanted['prefix'])
    return any(len(fields)>=6 and fields[5]=='m5ir0' and ipaddress.IPv6Address(int(fields[0],16)) in network and
        int(fields[4],16)&wanted['mask']==wanted['mask'] for fields in (line.split() for line in text.splitlines()))


def controls():
    found=files.controls()
    base={'startup':{'ready':True},'identity':{'threads':1,'uid':0,'expected_uid':0},
          'interface_states':[{'label':'initial-kernel'}]}
    case={'id':'ordinary','actions':[]}
    assert not witness_errors(base,'c',case)
    for label,change in [('missing-kernel',lambda x:x.update(interface_states=[])),
                         ('extra-owner-thread',lambda x:x['identity'].update(threads=2)),
                         ('wrong-runtime-uid',lambda x:x['identity'].update(uid=1))]:
        bad=copy.deepcopy(base);change(bad);assert witness_errors(bad,'c',case);found.append(label)
    local=dict(base,rows=[{'id':'cached:udp','response':{'records':[{'type':1,'ttl':0}]}}])
    case={'id':'cached','actions':[{'id':'cached','local_address_ttl':0}]}
    assert not witness_errors(local,'c',case)
    bad=copy.deepcopy(local);bad['rows'][0]['response']['records'][0]['ttl']=1
    assert witness_errors(bad,'c',case);found.append('local-ttl-not-hidden-by-cname-clock')
    allocation=dict(base,interface_states=[*base['interface_states'],{'label':'enumeration-fault','evidence':
        {'symbol':'calloc','required_size':40,'injected':True,'address':100,'calls':[{'size':40,'returned':0,'pc':100}]}}])
    case={'id':'allocation','actions':[{'allocation_fault':True}]}
    assert not witness_errors(allocation,'c',case)
    for label,change in [('wrong-allocation-size',lambda x:x['calls'][0].update(size=41)),
                         ('allocation-did-not-fail',lambda x:x['calls'][0].update(returned=1)),
                         ('wrong-allocator-pc',lambda x:x['calls'][0].update(pc=101))]:
        bad=copy.deepcopy(allocation);change(bad['interface_states'][-1]['evidence']);assert witness_errors(bad,'c',case);found.append(label)
    wanted={'label':'first','hostname':'client','domain':'chosen.records.test'}
    consumer=dict(base,domain_dhcp=[dict(wanted,address='127.0.0.40')])
    case={'id':'domain-consumer','actions':[{'domain_dhcp':wanted}]}
    assert not witness_errors(consumer,'c',case)
    for label,change in [('missing-dhcp-domain-consumer',lambda x:x.update(domain_dhcp=[])),
        ('wrong-dhcp-domain',lambda x:x['domain_dhcp'][0].update(domain='fallback.records.test'))]:
        bad=copy.deepcopy(consumer);change(bad);assert witness_errors(bad,'c',case);found.append(label)
    stream=dict(base,interface_states=[*base['interface_states'],{'label':'hosts-stream','mode':'partial-eio',
        'read_fds':[{'fd':3}],'fault':{'injected':True,'reads':[{'result':32},{'result':-errno.EIO,'injected':True}]}}])
    case={'id':'hosts-stream','actions':[{'hosts_stream':'partial-eio'}]}
    assert not witness_errors(stream,'c',case)
    for label,change in [('missing-hosts-stream',lambda x:x.update(interface_states=[])),
        ('missing-hosts-read-fd',lambda x:x['interface_states'][-1].update(read_fds=[])),
        ('missing-hosts-consumed-prefix',lambda x:x['interface_states'][-1]['fault'].update(reads=[{'result':-errno.EIO,'injected':True}]))]:
        bad=copy.deepcopy(stream);change(bad);assert witness_errors(bad,'c',case);found.append(label)
    return found


def compare_service(left,right,case):
    differences=[]
    guards=[{'phase':'witness','side':side,'error':error} for side,observed in [('c',left),('rust',right)]
        for error in witness_errors(observed,side,case)]
    if guards:return guards,[]
    for action in case['actions']:
        if action.get('hosts_stream') in ('fifo','shutdown'):
            mode=action['hosts_stream'];differences.append({'reason':'C hostsdir stream read blocks the parent; Rust keeps the single owner serving the prior complete generation.',
                'mode':mode,'c':next(state for state in left['interface_states'] if state.get('mode')==mode),
                'rust':next(state for state in right['interface_states'] if state.get('mode')==mode)})
    if case.get('debug_blocking_reference'):
        expected=[a['id']+':'+transport for a in case['actions'] if a['op']=='query' for transport in a.get('transports',['udp','tcp'])]
        if [r['id'] for r in left['rows']]!=expected or [r['id'] for r in right['rows']]!=expected:
            return [{'phase':'debug-boundary','error':'exact transport rows missing'}],[]
        projections={side:{r['id']:r for r in data['rows']} for side,data in [('c',left),('rust',right)]}
        for ident,c_data,rust_data in [('debug-parent:udp',None,['198.18.91.10','198.18.91.9'])]:
            for side,wanted in [('c',c_data),('rust',rust_data)]:
                row=projections[side][ident];answer=row.get('response')
                if wanted is None:
                    valid=answer is None and row.get('error',{}).get('kind')=='TimeoutError'
                else:
                    valid=answer is not None and row.get('error') is None and answer['flags']==0x8580 and \
                        [r['data'] for r in answer['records'] if r['type']==1]==wanted and \
                        all(r['ttl']==0 and r['class']==1 for r in answer['records'])
                if not valid:return [{'phase':'debug-boundary','side':side,'id':ident,'error':'source blocking/owner progress model not observed'}],[]
            differences.append({'id':ident,'reason':'C debug TCP loop holds the parent poll; Rust continues UDP and publishes the parent interface generation.',
                                'c':projections['c'][ident],'rust':projections['rust'][ident]})
        removed={'debug-parent:udp'}
        left=copy.deepcopy(left);right=copy.deepcopy(right);case=copy.deepcopy(case)
        for observed in (left,right):observed['rows']=[row for row in observed['rows'] if row['id'] not in removed]
        case['actions']=[a for a in case['actions'] if a.get('id') not in {'debug-parent'}]
    if case['id']=='hostsdir-runtime-emfile':
        for side,observed in [('c',left),('rust',right)]:
            if not any(action['op']=='actual-fd-limit' for action in observed['actions']) or \
                'failed to load names from /m2/files/dir/one: No file descriptors available' not in observed['stderr']:
                return [{'phase':'hosts-fd-limit','side':side,'error':'actual host-source EMFILE not witnessed'}],[]
        case=copy.deepcopy(case)
        for action in case['actions']:
            if action['op']=='fd-limit':action['op']='write'
    failures=files.compare(comparable_service(left),comparable_service(right),case)
    if left.get('domain_dhcp',[])!=right.get('domain_dhcp',[]):failures.append('actual DHCP domain packets differ')
    return failures,differences


def run_syntax(root,side,case,out):
    out.mkdir(parents=True)
    text='no-hosts\nuser=root\ngroup=root\nport=15353\n'+('no-resolv\n' if case.get('no_resolv',True) else '')+case['config']
    for path,value in case.get('files',{}).items():
        target=root/'m2'/path;target.parent.mkdir(parents=True,exist_ok=True)
        if target.exists() and not target.is_file():target.unlink()
        target.write_text(value)
    (root/'m2/interface-records.conf').write_text(text);(out/'config').write_text(text)
    argv=command(root,side,*case.get('argv',[]),'--test','-C','/m2/interface-records.conf')
    if case.get('resolver_fault'):
        result=resolver_fault_syntax(argv,case['resolver_fault'],out/'resolver-fault.json')
    elif case.get('resolver_fifo'):
        path=root/'m2/records-resolv';path.unlink();os.mkfifo(path)
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            try:process.communicate(timeout=.08);raise AssertionError('resolver FIFO did not block before writer')
            except subprocess.TimeoutExpired:pass
            writer=os.open(path,os.O_WRONLY|os.O_NONBLOCK)
            try:written=os.write(writer,b'search chosen.records.test\n')
            finally:os.close(writer)
            stdout,stderr=process.communicate(timeout=5)
            save(out/'resolver-fifo.json',{'blocked_before_writer':True,'written':written,'exit':process.returncode})
            result=subprocess.CompletedProcess(argv,process.returncode,stdout,stderr)
        finally:
            if process.poll() is None:process.kill();process.wait()
    else:result=subprocess.run(argv,capture_output=True,timeout=5)
    (out/'stdout').write_bytes(result.stdout);(out/'stderr').write_bytes(result.stderr)
    row={'exit':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')}
    save(out/'observed.json',row);return row


def resolver_fault_syntax(argv,fault,output):
    """Select the actual domain resolver fd during startup, not a later file read."""
    if platform.machine()!='aarch64':raise RuntimeError('startup fault ABI is pinned AArch64')
    class Iovec(ctypes.Structure):
        _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
    def preexec():
        if libc.ptrace(0,0,None,None):raise OSError(ctypes.get_errno(),'PTRACE_TRACEME')
    process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=preexec)
    pid=process.pid;registers=(ctypes.c_ulonglong*34)();attached=True
    report={'pid':pid,'fault':fault,'path':'/m2/records-resolv','calls':[],'injected':False}
    deadline=time.monotonic()+5;pending=None;consumed=False
    def ptrace(request,address=0,data=0):
        ctypes.set_errno(0);result=libc.ptrace(ctypes.c_uint(request),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'ptrace')
        return result
    def regs(write=False):
        iov=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers));ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(iov))
    def memory(address,length):
        buffer=(ctypes.c_ubyte*length)();local=Iovec(ctypes.addressof(buffer),length);remote=Iovec(address,length)
        count=libc.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
        if count<=0:raise AssertionError('startup pathname read failed')
        return bytes(buffer[:count]).split(b'\0')[0]
    def wait_stop():
        while time.monotonic()<deadline:
            returned,status=os.waitpid(pid,os.WNOHANG)
            if returned:return status
            time.sleep(.001)
        raise TimeoutError('startup fault syscall deadline')
    try:
        status=wait_stop()
        if not os.WIFSTOPPED(status):raise AssertionError('startup trace did not stop at exec')
        ptrace(0x4200,0,1)
        while not report['injected']:
            ptrace(24);status=wait_stop()
            if not os.WIFSTOPPED(status):process.returncode=os.waitstatus_to_exitcode(status);attached=False;raise AssertionError('startup ended before fault')
            if os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80):continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,128,ctypes.addressof(info));regs()
            if info[0]==1:
                number=int(registers[8]);target=None
                if number==56:
                    target=memory(int(registers[1]),256).decode(errors='surrogateescape')
                elif number==63:
                    try:target=os.readlink('/proc/'+str(pid)+'/fd/'+str(registers[0]))
                    except FileNotFoundError:pass
                if not target or not target.endswith('/m2/records-resolv'):continue
                inject=(fault=='open-denied' and number==56) or (fault!='open-denied' and number==63 and (fault=='read-empty-eio' or consumed))
                pending={'syscall':number,'target':target,'descriptor':int(registers[0]) if number==63 else None,'pc':int(registers[32]),'inject':inject}
                if inject:registers[8]=(1<<64)-1;regs(True)
            elif info[0]==2 and pending:
                if pending['inject']:
                    error=errno.EACCES if fault=='open-denied' else errno.EIO
                    registers[0]=((1<<64)-error);regs(True);pending['returned']=-error;report['injected']=True
                else:
                    pending['returned']=ctypes.c_longlong(registers[0]).value
                    if pending['syscall']==63 and pending['returned']>0:consumed=True
                report['calls'].append(pending);pending=None
        if fault=='read-partial-eio' and not consumed:raise AssertionError('partial resolver bytes were not consumed')
        ptrace(17);attached=False
        stdout,stderr=process.communicate(timeout=5);report['exit']=process.returncode;save(output,report)
        return subprocess.CompletedProcess(argv,process.returncode,stdout,stderr)
    finally:
        if attached:
            try:ptrace(17)
            except OSError:pass
        if process.poll() is None:process.kill();process.wait()
        save(output,report)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','both'],default='c');parser.add_argument('--mode',choices=['syntax','service'],default='syntax')
    parser.add_argument('--case',action='append');parser.add_argument('--allocator-map',type=Path);args=parser.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert not args.out.exists() and 'private' in args.out.parts
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));args.out.mkdir(parents=True)
    selected=[case for case in (syntax_cases() if args.mode=='syntax' else service_cases()) if (not args.case or case['id'] in args.case) and (args.side=='c' or not case.get('c_only'))]
    assert selected and (not args.case or len(selected)==len(set(args.case)))
    for case in selected:
        if args.allocator_map:case['allocator_map']=str(args.allocator_map)
    save(args.out/'schedule.json',selected);driver=args.out/'driver';driver.mkdir()
    for name in ['m5_interface_records.py','m5_interface_records.json','m5_dns_endpoints.py','m5_dns_endpoints.json',
        'm5_dns_endpoints_requirements.json','m5_dns_files.py','m5_option_matrix.py','m5_option_matrix_probes.py',
        'm5_dhcp_tags_options.py','dhcp_boot_service_diff.py','dns_service_probe.py','m2_rootfs.py','run_isolated.sh',
        'm5_tftp_allocation.py','test_single_poll_service.py','m2_dhcp_scenarios.py']:
        shutil.copy2(Path(__file__).with_name(name),driver/name)
    subprocess.run(['sysctl','-q','-w','net.ipv4.ip_local_port_range=40000 60999','net.ipv4.ip_unprivileged_port_start=1024'],check=True)
    sides=['c','rust'] if args.side=='both' else ['c'];roots={side:prepare(args.image_root,None,args.out/side,args.rust) for side in sides}
    report={'mode':args.mode,'comparison_executed':args.side=='both','source_commit':args.source_commit,
        'rust_sha256':sha256(args.rust),'c_sha256':STOCK_SHA256,'tool_sha256':sha256(__file__),
        'requirements_sha256':sha256(Path(__file__).with_suffix('.json')),'cases':[],'failures':[],
        'closed_options':[],'negative_controls':controls(),'reference_differences':[],'qualification':'Calibration and partial runs never close a frozen required row.'}
    for case in selected:
        folder=args.out/case['id'];folder.mkdir();row={'id':case['id'],'failures':[]}
        try:
            observed={side:(run_syntax(roots[side],side,case,folder/side) if args.mode=='syntax' else run_service_side(roots[side],side,case,folder/side)) for side in sides}
            if args.side=='both':
                if args.mode=='syntax':row['failures']=[] if endpoints.normal(observed['c'])==endpoints.normal(observed['rust']) else ['syntax differs']
                else:
                    row['failures'],differences=compare_service(observed['c'],observed['rust'],case)
                    report['reference_differences'].extend(dict(case=case['id'],**difference) for difference in differences)
            row['sides']={side:({'exit':data['exit']} if args.mode=='syntax' else {'startup':data['startup'],'rows':len(data['rows']),'cleanup':data['cleanup']}) for side,data in observed.items()}
        except Exception as error:
            row['failures'].append({'phase':'infrastructure','error':repr(error)})
            (folder/'traceback').write_text(traceback.format_exc())
        report['cases'].append(row);report['failures'].extend({'case':case['id'],'error':error} for error in row['failures'])
        save(args.out/'progress.json',report)
    save(args.out/'result.json',report);print(json.dumps({'cases':len(selected),'failures':len(report['failures']),'comparison_executed':report['comparison_executed'],'closed_options':[]}))
    return int(bool(report['failures']))


def trace_enumeration(pid,side,stage,output):
    """Fault only a selected namespace daemon at a real enumeration syscall."""
    if platform.machine()!='aarch64':raise RuntimeError('ptrace ABI is pinned AArch64')
    class Iovec(ctypes.Structure):
        _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
    def ptrace(request,address=0,data=0):
        ctypes.set_errno(0)
        result=libc.ptrace(ctypes.c_uint(request),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'ptrace')
        return result
    registers=(ctypes.c_ulonglong*34)()
    def regs(write=False):
        iov=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(iov))
    def memory(address,length):
        buffer=(ctypes.c_ubyte*length)();local=Iovec(ctypes.addressof(buffer),length);remote=Iovec(address,length)
        count=libc.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
        if count!=length:raise AssertionError('tracee memory read failed')
        return bytes(buffer)
    report={'pid':pid,'side':side,'stage':stage,'events':[],'polls':[],'injected':False};attached=False
    cycle=0
    armed=None;received=False;fault=False;active=None
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;ptrace(0x4200,0,1)
        Path(str(output)+'.ready').write_text('attached\n')
        if stage=='count':
            deadline=time.monotonic()+5
            while not Path(str(output)+'.go').exists():
                if time.monotonic()>deadline:raise AssertionError('queued-cycle start was not released')
                time.sleep(.005)
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            if not os.WIFSTOPPED(status):raise AssertionError('tracee ended before fault')
            if os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80):continue
            if stage=='count' and Path(str(output)+'.stop').exists():
                report['completed']=True;ptrace(17);attached=False;break
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                number=int(registers[8]);active={'syscall':number,'fd':int(registers[0])};fault=False
                if number in (72,73):active.update(poll_base=int(registers[0]),poll_count=int(registers[1]))
                if number in (207,212):active['receive_flags']=int(registers[3 if number==207 else 2])
                if number==206 and int(registers[2])>=17:
                    request=memory(registers[1],17)
                    kind=struct.unpack_from('=H',request,4)[0];family=request[16]
                    if kind==22 and family in (10,2):
                        armed=int(registers[0]);received=False
                        active.update(dump_family=family,dump_type=kind,cycle=cycle)
                        report['events'].append(dict(active,phase='request'))
                if stage=='before-clear':
                    fault=number==198 and int(registers[0])==2 and (int(registers[1])&15)==2
                elif armed is not None and number in (207,212) and int(registers[0])==armed and not active['receive_flags']&2:
                    family=next(row['dump_family'] for row in reversed(report['events']) if 'dump_family' in row)
                    fault=stage=='empty' or (stage=='partial' and family==2)
                if fault:
                    call=ctypes.c_int(-1);iov=Iovec(ctypes.addressof(call),ctypes.sizeof(call));ptrace(0x4205,0x404,ctypes.addressof(iov))
            elif info[0]==2:
                returned=ctypes.c_longlong(registers[0]).value
                number=active['syscall'] if active else int(registers[8])
                if number in (72,73):
                    cycle+=1
                    ready=[]
                    if active and number==73 and 0<active['poll_count']<4096:
                        data=memory(active['poll_base'],active['poll_count']*8)
                        ready=[{'fd':fd,'events':events,'revents':revents} for fd,events,revents in struct.iter_unpack('=ihh',data) if revents]
                    report['polls'].append({'cycle':cycle,'syscall':number,'result':returned,'ready':ready})
                if active is None:continue
                if fault:
                    registers[0]=(1<<64)-errno.EIO;regs(write=True)
                    report['events'].append(dict(active,phase='return',result=-errno.EIO,injected=True));report['injected']=True
                    ptrace(17);attached=False;break
                if armed is not None and active['fd']==armed and active['syscall'] in (207,212):
                    report['events'].append(dict(active,phase='return',result=returned,injected=False));received|=returned>0 and not active['receive_flags']&2
                active=None
    finally:
        if attached:
            try:ptrace(17)
            except OSError:pass
        save(Path(output),report)
    return 0


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--trace-interface-allocation':
        from m5_tftp_allocation import trace_allocation
        raise SystemExit(trace_allocation(int(sys.argv[2]),int(sys.argv[3]),sys.argv[4],int(sys.argv[5]),sys.argv[6],file_record=False))
    if len(sys.argv)>1 and sys.argv[1]=='--trace-enumeration':
        raise SystemExit(trace_enumeration(int(sys.argv[2]),sys.argv[3],sys.argv[4],sys.argv[5]))
    raise SystemExit(main())
