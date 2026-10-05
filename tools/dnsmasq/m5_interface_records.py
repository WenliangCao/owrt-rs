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
            files=extra.pop('files',{}),sys_files={},default_resolv=False,strict_order=True,
            no_upstream=True,negative_names=[a['name'] for a in actions if a.get('op')=='query'],actions=actions,**extra))
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
    def kernel(argv):return dict(op='write',path='kernel-action',text='',kernel_command=argv)
    def state(label):return dict(op='write',path='interface-state',text='',interface_state=label)
    v4only={'name':'m5ir0','addresses':['198.18.91.9/24']}
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
    states=[];dynamic=[];tracers=[]
    original_put=files.put;original_exchange=files.exchange
    def record(label):
        states.append({'label':label,'at':time.monotonic(),'addresses':json.loads(subprocess.check_output(['ip','-j','address','show'],text=True)),
            'ipv6_flags':Path('/proc/net/if_inet6').read_text()})
    def put(root,path,value,opened):
        if isinstance(value,dict) and 'enumeration_fault' in value:
            pid=int((root/'m2/files.pid').read_text());path=out/('fault-'+value['enumeration_fault']+'.json')
            tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-enumeration',str(pid),side,value['enumeration_fault'],str(path)])
            files.await_predicate(lambda:Path(str(path)+'.ready').exists() or tracer.poll() is not None,'enumeration fault attach')
            if tracer.poll() is not None:raise AssertionError('enumeration fault tracer exited')
            tracers.append((tracer,path));return
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
        if action['id']=='faulted':
            for tracer,path in tracers:
                if tracer.wait(5)!=0:raise AssertionError('enumeration fault injection failed')
                evidence=json.loads(path.read_text())
                if not evidence.get('injected'):raise AssertionError('enumeration failure was not witnessed')
        return row
    files.put=put;files.exchange=exchange
    try:result=endpoints.run_service_side(root,side,case,out)
    finally:
        files.put=original_put;files.exchange=original_exchange
        for tracer,path in tracers:
            if tracer.poll() is None:tracer.kill();tracer.wait()
            if path.exists():states.append({'label':'enumeration-fault','evidence':json.loads(path.read_text())})
        subprocess.run(['ip','link','del','m5peer0'],capture_output=True)
    result['interface_states']=states;result['dynamic_queries']=dynamic
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


def run_syntax(root,side,case,out):
    out.mkdir(parents=True)
    text='no-hosts\nuser=root\ngroup=root\nport=15353\n'+('no-resolv\n' if case.get('no_resolv',True) else '')+case['config']
    for path,value in case.get('files',{}).items():
        target=root/'m2'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(value)
    (root/'m2/interface-records.conf').write_text(text);(out/'config').write_text(text)
    result=subprocess.run(command(root,side,'--test','-C','/m2/interface-records.conf'),capture_output=True,timeout=5)
    (out/'stdout').write_bytes(result.stdout);(out/'stderr').write_bytes(result.stderr)
    row={'exit':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')}
    save(out/'observed.json',row);return row


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','both'],default='c');parser.add_argument('--mode',choices=['syntax','service'],default='syntax')
    parser.add_argument('--case',action='append');args=parser.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert not args.out.exists() and 'private' in args.out.parts
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));args.out.mkdir(parents=True)
    selected=[case for case in (syntax_cases() if args.mode=='syntax' else service_cases()) if not args.case or case['id'] in args.case]
    assert selected and (not args.case or len(selected)==len(set(args.case)))
    save(args.out/'schedule.json',selected);driver=args.out/'driver';driver.mkdir()
    for name in ['m5_interface_records.py','m5_interface_records.json','m5_dns_endpoints.py','m5_dns_endpoints.json',
        'm5_dns_endpoints_requirements.json','m5_dns_files.py','m5_option_matrix.py','m5_option_matrix_probes.py',
        'm5_dhcp_tags_options.py','dhcp_boot_service_diff.py','dns_service_probe.py','m2_rootfs.py','run_isolated.sh']:
        shutil.copy2(Path(__file__).with_name(name),driver/name)
    subprocess.run(['sysctl','-q','-w','net.ipv4.ip_local_port_range=40000 60999','net.ipv4.ip_unprivileged_port_start=1024'],check=True)
    sides=['c','rust'] if args.side=='both' else ['c'];roots={side:prepare(args.image_root,None,args.out/side,args.rust) for side in sides}
    report={'mode':args.mode,'comparison_executed':args.side=='both','source_commit':args.source_commit,
        'rust_sha256':sha256(args.rust),'c_sha256':STOCK_SHA256,'tool_sha256':sha256(__file__),
        'requirements_sha256':sha256(Path(__file__).with_suffix('.json')),'cases':[],'failures':[],
        'closed_options':[],'qualification':'Calibration and partial runs never close a frozen required row.'}
    for case in selected:
        folder=args.out/case['id'];folder.mkdir();row={'id':case['id'],'failures':[]}
        try:
            observed={side:(run_syntax(roots[side],side,case,folder/side) if args.mode=='syntax' else run_service_side(roots[side],side,case,folder/side)) for side in sides}
            if args.side=='both':
                row['failures']=([] if endpoints.normal(observed['c'])==endpoints.normal(observed['rust']) else ['syntax differs']) if args.mode=='syntax' else files.compare(comparable_service(observed['c']),comparable_service(observed['rust']),case)
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
    report={'pid':pid,'side':side,'stage':stage,'events':[],'injected':False};attached=False
    armed=None;received=False;fault=False;active=None
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;ptrace(0x4200,0,1)
        Path(str(output)+'.ready').write_text('attached\n')
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            if not os.WIFSTOPPED(status):raise AssertionError('tracee ended before fault')
            if os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80):continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                number=int(registers[8]);active={'syscall':number,'fd':int(registers[0])};fault=False
                if number in (207,212):active['receive_flags']=int(registers[3 if number==207 else 2])
                if number==206 and int(registers[2])>=17:
                    request=memory(registers[1],17)
                    kind=struct.unpack_from('=H',request,4)[0];family=request[16]
                    if kind==22:
                        armed=int(registers[0]);received=False
                        active.update(dump_family=family,dump_type=kind)
                        report['events'].append(dict(active,phase='request'))
                if stage=='before-clear':
                    fault=number==198 and int(registers[0])==(2 if side=='c' else 16) and (int(registers[1])&15)==(2 if side=='c' else 3)
                elif armed is not None and number in (207,212) and int(registers[0])==armed and not active['receive_flags']&2:
                    family=next(row['dump_family'] for row in reversed(report['events']) if 'dump_family' in row)
                    fault=stage=='empty' or (stage=='partial' and (family==2 if side=='c' else received))
                if fault:
                    call=ctypes.c_int(-1);iov=Iovec(ctypes.addressof(call),ctypes.sizeof(call));ptrace(0x4205,0x404,ctypes.addressof(iov))
            elif info[0]==2 and active:
                returned=ctypes.c_longlong(registers[0]).value
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
    if len(sys.argv)>1 and sys.argv[1]=='--trace-enumeration':
        raise SystemExit(trace_enumeration(int(sys.argv[2]),sys.argv[3],sys.argv[4],sys.argv[5]))
    raise SystemExit(main())
