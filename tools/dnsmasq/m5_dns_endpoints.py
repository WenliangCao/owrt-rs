#!/usr/bin/env python3
"""Exact-image endpoint/source-socket family; only disposable namespaces.

The initial syntax corpus establishes image libc expansion and error boundaries.
Service, source tuple, sharing and reload cases are separate gates in this same
family driver. Syntax alone never closes an endpoint option.
"""
from __future__ import annotations
import argparse
import ctypes
import errno
import signal
import sys
import copy
import json
import os
from pathlib import Path
import resource
import struct
import ipaddress
import threading
import shutil
import socket
import subprocess
import time
from m2_rootfs import command, prepare, sha256, STOCK_SHA256


def save(path, value): path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def syntax_cases():
    cases=[]
    def add(name, text, checks, **extra): cases.append(dict(id=name,config=text,checks=checks.split(),**extra))
    for directive in ['server','local']:
        for label, value in [
            ('v4','127.0.0.2'),('v6','::1'),('port0','127.0.0.2#0'),('portmax','127.0.0.2#65535'),
            ('portempty','127.0.0.2#'),('portwide','127.0.0.2#65536'),('portwrap','127.0.0.2#4294967349'),
            ('negative','127.0.0.2#-1'),('textport','127.0.0.2#bad'),('doubleport','127.0.0.2#53#54'),
            ('v4source','127.0.0.2@127.0.0.9'),('v6source','::1@::1'),('interface','127.0.0.2@lo'),
            ('combined','127.0.0.2@lo@127.0.0.9#34001'),('source-empty','127.0.0.2@'),
            ('interface-empty','127.0.0.2@@127.0.0.9'),('sourceport-empty','127.0.0.2@127.0.0.9#'),
            ('double-source','127.0.0.2@lo@missing'),('extra-at','127.0.0.2@lo@127.0.0.9@lo'),
            ('source-delimiter-order','127.0.0.2@lo#1@127.0.0.9'),
            ('family4-6','127.0.0.2@::1'),('family6-4','::1@127.0.0.9'),
            ('scope-valid','::1%lo'),('scope-unknown','::1%missing'),('scope-number','::1%1'),
            ('scope-empty','::1%'),('scope-v4','127.0.0.2%missing'),('scope-double','::1%lo%lo'),
            ('name-v4','v4.endpoint.test'),('name-v6','v6.endpoint.test'),('name-multi','multi.endpoint.test'),
            ('name-mixed','mixed.endpoint.test'),('named-source4','mixed.endpoint.test@127.0.0.9'),
            ('named-source6','mixed.endpoint.test@::1'),('named-all-mismatch','v4.endpoint.test@::1'),
            ('named-scope','mixed.endpoint.test%lo'),('named-bad-scope','mixed.endpoint.test%missing'),
            ('numeric-name','127.1'),('domain-multi','/one.test/two.test/multi.endpoint.test'),
            ('dotless','//v4.endpoint.test'),('default','/#/#'),('localonly','/local.test/'),
        ]:
            add(directive+'-'+label,directive+'='+value+'\n','GRAM-01 GRAM-02 GRAM-03 NAME-01 NAME-02')
    for label, value in [('v4','192.0.2.0/24,127.0.0.2'),('v4part','192.0.2.128/25,127.0.0.2'),
                         ('v4zero','192.0.2.0/0,127.0.0.2'),('v6','2001:db8::/64,::1'),
                         ('v6part','2001:db8::/65,::1'),('v6zero','2001:db8::/0,::1'),
                         ('local','192.0.2.0/24'),('host','192.0.2.0/24,v4.endpoint.test'),
                         ('multi','192.0.2.0/24,multi.endpoint.test'),
                         ('mixed-source','192.0.2.0/24,mixed.endpoint.test@127.0.0.9'),
                         ('partial-host-defect','192.0.2.0/25,v4.endpoint.test')]:
        add('rev-'+label,'rev-server='+value+'\n','REV-01 NAME-01 NAME-02',reference_defect=label=='partial-host-defect')
    for option in ['query-port','min-port','max-port','port-limit']:
        for value in ['', '0','1','65535','65536','-1','4294967296','4294967297']:
            add(option+'-'+(value or 'empty'),option+'='+value+'\n','PORT-01')
    add('range-inverted','min-port=34003\nmax-port=34001\n','PORT-01')
    add('range-limit-overflow','min-port=34001\nmax-port=34002\nport-limit=3\n','PORT-01')
    return cases


HOSTS = ('127.0.0.2 v4.endpoint.test\n::1 v6.endpoint.test\n'
         '127.0.0.2 multi.endpoint.test\n127.0.0.3 multi.endpoint.test\n'
         '127.0.0.2 mixed.endpoint.test\n::1 mixed.endpoint.test\n')


def run_syntax(root, side, case, out):
    out.mkdir(parents=True)
    text='no-hosts\nno-resolv\nuser=root\ngroup=root\nport=15353\n'+case['config']
    (out/'config').write_text(text);(root/'m2/endpoints.conf').write_text(text)
    (root/'etc/hosts').write_text(HOSTS)
    with (out/'stdout').open('wb') as stdout,(out/'stderr').open('wb') as stderr:
        process=subprocess.Popen(command(root,side,'--test','-C','/m2/endpoints.conf'),stdout=stdout,stderr=stderr)
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait();raise AssertionError('syntax process exceeded deadline')
    row={'exit':process.returncode,'stdout':(out/'stdout').read_text(),'stderr':(out/'stderr').read_text()}
    save(out/'observed.json',row);return row


def normal(row):
    result=copy.deepcopy(row)
    result['stderr']=result['stderr'].replace('dnsmasq-rs:','dnsmasq:')
    return result



def service_cases():
    from m5_dns_files import probe, write, signal_reload
    cases=[]
    def add(ident, config, names=('one.endpoint.test',), **extra):
        if 'all-servers' in config: extra.setdefault('udp_winner',0)
        actions=extra.pop('actions', [probe('query-'+str(i), name, transports=['udp','tcp']) for i,name in enumerate(names)])
        cases.append(dict(id=ident,config=('no-resolv\n' if extra.pop('no_resolv',True) else '')+config,files=extra.pop('files',{}),actions=actions,default_resolv=extra.pop('default_resolv',False),strict_order='all-servers' not in config,**extra))
    for directive in ('server','local'):
        for label, endpoint in [('v4','127.0.0.2'),('v6','::1'),('name-v4','v4.endpoint.test'),('name-v6','v6.endpoint.test'),('name-multi','multi.endpoint.test'),('name-mixed','mixed.endpoint.test'),('name-legacy','127.1'),('named-v4-source','mixed.endpoint.test@127.0.0.9'),('named-v6-source','mixed.endpoint.test@::1'),('named-all-filtered','v4.endpoint.test@::1'),('scope6','::1%lo'),('scope4-ignored','127.0.0.2%missing'),('source4','127.0.0.2@127.0.0.9'),('source6','::1@::1'),('interface','127.0.0.2@lo'),('combined','127.0.0.2@lo@127.0.0.9'),('fixed-source','127.0.0.2@127.0.0.9#34001'),('empty-source','127.0.0.2@'),('empty-interface','127.0.0.2@@127.0.0.9')]:
            add(directive+'-service-'+label,directive+'='+endpoint+'\n',sys_files={'/etc/hosts':HOSTS},local_upstream=label=='name-legacy',no_upstream=label=='named-all-filtered')
    for option in ('server','local'):
        add(option+'-multi-domain',option+'=/one.endpoint.test/two.endpoint.test/multi.endpoint.test\n',('one.endpoint.test','two.endpoint.test','other.endpoint.test'),sys_files={'/etc/hosts':HOSTS})
        add(option+'-wildcard',option+'=/*endpoint.test/127.0.0.2\n'+option+'=/*.labels.test/127.0.0.3\n',('badendpoint.test','x.labels.test','badlabels.test','labels.test'))
        add(option+'-markers',option+'=/local.endpoint.test/\n'+option+'=//127.0.0.2\n',('local.endpoint.test','dotless','other.endpoint.test'))
    for prefix in ['192.0.2.0/24','192.0.2.128/25','192.0.2.7/32','192.0.2.7/0','2001:db8::/64','2001:db8::/65','2001:db8::1/128']:
        add('reverse-'+prefix.replace(':','_').replace('/','-'),'rev-server='+prefix+',127.0.0.2\n',(ipaddress.ip_address(prefix.split('/')[0]).reverse_pointer,'129.2.0.192.in-addr.arpa','one.endpoint.test'),expected_start=not prefix.endswith('/0'),expected_test=1 if prefix.endswith('/0') else 0)
    add('reverse-hostname','rev-server=192.0.2.0/24,multi.endpoint.test\n',('7.2.0.192.in-addr.arpa',),sys_files={'/etc/hosts':HOSTS})
    for order in ('before','after'):
        text='query-port=34003\nserver=127.0.0.2\n' if order=='before' else 'server=127.0.0.2\nquery-port=34003\n'
        add('global-port-'+order,text,expected_source_port=34003)
    add('osport-explicit-zero','query-port=0\nserver=127.0.0.2\n',names=('one.endpoint.test','two.endpoint.test'),same_udp_port=True)
    add('osport-zero-then-fixed','query-port=34003\nserver=127.0.0.2\n',argv=['--query-port=0'],expected_source_port=34003)
    for source in ('127.0.0.9','lo','lo@127.0.0.9'):
        add('explicit-source-over-global-'+source.replace('@','-'),'query-port=34003\nserver=127.0.0.2@'+source+'\n',forbidden_udp_port=34003)
    add('fixed-source-over-global','query-port=34003\nserver=127.0.0.2@127.0.0.9#34004\n',expected_source_port=34004)
    add('same-fixed-source-destinations','server=127.0.0.2@127.0.0.9#34004\nserver=127.0.0.3@127.0.0.9#34004\nall-servers\n',expected_source_port=34004,same_udp_port=True)
    add('same-fixed-port-two-families','server=127.0.0.2@127.0.0.9#34004\nserver=::1@::1#34004\nall-servers\n',expected_source_port=34004)
    for width in (1,2,29,30):
        add('range-width-'+str(width),'min-port=34100\nmax-port='+str(34099+width)+'\nserver=127.0.0.2\n',names=tuple('repeat'+str(i)+'.endpoint.test' for i in range(4)),source_range=[34100,34099+width])
    add('range-one-occupied','min-port=34100\nmax-port=34101\nserver=127.0.0.2\n',occupied_ports=[34100],source_range=[34101,34101])
    add('range-all-occupied','min-port=34100\nmax-port=34101\nserver=127.0.0.2\n',occupied_ports=[34100,34101],no_udp_upstream=True)
    add('range-fixed-override','min-port=34100\nmax-port=34100\nserver=127.0.0.2@127.0.0.9#34004\n',expected_source_port=34004)
    add('range-two-families','min-port=34100\nmax-port=34100\nserver=127.0.0.2\nserver=::1\nall-servers\n',source_range=[34100,34100])
    for limit in (0,1,2,3):
        add('allservers-port-limit-'+str(limit),'port-limit='+str(limit)+'\nserver=127.0.0.2\nserver=127.0.0.3\nserver=127.0.0.4\nall-servers\n',udp_unique_ports= max(1,min(3,limit)),udp_winner=1,expected_start=limit!=0,expected_test=1 if limit==0 else 0)
    add('pool-single-port-concurrent','min-port=34100\nmax-port=34100\nserver=127.0.0.2\n',actions=[dict(op='start-udp',id='first',name='first.endpoint.test'),dict(op='start-udp',id='second',name='second.endpoint.test'),dict(op='inject',id='second',server=0),dict(op='receive-udp',id='second',pending='second'),dict(op='inject',id='first',server=0),dict(op='receive-udp',id='first',pending='first')],source_range=[34100,34100],same_udp_port=True)
    add('file-mixed-directives','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/v4.endpoint.test\nrev-server=192.0.2.0/24,multi.endpoint.test\nserver=/two.endpoint.test/127.0.0.3\nserver=/local.endpoint.test/\n'},names=('one.endpoint.test','7.2.0.192.in-addr.arpa','two.endpoint.test','local.endpoint.test'),sys_files={'/etc/hosts':HOSTS})
    add('file-errors-continue','servers-file=/m2/files/servers\n',files={'servers':'server=/bad.endpoint.test/::1%missing\nserver=/one.endpoint.test/v4.endpoint.test\nserver=/badsource.endpoint.test/127.0.0.2@::1\nserver=/two.endpoint.test/127.0.0.3\n'},names=('one.endpoint.test','two.endpoint.test','bad.endpoint.test','badsource.endpoint.test'),sys_files={'/etc/hosts':HOSTS},diagnostics=True)
    add('file-partial-hostname-scope','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/mixed.endpoint.test%missing\nserver=/two.endpoint.test/127.0.0.3\n'},names=('one.endpoint.test','two.endpoint.test'),sys_files={'/etc/hosts':HOSTS},diagnostics=True)
    add('file-hosts-hup-no-auto','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/v4.endpoint.test\n'},sys_files={'/etc/hosts':HOSTS},actions=[probe('initial','one.endpoint.test'),dict(op='write-system',path='/etc/hosts',text='127.0.0.3 v4.endpoint.test\n'),probe('no-auto','one.endpoint.test'),signal_reload(),probe('changed','one.endpoint.test')])
    add('file-source-snapshot','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2@127.0.0.9#34004\n'},actions=[dict(op='connect',id='held'),probe('old','old.endpoint.test',transports=['held']),write('servers','server=127.0.0.3@127.0.0.8#34005\n'),signal_reload(),probe('parent','parent.endpoint.test'),probe('child','child.endpoint.test',transports=['held']),dict(op='disconnect',id='held'),probe('fresh','fresh.endpoint.test')])
    add('endpoint-port-zero','server=127.0.0.2#0\n',no_upstream=True)
    add('endpoint-port-65535','server=127.0.0.2#65535\n',upstream_port=65535)
    add('osport-explicit-source-zero','query-port=0\nserver=127.0.0.2@127.0.0.9#0\n',names=('one.endpoint.test','two.endpoint.test'),same_udp_port=True)
    add('low-source-port-nonroot','server=127.0.0.2@127.0.0.9#79\n',user='dnsmasq',group='dnsmasq',expected_source_port=79)
    add('low-global-port-nonroot-file','query-port=77\nservers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2\n'},user='dnsmasq',group='dnsmasq',expected_source_port=77)
    for mode in ('wildcard','bind-interfaces','bind-dynamic'):
        add('occupied-fixed-'+mode,'server=127.0.0.2@127.0.0.1#34004\n'+('' if mode=='wildcard' else mode+'\n'),occupied_ports=[34004],expected_start=mode!='bind-interfaces',no_upstream=True)
    add('bad-source-address-failover','server=127.0.0.2@192.0.2.99\nserver=127.0.0.3\n')
    add('bad-source-interface-failover','server=127.0.0.2@missing_endpoint_if\nserver=127.0.0.3\n')
    add('bad-fixed-source-only-one-removed','server=127.0.0.2@192.0.2.99#34004\nserver=127.0.0.3\n')
    add('same-fixed-port-distinct-addresses','server=127.0.0.2@127.0.0.9#34004\nserver=127.0.0.3@127.0.0.8#34004\nall-servers\n',expected_source_port=34004)
    add('pool-overflow-incompatible','dns-forward-max=4\nserver=/one.endpoint.test/127.0.0.2@127.0.0.9\nserver=/two.endpoint.test/127.0.0.3@127.0.0.8\nserver=/three.endpoint.test/127.0.0.4@127.0.0.7\n',actions=[dict(op='start-udp',id='one',name='one.endpoint.test'),dict(op='start-udp',id='two',name='two.endpoint.test'),dict(op='start-udp',id='three',name='three.endpoint.test'),dict(op='inject',id='three',server=2,capture_server=2),dict(op='receive-udp',id='three',pending='three'),dict(op='inject',id='two',server=1,capture_server=1),dict(op='receive-udp',id='two',pending='two'),dict(op='inject',id='one',server=0,capture_server=0),dict(op='receive-udp',id='one',pending='one')])
    add('pool-capacity-compatible','dns-forward-max=4\nserver=127.0.0.2\n',actions=[dict(op='start-udp',id=name,name=name+'.endpoint.test') for name in ('one','two','three')]+[action for name in ('three','two','one') for action in (dict(op='inject',id=name,server=0),dict(op='receive-udp',id=name,pending=name))],udp_unique_ports=2)
    add('source-fixed-repeated-hup','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2@127.0.0.9#34004\n'},actions=[action for i in range(4) for action in (probe('before'+str(i),str(i)+'.endpoint.test',transports=['udp']),signal_reload())],same_udp_port=True,expected_source_port=34004)
    add('shared-socket-invalid-replies','min-port=34100\nmax-port=34100\nserver=127.0.0.2\n',injections=['wrong-id','wrong-name','wrong-type','short','valid'],actions=[dict(op='start-udp',id='held',name='held.endpoint.test')]+[action for i,mode in enumerate(('wrong-id','wrong-name','wrong-type','short')) for action in (dict(op='inject',id='held',server=0),dict(op='receive-udp',id='invalid'+str(i),pending='held',expect_timeout=True))]+[dict(op='inject',id='held',server=0),dict(op='receive-udp',id='valid',pending='held')],source_range=[34100,34100])
    add('shared-socket-unrelated-source','min-port=34100\nmax-port=34100\nserver=127.0.0.2\n',actions=[dict(op='start-udp',id='held',name='held.endpoint.test'),dict(op='inject',id='held',server=1),dict(op='receive-udp',id='wrong-source',pending='held',expect_timeout=True),dict(op='inject',id='held',server=0),dict(op='receive-udp',id='valid',pending='held')],source_range=[34100,34100])
    add('late-reply-after-server-retired','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2\n'},actions=[dict(op='start-udp',id='held',name='held.endpoint.test'),write('servers',''),signal_reload(),dict(op='inject',id='held',server=0),dict(op='receive-udp',id='late',pending='held',expect_timeout=True),write('servers','server=127.0.0.3\n'),signal_reload(),probe('recovered','fresh.endpoint.test')])
    add('fixed-new-slot-reallocates','servers-file=/m2/files/servers\n',files={'servers':'server=/old.test/127.0.0.2@127.0.0.9#34004\n'},actions=[probe('old','old.test'),write('servers','server=/new.test/127.0.0.3@127.0.0.8#34005\n'),signal_reload(),probe('new','new.test')])
    add('shared-recvfrom-eio','min-port=34100\nmax-port=34100\nserver=127.0.0.2\n',recv_fault=True,actions=[dict(op='start-udp',id='first',name='first.endpoint.test'),dict(op='start-udp',id='second',name='second.endpoint.test'),dict(op='inject',id='second',server=0),dict(op='receive-udp',id='second',pending='second'),dict(op='inject',id='first',server=0),dict(op='receive-udp',id='first',pending='first')],source_range=[34100,34100],same_udp_port=True)
    add('diagnostic-fixed-bind','server=127.0.0.2@192.0.2.99#34004\nserver=127.0.0.3\n',debug=True,source_diagnostics=True)
    add('diagnostic-random-bind','server=127.0.0.2@192.0.2.99\nserver=127.0.0.3\n',debug=True,source_diagnostics=True)
    add('diagnostic-random-interface','server=127.0.0.2@missing_endpoint_if\nserver=127.0.0.3\n',debug=True,source_diagnostics=True)
    add('inherited-nofile-pool-cap','dns-forward-max=40\nserver=127.0.0.2\n',inherited_nofile=40,actions=[dict(op='start-udp',id='q'+str(i),name='q'+str(i)+'.endpoint.test') for i in range(24)]+[action for i in reversed(range(24)) for action in (dict(op='inject',id='q'+str(i),server=0),dict(op='receive-udp',id='q'+str(i),pending='q'+str(i)))],udp_unique_ports=13)
    add('range-inclusive-ends','min-port=34100\nmax-port=34101\nserver=127.0.0.2\n',names=tuple('bound'+str(i)+'.endpoint.test' for i in range(64)),source_range=[34100,34101],range_ends=True)
    add('source-interface-cached-index','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2@lo\n'},actions=[probe('before','before.endpoint.test'),write('servers','server=127.0.0.2@missing_endpoint_if\n'),signal_reload(),probe('after','after.endpoint.test')])
    add('source-interface-cleared-index','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2@lo\n'},actions=[probe('before','before.endpoint.test'),write('servers','server=127.0.0.2\n'),signal_reload(),probe('after','after.endpoint.test')])
    add('source-ipv6-interface','server=::1@lo\n')
    add('source-ipv6-address-interface','server=::1@lo@::1\n')
    resolver_files={'/etc/hosts':'','/etc/resolv.conf':'nameserver 127.0.0.2\noptions timeout:1 attempts:1\n'}
    add('system-resolver-startup','server=lookup.endpoint.test\n',sys_files=resolver_files,resolver_fixture=True)
    add('system-resolver-nxdomain','server=lookup.endpoint.test\n',sys_files=resolver_files,resolver_fixture=True,resolver_rcode=3,expected_start=False,expected_test=1)
    add('system-resolver-servfail','server=lookup.endpoint.test\n',sys_files=resolver_files,resolver_fixture=True,resolver_rcode=2,expected_start=False,expected_test=1)
    add('system-resolver-before-invalid-row','server=lookup.endpoint.test\ninvalid-option=1\n',sys_files=resolver_files,resolver_fixture=True,expected_start=False,expected_test=1)
    add('file-partial-success-before-scope-error','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/partial.endpoint.test%missing\nserver=/two.endpoint.test/127.0.0.3\n'},sys_files={'/etc/hosts':'127.0.0.2 partial.endpoint.test\n2001:db8::53 partial.endpoint.test\n'},names=('one.endpoint.test','two.endpoint.test'),diagnostics=True)
    add('zero-server-preallocation-bound','bind-interfaces\nserver=0.0.0.0@192.0.2.99#34004\n',expected_start=False,no_upstream=True)
    reuse_actions=[]
    for round_index in range(2):
        for i in range(24):
            ident=f'r{round_index}-q{i}'
            reuse_actions.append(dict(op='start-udp',id=ident,name=ident+'.endpoint.test'))
        for i in reversed(range(24)):
            ident=f'r{round_index}-q{i}'
            reuse_actions.extend([dict(op='inject',id=ident,server=0),dict(op='receive-udp',id=ident,pending=ident)])
    add('pool-slot-reuse-round-robin','dns-forward-max=40\nserver=127.0.0.2\n',inherited_nofile=40,port_epochs=True,actions=reuse_actions)
    add('pool-retired-source-reference','dns-forward-max=2\nall-servers\nservers-file=/m2/files/servers\n',no_resolv=False,default_resolv=True,files={'resolv':'nameserver 127.0.0.2\n','servers':'server=127.0.0.3\n'},actions=[dict(op='start-udp',id='held',name='held.endpoint.test',upstream_count=2),write('resolv',''),dict(op='pause',seconds=.2),probe('new','new.endpoint.test',transports=['udp']),dict(op='inject',id='held',server=1,capture_server=0),dict(op='receive-udp',id='held',pending='held')],udp_unique_ports=2)
    mixed_config=('servers-file=/m2/files/servers\ninterface=lo\nno-ping\n'
                  'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,600\n'
                  'dhcp-option=224,owner-witness\ndhcp-leasefile=/m2/files/leases\n'
                  'enable-tftp\ntftp-root=/m2/files\n')
    add('slow-lookup-owner-dns-dhcp-tftp',mixed_config,resolver_fixture=True,resolver_delay=.5,owner_progress=True,
        sys_files={'/etc/hosts':'','/etc/resolv.conf':'nameserver 127.0.0.2\noptions timeout:3 attempts:1\n'},
        files={'servers':'server=127.0.0.3\n','payload':'T'*1400},
        actions=[write('servers','server=lookup.endpoint.test\n'),signal_reload(),
                 probe('during','ready.files.test'),dict(op='dhcp-inform',id='during-dhcp'),dict(op='tftp-start',id='transfer'),dict(op='tftp-finish',id='transfer'),
                 dict(op='pause',seconds=.4),probe('resolved','resolved.endpoint.test')])
    return cases


class SourceCapture:
    instances=[]


def run_service_side(root, side, case, folder):
    import m5_dns_files as files
    from dns_service_probe import exact_read, read_name
    parent_pid=None
    original_identity=files.process_identity
    def identity(root,pid):
        nonlocal parent_pid
        parent_pid=pid
        status=Path('/proc',str(pid),'status').read_text().splitlines()
        uid=int(next(line.split()[1] for line in status if line.startswith('Uid:')))
        expected_uid=next(int(line.split(':')[2]) for line in (root/'etc/passwd').read_text().splitlines() if line.split(':')[0]==case.get('user','root'))
        cap_eff=next(line.split()[1] for line in status if line.startswith('CapEff:'))
        return dict(original_identity(root,pid),cap_eff=cap_eff,threads=len(list(Path('/proc',str(pid),'task').iterdir())),uid=uid,expected_uid=expected_uid)
    files.process_identity=identity
    original_upstream=files.FileUpstream
    class Captured(original_upstream):
        def __init__(self,*args):
            self.source_events=[]
            args=(*args[:-1],case.get("upstream_port",args[-1]))
            if case.get('resolver_fixture') and args[1]=='127.0.0.2':
                fixtures=list(args[0])
                rcode=case.get('resolver_rcode',0)
                for kind in (1,28):
                    fixture={'name':'lookup.endpoint.test','type':kind,'rcode':rcode,'reply':'127.0.0.3' if kind==1 else '::1'}
                    if kind==28 or rcode: fixture['records']=[]
                    fixtures.append(fixture)
                args=(fixtures,*args[1:])
            super().__init__(*args)
            if case.get('injections') or case.get('recv_fault'):
                upstream=self;delegate=self.udp
                class InjectionSocket:
                    index=0
                    def __getattr__(self,name): return getattr(delegate,name)
                    def sendto(self,packet,peer):
                        if threading.current_thread() is threading.main_thread():
                            if case.get('recv_fault') and not self.index:
                                matches=[]
                                for line in Path('/proc',str(parent_pid),'net/udp').read_text().splitlines()[1:]:
                                    fields=line.split()
                                    if int(fields[1].split(':')[1],16)==34100: matches.append(fields[9])
                                descriptors=[int(path.name) for path in Path('/proc',str(parent_pid),'fd').iterdir() if os.readlink(path)=='socket:['+matches[0]+']']
                                if len(descriptors)!=1: raise AssertionError('source fd not unique')
                                output=folder/'recv-fault.json'
                                tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--inject-recvfrom-error',str(parent_pid),str(descriptors[0]),str(output)])
                                deadline=time.monotonic()+2
                                while not Path(str(output)+'.ready').exists():
                                    if tracer.poll() is not None or time.monotonic()>deadline: raise AssertionError('recv fault tracer failed to attach')
                                    time.sleep(.001)
                                sent=delegate.sendto(packet,peer)
                                tracer.wait(timeout=2)
                                upstream.recv_fault=json.loads(output.read_text())
                                if tracer.returncode or not upstream.recv_fault.get('injected'): raise AssertionError('recv error not injected')
                                self.index+=1
                                return sent
                            modes=case.get('injections',['valid'])
                            mode=modes[min(self.index,len(modes)-1)];self.index+=1
                            packet=bytearray(packet)
                            if mode=='wrong-id': packet[0]^=1
                            elif mode=='wrong-name': packet[13]^=1
                            elif mode=='wrong-type': struct.pack_into('!H',packet,read_name(packet,12)[1],28)
                            elif mode=='short': packet=packet[:5]
                            upstream.injected.append(dict(mode=mode,peer=list(peer),wire=bytes(packet).hex()))
                        return delegate.sendto(packet,peer)
                self.injected=[];self.udp=InjectionSocket()
            SourceCapture.instances.append(self)
        def udp_loop(self):
            while not self.stop.is_set():
                try:
                    packet,peer=self.udp.recvfrom(65535)
                    response=self.answer(packet,'udp')
                    host=read_name(packet,12)[0]
                    resolving=case.get('resolver_fixture') and host=='lookup.endpoint.test' and self.host=='127.0.0.2'
                    self.source_events.append(dict(transport='resolver' if resolving else 'udp',peer=list(peer),destination=list(self.udp.getsockname()),name=host,wire=packet.hex()))
                    event=self.source_events[-1]
                    if resolving and case.get('resolver_delay'): time.sleep(case['resolver_delay'])
                    self.captured.append((packet,peer,response))
                    if self.probes.get((read_name(packet,12)[0],struct.unpack_from('!H',packet,read_name(packet,12)[1])[0]),{}).get('drop_all'): continue
                    if 'udp_winner' in case and self.host!=['127.0.0.2','127.0.0.3','127.0.0.4'][case['udp_winner']]: time.sleep(.05)
                    if resolving: event['reply_at']=time.monotonic()
                    self.udp.sendto(response,peer)
                except socket.timeout: continue
                except OSError:
                    if not self.stop.is_set(): self.errors.append('UDP socket failure')
                except Exception as error: self.errors.append(repr(error))
        def connection(self,client):
            try:
                with client:
                    client.settimeout(2)
                    while not self.stop.is_set():
                        packet=exact_read(client,struct.unpack('!H',exact_read(client,2))[0])
                        response=self.answer(packet,'tcp')
                        self.source_events.append(dict(transport='tcp',peer=list(client.getpeername()),destination=list(client.getsockname()),name=read_name(packet,12)[0],wire=packet.hex()))
                        client.sendall(struct.pack('!H',len(response))+response)
            except (ConnectionError,OSError,EOFError): pass
            except Exception as error: self.errors.append(repr(error))
    files.FileUpstream=Captured
    SourceCapture.instances=[]
    occupied=[]
    original_socket=socket.socket
    progress_receipts=[]
    def lookup_pending():
        return any(row['transport']=='resolver' and 'reply_at' not in row for upstream in SourceCapture.instances for row in upstream.source_events)
    class ProgressSocket(original_socket):
        def record(self,data,peer=None):
            if case.get('owner_progress') and threading.current_thread() is threading.main_thread() and data:
                if peer is None:
                    try: peer=self.getpeername()
                    except OSError: peer=None
                progress_receipts.append({'pending':lookup_pending(),'tcp':self.type==socket.SOCK_STREAM,'peer':list(peer) if peer else None,'prefix':data[:4].hex(),'bytes':len(data),'at':time.monotonic()})
        def recv(self,*args):
            data=super().recv(*args);self.record(data);return data
        def recvfrom(self,*args):
            result=super().recvfrom(*args);self.record(result[0],result[1]);return result
        def recvmsg(self,*args):
            result=super().recvmsg(*args);self.record(result[0],result[3]);return result
    class ReservedListener(original_socket):
        def bind(self,address):
            if address==('127.0.0.1',0):
                self.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                address=('127.0.0.1',15353)
            return super().bind(address)
    def fixture_socket(*args,**kwargs):
        return ReservedListener() if not args and not kwargs else (ProgressSocket(*args,**kwargs) if case.get("owner_progress") else original_socket(*args,**kwargs))
    files.socket.socket=fixture_socket
    original_dhcp_receive=files.dhcp_wire.receive
    def receive_dhcp(*args,**kwargs):
        # C's blocking lookup cannot service this request. Its successful ACK
        # remains the byte reference after resolution; Rust receives during it.
        if side=='c' and case.get('owner_progress'): time.sleep(1.5)
        return original_dhcp_receive(*args,**kwargs)
    files.dhcp_wire.receive=receive_dhcp
    original_command=files.command
    def wrapped_command(root,side,*args):
        command=original_command(root,side,*case.get('argv',[]),*('-d' if arg=='-k' and case.get('debug') else arg for arg in args))
        if case.get('inherited_nofile'): command=['prlimit','--nofile='+str(case['inherited_nofile'])+':'+str(case['inherited_nofile']),*command]
        return command
    files.command=wrapped_command
    try:
        for port in case.get('occupied_ports',[]):
            bound=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);bound.bind(('0.0.0.0',port));occupied.append(bound)
        result=files.run_side(root,side,case,folder)
    finally:
        for bound in occupied: bound.close()
        files.command=original_command
        files.FileUpstream=original_upstream
        files.process_identity=original_identity
        files.socket.socket=original_socket
        files.dhcp_wire.receive=original_dhcp_receive
    result['source_events']=[row for upstream in SourceCapture.instances for row in upstream.source_events]
    result['progress_receipts']=progress_receipts
    result['injected_packets']=[row for upstream in SourceCapture.instances for row in getattr(upstream,'injected',[])]
    result['recv_faults']=[upstream.recv_fault for upstream in SourceCapture.instances if hasattr(upstream,'recv_fault')]
    result['fixture_errors']=[error for upstream in SourceCapture.instances for error in upstream.errors]
    result['source_diagnostics']=[line.replace('dnsmasq-rs:','dnsmasq:') for line in result['stderr'].splitlines() if 'server socket' in line or 'ignoring nameserver' in line]
    result['source_guard_errors']=source_guard_errors(result,case)
    save(folder/'observed.json',result)
    return result


def source_guard_errors(result,case):
    errors=[]
    if not result['startup']['ready']: return errors
    if result.get('identity',{}).get('uid')!=result.get('identity',{}).get('expected_uid'): errors.append('daemon UID does not match configured user')
    if result.get('identity',{}).get('threads')!=1: errors.append('parent daemon is not one thread')
    if case.get('recv_fault') and (len(result.get('recv_faults',[]))!=1 or not result['recv_faults'][0].get('injected')): errors.append('actual recvfrom EIO fault missing')
    udp=[row for row in result['source_events'] if row['transport']=='udp']
    tcp=[row for row in result['source_events'] if row['transport']=='tcp']
    ports={row['peer'][1] for row in udp}
    if case.get('expected_source_port') is not None and any(port!=case['expected_source_port'] for port in ports): errors.append('fixed source port differs')
    if case.get('forbidden_udp_port') in ports: errors.append('explicit source inherited global port')
    if case.get('source_range') and any(not case['source_range'][0]<=port<=case['source_range'][1] for port in ports): errors.append('source outside inclusive range')
    if case.get('range_ends') and ports!=set(case['source_range']): errors.append('both inclusive range ends not observed')
    if case.get('same_udp_port') and len(ports)!=1: errors.append('shared source uses different ports')
    if case.get('udp_unique_ports') is not None and len(ports)!=case['udp_unique_ports']: errors.append('port-limit allocation differs')
    if case.get('no_udp_upstream') and udp: errors.append('exhausted range still sent UDP')
    if not case.get('no_upstream') and not case.get('no_udp_upstream') and case.get('expected_start',True) and not udp and any(action['op']=='query' for action in case['actions']): errors.append('no actual upstream source capture')
    if any(row['peer'][1] in [case.get('expected_source_port'),*(case.get('source_range') or [])] for row in tcp): errors.append('TCP inherited configured UDP source port/range')
    return errors



def source_projection(observed,case):
    ports={};result=[]
    exact=set(case.get('source_range') or [])
    if 'expected_source_port' in case: exact.add(case['expected_source_port'])
    for original in observed['source_events']:
        row=copy.deepcopy(original);row.pop('wire',None);row.pop('reply_at',None)
        port=row['peer'][1]
        key=(row['transport'],port,row['name'].split('-')[0] if case.get('port_epochs') else '')
        sequential_range=row['transport']=='udp' and case.get('source_range') and not case.get('same_udp_port') and 'udp_unique_ports' not in case
        if sequential_range: row['peer'][1]='in-range'
        elif port not in exact:
            if key not in ports: ports[key]='port'+str(len(ports))
            row['peer'][1]=ports[key]
        if len(row['peer'])>3: row['peer'][3]=bool(row['peer'][3])
        if len(row['destination'])>3: row['destination'][3]=bool(row['destination'][3])
        result.append(row)
    return result


def controls():
    sample={'startup':{'ready':True},'identity':{'uid':0,'expected_uid':0,'threads':1},'source_events':[{'transport':'udp','peer':['127.0.0.9',34004],'destination':['127.0.0.2',53],'name':'one.test','wire':'abcd'}]}
    assert not source_guard_errors(sample,{})
    tests={}
    wrong=copy.deepcopy(sample);wrong['source_events'][0]['peer'][0]='127.0.0.8'
    tests['source-address-mutation']=source_projection(sample,{})!=source_projection(wrong,{})
    wrong=copy.deepcopy(sample);wrong['source_events'][0]['destination'][0]='127.0.0.3'
    tests['destination-address-mutation']=source_projection(sample,{})!=source_projection(wrong,{})
    wrong=copy.deepcopy(sample);wrong['source_events'][0]['peer'][1]=34005
    tests['fixed-port-mutation']=bool(source_guard_errors(wrong,{'expected_source_port':34004}))
    tests['range-membership-mutation']=bool(source_guard_errors(wrong,{'source_range':[34004,34004]}))
    shared=copy.deepcopy(sample);shared['source_events'].append(copy.deepcopy(shared['source_events'][0]))
    shared['source_events'][1]['peer'][1]=34005
    tests['shared-port-mutation']=bool(source_guard_errors(shared,{'same_udp_port':True}))
    tests['port-limit-mutation']=bool(source_guard_errors(sample,{'udp_unique_ports':2}))
    missing=copy.deepcopy(sample);missing['source_events']=[]
    tests['missing-expanded-endpoint']=bool(source_guard_errors(missing,{'actions':[{'op':'query'}]}))
    assert all(tests.values()),tests
    return tests

def run_service(args, cases):
    import m5_dns_files as files
    args.out.mkdir(parents=True)
    # Keep probe/listener allocation outside configured DNS source ranges.
    subprocess.run(['sysctl','-q','-w','net.ipv4.ip_local_port_range=40000 60999','net.ipv4.ip_unprivileged_port_start=1024'],check=True)
    driver=args.out/'driver';driver.mkdir()
    for name in ('m5_dns_endpoints.py','m5_dns_endpoints.json','m5_dns_files.py','m5_option_matrix.py','m5_option_matrix_probes.py','m5_dhcp_tags_options.py','dhcp_boot_service_diff.py','dns_service_probe.py','m2_rootfs.py','run_isolated.sh'):
        shutil.copy2(Path(__file__).with_name(name),driver/name)
    sides=['c','rust'] if args.side=='both' else ['c']
    roots={side:prepare(args.image_root,None,args.out/side,args.rust) for side in sides}
    save(args.out/'schedule.json',cases)
    report={'mode':'service','fixture_environment':{'listener_port':15353,'ephemeral_range':[40000,60999],'privileged_port_start':1024},'source_commit':args.source_commit,'rust_sha256':sha256(args.rust),'rust_bytes':args.rust.stat().st_size,'c_sha256':STOCK_SHA256,'comparison_executed':args.side=='both','cases':[],'failures':[],'closed_options':[],'negative_controls':controls(),'reference_differences':[]}
    for case in cases:
        folder=args.out/case['id'];folder.mkdir()
        row={'id':case['id'],'failures':[]}
        try:
            observed={side:run_service_side(roots[side],side,case,folder/side) for side in sides}
            if observed['c']['syntax']['exit']!=case.get('expected_test',0): row['failures'].append(dict(phase='c-syntax-calibration',observed=observed['c']['syntax']))
            if observed['c']['startup']['ready'] != case.get('expected_start',True): row['failures'].append(dict(phase='c-startup-calibration',observed=observed['c']['startup']))
            timeout_ids={action['id']+':udp-async' for action in case['actions'] if action.get('expect_timeout')}
            if any((entry.get('response') is None)!=(entry['id'] in timeout_ids) for entry in observed['c']['rows'] if entry['id'].endswith('udp-async')): row['failures'].append(dict(phase='c-async-calibration',error='missing awaited UDP reply'))
            if args.side=='both':
                comparison=copy.deepcopy(observed)
                compared_case=copy.deepcopy(case)
                if case.get('owner_progress'):
                    c_health=next(record for record in observed['c']['rows'] if record['id']=='during:udp')
                    rust_health=next(record for record in observed['rust']['rows'] if record['id']=='during:udp')
                    if c_health['response'] is not None or rust_health['response'] is None: row['failures'].append(dict(phase='blocked-reference-owner',c=c_health,rust=rust_health))
                    report['reference_differences'].append({'case':case['id'],'boundary':'OWNER-01','contract':'C blocks its owner in getaddrinfo; Rust resolves in an isolated child while DNS/DHCP/TFTP continue.','c_health':c_health,'rust_health':rust_health})
                    for side in comparison.values():
                        side['rows']=[record for record in side['rows'] if record['id']!='during:udp']
                        for record in side['rows']:
                            for upstream in record.get('upstreams',[]): upstream['events']=[event for event in upstream['events'] if event['name']!='lookup.endpoint.test']
                    for action in compared_case['actions']:
                        if action.get('id')=='during': action['transports']=['tcp']
                row['failures'].extend(files.compare(comparison['c'],comparison['rust'],compared_case))
                if case.get('source_diagnostics') and observed['c']['source_diagnostics']!=observed['rust']['source_diagnostics']: row['failures'].append(dict(phase='source-diagnostic',c=observed['c']['source_diagnostics'],rust=observed['rust']['source_diagnostics']))
                c,rust=(source_projection(observed[side],case) for side in ('c','rust'))
                if c!=rust: row['failures'].append(dict(phase='source-tuples',c=c,rust=rust))
            for side,result in observed.items():
                row['failures'].extend(dict(phase='source-witness',side=side,error=error) for error in result['source_guard_errors']+result['fixture_errors'])
            if case.get('owner_progress') and args.side=='both':
                receipts=[record for record in observed['rust']['progress_receipts'] if record['pending']]
                witnessed={
                    'udp_dns':any(record['peer'] and record['peer'][1]==15353 and not record['tcp'] for record in receipts),
                    'tcp_dns':any(record['peer'] and record['peer'][1]==15353 and record['tcp'] for record in receipts),
                    'dhcp':any(record['peer'] and record['peer'][1]==67 for record in receipts),
                    'tftp':any(record['prefix'].startswith('0003') and not record['tcp'] for record in receipts)}
                if not all(witnessed.values()): row['failures'].append(dict(phase='owner-progress',witnessed=witnessed))
            row['rows']=len(observed['c']['rows'])
        except Exception as error: row['failures'].append(dict(phase='infrastructure',error=repr(error)))
        report['cases'].append(row)
        report['failures'].extend(dict(case=case['id'],**failure) for failure in row['failures'])
        save(args.out/'progress.json',report)
    save(args.out/'result.json',report)
    print(json.dumps({'cases':len(cases),'failures':len(report['failures']),'closed_options':[]}))
    return int(bool(report['failures']))


def inject_recvfrom_error(pid,descriptor,output):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    class Iovec(ctypes.Structure): _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
    def ptrace(request,address=0,data=0):
        ctypes.set_errno(0)
        result=libc.ptrace(ctypes.c_uint(request),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if result==-1 and ctypes.get_errno(): raise OSError(ctypes.get_errno(),'ptrace')
        return result
    registers=(ctypes.c_ulonglong*34)()
    def regs(write=False):
        vector=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(vector))
    report={'pid':pid,'descriptor':descriptor,'injected':False,'events':[]};attached=False
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;ptrace(0x4200,0,1)
        Path(str(output)+'.ready').write_text('attached\n')
        active=False
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            if not os.WIFSTOPPED(status): raise AssertionError('tracee exited')
            if os.WSTOPSIG(status)!=(signal.SIGTRAP|0x80): continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                active=registers[8]==207 and registers[0]==descriptor
                if active:
                    syscall=ctypes.c_int(-1);vector=Iovec(ctypes.addressof(syscall),ctypes.sizeof(syscall))
                    ptrace(0x4205,0x404,ctypes.addressof(vector))
                    report['events'].append({'entry':'recvfrom','descriptor':descriptor,'syscall':207})
            elif info[0]==2 and active:
                registers[0]=(1<<64)-errno.EIO;regs(write=True)
                report['events'].append({'exit':-errno.EIO});report['injected']=True
                ptrace(17);attached=False;break
    finally:
        if attached:
            try: ptrace(17)
            except OSError: pass
        save(Path(output),report)
    return 0

def main():
    if len(sys.argv)==5 and sys.argv[1]=='--inject-recvfrom-error': return inject_recvfrom_error(int(sys.argv[2]),int(sys.argv[3]),sys.argv[4])
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','both'],default='both');parser.add_argument('--case',action='append');parser.add_argument('--mode',choices=['syntax','service'],default='syntax')
    args=parser.parse_args();assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert not args.out.exists() and 'private' in args.out.parts
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if args.mode=='service':
        selected=[case for case in service_cases() if not args.case or case['id'] in args.case]
        assert selected and (not args.case or len(selected)==len(set(args.case)))
        return run_service(args,selected)
    args.out.mkdir(parents=True)
    cases=[x for x in syntax_cases() if not args.case or x['id'] in args.case]
    assert cases and (not args.case or len(cases)==len(set(args.case)))
    save(args.out/'schedule.json',cases)
    driver=args.out/'driver';driver.mkdir()
    for filename in ['m5_dns_endpoints.py','m5_dns_endpoints.json','m2_rootfs.py','run_isolated.sh']:
        shutil.copy2(Path(__file__).with_name(filename),driver/filename)
    root=prepare(args.image_root,None,args.out/'image',args.rust)
    report={'mode':'syntax-only','comparison_executed':args.side=='both','source_commit':args.source_commit,
            'rust_sha256':sha256(args.rust),'c_sha256':STOCK_SHA256,'tool_sha256':sha256(__file__),
            'cases':[],'failures':[],'reference_defects':[],'closed_options':[]}
    for case in cases:
        sides={side:run_syntax(root,side,case,args.out/case['id']/side) for side in (['c','rust'] if args.side=='both' else ['c'])}
        if case.get('reference_defect'):
            report['reference_defects'].append({'case':case['id'],'sides':sides,'scope':'syntax-only; never run unsafe reference service'})
        elif args.side=='both' and normal(sides['c'])!=normal(sides['rust']):
            report['failures'].append({'case':case['id'],'sides':sides})
        report['cases'].append({'id':case['id'],'checks':case['checks'],'sides':sides})
        save(args.out/'progress.json',report)
    save(args.out/'result.json',report)
    print(json.dumps({'cases':len(cases),'failures':len(report['failures']),'reference_defects':report['reference_defects']}))
    return int(bool(report['failures']))
if __name__=='__main__': raise SystemExit(main())
