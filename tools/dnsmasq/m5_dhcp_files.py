#!/usr/bin/env python3
"""Exact-image DHCP static/dynamic file-bank family differential.

One isolated owner, existing packet/parser comparators, preserved raw wire and
file mutations. Directory semantics deliberately remain DHCP append semantics.
"""
from __future__ import annotations
import argparse
import copy
import ctypes
import errno
import platform
import re
import resource
import threading
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import m5_dhcp_tags_options as wire
from m2_rootfs import STOCK_SHA256,command,prepare,process_identity,sha256
from m5_helper import children
from m5_dns_files import partial_stream_error

MAC='02:00:00:00:00:01'
BASE='/m2/dhcp-files'


def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def option(code,value):return [code,value.hex()]


def scenarios():
    def packet(label,kind=1,**extra):return dict(op='packet',label=label,kind=kind,**extra)
    def write(name,text):return dict(op='write',path=name,text=text)
    def hup():return dict(op='hup')
    def inform(label):return packet(label,kind=8,ciaddr='127.0.0.40',prl=[224,225,43,60])
    def row(name,config,files,events,ids,**extra):return dict(name=name,config=config,files=files,events=events,boundaries=ids,**extra)
    rows=[
        row('static-host-reload','dhcp-hostsfile={base}/hosts',{'hosts':f'{MAC},127.0.0.30,first\n'},[
            packet('initial'),write('hosts',f'{MAC},127.0.0.31,second\n'),packet('before-hup'),hup(),packet('after-hup'),
            write('hosts',''),hup(),packet('empty-after-hup')],['HOST01','FILE02','RELOAD01']),
        row('dynamic-host-append','dhcp-hostsdir={base}/hosts',{'hosts/a':f'{MAC},127.0.0.30,first\n'},[
            packet('initial'),write('hosts/a',f'{MAC},127.0.0.31,second\n'),packet('rewritten-new-ip'),
            write('hosts/a','02:00:00:00:00:02,127.0.0.31,replacement\n'),packet('same-ip-old-selector'),
            packet('same-ip-new-selector',mac='020000000002'),write('hosts/a',''),packet('truncated-retains'),
            dict(op='unlink',path='hosts/a'),packet('deleted-retains'),hup(),packet('hup-removes')],['DYN01','DYN03','DYN04','DYN06','HOST02','RELOAD01']),
        row('static-option-reload','dhcp-option=224,inline\ndhcp-optsfile={base}/opts',{'opts':'224,first\n'},[
            inform('initial'),write('opts','224,second\n'),inform('before-hup'),hup(),inform('after-hup'),write('opts',''),hup(),inform('inline-after-clear')],['OPT01','OPT02','FILE02','RELOAD01','STATE04']),
        row('dynamic-option-append','dhcp-option=224,inline\ndhcp-optsdir={base}/opts',{'opts/a':'224,first\n'},[
            inform('initial'),write('opts/a','224,second\n'),inform('updated'),write('opts/a',''),inform('empty-retains'),
            dict(op='unlink',path='opts/a'),inform('deleted-retains'),hup(),inform('hup-inline')],['DYN01','DYN03','DYN05','DYN06','OPT02','STATE04']),
        row('static-host-directory-order','dhcp-hostsfile={base}/hosts',{'hosts/z':f'{MAC},127.0.0.31,last\n','hosts/a':f'{MAC},127.0.0.30,first\n'},
            [packet('alphabetical-precedence'),dict(op='unlink',path='hosts/z'),hup(),packet('removed-child')],['EXP01','EXP02']),
        row('dynamic-host-directory-order','dhcp-hostsdir={base}/hosts',{'hosts/z':f'{MAC},127.0.0.31,created-first\n','hosts/a':f'{MAC},127.0.0.30,created-second\n'},
            [packet('readdir-precedence')],['DYN01']),
        row('static-option-directory-order','dhcp-optsfile={base}/opts',{'opts/z':'224,last\n','opts/a':'224,first\n'},[inform('alphabetical-precedence')],['EXP01','OPT02']),
        row('dynamic-option-directory-order','dhcp-optsdir={base}/opts',{'opts/z':'224,created-first\n','opts/a':'224,created-second\n'},[inform('readdir-precedence')],['DYN01','OPT02']),
        row('host-duplicates-invalid','dhcp-host=02:00:00:00:00:02,127.0.0.30,inline\ndhcp-hostsfile={base}/hosts',
            {'hosts':f'{MAC},127.0.0.30,duplicate\n{MAC},127.0.0.31,valid-before\n02:GG:00:00:00:01\n{MAC},127.0.0.32,valid-after\n'},
            [packet('newest-valid-line'),packet('inline-ip-kept',mac='020000000002')],['HOST02','LEX01']),
        row('host-selector-reuse','dhcp-hostsfile={base}/hosts\ndhcp-option=tag:file,224,tagged',
            {'hosts':f'tag:lo,{MAC},127.0.0.30,set:file,named\n02:00:00:00:01:*,127.0.0.31,wild\nonlyname,127.0.0.32\n'},
            [packet('tagged',prl=[224]),packet('wildcard',mac='020000000102'),packet('name-only',mac='020000000202',extra=[option(12,b'onlyname')])],['HOST01']),
        row('option-grammar-reuse','dhcp-optsfile={base}/opts',{'opts':'tag:lo,224,tagged\noption:router,0.0.0.0\nvendor:PXEClient,20,vendor\nencap:172,17,nested\nvi-encap:13,17,enterprise\n'},
            [packet('all-encodings',kind=8,ciaddr='127.0.0.40',prl=[3,43,60,125,172,224],extra=[option(60,b'PXEClient')])],['OPT01','OPT02']),
        row('missing-static-files','dhcp-hostsfile={base}/missing-hosts\ndhcp-optsfile={base}/missing-opts\ndhcp-option=224,inline',{},[inform('inline-remains')],['FILE01','CFG02']),
        row('dynamic-create-dir-hup','dhcp-hostsdir={base}/missing',{},[
            packet('missing-dir'),dict(op='mkdir',path='missing'),write('missing/a',f'{MAC},127.0.0.30,created\n'),packet('not-watched-yet'),hup(),packet('hup-loads'),write('missing/b',f'{MAC},127.0.0.31,watched\n'),packet('watch-established')],['DYN02']),
        row('dynamic-rename-delete','dhcp-hostsdir={base}/hosts',{'hosts/seed':'# empty\n','incoming':f'{MAC},127.0.0.30,moved\n'},[
            dict(op='rename',path='incoming',to='hosts/live'),packet('rename-in'),dict(op='rename',path='hosts/live',to='outside'),packet('move-out-retained'),hup(),packet('hup-removes')],['DYN03','DYN06']),
        row('static-dynamic-priority','dhcp-hostsfile={base}/static\ndhcp-hostsdir={base}/dynamic',
            {'static':f'{MAC},127.0.0.30,static\n','dynamic/a':f'{MAC},127.0.0.31,dynamic\n'},[packet('dynamic-after-static'),hup(),packet('same-after-hup')],['RELOAD01']),
    ]
    rows.extend(extra_scenarios())
    rows.extend(remaining_scenarios())
    rows.extend(resource_scenarios())
    mapping = {
        'static-host-reload': ['HOST01/host-selectors', 'FILE02/static-no-live-watch', 'FILE02/hup-replace', 'FILE02/hup-empty-removes'],
        'dynamic-host-append': ['DYN04/host-live-add', 'DYN04/host-rewrite-same-ip', 'DYN04/host-rewrite-new-ip', 'DYN04/host-truncate-keeps-old', 'DYN06/host-delete-retained', 'DYN06/hup-after-delete'],
        'static-option-reload': ['OPT01/option-scalar-name', 'OPT02/option-duplicate-priority', 'FILE02/hup-replace'],
        'dynamic-option-append': ['DYN05/option-live-add', 'DYN05/option-rewrite-precedence', 'DYN05/option-empty-keeps-old', 'DYN06/option-delete-retained'],
        'static-host-directory-order': ['EXP01/static-dir-sorted', 'EXP01/static-line-order'],
        'dynamic-host-directory-order': ['DYN01/dynamic-initial-order'],
        'static-option-directory-order': ['EXP01/static-dir-sorted'],
        'dynamic-option-directory-order': ['DYN01/dynamic-initial-order'],
        'host-duplicates-invalid': ['HOST02/duplicate-inline-ip', 'HOST02/duplicate-file-ip', 'HOST02/duplicate-selector-new-ip', 'LEX01/malformed-middle'],
        'host-selector-reuse': ['HOST01/host-tags', 'HOST01/host-name-only', 'HOST01/host-selectors'],
        'option-grammar-reuse': ['OPT01/option-tags', 'OPT01/option-vendor-encap', 'OPT01/option-enterprise'],
        'missing-static-files': ['FILE01/missing-file', 'CFG02/test-skips-bank'],
        'dynamic-create-dir-hup': ['DYN02/missing-dir-start', 'DYN02/create-dir-then-hup'],
        'dynamic-rename-delete': ['DYN03/rename-in', 'DYN06/move-out-retained'],
        'static-dynamic-priority': ['RELOAD01/static-dynamic-priority'],
    }
    for scenario in rows:
        scenario.setdefault('cases', mapping.get(scenario['name'], []))
    return rows


def write_file(path, value):
    if isinstance(value, str): value={'text':value}
    if value.get('directory'):path.mkdir(exist_ok=True);return
    if value.get('fifo'):os.mkfifo(path);return
    if 'symlink' in value:
        path.unlink(missing_ok=True);path.symlink_to(value['symlink']);return
    if path.exists() and not path.is_file() and not path.is_dir():path.unlink()
    data=bytes.fromhex(value['hex']) if 'hex' in value else value.get('text','').encode()
    target=path.with_name(path.name+'.new') if value.get('atomic') else path
    target.write_bytes(data)
    if 'mode' in value:target.chmod(value['mode'])
    if target!=path:target.replace(path)


def extra_scenarios():
    def packet(label,kind=1,**fields):return dict(op='packet',label=label,kind=kind,**fields)
    def inform(label,**fields):return packet(label,8,ciaddr='127.0.0.40',prl=[3,15,26,43,60,119,125,172,224,225,226],**fields)
    def write(path,text,**fields):return dict(op='write',path=path,text=text,**fields)
    def action(op,**fields):return dict(op=op,**fields)
    def hup():return action('hup')
    def case(name,config,files,events,cases,**fields):
        return dict(name=name,config=config,files=files,events=events,cases=cases,boundaries=sorted({c.split('/')[0] for c in cases}),**fields)
    rows=[]
    rows.append(case('option-duplicate-tag-force','dhcp-option-force=226,forced\ndhcp-option=224,inline\ndhcp-optsfile={base}/opts',
        {'opts':'224,first\ntag:range,224,tagged\n224,last\n225,ordinary\n'},
        [inform('tagged-wins'),packet('empty-prl',8,ciaddr='127.0.0.40',prl=[]),write('opts',''),hup(),inform('inline-forced-survive')],
        ['OPT02/option-duplicate-priority','OPT02/option-inline-forced-retained','FILE02/hup-empty-removes']))
    rows.append(case('option-vendor-enterprise-order','dhcp-optsfile={base}/opts',
        {'opts':'vendor:Widget,1,1b\nvendor:Widget,2,second\nvendor:Widget,1,3b\nencap:172,1,4b\nencap:172,2,fifth\nvi-encap:1234,1,6b\nvi-encap:1234,2,seventh\n'},
        [inform('matched',extra=[option(60,b'WidgetClient')]),inform('unmatched',extra=[option(60,b'Other')])],
        ['OPT01/option-vendor-encap','OPT01/option-enterprise','OPT02/option-vendor-order']))
    rows.append(case('option-types-and-lexical','dhcp-optsfile={base}/opts',
        {'opts':'# blank and comment\r\n\r\n option:router,0.0.0.0\r\noption:mtu,1500\n224,"a,b # c" # outside\n225,"a\\tb\\ncolon:hex"\n226,01:02:03\0,ignored\noption:domain-search,a.example,b.example\ndhcp-option=224,illegal\ninvalid\n15,partial-final'},
        [inform('lexical-types')], ['LEX01/blank-comment','LEX01/quoted-comma-hash','LEX01/crlf-nul','LEX01/partial-last-line','LEX01/malformed-middle','OPT01/option-not-directive','OPT01/option-scalar-name']))
    rows.append(case('host-quoted-lexical-id-ignore','dhcp-hostsfile={base}/hosts',
        {'hosts':'# ignored\r\n02:00:00:00:00:01,id:*,127.0.0.30,"quoted",600s\r\n02:00:00:00:00:02,ignore\n02:00:00:00:00:03,127.0.0.32,third\0,this-is-ignored\n02:00:00:00:00:04,127.0.0.33,final'},
        [packet('id-wildcard',extra=[option(61,b'changed-id')]),packet('ignored',mac='020000000002',no_reply=True),packet('positive-after-silence',mac='020000000003'),packet('last-line',mac='020000000004')],
        ['HOST01/host-id-wildcard','HOST01/host-ignore','LEX01/crlf-nul','LEX01/partial-last-line']))
    for kind, directive, text, probe in [('host','dhcp-hostsfile',f'{MAC},127.0.0.30,kept\n',packet('selected')),('option','dhcp-optsfile','224,kept\n',inform('selected'))]:
        rows.append(case('static-'+kind+'-path-order',directive+'={base}/first\n'+directive+'={base}/second\n'+directive+'={base}/first',
            {'first':text,'second':text.replace('kept','other').replace('0.30','0.31')},[probe],
            ['CFG01/repeat-path','FILE01/repeated-inode','EXP01/static-multiple-path-order']))
        rows.append(case('static-'+kind+'-symlink-filter',directive+'={base}/files',
            {'files/a':text,'files/.hidden':text.replace('kept','hidden').replace('0.30','0.31'),'files/backup~':text.replace('kept','backup').replace('0.30','0.32'),'files/#auto#':text.replace('kept','auto').replace('0.30','0.33'),'files/subdir/deep':text.replace('kept','deep').replace('0.30','0.34'),'files/z':{'symlink':'a'}},[probe],
            ['EXP02/backup-dot-filter','EXP02/subdir-no-recursion','EXP02/symlink-child','FILE01/file-symlink']))
        rows.append(case('static-'+kind+'-missing-after-hup',directive+'={base}/file',{'file':text},[probe,action('unlink',path='file'),hup(),dict(probe,label='missing-retires')],
            ['FILE02/hup-missing-removes']))
        rows.append(case('static-'+kind+'-permission',directive+'={base}/file',{'file':{'text':text,'mode':0}},[probe,action('chmod',path='file',mode=0o644),hup(),dict(probe,label='readable-after-hup')],
            ['FILE01/denied-file'],user='dnsmasq'))
    rows.append(case('static-explicit-child-overlap','dhcp-optsfile={base}/files/a\ndhcp-optsfile={base}/files',{'files/a':'224,once\n','files/z':'224,last\n'},[inform('overlap-order'),action('unlink',path='files/a'),hup(),inform('explicit-missing')],['EXP02/explicit-overlap']))
    rows.append(case('static-type-transition','dhcp-optsfile={base}/input',{'input':'224,file\n'},[inform('file'),action('unlink',path='input'),action('mkdir',path='input'),write('input/a','224,directory\n'),hup(),inform('directory'),action('unlink',path='input/a'),action('rmdir',path='input'),write('input','224,file-again\n'),hup(),inform('file-again')],['EXP02/file-directory-transition']))
    rows.append(case('static-path-literal-bytes','dhcp-hostsfile="{base}/host file"\ndhcp-optsfile={base}/\xffopts',{'host file':f'{MAC},127.0.0.30,literal\n','\xffopts':'224,literal\n'},[packet('host'),inform('opts')],['CFG01/relative-quoted']))
    rows.append(case('dynamic-open-close-and-hidden','dhcp-optsdir={base}/dir',{'dir/seed':'224,initial\n'},[inform('before'),write('dir/live','224,opened\n',hold_open=True),inform('partial-not-published'),action('close',path='dir/live'),inform('close-published'),write('dir/.hidden','224,hidden\n'),write('dir/backup~','224,backup\n'),write('dir/#auto#','224,auto\n'),inform('hidden-ignored')],['DYN03/open-write-not-close','DYN03/close-write','DYN03/hidden-events']))
    rows.append(case('dynamic-option-invalid-retains','dhcp-optsdir={base}/dir',{'dir/a':'224,original\n'},[inform('before'),write('dir/a','invalid option\n'),inform('invalid-retains'),action('unlink',path='dir/a'),inform('deleted-retains')],['DYN05/option-invalid-keeps-old','DYN06/option-delete-retained']))
    rows.append(case('dynamic-duplicate-dirs','dhcp-optsdir={base}/dir\ndhcp-optsdir={base}/dir',{'dir/a':'vendor:Widget,1,first\nvendor:Widget,2,second\n'},[inform('duplicate-initial',extra=[option(60,b'Widget')]),write('dir/a','vendor:Widget,3,third\n'),inform('duplicate-live',extra=[option(60,b'Widget')])],['DYN01/duplicate-directories','OPT02/option-vendor-order']))
    rows.append(case('dynamic-type-filter','dhcp-optsdir={base}/dir',{'dir/a':'224,regular\n','dir/.hidden':'224,hidden\n','dir/sub/deep':'224,nested\n','dir/z':{'symlink':'a'}},[inform('regular-only')],['DYN01/dynamic-type-filter']))
    rows.append(case('dynamic-regular-not-directory','dhcp-hostsdir={base}/file\ndhcp-optsdir={base}/file',{'file':f'{MAC},127.0.0.30\n'},[packet('bad-dir-survives'),hup(),packet('retry-still-bad')],['DYN02/regular-instead-dir']))
    rows.append(case('dynamic-watch-fault','dhcp-hostsdir={base}/hosts\ndhcp-optsdir={base}/opts',{'hosts/a':f'{MAC},127.0.0.30\n','opts/a':'224,not-loaded\n'},[packet('watch-denied-host'),inform('watch-denied-option'),hup(),packet('failed-watch-not-retried')],['DYN02/watch-failure'],watch_fault=True))
    rows.append(case('dynamic-inode-lifetime','dhcp-optsdir={base}/dir',{'dir/a':'224,original\n'},[inform('initial'),action('rename',path='dir',to='old'),action('mkdir',path='dir'),write('dir/a','224,replacement\n'),inform('replacement-unwatched'),hup(),inform('hup-scans-replacement'),write('dir/a','224,newer\n'),inform('still-unwatched'),write('old/a','224,old-inode\n'),inform('old-watch-reads-configured-path'),action('unlink',path='old/a'),action('rmdir',path='old'),write('dir/a','224,after-watch-death\n'),hup(),inform('hup-no-reattach'),write('dir/a','224,last\n'),inform('unwatched-again')],['DYN07/directory-renamed','DYN07/directory-replaced','DYN07/hup-existing-watch','DYN07/nameless-event']))
    rows.append(case('mixed-static-dynamic-inputs','dhcp-hostsfile={base}/static-host\ndhcp-optsfile={base}/static-opt\ndhcp-hostsdir={base}/hosts-a\ndhcp-optsdir={base}/opts-a\ndhcp-hostsdir={base}/hosts-b\ndhcp-optsdir={base}/opts-b',{'static-host':f'{MAC},127.0.0.30,static\n','static-opt':'224,static\n','hosts-a/a':f'{MAC},127.0.0.31,hosts-a\n','opts-a/a':'224,opts-a\n','hosts-b/a':f'{MAC},127.0.0.32,hosts-b\n','opts-b/a':'224,opts-b\n'},[packet('dynamic-order'),inform('option-order'),hup(),packet('same-host-order'),inform('same-option-order')],['RELOAD01/host-option-stage-order','DYN01/dynamic-initial-order']))
    rows.append(case('mixed-files-errors','dhcp-hostsfile={base}/missing\ndhcp-hostsfile={base}/hosts\ndhcp-optsfile={base}/missing\ndhcp-optsfile={base}/opts',{'hosts':f'bad:mac\n{MAC},127.0.0.30,valid\n','opts':'bad option\n224,valid\n'},[packet('host-survives'),inform('option-survives'),write('hosts','bad:mac\n'),hup(),packet('bank-removed-valid-inline-remains')],['RELOAD01/mixed-errors','FILE02/hup-malformed-retains-inline']))
    rows.append(case('port-zero-dynamic','dhcp-hostsdir={base}/hosts\ndhcp-optsdir={base}/opts',{'hosts/a':f'{MAC},127.0.0.30\n','opts/a':'224,first\n'},[packet('initial'),write('hosts/b',f'{MAC},127.0.0.31\n'),packet('updated'),inform('opts')],['CFG02/dns-port-zero','STATE01/host-dns-disabled'],dns_port=0))
    rows.append(case('no-local-dhcp-skips-banks','dhcp-hostsfile={base}/broken\ndhcp-optsfile={base}/broken\ndhcp-hostsdir={base}/missing\ndhcp-optsdir={base}/missing',{'broken':'"broken quote\n'},[action('snapshot'),hup(),action('snapshot')],['CFG02/no-local-dhcp','CFG02/test-skips-bank'],dhcp=False))
    rows.append(case('name-inference-duplicate-boundary','addn-hosts={base}/dns\ndhcp-host='+MAC+',inferred\ndhcp-hostsfile={base}/hosts',{'dns':'127.0.0.30 inferred\n','hosts':''},[packet('inferred'),write('hosts','02:00:00:00:00:02,127.0.0.30,rejected\n'),hup(),packet('old-inferred-retained'),packet('duplicate-new-selector',mac='020000000002'),write('dns','127.0.0.31 inferred\n'),hup(),packet('new-dns-address')],['STATE01/host-name-to-address','STATE01/host-reload-dns-source']))
    for disabled in [False,True]:
        rows.append(case('name-inference-multiple-addresses-'+('port-zero' if disabled else 'dns'), 'addn-hosts={base}/dns\ndhcp-hostsdir={base}/hosts', {'dns':'127.0.0.30 inferred\n127.0.0.31 inferred\n','hosts/a':MAC+',inferred\n'}, [packet('multiple-addresses'),write('hosts/b','02:00:00:00:00:02,other\n'),packet('new-name-only',mac='020000000002')], ['STATE01/host-name-to-address','STATE01/host-dns-disabled'] if disabled else ['STATE01/host-name-to-address'],dns_port=0 if disabled else 15353))
    rows.append(case('live-two-lease-names-helper','dhcp-hostsdir={base}/hosts',{'hosts/seed':'# empty\n'},[packet('first-lease',3,address='127.0.0.30',extra=[option(12,b'oldfirst')]),packet('second-lease',3,address='127.0.0.31',mac='020000000002',extra=[option(12,b'oldsecond')]),write('hosts/a',f'{MAC},127.0.0.30,newfirst\n02:00:00:00:00:02,127.0.0.31,newsecond\n'),action('dns',name='newfirst.pool.test'),action('dns',name='30.0.0.127.in-addr.arpa',kind=12),action('dns',name='newsecond.pool.test'),hup(),action('snapshot'),action('unlink',path='hosts/a'),hup(),action('dns',name='newfirst.pool.test'),action('dns',name='31.0.0.127.in-addr.arpa',kind=12)],['STATE02/live-lease-rename','STATE02/lease-expiry-unchanged','STATE02/dns-a-ptr-helper','RELOAD02/hup-scripts','STATE05/dora-updated-bank'],helper=True))
    rows.append(case('live-address-mismatch-keeps-lease-name','dhcp-hostsdir={base}/hosts',{'hosts/seed':'# empty\n'},[packet('initial',3,address='127.0.0.30',extra=[option(12,b'oldname')]),write('hosts/a',f'{MAC},127.0.0.31,mismatch\n'),action('dns',name='oldname.pool.test'),action('snapshot')],['STATE02/rename-address-mismatch'],helper=True))
    rows.append(case('options-helper-pxe-shared-bank','pxe-prompt=Menu,3\npxe-service=0,Boot,boot.bin\ndhcp-option-force=226,forced\ndhcp-optsdir={base}/opts',{'opts/seed':'224,old\n'},[packet('lease',3,address='127.0.0.30'),write('opts/a','224,new\n'),inform('updated-inform'),packet('pxe',extra=[option(60,b'PXEClient'),option(93,b'\0\0')],prl=[43,60,224,226]),hup(),packet('pxe-after-hup',extra=[option(60,b'PXEClient'),option(93,b'\0\0')],prl=[43,60,224,226])],['STATE04/options-no-lease-event','STATE04/options-pxe-shared-bank','STATE04/inline-prompt-survives','STATE05/inform-updated-bank','STATE05/pxe-query-integration'],helper=True))
    rows.append(case('bootp-updated-host','dhcp-hostsdir={base}/hosts',{'hosts/a':f'{MAC},127.0.0.30,first\n'},[packet('before',0),write('hosts/a',f'{MAC},127.0.0.31,second\n'),packet('after',0)],['STATE05/bootp-updated-host']))
    rows.append(case('static-fifo-owner','dhcp-optsfile={base}/opts',{'opts':'224,old\n'},[inform('before'),action('fifo-reload',path='opts',text='224,partial'),inform('after')],['OWNER01/slow-stream-owner-progress','OWNER02/reload-queued-dhcp','OWNER03/fifo-hup-read','OWNER03/partial-stream-eof'],owner_liveness_difference=True))
    rows.append(case('large-file-and-event-burst','dhcp-optsfile={base}/large\ndhcp-optsdir={base}/opts',{'large':('# '+('x'*240)+'\n')*5000+'224,large\n','opts/a':'225,seed\n'},[inform('large-loaded'),action('event-burst',path='opts/a',count=64),inform('burst-final'),hup(),inform('large-reread')],['OWNER01/thread-count']))
    return rows


def fifo_reload(root,side,folder,event,process,endpoint,out,index):
    path=folder/event['path'];path.unlink();os.mkfifo(path)
    process.send_signal(signal.SIGHUP)
    deadline=time.monotonic()+2
    while True:
        try:writer=os.open(path,os.O_WRONLY|os.O_NONBLOCK);break
        except OSError as error:
            if error.errno!=errno.ENXIO or time.monotonic()>deadline:raise
            time.sleep(.005)
    observed={}
    try:
        os.write(writer,event['text'].encode())
        if event.get('repeat_signals'):
            observed['signal_delivery_windows']=[]
            for _ in range(3):
                process.send_signal(signal.SIGHUP);time.sleep(.02)
                status=Path(f'/proc/{process.pid}/status').read_text().splitlines()
                pending=[int(line.split()[1],16) for line in status if line.startswith(('SigPnd:','ShdPnd:'))]
                assert pending and not any(mask & 1 for mask in pending),'SIGHUP remained pending past delivery window'
                observed['signal_delivery_windows'].append('not-pending-after-20ms')
            path.unlink();write_file(path,'224,second-generation\n')
        try:health();observed['dns_during_read']='reply'
        except socket.timeout:observed['dns_during_read']='timeout'
        request_event=dict(kind=8,label='fifo-queued',ciaddr='127.0.0.40',prl=[224])
        request=wire.request(request_event,0xF1F00000+index)
        (out/f'{index:03}.fifo-request').write_bytes(request)
        endpoint.sendto(request,('255.255.255.255',67));endpoint.settimeout(.1)
        try:early,_=endpoint.recvfrom(65535)
        except socket.timeout:early=None
        assert early is None,'DHCP admitted a partial bank generation'
        observed['queued_dhcp_deferred']=True
    finally:os.close(writer)
    endpoint.settimeout(2);response,peer=endpoint.recvfrom(65535)
    assert response[4:8]==request[4:8],'queued packet identity'
    (out/f'{index:03}.fifo-response').write_bytes(response)
    observed.update(response=wire.comparable_reply(response,request_event),peer=list(peer))
    return observed


def exec_watch_fault(argv):
    assert platform.machine()=='aarch64','fault ABI pinned to image architecture'
    class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    # asm-generic inotify_add_watch=27. Only this syscall returns ENOSPC.
    filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,27),Filter(0x06,0,0,0x50000|errno.ENOSPC),Filter(0x06,0,0,0x7fff0000))
    program=Program(4,filters);libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):raise OSError(ctypes.get_errno(),'seccomp')
    os.execvp(argv[0],argv)


def remaining_scenarios():
    def packet(label,kind=1,**fields):return dict(op='packet',label=label,kind=kind,**fields)
    def inform(label):return packet(label,8,ciaddr='127.0.0.40',prl=[224,225])
    def action(op,**fields):return dict(op=op,**fields)
    def write(path,text):return action('write',path=path,text=text)
    def hup():return action('hup')
    def case(name,config,files,events,cases,**fields):return dict(name=name,config=config,files=files,events=events,cases=cases,boundaries=sorted({c.split('/')[0] for c in cases}),**fields)
    rows=[]
    for directive in ['dhcp-hostsfile','dhcp-optsfile','dhcp-hostsdir','dhcp-optsdir']:
        for suffix,exit_code in [('',1),('=',0)]:
            rows.append(case('syntax-'+directive+('-missing' if not suffix else '-empty'),directive+suffix,{},[],['CFG01/required-path'] if not suffix else ['CFG01/empty-safe-syntax','SAFE01/unsafe-empty-combinations'],syntax_only=True,expected_syntax=exit_code))
    for label,directive in [('host-filter','dhcp-host=tag:,'+MAC+',127.0.0.30'),('host-set','dhcp-host=set:,'+MAC+',127.0.0.30'),('option-filter','dhcp-option=tag:,224,unsafe')]:
        rows.append(case('syntax-shared-bank-unsafe-'+label,directive,{},[],['SAFE01/existing-parser-unsafe-classification'],syntax_only=True,expected_syntax=0,
                         unsafe_runtime_classification='option.c dhcp_netid_create stores opt_string_alloc(empty) as NULL; tag match/use dereferences it. BANK/OPTS enter the same host/option parser. Only outer --test is executed, never a daemon.'))
    rows.append(case('literal-dash-is-a-file','dhcp-optsfile=-',{},[inform('literal-dash')],['CFG01/literal-dash','FILE01/literal-dash-runtime'],system_files={'/-':'224,dash-file\n'}))
    rows.append(case('relative-byte-paths','dhcp-optsfile=m2/dhcp-files/\udcffopts\ndhcp-hostsfile="m2/dhcp-files/host file"',{'\udcffopts':'224,raw-path\n','host file':f'{MAC},127.0.0.30,relative\n'},[inform('non-utf8-path'),packet('relative-quoted')],['CFG01/relative-quoted']))
    rows.append(case('ethers-surviving-conflicts-open-failure','read-ethers\ndhcp-hostsfile={base}/hosts',{'hosts':''},[packet('ethers-initial'),action('system-unlink',path='/etc/ethers'),hup(),packet('ethers-open-failed-keeps-old'),write('hosts','02:00:00:00:00:02,127.0.0.30,bank-conflict\n'),hup(),packet('ethers-still-first'),packet('conflicting-bank-rejected',mac='020000000002'),action('system-write',path='/etc/ethers',text=MAC+' 127.0.0.31\n'),hup(),packet('ethers-new-address')],['STATE03/ethers-open-failure','STATE03/ethers-retained-conflict'],system_files={'/etc/ethers':MAC+' 127.0.0.30\n'}))
    decline=lambda label,mac,address:packet(label,4,mac=mac,extra=[option(50,socket.inet_aton(address)),option(54,socket.inet_aton('127.0.0.1'))],no_reply=True)
    rows.append(case('decline-inline-retained-bank-reset','dhcp-host=02:00:00:00:00:02,127.0.0.31,inline\ndhcp-hostsfile={base}/hosts',{'hosts':f'{MAC},127.0.0.30,file\n'},[packet('file-initial'),packet('inline-initial',mac='020000000002'),decline('file-decline','020000000001','127.0.0.30'),decline('inline-decline','020000000002','127.0.0.31'),packet('file-declined'),packet('inline-declined',mac='020000000002'),hup(),packet('file-decline-reset'),packet('inline-decline-retained',mac='020000000002')],['STATE03/inline-decline-survives','STATE03/file-decline-resets']))
    rows.append(case('auto-clear-data-without-script-rerun','resolv-file={base}/resolv\nclear-on-reload\ndhcp-optsfile={base}/opts',{'resolv':'nameserver 127.0.0.2\n','opts':'224,old\n'},[packet('lease',3,address='127.0.0.30',extra=[option(12,b'leased')]),write('opts','224,new\n'),write('resolv','nameserver 127.0.0.3\n'),inform('automatic-options'),action('snapshot'),hup(),action('snapshot')],['RELOAD02/automatic-clear-no-rerun','RELOAD02/hup-scripts'],helper=True,auto_resolv=True))
    rows.append(case('repeated-signal-during-bank-read','dhcp-optsfile={base}/opts',{'opts':'224,old\n'},[packet('lease',3,address='127.0.0.30'),action('fifo-reload',path='opts',text='224,first-generation',repeat_signals=True),inform('second-generation'),action('snapshot')],['RELOAD02/repeat-hup-during-read'],helper=True,owner_liveness_difference=True))
    rows.append(case('startup-queued-dhcp-file','dhcp-optsfile={base}/opts',{'opts':{'fifo':True}},[inform('after-startup')],['OWNER02/startup-queued-dhcp','CFG02/test-skips-bank'],startup_fifo='opts'))
    rows.append(case('stop-during-stream-load','dhcp-optsfile={base}/opts',{'opts':'224,old\n'},[inform('initial'),action('stop-loading',path='opts')],['OWNER02/stop-mid-load'],stop_loading=True,owner_liveness_difference=True))
    rows.append(case('fd-lifecycle-and-recovery','dhcp-hostsfile={base}/hosts\ndhcp-optsdir={base}/opts',{'hosts':f'{MAC},127.0.0.30,first\n','opts/a':'224,first\n'},[packet('initial'),action('fd-check'),action('unlink',path='hosts'),hup(),packet('missing-continues'),write('hosts',f'{MAC},127.0.0.31,second\n'),hup(),packet('recovered'),write('opts/a','224,second\n'),inform('option'),action('fd-check')],['OWNER02/failed-file-recovers','OWNER03/fd-count','OWNER03/watch-cleanup']))
    rows.append(case('dynamic-only-full-clear','dhcp-hostsdir={base}/hosts\ndhcp-optsdir={base}/opts',{'hosts/a':f'{MAC},127.0.0.30,first\n','opts/a':'224,first\n'},[packet('host-initial'),inform('option-initial'),action('unlink',path='hosts/a'),action('unlink',path='opts/a'),packet('live-host-retained'),inform('live-option-retained'),hup(),packet('host-bank-cleared'),inform('option-bank-cleared')],['RELOAD01/hup-dynamic-only']))
    return rows


def trace_malformed_inotify(pid, descriptor, output):
    """Replace one successful AArch64 inotify read with a bounded nameless event."""
    if platform.machine() != 'aarch64': raise RuntimeError('ptrace ABI pinned to AArch64 image')
    class Iovec(ctypes.Structure):
        _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
    def ptrace(request,address=0,data=0):
        ctypes.set_errno(0);value=libc.ptrace(ctypes.c_uint(request),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if value == -1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'ptrace')
        return value
    registers=(ctypes.c_ulonglong*34)()
    def regs(write=False):
        value=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers));ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(value))
    event=struct.pack('=iIII',1,0x00000008,0,8)+b'\0xxx\0\0\0\0'
    report={'pid':pid,'descriptor':descriptor,'event':event.hex(),'injected':False,'reads':[]};attached=False;active=False
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;Path(str(output)+'.ready').write_text('attached\n')
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            if not os.WIFSTOPPED(status):raise AssertionError('tracee ended before inotify read')
            if os.WSTOPSIG(status) not in (signal.SIGTRAP|0x80,signal.SIGTRAP):continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                active=registers[8] in (63,65) and registers[0]==descriptor
                if active:report['reads'].append({'stage':'entry','buffer':int(registers[1])})
            elif info[0]==2 and active:
                returned=ctypes.c_longlong(registers[0]).value
                report['reads'].append({'stage':'exit','result':returned})
                if returned>0:
                    buffer=int(registers[1]);
                    for offset in range(0,len(event),8):
                        word=int.from_bytes(event[offset:offset+8],'little')
                        ptrace(5,buffer+offset,word)
                    registers[0]=len(event);regs(write=True);report['injected']=True;dump(Path(output),report);ptrace(17);attached=False;return 0
                active=False
    finally:
        if attached:
            try:ptrace(17)
            except OSError:pass
        dump(Path(output),report)
    return 1


def find_inotify_fd(pid):
    for path in Path(f'/proc/{pid}/fd').iterdir():
        try:
            if os.readlink(path).startswith('anon_inode:inotify'):return int(path.name)
        except (FileNotFoundError,PermissionError):pass
    raise AssertionError('inotify fd not found')


def resource_scenarios():
    def inform(label):return dict(op='packet',label=label,kind=8,ciaddr='127.0.0.40',prl=[224])
    def case(name,config,events,cases,**fields):
        value=dict(name=name,config='no-daemon\n'+config,files={'opts':'224,old\n','dir/a':'224,old\n'},events=events,cases=cases,boundaries=sorted({c.split('/')[0] for c in cases}));value.update(fields);return value
    rows=[]
    for kind,directive,path in [('static','dhcp-optsfile={base}/opts','opts'),('dynamic','dhcp-optsdir={base}/dir','dir/a')]:
        rows.append(case('runtime-emfile-'+kind,directive,[inform('before'),dict(op='fd-limit'),dict(op='write',path=path,text='224,new\n'),dict(op='hup') if kind=='static' else dict(op='snapshot'),dict(op='emfile-witness',path=BASE+'/'+path),inform('during-emfile'),dict(op='fd-limit',restore=True),dict(op='hup'),inform('recovered')],['OWNER03/fd-open-failure','OWNER02/failed-file-recovers']))
    rows.append(case('runtime-emfile-directory-scan','dhcp-optsdir={base}/dir',[inform('before'),dict(op='fd-limit'),dict(op='hup'),dict(op='emfile-witness',path=BASE+'/dir'),inform('empty-bank-after-failed-opendir'),dict(op='fd-limit',restore=True),dict(op='write',path='dir/a',text='224,recovered\n'),inform('existing-watch-recovers')],['DYN02/watch-failure','OWNER03/fd-open-failure','OWNER02/failed-file-recovers']))
    rows.append(case('large-bank-owner-progress','dhcp-optsfile={base}/opts',[inform('before'),dict(op='large-file',path='opts',bytes=16*1024*1024,tail='224,large\n'),inform('after'),dict(op='fd-check')],['OWNER01/large-bank-owner-progress']))
    rows.append(case('large-option-bank-owner-progress','dhcp-optsfile={base}/opts',[inform('before'),dict(op='large-file',path='opts',bytes=512*1024,bank_rows=8192,tail='224,large-bank\n'),inform('after')],['OWNER01/large-bank-owner-progress']))
    rows.append(case('malformed-inotify-event','dhcp-optsdir={base}/dir',{'dir/a':'224,initial\n'},[inform('initial'),dict(op='malformed-event',path='dir/a'),inform('after-malformed')],['DYN03/bounded-event-parser'],malformed_event=True))
    rows.append(case('long-bank-line','dhcp-optsfile={base}/opts',[inform('before'),dict(op='large-file',path='opts',bytes=1024*1024,tail='224,long-line\n',single_line=True),inform('after')],['LEX01/partial-last-line']))
    rows.append(case('watch-burst-owner-progress','dhcp-optsdir={base}/dir',[inform('before'),dict(op='burst-progress',path='dir/a',bytes=128*1024,count=128,tail='224,burst\n'),inform('after'),dict(op='fd-check')],['OWNER01/event-burst-fairness']))
    for kind,directive,text,probe in [('hosts','dhcp-hostsfile',MAC+',127.0.0.30,partial',dict(op='packet',label='partial-host',kind=1)),('options','dhcp-optsfile','224,partial',inform('partial-option'))]:
        rows.append(dict(name='partial-read-eio-'+kind,config=directive+'=/m2/files/bank',files={},system_files={'/m2/files/bank':'# initially empty\n'},events=[dict(op='partial-eio',text=text),probe],cases=['LEX01/partial-last-line','OWNER03/partial-stream-eof'],boundaries=['LEX01','OWNER03']))
    rows.append(dict(name='fifo-tftp-owner-progress',config='dhcp-optsfile={base}/opts\nenable-tftp\ntftp-root={base}/data',files={'opts':'224,old\n','data/payload':'T'*1400},events=[dict(op='fifo-tftp',path='opts'),inform('after')],cases=['OWNER01/slow-stream-owner-progress'],boundaries=['OWNER01'],owner_liveness_difference=True))
    rows.append(dict(name='fifo-helper-owner-progress',config='dhcp-optsfile={base}/opts',files={'opts':'224,old\n'},events=[dict(op='packet',label='lease',kind=3,address='127.0.0.30'),dict(op='fifo-helper',path='opts'),dict(op='snapshot')],cases=['OWNER01/slow-stream-owner-progress'],boundaries=['OWNER01'],helper=True,helper_delay=True))
    return rows


def open_bank_fds(pid,path):
    found=[]
    for item in Path(f'/proc/{pid}/fd').iterdir():
        try:target=os.readlink(item)
        except FileNotFoundError:continue
        if target.endswith(path):found.append(int(item.name))
    return found


def fifo_other_protocol(folder,process,event):
    path=folder/event['path'];kind=event['op'];transfer=None;packets=[]
    if kind=='fifo-tftp':
        transfer=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);transfer.settimeout(1)
        transfer.sendto(b'\0\1payload\0octet\0',('127.0.0.1',69));packet,peer=transfer.recvfrom(4096)
        assert packet[:4]==b'\0\3\0\1','missing TFTP DATA1';packets.append(packet)
    path.unlink();os.mkfifo(path);process.send_signal(signal.SIGHUP);writer=fifo_writer(path)
    proof={}
    try:
        os.write(writer,b'224,loaded')
        assert open_bank_fds(process.pid,BASE+'/'+event['path']),'pending reader absent'
        if transfer:
            transfer.sendto(b'\0\4\0\1',peer);transfer.settimeout(.15)
            try:packet,received=transfer.recvfrom(4096)
            except socket.timeout:packet=None
            proof['tftp_while_pending']=packet is not None
            if packet is not None:
                assert received==peer and packet[:4]==b'\0\3\0\2';packets.append(packet)
                transfer.sendto(b'\0\4\0\2',peer);packet,received=transfer.recvfrom(4096)
                assert received==peer and packet[:4]==b'\0\3\0\3';packets.append(packet)
                transfer.sendto(b'\0\4\0\3',peer)
        else:
            log=folder/'helper.log';before=log.read_text().splitlines() if log.exists() else []
            assert not any(line.startswith('add|') for line in before),'slow helper finished before pending bank'
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                after=log.read_text().splitlines() if log.exists() else []
                if any(line.startswith('add|') for line in after):break
                time.sleep(.01)
            else:raise AssertionError('helper stalled during pending bank')
            assert open_bank_fds(process.pid,BASE+'/'+event['path']),'bank reader finished before helper witness'
            proof.update(helper_before=before,helper_while_pending=after,helper_completed_while_pending=True)
    finally:os.close(writer)
    if transfer:
        try:
            transfer.settimeout(1)
            if len(packets)==1:
                packet,received=transfer.recvfrom(4096);assert received==peer and packet[:4]==b'\0\3\0\2';packets.append(packet)
                transfer.sendto(b'\0\4\0\2',peer);packet,received=transfer.recvfrom(4096)
                assert received==peer and packet[:4]==b'\0\3\0\3';packets.append(packet);transfer.sendto(b'\0\4\0\3',peer)
            assert b''.join(packet[4:] for packet in packets)==b'T'*1400,'TFTP body mismatch'
            proof.update(packets=[packet.hex() for packet in packets],body_bytes=1400)
        finally:transfer.close()
    return proof


def load_progress(folder,process,event,out):
    path=folder/event['path'];inside=BASE+'/'+event['path']
    body=(b'#'+b'x'*(event['bytes']-2)+b'\n' if event.get('single_line') else (b'#'+b'x'*126+b'\n')*(event['bytes']//128))+event['tail'].encode()
    if event.get('bank_rows'):
        body=b''.join(('224,"row%05d-' % number + 'x'*56 + '"\n').encode() for number in range(event['bank_rows'])) + event['tail'].encode()
    samples=[];stop=threading.Event()
    def sample():
        while not stop.is_set():
            opened=bool(open_bank_fds(process.pid,inside));start=time.monotonic()
            try:answer=health();healthy=True
            except (OSError,AssertionError) as error:answer=repr(error);healthy=False
            samples.append({'file_active':opened,'file_still_active':bool(open_bank_fds(process.pid,inside)),'elapsed':time.monotonic()-start,'healthy':healthy,'reply':answer})
            time.sleep(.001)
    worker=threading.Thread(target=sample);worker.start()
    marker='read '+inside
    prior=sum(marker in line for line in (out/'daemon.log').read_text(errors='replace').splitlines())
    expected=1 if event['op']=='large-file' else event['count']
    try:
        if event['op']=='large-file':
            path.write_bytes(body);process.send_signal(signal.SIGHUP)
        else:
            process.send_signal(signal.SIGSTOP)
            deadline=time.monotonic()+1
            while '\nState:\tT' not in Path(f'/proc/{process.pid}/status').read_text():
                assert time.monotonic()<deadline,'SIGSTOP not observed';time.sleep(.001)
            try:
                for _ in range(event['count']):
                    path.write_bytes(body);path.with_name('.noise').write_text('alternate event\n')
            finally:process.send_signal(signal.SIGCONT)
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            reads=sum(marker in line for line in (out/'daemon.log').read_text(errors='replace').splitlines())-prior
            if len(samples)>=30 and reads>=expected and not open_bank_fds(process.pid,inside):break
            time.sleep(.002)
        else:raise AssertionError('file load did not finish expected reads')
    finally:
        stop.set();worker.join(2)
    assert not worker.is_alive() and samples,'health sampler missing/leaked'
    latency=sorted(sample['elapsed'] for sample in samples)
    active=sorted(sample['elapsed'] for sample in samples if sample['file_active'])
    return {'bytes':len(body),'file_sha256':sha256(path),'completed_reads':reads,'samples':samples,'p95_seconds':latency[min(len(latency)-1,int(len(latency)*.95))],
        'pending_p95_seconds':active[min(len(active)-1,int(len(active)*.95))] if active else None,
        'all_healthy':all(sample['healthy'] for sample in samples),'healthy_while_file_open':sum(sample['healthy'] and sample['file_active'] and sample['file_still_active'] for sample in samples)}


def file_syntax(root,side,text,out):
    out.mkdir()
    result=subprocess.run(command(root,side,'--test','-C','/m2/files.conf'),capture_output=True,timeout=5)
    (out/'stdout').write_bytes(result.stdout);(out/'stderr').write_bytes(result.stderr)
    return {'exit':result.returncode,'stdout':result.stdout.decode(errors='backslashreplace'),'stderr':result.stderr.decode(errors='backslashreplace')}


def fifo_writer(path):
    deadline=time.monotonic()+2
    while True:
        try:return os.open(path,os.O_WRONLY|os.O_NONBLOCK)
        except OSError as error:
            if error.errno!=errno.ENXIO or time.monotonic()>deadline:raise
            time.sleep(.005)


def startup_stream(folder,scenario,endpoint,out):
    writer=fifo_writer(folder/scenario['startup_fifo'])
    event=dict(kind=8,label='startup-queued',ciaddr='127.0.0.40',prl=[224])
    request=wire.request(event,0xD5110000)
    try:
        os.write(writer,b'224,startup-partial')
        endpoint.sendto(request,('255.255.255.255',67));endpoint.settimeout(.1)
        try:early,_=endpoint.recvfrom(65535)
        except socket.timeout:early=None
        assert early is None,'startup published incomplete bank'
    finally:os.close(writer)
    endpoint.settimeout(2);response,peer=endpoint.recvfrom(65535)
    assert response[4:8]==request[4:8]
    (out/'startup.request').write_bytes(request);(out/'startup.response').write_bytes(response)
    return {'deferred':True,'reply':wire.comparable_reply(response,event),'peer':list(peer)}


def stop_stream(folder,event,process):
    path=folder/event['path'];path.unlink();os.mkfifo(path)
    process.send_signal(signal.SIGHUP);writer=fifo_writer(path)
    try:
        os.write(writer,b'224,incomplete')
        process.send_signal(signal.SIGTERM)
        try:process.wait(.15);before='exited'
        except subprocess.TimeoutExpired:before='waiting'
    finally:os.close(writer)
    process.wait(3)
    return {'before_writer_close':before,'exit_after_close':process.returncode}


def config(scenario):
    text=wire.config({'fixed_host':False,'range':scenario.get('dhcp',True),'dns_port':scenario.get('dns_port',15353),'text':f"user={scenario.get('user','root')}\ngroup={scenario.get('user','root')}\nhost-record=health.test,192.0.2.7\n"+scenario['config'].format(base=BASE)+'\n'+ ('dhcp-script='+BASE+'/helper.sh\n' if scenario.get('helper') else '')})
    return text.replace('no-resolv\n','') if scenario.get('auto_resolv') else text


def install(root,scenario):
    folder=root/BASE.lstrip('/')
    if folder.exists():shutil.rmtree(folder)
    folder.mkdir()
    for name,text in scenario['files'].items():
        path=folder/name;path.parent.mkdir(parents=True,exist_ok=True);write_file(path,text)
    if scenario.get('user','root')!='root':
        (root/'m2').chmod(0o777);folder.chmod(0o777)
    else:(root/'m2').chmod(0o755)
    if scenario.get('helper'):
        path=folder/'helper.sh';path.write_text("#!/bin/sh\nprintf '%s|%s|%s|%s\\n' \"$1\" \"$2\" \"$3\" \"$4\" >> "+BASE+'/helper.log\n');path.chmod(0o755)
        if scenario.get('helper_delay'):
            script=path.read_text().replace('#!/bin/sh\n', '#!/bin/sh\nif [ "$1" = add ]; then : > '+BASE+'/helper-start; sleep 1; fi\n')
            path.write_text(script)
    for name,value in scenario.get('system_files',{}).items():
        path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);write_file(path,value)
    for name in ['family.pid','family.leases']:(root/'m2'/name).unlink(missing_ok=True)
    return folder


def health(scenario=None):
    return {'disabled':True} if scenario and scenario.get('dns_port')==0 else wire.dns_observe('health.test',1,0xF11E)


def lease_state(root):
    path=root/'m2/family.leases';text=path.read_text() if path.exists() else '';rows=[]
    now=int(time.time())
    for line in text.splitlines():
        fields=line.split()
        if fields and fields[0].isdigit() and len(fields)>=5:
            expiry=int(fields.pop(0));rows.append({'remaining':expiry-now if expiry else None,'fields':fields})
    return text,rows


def run_side(root,side,scenario,out):
    out.mkdir();folder=install(root,scenario);text=config(scenario)
    (out/'config').write_bytes(text.encode(errors='surrogateescape'));(root/'m2/files.conf').write_bytes(text.encode(errors='surrogateescape'))
    result={'side':side,'scenario':scenario['name'],'rows':[],'started':False,'expected_rust_sha256':sha256(root/'usr/sbin/dnsmasq-rs')};process=None;owned=set();opened={};limit_before=None
    with (out/'daemon.log').open('wb') as log,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.bind(('0.0.0.0',68));endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);endpoint.setsockopt(socket.SOL_SOCKET,25,b'lo\0')
        try:
            result['syntax']=file_syntax(root,side,text,out/'syntax');assert result['syntax']['exit']==scenario.get('expected_syntax',0),'--test result'
            if scenario.get('syntax_only'):
                result.update(syntax_only=True,exit=0,pid_removed=True);save(out/'result.json',result);return result
            argv=command(root,side,'-k','-C','/m2/files.conf')
            if scenario.get('watch_fault'):argv=[sys.executable,str(Path(__file__).resolve()),'--exec-watch-fault',*argv]
            process=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True)
            if scenario.get('startup_fifo'):result['startup_file']=startup_stream(folder,scenario,endpoint,out)
            deadline=time.monotonic()+3
            while True:
                assert process.poll() is None,'startup exit'
                if scenario.get('dns_port')==0:
                    time.sleep(.1);break
                try:
                    with socket.create_connection(('127.0.0.1',15353),.05):break
                except OSError:pass
                if time.monotonic()>deadline:raise AssertionError('startup deadline')
                time.sleep(.01)
            time.sleep(.05)
            result.update(started=True,identity=process_identity(root,process.pid),threads=len(list(Path(f'/proc/{process.pid}/task').iterdir())))
            result['health_before']=health(scenario)
            result['fd_before']=len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
            for index,event in enumerate(scenario['events']):
                observed={'index':index,'event':event,'alive':process.poll() is None}
                if event['op']=='packet':
                    request=wire.request(event,0xD5100000+index);(out/f'{index:03}.request').write_bytes(request)
                    response,peer,foreign,drained=wire.receive(endpoint,request,('255.255.255.255',67),timeout=.5)
                    observed.update(response=response.hex() if response is not None else None,peer=list(peer) if peer else None,foreign=foreign,drained=drained)
                    if response is not None:
                        (out/f'{index:03}.response').write_bytes(response);observed['comparable']=wire.comparable_reply(response,event)
                    assert (response is None)==event.get('no_reply',False),'response presence'
                elif event['op']=='write':
                    path=folder/event['path'];path.parent.mkdir(parents=True,exist_ok=True)
                    if event.get('hold_open'):
                        opened[event['path']]=path.open('wb');opened[event['path']].write(event['text'].encode());opened[event['path']].flush()
                    else:write_file(path,event.get('value',event.get('text','')))
                    time.sleep(.1)
                elif event['op']=='mkdir':(folder/event['path']).mkdir()
                elif event['op']=='unlink':(folder/event['path']).unlink();time.sleep(.1)
                elif event['op']=='rename':(folder/event['path']).rename(folder/event['to']);time.sleep(.1)
                elif event['op']=='hup':process.send_signal(signal.SIGHUP);time.sleep(.15)
                elif event['op']=='close':opened.pop(event['path']).close();time.sleep(.1)
                elif event['op']=='chmod':(folder/event['path']).chmod(event['mode']);time.sleep(.1)
                elif event['op']=='rmdir':(folder/event['path']).rmdir();time.sleep(.1)
                elif event['op']=='symlink':(folder/event['path']).symlink_to(event['target']);time.sleep(.1)
                elif event['op']=='dns':observed['dns']=wire.dns_observe(event['name'],event.get('kind',1),0xD500+index)
                elif event['op']=='snapshot':time.sleep(.1)
                elif event['op']=='fd-check':
                    targets={p.name:os.readlink(p) for p in Path(f'/proc/{process.pid}/fd').iterdir()}
                    observed['fd_targets']=targets
                    assert not any(BASE in target for target in targets.values()),'completed bank retained an open data file'
                    observed['bank_fds_closed']=True
                elif event['op']=='system-write':write_file(root/event['path'].lstrip('/'),event['text']);time.sleep(.1)
                elif event['op']=='system-unlink':(root/event['path'].lstrip('/')).unlink();time.sleep(.1)
                elif event['op']=='stop-loading':observed['stop']=stop_stream(folder,event,process)
                elif event['op']=='fifo-reload':observed['fifo']=fifo_reload(root,side,folder,event,process,endpoint,out,index)
                elif event['op'] in ('fifo-tftp','fifo-helper'):observed['pending_protocol']=fifo_other_protocol(folder,process,event)
                elif event['op']=='malformed-event':
                    descriptor=find_inotify_fd(process.pid);report_path=out/'malformed-inotify.json';tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-malformed-inotify',str(process.pid),str(descriptor),str(report_path)])
                    try:
                        deadline=time.monotonic()+2
                        while not Path(str(report_path)+'.ready').exists():
                            if tracer.poll() is not None:raise AssertionError('malformed tracer attach failed')
                            if time.monotonic()>deadline:raise AssertionError('malformed tracer attach timeout')
                            time.sleep(.005)
                        write_file(folder/event['path'],'224,malformed\n');deadline=time.monotonic()+3
                        while not report_path.exists() and tracer.poll() is None and time.monotonic()<deadline:time.sleep(.005)
                        if tracer.poll() is None:tracer.wait(2)
                        observed['malformed']=json.loads(report_path.read_text())
                        assert observed['malformed'].get('injected'),'malformed event was not injected'
                    finally:
                        if tracer.poll() is None:tracer.kill();tracer.wait()
                elif event['op']=='fd-limit':
                    if event.get('restore'):
                        resource.prlimit(process.pid,resource.RLIMIT_NOFILE,limit_before);limit_before=None
                    else:
                        limit_before=resource.prlimit(process.pid,resource.RLIMIT_NOFILE)
                        descriptors={int(p.name) for p in Path(f'/proc/{process.pid}/fd').iterdir()}
                        ceiling=next(n for n in range(max(descriptors)+2) if n not in descriptors)
                        resource.prlimit(process.pid,resource.RLIMIT_NOFILE,(ceiling,limit_before[1]))
                        observed['fd_exhaustion']={'descriptors':sorted(descriptors),'limits':resource.prlimit(process.pid,resource.RLIMIT_NOFILE)}
                elif event['op']=='partial-eio':
                    observed['partial_eio']=partial_stream_error(root,process,event['text'],out,relative='bank')
                    observed['partial_eio_verified']=True
                elif event['op']=='emfile-witness':
                    observed['emfile_diagnostics']=[line for line in (out/'daemon.log').read_text(errors='replace').splitlines() if event['path'] in line and ('No file descriptors available' in line or 'Too many open files' in line)]
                    assert observed['emfile_diagnostics'],'file open did not reach EMFILE'
                    observed['emfile_verified']=True
                elif event['op'] in ('large-file','burst-progress'):
                    observed['progress']=load_progress(folder,process,event,out)
                    assert observed['progress']['all_healthy'],'DNS failed during file work'
                    if side=='rust':assert observed['progress']['healthy_while_file_open']>0,'no live owner progress witnessed'
                    observed['owner_health_verified']=True
                elif event['op']=='event-burst':
                    process.send_signal(signal.SIGSTOP)
                    deadline=time.monotonic()+1
                    while '\nState:\tT' not in Path(f'/proc/{process.pid}/status').read_text():
                        assert time.monotonic()<deadline,'stop not observed';time.sleep(.001)
                    try:
                        for number in range(event['count']):
                            write_file(folder/event['path'],f'224,value{number}\n')
                            write_file(folder/(event['path']+'.noise'), '# alternate event\n')
                    finally:process.send_signal(signal.SIGCONT)
                    time.sleep(.2)
                else:raise AssertionError('unknown event')
                leases,observed['leases']=lease_state(root);(out/f'{index:03}.leases').write_text(leases)
                observed['health']={'stopped':True} if process.poll() is not None else health(scenario)
                observed['fds']=len(list(Path(f'/proc/{process.pid}/fd').iterdir())) if process.poll() is None else None
                if scenario.get('helper'):
                    time.sleep(.1);helper=folder/'helper.log';observed['helper']=helper.read_text().splitlines() if helper.exists() else []
                result['rows'].append(observed);save(out/'result.json',result)
            result['health_after']={'stopped':True} if process.poll() is not None else health(scenario)
            result['fd_after']=len(list(Path(f'/proc/{process.pid}/fd').iterdir())) if process.poll() is None else None
        except Exception as error:result['error']=repr(error)
        finally:
            for opened_file in opened.values():opened_file.close()
            if limit_before and process and process.poll() is None:resource.prlimit(process.pid,resource.RLIMIT_NOFILE,limit_before)
            if process is not None:
                owned=children(process.pid)
                if process.poll() is None:process.terminate()
                try:process.wait(3)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(1);result['forced']=True
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    for pid in owned-{process.pid}:
                        try:os.waitpid(pid,os.WNOHANG)
                        except ChildProcessError:pass
                    if not any(Path(f'/proc/{pid}').exists() for pid in owned):break
                    time.sleep(.01)
                result['remaining']=[pid for pid in owned if Path(f'/proc/{pid}').exists()]
                for pid in result['remaining']:
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                result['exit']=process.returncode
            result['pid_removed']=not (root/'m2/family.pid').exists()
    save(out/'result.json',result);return result


def compare(c,rust):
    failures=[]
    for key in ['started','threads','health_before','health_after','exit','pid_removed','forced','remaining','error','startup_file']:
        if c.get(key)!=rust.get(key):failures.append(key)
    if wire.comparable_syntax(c.get('syntax',{}))!=wire.comparable_syntax(rust.get('syntax',{})):failures.append('syntax')
    if len(c['rows'])!=len(rust['rows']):failures.append('row count')
    for first,second in zip(c['rows'],rust['rows']):
        for key in ['index','event','alive','health','peer','comparable','dns','helper','bank_fds_closed','emfile_verified','owner_health_verified','partial_eio_verified','malformed']:
            if first.get(key)!=second.get(key):failures.append(f"{first['index']}:{key}")
        if (first.get('response') is None)!=(second.get('response') is None):failures.append(f"{first['index']}:response presence")
        if 'pending_protocol' in first or 'pending_protocol' in second:
            left,right=copy.deepcopy(first.get('pending_protocol')),copy.deepcopy(second.get('pending_protocol'))
            if first['event']['op']=='fifo-tftp':
                if left.pop('tftp_while_pending') is not False or right.pop('tftp_while_pending') is not True:failures.append(f"{first['index']}:TFTP owner disposition")
            if left!=right:failures.append(f"{first['index']}:pending protocol")
        if 'stop' in first or 'stop' in second:
            if first.get('stop')!={'before_writer_close':'waiting','exit_after_close':0} or second.get('stop')!={'before_writer_close':'exited','exit_after_close':0}:failures.append(f"{first['index']}:stop owner disposition")
        if 'fifo' in first or 'fifo' in second:
            left,right=copy.deepcopy(first.get('fifo')),copy.deepcopy(second.get('fifo'))
            if left is None or right is None:failures.append(f"{first['index']}:fifo missing")
            else:
                if left.pop('dns_during_read')!='timeout' or right.pop('dns_during_read')!='reply':failures.append(f"{first['index']}:owner liveness disposition")
                if left!=right:failures.append(f"{first['index']}:fifo publication")
        left,right=first['leases'],second['leases']
        if len(left)!=len(right):failures.append(f"{first['index']}:lease count");continue
        for x,y in zip(left,right):
            if x['fields']!=y['fields'] or (x['remaining'] is None)!=(y['remaining'] is None) or (x['remaining'] is not None and abs(x['remaining']-y['remaining'])>2):failures.append(f"{first['index']}:lease")
    return failures


def audit_trace(folder,mode):
    report=json.loads((folder/'run/result.json').read_text())
    assert report['selected_comparison_passed'] and not report['failures']
    lines=(folder/'syscalls.log').read_text().splitlines()
    observations={}
    for side,observed in report['results'][0]['sides'].items():
        pid=observed['identity']['pid'];selected=[(number+1,line) for number,line in enumerate(lines) if re.match(str(pid)+r'\s',line)]
        if mode=='watch':
            watched=next((number,line) for number,line in selected if 'inotify_add_watch(' in line and '"/m2/dhcp-files/opts"' in line)
            opened=next((number,line) for number,line in selected if number>watched[0] and 'openat(' in line and '"/m2/dhcp-files/opts"' in line and 'O_DIRECTORY' in line)
            descriptor=int(re.search(r'= (\d+)$',opened[1])[1])
            read=next((number,line) for number,line in selected if number>opened[0] and f'getdents64({descriptor},' in line and re.search(r'= [1-9][0-9]*$',line))
            observations[side]={'pid':pid,'watch_before_open_before_readdir':True,'syscalls':[watched,opened,read]}
        elif mode=='watch-fault':
            attempts=[(number,line) for number,line in selected if 'inotify_add_watch(' in line]
            assert len(attempts)==2 and all('ENOSPC' in line for _,line in attempts),(side,attempts)
            observations[side]={'pid':pid,'failed_initial_watches':attempts,'hup_did_not_retry_failed_watch':True}
        elif mode=='signals':
            delivered=[(number,line) for number,line in selected if '--- SIGHUP ' in line]
            fifo=next(row for row in observed['rows'] if row['event']['op']=='fifo-reload')
            helpers=observed['rows'][-1]['helper']
            assert len(delivered)==4,(side,delivered)
            assert len([line for line in helpers if line.startswith('old|')])==len(delivered),(side,helpers)
            observations[side]={'pid':pid,'delivered_sighup_count':len(delivered),'helper_events':helpers,'delivery_syscalls':delivered,'delivery_windows':fifo['fifo']['signal_delivery_windows']}
        else:raise ValueError(mode)
    proof={'checked':True,'scope':mode,'source_commit':json.loads((folder/'run/manifest.json').read_text())['source_commit'],'trace_sha256':sha256(folder/'syscalls.log'),'observations':observations}
    save(folder/'trace-proof.json',proof)
    return proof


def witness_errors(scenario,observed,side):
    errors=[]
    for event,row in zip(scenario['events'],observed['rows']):
        if event['op'] in ('large-file','burst-progress'):
            proof=row.get('progress',{});samples=proof.get('samples',[])
            overlap=sum(sample.get('healthy',False) and sample.get('file_active',False) and sample.get('file_still_active',False) for sample in samples)
            if len(samples)<30 or proof.get('bytes',0)<event['bytes'] or not all(sample.get('healthy',False) for sample in samples):errors.append('large/burst health data absent or failed')
            if side=='rust' and not overlap:errors.append('no DNS progress while a bank file was open')
            if proof.get('healthy_while_file_open')!=overlap:errors.append('invalid overlap count')
            expected=event.get('count',1)
            if proof.get('completed_reads',0)<expected:errors.append('missing bank event reads')
        if event['op']=='emfile-witness' and not row.get('emfile_diagnostics'):errors.append('missing actual EMFILE diagnostic')
        if event['op']=='partial-eio':
            proof=row.get('partial_eio',{})
            if not proof.get('injected') or not any(read.get('result',0)>0 for read in proof.get('reads',[])) or not any(read.get('injected') and read.get('result')==-errno.EIO for read in proof.get('reads',[])):errors.append('partial data followed by injected EIO not proven')
        if event['op']=='fd-check':
            if not row.get('fd_targets') or any(BASE in target for target in row['fd_targets'].values()):errors.append('bank fd closure not proven')
    if observed.get('started'):
        expected=STOCK_SHA256 if side=='c' else observed.get('expected_rust_sha256')
        if observed.get('identity',{}).get('sha256')!=expected:errors.append('running ELF identity mismatch')
    return errors


def controls():
    baseline={'started':True,'threads':1,'syntax':{'exit':0,'stdout':'','stderr':'dnsmasq: syntax check OK.\n'},'exit':0,'pid_removed':True,'remaining':[],
        'rows':[{'index':0,'event':{'op':'packet','label':'ack','kind':3},'alive':True,'health':{'reply':'ok'},'peer':['127.0.0.1',67],'response':'0011','comparable':'0011',
                 'helper':['add|mac|ip|host'],'dns':{'reply':'answer'},'leases':[{'remaining':600,'fields':['mac','ip','host','*']}]}]}
    assert not compare(baseline,copy.deepcopy(baseline))
    detected=[]
    for name in ['missing-event','stale-host-or-option','wrong-peer','dropped-packet','missing-helper','missing-lease','wrong-lease-name','renewed-expiry','wrong-dns','wrong-syntax','leaked-pid','extra-thread']:
        changed=copy.deepcopy(baseline)
        if name=='missing-event':changed['rows'].clear()
        elif name=='stale-host-or-option':changed['rows'][0]['comparable']='0022'
        elif name=='wrong-peer':changed['rows'][0]['peer']=['127.0.0.2',67]
        elif name=='dropped-packet':changed['rows'][0]['response']=None
        elif name=='missing-helper':changed['rows'][0]['helper']=[]
        elif name=='missing-lease':changed['rows'][0]['leases']=[]
        elif name=='wrong-lease-name':changed['rows'][0]['leases'][0]['fields'][2]='different'
        elif name=='renewed-expiry':changed['rows'][0]['leases'][0]['remaining']=630
        elif name=='wrong-dns':changed['rows'][0]['dns']['reply']='other'
        elif name=='wrong-syntax':changed['syntax']['exit']=1
        elif name=='leaked-pid':changed['remaining']=[123]
        elif name=='extra-thread':changed['threads']=2
        assert compare(baseline,changed),name
        detected.append(name)
    case={'events':[{'op':'large-file','bytes':4096}]}
    sample={'healthy':True,'file_active':True,'file_still_active':True}
    witness={'rows':[{'progress':{'bytes':4096,'completed_reads':1,'samples':[sample]*30,'healthy_while_file_open':30}}]}
    assert not witness_errors(case,witness,'rust')
    for name in ['missing-health-samples','no-pending-overlap','missing-file-completion','wrong-byte-count']:
        changed=copy.deepcopy(witness);proof=changed['rows'][0]['progress']
        if name=='missing-health-samples':proof['samples']=[]
        elif name=='no-pending-overlap':
            for sample in proof['samples']:sample['file_still_active']=False
            proof['healthy_while_file_open']=0
        elif name=='missing-file-completion':proof['completed_reads']=0
        elif name=='wrong-byte-count':proof['bytes']=0
        assert witness_errors(case,changed,'rust'),name
        detected.append(name)
    return detected


def coverage(checklist,corpus,results):
    required={boundary['id']+'/'+case for boundary in checklist['boundaries'] for case in boundary['cases']}
    scheduled={case for scenario in corpus for case in scenario['cases']}
    assert scheduled<=required,sorted(scheduled-required)
    mapping={case:[] for case in required}
    for scenario,result in zip(corpus,results):
        paired=set(result['sides'])=={'c','rust'} and not result['errors']
        for case in scenario['cases']:
            mapping[case].append({'scenario':scenario['name'],'paired_observations':paired,
                                  'raw_evidence':[scenario['name']+'-'+side+'/result.json' for side in result['sides']]})
    return {'required_boundaries':len(checklist['boundaries']),'required_cases':len(required),
            'unmapped_cases':sorted(required-scheduled),
            'without_successful_pair':sorted(case for case,refs in mapping.items() if not any(ref['paired_observations'] for ref in refs)),
            'case_observations':mapping,
            'audit_status':'Mappings point to attempted observations only. Each compound source requirement still requires an evidence audit; scenario IDs are not closure.'}


def main(args):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert sorted(name for _,name in socket.if_nameindex())==['lo']
    assert not args.out.exists() and 'private' in args.out.parts;args.out.mkdir(parents=True)
    negative=controls()
    checklist=json.loads(Path(__file__).with_suffix('.json').read_text())
    corpus=[s for s in scenarios() if not args.case or s['name'] in args.case]
    assert corpus and (not args.case or len(corpus)==len(set(args.case)))
    sources=args.out/'executed-tools';sources.mkdir()
    for module in list(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).resolve().parent==Path(__file__).resolve().parent:shutil.copy2(path,sources/Path(path).name)
    shutil.copy2(__file__,sources/Path(__file__).name)
    shutil.copy2(Path(__file__).with_suffix('.json'),sources/'m5_dhcp_files.json')
    root=prepare(args.image_root,None,args.out,args.rust)
    manifest={'scenarios':corpus,'source_commit':args.source_commit,'tool_sha256':sha256(__file__),'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'elf_bytes':args.rust.stat().st_size,'sides':['c','rust'] if args.side=='both' else [args.side]}
    save(args.out/'manifest.json',manifest);results=[];failures=[]
    for scenario in corpus:
        rows={side:run_side(root,side,scenario,args.out/(scenario['name']+'-'+side)) for side in manifest['sides']}
        errors=[]
        for side,value in rows.items():
            errors.extend(side+': '+error for error in witness_errors(scenario,value,side))
            if scenario.get('syntax_only'):
                if value.get('error') or value['syntax']['exit']!=scenario.get('expected_syntax',0):errors.append(side+': syntax result')
                continue
            if not value['started'] or value.get('error') or value.get('exit')!=0 or value.get('forced') or value.get('remaining') or not value['pid_removed'] or value.get('threads')!=1 or len(value['rows'])!=len(scenario['events']):errors.append(side+': lifecycle/events')
        if args.side=='both':errors+=compare(rows['c'],rows['rust'])
        results.append({'scenario':scenario['name'],'sides':rows,'errors':errors});failures.extend(scenario['name']+': '+e for e in errors)
        save(args.out/'result.json',{'passed':False,'results':results,'failures':failures})
        print(json.dumps({'scenario':scenario['name'],'errors':errors}),flush=True)
    report={'passed':False,'family_qualified':False,'closed_options':[],'selected_comparison_passed':not failures and args.side=='both','reference_checks_passed':not failures,'comparison_executed':args.side=='both','c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'results':results,'failures':failures,'configuration_count':len(corpus),'event_count':sum(len(s['events']) for s in corpus),'normalization':'Existing validated DHCP timer relation normalization only; lease remaining time within2s; raw packets preserved.'}
    report.update(negative_controls=negative,coverage=coverage(checklist,corpus,results),owner_liveness_disposition='The FIFO witness requires C blocked DNS, Rust live DNS, and both deferring DHCP until EOF; the explicit owner-liveness difference is kept separately from bank semantics.')
    save(args.out/'result.json',report);return int(bool(failures))


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--audit-trace':
        print(json.dumps(audit_trace(Path(sys.argv[3]),sys.argv[2])));raise SystemExit(0)
    if len(sys.argv)>1 and sys.argv[1]=='--self-test':
        print(json.dumps({'scenarios':len(scenarios()),'negative_controls':controls()}));raise SystemExit(0)
    if len(sys.argv)>1 and sys.argv[1]=='--trace-malformed-inotify':
        raise SystemExit(trace_malformed_inotify(int(sys.argv[2]),int(sys.argv[3]),sys.argv[4]))
    if len(sys.argv)>1 and sys.argv[1]=='--exec-watch-fault':exec_watch_fault(sys.argv[2:])
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--source-commit',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--side',choices=['c','rust','both'],default='both');p.add_argument('--case',action='append');raise SystemExit(main(p.parse_args()))
