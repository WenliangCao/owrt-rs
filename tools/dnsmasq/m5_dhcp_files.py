#!/usr/bin/env python3
"""Exact-image DHCP static/dynamic file-bank family differential.

One isolated owner, existing packet/parser comparators, preserved raw wire and
file mutations. Directory semantics deliberately remain DHCP append semantics.
"""
from __future__ import annotations
import argparse
import copy
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
    return rows


def config(scenario):
    return wire.config({'fixed_host':False,'text':'user=root\ngroup=root\nhost-record=health.test,192.0.2.7\n'+scenario['config'].format(base=BASE)+'\n'})


def install(root,scenario):
    folder=root/BASE.lstrip('/')
    if folder.exists():shutil.rmtree(folder)
    folder.mkdir()
    for name,text in scenario['files'].items():
        path=folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    for name in ['family.pid','family.leases']:(root/'m2'/name).unlink(missing_ok=True)
    return folder


def health():
    return wire.dns_observe('health.test',1,0xF11E)


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
    (out/'config').write_text(text);(root/'m2/files.conf').write_text(text)
    result={'side':side,'scenario':scenario['name'],'rows':[],'started':False};process=None;owned=set()
    with (out/'daemon.log').open('wb') as log,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.bind(('0.0.0.0',68));endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);endpoint.setsockopt(socket.SOL_SOCKET,25,b'lo\0')
        try:
            result['syntax']=wire.syntax(root,side,text,out/'syntax');assert result['syntax']['exit']==0,'--test rejection'
            process=subprocess.Popen(command(root,side,'-k','-C','/m2/files.conf'),stdout=log,stderr=log,start_new_session=True)
            deadline=time.monotonic()+3
            while True:
                assert process.poll() is None,'startup exit'
                try:
                    with socket.create_connection(('127.0.0.1',15353),.05):break
                except OSError:pass
                if time.monotonic()>deadline:raise AssertionError('startup deadline')
                time.sleep(.01)
            time.sleep(.05)
            result.update(started=True,identity=process_identity(root,process.pid),threads=len(list(Path(f'/proc/{process.pid}/task').iterdir())))
            result['health_before']=health()
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
                    path=folder/event['path'];path.parent.mkdir(parents=True,exist_ok=True);path.write_text(event['text']);time.sleep(.1)
                elif event['op']=='mkdir':(folder/event['path']).mkdir()
                elif event['op']=='unlink':(folder/event['path']).unlink();time.sleep(.1)
                elif event['op']=='rename':(folder/event['path']).rename(folder/event['to']);time.sleep(.1)
                elif event['op']=='hup':process.send_signal(signal.SIGHUP);time.sleep(.15)
                else:raise AssertionError('unknown event')
                leases,observed['leases']=lease_state(root);(out/f'{index:03}.leases').write_text(leases)
                observed['health']=health();result['rows'].append(observed);save(out/'result.json',result)
            result['health_after']=health()
        except Exception as error:result['error']=repr(error)
        finally:
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
    for key in ['started','threads','health_before','health_after','exit','pid_removed','forced','remaining','error']:
        if c.get(key)!=rust.get(key):failures.append(key)
    if wire.comparable_syntax(c.get('syntax',{}))!=wire.comparable_syntax(rust.get('syntax',{})):failures.append('syntax')
    if len(c['rows'])!=len(rust['rows']):failures.append('row count')
    for first,second in zip(c['rows'],rust['rows']):
        for key in ['index','event','alive','health','peer','comparable']:
            if first.get(key)!=second.get(key):failures.append(f"{first['index']}:{key}")
        left,right=first['leases'],second['leases']
        if len(left)!=len(right):failures.append(f"{first['index']}:lease count");continue
        for x,y in zip(left,right):
            if x['fields']!=y['fields'] or (x['remaining'] is None)!=(y['remaining'] is None) or (x['remaining'] is not None and abs(x['remaining']-y['remaining'])>2):failures.append(f"{first['index']}:lease")
    return failures


def main(args):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert sorted(name for _,name in socket.if_nameindex())==['lo']
    assert not args.out.exists() and 'private' in args.out.parts;args.out.mkdir(parents=True)
    corpus=[s for s in scenarios() if not args.case or s['name'] in args.case]
    assert corpus and (not args.case or len(corpus)==len(set(args.case)))
    sources=args.out/'executed-tools';sources.mkdir()
    for module in list(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).resolve().parent==Path(__file__).resolve().parent:shutil.copy2(path,sources/Path(path).name)
    shutil.copy2(__file__,sources/Path(__file__).name)
    root=prepare(args.image_root,None,args.out,args.rust)
    manifest={'scenarios':corpus,'source_commit':args.source_commit,'tool_sha256':sha256(__file__),'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'elf_bytes':args.rust.stat().st_size,'sides':['c','rust'] if args.side=='both' else [args.side]}
    save(args.out/'manifest.json',manifest);results=[];failures=[]
    for scenario in corpus:
        rows={side:run_side(root,side,scenario,args.out/(scenario['name']+'-'+side)) for side in manifest['sides']}
        errors=[]
        for side,value in rows.items():
            if not value['started'] or value.get('error') or value.get('exit')!=0 or value.get('forced') or value.get('remaining') or not value['pid_removed'] or value.get('threads')!=1 or len(value['rows'])!=len(scenario['events']):errors.append(side+': lifecycle/events')
        if args.side=='both':errors+=compare(rows['c'],rows['rust'])
        results.append({'scenario':scenario['name'],'sides':rows,'errors':errors});failures.extend(scenario['name']+': '+e for e in errors)
        save(args.out/'result.json',{'passed':False,'results':results,'failures':failures})
        print(json.dumps({'scenario':scenario['name'],'errors':errors}),flush=True)
    report={'passed':not failures and args.side=='both','reference_checks_passed':not failures,'comparison_executed':args.side=='both','c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'results':results,'failures':failures,'configuration_count':len(corpus),'event_count':sum(len(s['events']) for s in corpus),'normalization':'Existing validated DHCP timer relation normalization only; lease remaining time within2s; raw packets preserved.'}
    save(args.out/'result.json',report);return int(bool(failures))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--source-commit',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--side',choices=['c','rust','both'],default='both');p.add_argument('--case',action='append');raise SystemExit(main(p.parse_args()))
