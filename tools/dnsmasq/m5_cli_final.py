#!/usr/bin/env python3
"""Final ordinary option --test and log-malloc acceptance/startup evidence.

The complete frozen inventory is mandatory; selected or reference runs never
qualify. C owns expected acceptance, output and parse-side effects.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

from m2_rootfs import command, prepare, sha256
from dns_service_probe import query, semantics

HERE=Path(__file__).resolve().parent


def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def fixtures(root):
    path=root/'m2/cli';shutil.rmtree(path,ignore_errors=True);path.mkdir()
    for name in ['confdir','hostsdir','dhcp-hostsdir','dhcp-optsdir','tftp']:(path/name).mkdir()
    for name,content in {'empty.conf':'','include.conf':'host-record=included.test,192.0.2.3\n','resolv':'nameserver 127.0.0.2\n',
                         'servers':'server=192.0.2.53\n','hosts':'192.0.2.4 hosts.test\n','dhcp-hosts':'02:00:00:00:00:01,192.0.2.10,client\n','dhcp-options':'3,192.0.2.1\n'}.items():(path/name).write_text(content)
    for name,content in {'config-script':"#!/bin/sh\nprintf 'host-record=script.test,192.0.2.6\\n'\n: > /m2/cli/script-effect\n",'lease-script':'#!/bin/sh\n: > /m2/cli/lease-effect\n'}.items():
        (path/name).write_text(content);(path/name).chmod(0o755)
    return path


def syntax_case(root,args,spec):
    folder=args.out/spec['case'];folder.mkdir()
    path=fixtures(root)
    flags=['--test','--conf-file=/m2/cli/empty.conf',*['--'+value for value in spec.get('dependencies',[])]]
    if spec.get('form')=='cli':flags+=['--'+spec['directive']]
    elif spec.get('form')=='file':
        (path/'case.conf').write_text('\n'.join([*spec.get('dependencies',[]),spec['directive']])+'\n');flags=['--test','--conf-file=/m2/cli/case.conf']
    else:
        flags+=spec.get('argv',[])
        if spec.get('config') is not None:
            (path/'empty.conf').write_text(spec['config'])
    save(folder/'fixture.json',spec)
    result=subprocess.run(command(root,args.side,*flags),capture_output=True,timeout=5)
    (folder/'stdout').write_bytes(result.stdout);(folder/'stderr').write_bytes(result.stderr)
    artifacts={name:(path/name).exists() for name in ['pid','log','dump','leases','lease-effect']}
    assert not any(artifacts.values()),'--test created daemon-only runtime state'
    script=(path/'script-effect').exists()
    row=dict(case=spec['case'],option=spec.get('option','test'),form=spec.get('form','control'),exit=result.returncode,
             stdout=result.stdout.replace(b'dnsmasq-rs',b'dnsmasq').hex(),stderr=result.stderr.replace(b'dnsmasq-rs',b'dnsmasq').hex(),runtime_artifacts=artifacts,config_script_effect=script)
    return row


def test_controls():
    return [dict(case='test-empty'),dict(case='test-repeated',argv=['--test','--test']),
            dict(case='test-unknown-option',argv=['--unknown-cli-final']),
            dict(case='test-cross-option',config='bind-interfaces\nbind-dynamic\n'),
            dict(case='test-cname-loop',config='cname=one.test,two.test\ncname=two.test,one.test\n'),
            dict(case='test-no-runtime-artifacts',config='port=10553\npid-file=/m2/cli/pid\nlog-facility=/m2/cli/log\ndumpfile=/m2/cli/dump\ndhcp-range=192.0.2.10,192.0.2.20,255.255.255.0,10m\ndhcp-leasefile=/m2/cli/leases\ndhcp-script=/m2/cli/lease-script\n'),
            dict(case='test-conf-script-effects',argv=['--conf-script=/m2/cli/config-script'])]


def trace_lines(data):
    parsed=[]
    for line in data.splitlines():
        match=re.search(rb'(malloc|realloc|expand_buf|expand_workspace|free): ([A-Za-z0-9_:]+):(\d+) (.*)',line)
        if not match:continue
        body=match[4]
        if match[1]==b'free':
            item=re.fullmatch(rb'block at ([0-9a-f]+)',body);assert item,'free trace syntax'
            pointers=[int(item[1],16)];size=None
        elif match[1]==b'malloc':
            item=re.fullmatch(rb'(\d+) bytes at ([0-9a-f]+)',body);assert item,'allocation trace syntax'
            size=int(item[1]);pointers=[int(item[2],16)]
        else:
            item=re.fullmatch(rb'(\d+) bytes from ([0-9a-f]+) to ([0-9a-f]+)',body);assert item,'reallocation trace syntax'
            size=int(item[1]);pointers=[int(item[2],16),int(item[3],16)]
        assert all(0<=pointer<=0xffffff for pointer in pointers),'real pointer hash range'
        parsed.append(dict(operation=match[1].decode(),function=match[2].decode(),line=int(match[3]),size=size,pointers=pointers))
    return parsed


class SyslogCollector:
    """Receive continuously so the fixture cannot backpressure ordinary logs."""
    def __init__(self,path):
        path.unlink(missing_ok=True);self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.socket.bind(str(path));self.socket.settimeout(.02);self.records=[];self.stop=threading.Event();self.error=None
        self.worker=threading.Thread(target=self.receive);self.worker.start()

    def receive(self):
        while not self.stop.is_set():
            try:self.records.append(self.socket.recv(65536))
            except socket.timeout:continue
            except Exception as error:self.error=repr(error);return

    def close(self):
        time.sleep(.05);self.stop.set();self.worker.join(1);self.socket.close()
        assert not self.worker.is_alive() and self.error is None,'independent syslog receiver health'
        return b'\n'.join(self.records)


def malloc_specs():
    return [dict(case='malloc-port-zero-gate',port_zero=True),dict(case='malloc-local-query',local=True),
            dict(case='malloc-forward-cache',forward=True),dict(case='malloc-hosts-hup',hosts=True),
            dict(case='malloc-tftp-lifecycle',tftp=True),dict(case='malloc-stderr-sink',forward=True),
            dict(case='malloc-file-sink',forward=True,file=True),dict(case='malloc-syslog-sink',forward=True,syslog=True),
            dict(case='malloc-signal-cleanup',local=True),dict(case='malloc-workload-no-overflow',forward=True,workload=True)]


def dns(name,ident=0x7a10):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(2);packet=query(name,1,ident);endpoint.sendto(packet,('127.0.0.1',10553));reply=endpoint.recv(4096)
    assert reply[:2]==packet[:2],'ordinary service health identity'
    return packet,reply


def malloc_case(root,args,spec):
    folder=args.out/spec['case'];folder.mkdir();path=fixtures(root)
    config=['port='+('0' if spec.get('port_zero') else '10553'),'no-hosts','no-resolv','listen-address=127.0.0.1','bind-interfaces','user=root','group=root',
            'pid-file=/m2/cli/pid','host-record=malloc.test,192.0.2.8','log-malloc']
    collector=None
    if spec.get('file'):config+=['log-facility=/m2/cli/allocation.log']
    elif not spec.get('syslog'):config+=['log-facility=-']
    if spec.get('syslog'):
        collector=SyslogCollector(root/'dev/log')
    upstream=None
    if spec.get('forward'):
        from m5_option_matrix import Upstream
        probes=[dict(name=('long-'+str(index)+'x'*48+'.malloc.test'),type=1,reply='192.0.2.8') for index in range(64 if spec.get('workload') else 4)]
        upstream=Upstream(probes,host='127.0.0.2',port=10561)
        config+=['server=127.0.0.2#10561','cache-size=5','query-port=10560']
    if spec.get('hosts'):
        config+=['addn-hosts=/m2/cli/hosts']
    if spec.get('tftp'):
        (path/'tftp/evidence').write_bytes(b'allocator-evidence')
        config+=['enable-tftp','tftp-root=/m2/cli/tftp','tftp-port-range=10690,10690']
    (path/'malloc.conf').write_text('\n'.join(config)+'\n');(folder/'config').write_text('\n'.join(config)+'\n')
    process=None;before=None;after=None
    try:
        with (folder/'stderr').open('wb') as log:
            process=subprocess.Popen(command(root,args.side,'-k','-C','/m2/cli/malloc.conf'),stdout=log,stderr=log)
            deadline=time.monotonic()+3
            while not (path/'pid').exists() and time.monotonic()<deadline:
                assert process.poll() is None,'log-malloc ordinary startup';time.sleep(.01)
            assert (path/'pid').exists(),'log-malloc ordinary readiness'
            before=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
            replies=[]
            if spec.get('local') or spec.get('forward') or spec.get('hosts'):
                for index,name in enumerate([probe['name'] for probe in probes] if upstream else ['malloc.test']):
                    request,reply=dns(name,0x7a10+index);(folder/f'{index}.request').write_bytes(request);(folder/f'{index}.reply').write_bytes(reply);replies.append(reply.hex())
            if spec.get('hosts'):
                (path/'hosts').write_text('192.0.2.9 changed.malloc.test\n');process.send_signal(signal.SIGHUP);time.sleep(.1)
                request,reply=dns('changed.malloc.test',0x7a70);(folder/'after-hup.request').write_bytes(request);(folder/'after-hup.reply').write_bytes(reply)
                assert any(record.get('data')=='192.0.2.9' for record in semantics(reply)['records']),'hosts reload allocation caller'
                replies.append(reply.hex())
            if spec.get('tftp'):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
                    endpoint.settimeout(2);endpoint.sendto(b'\0\1evidence\0octet\0',('127.0.0.1',69));reply,peer=endpoint.recvfrom(4096)
                    assert reply==b'\0\3\0\1allocator-evidence','actual TFTP allocation caller';endpoint.sendto(b'\0\4\0\1',peer)
                    (folder/'tftp.reply').write_bytes(reply)
                time.sleep(.05)
            after=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
            if spec.get('port_zero'):process.send_signal(signal.SIGHUP);time.sleep(.05)
            process.send_signal(signal.SIGTERM);assert process.wait(3)==0,'log-malloc ordinary service TERM'
        raw=collector.close() if collector else (path/'allocation.log').read_bytes() if spec.get('file') else (folder/'stderr').read_bytes();collector=None
        (folder/'allocator.raw').write_bytes(raw)
        parsed=trace_lines(raw);save(folder/'allocations.json',parsed)
        assert b'exiting on receipt of SIGTERM' in raw,'ordinary sink collected final shutdown notice'
        assert after==before,'allocation diagnostics introduced/leaked a descriptor'
        return dict(case=spec['case'],service_healthy=True,fd_stable=True,term_notice=True,
                    reply_semantics=[semantics(bytes.fromhex(reply)) for reply in replies],trace_seen=bool(parsed),
                    source_identity='c-util-wrappers' if args.side=='c' else 'rust-no-allocation-trace',allocation_records=len(parsed),
                    operations=sorted({record['operation'] for record in parsed}))
    finally:
        if process is not None and process.poll() is None:process.terminate();process.wait(3)
        if collector:collector.close()
        if upstream:upstream.close()


def run_side(args):
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','isolated namespace required'
    args.out.mkdir(parents=True,exist_ok=False);plan=json.loads((HERE/'m5_cli_final.json').read_text());save(args.out/'plan.json',plan)
    root=prepare(args.image_root,None,args.out/'filesystem',args.rust);rows=[];failures=[]
    tests=plan['test_cases']+test_controls() if args.family=='test' else [
        dict(case='malloc-syntax-file',option='log-malloc',form='file',directive='log-malloc'),
        dict(case='malloc-syntax-cli',option='log-malloc',form='cli',directive='log-malloc'),
        dict(case='malloc-syntax-repeat',option='log-malloc',form='control',config='log-malloc\nlog-malloc\n',argv=['--log-malloc','--log-malloc']),
        dict(case='malloc-syntax-argument',option='log-malloc',form='cli',directive='log-malloc=1'),
        dict(case='malloc-test-gate',option='log-malloc',form='cli',directive='log-malloc')]
    for spec in tests:
        try:rows.append(syntax_case(root,args,spec))
        except Exception as error:
            failure=dict(case=spec['case'],error=repr(error));failures.append(failure);save(args.out/spec['case']/'failure.json',failure)
    if args.family=='log-malloc':
        for spec in malloc_specs():
            try:rows.append(malloc_case(root,args,spec))
            except Exception as error:
                failure=dict(case=spec['case'],error=repr(error));failures.append(failure);save(args.out/spec['case']/'failure.json',failure)
    needed={spec['case'] for spec in plan['test_cases']}|set(plan['test_controls']) if args.family=='test' else set(plan['log_malloc_cases'])
    result=dict(side=args.side,family=args.family,rows=rows,failures=failures,missing=sorted(needed-{row['case'] for row in rows}),qualified=False,
                binary_sha256=sha256(args.image_root/'usr/sbin/dnsmasq' if args.side=='c' else args.rust))
    save(args.out/'result.json',result);print(json.dumps(dict(side=args.side,family=args.family,executed=len(rows),missing=len(result['missing']),failures=failures)))
    return bool(failures)


def qualify(out,family):
    plan=json.loads((HERE/'m5_cli_final.json').read_text());failures=[];pairs=[]
    sides={side:json.loads((out/side/'result.json').read_text()) for side in ['c','rust']}
    needed={spec['case'] for spec in plan['test_cases']}|set(plan['test_controls']) if family=='test' else set(plan['log_malloc_cases'])
    for side,result in sides.items():
        if result['failures'] or result['missing'] or {row['case'] for row in result['rows']}!=needed:
            failures.append(dict(side=side,kind='complete-frozen-inventory',failures=result['failures'],missing=result['missing']))
    rows={side:{row['case']:row for row in result['rows']} for side,result in sides.items()}
    for case in sorted(needed):
        if any(case not in rows[side] for side in rows):continue
        c,r=rows['c'][case],rows['rust'][case]
        if 'exit' in c:
            if c!=r:failures.append(dict(case=case,kind='exact-image-syntax-output-effects',c=c,rust=r))
            if family=='test' and c['form'] in ['cli','file'] and c['exit']!=0:
                failures.append(dict(case=case,kind='ordinary-C-option-form-rejected',exit=c['exit']))
            pairs.append(dict(case=case,contract='exact exit/stdout/stderr and parse-only effects',equal=c==r))
        else:
            shared=['service_healthy','fd_stable','term_notice','reply_semantics']
            if any(c[key]!=r[key] for key in shared):failures.append(dict(case=case,kind='ordinary-startup-service-sink-contract',c=c,rust=r))
            if not c['trace_seen'] or r['trace_seen']:
                failures.append(dict(case=case,kind='declared-allocation-content-difference',c=c,rust=r))
            pairs.append(dict(case=case,contract='ordinary startup/service/sink/FD/TERM; allocation content differs by explicit user scope',
                              allocation_records={side:rows[side][case]['allocation_records'] for side in rows},
                              allocation_content_equal=False))
    result=dict(family=family,qualified=not failures,paired_cases=len(pairs),failures=failures,pairs=pairs,
                binaries={side:value['binary_sha256'] for side,value in sides.items()},
                known_deferred=plan['known_deferred'],ordinary_option_count=169 if family=='test' else 1,
                allocation_content_difference=plan['log_malloc_contract'] if family=='log-malloc' else None)
    save(out/'result.json',result);print(json.dumps(dict(family=family,qualified=result['qualified'],paired_cases=len(pairs),failures=len(failures))))
    return not result['qualified']


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--family',choices=['test','log-malloc'],required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both')
    parser.add_argument('--qualify-existing',action='store_true')
    args=parser.parse_args()
    if args.qualify_existing:return qualify(args.out,args.family)
    if args.side!='both':return run_side(args)
    args.out.mkdir(parents=True,exist_ok=False)
    for side in ['c','rust']:
        separate=copy.copy(args);separate.side=side;separate.out=args.out/side;run_side(separate)
    return qualify(args.out,args.family)


if __name__=='__main__':raise SystemExit(main())
