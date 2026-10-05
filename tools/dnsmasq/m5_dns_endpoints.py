#!/usr/bin/env python3
"""Exact-image endpoint/source-socket family; only disposable namespaces.

The initial syntax corpus establishes image libc expansion and error boundaries.
Service, source tuple, sharing and reload cases are separate gates in this same
family driver. Syntax alone never closes an endpoint option.
"""
from __future__ import annotations
import argparse
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
        actions=extra.pop('actions', [probe('query-'+str(i), name, transports=['udp','tcp']) for i,name in enumerate(names)])
        cases.append(dict(id=ident,config='no-resolv\n'+config,files=extra.pop('files',{}),actions=actions,default_resolv=False,strict_order='all-servers' not in config,**extra))
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
    add('osport-zero-then-fixed','server=127.0.0.2\n',argv=['--query-port=0','--query-port=34003'],expected_source_port=34003)
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
        add('allservers-port-limit-'+str(limit),'port-limit='+str(limit)+'\nserver=127.0.0.2\nserver=127.0.0.3\nserver=127.0.0.4\nall-servers\n',udp_unique_ports= max(1,min(3,limit)),expected_start=limit!=0,expected_test=1 if limit==0 else 0)
    add('pool-single-port-concurrent','min-port=34100\nmax-port=34100\nserver=127.0.0.2\n',actions=[dict(op='start-udp',id='first',name='first.endpoint.test'),dict(op='start-udp',id='second',name='second.endpoint.test'),dict(op='inject',id='second',server=0),dict(op='receive-udp',id='second',pending='second'),dict(op='inject',id='first',server=0),dict(op='receive-udp',id='first',pending='first')],source_range=[34100,34100],same_udp_port=True)
    add('file-mixed-directives','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/v4.endpoint.test\nrev-server=192.0.2.0/24,multi.endpoint.test\nserver=/two.endpoint.test/127.0.0.3\nserver=/local.endpoint.test/\n'},names=('one.endpoint.test','7.2.0.192.in-addr.arpa','two.endpoint.test','local.endpoint.test'),sys_files={'/etc/hosts':HOSTS})
    add('file-errors-continue','servers-file=/m2/files/servers\n',files={'servers':'server=/bad.endpoint.test/::1%missing\nserver=/one.endpoint.test/v4.endpoint.test\nserver=/badsource.endpoint.test/127.0.0.2@::1\nserver=/two.endpoint.test/127.0.0.3\n'},names=('one.endpoint.test','two.endpoint.test','bad.endpoint.test','badsource.endpoint.test'),sys_files={'/etc/hosts':HOSTS},diagnostics=True)
    add('file-partial-hostname-scope','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/mixed.endpoint.test%missing\nserver=/two.endpoint.test/127.0.0.3\n'},names=('one.endpoint.test','two.endpoint.test'),sys_files={'/etc/hosts':HOSTS},diagnostics=True)
    add('file-hosts-hup-no-auto','servers-file=/m2/files/servers\n',files={'servers':'server=/one.endpoint.test/v4.endpoint.test\n'},sys_files={'/etc/hosts':HOSTS},actions=[probe('initial','one.endpoint.test'),dict(op='write-system',path='/etc/hosts',text='127.0.0.3 v4.endpoint.test\n'),probe('no-auto','one.endpoint.test'),signal_reload(),probe('changed','one.endpoint.test')])
    add('file-source-snapshot','servers-file=/m2/files/servers\n',files={'servers':'server=127.0.0.2@127.0.0.9#34004\n'},actions=[dict(op='connect',id='held'),probe('old','old.endpoint.test',transports=['held']),write('servers','server=127.0.0.3@127.0.0.8#34005\n'),signal_reload(),probe('parent','parent.endpoint.test'),probe('child','child.endpoint.test',transports=['held']),dict(op='disconnect',id='held'),probe('fresh','fresh.endpoint.test')])
    return cases


class SourceCapture:
    instances=[]


def run_service_side(root, side, case, folder):
    import m5_dns_files as files
    from dns_service_probe import exact_read, read_name
    class Captured(files.FileUpstream):
        def __init__(self,*args):
            self.source_events=[]
            super().__init__(*args)
            SourceCapture.instances.append(self)
        def udp_loop(self):
            while not self.stop.is_set():
                try:
                    packet,peer=self.udp.recvfrom(65535)
                    response=self.answer(packet,'udp')
                    self.source_events.append(dict(transport='udp',peer=list(peer),destination=list(self.udp.getsockname()),name=read_name(packet,12)[0],wire=packet.hex()))
                    self.captured.append((packet,peer,response))
                    if self.probes.get((read_name(packet,12)[0],struct.unpack_from('!H',packet,read_name(packet,12)[1])[0]),{}).get('drop_all'): continue
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
    original_command=files.command
    files.command=lambda root,side,*args: original_command(root,side,*case.get('argv',[]),*args)
    try:
        for port in case.get('occupied_ports',[]):
            bound=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);bound.bind(('0.0.0.0',port));occupied.append(bound)
        result=files.run_side(root,side,case,folder)
    finally:
        for bound in occupied: bound.close()
        files.command=original_command
    result['source_events']=[row for upstream in SourceCapture.instances for row in upstream.source_events]
    result['fixture_errors']=[error for upstream in SourceCapture.instances for error in upstream.errors]
    result['source_guard_errors']=source_guard_errors(result,case)
    save(folder/'observed.json',result)
    return result


def source_guard_errors(result,case):
    errors=[]
    if not result['startup']['ready']: return errors
    udp=[row for row in result['source_events'] if row['transport']=='udp']
    tcp=[row for row in result['source_events'] if row['transport']=='tcp']
    ports={row['peer'][1] for row in udp}
    if case.get('expected_source_port') is not None and any(port!=case['expected_source_port'] for port in ports): errors.append('fixed source port differs')
    if case.get('forbidden_udp_port') in ports: errors.append('explicit source inherited global port')
    if case.get('source_range') and any(not case['source_range'][0]<=port<=case['source_range'][1] for port in ports): errors.append('source outside inclusive range')
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
        row=copy.deepcopy(original);row.pop('wire',None)
        port=row['peer'][1]
        key=(row['transport'],port)
        if port not in exact:
            if key not in ports: ports[key]='port'+str(len(ports))
            row['peer'][1]=ports[key]
        if len(row['peer'])>3: row['peer'][3]=bool(row['peer'][3])
        if len(row['destination'])>3: row['destination'][3]=bool(row['destination'][3])
        result.append(row)
    return result

def run_service(args, cases):
    import m5_dns_files as files
    args.out.mkdir(parents=True)
    driver=args.out/'driver';driver.mkdir()
    for name in ('m5_dns_endpoints.py','m5_dns_endpoints.json','m5_dns_files.py','m5_option_matrix.py','m5_option_matrix_probes.py','m5_dhcp_tags_options.py','dhcp_boot_service_diff.py','dns_service_probe.py','m2_rootfs.py','run_isolated.sh'):
        shutil.copy2(Path(__file__).with_name(name),driver/name)
    sides=['c','rust'] if args.side=='both' else ['c']
    roots={side:prepare(args.image_root,None,args.out/side,args.rust) for side in sides}
    save(args.out/'schedule.json',cases)
    report={'mode':'service','source_commit':args.source_commit,'rust_sha256':sha256(args.rust),'rust_bytes':args.rust.stat().st_size,'c_sha256':STOCK_SHA256,'comparison_executed':args.side=='both','cases':[],'failures':[],'closed_options':[]}
    for case in cases:
        folder=args.out/case['id'];folder.mkdir()
        row={'id':case['id'],'failures':[]}
        try:
            observed={side:run_service_side(roots[side],side,case,folder/side) for side in sides}
            if observed['c']['syntax']['exit']!=case.get('expected_test',0): row['failures'].append(dict(phase='c-syntax-calibration',observed=observed['c']['syntax']))
            if observed['c']['startup']['ready'] != case.get('expected_start',True): row['failures'].append(dict(phase='c-startup-calibration',observed=observed['c']['startup']))
            if any(entry.get('response') is None for entry in observed['c']['rows'] if entry['id'].endswith('udp-async')): row['failures'].append(dict(phase='c-async-calibration',error='missing awaited UDP reply'))
            if args.side=='both':
                row['failures'].extend(files.compare(observed['c'],observed['rust'],case))
                c,rust=(source_projection(observed[side],case) for side in ('c','rust'))
                if c!=rust: row['failures'].append(dict(phase='source-tuples',c=c,rust=rust))
            for side,result in observed.items():
                row['failures'].extend(dict(phase='source-witness',side=side,error=error) for error in result['source_guard_errors']+result['fixture_errors'])
            row['rows']=len(observed['c']['rows'])
        except Exception as error: row['failures'].append(dict(phase='infrastructure',error=repr(error)))
        report['cases'].append(row)
        report['failures'].extend(dict(case=case['id'],**failure) for failure in row['failures'])
        save(args.out/'progress.json',report)
    save(args.out/'result.json',report)
    print(json.dumps({'cases':len(cases),'failures':len(report['failures']),'closed_options':[]}))
    return int(bool(report['failures']))

def main():
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
