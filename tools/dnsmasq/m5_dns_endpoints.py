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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--source-commit',required=True);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','both'],default='both');parser.add_argument('--case',action='append')
    args=parser.parse_args();assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert not args.out.exists() and 'private' in args.out.parts
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));args.out.mkdir(parents=True)
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
