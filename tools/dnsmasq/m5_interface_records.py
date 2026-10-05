#!/usr/bin/env python3
"""Exact-image interface/domain/synthetic/hostsdir family, isolated namespaces.

C-only calibration never qualifies an option. Every eventual frozen required
row needs concrete paired observations, complete identities and cleanup.
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
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
    return cases


def run_service_side(root,side,case,out):
    states=[];dynamic=[]
    original_put=files.put;original_exchange=files.exchange
    def record(label):
        states.append({'label':label,'at':time.monotonic(),'addresses':json.loads(subprocess.check_output(['ip','-j','address','show'],text=True)),
            'ipv6_flags':Path('/proc/net/if_inet6').read_text()})
    def put(root,path,value,opened):
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
            dynamic.append({'id':action['id'],'address':temporary,'name':action['name'],'kernel':raw})
        return original_exchange(port,action,*args)
    files.put=put;files.exchange=exchange
    try:result=endpoints.run_service_side(root,side,case,out)
    finally:
        files.put=original_put;files.exchange=original_exchange
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
            if row['id'].startswith(dynamic['id']+':'):
                response=row.get('response')
                if not response or response['questions'][0][0]!=dynamic['name'] or not any(record['type']==12 for record in response['records']):
                    raise AssertionError('actual privacy-address PTR answer missing')
                response['questions'][0][0]='actual-temporary-address'
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


if __name__=='__main__':raise SystemExit(main())
