#!/usr/bin/env python3
"""IPv4 dhcp-range family against exact-image C in disposable namespaces.

The first phase freezes parser and ordinary range observations. Packet transport
and namespaces reuse the existing DHCP matrix helpers; expected packets always
come from image C. Raw output and failed runs remain in private evidence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import m5_option_matrix_dhcp as dhcp
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from m5_dhcp_tags_options import options, primary_options
from test_single_poll_service import stop

SERVER = '10.77.0.1'


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def syntax_cases():
    values = [
        ('range-basic', 'normal', '10.77.0.10,10.77.0.14'),
        ('range-reverse', 'reverse', '10.77.0.14,10.77.0.10'),
        ('range-one-address', 'single', '10.77.0.10,10.77.0.10'),
    ]
    for prefix in ['lan', 'red', 'dead', '1234', '1.2.3', '2001:db8::1', '',
                   'set:dead', 'set:pool', 'tag:match', 'net:match', 'tag:!blocked',
                   'set:,red', 'tag:,net:,set:', 'set:a,set:b', 'red,blue']:
        values.append(('range-prefix-grammar', 'prefix-'+str(len(values)), prefix+',10.77.0.10,10.77.0.14'))
    for value in ['', '0', '119S', '121s', '1m', '2M', '1H', '1D', '1W', 'h',
                  'infinite', 'deprecated', 'DEPRECATED', 'word', '-1', '1 h',
                  '2147483647', '2147483648', '4294967295', '4294967296',
                  '4294967297', '2147483647w', '18446744073709551616']:
        group = ('range-wide-lease' if any(c.isdigit() for c in value) and len(value)>8
                 else 'range-infinite-deprecated' if value in ('infinite','deprecated','DEPRECATED')
                 else 'range-lease-grammar')
        values.append((group, 'lease-'+str(len(values)), '10.77.0.10,10.77.0.14,'+value))
    for value in [
        '10.77.0.10,10.77.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.200',
        '10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0,600',
        '10.77.0.10,10.77.0.14,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.0.255.0',
        '10.77.0.10,10.78.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,10.77.0.255',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600,extra',
        '10.77.0.10,static', '10.77.0.10,proxy',
    ]:
        values.append(('range-mask-grammar', 'mask-'+str(len(values)), value))
    for value in ['10.77.0.10', 'bad', '10.77.0.10,broken', '10.77.0.10,10.77.0.14,1.2.3',
                  '::,constructor:br-lan,ra-stateless', '2001:db8::10,2001:db8::20',
                  '0.0.0.0,255.255.255.255', '0.0.0.0,255.255.255.255,0.0.0.0']:
        values.append(('range-invalid','invalid-'+str(len(values)),value))
    return [{'name': group+'--'+name, 'group': group, 'ranges': [value], 'events': []}
            for group,name,value in values]


def service_cases():
    def event(name, action='discover', **fields):
        return dict(id=name, action=action, flags=0x8000, **fields)
    def row(name, ranges, events, extra=''):
        return dict(name=name, group=name.split('--')[0], ranges=ranges, events=events, extra=extra)
    yield row('range-basic--dora', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'),event('ack','select',address='assigned'),event('release','release',address='assigned')])
    yield row('range-reverse--offer', ['10.77.0.14,10.77.0.10,255.255.255.0,600'], [event('offer')])
    yield row('range-one-address--exhaust', ['10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('first'),event('ack','select',address='assigned'),event('exhausted',client=2)])
    for name, tail in [('absent',''),('empty',','),('deprecated',',deprecated'),('infinite',',infinite'),
                       ('minimum',',0'),('wide',',4294967297')]:
        yield row('range-lease-wire--'+name, ['10.77.0.10,10.77.0.14'+tail], [event('offer')])
    yield row('range-static--known-unknown', ['10.77.0.0,static,255.255.255.0,600'],
              [event('known'),event('ack','select',address='10.77.0.40'),event('unknown',client=2)],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n')
    yield row('range-proxy--ordinary-pxe', ['10.77.0.0,proxy,255.255.255.0,600'],
              [event('ordinary'),event('pxe',packet={'extra':[[60,b'PXEClient'.hex()],[93,'0000']]},prl=[43,60])],
              'pxe-service=0,Range fixture,boot.bin\n')
    yield row('range-tag-priority--matched', ['10.77.0.10,10.77.0.10,255.255.255.0,600',
                                           'tag:selected,set:chosen,10.77.0.20,10.77.0.20,255.255.255.0,600'],
              [event('without-tag'),event('with-tag',packet={'extra':[[60,b'Matrix'.hex()]]})],
              'dhcp-vendorclass=set:selected,Matrix\ndhcp-option=tag:chosen,224,2\n')


def configuration(case):
    lines=['no-hosts','no-resolv','user=root','group=root','port=15353',
           'interface=br-lan','no-ping','host-record=matrix.ready,8.8.8.8',
           'dhcp-authoritative','dhcp-leasefile=/m2/range.leases','pid-file=/m2/range.pid']
    lines.extend('dhcp-range='+value for value in case['ranges'])
    return '\n'.join(lines)+'\n'+case.get('extra','')


def lease_snapshot(root, observed_at, durations):
    file=root/'m2/range.leases'; text=file.read_text() if file.exists() else ''
    rows=[]
    for line in text.splitlines():
        fields=line.split()
        if not fields: continue
        if fields[0].isdigit():
            expires=int(fields[0]); address=fields[2]
            if expires:
                duration=durations[address]
                assert observed_at-3+duration <= expires <= observed_at+1+duration, (fields,duration)
                fields[0]='finite-'+str(duration)
            else: fields[0]='infinite'
        rows.append(fields)
    return text,sorted(rows)


def decode(raw):
    if raw['reply'] is None: return None
    wire=bytes.fromhex(raw['reply']);opts=options(wire);values={code:bytes.fromhex(value) for code,value in opts}
    return {'wire':raw['reply'],'options':opts,'status':values.get(53,b'\0')[0],
            'address':socket.inet_ntoa(wire[16:20]),'server':socket.inet_ntoa(values[54]) if 54 in values else None,
            'lease_time':int.from_bytes(values[51],'big') if 51 in values else None,'destination':raw['destination']}


def run(root, side, case, folder, syntax_only):
    folder.mkdir();text=configuration(case);(root/'m2/range.conf').write_text(text);(folder/'config').write_text(text)
    for name in ['range.leases','range.pid']:(root/'m2'/name).unlink(missing_ok=True)
    syntax=subprocess.run(command(root,side,'--test','-C','/m2/range.conf'),capture_output=True,timeout=5)
    result={'status':'failed','syntax':{'exit':syntax.returncode,'stdout':syntax.stdout.decode(errors='replace'),
            'stderr':syntax.stderr.decode(errors='replace')},'rows':[],'planned':len(case['events']), 'startup':None}
    (folder/'syntax.stdout').write_bytes(syntax.stdout);(folder/'syntax.stderr').write_bytes(syntax.stderr)
    if syntax_only:
        result['status']='ok' if syntax.returncode in (0,1) else 'failed'
        save(folder/'observed.json',result);return result
    network=process=None
    try:
        network=dhcp.setup_network(case)
        with (folder/'stdout').open('wb') as stdout,(folder/'stderr').open('wb') as stderr:
            process=subprocess.Popen(command(root,side,'-k','-C','/m2/range.conf'),stdout=stdout,stderr=stderr,start_new_session=True)
            deadline=time.monotonic()+3
            while process.poll() is None and time.monotonic()<deadline:
                try:
                    if dhcp.dns_health()['records'][0]['data']=='8.8.8.8':break
                except (socket.timeout,OSError):time.sleep(.01)
            ready=process.poll() is None and time.monotonic()<deadline
            result['startup']={'ready':ready,'exit':process.poll()}
            if not ready:
                if syntax.returncode==0:raise AssertionError('valid config did not start')
            else:
                result['identity']=process_identity(root,process.pid)
                assigned={};durations={}
                for index,source_event in enumerate(case['events']):
                    event=dhcp.wire_event(source_event,assigned)
                    output=network.exec(sys.executable,str(Path(dhcp.__file__).resolve()),'--client',json.dumps({'event':event,'xid':0xb500+index}))
                    raw=json.loads(output.stdout);observed=decode(raw);save(folder/f'{index:03}.raw.json',raw)
                    if observed and observed['status'] in (2,5):
                        assigned[str(event.get('client',1))]=observed['address']
                        if observed['lease_time'] is not None:durations[observed['address']]=observed['lease_time']
                    text,leases=lease_snapshot(root,time.time(),durations);(folder/f'{index:03}.leases').write_text(text)
                    result['rows'].append({'id':event['id'],'response':observed,'leases':leases,'health':dhcp.dns_health()})
            result['status']='ok'
    except Exception as error:result['error']=repr(error)
    finally:
        if process is not None:
            ended=stop(process);result['exit']=process.returncode;result['forced']=ended['forced'];result['reaped']=not Path(f'/proc/{process.pid}').exists()
        if network is not None:
            result['network_cleanup']=network.close()
            if result['network_cleanup']['forced'] or result['network_cleanup']['returncode']!=-signal.SIGTERM:
                result['status']='failed'
        result['interfaces_clean']=[name for _,name in socket.if_nameindex()]==['lo'];result['pid_removed']=not(root/'m2/range.pid').exists()
        if not result['interfaces_clean'] or not result['pid_removed'] or result.get('forced'):result['status']='failed'
        if result.get('exit') != (0 if syntax.returncode==0 else 1):result['status']='failed'
        save(folder/'observed.json',result)
    return result


def comparable(observed):
    value=copy.deepcopy(observed)
    for stream in ['stdout','stderr']:
        value['syntax'][stream]=value['syntax'][stream].replace('dnsmasq-rs:','dnsmasq:')
    return {key:value.get(key) for key in ['status','syntax','startup','rows','exit','forced','reaped','interfaces_clean','pid_removed']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both')
    parser.add_argument('--syntax',action='store_true');parser.add_argument('--case',action='append');parser.add_argument('--source-commit')
    args=parser.parse_args();assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert [name for _,name in socket.if_nameindex()]==['lo'];assert 'private' in args.out.resolve().parts and not args.out.exists()
    root=prepare(args.image_root,None,args.out/'image',args.rust);(root/'m2').chmod(0o777)
    cases=syntax_cases() if args.syntax else list(service_cases())
    if args.case:cases=[case for case in cases if case['name'] in args.case or case['group'] in args.case]
    assert cases;save(args.out/'plan.json',cases)
    result={'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'source_commit':args.source_commit,
            'tool_sha256':sha256(__file__),'comparison_executed':args.side=='both','cases':[],'failures':[]}
    for case in cases:
        folder=args.out/case['name'];folder.mkdir();observations={}
        for side in ['c','rust'] if args.side=='both' else [args.side]:observations[side]=run(root,side,case,folder/side,args.syntax)
        errors=[]
        if any(row['status']!='ok' for row in observations.values()):errors.append('failed-side')
        if args.side=='both' and comparable(observations['c'])!=comparable(observations['rust']):errors.append('difference')
        result['cases'].append({'name':case['name'],'group':case['group'],'errors':errors})
        if errors:result['failures'].append(case['name'])
        save(args.out/'result.json',result)
    result['passed']=not result['failures'];save(args.out/'result.json',result)
    print(json.dumps({'passed':result['passed'],'cases':len(cases),'failures':result['failures']}));return int(not result['passed'])


if __name__=='__main__':raise SystemExit(main())
