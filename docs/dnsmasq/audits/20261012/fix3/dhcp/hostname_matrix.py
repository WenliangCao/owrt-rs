#!/usr/bin/env python3
"""Independent three-way DHCP hostname/state audit; synthetic isolated traffic.

Uses the repository's transport/framing decoder, replacing the case generator.
Raw packets/config/logs stay in --out (must be under private/).
"""
import argparse, hashlib, json, os, socket, sys, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--main',type=Path,required=True);p.add_argument('--fix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert 'private' in a.out.resolve().parts
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
import audit_20261011_dhcp as base
from m2_rootfs import image_elf_command
orig=base.packet

def packet(kind,xid,mac=1,rapid=False,wanted=True,name=None,fqdn=None,clid=None,ciaddr=None,server='127.0.0.1',hlen=6,vendor=None):
    data=bytearray(orig(kind,xid,mac,rapid,False,None));data[2]=hlen
    if ciaddr:data[12:16]=socket.inet_aton(ciaddr)
    head=data[:240];pos=240
    while pos<len(data):
        code=data[pos];pos+=1
        if code==255:break
        size=data[pos];val=data[pos+1:pos+1+size];pos+=size+1
        if code!=54:head+=base.option(code,val)
    if wanted:head+=base.option(50,socket.inet_aton('127.0.0.30' if wanted is True else wanted))
    if kind==3 and server:head+=base.option(54,socket.inet_aton(server))
    if name is not None:head+=base.option(12,name.encode())
    if fqdn is not None:head+=base.option(81,bytes.fromhex(fqdn))
    if clid is not None:head+=base.option(61,bytes.fromhex(clid))
    if vendor is not None:head+=base.option(60,vendor.encode())
    return bytes(head)+b'\xff'
base.packet=packet

def normalize(row):
    row=json.loads(json.dumps(row))
    for event in row['events']:
        inp=event['input'];reply=event['reply']
        if inp['kind']==3 and inp.get('wanted',True) is False and inp.get('ciaddr') and reply and reply['message_type']==5:
            opts=reply['options'];lease=int(opts['51'],16);t1=int(opts['58'],16);t2=int(opts['59'],16)
            fuzz=lease//2-t1
            assert 0<=fuzz<=lease//16 and t2==lease*7//8-fuzz,(t1,t2,lease)
            opts['58']=(lease//2).to_bytes(4,'big').hex();opts['59']=(lease*7//8).to_bytes(4,'big').hex()
    return row

cases=list(base.cases())
policies={
 'none':'',
 'ignore':'dhcp-ignore-names=tag:pool\n',
 'generate':'dhcp-generate-names=tag:pool\n',
 'ignore-generate':'dhcp-ignore-names=tag:pool\ndhcp-generate-names=tag:pool\n',
 'tag-if':'tag-if=set:names,tag:pool\ndhcp-ignore-names=tag:names\ndhcp-generate-names=tag:names\n',
 'static-name':'dhcp-host=02:00:00:00:00:01,127.0.0.30,configured\n',
 'hosts-name':'addn-hosts={hosts}\ndomain=test\n',
}
name_inputs={
 'plain':{'name':'claimed'},
 'domain':{'name':'claimed.test'},
 'none':{},
 'fqdn-text':{'fqdn':(b'\x00\x00\x00claimed.test').hex()},
 'fqdn-wire':{'fqdn':(b'\x04\x00\x00\x07claimed\x04test\x00').hex()},
 'fqdn-leading-dot':{'fqdn':(b'\x00\x00\x00.test').hex()},
}
for policy,config in policies.items():
    for label,fields in name_inputs.items():
        for mode in ['select','rapid']:
            event=dict(kind=3 if mode=='select' else 1,rapid=mode=='rapid',**fields)
            cases.append(dict(name=f'{policy}-{label}-{mode}',config=config,hosts='127.0.0.30 authoritative.test\n',events=[event]))
# Retain a previous accepted name when a later client name is suppressed.
for mode in ['select','rapid','renew','inform']:
    event=dict(kind={'select':3,'rapid':1,'renew':3,'inform':8}[mode],mac=1,name='replacement',vendor='ignore',rapid=mode=='rapid')
    if mode in ['renew','inform']:event.update(wanted=False,ciaddr='127.0.0.30',server=None)
    cases.append(dict(name='retained-'+mode,config='dhcp-vendorclass=set:blocked,ignore\ndhcp-ignore-names=tag:blocked\n',events=[dict(kind=3,name='claimed'),event]))
# Multi-MAC handoff without a configured hostname exercises non-authoritative names.
for mode in ['select','rapid','renew']:
    event=dict(kind=1 if mode=='rapid' else 3,mac=2,name='replacement',rapid=mode=='rapid')
    if mode=='renew':event.update(wanted=False,ciaddr='127.0.0.30',server=None)
    cases.append(dict(name='unnamed-handoff-'+mode,config='dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30\n',events=[dict(kind=3,name='claimed'),event]))

a.out.mkdir(parents=True,exist_ok=False)
stock=a.image/'usr/sbin/dnsmasq';assert base.sha(stock)==base.STOCK_SHA256
commands={side:image_elf_command(a.image,path) for side,path in [('c',stock),('main',a.main),('fix',a.fix)]}
report=dict(script_sha256=base.sha(__file__),binary_sha256={side:base.sha(path) for side,path in [('c',stock),('main',a.main),('fix',a.fix)]},cases=[])
for i,case in enumerate(cases):
    rows={side:base.execute(cmd,case,a.out/(case['name']+'-'+side)) for side,cmd in commands.items()}
    norm={side:normalize(row) for side,row in rows.items()}
    report['cases'].append(dict(name=case['name'],config=case['config'],main_matches_c=norm['main']==norm['c'],fix_matches_c=norm['fix']==norm['c'],fix_matches_main=norm['fix']==norm['main'],observed=rows))
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(i+1,case['name'],*[side+':'+str(norm[side]==norm['c']) for side in ['main','fix']],flush=True)
print(json.dumps({'cases':len(report['cases']),'main_c':sum(r['main_matches_c'] for r in report['cases']),'fix_c':sum(r['fix_matches_c'] for r in report['cases']),'changed':sum(not r['fix_matches_main'] for r in report['cases'])}))
