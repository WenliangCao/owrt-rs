#!/usr/bin/env python3
"""Independent DHCP wire scenarios; reuse the established isolated transport only."""
import argparse, hashlib, json, os, socket, struct, sys
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--source',type=Path,required=True); p.add_argument('--rust',type=Path,required=True); p.add_argument('--image-root',type=Path,required=True); p.add_argument('--out',type=Path,required=True); a=p.parse_args()
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
import audit_20261011_dhcp as base
from m2_rootfs import image_elf_command
assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert 'private' in a.out.parts
orig=base.packet

def packet(kind,xid,mac=1,rapid=False,wanted=True,name=None,fqdn=None,clid=None,ciaddr=None,server='127.0.0.1',hlen=6):
    wire=bytearray(orig(kind,xid,mac,rapid,False,None))
    wire[2]=hlen
    if ciaddr: wire[12:16]=socket.inet_aton(ciaddr)
    # Remove auto-generated server-id, then append all chosen options.
    head=wire[:240]; pos=240
    while pos<len(wire):
        code=wire[pos]; pos+=1
        if code==255: break
        length=wire[pos]; val=wire[pos+1:pos+1+length]; pos+=1+length
        if code!=54: head+=base.option(code,val)
    if wanted: head+=base.option(50,socket.inet_aton('127.0.0.30' if wanted is True else wanted))
    if kind==3 and server: head+=base.option(54,socket.inet_aton(server))
    if name is not None: head+=base.option(12,name.encode())
    if fqdn is not None: head+=base.option(81,bytes.fromhex(fqdn))
    if clid is not None: head+=base.option(61,bytes.fromhex(clid))
    return bytes(head)+b'\xff'
base.packet=packet
cases=list(base.cases())
def add(name,config,events,hosts=''):
    cases.append(dict(name=name,config=config,events=events,hosts=hosts))
for rapid in [False,True]:
    prefix='rapid' if rapid else 'request'; event=dict(kind=1 if rapid else 3,rapid=rapid)
    for name in ['client.lan','.lan','client.','CLIENT','client\0','bad/name','']:
        add(prefix+'-hostname-'+name.encode().hex(),'domain=lan\n',[dict(event,name=name)])
    for flags in [0,1,4,5,8,9,12,13]:
        for name in ['client.lan','.lan','client.other']:
            val=(b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0') if flags&4 else name.encode()
            add(prefix+f'-fqdn-{flags}-'+name.encode().hex(),'domain=lan\n',[dict(event,fqdn=(bytes([flags,0,0])+val).hex())])
    for policy in ['dhcp-ignore-names=tag:derived\n','dhcp-generate-names=tag:derived\n','dhcp-ignore-names=tag:derived\ndhcp-generate-names=tag:derived\n']:
        for hosts in ['', '127.0.0.30 auth.lan\n']:
            add(prefix+'-tag-'+str(len(cases)), 'domain=lan\ntag-if=set:derived,tag:pool\n'+policy+('addn-hosts={hosts}\n' if hosts else ''), [dict(event,name='client')],hosts)
    for clid in [None,'01020000000001','00abcd']:
        add(prefix+'-handoff-'+str(clid),'dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual\n', [dict(kind=3,clid=clid),dict(event,mac=2,clid='01020000000002'),dict(event,mac=1,clid=clid),dict(event,mac=2,clid='01020000000002')])
    for second in [dict(name=None),dict(name='second'),dict(fqdn='0100007365636f6e642e6c616e')]:
        add(prefix+'-retained-'+str(len(cases)),'domain=lan\n',[dict(kind=3,name='first'),dict(event,**second)])
    add(prefix+'-configured-name-ignore','dhcp-host=02:00:00:00:00:01,127.0.0.30,fixed\ndhcp-ignore-names\ndhcp-generate-names\n',[dict(event,name='client')])
    add(prefix+'-name-matched-ignore','dhcp-host=client,127.0.0.30\ndhcp-ignore-names\n',[dict(event,name='client')])
    add(prefix+'-generate-no-mac','dhcp-generate-names\n',[dict(event,hlen=0,clid='00aabbcc')])
# Pool policy must select actual allocation when option 50 points at another address.
add('rapid-unavailable-requested-address','dhcp-ignore-names=tag:pool\n',[dict(kind=1,rapid=True,wanted='127.0.0.31',name='client')])
# Generated name should retain C precedence after an existing named lease.
add('rapid-previous-name-generated','dhcp-generate-names=tag:pool\n',[dict(kind=3,name='first'),dict(kind=1,rapid=True)])
add('rapid-ignore-keeps-existing','dhcp-ignore-names=tag:pool\n',[dict(kind=3,name='first'),dict(kind=1,rapid=True,name='second')])
a.out.mkdir(parents=True,exist_ok=False)
stock=a.image_root/'usr/sbin/dnsmasq'; assert base.sha(stock)==base.STOCK_SHA256
commands={'c':[str(a.image_root/'lib/ld-musl-aarch64.so.1'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(stock)],'rust':image_elf_command(a.image_root,a.rust)}
report={'rust_sha256':base.sha(a.rust),'c_sha256':base.sha(stock),'source_commit':(a.source/'.git-head').read_text().strip() if (a.source/'.git-head').exists() else '6b8eee96eda8aaa4cc47580530e5f287baeaaaa4','script_sha256':base.sha(__file__),'cases':[],'failures':[]}
for case in cases:
    rows={side:base.execute(cmd,case,a.out/f'{case["name"]}-{side}') for side,cmd in commands.items()}
    # Exact packet options, lease identity/name, local DNS and lifecycle are compared.
    same=rows['c']==rows['rust']; report['cases'].append({'name':case['name'],'matched':same,**rows})
    if not same: report['failures'].append(case['name'])
    print(json.dumps({'name':case['name'],'matched':same}),flush=True)
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases':len(cases),'failures':report['failures']}))
