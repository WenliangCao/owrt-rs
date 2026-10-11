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
cases=[]
def add(name,config,events,hosts=''):
    cases.append(dict(name=name,config=config,events=events,hosts=hosts))
for rapid in [False, True]:
    event=dict(kind=1 if rapid else 3,rapid=rapid)
    for wanted in [False,True,'127.0.0.31']:
        for policy in ['ignore','generate','both']:
            config='dhcp-range=set:other,127.0.0.31,127.0.0.31,255.0.0.0,1h\n'
            if policy in ['ignore','both']: config+='dhcp-ignore-names=tag:other\n'
            if policy in ['generate','both']: config+='dhcp-generate-names=tag:other\n'
            add(f'context-{rapid}-{wanted}-{policy}',config,[dict(kind=3,name='first'),dict(event,mac=2,wanted=wanted, name='claimed' if policy!='generate' else None)])
    add(f'handoff-full-{rapid}','dhcp-lease-max=1\ndhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual\n',[dict(kind=3),dict(event,mac=2),dict(event,mac=1),dict(event,mac=2)])
    for name in ['auth.lan','auth.other','auth']:
        add(f'context-static-name-{rapid}-{name}','domain=lan\naddn-hosts={hosts}\ndhcp-range=set:other,127.0.0.31,127.0.0.31,255.0.0.0,1h\n',[dict(kind=3),dict(event,mac=2,wanted=False,name='claimed')],f'127.0.0.31 {name}\n')
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
