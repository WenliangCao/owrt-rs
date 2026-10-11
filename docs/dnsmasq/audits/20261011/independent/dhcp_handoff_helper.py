#!/usr/bin/env python3
"""Independent DHCP wire scenarios; reuse the established isolated transport only."""
import argparse, hashlib, json, os, socket, struct, sys
from pathlib import Path
def normalize_renewal_timers(event, reply):
    """Validate this fixture's independent C/Rust renewal fuzz before comparing."""
    if not (event['kind'] == 3 and event.get('wanted', True) is False
            and event.get('server') is None
            and event.get('ciaddr') not in (None, '0.0.0.0')):
        return
    # The fixture has a 1h range, no timer overrides. REQUEST can shorten it.
    lease = min(3600, max(120, event.get('lease_time', 3600)))
    if not reply or reply.get('message_type') != 5:
        raise ValueError('RENEW did not receive ACK')
    options = reply['options']
    if any(len(options.get(code, '')) != 8 for code in ['51', '58', '59']):
        raise ValueError('RENEW lease/T1/T2 must each contain four bytes')
    values = {code: int(options[code], 16) for code in ['51', '58', '59']}
    # rfc2131.c:1486,2776-2780: limit rand16() to T1/8 and subtract
    # that same value from T1 and T2. Keep the granted lease exact.
    fuzz = lease // 2 - values['58']
    if not (values['51'] == lease and 0 <= fuzz <= lease // 16
            and values['59'] == lease * 7 // 8 - fuzz):
        raise ValueError(f'invalid RENEW timer relation: {values}')
    options['58'] = (lease // 2).to_bytes(4, 'big').hex()
    options['59'] = (lease * 7 // 8).to_bytes(4, 'big').hex()


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

import time
packet_base=base.packet
def with_vendor(vendor=None, **kwargs):
    if kwargs['xid'] != 0xabc000:
        deadline=time.monotonic()+3
        while not active_eventfile.exists() or not active_eventfile.read_text().strip():
            if time.monotonic()>deadline: raise RuntimeError('first lease helper event did not arrive')
            time.sleep(.01)
    data=packet_base(**kwargs)
    return data[:-1]+(base.option(60,vendor.encode()) if vendor else b'')+b'\xff'
base.packet=with_vendor
dns_base=base.dns_answer
def after_helpers(name,kind):
    global helper_settled, helper_before_stop
    if not helper_settled:
        # Keep the daemon alive for a fixed observation window. Both sides get
        # identical time, including cases where C correctly emits no old event.
        started=time.monotonic()
        previous=None
        stable_since=started
        while time.monotonic()-started < 1.0 or time.monotonic()-stable_since < .3:
            current=active_eventfile.read_text() if active_eventfile.exists() else ''
            if current!=previous: previous=current; stable_since=time.monotonic()
            if time.monotonic()-started>3: raise RuntimeError('helper events never settled')
            time.sleep(.01)
        helper_before_stop=[json.loads(line) for line in active_full_eventfile.read_text().splitlines()] if active_full_eventfile.exists() else []
        helper_settled=True
    return dns_base(name,kind)
base.dns_answer=after_helpers

a.out.mkdir(parents=True,exist_ok=False)
stock=a.image_root/'usr/sbin/dnsmasq'; assert base.sha(stock)==base.STOCK_SHA256
commands={'c':[str(a.image_root/'lib/ld-musl-aarch64.so.1'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(stock)],'rust':image_elf_command(a.image_root,a.rust)}
cases=[]
for mode in ['rapid','renew','selecting']:
    for wanted in ([False, True] if mode=='rapid' else [mode=='selecting']):
        cases.append((f'handoff-{mode}-{wanted}',dict(kind=1 if mode=='rapid' else 3,rapid=mode=='rapid',wanted=wanted,server='127.0.0.1' if mode=='selecting' else None,ciaddr='127.0.0.30' if mode=='renew' else None)))
# Same-MAC Rapid Commit renewal must not manufacture helper invocations.
cases.append(('rapid-same-mac-requested',dict(kind=1,rapid=True,wanted=True,mac=1)))
report={'rust_sha256':base.sha(a.rust),'c_sha256':base.sha(stock),'script_sha256':base.sha(__file__),'cases':[]}
for case_name,event in cases:
    rows={}
    for side,cmd in commands.items():
        hook=a.out/f'{case_name}-{side}.sh'; eventfile=a.out/f'{case_name}-{side}.events'
        full_eventfile=eventfile.with_suffix('.full.jsonl')
        hook.write_text('#!/usr/bin/python3\nimport os,sys,json\n'
            + 'with open('+repr(str(full_eventfile))+', "a") as f: f.write(json.dumps({"argv":sys.argv[1:],"env":{k:v for k,v in os.environ.items() if k.startswith("DNSMASQ_")}},sort_keys=True)+"\\n")\n'
            + 'with open('+repr(str(eventfile))+', "a") as f: f.write("|".join(sys.argv[1:4]+[os.environ.get("DNSMASQ_VENDOR_CLASS",""),os.environ.get("DNSMASQ_SUPPLIED_HOSTNAME","")])+"\\n")\n')
        hook.chmod(0o755)
        active_eventfile=eventfile
        active_full_eventfile=full_eventfile
        helper_settled=False
        helper_before_stop=[]
        event.setdefault('mac',2)
        case={'name':case_name,'config':f'dhcp-script={hook}\ndhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.30,dual\n','events':[dict(kind=3,name='first',vendor='original'),dict(event,name='second',vendor='replacement')]}
        rows[side]=base.execute(cmd,case,a.out/f'{case_name}-{side}')
        rows[side]['helper_events']=eventfile.read_text().splitlines() if eventfile.exists() else []
        rows[side]['helper_events_full']=helper_before_stop
    def normalized(row):
        row=json.loads(json.dumps(row))
        for event in row['events']:
            normalize_renewal_timers(event['input'], event['reply'])
        for event in row['helper_events_full']:
            for key in ['DNSMASQ_LEASE_EXPIRES','DNSMASQ_TIME_REMAINING']:
                event['env'].pop(key,None)
        return row
    report['cases'].append({'name':case_name,'matched':normalized(rows['c'])==normalized(rows['rust']),**rows})
(a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
