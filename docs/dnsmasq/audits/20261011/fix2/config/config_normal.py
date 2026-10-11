#!/usr/bin/env python3
"""Independent config/ACL/signal probes. Run on oracle through run_isolated.sh."""
import argparse, hashlib, json, os, re, signal, socket, struct, subprocess, time
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
a.out.mkdir(exist_ok=False)
loader=next((a.image/'lib').glob('ld-musl-*.so.1'))
cmds={'c':[str(loader),'--library-path',f'{a.image}/lib:{a.image}/usr/lib',str(a.image/'usr/sbin/dnsmasq')], 'rust':[str(a.rust)]}
base=['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--no-resolv','--port=15353','--host-record=audit.test,192.0.2.42','--log-facility=-']
def query(v6=False,tcp=False):
    wire=struct.pack('!6H',0x4851,0x100,1,0,0,0)+b'\x05audit\x04test\0\0\1\0\1'
    with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
        s.settimeout(.12)
        try:
            s.connect(('::1' if v6 else '127.0.0.1',15353))
            s.sendall((len(wire).to_bytes(2,'big') if tcp else b'')+wire)
            answer=s.recv(65535)
            return answer.hex()
        except OSError as e: return type(e).__name__

def stop(proc):
    if proc.poll() is None: proc.terminate()
    try: proc.wait(timeout=2)
    except subprocess.TimeoutExpired: proc.kill();proc.wait()

rows=[]
values={
 'auth-server':['','ns.test','ns.test,lo','ns.test,lo/4','ns.test,lo/6','ns.test,lo/5','ns.test,lo/4/6','ns.test,','ns.test,,lo','ns.test,127.0.0.1','ns.test,::1','ns.test,127.00.0.1','ns.test,lo*',',lo','"ns.test,lo"','ns.test,"lo/4"','ns.test,lo,'],
 'auth-ttl':['','0','-1','+1','60','2147483648','4294967296','18446744073709551616',' 60','"60 "','nan'],
 'auth-soa':['','1','1,a,b,c,d,e','"1,2"','a,b,c'],
 'auth-sec-servers':['','x','x,,y','a,b'],
 'auth-peer':['','127.0.0.1','::1','1.2.3.04','127.0.0.1,','127.0.0.1,::1','::ffff:127.0.0.1','bad'],
 'no-dhcpv6-interface':['','lo','lo,','lo*','"lo,lo"'],
 **{n:['__bare__','','1'] for n in ['quiet-ra','quiet-dhcp6','enable-ra','dnssec-debug','dnssec-no-timecheck']}}
for option,vs in values.items():
    for value in vs:
        text=option+('' if value=='__bare__' else '='+value)
        conf=a.out/'syntax.conf';conf.write_text('port=0\n'+text+'\n')
        obs={}
        for side,cmd in cmds.items():
            r=subprocess.run(cmd+['-C',str(conf),'--test'],capture_output=True,timeout=3)
            obs[side]={'exit':r.returncode,'stderr':r.stderr.decode(errors='replace')}
        rows.append({'directive':text,'result':obs,'same_status':obs['c']['exit']==obs['rust']['exit']})

services=[]
for bind in ['', '--bind-interfaces','--bind-dynamic']:
  for auth in ['','--auth-server=ns.test,lo','--auth-server=ns.test,lo/4','--auth-server=ns.test,lo/6','--auth-server=ns.test,127.0.0.1','--auth-server=ns.test,::1']:
    for acl in ['', '--except-interface=lo','--listen-address=127.0.0.1']:
      flags=[f for f in [bind,auth,acl] if f]
      obs={}
      for side,cmd in cmds.items():
        logfile=a.out/f'acl-{len(services)}-{side}.log'
        with logfile.open('wb') as log:
          proc=subprocess.Popen(cmd+base+['--log-queries=auth']+flags,stdout=log,stderr=log)
          try:
            time.sleep(.04)
            replies={f'{family}-{transport}':query(family=='v6',transport=='tcp') for family in ['v4','v6'] for transport in ['udp','tcp']}
          finally:stop(proc)
        txt=logfile.read_text()
        obs[side]={'responses':replies,'exit':proc.returncode,'query_logs':[line.split(': ',1)[-1] for line in txt.splitlines() if 'query[' in line or 'auth[' in line]}
      services.append({'flags':flags,'result':obs,'equal':obs['c']==obs['rust']})

result={'sha256':{k:hashlib.sha256(Path(v[-1]).read_bytes()).hexdigest() for k,v in cmds.items()},'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'syntax':rows,'services':services}
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'syntax':len(rows),'syntax_diffs':[r['directive'] for r in rows if not r['same_status']],'services':len(services),'service_diffs':[r for r in services if not r['equal']]},indent=2))
