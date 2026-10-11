#!/usr/bin/env python3
"""Normal configured-record diagnostics comparison, isolated exact image."""
import argparse, hashlib, json, os, signal, socket, struct, subprocess, sys, time
from pathlib import Path

p=argparse.ArgumentParser()
for n in ('source','image','rust','out'):p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import prepare, command, sha256
a.out.mkdir(exist_ok=False)
root=prepare(a.image,None,a.out,a.rust)
base=['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--no-resolv','--port=15353','--listen-address=127.0.0.1','--bind-interfaces','--log-facility=-','--log-queries']
cases=[
 ('orphan-cname',['--cname=alias.test,missing.test']),
 ('resolved-cname',['--host-record=target.test,192.0.2.42','--cname=alias.test,target.test']),
 ('chain-cname',['--host-record=target.test,192.0.2.42','--cname=middle.test,target.test','--cname=alias.test,middle.test']),
 ('configured-dns',['--host-record=target.test,192.0.2.42,2001:db8::42','--address=/suffix.test/192.0.2.43','--mx-host=mx.test,target.test,10','--txt-record=txt.test,hello']),
 ('literal-address',['--host-record=target.test,::192.0.2.42']),
]
rows=[]
for name,flags in cases:
 obs={}
 for side in ('c','rust'):
  log=a.out/f'{name}-{side}.log'
  with log.open('wb') as out:
   proc=subprocess.Popen(command(root,side,*base,*flags),stdout=out,stderr=out)
   try:
    time.sleep(.12)
    proc.send_signal(signal.SIGUSR1)
    time.sleep(.12)
    live=proc.poll() is None
   finally:
    if proc.poll() is None:proc.terminate()
    proc.wait(timeout=3)
  txt=log.read_text()
  obs[side]={'alive_after_dump':live,'exit':proc.returncode,'log':txt}
 rows.append({'case':name,'flags':flags,'result':obs})
result={'source_revision':'6d001a77','sha256':{'c':sha256(root/'usr/sbin/dnsmasq'),'rust':sha256(a.rust),'tool':sha256(Path(__file__))},'rows':rows}
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
