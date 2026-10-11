#!/usr/bin/env python3
"""Observe normal restored-lease helper callbacks during hostsdir init."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';assert 'private' in a.out.resolve().parts
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import image_elf_command,STOCK_SHA256
from audit_20261011_dhcp import dns_answer
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
stock=a.image_root/'usr/sbin/dnsmasq';assert sha(stock)==STOCK_SHA256
a.out.mkdir(parents=True,exist_ok=False)
report={'script_sha256':sha(__file__),'rust_sha256':sha(a.rust),'c_sha256':sha(stock),'observed':{}}
for side,binary in [('c',stock),('rust',a.rust)]:
 d=a.out/side;d.mkdir();hd=d/'hostsdir';hd.mkdir();hosts=hd/'source';leases=d/'leases';resolver=d/'resolver';events=d/'events.jsonl';hook=d/'hook.py';pidfile=d/'daemon-pid'
 hosts.write_bytes((b'#'+b'x'*126+b'\n')*65536+b'127.0.0.30 authoritative-one.test\n127.0.0.31 authoritative-two.test\n')
 leases.write_text('0 02:00:00:00:00:01 127.0.0.30 restored-one *\n0 02:00:00:00:00:02 127.0.0.31 restored-two *\n');resolver.write_text('nameserver 127.0.0.1\n')
 hook.write_text('#!/usr/bin/python3\nimport os,sys,json,time\nfrom pathlib import Path\n'+f'sys.path.insert(0,{str(a.source/"tools/dnsmasq")!r})\nfrom audit_20261011_dhcp import dns_answer\n'+f'pid=int(Path({str(pidfile)!r}).read_text())\n'+f'opened=any(fd.resolve()==Path({str(hosts)!r}) for fd in Path(f"/proc/{{pid}}/fd").iterdir())\n'+ 'row={"argv":sys.argv[1:],"env":{k:v for k,v in os.environ.items() if k.startswith("DNSMASQ_")},"monotonic_ns":time.monotonic_ns(),"hosts_open":opened}\ntry:row["dns"]=dns_answer("authoritative-one.test",1)\nexcept Exception as e:row["dns_error"]=str(e)\n'+f'with open({str(events)!r},"a") as f:f.write(json.dumps(row,sort_keys=True)+"\\n")\n');hook.chmod(0o755)
 argv=image_elf_command(a.image_root,binary)+['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--bind-interfaces','--listen-address=127.0.0.1','--port=15353','--no-ping','--dhcp-authoritative','--domain=test','--dhcp-range=127.0.0.30,127.0.0.31,255.0.0.0,infinite','--hostsdir='+str(hd),'--resolv-file='+str(resolver),'--dhcp-leasefile='+str(leases),'--dhcp-script='+str(hook),'--log-facility=-']
 row={'argv':argv,'hosts_bytes':hosts.stat().st_size,'hosts_sha256':sha(hosts)}
 with (d/'daemon.log').open('wb') as log:
  proc=subprocess.Popen(argv,stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'});pidfile.write_text(str(proc.pid))
  try:
   start=stable=time.monotonic();previous=None
   while time.monotonic()-start<1.5 or time.monotonic()-stable<.4:
    current=events.read_text() if events.exists() else ''
    if current!=previous:previous=current;stable=time.monotonic()
    if proc.poll() is not None:raise RuntimeError((d/'daemon.log').read_text())
    if time.monotonic()-start>6:raise RuntimeError('callbacks did not settle')
    time.sleep(.01)
   row['callbacks']=[json.loads(x) for x in events.read_text().splitlines()];row['leases_after']=leases.read_text();row['dns_after']=dns_answer('authoritative-one.test',1);row['alive']=proc.poll() is None
  finally:
   if proc.poll() is None:proc.terminate()
   try:proc.wait(timeout=3)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   row['exit']=proc.returncode
 row['log']=(d/'daemon.log').read_text();report['observed'][side]=row;(a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({side:[{k:v for k,v in event.items() if k!='env'} for event in row['callbacks']] for side,row in report['observed'].items()},indent=2))
