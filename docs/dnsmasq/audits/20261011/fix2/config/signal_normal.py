#!/usr/bin/env python3
import argparse,json,os,signal,sys,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser()
for n in ('source','image','rust','out'):p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import prepare,command,sha256
from audit_20261011_runtime_signals import run_dump,query
a.out.mkdir(exist_ok=False)
root=prepare(a.image,None,a.out,a.rust)
rows=[];dumps=[]
for side,binary in [('c',root/'usr/sbin/dnsmasq'),('rust',a.rust)]:
 for sig in [signal.SIGHUP,signal.SIGUSR2,signal.SIGUSR1,signal.SIGALRM]:
  log=a.out/f'{side}-{signal.Signals(sig).name}.log'
  argv=command(root,side,'-C','/dev/null','-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--address=/audit.test/192.0.2.1','--pid-file=','--log-facility=-')
  with log.open('wb') as stream:
   proc=subprocess.Popen(argv,stdout=stream,stderr=stream)
   try:
    deadline=time.monotonic()+3
    while not query(15353):
     if proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError(log.read_text())
    proc.send_signal(sig);time.sleep(.15)
    row={'side':side,'sha256':sha256(binary),'signal':signal.Signals(sig).name,'dns_after':query(15353),'exit_status_after_signal':proc.poll()}
   finally:
    if proc.poll() is None:proc.terminate()
    proc.wait(timeout=3)
  row['normal_exit']=proc.returncode;row['log']=log.read_text();rows.append(row)
 dumps.append(run_dump(side,command(root,side),binary,a.out))
result={'tool_sha256':sha256(Path(__file__)),'signals':rows,'dumps':dumps,
 'passed':all(r['dns_after'] and r['exit_status_after_signal'] is None for r in rows) and all(r['daemon_alive'] and r['upstream_queries']==3 for r in dumps) and dumps[0]['dump']==dumps[1]['dump']}
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
