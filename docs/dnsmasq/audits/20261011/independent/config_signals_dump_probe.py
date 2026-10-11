#!/usr/bin/env python3
"""SIGUSR1 scoped upstream diagnostic comparison against the exact image."""
import argparse,hashlib,json,os,signal,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';a.out.mkdir(exist_ok=False)
loader=next((a.image/'lib').glob('ld-musl-*.so.1'))
cmds={'c':[str(loader),'--library-path',f'{a.image}/lib:{a.image}/usr/lib',str(a.image/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]}
base=['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--no-resolv','--port=15353','--listen-address=127.0.0.1','--bind-interfaces','--log-facility=-']
rows=[]
for extra in [['--server=fe80::1%lo'],['--server=127.0.0.1#15354']]:
 obs={}
 for side,cmd in cmds.items():
  log=a.out/f'{len(rows)}-{side}.log'
  with log.open('wb') as stream:
   proc=subprocess.Popen(cmd+base+extra,stdout=stream,stderr=stream)
   try:
    time.sleep(.1);proc.send_signal(signal.SIGUSR1);time.sleep(.1);alive=proc.poll() is None
   finally:
    if proc.poll() is None:proc.terminate()
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
  obs[side]={'alive_after_usr1':alive,'exit':proc.returncode,'log':log.read_text()}
 rows.append({'args':extra,'result':obs})
result={'sha256':{k:hashlib.sha256(Path(v[-1]).read_bytes()).hexdigest() for k,v in cmds.items()},'rows':rows}
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
