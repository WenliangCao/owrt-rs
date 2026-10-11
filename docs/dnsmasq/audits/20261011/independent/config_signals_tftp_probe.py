#!/usr/bin/env python3
"""Independent TFTP interface checks for restored inactive options."""
import argparse, hashlib, json, os, signal, socket, struct, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--image',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';a.out.mkdir(exist_ok=False)
loader=next((a.image/'lib').glob('ld-musl-*.so.1'))
cmds={'c':[str(loader),'--library-path',f'{a.image}/lib:{a.image}/usr/lib',str(a.image/'usr/sbin/dnsmasq')], 'rust':[str(a.rust)]}
(a.out/'audit.txt').write_text('audit-file')
base=['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--no-resolv','--port=0',f'--tftp-root={a.out}','--log-facility=-']
def query(v6):
    with socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(.075)
        try:
            s.sendto(b'\0\1audit.txt\0octet\0',('::1' if v6 else '127.0.0.1',69));r,peer=s.recvfrom(65535)
            if r[:2]==b'\0\3':s.sendto(b'\0\4'+r[2:4],peer)
            return r.hex()
        except OSError as e:return type(e).__name__
rows=[]
for bind in ['', '--bind-interfaces','--bind-dynamic']:
  for auth in ['', '--auth-server=ns.test,lo', '--auth-server=ns.test,lo/4', '--auth-server=ns.test,lo/6']:
    for exc in ['', '--no-dhcpv6-interface=lo', '--no-dhcpv4-interface=lo', '--no-dhcp-interface=lo']:
      for enable in ['--enable-tftp','--enable-tftp=lo']:
        flags=[f for f in [bind,auth,exc,enable] if f];obs={}
        for side,cmd in cmds.items():
          logfile=a.out/f'{len(rows)}-{side}.log'
          with logfile.open('wb') as log:
            proc=subprocess.Popen(cmd+base+flags,stdout=log,stderr=log)
            try:
              time.sleep(.025);obs[side]={'v4':query(False),'v6':query(True),'alive':proc.poll() is None}
            finally:
              if proc.poll() is None:proc.terminate()
              try:proc.wait(timeout=2)
              except subprocess.TimeoutExpired:proc.kill();proc.wait()
            obs[side]['exit']=proc.returncode
        rows.append({'flags':flags,'result':obs,'equal':obs['c']==obs['rust']})
result={'sha256':{k:hashlib.sha256(Path(v[-1]).read_bytes()).hexdigest() for k,v in cmds.items()},'rows':rows}
(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'cases':len(rows),'differences':[r for r in rows if not r['equal']]},indent=2))
