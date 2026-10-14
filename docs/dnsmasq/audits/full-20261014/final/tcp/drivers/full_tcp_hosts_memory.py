#!/usr/bin/env python3
import argparse, json, os, socket, struct, subprocess, time
from pathlib import Path
import sys
from m2_rootfs import prepare,command,sha256,STOCK_SHA256

def q(name):
 return struct.pack('!6H',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
def udp(name):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1);p=q(name);s.sendto(p,('127.0.0.1',15353));r=s.recv(4096);s.close();assert struct.unpack('!H',r[6:8])[0]==1,(name,r.hex());return r

def tree(pid):
 result=[];pending=[pid]
 while pending:
  p=pending.pop()
  try: children=Path('/proc/%d/task/%d/children'%(p,p)).read_text().split()
  except FileNotFoundError: continue
  pending += [int(x) for x in children];result.append(p)
 return result

def stats(pid):
 rows=[]
 for p in tree(pid):
  d={'pid':p,'fd':len(list(Path('/proc/%d/fd'%p).iterdir()))}
  for f in ('status','smaps_rollup'):
   for line in Path('/proc/%d/%s'%(p,f)).read_text().splitlines():
    a=line.split()
    if a[0].rstrip(':') in ('Pss','Rss','Private_Dirty','Private_Clean','Anonymous','VmSize','VmRSS','VmHWM','Threads'):
     d[a[0].rstrip(':')]=int(a[1])
  rows.append(d)
 return {'processes':rows, 'sum':{key:sum(r.get(key,0) for r in rows) for key in ('Pss','Rss','Private_Dirty','Private_Clean','Anonymous','VmRSS','fd','Threads')}}

def run(args,side,rows):
 out=args.output/f'{side}-{rows}';out.mkdir()
 root=prepare(args.image_root,None,out/'stage',args.rust)
 (root/'m2/hosts').write_text(''.join(f'192.0.2.{i%250+1} host{i:06d}.test\n' for i in range(rows)))
 if args.config_hosts:
  (root/'m2/direct.conf').write_text(''.join(f'host-record=host{i:06d}.test,192.0.2.{i%250+1}\n' for i in range(rows)))
 argsv=['-k','--conf-file=','--no-resolv','--no-hosts','--user=root','--group=root','--listen-address=127.0.0.1','--bind-interfaces','--port=15353','--pid-file=/m2/pid','--host-record=ready.test,192.0.2.41','--addn-hosts=/m2/hosts','--cache-size=1000','--log-facility=/dev/null']
 if args.config_hosts: argsv=[v for v in argsv if not v.startswith('--addn-hosts=')];argsv[1]='--conf-file=/m2/direct.conf'
 result={'side':side,'hosts':rows,'config_hosts':args.config_hosts,'argv':argsv,'samples':[]};socks=[]
 with (out/'stderr').open('wb') as log:
  proc=subprocess.Popen(command(root,side,*argsv),stdout=log,stderr=log,start_new_session=True)
  try:
   for _ in range(100):
    try: udp(f'host{rows-1:06d}.test' if rows else 'ready.test');break
    except (TimeoutError,ConnectionRefusedError):
     if proc.poll() is not None: raise RuntimeError('early exit')
     time.sleep(.05)
   else: raise RuntimeError('startup timeout')
   result['samples'].append({'connections':0,**stats(proc.pid)})
   for target in (1,10,20):
    while len(socks)<target:
     start=time.perf_counter_ns();s=socket.create_connection(('127.0.0.1',15353),3);s.settimeout(3);p=q('ready.test');s.sendall(struct.pack('!H',len(p))+p)
     hdr=s.recv(2);assert len(hdr)==2;remaining=struct.unpack('!H',hdr)[0];r=b''
     while len(r)<remaining:r+=s.recv(remaining-len(r))
     assert r==udp('ready.test');socks.append(s)
    time.sleep(.15)
    result['samples'].append({'connections':target,**stats(proc.pid)})
   for s in socks:s.close()
   socks=[];time.sleep(.5);result['drained']=stats(proc.pid);udp('ready.test')
  finally:
   for s in socks:s.close()
   proc.terminate()
   try:proc.wait(3)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   result['exit']=proc.returncode
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--image-root',type=Path,required=True);ap.add_argument('--rust',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--config-hosts',action='store_true');ap.add_argument('--rows',default='0,1000,10000,50000');a=ap.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';assert not a.output.exists();a.output.mkdir()
 result={'c_sha256':sha256(a.image_root/'usr/sbin/dnsmasq'),'rust_sha256':sha256(a.rust),'driver_sha256':sha256(Path(__file__)),'runs':[]}
 assert result['c_sha256']==STOCK_SHA256
 for i,n in enumerate(map(int,a.rows.split(','))):
  for side in (('c','rust') if i%2==0 else ('rust','c')):
   row=run(a,side,n);result['runs'].append(row);(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(side,n,[(r['connections'],r['sum']['Pss']) for r in row['samples']],flush=True)
if __name__=='__main__':main()
