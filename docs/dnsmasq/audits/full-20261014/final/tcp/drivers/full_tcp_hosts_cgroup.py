#!/usr/bin/env python3
import argparse,json,os,socket,struct,subprocess,tempfile,time
from pathlib import Path
import sys
from m2_rootfs import prepare,command,sha256,STOCK_SHA256
Q=bytes.fromhex('123401000001000000000000')+b'\x05ready\x04test\0\0\x01\0\x01'
def probe():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.3);s.sendto(Q,('127.0.0.1',15353))
 try:return s.recv(4096)[6:8]==b'\0\1'
 except (TimeoutError,ConnectionRefusedError):return False
 finally:s.close()
def measure(cg):
 return {n:(cg/n).read_text().strip() for n in ('memory.current','memory.peak','memory.events','cgroup.procs')}
def run(a,side):
 out=a.output/side;out.mkdir();root=prepare(a.image_root,None,out/'stage',a.rust);(root/'m2/hosts').write_text(''.join(f'192.0.2.{i%250+1} host{i:06d}.test\n' for i in range(50000)))
 argv=['-k','--conf-file=','--no-resolv','--no-hosts','--user=root','--group=root','--listen-address=127.0.0.1','--bind-interfaces','--port=15353','--pid-file=/m2/pid','--host-record=ready.test,192.0.2.41','--addn-hosts=/m2/hosts','--cache-size=1000','--log-facility=/dev/null']
 cg=Path(tempfile.mkdtemp(prefix='full-tcp-hosts-',dir='/sys/fs/cgroup')); (cg/'memory.max').write_text(str(a.budget_mib*1024*1024));(cg/'memory.swap.max').write_text('0')
 def enter(): (cg/'cgroup.procs').write_text(str(os.getpid()))
 result={'side':side,'argv':argv,'budget_bytes':a.budget_mib*1024*1024,'connections':[]};socks=[]
 try:
  with (out/'stderr').open('wb') as log:
   p=subprocess.Popen(command(root,side,*argv),stdout=log,stderr=log,preexec_fn=enter)
   try:
    for _ in range(100):
     if p.poll() is not None:raise RuntimeError('startup exited')
     if probe():break
     time.sleep(.02)
    else:raise RuntimeError('startup timeout')
    result['ready']=measure(cg)
    for i in range(20):
     row={'connection':i+1}
     try:
      s=socket.create_connection(('127.0.0.1',15353),2);s.settimeout(2);socks.append(s);s.sendall(struct.pack('!H',len(Q))+Q);hdr=s.recv(2);assert len(hdr)==2;size=struct.unpack('!H',hdr)[0];data=b''
      while len(data)<size:
       block=s.recv(size-len(data));assert block;data+=block
      row['ok']=data[:2]==Q[:2] and data[6:8]==b'\0\1'
     except Exception as e:row.update(ok=False,error=repr(e))
     time.sleep(.05);row['process_exit']=p.poll();row['cgroup']=measure(cg);result['connections'].append(row)
     if not row['ok']:break
    if a.hup and len(socks)==20 and all(row['ok'] for row in result['connections']):
     query=Q[:12]+b'\x0ahost000000\x04test\0\0\x01\0\x01'
     def tcp(client):
      client.sendall(struct.pack('!H',len(query))+query);hdr=client.recv(2);assert len(hdr)==2;size=struct.unpack('!H',hdr)[0];data=b''
      while len(data)<size:
       block=client.recv(size-len(data));assert block;data+=block
      return data[-4:].hex()
     (root/'m2/hosts').write_text(''.join(f'192.0.2.{(i+1)%250+1} host{i:06d}.test\n' for i in range(50000)))
     import signal
     p.send_signal(signal.SIGHUP)
     for _ in range(100):
      with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
       client.settimeout(.2);client.sendto(query,('127.0.0.1',15353))
       try:changed=client.recv(4096)[-4:].hex()=='c0000202'
       except (TimeoutError,ConnectionRefusedError):changed=False
      if changed:break
      time.sleep(.02)
     assert changed,'HUP must publish the new generation'
     result['hup']={'old_answers':[tcp(client) for client in socks]}
     for client in socks[:10]:client.close()
     socks=socks[10:];time.sleep(.2)
     result['hup']['new_answers']=[]
     for _ in range(10):
      client=socket.create_connection(('127.0.0.1',15353),2);client.settimeout(2);socks.append(client)
      result['hup']['new_answers'].append(tcp(client))
     assert set(result['hup']['old_answers'])=={'c0000201'}
     assert set(result['hup']['new_answers'])=={'c0000202'}
    result['udp_after']=probe();result['exit_before_cleanup']=p.poll();result['final_cgroup']=measure(cg)
   finally:
    for s in socks:s.close()
    if p.poll() is None:p.terminate()
    try:p.wait(3)
    except subprocess.TimeoutExpired:p.kill();p.wait()
    result['exit']=p.returncode
  for _ in range(100):
   if not (cg/'cgroup.procs').read_text().strip():break
   time.sleep(.02)
  result['cleanup_cgroup']=measure(cg)
 finally:
  (cg/'cgroup.kill').write_text('1')
  for _ in range(100):
   try:cg.rmdir();break
   except OSError:time.sleep(.02)
  result['cgroup_removed']=not cg.exists()
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result
ap=argparse.ArgumentParser();ap.add_argument('--image-root',type=Path,required=True);ap.add_argument('--rust',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--budget-mib',type=int,default=64);ap.add_argument('--hup',action='store_true');a=ap.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';assert not a.output.exists();a.output.mkdir();(a.output/'driver.py').write_bytes(Path(__file__).read_bytes())
result={'driver_sha256':sha256(Path(__file__)),'c_sha256':sha256(a.image_root/'usr/sbin/dnsmasq'),'rust_sha256':sha256(a.rust),'runs':[]}
assert result['c_sha256']==STOCK_SHA256
for side in ('c','rust'):
 r=run(a,side);result['runs'].append(r);(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(side,len(r['connections']),r['udp_after'],r['exit_before_cleanup'],r['final_cgroup'],flush=True)
