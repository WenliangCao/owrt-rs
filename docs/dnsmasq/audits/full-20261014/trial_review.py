#!/usr/bin/env python3
import argparse,ctypes,json,os,signal,struct,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq')
from test_trial_oracle import Trial
from test_deploy_oracle import wait
from m2_rootfs import command,STOCK_SHA256

def trace(pid, ready, result):
 libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
 def p(req,a=0,d=0):
  r=libc.ptrace(req,pid,ctypes.c_void_p(a),ctypes.c_void_p(d))
  if r==-1:raise OSError(ctypes.get_errno(),'ptrace')
  return r
 p(0x4206,0,1);p(0x4207);os.waitpid(pid,0);Path(ready).touch();deliver=0
 with open(f'/proc/{pid}/mem','rb',buffering=0) as mem:
  while True:
   p(24,0,deliver);_,s=os.waitpid(pid,0)
   assert os.WIFSTOPPED(s),s
   sig=os.WSTOPSIG(s);deliver=0 if sig in (5,133) else sig
   if sig!=133:continue
   info=ctypes.create_string_buffer(128);p(0x420e,len(info),ctypes.addressof(info));raw=info.raw
   if raw[0]==1 and struct.unpack_from('Q',raw,24)[0]==56:
    args=struct.unpack_from('6Q',raw,32);mem.seek(args[1]);name=mem.read(512).split(b'\0')[0].decode()
    # The shell opens args when _watch starts, then later opens these pidfiles
    # in child cat processes. Its own next relevant open is script path on exec.
   if raw[0]==1 and struct.unpack_from('Q',raw,24)[0]==221:
    # execve of /etc/init.d/dnsmasq is performed by child, not parent; do not rely on it.
    pass
   root=Path(f'/proc/{pid}/root/tmp/dnsmasq-trial')
   if not (root/'deadline.pid').exists() and not (root/'watch.pid').exists():
    Path(result).write_text(json.dumps({'pid':pid,'syscall':struct.unpack_from('Q',raw,24)[0] if raw[0]==1 else None,'pidfiles_absent':True}))
    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);return

if sys.argv[1]=='trace':trace(int(sys.argv[2]),*sys.argv[3:]);raise SystemExit
p=argparse.ArgumentParser();p.add_argument('--case',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.image_root=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files');a.rust_binary=Path('/home/ubuntu/full-audit-20261014/private/release/dnsmasq-rs');a.trial=Path('/home/ubuntu/full-audit-20261014/private/source/tools/dnsmasq/deploy/dnsmasq-trial')
d=Trial(a);r=d.row
try:
 d.boot()
 if a.case=='documented-path':
  import shutil
  shutil.copy2(a.trial,d.root/'tmp/dnsmasq-trial')
  q=d.run('/bin/sh','/tmp/dnsmasq-trial','start','/usr/sbin/dnsmasq-rs',d.rust,'lifecycle.lan','192.168.1.1','20',check=False)
  r.update(rc=q.returncode,stdout=q.stdout,stderr=q.stderr,c_still_running=bool(d.one(STOCK_SHA256)))
  (d.root/'tmp/dnsmasq-trial').unlink()
 elif a.case=='rollback-killed':
  d.start(seconds=25)
  # Start the genuine rollback under a paused launcher, then attach tracer
  # before exec of the unchanged script. Inject one SIGKILL after both
  # automatic helpers have been cancelled; candidate itself stays untouched.
  proc=subprocess.Popen(command(d.root,'/bin/sh','-c','kill -STOP $$; exec /usr/sbin/dnsmasq-trial rollback audit'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  time.sleep(.1)
  ready=d.out/'ready';evidence=d.out/'fault.json'
  tracer=subprocess.Popen([sys.executable,__file__,'trace',str(proc.pid),str(ready),str(evidence)])
  wait(ready.exists,'tracer ready',5);os.kill(proc.pid,signal.SIGCONT)
  assert tracer.wait(15)==0
  r['fault']=json.loads(evidence.read_text());r['rollback_exit']=proc.wait(2)
  time.sleep(35)
  r['after_deadline']={'candidate':d.daemons(d.rust),'c':d.daemons(STOCK_SHA256),'helper_files':list(str(x.name) for x in (d.root/'tmp/dnsmasq-trial').glob('*.pid')),'mounted':' /usr/sbin/dnsmasq ' in d.run('/bin/cat','/proc/mounts').stdout}
  d.trial('rollback');d.back_to_c('manual_recovery')
 r['passed']=True
finally:
 (a.output/'result.json').write_text(json.dumps(r,indent=2,default=str)+'\n');d.close()
