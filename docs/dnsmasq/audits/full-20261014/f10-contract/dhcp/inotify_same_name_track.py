import json,os,shutil,signal,socket,subprocess,time
from pathlib import Path
from m2_rootfs import command,prepare,process_identity,sha256,STOCK_SHA256
from probe import exchange,ADDRESS
FIXTURE="192.0.2.1 lease.test alias.test\n"
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--rust',type=Path,required=True)
parser.add_argument('--sha256',required=True)
parser.add_argument('--source-commit',required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
base=args.output
assert 'private' in base.resolve().parts
base.mkdir(parents=True,exist_ok=False)
binary=args.rust
assert sha256(binary)==args.sha256
image=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert sha256(image/'usr/sbin/dnsmasq')==STOCK_SHA256
runs=[]
for iteration in range(2):
 repeat=iteration
 for retained in [True]:
  out=base/f'c-retained-{int(retained)}-repeat{iteration}'
  out.mkdir()
  root=prepare(image,None,out/'stage',binary)
  (root/'m2/hostsdir').mkdir()
  (root/'m2/hostsdir/hosts').write_text('')
  (root/'m2/leases').write_text(('0' if repeat==0 else str(int(time.time())+3600))+' 02:00:00:00:00:01 192.0.2.1 lease *\n')
  if repeat==2:
   with (root/'m2/leases').open('a') as leases:
    leases.write(str(int(time.time())+3600)+' 02:00:00:00:00:02 192.0.2.9 a.test *\n')
  argv=command(root,'rust','-k','--conf-file=','--no-resolv','--no-hosts','--user=root','--group=root','--listen-address=127.0.0.1','--bind-interfaces','--port=15353','--pid-file=/m2/pid','--host-record=ready.test,192.0.2.41','--hostsdir=/m2/hostsdir','--cache-size=1000','--edns-packet-max=1232','--local-ttl=37','--log-queries','--log-facility=/m2/diagnostic.log','--dhcp-leasefile=/m2/leases','--dhcp-range=192.0.2.1,192.0.2.100,255.255.255.0,1h','--domain=test','--no-ping')
  result={'retained':retained,'repeat':repeat,'argv':argv,'c_sha256':STOCK_SHA256,'rust_sha256':sha256(binary),'source_commit':args.source_commit,'case':['infinite','finite','cross-alias'][repeat]}
  with (out/'stderr').open('wb') as log:
   p=subprocess.Popen(argv,stdout=log,stderr=log)
   try:
    for _ in range(100):
     assert p.poll() is None
     try:
      if exchange('ready.test')['answer_order']==['192.0.2.41']:break
     except (TimeoutError,ConnectionRefusedError):pass
     time.sleep(.02)
    else:raise TimeoutError('startup')
    result['identity']=process_identity(root,p.pid)
    result['initial_a']=exchange('lease.test')
    assert set(result['initial_a']['answer_order'])==({'192.0.2.1','192.0.2.9'} if repeat==2 else {'192.0.2.1'}),result['initial_a']
    result['initial_ptr']=exchange('1.2.0.192.in-addr.arpa',12)
    (root/'m2/hostsdir/hosts').write_text(FIXTURE)
    result['fixture_sha256']=sha256(root/'m2/hostsdir/hosts')
    # close-write is the only reload trigger
    for _ in range(100):
     if exchange('alias.test')['answer_order']==['192.0.2.1']:break
     time.sleep(.02)
    else:raise TimeoutError('HUP')
    result['after_a']=exchange('lease.test')
    result['after_y']=exchange('alias.test')
    result['after_ptr']=exchange('1.2.0.192.in-addr.arpa',12)
    result['ptr_track_udp']=[result['after_ptr']]+[exchange('1.2.0.192.in-addr.arpa',12) for _ in range(2)]
    with socket.create_connection(ADDRESS,2) as tcp:
     tcp.settimeout(2)
     result['after_tcp_ptr']=exchange('1.2.0.192.in-addr.arpa',12,tcp)
     result['ptr_track_tcp']=[result['after_tcp_ptr']]+[exchange('1.2.0.192.in-addr.arpa',12,tcp) for _ in range(2)]
    p.send_signal(signal.SIGUSR1);time.sleep(.05)
    result['alive']=p.poll() is None
   except Exception as e:
    result['error']=repr(e)
   finally:
    p.terminate();p.wait(3);result['exit']=p.returncode
    if (root/'m2/diagnostic.log').exists():shutil.copy2(root/'m2/diagnostic.log',out/'daemon.log')
  (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
  runs.append(result)
  (base/'result.json').write_text(json.dumps({'runs':runs},indent=2)+'\n')
  print(json.dumps({k:result.get(k) for k in ['retained','repeat','alive','error','exit']}),flush=True)
  if 'error' in result:raise RuntimeError(result['error'])
