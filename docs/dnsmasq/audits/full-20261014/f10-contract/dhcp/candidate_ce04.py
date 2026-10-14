import json,os,shutil,signal,socket,subprocess,time
from pathlib import Path
from m2_rootfs import command,prepare,process_identity,sha256,STOCK_SHA256
from probe import exchange,FIXTURE,ADDRESS
base=Path('/dev/shm/full-f10-dhcp-20261014/private/candidate-ce04')
binary=Path('/dev/shm/full-f10-product-20261014/private/release-ce04/dnsmasq-rs')
assert sha256(binary)=='2e64dc09e52c50f740c994cbd224953b57f3fbe77970fd8af4b72963f9ab5404'
image=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert sha256(image/'usr/sbin/dnsmasq')==STOCK_SHA256
runs=[]
for repeat in range(3):
 for retained in [True]:
  out=base/f'c-retained-{int(retained)}-repeat{repeat}'
  out.mkdir()
  root=prepare(image,None,out/'stage',binary)
  (root/'m2/hosts').write_text('')
  (root/'m2/leases').write_text(('0' if repeat==0 else str(int(time.time())+3600))+' 02:00:00:00:00:01 192.0.2.1 a *\n')
  if repeat==2:
   with (root/'m2/leases').open('a') as leases:
    leases.write(str(int(time.time())+3600)+' 02:00:00:00:00:02 192.0.2.9 a.test *\n')
  argv=command(root,'rust','-k','--conf-file=','--no-resolv','--no-hosts','--user=root','--group=root','--listen-address=127.0.0.1','--bind-interfaces','--port=15353','--pid-file=/m2/pid','--host-record=ready.test,192.0.2.41','--addn-hosts=/m2/hosts','--cache-size=1000','--edns-packet-max=1232','--local-ttl=37','--log-queries','--log-facility=/m2/diagnostic.log','--dhcp-leasefile=/m2/leases','--dhcp-range=192.0.2.1,192.0.2.100,255.255.255.0,1h','--domain=test','--no-ping')
  result={'retained':retained,'repeat':repeat,'argv':argv,'c_sha256':STOCK_SHA256,'rust_sha256':sha256(binary),'source_commit':'ce04a28d','case':['infinite','finite','cross-alias'][repeat]}
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
    result['initial_a']=exchange('a.test')
    assert set(result['initial_a']['answer_order'])==({'192.0.2.1','192.0.2.9'} if repeat==2 else {'192.0.2.1'}),result['initial_a']
    result['initial_ptr']=exchange('1.2.0.192.in-addr.arpa',12)
    (root/'m2/hosts').write_text(FIXTURE)
    result['fixture_sha256']=sha256(root/'m2/hosts')
    p.send_signal(signal.SIGHUP)
    for _ in range(100):
     if exchange('old.test')['answer_order']==['192.0.2.2']:break
     time.sleep(.02)
    else:raise TimeoutError('HUP')
    result['after_a']=exchange('a.test')
    result['after_y']=exchange('y.test')
    result['after_ptr']=exchange('1.2.0.192.in-addr.arpa',12)
    with socket.create_connection(ADDRESS,2) as tcp:
     tcp.settimeout(2)
     result['after_tcp_ptr']=exchange('1.2.0.192.in-addr.arpa',12,tcp)
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
