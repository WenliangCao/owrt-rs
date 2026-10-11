#!/usr/bin/env python3
"""Bounded normal DHCP compatibility test during initial hostsdir loading."""
import argparse, hashlib, json, os, signal, socket, subprocess, sys, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--rust',type=Path,required=True);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
assert 'private' in a.out.resolve().parts
sys.path.insert(0,str(a.source/'tools/dnsmasq'))
from m2_rootfs import image_elf_command, STOCK_SHA256
from audit_20261011_dhcp import packet, decode, dns_answer
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
stock=a.image_root/'usr/sbin/dnsmasq';assert sha(stock)==STOCK_SHA256
a.out.mkdir(parents=True,exist_ok=False)
report={'source_script_sha256':sha(__file__),'rust_sha256':sha(a.rust),'c_sha256':sha(stock),'cases':[]}
def has_open(pid,path):
 try:
  return any(fd.resolve()==path for fd in Path(f'/proc/{pid}/fd').iterdir())
 except (FileNotFoundError,PermissionError):return False
for mode in ['poll','no-poll','no-resolv']:
 rows={}
 for side,binary in [('c',stock),('rust',a.rust)]:
  d=a.out/(mode+'-'+side);d.mkdir();hd=d/'hostsdir';hd.mkdir();hosts=hd/'source';leases=d/'leases';resolver=d/'resolver'
  hosts.write_bytes((b'#'+b'x'*126+b'\n')*65536+b'127.0.0.30 authoritative.test\n')
  leases.write_text('0 02:00:00:00:00:01 127.0.0.30 restored *\n')
  resolver.write_text('nameserver 127.0.0.1\n')
  argv=image_elf_command(a.image_root,binary)+['-C','/dev/null','-k','--user=root','--group=root','--pid-file=','--no-hosts','--bind-interfaces','--listen-address=127.0.0.1','--port=15353','--no-ping','--dhcp-authoritative','--domain=test','--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,infinite','--hostsdir='+str(hd),'--resolv-file='+str(resolver),'--dhcp-leasefile='+str(leases),'--log-facility=-']
  if mode!='poll':argv+=['--'+mode]
  row={'argv':argv,'hosts_bytes':hosts.stat().st_size,'hosts_sha256':sha(hosts)}
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client,(d/'daemon.log').open('wb') as log:
   client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);client.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'lo\0');client.bind(('0.0.0.0',68))
   proc=subprocess.Popen(argv,stdout=log,stderr=log,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
   try:
    deadline=time.monotonic()+3
    while not has_open(proc.pid,hosts):
     if proc.poll() is not None:raise RuntimeError((d/'daemon.log').read_text())
     if time.monotonic()>deadline:raise RuntimeError('missed initial hostsdir open')
     time.sleep(.0005)
    row['hosts_open_at_send']=True;row['send_monotonic_ns']=time.monotonic_ns()
    request=packet(3,0x88440001,name='supplied-wrong');client.sendto(request,('255.255.255.255',67));client.settimeout(4)
    reply=client.recv(4096);assert reply[4:8]==request[4:8]
    row['reply']=decode(reply);row['reply_wire']=reply.hex();row['reply_monotonic_ns']=time.monotonic_ns();row['hosts_open_at_reply']=has_open(proc.pid,hosts)
    deadline=time.monotonic()+4
    while has_open(proc.pid,hosts):
     if time.monotonic()>deadline:raise RuntimeError('hostsdir failed to finish')
     time.sleep(.005)
    time.sleep(.05)
    row['dns_after']=dns_answer('authoritative.test',1);row['leases_after']=leases.read_text();row['alive']=proc.poll() is None
   finally:
    if proc.poll() is None:proc.terminate()
    try:proc.wait(timeout=3)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
    row['exit']=proc.returncode
  row['log']=(d/'daemon.log').read_text();rows[side]=row
 case={'mode':mode,'observed':rows,'reply_equal':rows['c']['reply']==rows['rust']['reply']}
 report['cases'].append(case)
 (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps([{'mode':r['mode'],'reply_equal':r['reply_equal'],'sides':{s:{k:v[k] for k in ['reply','hosts_open_at_reply','alive','exit']} for s,v in r['observed'].items()}} for r in report['cases']],indent=2))
