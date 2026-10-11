#!/usr/bin/env python3
"""Cache/DHCP/TCP priority audit in a private namespace; no product changes."""
import argparse, hashlib, json, os, pathlib, signal, socket, struct, subprocess, sys, threading, time
from dns_hosts_probe import query, exchange

def main():
    p=argparse.ArgumentParser();p.add_argument('--tools',required=True);p.add_argument('--image-root',type=pathlib.Path,required=True);p.add_argument('--rust',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';sys.path.insert(0,a.tools)
    from audit_20261011_dhcp import packet,decode
    a.out.mkdir(parents=True,exist_ok=False)
    cmds={'c':[str(a.image_root/'lib/libc.so'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(a.image_root/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]}
    result={'rust_sha256':hashlib.sha256(a.rust.read_bytes()).hexdigest(),'cases':[]}
    for debug in [False,True]:
      for stale in [False,True]:
       for side,cmd in cmds.items():
        folder=a.out/f'{side}-debug{debug}-stale{stale}';folder.mkdir();events=[];stop=threading.Event()
        up=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);up.bind(('127.0.0.1',15354));up.settimeout(.05)
        def serve():
          while not stop.is_set():
            try:wire,peer=up.recvfrom(4096)
            except socket.timeout:continue
            pos=12
            while wire[pos]:pos+=wire[pos]+1
            end=pos+5;events.append(wire.hex())
            up.sendto(wire[:2]+struct.pack('!5H',0x8183,1,0,0,0)+wire[12:end],peer)
        thread=threading.Thread(target=serve);thread.start()
        log=(folder/'daemon.log').open('wb')
        argv=cmd+['-C','/dev/null','-d' if debug else '-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--pid-file=','--log-facility=-','--log-queries','--host-record=ready.test,192.0.2.123','--server=127.0.0.1#15354','--cache-size=32','--neg-ttl=1' if stale else '--neg-ttl=60','--no-ping','--dhcp-authoritative','--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,1h',f'--dhcp-leasefile={folder}/leases']+(['--use-stale-cache=30'] if stale else [])
        proc=subprocess.Popen(argv,stdout=log,stderr=log)
        try:
          for _ in range(100):
            if exchange(query('ready.test')).endswith('c000027b'):break
            if proc.poll() is not None:raise RuntimeError((folder/'daemon.log').read_text())
            time.sleep(.01)
          before=exchange(query('client',28));time.sleep(2.1 if stale else .05)
          with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dhcp:
            dhcp.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);dhcp.setsockopt(socket.SOL_SOCKET,25,b'lo\0');dhcp.bind(('0.0.0.0',68));dhcp.settimeout(2)
            dhcp.sendto(packet(3,0x12345678,name='client'),('255.255.255.255',67));ack=decode(dhcp.recv(4096))
          count=len(events);wire=query('client');wire=wire[:10]+b'\0\1'+wire[12:]+b'\0'+struct.pack('!HHIH',41,1232,0,0)
          after=exchange(wire,True);time.sleep(.3);following=events[count:]
          result['cases'].append({'side':side,'debug':debug,'stale':stale,'negative_before':before,'ack':ack['message_type'],'tcp_after':after,'upstream_after_tcp':following,'alive':proc.poll() is None})
        finally:
          proc.terminate()
          try:proc.wait(timeout=3)
          except subprocess.TimeoutExpired:proc.kill();proc.wait()
          stop.set();thread.join();up.close();log.close()
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
