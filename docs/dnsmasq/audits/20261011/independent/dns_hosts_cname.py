#!/usr/bin/env python3
"""Show cached CNAME/local-record lookup order using exact daemon packets."""
import argparse, hashlib, json, os, pathlib, signal, socket, struct, subprocess, threading, time
from dns_hosts_probe import query,exchange

def main():
 p=argparse.ArgumentParser();p.add_argument('--image-root',type=pathlib.Path,required=True);p.add_argument('--rust',type=pathlib.Path,required=True);p.add_argument('--main',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
 assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';a.out.mkdir(parents=True,exist_ok=False)
 cmds={'c':[str(a.image_root/'lib/libc.so'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(a.image_root/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]}
 if a.main:cmds['main']=[str(a.main)]
 results=[]
 for debug in [False,True]:
  for side,cmd in cmds.items():
   folder=a.out/f'{side}-debug{debug}';folder.mkdir();events=[];stop=threading.Event()
   up=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);up.bind(('127.0.0.1',15354));up.settimeout(.05)
   def serve():
    while not stop.is_set():
     try:wire,peer=up.recvfrom(4096)
     except socket.timeout:continue
     pos=12
     while wire[pos]:pos+=wire[pos]+1
     end=pos+5;events.append(wire.hex());target=query('target.test')[12:-4]
     if struct.unpack('!H',wire[end-4:end-2])[0]==16:
      data=b'\x0ftarget-upstream';reply=wire[:2]+struct.pack('!5H',0x8180,1,1,0,0)+wire[12:end]+b'\xc0\x0c'+struct.pack('!HHIH',16,1,600,len(data))+data
     else:
      reply=wire[:2]+struct.pack('!5H',0x8180,1,2,0,0)+wire[12:end]
      reply+=b'\xc0\x0c'+struct.pack('!HHIH',5,1,600,len(target))+target
      reply+=target+struct.pack('!HHIH',1,1,600,4)+b'\xc0\0\2\x4d'
     up.sendto(reply,peer)
   thread=threading.Thread(target=serve);thread.start();log=(folder/'daemon.log').open('wb')
   argv=cmd+['-C','/dev/null','-d' if debug else '-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--pid-file=','--log-facility=-','--log-queries','--host-record=ready.test,192.0.2.123','--server=127.0.0.1#15354','--cache-size=32','--cache-rr=TXT','--txt-record=alias.test,alias-local']
   proc=subprocess.Popen(argv,stdout=log,stderr=log)
   try:
    for _ in range(100):
     if exchange(query('ready.test')).endswith('c000027b'):break
     if proc.poll() is not None:raise RuntimeError((folder/'daemon.log').read_text())
     time.sleep(.01)
    warmed=exchange(query('alias.test'));warm_target=exchange(query('target.test',16));rows={}
    for host in ['alias.test','target.test']:
     rows[host]={'tcp_txt':exchange(query(host,16),True),'udp_txt':exchange(query(host,16))}
    if side!='main':proc.send_signal(signal.SIGUSR1)
    time.sleep(.1)
    results.append({'side':side,'debug':debug,'sha256':hashlib.sha256(pathlib.Path(cmd[-1]).read_bytes()).hexdigest(),'warm_reply':warmed,'warm_target':warm_target,'replies':rows,'upstream':events,'alive':proc.poll() is None,'log':(folder/'daemon.log').read_text()})
   finally:
    proc.terminate()
    try:proc.wait(timeout=3)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
    stop.set();thread.join();up.close();log.close()
 result={'cases':results};(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps([{k:v for k,v in r.items() if k!='log'} for r in results],indent=2))

if __name__=='__main__':main()
