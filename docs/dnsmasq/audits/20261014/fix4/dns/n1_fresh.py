#!/usr/bin/env python3
"""Reproduce filterwin2k's newly exposed TCP CNAME NXDOMAIN response.
C/main/fix, three repeats, normal/debug, cold/UDP-warm/same-TCP-warm.
Fresh recheck: add a UDP health query after the TCP connection closes.
Origin SHA-256: e5b28151ab984e3bc010900db60c524a8bbf41939f5672a1d68c35c7f19067b6.
All daemons and stub run inside run_isolated.sh and exact-image chroots.
"""
import argparse,json,os,shutil,signal,socket,struct,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--tools',type=Path,required=True);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--main',type=Path,required=True);p.add_argument('--fix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
sys.path.insert(0,str(a.tools));import audit_20261011_dns as w
from m2_rootfs import prepare,command,sha256
assert os.getenv('DNSMASQ_TEST_ISOLATED')=='1'
a.out.mkdir(parents=True,exist_ok=False);root=prepare(a.image_root,None,a.out,a.fix);shutil.copy2(a.main,root/'usr/sbin/dnsmasq-main')
def reply(packet):
 e=w.question_end(packet);flags=0x8083|(struct.unpack_from('!H',packet,2)[0]&0x0110)
 return packet[:2]+struct.pack('!5H',flags,1,1,1,0)+packet[12:e]+w.rr(b'\xc0\x0c',5,w.name('target.example'),ttl=300)+w.rr(w.name('example'),6,w.name('ns.example')+w.name('hostmaster.example')+struct.pack('!5I',1,60,60,60,300),ttl=300)
w.stub_reply=reply;stub=w.Stub()
base='port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\ncache-size=150\nno-round-robin\nserver=127.0.0.1#15354\nhost-record=ready.test,192.0.2.1\n'
def persistent(sock,packet):
 sock.sendall(struct.pack('!H',len(packet))+packet);data=w.exact(sock,struct.unpack('!H',w.exact(sock,2))[0]);return {'status':'reply','hex':data.hex(),'header':list(struct.unpack('!6H',data[:12])),'length':len(data)}
def request(packet,protocol,connection):return persistent(connection,packet) if protocol=='persistent' else w.request(packet,protocol)
result={'identities':{'c':sha256(root/'usr/sbin/dnsmasq'),'main':sha256(a.main),'fix':sha256(a.fix),'driver':sha256(Path(__file__))},'runs':[]}
for repeat in range(1,4):
 for debug in [False,True]:
  for filtered in [True,False]:
   for warmth in ['cold','udp','persistent']:
    for kind in [6,33]:
     label=f'r{repeat}-debug{int(debug)}-filter{int(filtered)}-{warmth}-q{kind}';row={'name':label,'repeat':repeat,'debug':debug,'filterwin2k':filtered,'warmth':warmth,'qtype':kind,'query':w.query('alias.example',kind,extra=w.opt(ttl=0x8000),ar=1).hex(),'config':base+('filterwin2k\n' if filtered else ''),'sides':{}};(root/'m2/dns.conf').write_text(row['config'])
     for side,binary in [('c','c'),('main','/usr/sbin/dnsmasq-main'),('fix','rust')]:
      with (a.out/(label+'-'+side+'.log')).open('wb') as log:
       proc=subprocess.Popen(command(root,binary,'-C','/m2/dns.conf','-d' if debug else '-k','--user=root','--group=root','--pid-file=','--log-facility=-'),stdout=log,stderr=log)
       for _ in range(30):
        if proc.poll() is not None:raise RuntimeError('daemon exited')
        if w.request(w.query('ready.test'),'udp')['status']=='reply':break
        time.sleep(.01)
       conn=None;observed={}
       try:
        if warmth=='persistent':
         conn=socket.create_connection(('127.0.0.1',15353),timeout=.5);conn.settimeout(.5)
        if warmth!='cold':
         warm=w.query('alias.example',1);start=len(stub.records);observed['warm_query']=warm.hex();observed['warm_response']=request(warm,warmth,conn);observed['warm_upstream']=stub.records[start:]
        start=len(stub.records);observed['response']=request(bytes.fromhex(row['query']),'persistent' if conn else 'tcp',conn);observed['upstream']=stub.records[start:];observed['alive']=proc.poll() is None
       finally:
        if conn:conn.close()
        observed['health_after_connection_close']=w.request(w.query('ready.test'),'udp')
        proc.send_signal(signal.SIGTERM)
        try:proc.wait(timeout=2)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
       observed['exit']=proc.returncode;row['sides'][side]=observed
     result['runs'].append(row)
     print(json.dumps({'run':label,'rcode':{k:v['response'].get('header',[0,0])[1]&15 for k,v in row['sides'].items()},'upstream':{k:len(v['upstream']) for k,v in row['sides'].items()}}),flush=True)
     (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
stub.stop.set();print(json.dumps({'complete':True,'runs':len(result['runs'])}))
