#!/usr/bin/env python3
"""Independent C/main/fix CNAME terminal and malformed DNS differential driver.
Runs only under run_isolated.sh; product code is not modified.
"""
import argparse,hashlib,json,os,shutil,signal,socket,struct,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--tools',type=Path,required=True);p.add_argument('--image-root',type=Path,required=True);p.add_argument('--main',type=Path,required=True);p.add_argument('--fix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
sys.path.insert(0,str(args.tools));import audit_20261011_dns as w
from m2_rootfs import prepare,command,sha256
assert os.getenv('DNSMASQ_TEST_ISOLATED')=='1'
args.out.mkdir(parents=True,exist_ok=False);root=prepare(args.image_root,None,args.out,args.fix)
shutil.copy2(args.main,root/'usr/sbin/dnsmasq-main')
def dn(b,o):
 labels=[];end=None;seen=set()
 while True:
  if o in seen:raise ValueError('pointer loop')
  seen.add(o);n=b[o];o+=1
  if n==0:return '.'.join(labels).lower(),end or o
  if n&192==192:
   if end is None:end=o+1
   o=((n&63)<<8)|b[o];continue
  labels.append(b[o:o+n].hex());o+=n

def canonical(r):
 if r['status']!='reply':return r
 b=bytes.fromhex(r['hex']);h=struct.unpack('!6H',b[:12]);out={'flags':h[1],'counts':h[2:],'questions':[],'records':[]};o=12
 try:
  for _ in range(h[2]):n,o=dn(b,o);t,c=struct.unpack_from('!HH',b,o);o+=4;out['questions'].append((n,t,c))
  for count in h[3:]:
   sec=[]
   for _ in range(count):
    n,o=dn(b,o);t,c,ttl,ln=struct.unpack_from('!HHIH',b,o);o+=10;data=b[o:o+ln].hex()
    if t in (2,5,12):data=dn(b,o)[0]
    if t==15:data=[struct.unpack_from('!H',b,o)[0],dn(b,o+2)[0]]
    if t==33:data=[*struct.unpack_from('!HHH',b,o),dn(b,o+6)[0]]
    if t==6:
     n1,z=dn(b,o);n2,z=dn(b,z);data=[n1,n2,*struct.unpack_from('!IIIII',b,z)]
    sec.append([n,t,c,data]);o+=ln
   out['records'].append(sec)
  return out
 except Exception as e:return {'parse_error':repr(e),'raw':r}
mode='positive';target='target.example'
def reply(packet):
 end=w.question_end(packet);q=packet[12:end];rr=w.rr(w.name(target),1,socket.inet_aton('192.0.2.77'),ttl=300);an,ns,flags=2,0,0x8180
 if mode=='negative':
  rr=w.rr(w.name('example'),6,w.name('ns.example')+w.name('hostmaster.example')+struct.pack('!5I',1,60,60,60,300),ttl=300);an,ns,flags=1,1,0x8183
 return packet[:2]+struct.pack('!5H',flags,1,an,ns,0)+q+w.rr(b'\xc0\x0c',5,w.name(target),ttl=300)+rr
w.stub_reply=reply;stub=w.Stub()
base='port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\nno-round-robin\nlocal-ttl=60\ncache-size=150\nserver=127.0.0.1#15354\nhost-record=ready.test,192.0.2.1\n'
profiles=[('plain',''),('target-txt','txt-record=target.example,terminal\n'),('alias-txt','txt-record=alias.example,owner\n'),('target-mx','mx-host=target.example,mail.example,10\nhost-record=mail.example,192.0.2.2\n'),('target-srv','srv-host=target.example,mail.example,123,1,2\nhost-record=mail.example,192.0.2.2\n'),('target-raw','dns-rr=target.example,257,000569737375656578616d706c65\n'),('target-host','host-record=target.example,192.0.2.2\n'),('target-interface','interface-name=target.example,lo\n'),('target-local','local=/target.example/\n'),('target-literal','address=/target.example/192.0.2.4\n'),('filter','filterwin2k\n'),('filter-target-txt','filterwin2k\ntxt-record=target.example,terminal\n'),('target-long-txt',''.join('txt-record=target.example,'+'x'*200+str(i)+'\n' for i in range(5))),('target-long-mx',''.join('mx-host=target.example,m'+str(i)+'.example,10\n' for i in range(30)))]
result={'identities':{x:sha256(y) for x,y in [('c',root/'usr/sbin/dnsmasq'),('main',args.main),('fix',args.fix),('driver',Path(__file__))]},'profiles':[]}
for profile,config in profiles:
 for mode_value in ['positive','negative']:
  mode=mode_value;row={'name':profile+'-'+mode,'config':base+config,'sides':{},'cases':{}}
  (root/'m2/dns.conf').write_text(base+config)
  for side,binary in [('c','c'),('main','/usr/sbin/dnsmasq-main'),('fix','rust')]:
   log=args.out/(row['name']+'-'+side+'.log')
   with log.open('wb') as f:
    proc=subprocess.Popen(command(root,binary,'-C','/m2/dns.conf','-k','--user=root','--group=root','--pid-file=','--log-facility=-'),stdout=f,stderr=f)
    for i in range(30):
     if proc.poll() is not None:break
     if w.request(w.query('ready.test'),'udp')['status']=='reply':break
     time.sleep(.01)
    row['sides'][side]={'ready':proc.poll() is None}
    if proc.poll() is None:
     queries=[('seed',w.query('alias.example'))]
     for t in [1,5,6,12,15,16,28,33,255,257]:
      for flags,extra,label in [(0x100,b'','rd'),(0,b'','nord'),(0x100,w.opt(ttl=0x8000),'do')]:queries.append((str(t)+'-'+label,w.query('alias.example',t,flags=flags,extra=extra,ar=bool(extra))))
     for label,packet in queries:
      for protocol in ('udp','tcp'):
       proc.send_signal(signal.SIGHUP);time.sleep(.012)
       warm=w.request(w.query('alias.example'),'udp')
       before=len(stub.records);response=w.request(packet,protocol);canon=canonical(response)
       row['cases'].setdefault(label+'-'+protocol,{'query':packet.hex()})[side]={'response':response,'canonical':canon,'upstream':len(stub.records)-before,'warm':warm}
     proc.send_signal(signal.SIGTERM)
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:proc.kill();proc.wait()
    row['sides'][side]['exit']=proc.returncode
  result['profiles'].append(row)
  print(json.dumps({'profile':row['name'],'changed':sum(c['main']['canonical']!=c['fix']['canonical'] for c in row['cases'].values()),'fix_c_diff':sum(c['c']['canonical']!=c['fix']['canonical'] for c in row['cases'].values())}),flush=True)
  (args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
# Same packet set with configured local records covers the shared parser refactor.
mode='positive';config=base+'local=/audit.test/\nhost-record=host.audit.test,192.0.2.42,2001:db8::42\ncname=alias.audit.test,host.audit.test\ntxt-record=txt.audit.test,hello\n'
row={'name':'malformed','config':config,'cases':{},'sides':{}};(root/'m2/dns.conf').write_text(config)
for side,binary in [('c','c'),('main','/usr/sbin/dnsmasq-main'),('fix','rust')]:
 with (args.out/('malformed-'+side+'.log')).open('wb') as f:
  proc=subprocess.Popen(command(root,binary,'-C','/m2/dns.conf','-k','--user=root','--group=root','--pid-file=','--log-facility=-'),stdout=f,stderr=f);time.sleep(.1)
  for label,packet in w.local_cases():
   for protocol in ('udp','tcp'):
    response=w.request(packet,protocol);row['cases'].setdefault(label+'-'+protocol,{'query':packet.hex()})[side]={'response':response,'canonical':canonical(response)}
  row['sides'][side]={'alive':proc.poll() is None};proc.send_signal(signal.SIGTERM);proc.wait(timeout=2)
result['profiles'].append(row);(args.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
stub.stop.set()
print(json.dumps({'complete':True,'cases':sum(len(r['cases']) for r in result['profiles'])}))
