#!/usr/bin/env python3
"""Independent targeted shared-answer boundary audit. No product edits.
Retains TTLs, OPT words, all flags and wire bytes; no equality waivers.
"""
import argparse,hashlib,json,os,shutil,signal,socket,struct,subprocess,sys,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--tools',type=Path,required=True);p.add_argument('--image',type=Path,required=True);p.add_argument('--main',type=Path,required=True);p.add_argument('--pre',type=Path,required=True);p.add_argument('--fix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--profiles',help='Comma separated primary profiles; omitted runs all');a=p.parse_args()
sys.path.insert(0,str(a.tools));import audit_20261011_dns as w
from m2_rootfs import prepare,command,sha256
assert os.getenv('DNSMASQ_TEST_ISOLATED')=='1'
a.out.mkdir(parents=True,exist_ok=False);root=prepare(a.image,None,a.out,a.fix)
for k,p in [('main',a.main),('pre',a.pre)]:shutil.copy2(p,root/('usr/sbin/dnsmasq-'+k))
mode='ordinary'

def reply(packet):
 e=w.question_end(packet);q=packet[12:e];t=struct.unpack('!H',packet[e-4:e-2])[0];flags=0x8080|(struct.unpack_from('!H',packet,2)[0]&0x0110)
 if mode=='route':return packet[:2]+struct.pack('!5H',flags,1,2,0,0)+q+w.rr(b'\xc0\x0c',5,w.name('target.test'),ttl=120)+w.rr(w.name('target.test'),1,socket.inet_aton('192.0.2.77'),ttl=120)
 if t==1:return packet[:2]+struct.pack('!5H',flags,1,1,0,0)+q+w.rr(b'\xc0\x0c',1,socket.inet_aton('192.0.2.77'),ttl=120)
 soa=w.rr(w.name('test'),6,w.name('ns.test')+w.name('hostmaster.test')+struct.pack('!5I',1,60,60,60,120),ttl=120)
 flags|=3
 if mode=='truncated':flags|=0x200
 additional=w.opt(ttl=0x01000000) if mode=='extended' else b''
 return packet[:2]+struct.pack('!5H',flags,1,0,1,int(bool(additional)))+q+soa+additional
w.stub_reply=reply;stub=w.Stub()
base='port=15353\nlisten-address=127.0.0.1\nbind-interfaces\nno-hosts\nno-resolv\nno-round-robin\nlocal-ttl=37\ncache-size=150\nserver=127.0.0.1#15354\nhost-record=ready.test,192.0.2.1\nhost-record=local.test,192.0.2.9,2001:db8::9\ntxt-record=local.test,hello\ndns-rr=raw.test,65401,abcd\ndns-rr=raw.test,65400,0102\ndns-rr=raw.test,65401,1234\ncaa-record=raw.test,0,issue,ca.test\n'

def name_at(b,o):
 labels=[];end=None;seen=set()
 while True:
  if o in seen:raise ValueError('loop')
  seen.add(o);n=b[o];o+=1
  if n==0:return '.'.join(labels),end or o
  if n&192==192:
   if end is None:end=o+1
   o=((n&63)<<8)|b[o];continue
  labels.append(b[o:o+n].hex());o+=n

def decoded(v):
 if v['status']!='reply':return {'status':v['status']}
 b=bytes.fromhex(v['hex'])
 if len(b)<12:return {'status':'short-reply','length':len(b),'hex':b.hex()}
 h=list(struct.unpack('!6H',b[:12]));out={'header':h,'records':[]};o=12
 try:
  questions=[]
  for _ in range(h[2]):n,o=name_at(b,o);questions.append([n,*struct.unpack_from('!HH',b,o)]);o+=4
  out['questions']=questions
  for section,count in enumerate(h[3:]):
   for _ in range(count):
    n,o=name_at(b,o);t,c,ttl,size=struct.unpack_from('!HHIH',b,o);o+=10;data=b[o:o+size].hex()
    if t in [2,5,12]:data=name_at(b,o)[0]
    elif t==6:
     n1,z=name_at(b,o);n2,z=name_at(b,z);data=[n1,n2,*struct.unpack_from('!5I',b,z)]
    out['records'].append({'section':section,'owner':n,'type':t,'class':c,'ttl':ttl,'rdata':data});o+=size
  out['trailing']=b[o:].hex();return out
 except Exception as e:return {'parse_error':repr(e),'header':h}

def exchange(packet,protocol,conn=None):
 if not conn:return w.request(packet,protocol)
 try:
  conn.sendall(struct.pack('!H',len(packet))+packet);data=w.exact(conn,struct.unpack('!H',w.exact(conn,2))[0]);return {'status':'reply','hex':data.hex(),'length':len(data),'header':list(struct.unpack('!6H',data[:12]))}
 except EOFError:return {'status':'eof'}
 except OSError as e:return {'status':'socket-error','errno':e.errno}

queries=[]
for name,t in [('local.test',1),('local.test',16),('raw.test',65401),('raw.test',65400),('raw.test',257),('raw.test',255),('cache.test',1)]:
 for size,ttl,label in [(None,0,'plain'),(0,0,'edns0'),(512,0,'edns512'),(1232,0x8000,'do'),(4096,0x10000,'v1')]:
  queries.append((name+'-'+str(t)+'-'+label,w.query(name,t,extra=w.opt(size,ttl) if size is not None else b'',ar=int(size is not None))))
for name in ['local.test','cache.test']:
 for label,extra in [('truncated-rr',w.opt()[:-1]),('truncated-data',w.opt(data=b'\x00\x0a\x00\x08a')),('duplicate',w.opt()+w.opt(4096,0x8000))]:queries.append((name+'-'+label,w.query(name,extra=extra,ar=2 if label=='duplicate' else 1)))
# Full output boundaries around DNS-over-TCP's two-byte length; small queries only.
profiles=[('ordinary',base,queries)]
for length in [65480,65496,65497]:
 config=base+'dns-rr=huge.test,65401,'+'00'*length+'\n'
 profiles.append(('large-'+str(length),config,[(str(length)+'-'+s,w.query('huge.test',65401,extra=w.opt(4096,0x8000) if s=='do' else b'',ar=int(s=='do'))) for s in ['plain','do']]))
profiles += [('route-local',base+'local=/target.test/\n', [('route-'+str(t),w.query('alias.test',t)) for t in [6,12,15,16,28,33,255,257]]), ('route-address',base+'address=/target.test/192.0.2.4\n',[('route-255',w.query('alias.test',255))])]
result={'identities':{k:sha256(p) for k,p in [('c',root/'usr/sbin/dnsmasq'),('main',a.main),('pre',a.pre),('fix',a.fix),('driver',Path(__file__))]},'profiles':[]}
for profile,config,cases in profiles:
 if a.profiles and profile not in a.profiles.split(','):continue
 mode='route' if profile.startswith('route-') else 'ordinary'
 row={'name':profile,'config_sha256':hashlib.sha256(config.encode()).hexdigest(),'cases':{},'processes':{}};(root/'m2/dns.conf').write_text(config)
 for side,binary in [('c','c'),('main','/usr/sbin/dnsmasq-main'),('pre','/usr/sbin/dnsmasq-pre'),('fix','rust')]:
  with (a.out/(profile+'-'+side+'.log')).open('wb') as log:
   proc=subprocess.Popen(command(root,binary,'-C','/m2/dns.conf','-k','--user=root','--group=root','--pid-file=','--log-facility=-'),stdout=log,stderr=log)
   ready=False
   for _ in range(30):
    if proc.poll() is not None:break
    if w.request(w.query('ready.test'),'udp')['status']=='reply':ready=True;break
    time.sleep(.01)
   row['processes'][side]={'ready':ready}
   if ready:
    warm=w.request(w.query('alias.test' if mode=='route' else 'cache.test'),'udp');row['processes'][side]['warm']=warm
    for label,packet in cases:
     for protocol in ['udp','tcp']:
      before=len(stub.records);v=exchange(packet,protocol);row['cases'].setdefault(label+'-'+protocol,{'query':packet.hex()})[side]={'response':v,'decoded':decoded(v),'upstream':stub.records[before:]}
    row['processes'][side]['alive']=proc.poll() is None;row['processes'][side]['health']=w.request(w.query('ready.test'),'udp')
   proc.send_signal(signal.SIGTERM)
   try:proc.wait(timeout=2)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   row['processes'][side]['exit']=proc.returncode
 result['profiles'].append(row);(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'profile':profile,'cases':len(row['cases'])}),flush=True)
# Warm known names: NX conversion must not rewrite TC or extended RCODE errors.
for mode in ['ordinary','truncated','extended']:
 row={'name':'known-'+mode,'cases':{},'processes':{}};(root/'m2/dns.conf').write_text(base)
 for side,binary in [('c','c'),('main','/usr/sbin/dnsmasq-main'),('pre','/usr/sbin/dnsmasq-pre'),('fix','rust')]:
  with (a.out/(row['name']+'-'+side+'.log')).open('wb') as log:
   proc=subprocess.Popen(command(root,binary,'-C','/m2/dns.conf','-k','--user=root','--group=root','--pid-file=','--log-facility=-'),stdout=log,stderr=log);time.sleep(.05)
   row['processes'][side]={'warm':w.request(w.query('known.test'),'udp')}
   for name in ['known.test','cold.test']:
    packet=w.query(name,16,extra=w.opt(ttl=0x8000),ar=1)
    for protocol in ['udp','tcp']:
     start=len(stub.records);v=exchange(packet,protocol);row['cases'].setdefault(name+'-'+protocol,{'query':packet.hex()})[side]={'response':v,'decoded':decoded(v),'upstream':stub.records[start:]}
   proc.send_signal(signal.SIGTERM);proc.wait(timeout=2);row['processes'][side]['exit']=proc.returncode
 result['profiles'].append(row);(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
stub.stop.set();print(json.dumps({'complete':True,'cases':sum(len(p['cases']) for p in result['profiles'])}))
