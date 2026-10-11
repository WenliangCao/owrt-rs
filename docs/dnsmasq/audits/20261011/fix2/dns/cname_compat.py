#!/usr/bin/env python3
"""Normal DNS compatibility cases for dynamic aliases and configured terminals."""
import argparse, hashlib, json, os, pathlib, socket, struct, subprocess, threading, time

def name(s): return b''.join(bytes([len(p)])+p.encode() for p in s.split('.'))+b'\0'
def query(s,k=1): return struct.pack('!6H',0x4321,0x100,1,0,0,0)+name(s)+struct.pack('!HH',k,1)
def exact(s,n):
 out=b''
 while len(out)<n:
  p=s.recv(n-len(out))
  if not p: raise EOFError()
  out+=p
 return out

def exchange(w,tcp=False):
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(1)
  if tcp:
   s.connect(('127.0.0.1',15353));s.sendall(struct.pack('!H',len(w))+w)
   return exact(s,struct.unpack('!H',exact(s,2))[0])
  s.sendto(w,('127.0.0.1',15353));return s.recv(65535)

def decode(w):
 def dn(p):
  r=[];end=None
  for _ in range(30):
   l=w[p]
   if l&192==192:
    end=end or p+2;p=((l&63)<<8)|w[p+1];continue
   p+=1
   if not l:return '.'.join(r),end or p
   r.append(w[p:p+l].decode());p+=l
  raise ValueError('name')
 h=struct.unpack('!6H',w[:12]);p=12;qs=[];rrs=[]
 for _ in range(h[2]):
  n,p=dn(p);k,c=struct.unpack('!HH',w[p:p+4]);p+=4;qs.append([n,k,c])
 for _ in range(sum(h[3:])):
  n,p=dn(p);k,c,ttl,l=struct.unpack('!HHIH',w[p:p+10]);p+=10
  val=dn(p)[0] if k in (5,12) else w[p:p+l].hex();rrs.append({'name':n,'type':k,'class':c,'ttl':ttl,'data':val});p+=l
 return {'flags':h[1],'question':qs,'counts':list(h[3:]),'records':rrs}

class Upstream:
 def __init__(self):
  self.stop=threading.Event();self.events=[];self.socks=[];self.threads=[]
  for typ in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
   s=socket.socket(socket.AF_INET,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',15354));s.settimeout(.05)
   if typ==socket.SOCK_STREAM:s.listen(4)
   self.socks.append(s);t=threading.Thread(target=self.serve,args=(s,typ));t.start();self.threads.append(t)
 def reply(self,w,transport):
  p=12
  while w[p]:p+=w[p]+1
  end=p+5;k=struct.unpack('!H',w[end-4:end-2])[0];self.events.append({'transport':transport,'query':decode(w)})
  alias=w[12:p+1]==name('alias.test');owner=name('target.test') if alias else w[12:p+1]
  rows=[]
  if alias:rows.append(b'\xc0\x0c'+struct.pack('!HHIH',5,1,600,len(owner))+owner)
  if k==1:data=socket.inet_aton('192.0.2.77')
  elif k==16:data=b'\x0fupstream-value!'
  elif k==15:data=struct.pack('!H',20)+name('upstream-mail.test')
  elif k==33:data=struct.pack('!HHH',20,0,443)+name('upstream-service.test')
  else:data=b'\x01\x02'
  if k!=5:rows.append(owner+struct.pack('!HHIH',k,1,600,len(data))+data)
  return w[:2]+struct.pack('!5H',0x8180,1,len(rows),0,0)+w[12:end]+b''.join(rows)
 def serve(self,s,typ):
  while not self.stop.is_set():
   try:
    if typ==socket.SOCK_DGRAM:
     w,p=s.recvfrom(4096);s.sendto(self.reply(w,'udp'),p)
    else:
     c,_=s.accept()
     with c:
      c.settimeout(.5)
      try:
       while not self.stop.is_set():
        w=exact(c,struct.unpack('!H',exact(c,2))[0]);r=self.reply(w,'tcp');c.sendall(struct.pack('!H',len(r))+r)
      except (OSError,EOFError):pass
   except socket.timeout:pass
 def close(self):
  self.stop.set()
  for t in self.threads:t.join()
  for s in self.socks:s.close()

def run(command,options,qtype,tcp,debug,folder,warm_txt=False):
 folder.mkdir(parents=True);up=Upstream();argv=command+['-C','/dev/null','-d' if debug else '-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--pid-file=','--log-facility=-','--log-queries','--host-record=ready.test,192.0.2.123','--server=127.0.0.1#15354','--cache-size=32','--cache-rr=TXT']+options
 with (folder/'daemon.log').open('wb') as log:
  proc=subprocess.Popen(argv,stdout=log,stderr=log)
  row={'argv':argv}
  try:
   for _ in range(100):
    try:
     if exchange(query('ready.test')).endswith(socket.inet_aton('192.0.2.123')):break
    except OSError:time.sleep(.01)
    if proc.poll()!=None:raise RuntimeError((folder/'daemon.log').read_text())
   row['warm_A']=decode(exchange(query('alias.test')))
   if warm_txt:row['warm_TXT']=decode(exchange(query('target.test',16)))
   w=exchange(query('alias.test',qtype),tcp);row['answer']=decode(w);row['wire']=w.hex();row['upstream']=list(up.events);row['alive']=proc.poll()==None
  finally:
   proc.terminate()
   try:proc.wait(timeout=3)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   row['exit']=proc.returncode;up.close()
 row['log']=(folder/'daemon.log').read_text();return row

def main():
 p=argparse.ArgumentParser();p.add_argument('--image-root',type=pathlib.Path,required=True);p.add_argument('--rust',type=pathlib.Path,required=True);p.add_argument('--main',type=pathlib.Path);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';a.out.mkdir(parents=True,exist_ok=False)
 cmds={'c':[str(a.image_root/'lib/libc.so'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(a.image_root/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]}
 if a.main:cmds['main']=[str(a.main)]
 cases=[('original',16,['--txt-record=alias.test,alias-local'],True),('terminal-txt',16,['--txt-record=target.test,local-target'],False),('both-txt',16,['--txt-record=alias.test,alias-local','--txt-record=target.test,local-target'],False),('terminal-mx',15,['--mx-host=target.test,local-mail.test,10'],False),('terminal-srv',33,['--srv-host=target.test,local-service.test,8443,10,0'],False)]
 result={'identities':{k:hashlib.sha256(pathlib.Path(v[-1]).read_bytes()).hexdigest() for k,v in cmds.items()},'cases':[]}
 for ident,k,opts,warm in cases:
  for debug in (False,True):
   for tcp in (False,True):
    key=f'{ident}-debug{debug}-tcp{tcp}';rows={side:run(cmd,opts,k,tcp,debug,a.out/(key+'-'+side),warm) for side,cmd in cmds.items()}
    result['cases'].append({'id':key,'matched':rows['c']['answer']==rows['rust']['answer'],'observed':rows});(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'cases':len(result['cases']),'mismatches':[r['id'] for r in result['cases'] if not r['matched']]},indent=2))
if __name__=='__main__':main()
