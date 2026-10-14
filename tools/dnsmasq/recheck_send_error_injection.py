import pathlib,subprocess,time,os,signal,json,hashlib,socket,struct,threading
import argparse
parser=argparse.ArgumentParser(description='Inject one upstream sendto errno into unmodified C/R ELF in a disposable network namespace')
parser.add_argument('--output',required=True,type=pathlib.Path)
parser.add_argument('--image-root',required=True,type=pathlib.Path)
parser.add_argument('--rust-binary',required=True,type=pathlib.Path)
args=parser.parse_args()
root=args.output;root.mkdir(parents=True,exist_ok=True)
image=args.image_root
final=args.rust_binary
subprocess.run(['ip','link','set','lo','up'],check=True)
result={'scope':'Unmodified ELF, isolated oracle network namespace, ptrace inject first upstream UDP sendto only, ordinal calibrated independently per ELF; no product code modification','identities':{},'cases':[]}
for impl,path in [('C',image/'usr/sbin/dnsmasq'),('R_final',final)]:
 result['identities'][impl]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
 binary=[str(path)] if impl=='R_final' else [str(image/'lib/ld-musl-aarch64.so.1'),'--library-path',str(image/'lib')+':'+str(image/'usr/lib'),str(path)]
 for err in ['CALIBRATE','EPERM','ENOBUFS','ECONNREFUSED']:
  for edns in ([False] if err=='CALIBRATE' else [False,True]):
   out=root/(impl+'-'+err+('-edns' if edns else '-plain'));out.mkdir();out.chmod(0o777)
   conf=out/'config';conf.write_text('no-hosts\nno-resolv\nport=15353\nlisten-address=127.0.0.1\nbind-interfaces\nserver=127.0.0.1#15354@127.0.0.1\ncache-size=1000\nedns-packet-max=1232\ndomain-needed\nstop-dns-rebind\nrebind-localhost-ok\nlocal-service\nlocalise-queries\nuser=nobody\ngroup=nogroup\nlog-queries=extra\nlog-facility='+str(out/'service.log')+'\n')
   us=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);us.bind(('127.0.0.1',15354));us.settimeout(.1)
   stopped=False;packets=[]
   def serve():
    while not stopped:
     try:
      q,peer=us.recvfrom(2048);packets.append(q.hex());at=12
      while q[at]:at+=1+q[at]
      at+=5
      a=q[:2]+struct.pack('!5H',0x8180,1,1,0,0)+q[12:at]+bytes.fromhex('c00c0001000100000e1000045db8d70e')
      us.sendto(a,peer)
     except TimeoutError:pass
   t=threading.Thread(target=serve);t.start()
   command=['strace','-ff','-ttt','-s','1024','-xx','-e','trace=sendto',*((['-e','inject=sendto:error='+err+':when='+str(inject_at)]) if err!='CALIBRATE' else []),'-o',str(out/'syscalls')]+binary+['-k','-C',str(conf)]
   p=subprocess.Popen(command,stdout=(out/'daemon.log').open('w'),stderr=subprocess.STDOUT,start_new_session=True)
   try:
    time.sleep(.4)
    client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.bind(('127.0.0.1',0));client.settimeout(2)
    replies=[]
    for index in [1,2]:
     name='fault'+str(index)+'.audit.example'
     q=struct.pack('!6H',0x1200+index,0x0100,1,0,0,1 if edns else 0)+b''.join(bytes([len(l)])+l.encode() for l in name.split('.'))+b'\0\0\1\0\1'
     if edns:q+=bytes.fromhex('00002904d0000000000000')
     client.sendto(q,('127.0.0.1',15353));a,_=client.recvfrom(2048)
     replies.append({'query_hex':q.hex(),'reply_hex':a.hex(),'rcode':a[3]&15,'upstream_packets_after_reply':len(packets)})
    client.close()
    result['cases'].append({'implementation':impl,'errno':err,'edns':edns,'responses':replies,'upstream_query_hex':packets,'artifact':out.name,'injected_command':command})
   finally:
    os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=3)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
    stopped=True;t.join();us.close()
   if err=='CALIBRATE':
    calls=[l for f in out.glob('syscalls.*') for l in f.read_text().splitlines() if 'sendto(' in l]
    inject_at=next(i+1 for i,l in enumerate(calls) if 'sin_port=htons(15354)' in l)
    print(impl,'inject_at',inject_at,flush=True)
result['plain_fault_packets_equal']=all(next(x for x in result['cases'] if x['implementation']=='C' and x['errno']==e and not x['edns'])['responses'][0]['reply_hex']==next(x for x in result['cases'] if x['implementation']=='R_final' and x['errno']==e and not x['edns'])['responses'][0]['reply_hex'] for e in ['EPERM','ENOBUFS','ECONNREFUSED'])
result['edns_fault_packets_equal']=all(next(x for x in result['cases'] if x['implementation']=='C' and x['errno']==e and x['edns'])['responses'][0]['reply_hex']==next(x for x in result['cases'] if x['implementation']=='R_final' and x['errno']==e and x['edns'])['responses'][0]['reply_hex'] for e in ['EPERM','ENOBUFS','ECONNREFUSED'])
(root/'injection-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))
