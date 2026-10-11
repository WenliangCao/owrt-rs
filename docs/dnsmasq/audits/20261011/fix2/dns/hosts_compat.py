#!/usr/bin/env python3
"""Benign hosts ingestion/reload compatibility and unsupported-IDN diagnostics."""
import argparse,hashlib,json,os,pathlib,signal,subprocess,time,sys,re
from cname_compat import query,exchange,decode

def logs(path):
 return [re.sub(r'^.*?dnsmasq\[\d+\]: ','',x) for x in path.read_text().splitlines() if any(y in x for y in ['bad name at ','bad address at ','read /'])]

def run(cmd,kind,debug,folder):
 folder.mkdir(parents=True);hdir=folder/'input';hdir.mkdir();hosts=hdir/'names';log=folder/'daemon.log'
 content=('# ordinary host file\n192.0.2.7 First.Test first-alias.test\n192.0.2.7 repeated.test\n2001:db8::7 v6.test\n192.0.2.8 short\n192.0.2.9 café.test good.test\nnot-an-address ignored.test\n192.0.2.10 final.test').encode()
 hosts.write_bytes(content);arg=str(hosts if kind=='addn-hosts' else hdir)
 opt='hostsdir' if kind=='hostsdir' else 'addn-hosts';argv=cmd+['-C','/dev/null','-d' if debug else '-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--pid-file=','--log-facility=-','--domain=test','--expand-hosts',f'--{opt}={arg}']
 row={'argv':argv,'content_sha256':hashlib.sha256(content).hexdigest(),'phases':[]}
 with log.open('wb') as stream:
  p=subprocess.Popen(argv,stdout=stream,stderr=stream)
  try:
   for reload in (False,True):
    if reload:
     hosts.write_bytes(content+b'\n192.0.2.11 reloaded.test\n');p.send_signal(signal.SIGHUP)
    deadline=time.monotonic()+5;sentinel='reloaded.test' if reload else 'final.test'
    while True:
     try:
      w=exchange(query(sentinel))
      if decode(w)['counts'][0]==1:break
     except OSError:pass
     if time.monotonic()>deadline:raise RuntimeError(log.read_text())
     time.sleep(.01)
    cases=[('First.Test',1),('first-alias.test',1),('repeated.test',1),('v6.test',28),('short',1),('short.test',1),('good.test',1),('final.test',1),('7.2.0.192.in-addr.arpa',12)]
    if reload:cases.append(('reloaded.test',1))
    answers={f'{n}/{k}':{t:decode(exchange(query(n,k),t=='tcp')) for t in ('udp','tcp')} for n,k in cases}
    row['phases'].append({'reload':reload,'answers':answers,'notices':logs(log),'alive':p.poll()==None})
  finally:
   p.terminate()
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.wait()
   row['exit']=p.returncode
 row['log']=log.read_text();return row

def main():
 p=argparse.ArgumentParser();p.add_argument('--image-root',type=pathlib.Path,required=True);p.add_argument('--rust',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1';a.out.mkdir(parents=True,exist_ok=False)
 cmds={'c':[str(a.image_root/'lib/libc.so'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(a.image_root/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]};result={'script_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'identities':{k:hashlib.sha256(pathlib.Path(v[-1]).read_bytes()).hexdigest() for k,v in cmds.items()},'cases':[]}
 for kind in ('addn-hosts','directory','hostsdir'):
  for debug in (False,True):
   key=f'{kind}-debug{debug}';rows={s:run(c,kind,debug,a.out/(key+'-'+s)) for s,c in cmds.items()}
   def normalized(row,side):
    r=json.loads(json.dumps(row['phases']));path=str(a.out/(key+'-'+side))
    for phase in r:phase['notices']=[n.replace(path,'<fixture>') for n in phase['notices']]
    return r
   result['cases'].append({'id':key,'matched':normalized(rows['c'],'c')==normalized(rows['rust'],'rust'),'observed':rows});(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'cases':len(result['cases']),'mismatches':[x['id'] for x in result['cases'] if not x['matched']]},indent=2))
if __name__=='__main__':main()
