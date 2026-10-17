import hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work')
SOURCE=ROOT/'source-b8617f57';OUT=ROOT/'private/final-b8617f57/sdk-smoke';BINARY=OUT/'dnsmasq-rs'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BINARY)=='c30fad397d582fd544d7af31e8e70f1408f18bb6c29e143bcd5abc12ed309eaa'
assert sha(OUT/'dnsmasq-2.93-r4.apk')=='aa66ba0b8cc57d3991aa81b393bc0d0590360eee45819cec69348713867d9b22'
BINARY.chmod(0o755)
report={'status':'running','source_commit':'b8617f574d6d3674e35627f7beedb73a9dd655eb','canonical_ci':39027546957,'binary_sha256':sha(BINARY),'apk_sha256':sha(OUT/'dnsmasq-2.93-r4.apk'),'phases':[]}
def save():(OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
try:
 for name,command in [
  ('dns-signal',['python3',str(SOURCE/'tools/dnsmasq/dns_signal_smoke.py'),'--binary',str(BINARY),'--output',str(OUT/'dns-signal')]),
  ('dhcp',['python3',str(SOURCE/'tools/dnsmasq/dhcp_daemon_smoke.py'),'--binary',str(BINARY),'--output',str(OUT/'dhcp')]),
  ('startup',['python3',str(OUT/'startup_smoke.py')])]:
  command=['sudo','-n','sh',str(SOURCE/'tools/dnsmasq/run_isolated.sh'),*command]
  row={'name':name,'command':command,'start':time.time()};report['phases'].append(row);save()
  with (OUT/(name+'.log')).open('wb') as stream:r=subprocess.run(command,cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT,timeout=60)
  row.update(returncode=r.returncode,log_sha256=sha(OUT/(name+'.log')),end=time.time());save()
  assert r.returncode==0,name
  path=OUT/name/('summary.json' if name=='dhcp' else 'result.json')
  row['result']=json.loads(path.read_text());assert row['result']['status']=='passed';save()
  print(json.dumps({'name':name,'returncode':r.returncode,'result':{k:v for k,v in row['result'].items() if k!='replies'}}),flush=True)
 report['status']='passed'
except BaseException as error:report.update(status='failed',error=repr(error));raise
finally:save()
