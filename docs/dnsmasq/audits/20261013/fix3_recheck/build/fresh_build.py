#!/usr/bin/env python3
"""Build a frozen HEAD release and tests, run ordinary units and runtime RELRO."""
import argparse,hashlib,importlib.util,json,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args()
R=a.root.resolve();S=R/'source';P=R/'private';P.mkdir(exist_ok=True);report_path=P/'fresh-build.json'
assert not report_path.exists(),'fresh report required'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save():report_path.write_text(json.dumps(report,indent=2)+'\n')
identity=json.loads((R/'head-input-identity.json').read_text())
spec=importlib.util.spec_from_file_location('package',S/'tools/dnsmasq/build_package.py'); package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
assert package.inputs(S)==identity['source_files']
report={'head':identity['head'],'source_digest':identity['digest'],'input_count':len(identity['source_files']),'controller_sha256':sha(__file__),'commands':[],'passed':False}
def run(name,argv,timeout=1200):
 row={'name':name,'argv':list(map(str,argv)),'started':time.time()};report['commands'].append(row);save()
 log=P/(name+'.log')
 with log.open('wb') as f:proc=subprocess.run(row['argv'],stdout=f,stderr=f,timeout=timeout)
 row.update(exit=proc.returncode,seconds=time.time()-row['started'],log_sha256=sha(log));save();assert proc.returncode==0,row
 return row
try:
 for kind in ('release','tests'):
  run(kind+'-build',['sh',S/'tools/dnsmasq/oracle_build.sh',S,P/kind,kind]);report[kind]=json.loads((P/kind/'build.json').read_text());save()
 counts=[]
 for name in ('lib-dnsmasq_rs','bin-dnsmasq-rs'):
  binary=P/'tests'/name
  row=run('unit-'+name,['sudo','-n','sh',S/'tools/dnsmasq/run_isolated.sh','sh','-c','mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"','unit',binary,'--test-threads=1'],600)
  match=re.search(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',(P/('unit-'+name+'.log')).read_text());assert match
  row['counts']=dict(zip(('passed','failed','ignored','measured','filtered_out'),map(int,match.groups())));row['elf_sha256']=sha(binary);counts.append(row['counts']);save()
 report['ordinary_units']={k:sum(v[k] for v in counts) for k in counts[0]};assert report['ordinary_units']=={'passed':846,'failed':0,'ignored':23,'measured':0,'filtered_out':0}
 main=Path('/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs');report['main_rehash']={'path':str(main),'sha256':sha(main),'bytes':main.stat().st_size};assert report['main_rehash']['sha256']=='ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863'
 run('release-protection',['sudo','-n','sh',S/'tools/dnsmasq/run_isolated.sh','python3',R/'build_protections_probe.py',S,P/'release/dnsmasq-rs',P/'release-protection','--require-relro'])
 report['protection']=json.loads((P/'release-protection/result.json').read_text());assert report['protection']['passed']
 assert package.inputs(S)==identity['source_files'];report['source_inputs_unchanged']=True;report['passed']=True
except BaseException as error:report['error']=repr(error);raise
finally:report['ended']=time.time();save()
