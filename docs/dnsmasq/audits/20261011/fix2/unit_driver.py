from pathlib import Path
import hashlib,json,subprocess,time,os
ROOT=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011'); SOURCE=ROOT/'source'; OUT=ROOT/'private/unit-run'
OUT.mkdir(exist_ok=False)
result={'source_commit':'6d001a77f06a0cf0111537507827f5399cb49a14','build':json.loads((ROOT/'private/tests/build.json').read_text()),'commands':[],'passed':False}
def save(): (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
for name in ['lib-dnsmasq_rs','bin-dnsmasq-rs']:
 binary=ROOT/'private/tests'/name
 argv=['sudo','-n','sh',str(SOURCE/'tools/dnsmasq/run_isolated.sh'),'sh','-c','mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"','unit',str(binary),'--test-threads=1']
 row={'name':name,'argv':argv,'started':time.time(),'elf_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};result['commands'].append(row);save();print('START',name,flush=True)
 with (OUT/(name+'.log')).open('wb') as f:r=subprocess.run(argv,stdout=f,stderr=f,timeout=600)
 row.update(returncode=r.returncode,elapsed_seconds=time.time()-row['started'],log_sha256=hashlib.sha256((OUT/(name+'.log')).read_bytes()).hexdigest(),test_summary=[s for s in (OUT/(name+'.log')).read_text().splitlines() if s.startswith('test result:')]);save();print(row['test_summary'],flush=True)
 if r.returncode:raise SystemExit(1)
result['passed']=True;save()
