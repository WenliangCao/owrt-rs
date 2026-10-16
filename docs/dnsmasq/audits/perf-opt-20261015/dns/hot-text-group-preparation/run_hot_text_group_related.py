from pathlib import Path
import json,hashlib,os,subprocess,time
p=Path('/home/ubuntu/dnsmasq-perf-20261015/correctness/private');source=Path('/home/ubuntu/dnsmasq-perf-20261015/root/source-hot-text-group');env={**os.environ,'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0'}
with (p/'hot-text-group-tests-build.log').open('w') as log:subprocess.run(['sh',str(source/'tools/dnsmasq/oracle_build.sh'),str(source),str(p/'hot-text-group-tests'),'tests'],env=env,stdout=log,stderr=log,check=True)
with (p/'hot-text-group-allocation-build.log').open('w') as log:subprocess.run(['python3',str(p/'build_hot_text_group_allocations.py')],env=env,stdout=log,stderr=log,check=True)
out=p/'hot-text-group-unit-run';out.mkdir();old=json.loads((p/'e-unit-run/result.json').read_text());rows=[]
for gate in old['gates']:
 name=gate['gate'];argv=[a.replace('root/source-e','root/source-hot-text-group').replace('/e-tests/','/hot-text-group-tests/').replace('/e-allocation-build/','/hot-text-group-allocation-build/') for a in gate['argv']];start=time.time()
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(argv,stdout=log,stderr=log)
 binary=next(Path(a) for a in argv if '/hot-text-group-tests/'in a or '/hot-text-group-allocation-build/'in a);summary=[line for line in (out/(name+'.log')).read_text().splitlines() if line.startswith('test result:')]
 row={'gate':name,'argv':argv,'exit':r.returncode,'elapsed_seconds':time.time()-start,'summary':summary,'log_sha256':hashlib.sha256((out/(name+'.log')).read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};rows.append(row)
 (out/'result.json').write_text(json.dumps({'source_commit':'c95c5571fe8915c4a67af8e438026e5f4f5d3a61','source':str(source),'fresh_test_build_receipt':str(p/'hot-text-group-tests/build.json'),'gates':rows},indent=2)+'\n');print(name,r.returncode,summary,flush=True)
 if r.returncode:raise SystemExit(r.returncode)
(p/'hot-text-group-related-ready.json').write_text(json.dumps({'source_commit':'c95c5571fe8915c4a67af8e438026e5f4f5d3a61','state':'five-original-related-groups-complete'},indent=2)+'\n')
