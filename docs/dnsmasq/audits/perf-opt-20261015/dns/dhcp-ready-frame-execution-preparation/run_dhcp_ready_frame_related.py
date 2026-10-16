from pathlib import Path
import json,hashlib,os,subprocess,time
p=Path('/home/ubuntu/dnsmasq-perf-20261015/correctness/private');source=Path('/home/ubuntu/dnsmasq-perf-20261015/root/source-dhcp-ready-frame');env={**os.environ,'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0'}
with (p/'dhcp-ready-frame-tests-build.log').open('w') as log:subprocess.run(['sh',str(source/'tools/dnsmasq/oracle_build.sh'),str(source),str(p/'dhcp-ready-frame-tests'),'tests'],env=env,stdout=log,stderr=log,check=True)
with (p/'dhcp-ready-frame-allocation-build.log').open('w') as log:subprocess.run(['python3',str(p/'build_dhcp_ready_frame_allocations.py')],env=env,stdout=log,stderr=log,check=True)
out=p/'dhcp-ready-frame-unit-run';out.mkdir();old=json.loads((p/'e-unit-run/result.json').read_text());rows=[]
for gate in old['gates']:
 name=gate['gate'];argv=[a.replace('root/source-e','root/source-dhcp-ready-frame').replace('/e-tests/','/dhcp-ready-frame-tests/').replace('/e-allocation-build/','/dhcp-ready-frame-allocation-build/') for a in gate['argv']];start=time.time()
 with (out/(name+'.log')).open('w') as log:r=subprocess.run(argv,stdout=log,stderr=log)
 binary=next(Path(a) for a in argv if '/dhcp-ready-frame-tests/'in a or '/dhcp-ready-frame-allocation-build/'in a);summary=[line for line in (out/(name+'.log')).read_text().splitlines() if line.startswith('test result:')]
 row={'gate':name,'argv':argv,'exit':r.returncode,'elapsed_seconds':time.time()-start,'summary':summary,'log_sha256':hashlib.sha256((out/(name+'.log')).read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()};rows.append(row)
 (out/'result.json').write_text(json.dumps({'source_commit':'025c2f2c5ca11758c01dd7e58e2b49c4d087ed5c','source':str(source),'fresh_test_build_receipt':str(p/'dhcp-ready-frame-tests/build.json'),'gates':rows},indent=2)+'\n');print(name,r.returncode,summary,flush=True)
 if r.returncode:raise SystemExit(r.returncode)
(p/'dhcp-ready-frame-related-ready.json').write_text(json.dumps({'source_commit':'025c2f2c5ca11758c01dd7e58e2b49c4d087ed5c','state':'five-original-related-groups-complete'},indent=2)+'\n')
