#!/usr/bin/env python3
"""Rehash retained source-built SDK against HEAD inputs; fresh ordinary tests."""
import hashlib,importlib.util,json,pathlib,subprocess,time
R=pathlib.Path('/home/ubuntu/dnsmasq-audit-fix4-20261014-build')
S=pathlib.Path('/home/ubuntu/dnsmasq-fix4-repair-20261013/source-final')
P=pathlib.Path('/home/ubuntu/dnsmasq-fix4-repair-20261013/private')
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(pathlib.Path(p).read_text())
R.mkdir(exist_ok=True);(R/'private').mkdir(exist_ok=True)
head=read('/home/ubuntu/fix4-local-input-identity.json');expected=head['source_inputs']
report={'head':head['head'],'main':head['main'],'source_digest':head['source_digest'],'scope':'Reused final SDK artifacts with fresh SHA/source-input checks; fresh test-profile build/run. No new SDK build.','commands':[],'complete':False}
def save(): (R/'private/result.json').write_text(json.dumps(report,indent=2)+'\n')
assert not head['git_worktree_mismatches']
assert all(sha(S/n)==h for n,h in expected.items())
report['source_files_verified']=len(expected)
report['sdk']=[]
for kind in ['sdk-acquire-final','sdk-verify-final']:
 M=P/kind;m=read(M/'manifest.json');assert m['source_files']==expected and m['source_digest']==head['source_digest'] and m['source_build_passed'] and not m['frozen_elf']
 row={'kind':kind,'manifest_sha256':sha(M/'manifest.json'),'source_build_passed':m['source_build_passed'],'failure_boundary':m['failure_boundary'],'elf':m['elf'],'artifact':m['artifact'],'budget_checks':m['budget_checks']}
 for k in ['elf','artifact','pre_sdk_strip_elf']:
  a=m[k];assert sha(a['path'])==a['sha256'];row[k]=a
 row['payload_files_verified']=sum(sha(M/'payload'/n)==h for n,h in m['payload_files'].items())
 assert row['payload_files_verified']==len(m['payload_files'])
 report['sdk'].append(row)
report['sdk_rebuild_elf_identical']=report['sdk'][0]['elf']['sha256']==report['sdk'][1]['elf']['sha256']
report['sdk_rebuild_apk_identical']=report['sdk'][0]['artifact']['sha256']==report['sdk'][1]['artifact']['sha256']
assert report['sdk_rebuild_elf_identical'] and report['sdk_rebuild_apk_identical']
report['release']={'path':str(P/'release-final/dnsmasq-rs'),'sha256':sha(P/'release-final/dnsmasq-rs'),'build_manifest_sha256':sha(P/'release-final/build.json')}
save()
def run(name,argv,timeout=1200):
 log=R/'private'/(name+'.log');row={'name':name,'argv':list(map(str,argv)),'started':time.time()};report['commands'].append(row);save()
 with log.open('wb') as f:p=subprocess.run(row['argv'],stdout=f,stderr=f,timeout=timeout)
 row.update(exit=p.returncode,elapsed_seconds=time.time()-row['started'],log_sha256=sha(log));save();assert p.returncode==0,name
run('fresh-tests-build',['sh',S/'tools/dnsmasq/oracle_build.sh',S,R/'private/tests','tests'])
report['test_build']=read(R/'private/tests/build.json')
for name in ['lib-dnsmasq_rs','bin-dnsmasq-rs']:
 binary=R/'private/tests'/name
 run('unit-'+name,['sudo','-n','sh',S/'tools/dnsmasq/run_isolated.sh','sh','-c','mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"','unit',binary,'--test-threads=1'],600)
 row=report['commands'][-1];row['elf_sha256']=sha(binary);row['test_summary']=[s for s in (R/'private'/('unit-'+name+'.log')).read_text().splitlines() if s.startswith('test result:')];save()
assert all(sha(S/n)==h for n,h in expected.items())
report['complete']=True;save();print(json.dumps({k:v for k,v in report.items() if k not in ['test_build','sdk']}))
