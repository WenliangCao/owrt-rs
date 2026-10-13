#!/usr/bin/env python3
"""Fresh fixed-revision release/unit/SDK evidence, never modifies product source."""
import hashlib, importlib.util, json, os, subprocess, sys, time
from pathlib import Path
R=Path('/home/ubuntu/dnsmasq-audit-fix3-20261013')
SDK=R/'private/sdk-isolated/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64'
COMMITS={'main':('be531cee49e366bb5044443d473944dbea45b87e','1791711247'),'fix':('e3a37f55b2939ee2a0c229b0ac96a2a9c407b8aa','1791826938')}
REPORT=R/'private/build-sequence.json'
report={'commands':[],'complete':False,'source_commits':COMMITS}
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(): REPORT.write_text(json.dumps(report,indent=2)+'\n')
def run(name,argv,timeout=1200):
 row={'name':name,'argv':list(map(str,argv)),'started':time.time()};report['commands'].append(row);save()
 log=R/'private'/f'{name}.driver.log'
 with log.open('wb') as f: p=subprocess.run(row['argv'],stdout=f,stderr=f,timeout=timeout)
 row.update(exit=p.returncode,seconds=time.time()-row['started'],log_sha256=sha(log));save();return p.returncode
for side in COMMITS:
 source=R/f'source-{side}'
 # Release builds are a separately started sequential job; these are immutable outputs.
 while not (R/f'private/release-{side}/build.json').exists(): time.sleep(2)
 assert run('tests-build-'+side,['sh',source/'tools/dnsmasq/oracle_build.sh',source,R/f'private/tests-{side}','tests']) == 0
 for name in ['lib-dnsmasq_rs','bin-dnsmasq-rs']:
  binary=R/f'private/tests-{side}'/name
  assert run('unit-'+side+'-'+name,['sudo','-n','sh',source/'tools/dnsmasq/run_isolated.sh','sh','-c','mount -t tmpfs -o mode=1777 tmpfs /tmp; exec "$@"','unit',binary,'--test-threads=1'],600)==0
  row=report['commands'][-1];row['elf_sha256']=sha(binary);row['test_summary']=[s for s in (R/'private'/f'unit-{side}-{name}.driver.log').read_text().splitlines() if s.startswith('test result:')];save()
for side,(commit,epoch) in COMMITS.items():
 source=R/f'source-{side}'
 spec=importlib.util.spec_from_file_location('p_'+side,source/'tools/dnsmasq/build_package.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
 digest=hashlib.sha256(json.dumps(p.inputs(source),sort_keys=True,separators=(',',':')).encode()).hexdigest()
 common=['python3',R/'sdk_source_build.py','--source',source,'--sdk',SDK,'--workspace',R/f'private/sdk-workspace-{side}','--source-commit',commit,'--source-date-epoch',epoch,'--expected-source-digest',digest]
 run('sdk-acquire-'+side,common+['--out',R/f'private/sdk-acquire-{side}','--acquire'])
 manifest=json.loads((R/f'private/sdk-acquire-{side}/manifest.json').read_text());assert manifest.get('source_build_passed'),manifest
 if side=='fix':
  run('sdk-verify-'+side,common+['--out',R/f'private/sdk-verify-{side}','--expected-elf-sha256',manifest['elf']['sha256']])
  verify=json.loads((R/f'private/sdk-verify-{side}/manifest.json').read_text());assert verify.get('artifact_identity_verified'),verify
report['complete']=True;save()
