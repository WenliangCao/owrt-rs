#!/usr/bin/env python3
"""One authorized sequential correctness queue, no performance interpretation."""
import hashlib, importlib.util, json, os, shutil, subprocess, sys, time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/unified-work')
SOURCE=ROOT/'source-e21245d2'
PRIVATE=ROOT/'private'
TOOLS=PRIVATE/'core-runtime-tools'
OUT=PRIVATE/'core-functional-supplement-e21245d2'
STOCK=Path('/srv/owrt-archive/image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c')
COMMIT='e21245d2404f6542759f45d064214ac3696c355f'
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,v): p.write_text(json.dumps(v,indent=2)+'\n')
def require(value,message):
 if not value: raise RuntimeError(message)
out_tools=OUT/'tools'
OUT.mkdir(exist_ok=False);out_tools.mkdir()
qualification=TOOLS/'qualification.json'
require(sha(qualification)=='73da8600a8afaf010500360497ba90913aa808b9875608ca5fd22fabb90d4125','tool qualification differs')
q=json.loads(qualification.read_text());require(q['source_commit']==COMMIT,'tool source differs')
target_check=PRIVATE/'core-ci39047139959/target/core-target-check.json'
ci=json.loads(target_check.read_text());require(ci['status']=='passed' and ci['source_commit']==COMMIT,'candidate CI differs')
vmanifest=PRIVATE/'runtime-inputs/v021-manifest.json'
v=json.loads(vmanifest.read_text())
before=PRIVATE/'r131-control-reconstruction/before-rs'
before_build=PRIVATE/'r131-control-reconstruction/build.json'
require(sha(before)=='a11476a8ad815069d77aa9c6f84d48f2fd8e85064a9f97b431d48a06b4418f02','R131 reconstruction differs')
br=json.loads(before_build.read_text());require(br['source_commit']=='4e45d2ecc41d8548916c2f92f30c7ac4d2bb65dc','R131 source differs')
paths={
 'ns':TOOLS/'bins/ns-exec','benchmark':TOOLS/'bins/owrt-benchmark','guard':TOOLS/'bins/r95-guard',
 'wireprobe':TOOLS/'examples/wireprobe','stress':TOOLS/'r131-event-stress-corrected/r131-event-stress-libubus',
 'before':before}
for key,p in paths.items():
 if key!='before': require(sha(p)==q['artifacts'][str(p.relative_to(TOOLS))]['sha256'],'tool differs '+key)
subjects={}
for role,folder in [('v021',PRIVATE/'runtime-inputs/v021-baseline'),('candidate',PRIVATE/'core-ci39047139959/target/core-candidates')]:
 subjects[role]={}
 for component,binary in [('ubusd','ubusd-rs'),('reload-config','reload_config_rs')]:
  p=folder/binary;expected=v['components'][component]['rust_sha256'] if role=='v021' else ci['binary_sha256'][binary]
  require(sha(p)==expected,role+' product identity differs')
  subjects[role][component]={'path':str(p),'sha256':expected,'bytes':p.stat().st_size}
scripts={
 'isolated.sh':('tools/benchmark/isolated.sh','1b91816976dcbfedad6323c9d482eb2f8398a0ae2e34f22be875824d2bdcfff1'),
 'r98_ubusd_events.sh':('tools/r98_ubusd_events.sh','1a8d48e431cb3b96f0326dc703ffb6f80c53af8acb3dfa606c0aacbdf5dcf93d'),
 'ubusd_fd_boundary.sh':('tools/r134/ubusd_fd_boundary.sh','fa2fab0a398b0ff6eec6a50e9ea01b6309f96d7a8cd2e61f8fbbc7b327e65c57'),
 'r131_ubusd_event_stress.sh':('tools/r131_ubusd_event_stress.sh','8a11da1895f061cf4b7a37eb5d5c7bc2308697d69d65f6a1ff94b378fe3a3dc5'),
 'r95_reload_config_probe.sh':('tools/r95_reload_config_probe.sh','999d1c576f786cba00b4dfb56e03e10b9008e3fc9d4f4d847135097dd4c37172')}
for name,(rel,digest) in scripts.items():
 require(sha(SOURCE/rel)==digest,'script differs '+name)
 shutil.copy2(SOURCE/rel,out_tools/name)
spec=importlib.util.spec_from_file_location('original_stress',SOURCE/'tools/r134/ubusd_stress_oracle.py')
original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
require(sha(STOCK/'sbin/ubusd')==original.STOCK_SHA,'stock C differs')
for name,digest in original.LIBRARIES.items(): require(sha(STOCK/name.lstrip('/'))==digest,'stock library differs '+name)
require({0,1}<=os.sched_getaffinity(0),'needs original CPUs0/1')
jobs=[('fd','v021'),('events','v021'),('fd','candidate'),('events','candidate'),
      ('stress','c'),('stress','v021'),('stress','candidate'),('reload','v021'),('reload','candidate')]
inputs={str(p):{'sha256':sha(p),'bytes':p.stat().st_size} for p in [qualification,target_check,vmanifest,before_build,*paths.values()]}
plan={'source_commit':COMMIT,'scope':'original functional supplement only; no router, deployment or performance comparison',
 'jobs':jobs,'subjects':subjects,'inputs':inputs,'scripts':scripts,'control':br,
 'original_stress_validator_sha256':sha(SOURCE/'tools/r134/ubusd_stress_oracle.py')}
save(OUT/'plan.json',plan)
shutil.copy2(before_build,OUT/'before-build.json')
shutil.copy2(qualification,OUT/'tool-qualification.json')
rows=[]
for index,(kind,role) in enumerate(jobs,1):
 name=f'{index:02d}-{kind}-{role}';case=OUT/name;case.mkdir()
 bundle=case/'bundle';bundle.mkdir();raw=case/'raw';raw.mkdir();work=case/'work';work.mkdir()
 component='reload-config' if kind=='reload' else 'ubusd'
 mapping={'ns-exec':paths['ns'],'owrt-benchmark':paths['wireprobe'] if kind in ('fd','events') else paths['benchmark']}
 if role!='c': mapping['reload_config_rs' if kind=='reload' else 'ubusd-rs']=Path(subjects[role][component]['path'])
 if kind in ('fd','events'): mapping['before-rs']=before
 if kind=='stress': mapping['event-benchmark']=paths['stress']
 if kind=='reload': mapping.update({'event-benchmark':paths['benchmark'],'guard':paths['guard']})
 for alias,p in mapping.items():
  shutil.copy2(p,bundle/alias);require(sha(bundle/alias)==sha(p),'bundle copy differs');(bundle/alias).chmod(0o555)
 script=out_tools/({'fd':'ubusd_fd_boundary.sh','events':'r98_ubusd_events.sh','stress':'r131_ubusd_event_stress.sh','reload':'r95_reload_config_probe.sh'}[kind])
 command=['sudo','-n',str(paths['guard']),'120',str(paths['ns']),'/bin/sh',str(script),'--namespace',
  str(STOCK),str(bundle),component,'c' if role=='c' else 'rs',str(raw),'2000' if kind=='stress' else '1',str(work),str(script)]
 row={'name':name,'kind':kind,'role':role,'command':command,'start':time.time(),
      'bundle_sha256':{alias:sha(bundle/alias) for alias in mapping},'passed':False}
 save(case/'invocation.json',row)
 print(json.dumps({'event':'start','name':name}),flush=True)
 try:
  with (case/'run.log').open('xb') as log:
   result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=140)
  row['exit']=result.returncode
  require(result.returncode==0 and (raw/'COMPLETE').is_file(),'original functional gate failed')
  if kind=='fd':
   require((raw/'c-fd_boundary.txt').read_bytes()==(raw/'before-fd_boundary.txt').read_bytes(),'R131 C-exact FD control failed')
   if index==1:
    save(OUT/'before-control-qualified.json',{'source_commit':br['source_commit'],'elf_sha256':sha(before),
      'historical_byte_match':False,'original_C_exact_six_FD_transcript':True,
      'c_transcript_sha256':sha(raw/'c-fd_boundary.txt'),'before_build_sha256':sha(before_build)})
  elif kind=='stress':
   checks=[]
   for lane in ('grouped','interleaved','monitor','slow'):
    data=(raw/lane/'helper.jsonl').read_text();pid=json.loads(data.splitlines()[-1])['subject_pid']
    checks.append(original.validate(data,lane,192 if lane=='slow' else 2000,pid))
   row['checks']=checks
  elif kind=='reload':
   lines=(raw/'results.txt').read_text().splitlines()
   require(len(lines)==10,'mandatory reload cases incomplete');row['checks']=lines
  for alias in mapping:require(sha(bundle/alias)==row['bundle_sha256'][alias],'bundle changed after run')
  row['passed']=True
 except BaseException as error:
  row['error']=repr(error)
 finally:
  row['end']=time.time();row['log_sha256']=sha(case/'run.log')
  row['raw_files']={str(p.relative_to(raw)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(raw.rglob('*')) if p.is_file()}
  save(case/'result.json',row);rows.append(row)
  save(OUT/'result.json',{'source_commit':COMMIT,'scope':plan['scope'],'expected_jobs':9,'completed_jobs':len(rows),
    'passed':len(rows)==9 and all(x['passed'] for x in rows),'rows':rows})
  print(json.dumps({'event':'finished','name':name,'passed':row['passed'],'exit':row.get('exit'),'error':row.get('error')}),flush=True)
 if not row['passed']:sys.exit(1)
print(json.dumps({'event':'complete','jobs':len(rows),'passed':True}),flush=True)
