from pathlib import Path
import hashlib,json,tarfile,re
base=Path('.')
archive=base/'private/f10-product-20261014/core-238e.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='cb75c214e1764a505fefdad97fbd0953a4e0ac9c75f79ad305b7e2d887e024d2'
elf='2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb'
report={'source_commit':'238e7ca4374b1889696f91816c1c239d7fe32baa','elf_sha256':elf,'oracle_root':'/dev/shm/full-f10-product-20261014/private','cases':{},'units':[],'raw_archive':{'path':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size},'scope':'Targeted same-ELF TCP and hosts reload resource gates; no router, APK or F5 package qualification.'}
with tarfile.open(archive) as t:
 def raw(n):return t.extractfile(n).read()
 def data(n):return json.loads(raw(n))
 def sha(n):return hashlib.sha256(raw(n)).hexdigest()
 report['suite']=data('core-238e-suite.json')
 for row in report['suite']:
  name=row['case'];p=name+'/result.json';r=data(p)
  assert row['exit']==0 and r['rust_sha256']==elf
  value={'exit':row['exit'],'result_sha256':sha(p),'command':data(name+'.command.json')}
  if 'cases' in r:
   assert all(c['passed'] for c in r['cases'])
   value['runs']=[{k:v for k,v in c.items() if not isinstance(v,(list,dict))} for c in r['cases']]
  elif name.endswith('tcp-hup'):
   runs=[]
   for c in r['runs']:
    events={k:int(v)for k,v in(line.split()for line in c['final_cgroup']['memory.events'].splitlines())}
    assert len(c['connections'])==20 and c['udp_after'] and all(v==0 for v in events.values())
    runs.append({'side':c['side'],'connections':len(c['connections']),'old_hup_answers':len(c['hup']['old_answers']),'new_hup_answers':len(c['hup']['new_answers']),'peak_bytes':int(c['final_cgroup']['memory.peak']),'events':events,'exit':c['exit'],'cgroup_removed':c['cgroup_removed']})
   value['runs']=runs
  else:
   assert r['matched'] and all(c['alive'] for c in r['runs'])
   value.update(matched=r['matched'],observations_per_side=[len(c['observations'])for c in r['runs']])
  report['cases'][name]=value
 for n in ['unit-lib-238e.log','unit-bin-238e-serial.log','allocator-238e.log']:
  s=raw(n);m=re.search(rb'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored',s);assert m
  report['units'].append({'log':n,'sha256':sha(n),'passed':int(m[1]),'failed':int(m[2]),'ignored':int(m[3])})
 report['serial_command']=data('unit-bin-238e-serial.command.json')
 report['test_build']=data('tests-238e/build.json')
 report['retained_parallel_failure']={'log':'unit-bin-238e.log','sha256':sha('unit-bin-238e.log'),'passed':80,'failed':1,'ignored':3,'classification':'One owner test failed under parallel execution; same binary passed the isolated single test and the complete serial suite. Shared signal/owner test interference is suspected, not proven.'}
 (base/'docs/dnsmasq/audits/full-20261014/f10-contract/core-final238e/result.json').write_text(json.dumps(report,indent=2)+'\n')
 (base/'docs/dnsmasq/audits/full-20261014/f10-contract/core-final238e/run_core.py').write_bytes(raw('run_core_238e.py'))
artifact=base/'private/f10-product-20261014/artifact-238e.tar.gz'
with tarfile.open(artifact) as t:
 identity=json.load(t.extractfile('identity-238e-after.json'))
 for p,h in identity['files'].items():assert hashlib.sha256(t.extractfile('source-238e/'+p).read()).hexdigest()==h
 assert hashlib.sha256(t.extractfile('release-238e/dnsmasq-rs').read()).hexdigest()==elf
 identity['local_archive']={'path':str(artifact),'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'bytes':artifact.stat().st_size}
 identity['build']=json.load(t.extractfile('release-238e/build.json'))
 (base/'docs/dnsmasq/audits/full-20261014/f10-contract/core-final238e/identity.json').write_text(json.dumps(identity,indent=2)+'\n')
print('verified core results, tests and',len(identity['files']),'frozen inputs')
