from pathlib import Path
import hashlib,json,os,re,subprocess,time
ROOT=Path('/home/ubuntu/dnsmasq-perf-20261015');OUT=ROOT/'loop/private/g-udp-stage-linux-gates-20261016';STATE=ROOT/'loop/private/g-udp-stage-inputs/state.json'
EXPECTED={'g-udp-stage':'a34e73107bc15f29b29b83499ceb0e0bc746d915'}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert os.sched_getaffinity(0)=={2}
assert os.getpriority(os.PRIO_PROCESS,0)>=10
OUT.mkdir(exist_ok=False)
report={'scope':'EXCLUDED accepted-G UDP-stage diagnostic: native musl build, exact synthetic fixture, normal bin and original ignored selections; CPU2 nice10 one build job; no timing, full44 qualification or acceptance claim.','runner_pid':os.getpid(),'affinity':sorted(os.sched_getaffinity(0)),'nice':os.getpriority(os.PRIO_PROCESS,0),'started_epoch':time.time(),'status':'running','candidates':[],'active':None}
def save():
 temp=OUT/'result.tmp';temp.write_text(json.dumps(report,indent=2)+'\n');temp.replace(OUT/'result.json')
def source_identity(name):
 state=json.loads(STATE.read_text());prepared=state['prepared'][name];assert prepared['commit']==EXPECTED[name] and prepared['verified_inputs']==180
 source=Path(prepared['source']);assert source==ROOT/'root/source-g-udp-stage';identity=source/'research-git-identity.json';assert sha(identity)==prepared['identity_sha256'];data=json.loads(identity.read_text());assert data['commit']==EXPECTED[name]
 for path,blob in data['git_blob_sha1'].items():
  raw=(source/path).read_bytes();assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob,path
 assert len(data['git_blob_sha1'])==180
 return source,prepared,sha(identity)
def command(argv,folder,name):
 started=time.time();report['active']={'name':name,'argv':argv,'started_epoch':started};save()
 with (folder/(name+'.stdout')).open('x') as out,(folder/(name+'.stderr')).open('x') as err:
  proc=subprocess.Popen(argv,stdout=out,stderr=err,env={**os.environ,'CARGO_BUILD_JOBS':'1','CARGO_INCREMENTAL':'0','RUSTUP_TOOLCHAIN':'1.98.1'})
  report['active']['pid']=proc.pid;save();rc=proc.wait()
 result={'name':name,'argv':argv,'returncode':rc,'elapsed_seconds':time.time()-started,'stdout_sha256':sha(folder/(name+'.stdout')),'stderr_sha256':sha(folder/(name+'.stderr'))}
 report['active']=None;save();return result
try:
 for name in EXPECTED:
  source,prepared,identity_sha=source_identity(name);folder=OUT/name;folder.mkdir();build=folder/'tests'
  candidate={'name':name,'source_commit':EXPECTED[name],'source':str(source),'prepared_identity_sha256':identity_sha,'source_inputs_verified_before':180,'commands':[],'status':'building'};report['candidates'].append(candidate);save()
  built=command(['sh',str(source/'tools/dnsmasq/oracle_build.sh'),str(source),str(build),'tests'],folder,'build');candidate['commands'].append(built);save();assert built['returncode']==0,(name,'build')
  receipt=json.loads((build/'build.json').read_text());assert receipt['source']==str(source) and receipt['kind']=='tests'
  assert len(receipt['artifacts'])==2
  for artifact in receipt['artifacts']:assert sha(build/artifact['path'])==artifact['sha256']
  candidate['build_receipt_sha256']=sha(build/'build.json');candidate['artifacts']=receipt['artifacts'];candidate['rustflags']=receipt['rustflags'];source_identity(name)
  isolate=['sudo','-n','sh',str(source/'tools/dnsmasq/run_isolated.sh'),'env','DNSMASQ_C_REFERENCE='+str(ROOT/'correctness/private/image-runner/dnsmasq-image-runner'),'python3','-c','import os,subprocess,sys; subprocess.run(["mount","--make-rprivate","/"],check=True); subprocess.run(["mount","-t","tmpfs","-o","mode=1777","tmpfs","/tmp"],check=True); os.execv(sys.argv[1],sys.argv[1:])']
  fixture='dns::udp_stage_diagnostic::tests::synthetic_replies_match_the_fixed_input_and_address_contract'
  gates=[('stage-fixture',build/'lib-dnsmasq_rs',['--exact',fixture]),('bin',build/'bin-dnsmasq-rs',[]),('bin-ignored-live',build/'bin-dnsmasq-rs',['--ignored'])]
  candidate['status']='testing';save()
  for gate,binary,args in gates:
   result=command([*isolate,str(binary),*args,'--test-threads=1'],folder,gate);text=(folder/(gate+'.stdout')).read_text();matches=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',text)
   assert len(matches)==1,(name,gate,'summary');status,passed,failed,ignored,measured,filtered=matches[0]
   result.update(summary=[line for line in text.splitlines() if line.startswith('test result:')],passed=int(passed),failed=int(failed),ignored=int(ignored),binary_sha256=sha(binary))
   result['passed_test_names']=re.findall(r'^test (.+) \.\.\. ok$',text,re.M)
   result['ignored_test_names']=re.findall(r'^test (.+) \.\.\. ignored(?:,.*)?$',text,re.M)
   assert len(result['passed_test_names'])==int(passed)
   if gate=='stage-fixture':assert int(passed)==1 and result['passed_test_names']==[fixture]
   candidate['commands'].append(result);save();assert result['returncode']==0 and status=='ok' and int(failed)==0,(name,gate)
  source_identity(name);candidate['source_inputs_verified_after']=180;candidate['status']='passed';save()
 report['status']='complete';report['finished_epoch']=time.time();report['active']=None;save()
except BaseException as error:
 report['status']='failed';report['error']=repr(error);report['finished_epoch']=time.time();save();raise
