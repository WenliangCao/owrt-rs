import hashlib,json,os,shutil,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');OUT=ROOT/'private/fork-a97edbc1/startup-tools-final';runtime=Path('/tmp/owrt-archive-v022-slot-04');assert not runtime.exists()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(OUT/'device_selfexec_lifecycle.c')=='ea68d6a8f94db07dacd0e5651155ed503881684185b3d2ab783dd473cd6a9b43'
built=json.loads((OUT/'build-result.json').read_text());assert built['returncode']==0;assert sha(OUT/'device_selfexec_lifecycle')==built['elf_sha256']
assert os.geteuid()==0
use=ROOT/'private/fork-a97edbc1/pgo/train-stage/use';artifact=json.loads((use/'build.json').read_text())['artifacts'][0]
assert json.loads((use.parent/'state.json').read_text())['status']=='trained-use-built-unqualified'
runtime.mkdir();(runtime/'runs').mkdir();(runtime/'inputs').mkdir()
for role,binary,digest in [('k',ROOT/'private/baseline-k/dnsmasq-rs','f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08'),('candidate',use/'dnsmasq-rs',artifact['sha256'])]:
 assert sha(binary)==digest
 directory=runtime/'inputs'/role;directory.mkdir();target=directory/'dnsmasq';shutil.copyfile(binary,target);target.chmod(0o755);os.chown(target,0,0)
 if 'security.capability' in os.listxattr(target):os.removexattr(target,'security.capability')
 assert sha(target)==digest;os.link(target,runtime/('artifact-'+role))
for name in ('device_selfexec_lifecycle','safe_v022_startup_case.sh','safe_v022_startup_group.sh'):
 shutil.copy2(OUT/name,runtime/name);(runtime/name).chmod(0o755)
for name in ('m6a_upstream','nice10','device_perf_netns'):
 shutil.copy2(ROOT/'private/final-b8617f57/pgo/workload'/name,runtime/name);(runtime/name).chmod(0o755)
sys.path.insert(0,str(OUT));import safe_v022_startup_run as validate
report={'status':'running','scope':'forty inner-case Oracle tool-preview starts only; no router or candidate promotion; helper no-proc and resolver proc-visible for K compatibility','runtime_root':str(runtime),'source_commit':'a97edbc1382fc92b83110ed0822284aafeee7461','observer_sha256':sha(runtime/'device_selfexec_lifecycle'),'cases':[]}
def save():(OUT/'preview-result.json').write_text(json.dumps(report,indent=2)+'\n')
save()
try:
 for mode,role in validate.ORDER:
  label='startup-'+mode+'-'+role;command=[str(runtime/'nice10'),str(runtime/'device_perf_netns'),'/bin/sh',str(runtime/'safe_v022_startup_case.sh'),mode,role,label]
  record={'mode':mode,'role':role,'argv':command,'start':time.time()};report['cases'].append(record);save()
  process=None
  try:
   with (OUT/(label+'.controller.log')).open('wb') as log:
    process=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
    record['returncode']=process.wait(timeout=60)
  finally:
   if process is not None and process.poll() is None:
    os.killpg(process.pid,signal.SIGTERM)
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
   record['end']=time.time();save()
  assert record['returncode']==0,label+' real tool/behavior failure; stop after first, no retry'
  record['validation']=validate.validate(runtime/'runs'/label,mode,role,sha(runtime/('artifact-'+role)))
  save();print(json.dumps({'case':label,'returncode':record['returncode'],'starts':len(record['validation']['starts']),'callback_counts':[r.get('callback_count') for r in record['validation']['starts']]}),flush=True)
 helper=[r for r in report['cases'] if r['mode']=='helper'];assert len(helper)==2
 counts=[[r['callback_count'] for r in x['validation']['starts']] for x in helper];assert counts[0]==counts[1]
 report.update(status='passed-tool-preview',starts=40,helper_callback_counts=counts[0],helper_callback_workload_equal=True)
except BaseException as error:report.update(status='failed-tool-preview-preserved',error=repr(error));raise
finally:save()
