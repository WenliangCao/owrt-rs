import hashlib,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/fork-a97edbc1';OUT=Path('/srv/owrt-archive/unified-work/private/dnsmasq-final/runtime');SOURCE=Path('/srv/owrt-archive/unified-work/source-e21245d2')
IMAGE=Path('/srv/owrt-archive/image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c');sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
use=Path('/srv/owrt-archive/unified-work/private/dnsmasq-final/input');built=json.loads((use/'build.json').read_text());assert built['status']=='ci-built-runtime-adapter-unqualified'
assert built['source_commit']=='e21245d2404f6542759f45d064214ac3696c355f' and len(built['source_files'])==212
verified={'source_commit':built['source_commit']};candidate=use/'dnsmasq-rs';candidate_sha=built['artifacts'][0]['sha256'];assert sha(candidate)==candidate_sha
k=ROOT/'private/baseline-k/dnsmasq-rs';ksha='f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08';assert sha(k)==ksha
for name,digest in json.loads((OUT/'tool-identity.json').read_text())['files'].items():assert sha(OUT/name)==digest
assert not (OUT/'batch-result.json').exists()
report={'status':'running','scope':'actual canonical CI ELF runtime qualification; K pressure references unchanged same-tool plain preflight control','candidate_source':verified['source_commit'],'candidate_elf':candidate_sha,'k_elf':ksha,'commands':[]}
def save():(OUT/'batch-result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,tool,binary,digest,commit,extra):
 folder=OUT/label;cmd=['sudo','-n','env','PYTHONPATH='+str(SOURCE/'tools/dnsmasq'),'unshare','--mount','--net','sh','-c','mount --make-rprivate / && ip link set lo up && exec "$@"','isolated','python3',str(OUT/tool),'--image-root',str(IMAGE),'--binary',str(binary),'--sha256',digest,'--source-commit',commit,'--output',str(folder)]+extra
 row={'label':label,'argv':cmd,'start':time.time()};report['commands'].append(row);save();process=None
 try:
  with (OUT/(label+'.stdout')).open('xb') as stdout,(OUT/(label+'.stderr')).open('xb') as stderr:
   process=subprocess.Popen(cmd,stdout=stdout,stderr=stderr,start_new_session=True);row['pid']=process.pid;save();row['returncode']=process.wait(timeout=300)
 finally:
  if process is not None and process.poll() is None:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
   row['forced_cleanup']=True
  row['end']=time.time()
  if (folder/'result.json').exists():row['result']=json.loads((folder/'result.json').read_text());row['result_sha256']=sha(folder/'result.json')
  save()
 print(json.dumps({'label':label,'returncode':row.get('returncode'),'passed':row.get('result',{}).get('passed')}),flush=True);return row
try:
 row=run('candidate-no-proc','selfexec_jail_boundary.py',candidate,candidate_sha,verified['source_commit'],['--case','both','--expect','success']);assert row['returncode']==0 and row['result']['passed'],'newfork no-proc failure; stop'
 previous=ROOT/'private/proc-free-8adcdeaf/final-runtime/k-no-proc-helper';prior=json.loads((previous/'helper/result.json').read_text());assert prior['passed'] and prior['helper_child']['exe_sha256']==ksha
 helper=json.loads((OUT/'candidate-no-proc/helper/result.json').read_text());assert helper['callback']==prior['callback'];assert (OUT/'candidate-no-proc/helper/rootfs/fixture/config').read_bytes()==(previous/'helper/rootfs/fixture/config').read_bytes()
 report['k_no_proc_helper_control_reused']={'path':str(previous/'result.json'),'sha256':sha(previous/'result.json'),'same_fixture_sha256':'510f0aa18d7d325a528b6f0b458a2006941b60d12f5978c63a2a1ea37cfba313','full_callback_equal':True}
 run('candidate-fd-pressure','selfexec_fd_headroom.py',candidate,candidate_sha,verified['source_commit'],['--proc-mode','visible'])
 report['k_pressure_control_reused']={'path':str(BASE/'plain-runtime/k-fd-pressure/result.json'),'sha256':sha(BASE/'plain-runtime/k-fd-pressure/result.json')}
 results={'k':json.loads((BASE/'plain-runtime/k-fd-pressure/result.json').read_text()),'candidate':json.loads((OUT/'candidate-fd-pressure/result.json').read_text())};by_role={role:{(x['mode'],x['fd_pressure']['headroom']):x for x in result['cases']} for role,result in results.items()}
 assert all(len(v)==8 for v in by_role.values())
 regressions=[];compact=[]
 for key,baseline in by_role['k'].items():
  current=by_role['candidate'][key]
  if baseline['passed'] and not current['passed']:regressions.append({'mode':key[0],'holes':key[1]})
  for role,case in [('k',baseline),('candidate',current)]:
   f=case['fd_pressure'];compact.append({'role':role,'mode':key[0],'holes':key[1],'passed':case['passed'],'error':case.get('error'),'applied_exactly':f.get('limit_change',{}).get('applied_exactly'),'restored':f.get('limit_change',{}).get('restore',{}).get('restored'),'pressure_operation':f.get('pressure',{}).get('operation_ok'),'pressure_health':f.get('pressure',{}).get('health_received'),'recovery_operation':f.get('recovery',{}).get('operation_ok'),'recovery_health':f.get('recovery',{}).get('health_received')})
 report.update(status='completed',regressions_against_k=regressions,resolver4_passed=by_role['candidate'][('resolver',4)]['passed'],pressure_rows=compact)
 (OUT/'pressure-compact.json').write_text(json.dumps({'regressions':regressions,'cases':compact},indent=2)+'\n');print(json.dumps({'regressions':regressions,'cases':compact}),flush=True)
except BaseException as error:report.update(status='failed-preserved',error=repr(error));raise
finally:save()
