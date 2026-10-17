import hashlib,json,os,signal,subprocess,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/proc-free-8adcdeaf';OUT=BASE/'final-runtime'
TRAIN=BASE/'pgo/train-stage';USE=TRAIN/'use';SOURCE=ROOT/'source-8adcdeaf'
IMAGE=Path('/srv/owrt-archive/image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
state=json.loads((TRAIN/'state.json').read_text());assert state['status']=='trained-use-built-unqualified'
build=json.loads((USE/'build.json').read_text());assert build['source_commit']=='8adcdeafddb7cfd8bc5d059e396d898c0447cb70' and len(build['source_files'])==193
candidate=USE/'dnsmasq-rs';candidate_sha=build['artifacts'][0]['sha256'];assert sha(candidate)==candidate_sha
k=ROOT/'private/baseline-k/dnsmasq-rs';ksha='f6710d37912bd414e01b32be97fd73b2ed4cf2ddf637eaa1254fa660603eba08';assert sha(k)==ksha
for name,digest in json.loads((OUT/'tool-identity.json').read_text())['files'].items():assert sha(OUT/name)==digest
assert not (OUT/'batch-result.json').exists()
report={'status':'running','scope':'actual new PGO runtime correctness; no performance inference','candidate_source':build['source_commit'],'candidate_elf':candidate_sha,'k_elf':ksha,'commands':[]}
def save():(OUT/'batch-result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,tool,binary,digest,commit,extra,timeout=300):
 folder=OUT/label
 cmd=['sudo','-n','env','PYTHONPATH='+str(SOURCE/'tools/dnsmasq'),'unshare','--mount','--net','sh','-c','mount --make-rprivate / && ip link set lo up && exec "$@"','isolated','python3',str(OUT/tool),'--image-root',str(IMAGE),'--binary',str(binary),'--sha256',digest,'--source-commit',commit,'--output',str(folder)]+extra
 row={'label':label,'argv':cmd,'start':time.time()};report['commands'].append(row);save();process=None
 try:
  with (OUT/(label+'.stdout')).open('xb') as stdout,(OUT/(label+'.stderr')).open('xb') as stderr:
   process=subprocess.Popen(cmd,stdout=stdout,stderr=stderr,start_new_session=True);row['pid']=process.pid;save();row['returncode']=process.wait(timeout=timeout)
 finally:
  if process is not None and process.poll() is None:
   os.killpg(process.pid,signal.SIGTERM)
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
   row['forced_cleanup']=True
  row['end']=time.time()
  if (folder/'result.json').exists():row['result']=json.loads((folder/'result.json').read_text());row['result_sha256']=sha(folder/'result.json')
  save()
 print(json.dumps({'label':label,'returncode':row.get('returncode'),'passed':row.get('result',{}).get('passed')}),flush=True)
 return row
try:
 for label,binary,digest,commit,extra in [('k-no-proc-helper',k,ksha,'4ce24c627615ae5ff42d3dcdbccb66d57b218b5a',['--case','helper','--expect','success']),('k-no-proc-resolver-negative',k,ksha,'4ce24c627615ae5ff42d3dcdbccb66d57b218b5a',['--case','resolver','--expect','resolver-proc-failure']),('candidate-no-proc',candidate,candidate_sha,build['source_commit'],['--case','both','--expect','success'])]:
  row=run(label,'selfexec_jail_boundary.py',binary,digest,commit,extra)
  assert row['returncode']==0 and row['result']['passed'],label+' failed; stop new dependent gates'
 khelper=json.loads((OUT/'k-no-proc-helper/helper/result.json').read_text());ch=json.loads((OUT/'candidate-no-proc/helper/result.json').read_text())
 assert khelper['callback']==ch['callback']
 assert (OUT/'k-no-proc-helper/helper/rootfs/fixture/config').read_bytes()==(OUT/'candidate-no-proc/helper/rootfs/fixture/config').read_bytes()
 report['same_helper_config_and_full_callback_work']=True;save()
 # Each independently frozen six-case batch runs even when the other fails.
 for role,binary,digest,commit in [('k',k,ksha,'4ce24c627615ae5ff42d3dcdbccb66d57b218b5a'),('candidate',candidate,candidate_sha,build['source_commit'])]:
  run(role+'-fd-pressure','selfexec_fd_headroom.py',binary,digest,commit,['--proc-mode','visible'])
 report['status']='completed';report['passed']=all(row.get('returncode')==0 and row.get('result',{}).get('passed') for row in report['commands'])
except BaseException as error:report.update(status='failed-preserved',error=repr(error));raise
finally:save()
