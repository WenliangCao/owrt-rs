from pathlib import Path
import hashlib,json,os,subprocess,time,traceback
inputs=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(inputs/'plan.json')=='f413ce0507f4047d0d701de59ab2118418fac024c4858d317833850221444c86'
assert sha(inputs/'analysis-binding.json')=='434eeba65071f4d2d30e30921adffcbe64ada86c73e882bc328f3492eea5671c'
plan=json.loads((inputs/'plan.json').read_text());binding=json.loads((inputs/'analysis-binding.json').read_text());preflight=json.loads((inputs/'preflight.json').read_text())
assert preflight['status']=='PASS_READY_FOR_FROZEN16'
for name,digest in preflight['bindings'].items():assert sha(name)==digest,name
for row in preflight['versions'].values():assert sha(row['path'])==row['sha256']
root=Path(plan['paths']['raw_root']);root.mkdir()
save=lambda name,obj:(root/name).write_text(json.dumps(obj,indent=2)+'\n')
save('launch.json',{'pid':os.getpid(),'epoch':time.time(),'plan_sha256':sha(inputs/'plan.json'),'analysis_binding_sha256':sha(inputs/'analysis-binding.json'),'preflight_sha256':sha(inputs/'preflight.json'),'launcher_sha256':sha(__file__)})
progress=[]
try:
 for phase,rows in [('capture',plan['windows']),('analysis',binding['analysis_commands'])]:
  for row in rows:
   label=row['id'];argv=row['argv'];started=time.time()
   save('active.json',{'phase':phase,'id':label,'argv':argv,'started':started})
   with (root/(label+'.'+phase+'.stdout')).open('xb') as stdout,(root/(label+'.'+phase+'.stderr')).open('xb') as stderr:
    result=subprocess.run(argv,stdout=stdout,stderr=stderr)
   progress.append({'phase':phase,'id':label,'argv':argv,'started':started,'ended':time.time(),'returncode':result.returncode});save('progress.json',progress)
   assert result.returncode==0,(phase,label,result.returncode)
 save('complete.json',{'capture_windows':16,'analysis_windows':16,'complete':True,'epoch':time.time()})
except BaseException:
 save('failure.json',{'epoch':time.time(),'error':traceback.format_exc(),'completed_steps':len(progress)})
 raise
