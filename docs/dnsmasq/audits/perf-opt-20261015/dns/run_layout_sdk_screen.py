from pathlib import Path
import hashlib,json,os,subprocess,time
import sys
root=Path('/home/ubuntu/dnsmasq-perf-20261015/root')
candidate=sys.argv[1];assert candidate in ('reply-layout','address-dispatch')
out=root/('private/layout-sdk-'+candidate+'-screen1');assert not out.exists();out.mkdir()
driver=root/'private/post-f-primary-inputs/loop_owner_profile.py';inputs=root/'private/inputs-fe'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
artifacts={'F':{'directory':root/'private/sdk-f-control-after-f','source':'3a3d8e3e848b93b0309353acfa0033d0b01a7cd0','sha256':'b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc'},candidate:{'directory':root/('private/sdk-'+candidate),'source':{'reply-layout':'2bd0d6b2c15c4616e3c4c2a0e3203eca69adecbf','address-dispatch':'26aefa7952e001881757d41ae32456c5b2a12107'}[candidate],'sha256':{'reply-layout':'afc32ddc00b34c5a9b45553a6fd52e724e098cffd5329f89d013fd76e099fdee','address-dispatch':'77dca9febedc4211f51da547027729faea4efd7aac43653875a8505ad5e1dc40'}[candidate]}}
for row in artifacts.values():
 b=json.loads((row['directory']/'build.json').read_text());assert b['source_commit']==row['source'] and b['source_unchanged'] and b['within_existing_budget'];assert sha(row['directory']/'dnsmasq-rs')==row['sha256'];assert sha(row['directory']/'link.map')==b['link_map']['sha256'];row['build_receipt_sha256']=sha(row['directory']/'build.json');row['link_map_sha256']=b['link_map']['sha256']
loadgen='f7c7d8e94a96e5c23f06aec1396539c439516fa4408a3657835cf78bdceb618e';assert sha(inputs/'m6a_loadgen')==loadgen
assert os.getpriority(os.PRIO_PROCESS,0)==0, 'parent must be nice0 so the driver gives daemon absolute nice10'
plan=[]
for observer,pairs in [('stat',3),('none',5)]:
 for load,rate in [('low',200)]:
  for pair in range(1,pairs+1):
   for side in (['F',candidate] if pair%2 else [candidate,'F']):
    label=f'{observer}-{load}-r{pair}-{side}'
    argv=['sudo','-n','unshare','--net','sh','-c','ip link set lo up; exec "$@"','udp-screen','taskset','-c','0','python3',str(driver),'--build',str(artifacts[side]['directory']),'--tools',str(inputs),'--out',str(out/label),'--mode','udp','--profile','hit','--rate',str(rate),'--loadgen-sha256',loadgen]
    argv+=['--strace'] if observer=='strace' else ['--observer',observer]
    plan.append({'label':label,'observer':observer,'load':load,'rate':rate,'pair':pair,'side':side,'argv':argv})
assert len(plan)==16
identity={'scope':'Fixed independent SDK local/cache layout diagnostic, not full acceptance','declared_plan_sha256':sha(Path(__file__).with_name('plan.json')),'driver_sha256':sha(driver),'isolation':'network-only namespace; original profiling /proc/1 comparison retained','loadgen_sha256':loadgen,'artifacts':{s:{k:str(v) if isinstance(v,Path) else v for k,v in a.items()} for s,a in artifacts.items()},'windows':plan,'controller_sha256':sha(Path(__file__)),'started_epoch':time.time()}
(out/'identity.json').write_text(json.dumps(identity,indent=2)+'\n');progress=[]
for window in plan:
 row={k:v for k,v in window.items() if k!='argv'};row['started_epoch']=time.time()
 with (out/(window['label']+'.stdout')).open('wb') as stdout,(out/(window['label']+'.stderr')).open('wb') as stderr:
  p=subprocess.Popen(window['argv'],stdout=stdout,stderr=stderr,start_new_session=True);row['pid']=p.pid;(out/'active.json').write_text(json.dumps(row)+'\n')
  try:status=p.wait(timeout=100)
  except subprocess.TimeoutExpired:
   import signal
   os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=10);row['timeout']=True;status=p.returncode
 row['returncode']=status;row['finished_epoch']=time.time();progress.append(row);(out/'progress.json').write_text(json.dumps(progress,indent=2)+'\n');(out/'active.json').unlink()
 if status!=0:raise RuntimeError('retained failed diagnostic window: '+window['label'])
 complete=json.loads((out/window['label']/'complete.json').read_text());assert complete['valid_count_profile'] and complete['tree_tail_complete'] and complete['rate']==window['rate']
 print(json.dumps(row),flush=True)
for row in artifacts.values():assert sha(row['directory']/'dnsmasq-rs')==row['sha256']
assert sha(driver)==identity['driver_sha256']
(out/'complete.json').write_text(json.dumps({'complete':True,'windows':len(progress),'ended_epoch':time.time()})+'\n')
