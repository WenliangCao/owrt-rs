# Frozen exact-source original-SDK owner32; launch requires the coordinator reservation.
SDK_ELF_SHA256 = '70f9512eb5c62b239d3ad25d3d1a61bc9d67f898e559ef9df20214d36ecd23a5'
SDK_BUILD_RECEIPT_SHA256 = 'b168a2fcf084e02b97cfcbeb50057c7db2f7986dc1ad8c96f1d09246887a3a44'
SDK_MAP_SHA256 = '26c352cfe13e48816bf91aa05e907f1a105b27f6b953a0e892eaf2182440f9fc'
QUALIFICATION_RECEIPT_PATH = '/home/ubuntu/dnsmasq-perf-20261015/correctness/private/local-cache-linux-gates-20261016/verified-receipt.json'
QUALIFICATION_RECEIPT_SHA256 = '050fe64b167ad1c449449e074ff62df876ab132285317a18fa38813a25f43c53'
from pathlib import Path
import hashlib,json,os,subprocess,time
root=Path('/home/ubuntu/dnsmasq-perf-20261015/root');out=root/'private/local-miss-stack-owner-screen1';assert not out.exists();out.mkdir()
driver=root/'private/post-f-primary-inputs/loop_owner_profile.py';inputs=root/'private/inputs-fe'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
artifacts={'F':{'directory':root/'private/sdk-f-control-after-f','source':'3a3d8e3e848b93b0309353acfa0033d0b01a7cd0','sha256':'b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc'},'local-miss-stack':{'directory':root/'private/sdk-local-address-miss-stack','source':'c44cd116283b9e358f7cfedab13ee5eb3d9b920e','sha256':SDK_ELF_SHA256}}
for row in artifacts.values():
 b=json.loads((row['directory']/'build.json').read_text());assert b['source_commit']==row['source'] and b['source_unchanged'] and b['within_existing_budget'];assert sha(row['directory']/'dnsmasq-rs')==row['sha256'];assert sha(row['directory']/'link.map')==b['link_map']['sha256'];row['build_receipt_sha256']=sha(row['directory']/'build.json');row['link_map_sha256']=b['link_map']['sha256']
loadgen='f7c7d8e94a96e5c23f06aec1396539c439516fa4408a3657835cf78bdceb618e';assert sha(inputs/'m6a_loadgen')==loadgen
assert os.getpriority(os.PRIO_PROCESS,0)==0, 'parent must be nice0 so the driver gives daemon absolute nice10'
qualification=Path(QUALIFICATION_RECEIPT_PATH)
assert sha(qualification)==QUALIFICATION_RECEIPT_SHA256
assert sha(artifacts['local-miss-stack']['directory']/'build.json')==SDK_BUILD_RECEIPT_SHA256
q=json.loads(qualification.read_text())
assert q['status']=='complete' and q['all_builds_and_tests_exited'] and not q['owned_live_processes'] and q['active'] is None
assert q['total_test_passes']==2809 and q['source_files_rechecked_total']==537 and q['base_F_source_files_rechecked_after']==179
assert q['log_files_rechecked']==30 and q['artifact_files_rechecked']==6
matches=[c for c in q['candidates'] if c['source_commit']==artifacts['local-miss-stack']['source']]
assert len(matches)==1, 'exact source must identify one entry in the batch receipt'
c=matches[0]
assert c['name']=='local-address-miss-stack' and c['status']=='passed'
assert c['source']==str(root/'source-local-address-miss-stack')
assert c['source_inputs_verified_before']==c['source_inputs_verified_after']==c['source_inputs_rechecked_after']==179
assert c['all_log_hashes_rechecked'] and c['both_artifact_hashes_rechecked']
assert q['input_bindings']['local-address-miss-stack']['identity_sha256']==c['prepared_identity_sha256']
assert all(r['returncode']==0 and r.get('failed',0)==0 for r in c['commands'])
commands={r['name']:r for r in c['commands']}
assert len(commands)==len(c['commands'])==5 and set(commands)=={'build','lib','lib-ignored-live','bin','bin-ignored-live'}
assert {name:commands[name]['passed'] for name in ('lib','lib-ignored-live','bin','bin-ignored-live')}=={'lib':832,'lib-ignored-live':18,'bin':82,'bin-ignored-live':4}
assert sha(artifacts['local-miss-stack']['directory']/'link.map')==SDK_MAP_SHA256
plan=[]
for observer,pairs in [('stat',3),('none',5)]:
 for load,rate in [('low',200),('high',0)]:
  for pair in range(1,pairs+1):
   for side in (['F','local-miss-stack'] if pair%2 else ['local-miss-stack','F']):
    label=f'{observer}-{load}-r{pair}-{side}'
    argv=['sudo','-n','unshare','--net','sh','-c','ip link set lo up; exec "$@"','udp-screen','taskset','-c','0','python3',str(driver),'--build',str(artifacts[side]['directory']),'--tools',str(inputs),'--out',str(out/label),'--mode','udp','--profile','hit','--rate',str(rate),'--loadgen-sha256',loadgen]
    argv+=['--strace'] if observer=='strace' else ['--observer',observer]
    plan.append({'label':label,'observer':observer,'load':load,'rate':rate,'pair':pair,'side':side,'argv':argv})
assert len(plan)==32
identity={'scope':'Fixed independent local-miss-stack owner diagnostic, not full acceptance','declared_plan_commit':'03fba86b3d2705137edf72091ce1d6f5b50e2c4e','driver_sha256':sha(driver),'isolation':'network-only namespace; original profiling /proc/1 comparison retained','loadgen_sha256':loadgen,'artifacts':{s:{k:str(v) if isinstance(v,Path) else v for k,v in a.items()} for s,a in artifacts.items()},'windows':plan,'controller_sha256':sha(Path(__file__)), 'runtime_receipt_sha256':sha(qualification),'started_epoch':time.time()}
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
