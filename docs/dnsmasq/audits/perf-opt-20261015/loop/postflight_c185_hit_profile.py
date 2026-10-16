from pathlib import Path
import fcntl,hashlib,json,os,subprocess,time
inputs=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
j=lambda p:json.loads(Path(p).read_text())
plan=j(inputs/'plan.json');root=Path(plan['paths']['raw_root']);launch=j(root/'launch.json');pre=j(inputs/'preflight.json');binding=j(inputs/'analysis-binding.json')
assert not Path('/proc/'+str(launch['pid'])).exists(),'controller still present'
assert not (root/'failure.json').exists();complete=j(root/'complete.json');assert complete['complete'] and complete['capture_windows']==complete['analysis_windows']==16
progress=j(root/'progress.json');expected=[('capture',w['id'],w['argv']) for w in plan['windows']]+[('analysis',w['id'],w['argv']) for w in binding['analysis_commands']]
assert [(r['phase'],r['id'],r['argv']) for r in progress]==expected
assert all(r['returncode']==0 and r['ended']>=r['started'] for r in progress)
assert all(a['ended']<=b['started'] for a,b in zip(progress,progress[1:]))
assert (inputs/'controller.stderr').stat().st_size==0
for name,digest in pre['bindings'].items():assert sha(name)==digest,name
for row in pre['versions'].values():assert sha(row['path'])==row['sha256']
build=j(Path(plan['paths']['candidate_sdk'])/'build.json')
for name,digest in build['source_files'].items():assert sha(Path(build['source'])/name)==digest,name
raw_files={};attrs={};windows=[]
for w in plan['windows']:
 p=Path(w['output']);a=j(p/'analysis.json');scope=j(p/'profile-scope.json');identity=j(p/'process-identity.json');tail=j(p/'tree-tail.json');controls=j(p/'perf-controls.json');c=controls['controls']
 assert scope['observer']==w['observer'] and scope['mode']==w['mode'] and scope['profile']=='hit';assert a['completed_operations']==5000
 assert identity['pid']==tail['root_pid'] and tail['complete'] and not tail['remaining_children'];assert not Path('/proc/'+str(identity['pid'])).exists()
 assert [x['command'] for x in c]==['enable','disable'];assert all(x['sent_ns']<=x['acknowledged_ns'] and bytes.fromhex(x['ack_hex']).rstrip(b'\n\0')==b'ack' for x in c)
 assert c[0]['acknowledged_ns']<=controls['load_start_ns']<=controls['load_end_ns']<=tail['drain_started_ns']<=tail['drain_ended_ns']<=c[1]['sent_ns']
 assert tail['drain_ended_ns']-tail['drain_started_ns']>=1000000000
 assert a['elf_sha256']==(plan['artifacts']['C_elf_sha256'] if w['side']=='C' else plan['artifacts']['candidate']['dnsmasq-rs'])
 if w['observer']=='sample':
  assert scope['sample_event']=='cycles:u' and scope['sample_period']==10000
  assert a['totals']['lost_samples']==0 and a['process_tree']['all_samples_bound_to_fork_tree']
  text=subprocess.check_output(['perf','evlist','-v','-i',str(p/'perf.data')],text=True);event=next(line for line in text.splitlines() if line.startswith('cycles:u:'))
  assert '10000' in event and all(s in event for s in ('inherit: 1','exclude_kernel: 1','exclude_hv: 1'))
  assert 'PERF_COUNT_HW_CPU_CYCLES' in event
  dst=p/'event-attributes.txt';assert not dst.exists();dst.write_text(text);attrs[w['id']]=text
 else:
  assert a['inherit'] and a['one_group'];assert set(a['events'])=={'instructions:u','instructions:k','cycles:u','cycles:k'}
 files={str(f.relative_to(p)):sha(f) for f in p.rglob('*') if f.is_file()};raw_files[w['id']]=files
 windows.append({'id':w['id'],'observer':w['observer'],'analysis_sha256':sha(p/'analysis.json'),'raw_files':len(files),'descendants':len(a.get('process_tree',{}).get('exited_children',[])),'all_unscaled':a.get('all_unscaled'),'controls_valid':True,'fixed_drain_ns':tail['drain_ended_ns']-tail['drain_started_ns']})
research=[];ancestors=set();pid=os.getpid()
while pid>1:
 ancestors.add(pid)
 try:pid=int((Path('/proc')/str(pid)/'stat').read_text().split(') ',1)[1].split()[1])
 except (FileNotFoundError,ProcessLookupError):break
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit() or int(proc.name) in ancestors:continue
 try:args=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace');comm=(proc/'comm').read_text().strip()
 except (FileNotFoundError,ProcessLookupError,PermissionError):continue
 if comm in ('dnsmasq-rs','m6a_loadgen','m6a_upstream','perf','cargo','rustc','device_perf_netns','device_perf','dhcp_loadgen') or any(s in args for s in ('loop_owner_profile.py','original_stat_driver.py','oracle_controller.py','device_perf_controller.py','run-full.py','/dnsmasq-c')):research.append({'pid':int(proc.name),'comm':comm,'args':args})
assert not research,research
for lock in pre['locks_obtainable']:
 with open(lock,'a') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
report={'status':'PASS_CAPTURE_ANALYSIS_AND_RAW_POSTFLIGHT','epoch':time.time(),'controller_exited':True,'capture_windows':16,'analysis_windows':16,'source_files_verified':len(build['source_files']),'bindings_verified':len(pre['bindings']),'raw_files':raw_files,'sample_event_attributes':attrs,'windows':windows,'research':research,'locks_obtainable':pre['locks_obtainable'],'input_receipts':{name:sha(inputs/name) for name in ('plan.json','analysis-binding.json','preflight.json','preflight-attempt1-failure.json','run.py','postflight.py')},'controller_receipts':{name:sha(root/name) for name in ('launch.json','progress.json','complete.json')}}
out=inputs/'postflight.json';assert not out.exists();out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'raw_files':sum(len(v) for v in raw_files.values()),'windows':windows,'postflight_sha256':sha(out),'research':research},indent=2))
