"""Original 5c peer-phase raw sequence/identity blocks, warm paths and pins."""
from pathlib import Path
import hashlib,json,sys
INP=Path('/home/ubuntu/dnsmasq-perf-20261015/loop/private/warm-address-encode-owner32-inputs')
RAW=INP.with_name('warm-address-encode-owner32')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();read=lambda p:json.loads(p.read_text())
assert len(sys.argv)==5
plan=read(INP/'plan.json');launch=read(INP/'launch.json');ready=read(INP/'final-ready-metadata.json');pre=read(INP/'pretransfer.json');post=read(INP/'postflight-raw.json');release=read(INP/'release-to-correctness.json')
assert sha(INP/'result.json')==post['analysis_sha256']==release['analysis_sha256']==sys.argv[1]
assert sha(INP/'postflight-raw.json')==release['postflight_sha256']==sys.argv[2]
assert sha(INP/'release-to-correctness.json')==sys.argv[3]
assert sha(INP/'plan.json')==launch['plan_sha256']==ready['plan_sha256']==post['plan_sha256']=='a26e73f253cda85388ef0b65454ff609fa704c6ca82c8c0f9f4362f07ff7ceb2'
assert sha(INP/'plan-before-ready.json')==pre['plan_sha256']=='ee3e6e3c14b6116ccb5385539906129e30ac9755c62bc218da7b86b8e5c0da9d'
assert sha(INP/'final-ready-metadata.json')==launch['final_metadata_sha256']=='1db5b2b4e4d6c41b81aa276c7e7938078e4ea2fe263c967b7553a039915e1ade'
assert sha(INP/'pretransfer.json')=='899a036e9bd1156f183aebcbbab6f24e13cdaadb8066aec57dba041056c572ee'
quiet_path=Path(plan['explicit_slot_release']['path']);quiet=read(quiet_path)
assert sha(quiet_path)==launch['explicit_release_sha256']==ready['release_sha256']==plan['explicit_slot_release']['sha256']=='6978d36e1c320180c458f20ed7b20e3f01855eded20f3585cb44fcf73829a0a1'
assert pre['epoch']<quiet['epoch']<ready['epoch']<launch['epoch']
assert quiet['research_including_exact_image_C']==[] and quiet['performance_timing_released'] and quiet['accepted_G_triple_rehashed']
assert not quiet['all_bulk_downloads_complete']
manifest=read(INP/'input-manifest.json');assert manifest==pre['files'] and len(manifest)==11 and pre['file_count_with_manifest']==12
for name,row in manifest.items():
 path=INP/('plan-before-ready.json' if name=='plan.json' else name);assert sha(path)==row['sha256'] and path.stat().st_size==row['bytes']
controller=INP/'run_warm_address_encode_owner32.py';analyzer=INP/'analyze_warm_address_encode_owner32.py'
assert sha(controller)==plan['controller_sha256']==launch['controller_sha256']=='9f81b7245ba5dfd53cc6e9ff0c88fd4930ddf458855ba09bf5c7ad8346d3dd9a'
assert sha(analyzer)==plan['analysis_sha256']==post['analysis_tool_sha256']=='434eb14be206085d7e4fe39f30a831e8ee7b5f298b53d82324f7518cbd5f624a'
assert len(plan['analysis_inputs_sha256'])==8
for name,digest in plan['analysis_inputs_sha256'].items():assert sha(INP/'analysis-inputs'/name)==digest
for name,digest in plan['tool_sha256'].items():assert sha(Path(name))==digest
source='6dadfec2e79d0c7c858dde296f7fa0e48e91afa6';assert plan['candidate_commit']==quiet['source_commit']==release['source_commit']==source
for side,artifact in plan['artifacts'].items():
 directory=Path(artifact['directory'])
 for name,field in [('dnsmasq-rs','sha256'),('build.json','build_receipt_sha256'),('link.map','link_map_sha256')]:assert sha(directory/name)==artifact[field]
 built=read(directory/'build.json');assert built['source_commit']==artifact['source']==plan['sources'][side]['commit']
 assert built['source_files']==plan['sources'][side]['files'] and len(built['source_files'])==179
 assert built['source_unchanged'] and built['within_existing_budget'] and built['status']=='built-unqualified'
 for name,digest in built['source_files'].items():assert sha(Path(plan['sources'][side]['directory'])/name)==digest
gate_path=Path(plan['linux_gate']['path']);gate=read(gate_path)
assert sha(gate_path)==plan['linux_gate']['sha256']==quiet['related_verified_sha256']=='088f8d2ecc4ac5ffebfa4407a6e9de7dd144514890f0cbc56c1440dd6d35293f'
assert gate['total_passed']==plan['linux_gate']['expected_passes']==961 and gate['source_commit']==source and gate['research']==[] and gate['wrapper_exited']
assert launch['argv']==['taskset','-c','0','python3',str(controller),str(INP/'plan.json')]
assert launch['windows']==plan['window_count']==32 and launch['stat_windows']==plan['pmu_window_count']==12 and launch['plain_windows']==plan['plain_window_count']==20
assert launch['no_measurement_retries'] and launch['transfers_held_during_both_measurement_slots']
identity=read(RAW/'identity.json');progress=read(RAW/'progress.json');complete=read(RAW/'complete.json')
assert identity['plan_sha256']==sha(INP/'plan.json') and identity['controller_sha256']==sha(controller)
assert identity['artifacts']==plan['artifacts'] and identity['linux_gate_sha256']==sha(gate_path)
assert launch['epoch']<=identity['started_epoch']<=progress[0]['started_epoch']
assert len(progress)==len(identity['windows'])==complete['windows']==32 and complete['complete']
last=identity['started_epoch']
for row,window in zip(progress,identity['windows']):
 assert row['label']==window['label'] and row['returncode']==0 and row['group_exited']
 assert last<=row['started_epoch']<row['finished_epoch'];last=row['finished_epoch']
 artifact=plan['artifacts'][row['side']]
 assert post['raw_files'][row['label']]['dnsmasq-rs']['sha256']==artifact['sha256']
 assert post['raw_files'][row['label']]['link.map']['sha256']==artifact['link_map_sha256']
 assert sha(RAW/row['label']/'build.json')==artifact['build_receipt_sha256']
assert not (RAW/'failure.json').exists() and not (RAW/'active.json').exists()
analysis_launch=read(INP/'analysis-launch.json')
assert last<=complete['ended_epoch']<analysis_launch['epoch']<post['epoch']<release['epoch']
assert read(INP/'analysis-command.json')==analysis_launch['argv']
assert analysis_launch['argv']==['sudo','-n','taskset','-c','0','python3',str(analyzer),str(RAW),str(INP/'result.json'),str(INP/'analysis-inputs')]
assert read(INP/'analysis-exit.json')=={'returncode':0}
assert (INP/'analysis.stderr').stat().st_size==(INP/'controller.stderr').stat().st_size==0
for name in ['identity','progress','complete']:assert sha(RAW/(name+'.json'))==post[name+'_sha256']
assert post['measurement_retries']==0 and post['controller_exited']
assert release['controller_exited'] and release['analysis_exited_zero'] and release['no_measurement_retries'] and release['native240_not_run']
assert release['research_including_exact_image_C']==release['idle_SDK_background']==[] and len(release['locks_available'])==3
assert release['loop_stops_Oracle_access_after_handoff'] and release['all_bulk_held_until_DHCP_archival_restoration_release']
assert not release['local_archive_download_completed'] and not release['local_archive_transfer_audit_completed']
assert sha(Path(release['collection_path']))==release['collection_sha256']
receipt={'status':'PASS_REMOTE_ORIGINAL_WARM_OWNER32_PHASE_IDENTITY_BINDINGS','source_commit':source,'plan_sha256':sha(INP/'plan.json'),'author_result_sha256':sha(INP/'result.json'),'postflight_sha256':sha(INP/'postflight-raw.json'),'release_sha256':sha(INP/'release-to-correctness.json'),'controller_sha256':sha(controller),'analyzer_sha256':sha(analyzer),'local_before_phase_receipt_sha256':'9672babe27ae23205ddeae818fbda0f6e10db712943c46b122bce7b81a3c61a0','pretransfer12_and_source358_and_both_SDK_triples_rehashed':True,'original32_sequential_completion_and_analysis_chain_verified':True,'recorded_order':'pretransfer < fresh correctness quiet < ready < launch < 32 sequential windows < original analysis < postflight < release','bulk_download_and_archive_audit_pending':True,'scope':'Existing raw phase/identity read only; no timing/workload. Original full-bin math independently checked by main reviewer; local input archive/Git/ref checks in the pinned before-phase receipt. No5c signals or5c-only metadata failure inherited. Remote quiet is receipt-bound, not a new observation.','script_sha256':sha(Path(__file__))}
out=Path(sys.argv[4]);assert not out.exists()
with out.open('x') as f:f.write(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'status':receipt['status'],'sha256':sha(out),'path':str(out)}))
