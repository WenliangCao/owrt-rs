#!/usr/bin/env python3
"""Read existing Git/build/test/performance evidence; never run a workload."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

COMMIT='a4d7c2150fef01307ffa9d5050f08e416151c316'
MAIN='be531cee49e366bb5044443d473944dbea45b87e'
SDK_SHA='f40ce1218aa2040eec81a497fd07f26a689d50c0cd906ec506a813a17b8623ff'
RELEASE_SHA='1799be0828dd4f7f0a71bea9db13e713721a572adf1c50f043dada2ce7f3bffc'
ROOT=Path('/home/ubuntu/dnsmasq-fix2-repair-20261011')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def file(p):return {'path':str(p),'sha256':sha(p),'bytes':Path(p).stat().st_size}
def save(p,value):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
def git(repo,*args):return subprocess.check_output(['git','-C',str(repo),*args])
def digest_files(files):return hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def witness(args):
 repo=args.repo.resolve();sys.path.insert(0,str(repo/'tools/dnsmasq'));import build_package
 files=build_package.inputs(repo);assert len(files)==177
 assert git(repo,'rev-parse','main').decode().strip()==MAIN
 assert git(repo,'branch','--show-current').decode().strip()=='fix/audit-20261011'
 for name,value in files.items():
  assert hashlib.sha256(git(repo,'show',COMMIT+':'+name)).hexdigest()==value,name
  assert hashlib.sha256(git(repo,'show','HEAD:'+name)).hexdigest()==value,name
 result={'passed':True,'created_unix':time.time(),'source_commit':COMMIT,'main_actual':MAIN,
  'head':git(repo,'rev-parse','HEAD').decode().strip(),'branch':'fix/audit-20261011',
  'product_input_count':len(files),'source_digest':digest_files(files),'source_files':files,
  'worktree_status':git(repo,'status','--short').decode(),
  'scope':'All current worktree/HEAD product inputs equal frozen commit; unrelated user document edits retained.'}
 save(args.out,result);print(json.dumps({k:v for k,v in result.items() if k not in ['source_files','worktree_status']}))

def remote(args):
 private=ROOT/'private';source=ROOT/'source-parsed';functional=private/'functional-parsed'
 report={'passed':False,'created_unix':time.time(),'controller_sha256':sha(__file__),'argv':sys.argv,'checks':{},'inputs':{},'limits':[
  'Closure verifies retained evidence integrity and cleanup, not replacement or deployment approval.',
  'Original ELF/APK budget remains rejected; performance interpretation stays in the frozen summary.',
  'Local Git is independently read in the supplied witness; rerun witness if product files or main change.']}
 handles=[]
 def check(name,value):
  assert value,name
  report['checks'][name]=True
 def bind(name,p):report['inputs'][name]=file(p)
 try:
  assert os.geteuid()==0 and not sys.flags.optimize
  witness=read(args.git_witness);check('git_witness_passed',witness['passed'] and witness['source_commit']==COMMIT and witness['main_actual']==MAIN)
  bind('git_witness',args.git_witness)
  sys.path.insert(0,str(source/'tools/dnsmasq'));import build_package, m5_final_validation as final
  locks=[Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock')]
  locks.append(Path('/home/ubuntu/dnsmasq-review-fix-20261011/sdk-isolated/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/.owrt-dnsmasq-build.lock'))
  for lock in locks:
   handle=lock.open('r');fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB);handles.append(handle)
  check('build_and_sdk_locks_idle',True)
  excluded=final.related_processes();busy=[]
  for path in Path('/proc').glob('[0-9]*/cmdline'):
   if int(path.parent.name) in excluded:continue
   try:raw=path.read_bytes();parts=raw.split(b'\0');argv=b' '.join(parts).decode(errors='replace')
   except (FileNotFoundError,ProcessLookupError,PermissionError):continue
   if not raw:continue
   executable=Path(parts[0].decode(errors='replace')).name
   task=str(ROOT) in argv
   workload=executable in {'cargo','rustc','make','perf','strace','dnsmasq','dnsmasq-rs','m6a_loadgen','m6a_upstream'}
   if task or workload:busy.append({'pid':int(path.parent.name),'argv':argv})
  report['processes']=busy;check('no_remaining_task_or_matching_workloads',not busy)
  identity=read(private/'source-parsed-identity.json');files=build_package.inputs(source)
  check('177_product_inputs_equal_git_and_frozen_export',len(files)==177 and files==identity['source_files']==witness['source_files'])
  check('source_digest_and_revision',digest_files(files)==identity['source_digest']==witness['source_digest'] and identity['source_commit']==COMMIT)
  check('archive_identity',sha(private/'source-parsed.tar')==identity['source_archive_sha256']);bind('source_identity',private/'source-parsed-identity.json')
  build=read(private/'build-units-parsed/result.json');check('build_units_complete',build['passed'] and build['source_commit']==COMMIT and build['source_files']==files)
  units=[r for r in build['commands'] if r['name'] in ['lib-dnsmasq_rs','bin-dnsmasq-rs']]
  check('842_ordinary_units',len(units)==2 and sum(r['counts']['passed'] for r in units)==842 and sum(r['counts']['failed'] for r in units)==0 and sum(r['counts']['ignored'] for r in units)==23)
  for command in build['commands']:
   check('build_log_'+command['name'],sha(private/'build-units-parsed'/(command['name']+'.log'))==command['log_sha256'])
   if command.get('build_receipt'):
    folder=private/('release-parsed' if command['name']=='release-build' else 'tests-parsed')
    check(command['name']+'_receipt',sha(folder/'build.json')==command['receipt_sha256'] and read(folder/'build.json')==command['build_receipt'])
    for artifact in command['build_receipt']['artifacts']:check(command['name']+'_'+artifact['path'],sha(folder/artifact['path'])==artifact['sha256'])
  manifests=[]
  for folder in ['sdk-acquire-parsed','sdk-verify-parsed']:
   p=private/folder;m=read(p/'manifest.json');manifests.append(m);command=next(r for r in build['commands'] if r['name']==folder)
   check(folder+'_manifest',sha(p/'manifest.json')==command['manifest_sha256'])
   check(folder+'_source_build',all(m[k] for k in ['source_build_passed','source_inputs_unchanged','sdk_inputs_unchanged','sdk_recipe_restored','sdk_strip_payload_identity_verified']) and not m['frozen_elf'])
   check(folder+'_source_identity',m['source_commit']==COMMIT and m['source_files']==files)
   check(folder+'_elf',sha(m['elf']['path'])==m['elf']['sha256']==SDK_SHA)
   check(folder+'_apk',sha(m['artifact']['path'])==m['artifact']['sha256'])
   check(folder+'_budget_retained',command['returncode']==1 and m['failure_boundary']=='size-target' and m['budget_checks']=={'apk':False,'elf':False})
  check('sdk_two_build_identities',manifests[1]['artifact_identity_verified'] and manifests[1]['apk_byte_identical'] and manifests[0]['artifact']['sha256']==manifests[1]['artifact']['sha256'])
  check('release_identity',sha(private/'release-parsed/dnsmasq-rs')==RELEASE_SHA);bind('build_result',private/'build-units-parsed/result.json')
  plan=read(functional/'plan.json');state=read(functional/'state.json')
  check('functional_complete',state['passed'] and len(state['commands'])==len(plan['jobs'])==36 and state['source_commit']==COMMIT)
  check('functional_families',len(state['families'])==11 and set(state['families'])==set(plan['selected_families']) and sum(v['commands'] for v in state['families'].values())==24 and all(v['passed'] for v in state['families'].values()))
  check('functional_tool_inputs',all(sha(source/name)==value for name,value in plan['tool_files'].items()))
  check('functional_product_inputs',plan['source_files']==files and sha(plan['elf'])==plan['elf_sha256']==state['elf_sha256']==SDK_SHA)
  for actual,expected in zip(state['commands'],plan['jobs']):
   check('functional_'+actual['id'],actual['id']==expected['id'] and actual['argv']==expected['argv'] and actual['passed'] and actual['returncode']==0 and sha(actual['result'])==actual['result_sha256'])
  bind('functional_plan',functional/'plan.json');bind('functional_state',functional/'state.json')
  resources=private/'startup-resources-parsed';r5=read(resources/'result.json');r5cmd=read(private/'startup-resources-parsed-command.json')
  check('R5_complete',r5['passed'] and r5['main_level']['passed'] and len(r5['runs'])==27 and r5['source_commit']==COMMIT and r5cmd['passed'] and r5cmd['returncode']==0 and sha(resources/'result.json')==r5cmd['result_sha256'])
  for count,cfg in r5['configs'].items():check('R5_config_'+count,sha(resources/('hostrecords-'+count+'.conf'))==cfg['sha256'])
  raw_r5={}
  for row in r5['runs']:
   folder=resources/row['directory'];saved=read(folder/'result.json')
   check('R5_'+row['directory'],row['passed'] and row['exit']==0 and row['query']['correct'] and row['actual_exe_sha256']==row['expected_sha256'] and sha(folder/'daemon.log')==row['log_sha256'] and all(saved[k]==v for k,v in row.items() if k not in ['round','directory']))
   for p in folder.iterdir():
    if p.is_file():raw_r5[str(p.relative_to(resources))]=sha(p)
  report['R5_raw_index']=raw_r5;report['R5_raw_index_prior']='No separate retained raw index; per-run logs/results checked and all existing status/smaps files indexed now.';bind('R5_result',resources/'result.json')
  perf=args.performance_out.resolve();ready=read(args.ready_receipt);pp=read(perf/'plan.json');run=read(perf/'run.json');summary=read(perf/'summary.json');inv=read(perf/'driver-invocation.json')
  check('performance_ready',ready['functional_complete'] and ready['builds_complete'] and ready['source_commit']==COMMIT and ready['candidate_sha256']==RELEASE_SHA and ready['functional_state_sha256']==sha(functional/'state.json') and ready['build_result_sha256']==sha(private/'build-units-parsed/result.json') and ready['resource_result_sha256']==sha(resources/'result.json'))
  check('performance_plan_identity',pp['source_commit']==COMMIT and pp['main_commit']==MAIN and pp['source_identity']==identity and sha(perf/'plan.json')==ready['plan_sha256']==run['plan_sha256']==summary['plan_sha256']==inv['plan_sha256'])
  check('performance_ready_copy',sha(args.ready_receipt)==sha(perf/'ready-receipt.json')==run['ready_receipt_sha256']==inv['ready_receipt_sha256'])
  check('performance_controller_complete',run['status']=='complete' and inv['status']=='completed' and inv['returncode']==0 and sha(inv['argv'][3])==inv['driver_sha256'] and sha(perf/'driver.log')==inv['driver_log_sha256'])
  check('performance_assets',all(sha(p)==value for p,value in pp['assets'].items()))
  check('performance_complete_inventory',summary['complete'] and not summary['errors'] and len(pp['windows'])==len(run['windows'])==len(summary['windows'])==16 and [w['id'] for w in pp['windows']]==[w['id'] for w in run['windows']]==[w['id'] for w in summary['windows']])
  raw_perf={}
  for planned,executed,observed in zip(pp['windows'],run['windows'],summary['windows']):
   ident=planned['id'];folder=perf/ident;row=read(folder/'result.json');group=pp['groups'][planned['variant']]
   check('performance_'+ident,executed['returncode']==0 and row['accepted'] and row['measurement_valid'] and row['identity']['expected_elf_sha256']==group['sha256'] and row['identity']['argv']==planned['argv'][3:] and observed['valid_for_comparison'])
   for field in ['perf_record','strace_summary','wake_metrics']:check(ident+'_'+field+'_off',not row['identity'][field])
   check(ident+'_raw_hashes',all(sha(folder/name)==value for name,value in observed['raw_files'].items()))
   check(ident+'_controller_hashes',all(sha(value['path'])==value['sha256'] for value in observed['controller_evidence'].values()))
   raw_perf[ident]=observed['raw_files']
  for name,group in pp['groups'].items():check('performance_group_'+name,sha(group['elf'])==group['sha256'] and read(group['build_receipt'])==group['build'])
  report['performance_raw_index']=raw_perf;report['performance_comparisons']=summary.get('comparisons')
  for name in ['plan.json','ready-receipt.json','run.json','summary.json','driver-invocation.json']:bind('performance_'+name,perf/name)
  if args.performance_raw_index:
   supplied=read(args.performance_raw_index)
   check('published_performance_raw_index',supplied['source_summary_sha256']==sha(perf/'summary.json') and {w['id']:w['raw_files'] for w in supplied['windows']}==raw_perf)
   bind('published_performance_raw_index',args.performance_raw_index)
  else:report['published_performance_raw_index']='No external index supplied; summary raw index independently hashed above.'
  report['passed']=True
 except Exception as error:report['error']=repr(error)
 finally:
  for h in handles:h.close()
  save(args.out,report)
 print(json.dumps({'passed':report['passed'],'checks':len(report['checks']),'error':report.get('error'),'output':str(args.out)}))
 return int(not report['passed'])

parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
w=sub.add_parser('git-witness');w.add_argument('--repo',type=Path,required=True);w.add_argument('--out',type=Path,required=True)
r=sub.add_parser('remote');r.add_argument('--git-witness',type=Path,required=True);r.add_argument('--performance-out',type=Path,required=True);r.add_argument('--ready-receipt',type=Path,required=True);r.add_argument('--performance-raw-index',type=Path);r.add_argument('--out',type=Path,required=True)
a=parser.parse_args();raise SystemExit(witness(a) if a.mode=='git-witness' else remote(a))
