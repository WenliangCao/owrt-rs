"""Frozen SDK-payload validation for R1/R2/R4/R5; no performance claims."""
from pathlib import Path
import hashlib, json, os, re, subprocess, sys, time
ROOT=Path('/home/ubuntu/dnsmasq-fix2-repair-20261011')
SOURCE=ROOT/'source-parsed';TOOLS=SOURCE/'tools/dnsmasq';AUDIT=SOURCE/'docs/dnsmasq/audits/20261011/independent'
FIX2=SOURCE/'docs/dnsmasq/audits/20261011/fix2'
OUT=ROOT/'private/functional-parsed'
ELF=ROOT/'private/sdk-acquire-parsed/payload/usr/sbin/dnsmasq'
ELF_SHA='f40ce1218aa2040eec81a497fd07f26a689d50c0cd906ec506a813a17b8623ff'
COMMIT='a4d7c2150fef01307ffa9d5050f08e416151c316'
IMAGE=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
BASE=Path('/home/ubuntu/dnsmasq-tftp-repair-889fe4f5/source/private/m6b-final-hosts/identity.json')
SELECTED={
 'm5_dns_cache':'R1 CNAME terminal order, cache eligibility and negative authority',
 'm5_edns':'R1 RD/DO/EDNS and cached answer construction',
 'dhcp-files':'R2/R5 initial file publication and lease readiness',
 'dns-files':'R2/R5 hosts and resolver initialization/reload ownership',
 'm5_helper':'R2/R5 restored lease script metadata and initial callback delivery',
 'helper-shutdown':'R2/R5 callback admission during initialization and shutdown',
 'm5_lease_recovery':'R2/R5 synchronization of restored leases after initial hosts publication',
 'm5_option_matrix':'R2/R5 expand-hosts/domain and DNS name options',
 'm5_option_matrix_lease_names':'R2/R5 startup hosts interaction with DHCP authoritative/restored names',
 'm5_local_records':'R2/R5 configured records across initial cache reload',
 'logging-all-scopes':'R4 diagnostic and startup/daemon/debug/privileges/helper lifecycle and R2/R5 error ordering',
}
def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,d):
 p=Path(p);tmp=p.with_suffix(p.suffix+'.tmp');tmp.write_text(json.dumps(d,indent=2)+'\n');tmp.replace(p)
assert os.geteuid()==0 and not sys.flags.optimize
assert sha(ELF)==ELF_SHA
sys.path.insert(0,str(TOOLS))
import m5_final_validation as final
import build_package as package
from m2_rootfs import STOCK_SHA256
assert sha(IMAGE/'usr/sbin/dnsmasq')==STOCK_SHA256
inputs=package.inputs(SOURCE)
tool_inputs={str(p.relative_to(SOURCE)):sha(p) for p in [*TOOLS.iterdir(), *AUDIT.iterdir(), *FIX2.rglob('*.py')] if p.is_file()}
assert not any('{link_map}' in str(j) for f in read(TOOLS/'m5_final_families.draft.json')['families'] if f['id'] in SELECTED for j in f['steps'])
OUT.mkdir(parents=True,exist_ok=False)
def isolated(script,*args):return ['sh',str(TOOLS/'run_isolated.sh'),'python3',str(script),*map(str,args)]
def item(name,argv,result=None,check=None):return dict(id=name,argv=argv,result=str(result) if result else None,custom_check=check,timeout_seconds=1800)
image_args=['--image-root',IMAGE,'--rust',ELF]
jobs=[
 item('dhcp-over-nxdomain',isolated(AUDIT/'dns_hosts_stale.py','--tools',TOOLS,*image_args,'--out',OUT/'dhcp-negative','--fresh-only','--require-match'),OUT/'dhcp-negative/result.json','dhcp-negative'),
 item('R1-cname',isolated(FIX2/'dns/cname_compat.py',*image_args,'--out',OUT/'r1-cname','--require-match'),OUT/'r1-cname/result.json','r1-cname'),
 item('R1-flags',isolated(FIX2/'dns/cname_flags.py',*image_args,'--out',OUT/'r1-flags','--require-match'),OUT/'r1-flags/result.json','r1-flags'),
 item('R2-hostsdir',isolated(FIX2/'dhcp/hostsdir_startup.py','--source',SOURCE,*image_args,'--out',OUT/'r2-hostsdir','--require-match'),OUT/'r2-hostsdir/result.json','r2'),
 item('R4-dump',isolated(FIX2/'config/dump_rows.py','--source',SOURCE,'--image',IMAGE,'--rust',ELF,'--source-revision',COMMIT,'--out',OUT/'r4-dump','--require-match'),OUT/'r4-dump/result.json','r4'),
 item('runtime-signals',isolated(TOOLS/'audit_20261011_runtime_signals.py',*image_args,'--c-native','/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01/dnsmasq/dnsmasq','--out',OUT/'signals'),OUT/'signals/result.json','signals'),
 item('hosts-startup-helper',isolated(TOOLS/'audit_fix_20261011_hosts_startup.py','--source',SOURCE,*image_args,'--out',OUT/'startup-helper'),OUT/'startup-helper/result.json','startup-helper'),
 item('hosts-startup-dhcp',isolated(TOOLS/'audit_fix_20261011_hosts_startup_dhcp.py','--source',SOURCE,*image_args,'--out',OUT/'startup-dhcp'),OUT/'startup-dhcp/result.json','startup-dhcp'),
 item('F04-relro',isolated(AUDIT/'build_protections_probe.py',SOURCE,ELF,OUT/'relro','--image-root',IMAGE,'--require-relro'),OUT/'relro/result.json','relro'),
 item('hosts-diagnostics',isolated(TOOLS/'audit_fix_20261011_hosts.py',*image_args,'--out',OUT/'hosts'),OUT/'hosts/result.json','hosts'),
 item('hosts-original',isolated(AUDIT/'dns_hosts_probe.py',*image_args,'--out',OUT/'original'),OUT/'original/result.json','original'),
 item('hosts-memory',isolated(TOOLS/'audit_20261011_hosts_memory.py',*image_args,'--out',OUT/'memory'),OUT/'memory/result.json','memory'),
]
spec=read(BASE);spec.update(source_root=str(SOURCE),tools_root=str(TOOLS),source_commit=COMMIT,elf=str(ELF),elf_sha256=ELF_SHA,selected_families=list(SELECTED),family_registry=read(TOOLS/'m5_final_families.draft.json'))
spec.pop('family_tool_overrides',None);spec['bindings'].pop('link_map',None)
family_jobs=final.commands(spec,'families',OUT/'families')
assert len(family_jobs)==24 and {j['family'] for j in family_jobs}==set(SELECTED)
jobs+=family_jobs
save(OUT/'plan.json',dict(source_commit=COMMIT,elf=str(ELF),elf_sha256=ELF_SHA,selected_families=SELECTED,source_files=inputs,tool_files=tool_inputs,controller_sha256=sha(__file__),jobs=jobs,scope='12 directed/supplementary runs and 11 complete affected families /24 registered commands using SDK-produced ELF; R3 and performance excluded; R5 startup-resource runs separately'))
state=dict(passed=False,source_commit=COMMIT,elf_sha256=ELF_SHA,commands=[],families={})
save(OUT/'state.json',state)
for job in jobs:
 record=dict(job,passed=False,started=time.time());state['commands'].append(record);save(OUT/'state.json',state)
 print('START',job['id'],flush=True)
 with (OUT/(job['id']+'.log')).open('wb') as log:
  process=subprocess.Popen(job['argv'],cwd=SOURCE,stdout=log,stderr=log,start_new_session=True);known={}
  try:
   while process.poll() is None:
    final.remember_job_processes(process,known)
    if time.time()-record['started']>job['timeout_seconds']:raise TimeoutError(job['id'])
    try:process.wait(timeout=1)
    except subprocess.TimeoutExpired:pass
  finally:final.stop_job_processes(process,known)
 record['returncode']=process.returncode
 try:
  assert process.returncode==0, f'exit {process.returncode}'
  result=read(job['result'])
  check=job.get('custom_check')
  if check=='dhcp-negative':assert result['passed']
  if check=='r1-cname':assert result['passed'] and len(result['cases'])==20
  if check=='r1-flags':assert result['passed'] and len(result['cases'])==16
  if check=='r2':assert result['passed'] and len(result['cases'])==3
  if check=='r4':assert result['r4_passed'] and len(result['rows'])==5
  if check=='signals':assert result['passed']
  if check=='startup-helper':
   assert result['passed'] and len(result['cases'])==3
   for case in result['cases']:
    for side in ('c','rust'):
     row=case['observed'][side]
     assert len(row['callbacks_before_stop'])==5
     if case['id']=='held-fifo':assert row['callbacks_before_resolver_close']==0
  if check=='startup-dhcp':assert result['passed']
  if check=='relro':
   assert result['passed'] and result['require_relro'] and result['dns_answers_match']
   assert result['variants']['rust']['sha256']==ELF_SHA
   assert result['variants']['c']['sha256']==STOCK_SHA256
   for side in ('c','rust'):
    variant=result['variants'][side];assert len(variant['runs'])==3 and variant['distinct_bases']==3
    for run in variant['runs']:
     assert run['relro_readonly'] and run['relro_end_page_aligned'] and run['exit']==0 and not run['failures']
     assert 'x' not in run['stack_permissions'] and not run['wx_mappings']
     if side=='rust':assert len(run['mapped_files'])==1
  if check=='hosts':assert result['passed'] and len(result['cases'])==8
  if check=='original':
   assert result['rust_sha256']==ELF_SHA and result['c_sha256']==STOCK_SHA256
   assert len(result['rows'])==4
   for row in result['rows']:
    assert row['c']['alive'] and row['rust']['alive']
    assert {k:v for k,v in row['c'].items() if k!='dump'}=={k:v for k,v in row['rust'].items() if k!='dump'}
    if row['mode'] in ('addn-hosts','hostsdir'):
     diagnostics={side:re.findall(r'bad (?:name|address) at [^\n]+',row[side]['dump']) for side in ('c','rust')}
     assert diagnostics['c']==diagnostics['rust'] and diagnostics['c'],diagnostics
     assert any('bad name at ' in value and value.endswith(' line 6') for value in diagnostics['c'])
  if check=='memory':assert not result['failures'] and result['paired_cases_passed']==3
  if 'family' in job:final.check_result(Path(job['result']),job['checks'],job.get('inventory'))
  record.update(passed=True,result_sha256=sha(job['result']))
 except Exception as error:record['error']=repr(error)
 record['elapsed_seconds']=time.time()-record['started'];save(OUT/'state.json',state)
 print('PASS' if record['passed'] else 'FAIL',job['id'],record.get('error'),flush=True)
 if not record['passed']:raise SystemExit(1)
assert package.inputs(SOURCE)==inputs and sha(ELF)==ELF_SHA
assert all(sha(SOURCE/name)==value for name,value in tool_inputs.items())
for family in SELECTED:
 expected=[j for j in family_jobs if j['family']==family];actual=[j for j in state['commands'] if j.get('family')==family]
 assert len(expected)==len(actual) and all(j['passed'] for j in actual)
 state['families'][family]=dict(passed=True,commands=len(actual))
state['passed']=True;save(OUT/'state.json',state);print('ALL PASS',flush=True)
