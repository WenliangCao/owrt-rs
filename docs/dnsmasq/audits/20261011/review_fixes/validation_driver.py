"""Frozen SDK-payload validation for F01/F02/F03/F06; no performance claims."""
from pathlib import Path
import hashlib, json, os, re, subprocess, sys, time
ROOT=Path('/home/ubuntu/dnsmasq-review-fix-20261011')
SOURCE=ROOT/'source'
TOOL_SOURCE=ROOT/'private/tool-source-02'
TOOLS=TOOL_SOURCE/'tools/dnsmasq';AUDIT=TOOL_SOURCE/'docs/dnsmasq/audits/20261011/independent'
OUT=ROOT/'private/functional-02'
ELF=SOURCE/'private/sdk-source-acquire-02/payload/usr/sbin/dnsmasq'
ELF_SHA='e099e180569db342827fde366f3be81dc6d0faed8ca0e1404235b76ffcfd2580'
COMMIT='18cc40367328056f41e237b0d4ff2f23b33a7ef4'
IMAGE=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
BASE=Path('/home/ubuntu/dnsmasq-tftp-repair-889fe4f5/source/private/m6b-final-hosts/identity.json')
SELECTED={
 'm5_dns_cache':'F02 CNAME/negative/expiry/stale/RD/DO lookup order',
 'm5_local_records':'F02 typed local records and configured aliases',
 'm5_edns':'F02 cache eligibility and query flags',
 'm5_option_matrix_lease_names':'F02/F03 DHCP DNS publication and name/TTL policy',
 'm5_helper':'F03 real helper lifecycle and metadata',
 'helper-shutdown':'F03 queued callbacks/exit lifecycle',
 'dhcp-identities':'F03 multi-MAC and client identity reuse',
 'm5_lease_recovery':'F03 restored/existing lease helper state',
 'logging-all-scopes':'F06 shared diagnostic rendering and F03 helper/packet logs',
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
tool_inputs={str(p.relative_to(TOOL_SOURCE)):sha(p) for folder in (TOOLS,AUDIT) for p in folder.iterdir() if p.is_file()}
assert not any('{link_map}' in str(j) for f in read(TOOLS/'m5_final_families.draft.json')['families'] if f['id'] in SELECTED for j in f['steps'])
OUT.mkdir(parents=True,exist_ok=False)
def isolated(script,*args):return ['sh',str(TOOLS/'run_isolated.sh'),'python3',str(script),*map(str,args)]
def item(name,argv,result=None,check=None):return dict(id=name,argv=argv,result=str(result) if result else None,custom_check=check,timeout_seconds=1800)
image_args=['--image-root',IMAGE,'--rust',ELF]
jobs=[
 item('F02-cached-cname',isolated(AUDIT/'dns_hosts_cname.py',*image_args,'--out',OUT/'cname','--require-match'),OUT/'cname/result.json'),
 item('F02-published-dhcp',isolated(AUDIT/'dns_hosts_stale.py','--tools',TOOLS,*image_args,'--out',OUT/'negative','--fresh-only','--require-match'),OUT/'negative/result.json'),
 item('F03-original-five',isolated(AUDIT/'dhcp_handoff_helper.py','--source',TOOL_SOURCE,*image_args,'--out',OUT/'helper-original'),OUT/'helper-original/result.json','helper-five'),
 item('F03-helper-ten',isolated(TOOLS/'audit_fix_20261011_dhcp_helper.py','--source',TOOL_SOURCE,*image_args,'--out',OUT/'helper-ten'),OUT/'helper-ten/result.json','helper-ten'),
 item('F06-scoped-dump',isolated(AUDIT/'config_signals_dump_probe.py','--image',IMAGE,'--rust',ELF,'--out',OUT/'scope'),OUT/'scope/result.json','scope'),
 item('signals-regression',isolated(TOOLS/'audit_20261011_runtime_signals.py',*image_args,'--c-native','/home/ubuntu/dnsmasq-rewrite-20260929/c-native-01/dnsmasq/dnsmasq','--out',OUT/'signals'),OUT/'signals/result.json','signals'),
 item('dhcp-dns-34',isolated(ROOT/'private/image-legacy.py',TOOLS/'dhcp_dns_diff.py','--c',IMAGE/'usr/sbin/dnsmasq','--rust',ELF,'--out',OUT/'dhcp-dns'),OUT/'dhcp-dns/summary.json','dhcp-dns'),
]
spec=read(BASE);spec.update(source_root=str(SOURCE),tools_root=str(TOOLS),source_commit=COMMIT,elf=str(ELF),elf_sha256=ELF_SHA,selected_families=list(SELECTED),family_registry=read(TOOLS/'m5_final_families.draft.json'))
spec.pop('family_tool_overrides',None);spec['bindings'].pop('link_map',None)
family_jobs=final.commands(spec,'families',OUT/'families')
assert len(family_jobs)==22 and {j['family'] for j in family_jobs}==set(SELECTED)
jobs+=family_jobs
save(OUT/'plan.json',dict(source_commit=COMMIT,tool_commit=read(ROOT/'private/tool-snapshot-02.json')['commit'],tool_snapshot=read(ROOT/'private/tool-snapshot-02.json'),elf=str(ELF),elf_sha256=ELF_SHA,selected_families=SELECTED,source_files=inputs,tool_files=tool_inputs,controller_sha256=sha(__file__),jobs=jobs,scope='7 directed/supplementary runs and 9 complete affected families /22 registered commands using SDK-produced ELF; F04/F05/F07 and performance excluded'))
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
  if job['id'].startswith('F02-'):assert result['passed']
  if check=='helper-five':assert len(result['cases'])==5 and all(r['matched'] for r in result['cases'])
  if check=='helper-ten':assert result['passed'] and len(result['cases'])==10
  if check=='scope':
   assert len(result['rows'])==2
   for row,expected in zip(result['rows'],('server fe80::1%lo#53:', 'server 127.0.0.1#15354:')):
    values=row['result'];assert all(v['alive_after_usr1'] and v['exit']==0 for v in values.values())
    lines={side:re.findall(r'(?m)^.*?(server [^\n]+: queries sent [^\n]+)$',v['log']) for side,v in values.items()}
    assert lines['c']==lines['rust'] and len(lines['c'])==1 and expected in lines['c'][0],lines
  if check=='signals':assert result['passed']
  if check=='dhcp-dns':assert result['status']=='passed' and result['matched']==34 and not result['mismatches']
  if 'family' in job:final.check_result(Path(job['result']),job['checks'],job.get('inventory'))
  record.update(passed=True,result_sha256=sha(job['result']))
 except Exception as error:record['error']=repr(error)
 record['elapsed_seconds']=time.time()-record['started'];save(OUT/'state.json',state)
 print('PASS' if record['passed'] else 'FAIL',job['id'],record.get('error'),flush=True)
 if not record['passed']:raise SystemExit(1)
assert package.inputs(SOURCE)==inputs and sha(ELF)==ELF_SHA
assert all(sha(TOOL_SOURCE/name)==value for name,value in tool_inputs.items())
for family in SELECTED:
 expected=[j for j in family_jobs if j['family']==family];actual=[j for j in state['commands'] if j.get('family')==family]
 assert len(expected)==len(actual) and all(j['passed'] for j in actual)
 state['families'][family]=dict(passed=True,commands=len(actual))
state['passed']=True;save(OUT/'state.json',state);print('ALL PASS',flush=True)
