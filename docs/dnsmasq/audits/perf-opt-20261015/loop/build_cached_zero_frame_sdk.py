SOURCE_IDENTITY_SHA256 = '0fdf69233a1c32cfe2ae3d1280801e1256b7542b4df68c732e028ddc29670762'
GATE_RECEIPT_PATH = '/home/ubuntu/dnsmasq-perf-20261015/correctness/private/cached-zero-frame-linux-gates-20261016/verified-receipt.json'
GATE_RECEIPT_SHA256 = 'b5089b4b54bcde00a4d887453a1912965c10062066bb48323ea7607f2b651501'
EXPECTED_RELATED_PASSES = 940
from pathlib import Path
import hashlib,json,os,subprocess,time
root=Path('/home/ubuntu/dnsmasq-perf-20261015/root');private=root/'private';inputs=private/'cached-zero-frame-sdk-inputs'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
receipt={'scope':'Independent185 combined reply-storage/local-frame SDK; original recipe/canonical paths/budgets; Linux gate and reservation required','controller_pid':os.getpid(),'epoch':time.time(),'builds':[]}
state=inputs/'sdk-state.json'
assert not state.exists()
def save():
 t=state.with_suffix('.tmp');t.write_text(json.dumps(receipt,indent=2)+'\n');t.replace(state)
builder=private/'sdk-builder-5e6c41f6/perf_opt_sdk_build.py';assert sha(builder)=='f4540b1cbfd235ab2decde1bf7a09a6326fdb6fda7fe4d906239eac55a785f33'
declared=[('cached-zero-frame', '/home/ubuntu/dnsmasq-perf-20261015/root/source-cached-zero-frame', '185db90c9cabd26c0af09765636ef15bf6d35f79')]
assert sha(builder.with_name('build_package.py'))=='f280b97d7ca572b8311e2cd9564ffb7e641cc1e98c0fc1ac69622bc47f819310'
source=Path(declared[0][1]);assert sha(source/'research-git-identity.json')==SOURCE_IDENTITY_SHA256
qualification=Path(GATE_RECEIPT_PATH);assert sha(qualification)==GATE_RECEIPT_SHA256
q=json.loads(qualification.read_text())
assert q['status']=='PASS_RELATED_LINUX_GATES_VERIFIED' and q['source_commit']==declared[0][2] and q['source']==str(source)
assert q['identity_sha256']==SOURCE_IDENTITY_SHA256 and q['source_files_rehashed_after']==q['F_source_files_rehashed_after']==q['previous_0161_source_files_rehashed_after']==179
assert q['all_command_logs_rehashed']==10 and q['all_test_artifacts_rehashed']==2 and q['total_passed']==EXPECTED_RELATED_PASSES and q['owned_processes']==[]
assert q['raw_result']['status']=='complete' and q['raw_result']['active'] is None
candidate,=q['raw_result']['candidates'];assert candidate['source_commit']==declared[0][2] and candidate['status']=='passed'
assert all(c['returncode']==0 and c.get('failed',0)==0 for c in candidate['commands'])
counts={c['name']:c['passed'] for c in candidate['commands'] if 'passed' in c}
assert counts=={'lib':836,'lib-ignored-live':18,'bin':82,'bin-ignored-live':4}
receipt['qualification']={'source_commit':declared[0][2],'identity_sha256':SOURCE_IDENTITY_SHA256,'gate_receipt_sha256':GATE_RECEIPT_SHA256,'related_test_passes':EXPECTED_RELATED_PASSES}
sequence=[]
for name,path,commit in declared:
 source=Path(path);identity=json.loads((source/'research-git-identity.json').read_text());assert identity['commit']==commit and len(identity['git_blob_sha1'])==179
 sequence.append((name,source,identity))
for name,source,identity in sequence:
 out=private/('sdk-'+name);assert not out.exists()
 argv=['python3',str(builder),'--source',str(source),'--commit',identity['commit'],'--epoch',identity['epoch'],'--sdk','/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64','--out',str(out),'--cargo','/home/ubuntu/.cargo/bin/cargo','--build-slot',str(private/'sdk-build-slot'),'--cargo-target',str(private/'sdk-cargo-target')]
 if name=='f-control-after-f':argv+=['--expected-baseline-sha','b7926bcf39cd7f33b4f0c110315ddc1ad719b39427bec53430ea05aeacd781fc']
 with (inputs/(name+'.stdout')).open('wb') as stdout,(inputs/(name+'.stderr')).open('wb') as stderr:
  p=subprocess.Popen(argv,stdout=stdout,stderr=stderr)
  row={'name':name,'argv':argv,'pid':p.pid,'started_epoch':time.time()};receipt['builds'].append(row);save();status=p.wait()
 row.update(returncode=status,finished_epoch=time.time());save();assert status==0
 built=json.loads((out/'build.json').read_text());assert built['status']=='built-unqualified' and built['source_unchanged'] and built['within_existing_budget']
 assert built['source_commit']==identity['commit'] and len(built['source_files'])==179 and built['sdk_recipe_restored']
 layout=built['elf_layout'];assert layout['type']=='ET_DYN' and layout['machine']=='AArch64' and layout['linkage']=='static-pie' and layout['interpreter'] is None and not layout['needed']
 assert all(layout[k] for k in ('pie','bind_now','gnu_relro','nx_stack')) and not layout['writable_executable_load']
 assert all(sha(out/a['path'])==a['sha256'] and (out/a['path']).stat().st_size==a['bytes'] for a in built['artifacts'])
 assert sha(out/'link.map')==built['link_map']['sha256']
 assert all(sha(source/path)==digest for path,digest in built['source_files'].items())
 if name=='f-control-after-f':assert built['baseline_matches_expected'] is True
 row.update(artifacts=built['artifacts'],link_map=built['link_map'],receipt_sha256=sha(out/'build.json'));save()
receipt['complete']=True;save();print(json.dumps({'complete':True,'builds':[{k:x[k] for k in ['name','artifacts','link_map','receipt_sha256']} for x in receipt['builds']]}))
