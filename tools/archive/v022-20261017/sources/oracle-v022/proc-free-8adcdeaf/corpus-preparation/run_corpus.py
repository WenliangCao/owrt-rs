import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work')
TOOLS=ROOT/'private/corpus-tools-500865ba/tools/dnsmasq'
SOURCE=ROOT/'source-8adcdeaf';CACHE=ROOT/'private/cargo-target'
OUT=TOOLS.parent.parent/'private/corpus-8adcdeaf';PROBE=ROOT/'private/proc-free-8adcdeaf/corpus-probe-tests'
CONTROLS=ROOT/'private/correctness-inputs'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert not OUT.exists();OUT.mkdir(parents=True)
sys.path.insert(0,str(TOOLS));import rust_lib_probe
report={'status':'preparing','source_commit':'8adcdeafddb7cfd8bc5d059e396d898c0447cb70','tool_commit':'500865ba9fbdab24faf34760c23cf6fdd41ed5d3','scope':'same-source diagnostic musl libtest and pinned C corpora; actual final PGO separately runs shipping family/runtime gates','phases':[]}
def save():(OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,cmd,env=None,timeout=900):
 row={'name':name,'argv':cmd,'start':time.time()};report['phases'].append(row);save()
 with (OUT/(name+'.stdout')).open('xb') as stdout,(OUT/(name+'.stderr')).open('xb') as stderr:
  row['returncode']=subprocess.run(cmd,stdout=stdout,stderr=stderr,env=env,timeout=timeout).returncode
 row['end']=time.time();row['stdout_sha256']=sha(OUT/(name+'.stdout'));row['stderr_sha256']=sha(OUT/(name+'.stderr'));save()
 assert row['returncode']==0,name+' failed; original attempt retained'
 return (OUT/(name+'.stdout')).read_text()
try:
 run('probe-build',['env','ORACLE_BUILD_TARGET_DIR='+str(CACHE),'CARGO_BUILD_JOBS=2','sh',str(TOOLS/'oracle_build.sh'),str(SOURCE),str(PROBE),'probe-tests'])
 binding=rust_lib_probe.validate(PROBE/'lib-dnsmasq_rs',SOURCE,PROBE/'build.json',CACHE);report['binding']=binding
 reference=CONTROLS/'reference-native/dnsmasq/dnsmasq';assert sha(reference)=='11e5683091fb70a3f126adae2880aff96695d705e4441885b55d66e9235e038b'
 env=dict(os.environ,DNSMASQ_C_REFERENCE=str(reference),LD_LIBRARY_PATH=str(CONTROLS/'reference-native/deps/lib'))
 for name in ['config::tests::scalar_config_acceptance_matches_c','config::dns::tests::dns_config_acceptance_matches_c','config::records::tests::local_record_acceptance_matches_c','config::loader::tests::cli_include_acceptance_matches_c']:
  rust_lib_probe.recheck(binding)
  stdout=run(name.split('::')[-1],rust_lib_probe.argv(PROBE/'lib-dnsmasq_rs',name),env)
  rust_lib_probe.require_one_test(stdout,name);rust_lib_probe.recheck(binding)
 args=['--rust-test-binary',str(PROBE/'lib-dnsmasq_rs'),'--rust-source-root',str(SOURCE),'--rust-build-receipt',str(PROBE/'build.json'),'--rust-cargo-target-dir',str(CACHE)]
 cases=[('cache-answer','cache_answer_diff.py',['--oracle-command',str(CONTROLS/'cache-answer-c/local-answer-oracle')+' -C '+str(CONTROLS/'cache-answer-c/cache.conf'),'--oracle-identity',str(CONTROLS/'cache-answer-c/identity.json'),'--output',str(OUT/'cache-answer')]),('cache-transfer','cache_transfer_rust_diff.py',['--baseline',str(CONTROLS/'transfer-c-recovered'),'--out',str(OUT/'cache-transfer')]),('lease-insert','lease_insert_diff.py',['--compare-baseline',str(CONTROLS/'lease-insert-c'),'--output',str(OUT/'lease-insert')]),('stale-metadata','stale_metadata_diff.py',['--baseline',str(CONTROLS/'stale-metadata-c'),'--out',str(OUT/'stale-metadata')])]
 for label,tool,extra in cases:run(label,['python3',str(TOOLS/tool)]+args+extra,env)
 rust_lib_probe.recheck(binding);report.update(status='passed',corpus_gates=8)
except BaseException as error:report.update(status='failed-preserved',error=repr(error));raise
finally:save()
