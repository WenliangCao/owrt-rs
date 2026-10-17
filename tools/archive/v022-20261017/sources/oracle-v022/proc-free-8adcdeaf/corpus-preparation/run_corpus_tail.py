import hashlib,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');TOOLS=ROOT/'private/corpus-tools-500865ba/tools/dnsmasq';SOURCE=ROOT/'source-8adcdeaf';CACHE=ROOT/'private/cargo-target'
OUT=TOOLS.parent.parent/'private/corpus-8adcdeaf';PROBE=ROOT/'private/proc-free-8adcdeaf/corpus-probe-tests';CONTROLS=ROOT/'private/correctness-inputs'
sys.path.insert(0,str(TOOLS));import rust_lib_probe
binding=rust_lib_probe.validate(PROBE/'lib-dnsmasq_rs',SOURCE,PROBE/'build.json',CACHE)
original=json.loads((OUT/'summary.json').read_text());assert original['status']=='failed-preserved' and [r['returncode'] for r in original['phases']]==[0,0,0,0,0,0,1]
report={'reason':'original transfer invocation selected historic identity pin; retained control is independently validated fresh-c-receipt; no C/R comparison ran in failed preflight','rerun_passed_gates':False,'phases':[],'status':'running'}
summary=OUT/'tail-summary.json';assert not summary.exists()
def save():summary.write_text(json.dumps(report,indent=2)+'\n')
args=['--rust-test-binary',str(PROBE/'lib-dnsmasq_rs'),'--rust-source-root',str(SOURCE),'--rust-build-receipt',str(PROBE/'build.json'),'--rust-cargo-target-dir',str(CACHE)]
env=dict(os.environ,LD_LIBRARY_PATH=str(CONTROLS/'reference-native/deps/lib'))
cases=[('cache-transfer-fresh-receipt','cache_transfer_rust_diff.py',['--baseline',str(CONTROLS/'transfer-c-recovered'),'--fresh-c-receipt',str(CONTROLS/'transfer-c-recovered/fresh-c-receipt.json'),'--out',str(OUT/'cache-transfer-fresh-receipt')]),('lease-insert','lease_insert_diff.py',['--compare-baseline',str(CONTROLS/'lease-insert-c'),'--output',str(OUT/'lease-insert')]),('stale-metadata','stale_metadata_diff.py',['--baseline',str(CONTROLS/'stale-metadata-c'),'--out',str(OUT/'stale-metadata')])]
try:
 for label,tool,extra in cases:
  rust_lib_probe.recheck(binding);cmd=['python3',str(TOOLS/tool)]+args+extra;row={'label':label,'argv':cmd,'start':time.time()};report['phases'].append(row);save()
  with (OUT/(label+'.stdout')).open('xb') as stdout,(OUT/(label+'.stderr')).open('xb') as stderr:row['returncode']=subprocess.run(cmd,stdout=stdout,stderr=stderr,env=env,timeout=300).returncode
  row['end']=time.time();save();assert row['returncode']==0,label+' failed; preserved';rust_lib_probe.recheck(binding)
 report.update(status='passed',qualified_gate_total_with_original=8)
except BaseException as e:report.update(status='failed-preserved',error=repr(e));raise
finally:save()
