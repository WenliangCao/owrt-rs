#!/usr/bin/env python3
"""Continue only never-started R92 gates with the unchanged existing drivers."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
ROOT=Path('/srv/owrt-archive/unified-work');BASE=ROOT/'private/core-functional-e21245d2';SOURCE=ROOT/'source-e21245d2';OUT=BASE/'r92-continuation'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
original=json.loads((BASE/'r92/results.json').read_text());assert len(original['results'])==31 and original['results'][-1]['name']=='netifd-suite' and not (Path('/proc') / os.environ['OWRT_PRIOR_RUNNER_PID']).exists()
command=json.loads((BASE/'original-r92-command.json').read_text());common=command['argv'];assert common[4]==str(BASE/'r92')
normal=['logd-r15','logd-r28','r21_logd_reconnect_check','r25_logd_stream_probe','r83_logd_ring_wrap','r83_logd_oversize_read','fw4-upstream','fw4-r29','fw4-defaults','uci-r16','uci-r24','uci-r83','reload-config-r1','r92-fw4']
assert not set(normal)&{r['name'] for r in original['results']}
assert json.loads((BASE/'fw4-image-tools-correction/result.json').read_text())['returncode']==0
sys.path.insert(0,str(SOURCE/'tools'));import r92_recovery_probe as recovery;import r92_compat_probe as compat
recover=[name for name,component in recovery.CASES.items() if component!='procd'];compatible=[name for name,item in compat.CASES.items() if item[0]!='procd'];assert len(recover)==8
OUT.mkdir();report={'status':'running','source_commit':'e21245d2404f6542759f45d064214ac3696c355f','original_result_sha256':sha(BASE/'r92/results.json'),'original_count':31,'normal_gates':normal,'recovery_cases':recover,'compat_cases':compatible,'procd_excluded':True,'fw4_image_reused':True,'commands':[]}
def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def run(name,argv):
 row={'name':name,'argv':argv,'started':time.time()};report['commands'].append(row);save()
 with (OUT/(name+'.log')).open('x') as log:
  p=subprocess.Popen(argv,cwd=SOURCE,env=dict(os.environ,RUSTFLAGS='-Dwarnings',RUSTDOCFLAGS='-Dwarnings'),stdout=log,stderr=log,start_new_session=True);row['pid']=p.pid;save();row['exit']=p.wait()
 row.update(finished=time.time(),log_sha256=sha(OUT/(name+'.log')));save();print(json.dumps({'name':name,'exit':row['exit']}),flush=True);assert row['exit']==0,name+' failed; retain and stop before next gate'
try:
 for name in normal:
  argv=list(common);argv[4]=str(OUT/name);argv+=['--gates',name];run(name,argv)
 ns=ROOT/'private/core-runtime-tools/bins/ns-exec';image=common[2];bins=common[3]
 prefix=['sudo','-n',str(ns),'python3',str(SOURCE/'tools/r92_validate.py'),'--namespace-command','python3']
 for name in recover:
  run('recovery-'+name,prefix+[str(SOURCE/'tools/r92_recovery_probe.py'),image,bins,str(OUT/('recovery-'+name)),'--cases',name,'--output-helper',str(ROOT/'private/core-runtime-tools/examples/output_lifecycle')])
 for name in compatible:
  run('compat-'+name,prefix+[str(SOURCE/'tools/r92_compat_probe.py'),image,bins,str(OUT/('compat-'+name)),'--cases',name])
 report.update(status='complete-original-remaining-gates',original_result_unchanged=sha(BASE/'r92/results.json')==report['original_result_sha256'])
 assert report['original_result_unchanged']
except BaseException as e:report.update(status='failed-preserved',error=repr(e));raise
finally:save()
