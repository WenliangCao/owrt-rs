"""Frozen, bounded ordinary workload cost screen. No saturation, retries or product edits."""
from pathlib import Path
import fcntl,hashlib,json,os,statistics,subprocess,sys,time
ROOT=Path('/home/ubuntu/dnsmasq-audit-fix2-20261011');SOURCE=ROOT/'source';TOOLS=SOURCE/'tools/dnsmasq';OUT=ROOT/'private/performance'
IMAGE=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
sys.path.insert(0,str(TOOLS))
from m6a_analyze import analyze_window
from m5_final_validation import remember_job_processes,stop_job_processes
from audit_20261011_pie_cost import foreign_workloads

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def save(p,v):
 p=Path(p);tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n');tmp.replace(p)
def verify(plan):
 for p,h in plan['assets'].items():assert sha(p)==h,p

def prepare():
 OUT.mkdir(exist_ok=False);native=OUT/'native';native.mkdir()
 for name in ('m6a_loadgen','m6a_upstream'):
  subprocess.run(['cc','-O2','-std=c11','-Wall','-Wextra','-Werror',str(TOOLS/(name+'.c')),'-o',str(native/name)],check=True)
 groups={}
 assets=[Path(__file__),IMAGE/'usr/sbin/dnsmasq',native/'m6a_loadgen',native/'m6a_upstream',ROOT/'private/identity.json']+list(TOOLS.glob('*.py'))+[TOOLS/'run_isolated.sh',TOOLS/'m6a_loadgen.c',TOOLS/'m6a_upstream.c']
 for variant,folder in [('main','main-release'),('fix','release')]:
  elf=ROOT/'private'/folder/'dnsmasq-rs';receipt=elf.parent/'build.json';b=read(receipt)
  assert b['features']=='' and b['opt_level']=='3'
  assert b['artifacts']==[dict(path=elf.name,bytes=elf.stat().st_size,sha256=sha(elf))]
  groups[variant]=dict(elf=str(elf),sha256=sha(elf),bytes=elf.stat().st_size,build=b);assets.extend([elf,receipt])
 elf=IMAGE/'usr/sbin/dnsmasq';groups['c']=dict(elf=str(elf),sha256=sha(elf),bytes=elf.stat().st_size)
 assert groups['c']['sha256']=='097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
 profiles=[('udp-hit','hit','hit',2000,4096),('udp-miss','miss','miss',2000,4096),('tcp-hit','tcp','hit',500,4096),('tcp-miss','tcp','miss',500,4096),('dhcp-lease','dhcp','hit',20,256),('reload-tftp','reload','hit',500,256)]
 plan=dict(source_commit='6d001a77f06a0cf0111537507827f5399cb49a14',main_commit='be531cee49e366bb5044443d473944dbea45b87e',groups=groups,assets={str(p):sha(p) for p in assets},windows=[],scope='Oracle bounded ordinary workload screening, three rounds, not formal M6/router qualification',rule='No retries or discarded observations. Count behavior failures even when runner marks invalid. Cost signal: >10% median increase, exceeding both range/median dispersions, and all 3 paired directions higher. No signal does not establish equivalence. Skips or generator limits restrict interpretation.',measurement='5s warmup + 15s measured + barrier then 0/1/5s drain; cgroup CPU includes TCP descendants; 1Hz sampled memory peaks, PSS primary; C barrier only checks no children, Rust also returns to idle FD count; reload is one-line hosts plus 10 TFTP transfers/s, period5s; no saturation')
 for n in range(1,4):
  order=[['main','fix','c'],['fix','c','main'],['c','main','fix']][n-1]
  for profile,scenario,tcp,rate,names in profiles:
   for variant in order:
    ident=f'{profile}-r{n}-{variant}';rust=groups['fix' if variant=='c' else variant]
    argv=['sh',str(TOOLS/'run_isolated.sh'),'python3',str(TOOLS/'m6a_window.py'),'--implementation','c' if variant=='c' else 'rs','--rust',rust['elf'],'--expected-rust-sha',rust['sha256'],'--image-root',str(IMAGE),'--loadgen',str(native/'m6a_loadgen'),'--upstream',str(native/'m6a_upstream'),'--preflight','--scenario',scenario,'--tcp-profile',tcp,'--round',str(n),'--rate',str(rate),'--cache-names',str(names),'--clients','20','--warmup','5','--duration','15','--saturation-seconds','0','--reload-period','5','--cpu-daemon','0','--cpu-upstream','1','--cpu-load','2','--cpu-control','3','--drain-sample-seconds','0,1,5','--drain-timeout-seconds','30','--seed',str(0x46324900+n),'--output',str(OUT/ident)]
    plan['windows'].append(dict(id=ident,profile=profile,variant=variant,round=n,rate=rate,argv=argv))
 save(OUT/'plan.json',plan);print('PREPARED',len(plan['windows']),sha(OUT/'plan.json'),flush=True)

def run():
 assert os.geteuid()==0
 plan=read(OUT/'plan.json');verify(plan);assert not (OUT/'run.json').exists()
 with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  busy=foreign_workloads();save(OUT/'foreign-before.json',busy);assert not busy,busy
  os.sched_setaffinity(0,{3});state=dict(status='running',started=time.time(),windows=[]);save(OUT/'run.json',state)
  try:
   for w in plan['windows']:
    verify(plan);row=dict(id=w['id'],started=time.time());state['windows'].append(row);save(OUT/'run.json',state)
    with (OUT/(w['id']+'.log')).open('wb') as log:
     p=subprocess.Popen(w['argv'],cwd=SOURCE,stdout=log,stderr=log,start_new_session=True,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'));known={}
     try:
      while p.poll() is None:
       remember_job_processes(p,known)
       if time.time()-row['started']>180:raise TimeoutError(w['id'])
       try:p.wait(timeout=1)
       except subprocess.TimeoutExpired:pass
     finally:stop_job_processes(p,known)
    row.update(returncode=p.returncode,ended=time.time());save(OUT/'run.json',state);print(json.dumps(row),flush=True)
    # Keep failures; do not replace or retry a window. A catastrophic harness failure ends this attempt.
    if p.returncode and not (OUT/w['id']/'result.json').exists():raise RuntimeError('failed window without result: '+w['id'])
   state['status']='complete'
  except BaseException as e:state.update(status='incomplete',error=repr(e));raise
  finally:state['ended']=time.time();save(OUT/'run.json',state)
 summarize()

def compare(a,b):
 ma,mb=statistics.median(a),statistics.median(b);wa=(max(a)-min(a))/ma if ma else 0;wb=(max(b)-min(b))/mb if mb else 0
 delta=mb/ma-1 if ma else None;direction=sum(y>x for x,y in zip(a,b))
 return dict(baseline=a,fix=b,baseline_median=ma,fix_median=mb,relative_delta=delta,baseline_W=wa,fix_W=wb,worse_pairs=direction,flag=delta is not None and delta>.1 and delta>max(wa,wb) and direction==3)

def summarize():
 plan=read(OUT/'plan.json');verify(plan);result=dict(scope=plan['scope'],rule=plan['rule'],measurement=plan['measurement'],plan_sha256=sha(OUT/'plan.json'),groups=plan['groups'],windows=[],comparisons=[],errors=[])
 for w in plan['windows']:
  folder=OUT/w['id'];row={k:v for k,v in w.items() if k!='argv'};result['windows'].append(row)
  if not folder.exists():row['status']='not-run';continue
  # Retain all outcome paths, including result files the legacy runner labels invalid.
  row['raw_files']={str(p.relative_to(folder)):sha(p) for p in sorted(folder.rglob('*')) if p.is_file() and 'root' not in p.relative_to(folder).parts}
  try:
   raw=read(folder/'result.json');row['runner_accepted']=raw.get('accepted');row['runner_behavior_valid']=raw.get('behavior_valid');row['runner_errors']=raw.get('errors',[])
   analysis=analyze_window(folder);save(folder/'audit-analysis.json',analysis)
   actual=read(folder/'process-identity.json');assert actual['sha256']==plan['groups'][w['variant']]['sha256']
   row.update(methodology_valid=analysis['methodology_valid'],analysis_errors=analysis['analysis_errors'],analysis_sha256=sha(folder/'audit-analysis.json'))
   m=analysis['measurement'];load=read(folder/'load.json')
   errors={k:m['origin_counts'][k] for k in ('wrong','timeout','transport_error')}
   errors.update({'aux_'+k:v['errors'] for k,v in analysis['auxiliary'].items()})
   counts={phase:{k:load[phase].get(k) for k in ('scheduled','sent','scheduled_skipped','correct','wrong','timeout','transport_error','send_lag_sum_ns','send_lag_max_ns')} for phase in ('warmup','measurement')}
   for phase in counts:
    errors.update({phase+'_'+k:counts[phase][k] or 0 for k in ('scheduled_skipped','wrong','timeout','transport_error')})
   if w['profile']=='dhcp-lease' and not analysis['behavior_checks']['dhcp_release_endstate']['leasefile_empty']:errors['leasefile_nonempty']=1
   row.update(status='analyzed',metrics=dict(cpu_us_per_correct=m['cpu_us_per_correct'],p95_ns=m['latency_ns']['p95'],**m['resources']['sampled_tree_peaks']),load_counts=counts,correct=m['origin_counts']['correct'],correct_qps=m['origin_counts']['correct']/m['seconds'],errors=errors,generator_limited=m['generator_limited'],generator_limit_reasons=m['generator_limit_reasons'],send_lag_ns=m['send_lag_ns'])
   if not row['methodology_valid'] or row['analysis_errors'] or any(errors.values()) or row['generator_limited']:result['errors'].append(dict(id=w['id'],errors=errors,methodology_valid=row['methodology_valid'],analysis_errors=row['analysis_errors'],generator_limit_reasons=row['generator_limit_reasons']))
  except Exception as e:row.update(status='analysis-failed',error=repr(e));result['errors'].append(dict(id=w['id'],error=repr(e)))
 result['complete']=len(result['windows'])==len(plan['windows']) and all(r['status']=='analyzed' for r in result['windows'])
 if result['complete']:
  for profile in dict.fromkeys(w['profile'] for w in plan['windows']):
   for metric in ('cpu_us_per_correct','p95_ns','pss_kib','rss_kib','fd_count'):
    values={v:[next(r['metrics'][metric] for r in result['windows'] if r['profile']==profile and r['variant']==v and r['round']==n) for n in range(1,4)] for v in ('main','fix','c')}
    for baseline in ('main','c'):result['comparisons'].append(dict(profile=profile,metric=metric,baseline_variant=baseline,**compare(values[baseline],values['fix'])))
 save(OUT/'summary.json',result);print(json.dumps(dict(complete=result['complete'],errors=result['errors'],flags=[x for x in result['comparisons'] if x['flag']]),indent=2),flush=True)

if __name__=='__main__':globals()[sys.argv[1]]()
