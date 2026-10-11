#!/usr/bin/env python3
"""Independent final-branch/main screen; fixed plan, retained first attempt."""
import fcntl, hashlib, json, math, os, pathlib, statistics, subprocess, sys, time
P=pathlib.Path
ROOT=P('/home/ubuntu/dnsmasq-fix-independent-20261011')
SOURCE=ROOT/'source'
TOOLS=SOURCE/'tools/dnsmasq'
OUT=ROOT/'private/perf'
IMAGE=P('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
NATIVE=P('/home/ubuntu/dnsmasq-final135-889fe4f5/private/native')
sys.path.insert(0,str(TOOLS))
from m6a_analyze import analyze_window
from m5_final_validation import remember_job_processes, stop_job_processes
from audit_20261011_pie_cost import foreign_workloads

def sha(p):
    h=hashlib.sha256()
    with P(p).open('rb') as f:
        for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
    return h.hexdigest()

def save(p,v):
    p=P(p); tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n');tmp.replace(p)

def prepare():
    OUT.mkdir(exist_ok=False)
    groups={}
    assets={str(p):sha(p) for p in [P(__file__),IMAGE/'usr/sbin/dnsmasq',NATIVE/'m6a_loadgen',NATIVE/'m6a_upstream']+[TOOLS/n for n in ('m6a_window.py','m6a_analyze.py','run_isolated.sh','m2_rootfs.py','dns_service_probe.py','m5_final_validation.py')]}
    for variant,folder in [('main','main-release'),('fix','release')]:
        elf=ROOT/'private'/folder/'dnsmasq-rs'
        receipt=elf.parent/'build.json';build=json.loads(receipt.read_text())
        assert build['features']=='' and build['opt_level']=='3'
        assert build['artifacts']==[dict(path=elf.name,bytes=elf.stat().st_size,sha256=sha(elf))]
        groups[variant]=dict(elf=str(elf),sha256=sha(elf),bytes=elf.stat().st_size,build=build)
        assets[str(elf)]=sha(elf);assets[str(receipt)]=sha(receipt)
    profiles=[('udp-hit','hit','hit',10000,4096),('tcp-hit','tcp','hit',10000,4096),('tcp-miss','tcp','miss',10000,4096),('dhcp-lease','dhcp','hit',20,256),('reload-concurrent','reload','hit',1000,256)]
    plan=dict(scope='Independent final branch versus main; Oracle scoped cost screen, not target-router or saturation qualification',groups=groups,assets=assets,windows=[],rule='No retries or discarded valid windows. Compare medians, W=(max-min)/median and paired direction. Flag >10% increase exceeding both Ws with all three pairs worse; below threshold does not prove equivalence. Retain errors and generator limits.')
    for n in range(1,4):
        for profile,scenario,tcp,rate,names in profiles:
            for variant in (['main','fix'] if n%2 else ['fix','main']):
                ident=f'{profile}-r{n}-{variant}'
                argv=['bash',str(TOOLS/'run_isolated.sh'),'python3',str(TOOLS/'m6a_window.py'),'--implementation','rs','--rust',groups[variant]['elf'],'--expected-rust-sha',groups[variant]['sha256'],'--image-root',str(IMAGE),'--loadgen',str(NATIVE/'m6a_loadgen'),'--upstream',str(NATIVE/'m6a_upstream'),'--preflight','--scenario',scenario,'--tcp-profile',tcp,'--round',str(n),'--rate',str(rate),'--cache-names',str(names),'--clients','20','--warmup','10','--duration','30','--saturation-seconds','0','--cpu-daemon','0','--cpu-upstream','1','--cpu-load','2','--cpu-control','3','--drain-sample-seconds','0,1,5','--drain-timeout-seconds','65','--seed',str(0x4d464900+n),'--output',str(OUT/ident)]
                plan['windows'].append(dict(id=ident,profile=profile,variant=variant,round=n,argv=argv))
    save(OUT/'plan.json',plan)
    print('prepared',len(plan['windows']),flush=True)

def verify(plan):
    for p,h in plan['assets'].items():assert sha(p)==h,p

def run():
    assert os.geteuid()==0
    plan=json.loads((OUT/'plan.json').read_text()); verify(plan)
    assert not (OUT/'run.json').exists()
    with P('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        busy=foreign_workloads();save(OUT/'foreign-before.json',busy);assert not busy,busy
        os.sched_setaffinity(0,{3})
        state=dict(status='running',started=time.time(),windows=[]);save(OUT/'run.json',state)
        try:
            for w in plan['windows']:
                verify(plan)
                rec=dict(id=w['id'],started=time.time());state['windows'].append(rec);save(OUT/'run.json',state)
                with (OUT/(w['id']+'.log')).open('wb') as log:
                    p=subprocess.Popen(w['argv'],cwd=SOURCE,stdout=log,stderr=log,start_new_session=True)
                    known={};started=time.monotonic()
                    try:
                        while p.poll() is None:
                            remember_job_processes(p,known)
                            if time.monotonic()-started>210:raise TimeoutError(w['id'])
                            try:p.wait(timeout=1)
                            except subprocess.TimeoutExpired:pass
                    finally:stop_job_processes(p,known)
                rec.update(returncode=p.returncode,ended=time.time());save(OUT/'run.json',state)
                print(json.dumps(rec),flush=True)
                if p.returncode:raise RuntimeError('failed window, no retry: '+w['id'])
            state['status']='complete'
        except BaseException as e:
            state['status']='incomplete';state['error']=repr(e);raise
        finally:
            state['ended']=time.time();save(OUT/'run.json',state)
    summarize()

def compare(a,b):
    ma,mb=statistics.median(a),statistics.median(b)
    wa=(max(a)-min(a))/ma if ma else 0;wb=(max(b)-min(b))/mb if mb else 0
    delta=mb/ma-1 if ma else 0;direction=sum(y>x for x,y in zip(a,b))
    return dict(main=a,fix=b,main_median=ma,fix_median=mb,relative_delta=delta,main_W=wa,fix_W=wb,worse_pairs=direction,flag=delta>.1 and delta>max(wa,wb) and direction==3)

def summarize():
    plan=json.loads((OUT/'plan.json').read_text());verify(plan)
    result=dict(scope=plan['scope'],plan_sha256=sha(OUT/'plan.json'),groups=plan['groups'],windows=[],comparisons=[],errors=[])
    for w in plan['windows']:
        folder=OUT/w['id']
        try:
            row=analyze_window(folder);save(folder/'independent-analysis.json',row)
            actual=json.loads((folder/'process-identity.json').read_text())
            assert actual['sha256']==plan['groups'][w['variant']]['sha256']
            assert row['methodology_valid'] and not row['analysis_errors'],row['analysis_errors']
            m=row['measurement'];errors={k:m['origin_counts'][k] for k in ('wrong','timeout','transport_error')}
            errors.update({'aux_'+k:v['errors'] for k,v in row['auxiliary'].items()})
            for phase in ('warmup','measurement'):
                errors.update({phase+'_'+k:row['load_counters'][phase][k] for k in ('wrong','timeout','transport_error')})
                errors[phase+'_scheduled_skipped']=row['load_counters'][phase].get('scheduled_skipped',0)
            if w['profile']=='dhcp-lease' and not row['behavior_checks']['dhcp_release_endstate']['leasefile_empty']:errors['leasefile_nonempty']=1
            if any(errors.values()) or m['generator_limited']:result['errors'].append(dict(id=w['id'],behavior=errors,limited=m['generator_limit_reasons']))
            metrics=dict(cpu_us_per_correct=m['cpu_us_per_correct'],p95_ns=m['latency_ns']['p95'],**m['resources']['sampled_tree_peaks'])
            result['windows'].append({**{k:v for k,v in w.items() if k!='argv'},'metrics':metrics,'errors':errors,'correct':m['origin_counts']['correct'],'correct_qps':m['origin_counts']['correct']/m['seconds'],'load_counts':{phase:{k:row['load_counters'][phase].get(k) for k in ('scheduled','sent','scheduled_skipped','correct','wrong','timeout','transport_error')} for phase in ('warmup','measurement')},'raw_inputs':row['input_sha256'],'analysis_sha256':sha(folder/'independent-analysis.json')})
        except Exception as e:result['errors'].append(dict(id=w['id'],error=repr(e)))
    result['complete']=len(result['windows'])==len(plan['windows'])
    if result['complete']:
        for profile in dict.fromkeys(w['profile'] for w in plan['windows']):
            for metric in ['cpu_us_per_correct','p95_ns','pss_kib','rss_kib','fd_count']:
                values={v:[next(r['metrics'][metric] for r in result['windows'] if r['profile']==profile and r['variant']==v and r['round']==n) for n in range(1,4)] for v in ('main','fix')}
                result['comparisons'].append(dict(profile=profile,metric=metric,**compare(values['main'],values['fix'])))
    save(OUT/'summary.json',result)
    print(json.dumps(dict(complete=result['complete'],errors=result['errors'],flags=[x for x in result['comparisons'] if x['flag']]),indent=2),flush=True)

if __name__=='__main__':globals()[sys.argv[1]]()
