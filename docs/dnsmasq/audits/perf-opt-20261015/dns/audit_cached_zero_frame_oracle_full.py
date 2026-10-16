from pathlib import Path, PurePosixPath
import hashlib,json,math,re,statistics,struct,tarfile
ROOT=Path('/home/ubuntu/dnsmasq-perf-20261015/root/private')
p=ROOT/'oracle-cached-zero-frame-vs-e'; sp=ROOT/'oracle-cached-zero-frame-vs-e-summary.json'; summary=json.loads(sp.read_text())
j=lambda p:json.loads(p.read_text())
lines=lambda p:[json.loads(x) for x in p.read_text().splitlines()]
sha=lambda b:hashlib.sha256(b).hexdigest()
errors=[]; derived=[]; archives={}; files=0
identity=j(p/'identity.json');assert all(sha((p/name).read_bytes())==digest for name,digest in identity['inputs'].items());assert identity['affinity']==[2] and not (p/'failure.json').exists();progress=j(p/'progress.json');summaries={r['label']:r for r in summary['windows']}
def check(v,label):
 if not v:errors.append(label)
def eq(a,b,label):
 check(math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-9) if isinstance(a,float) or isinstance(b,float) else a==b,label)
def quant(a):
 a=sorted(a);n=len(a)
 return dict(n=n,min=a[0],p50=a[math.ceil(n/2)-1],p95=a[math.ceil(n*.95)-1],p99=a[math.ceil(n*.99)-1] if n>=10000 else None,max=a[-1])
scenes=['udp-hit','udp-miss','udp-mixed','tcp-hit','tcp-miss','dhcp-home6','dhcp','startup-small','config-small','hup-small','hup-large']
expected=[f'{s}-r{r}-{v}' for s in scenes for r in range(1,6) for v in (['c','rust'] if r%2 else ['rust','c'])]
check([r['label'] for r in progress]==expected,'110-alternating-order')
check(all(r['valid'] and not r['errors'] for r in progress),'all-controller-valid')
check(all(a['epoch']<b['epoch'] for a,b in zip(progress,progress[1:])),'serial-order')
check(set(x.name for x in (p/'runs').iterdir())==set(expected),'complete-run-set')
check(j(p/'complete.json')==dict(complete=True,smoke_only=False,windows=110,valid=110),'complete-marker')
check(identity['comparison']==dict(c='8b8082b9b77af986749ebbc75a625079ebbcf095cb919363dde3837a622e8d27',rust='9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99'),'artifact-identities')
for r in progress:
 label=r['label'];f=p/'runs'/label;m=j(p/(label+'.archive.json'));archive=p/(label+'.tar.gz')
 archives[label]=sha(archive.read_bytes());check(archives[label]==m['archive_sha256'],label+'/archive-hash')
 with tarfile.open(archive) as tar:
  seen=set();members={}
  for t in tar:
   q=PurePosixPath(t.name);check(not q.is_absolute() and '..' not in q.parts and q.parts[0]==label,label+'/safe-path')
   check(t.name not in seen,label+'/unique-member');seen.add(t.name)
   check(t.isfile() or t.isdir(),label+'/regular-or-directory')
   if t.isfile():members['/'.join(q.parts[1:])]=sha(tar.extractfile(t).read())
  check(members==m['files'],label+'/tar-file-hashes')
 actual={str(x.relative_to(f)):sha(x.read_bytes()) for x in f.rglob('*') if x.is_file()}
 check(actual==m['files'],label+'/extracted-file-hashes');files+=len(actual)
 check((f/'elf.sha256').read_text().split()[0]==identity['comparison'][r['side']],label+'/elf')
 if (f/'config.sha256').exists():check((f/'config.sha256').read_text().split()[0]==sha((f/'config').read_bytes()),label+'/config-hash')
 for line in (f/'tools.sha256').read_text().splitlines():
  h,name=line.split(maxsplit=1);check(h==identity['inputs'].get(Path(name).name),label+'/tool/'+Path(name).name)
 out=dict(r);life=(f/'lifecycle.jsonl').exists()
 if life:
  v=lines(f/'lifecycle.jsonl');check(len(v)==20 and all(x['ok'] and x['index']==i and x['latency_ns']==x['visible_ns']-x['start_ns'] for i,x in enumerate(v)),label+'/lifecycle-20-success')
  check(all(b['start_ns']-a['start_ns']>=10**9 for a,b in zip(v,v[1:])),label+'/period-1s')
  cpu,hz=map(int,re.search(r'children_cpu_usec=(\d+) clk_tck=(\d+)',(f/'lifecycle.stderr').read_text()).groups());check(hz==100,label+'/HZ')
  out.update(latency_ms=quant([x['latency_ns']/1e6 for x in v]),cpu_ticks=cpu*hz/1e6,cpu_operations=20,cpu_us_per_operation=cpu/20,rss_median_kib=statistics.median(x['rss_kib'] for x in v),rss_peak_kib=max(x['rss_kib'] for x in v),anon_peak_kib=max(x['anon_kib'] for x in v),file_peak_kib=max(x['file_kib'] for x in v),shmem_peak_kib=max(x['shmem_kib'] for x in v),tree_fd_peak=max(x['fds'] for x in v),parent_fd_peak=max(x['fds'] for x in v),observed_thread_peak=max(x['threads'] for x in v))
 else:
  check((f/'live.sha256').read_text().split()[0]==identity['comparison'][r['side']],label+'/live-elf')
  check((f/'netns.txt').read_bytes()==(f/'daemon.netns').read_bytes(),label+'/netns')
  load=j(f/'client.json');epoch=j(f/'epoch.json');dhcp=load['mode']=='dhcp';rate=100 if dhcp else 200
  check(load['rate']==rate and load['warmup_seconds']==5 and load['measurement_seconds']==20 and load['saturation_seconds']==0 and not load['interrupted'] and not load['output_failed'],label+'/load-parameters')
  check(load['clients']==(6 if r['scene']=='dhcp-home6' else 150 if dhcp else 8 if load['mode']=='tcp' else 32),label+'/clients')
  for phase,secs in [('warmup',5),('measurement',20)]:
   c=load[phase];check(all(c[k]==rate*secs for k in ['scheduled','sent','correct']) and not any(c[k] for k in ['timeout','wrong','transport_error','scheduled_skipped']),label+'/'+phase+'-counts')
  check(load['measurement']['correct_in_window']+load['measurement']['correct_after_window']==load['measurement']['correct'],label+'/completion-window-accounting')
  out['completion_window_accounting']={k:load['measurement'][k] for k in ['correct_in_window','correct_after_window']}
  lat=list(struct.iter_unpack('<QQQHHBBBB',(f/'client.latencies.bin').read_bytes()));lr=list(struct.iter_unpack('<QQ',(f/'client.send-lag.bin').read_bytes()));lag=dict(lr)
  check(len(lat)==len(lr)==len(lag)==rate*20 and {x[0] for x in lat}==set(lag),label+'/binary-counts')
  check(all(x[5]==0 and x[6]==1 and x[8]==0 for x in lat),label+'/binary-status')
  if not dhcp:check(all(x[4]==(1 if x[0]%800%10<7 else 28) for x in lat),label+'/qtype')
  out.update(latency_ms=quant([x[1]/1e6 for x in lat]),scheduled_latency_ms=quant([(x[1]+lag[x[0]])/1e6 for x in lat]),send_lag_ms=quant([lag[x[0]]/1e6 for x in lat]))
  before=lines(f/'before.jsonl')[0];after=lines(f/'after.jsonl')[0];check(len(before['processes'])==len(after['processes'])==1,label+'/reaped')
  a=before['processes'][0];b=after['processes'][0];check((a['pid'],a['starttime_ticks'])==(b['pid'],b['starttime_ticks']),label+'/same-parent')
  fields=['user_ticks','system_ticks','waited_child_user_ticks','waited_child_system_ticks'];check(all(b[k]>=a[k] for k in fields),label+'/cpu-monotonic')
  ticks=sum(b[k]-a[k] for k in fields);check(before['clock_ticks_per_second']==after['clock_ticks_per_second']==100,label+'/HZ');ops=load['warmup']['correct']+load['measurement']['correct']
  out.update(cpu_ticks=ticks,cpu_operations=ops,cpu_us_per_operation=ticks*10000/ops)
  samples=[x for x in lines(f/'resources.jsonl') if epoch['measurement_start_ns']<=x['monotonic_ns']<=epoch['measurement_end_ns']];check(bool(samples) and not any(x['tree_truncated'] for x in samples),label+'/resources')
  parents=[next(y for y in x['processes'] if (y['pid'],y['starttime_ticks'])==(a['pid'],a['starttime_ticks'])) for x in samples]
  out.update(rss_median_kib=statistics.median(x['rss_kib'] for x in parents),rss_peak_kib=max(x['rss_kib'] for x in parents),anon_peak_kib=max(x['rss_anon_kib'] for x in parents),file_peak_kib=max(x['rss_file_kib'] for x in parents),shmem_peak_kib=max(x['rss_shmem_kib'] for x in parents),tree_rss_peak_kib=max(x['tree_rss_kib'] for x in samples),tree_fd_peak=max(sum(y['fd_count'] for y in x['processes']) for x in samples),parent_fd_peak=max(x['fd_count'] for x in parents),thread_peak=max(sum(y['thread_count'] for y in x['processes']) for x in samples),process_peak=max(len(x['processes']) for x in samples))
  check(all(x['pss_kib']>=0 and x['private_clean_kib']>=0 and x['private_dirty_kib']>=0 for x in parents),label+'/PSS-USS-available')
  out.update(pss_peak_kib=max(x['pss_kib'] for x in parents),uss_peak_kib=max(x['private_clean_kib']+x['private_dirty_kib'] for x in parents),tree_pss_peak_kib=max(x['tree_pss_kib'] for x in samples),tree_uss_peak_kib=max(sum(y['private_clean_kib']+y['private_dirty_kib'] for y in x['processes']) for x in samples))
  up=j(f/'upstream.json');check(up['ttl']==120 and up['delay_us']==1000 and up['delay_queue_dropped']==0,label+'/upstream')
  check(up['total']['requests']==up['total']['replies'] and not any(up['total'][k] for k in ['invalid_queries','dropped_requests','disabled_requests']),label+'/upstream-completeness')
  if not dhcp:
   if load['profile']=='miss' and load['saturation_seconds']==0:
    check(load['mode']==r['scene'].split('-')[0] and not (f/'prewarm.json').exists() and not any(up['phases'][phase]['requests'] for phase in ['fault','recovery']) and up['total']['requests']==rate*25,label+'/upstream-miss-cohort-5000')
   else:check(up['phases']['steady']['requests']==dict(hit=0,miss=4000,mixed=800)[load['profile']],label+'/upstream-requests')
  if (f/'prewarm.json').exists():
   pre=j(f/'prewarm.json');check(all(pre['measurement'][k]==1000 for k in ['scheduled','sent','correct']) and not pre['interrupted'] and not pre['output_failed'],label+'/prewarm')
  if dhcp:
   d=lines(f/'client.dhcp-dora.jsonl');check(len(d)==load['clients']==load['warmup']['dora_correct'] and len({x['client'] for x in d})==load['clients'],label+'/DORA')
   out['dora_latency_ms']=quant([(x['ack_ns']-x['sent_ns'])/1e6 for x in d])
 for key,value in out.items():
  if key not in summaries[label]:continue
  if isinstance(value,dict):
   for k,v in value.items():eq(v,summaries[label][key][k],label+'/'+key+'/'+k)
  else:eq(value,summaries[label][key],label+'/'+key)
 derived.append(out)
comparisons={};resources={};gains=[];regressions=[]
for scene in scenes:
 by={s:sorted([r for r in derived if r['scene']==scene and r['side']==s],key=lambda x:x['round']) for s in ['c','rust']};comparisons[scene]={};resources[scene]={}
 for metric in ['p50_ms','p95_ms','cpu_us']+(['dora_p50_ms','dora_p95_ms'] if scene=='dhcp' else []):
  vals={s:[r['cpu_us_per_operation'] if metric=='cpu_us' else r['dora_latency_ms' if metric.startswith('dora') else 'latency_ms']['p50' if 'p50' in metric else 'p95'] for r in rows] for s,rows in by.items()}
  a,b=vals['c'],vals['rust'];am,bm=statistics.median(a),statistics.median(b);delta=bm-am;change=100*delta/am;W=100*max((max(a)-min(a))/am,(max(b)-min(b))/bm);pairs=sum((y-x)*delta>0 for x,y in zip(a,b))
  ticks={s:[r['cpu_ticks'] for r in rows] for s,rows in by.items()};precision=metric!='cpu_us' or min(ticks['c']+ticks['rust'])>=10 and abs(statistics.median(ticks['rust'])-statistics.median(ticks['c']))>8
  resolution=1 if ('small' in scene or 'large' in scene) and metric!='cpu_us' else 0
  significant=abs(change)>W and pairs>=4 and precision and abs(delta)>=resolution;direction=('slower' if delta>0 else 'faster') if significant else 'within_variation_or_resolution'
  out=dict(left_median=am,right_median=bm,relative_change_pct=change,W_pct=W,same_direction_pairs=pairs,precision_ok=precision,discernible=significant,direction=direction)
  if metric=='cpu_us':out['cpu_ticks']=ticks
  comparisons[scene][metric]=out
  for key in ['relative_change_pct','W_pct','same_direction_pairs','precision_ok','discernible','direction']:eq(out[key],summary['comparisons'][scene][metric][key],scene+'/'+metric+'/'+key)
  if significant and metric in ['p50_ms','p95_ms','cpu_us']:(regressions if delta>0 else gains).append(dict(scene=scene,metric=metric,**out))
 for key in ['rss_median_kib','rss_peak_kib','anon_peak_kib','file_peak_kib','shmem_peak_kib','tree_rss_peak_kib','tree_fd_peak','parent_fd_peak','thread_peak','process_peak','observed_thread_peak','pss_peak_kib','uss_peak_kib','tree_pss_peak_kib','tree_uss_peak_kib']:
  if not all(key in r for rows in by.values() for r in rows):continue
  vals={s:[r[key] for r in rows] for s,rows in by.items()};med={s:statistics.median(v) for s,v in vals.items()}
  resources[scene][key]=dict(baseline_median=med['c'],candidate_median=med['rust'],delta=med['rust']-med['c'],baseline_min_max=[min(vals['c']),max(vals['c'])],candidate_min_max=[min(vals['rust']),max(vals['rust'])])
  if key in summary['comparisons'][scene]:
   for s,k in [('c','left'),('rust','right')]:eq(vals[s],summary['comparisons'][scene][key][k]['rounds'],scene+'/'+key+'/'+s)
report=dict(status='PASS' if not errors else 'FAIL',scope='Independent remote read-only raw and statistical audit on one CPU after timing completed; existing audit reused, no reruns or pooling; raw remains Oracle during router test.',summary_sha256=sha(sp.read_bytes()),identity_sha256=sha((p/'identity.json').read_bytes()),progress_sha256=sha((p/'progress.json').read_bytes()),verified_archives=len(archives),verified_files=files,windows=len(derived),errors=errors,comparison_identities=identity['comparison'],archive_index_sha256=sha(json.dumps(archives,sort_keys=True).encode()),primary_improvements=gains,primary_regressions=regressions,comparisons=comparisons,resources=resources,derived_windows=derived)
Path(__file__).with_name('independent-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ['status','verified_archives','verified_files','windows','errors','primary_regressions']},indent=2))
print('GAINS',[(x['scene'],x['metric'],x['relative_change_pct']) for x in gains])
print('PSS/USS',{s:{k:v for k,v in row.items() if k in ['pss_peak_kib','uss_peak_kib']} for s,row in resources.items() if 'pss_peak_kib' in row})
