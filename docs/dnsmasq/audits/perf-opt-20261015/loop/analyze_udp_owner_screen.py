#!/usr/bin/env python3
import hashlib,json,statistics,struct,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from loop_owner_profile import validate_load_counts
from loop_owner_profile_analyze import stat_counts
from loop_hit_syscalls import parse,aggregate
from perf_opt_analyze import quantiles,compare
base=Path(sys.argv[1]); output=Path(sys.argv[2]); assert not output.exists()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
identity=json.loads((base/'identity.json').read_text()); progress=json.loads((base/'progress.json').read_text())
finished=json.loads((base/'complete.json').read_text()); assert finished['complete'] and finished['windows']==len(progress)==len(identity['windows'])
right=next(s for s in identity['artifacts'] if s!='F')
assert len(identity['artifacts'])==2
report={'scope':'Independent F/prototype UDP diagnostic; not full acceptance','prototype':right, 'identity_sha256':sha(base/'identity.json'),'progress_sha256':sha(base/'progress.json'),'rows':[],'summaries':{}}
for planned,row in zip(identity['windows'],progress):
 assert row['label']==planned['label'] and row['returncode']==0
 p=base/row['label']; load=json.loads((p/'client.json').read_text()); complete=json.loads((p/'complete.json').read_text()); scope=json.loads((p/'profile-scope.json').read_text()); process=json.loads((p/'process-identity.json').read_text()); tail=json.loads((p/'tree-tail.json').read_text())
 assert scope['elf_sha256']==identity['artifacts'][row['side']]['sha256']
 assert complete['valid_count_profile'] and complete['tree_tail_complete'] and tail['complete'] and not tail['remaining_children']
 validate_load_counts(load,5,20,row['rate'])
 validate_load_counts(json.loads((p/'prewarm.json').read_text()),0,5,200)
 count=load['warmup']['correct']+load['measurement']['correct']; assert count==complete['completed_operations']
 result={k:row[k] for k in ('label','observer','load','rate','pair','side')}
 result.update(operations=count,measurement=load['measurement'],warmup=load['warmup'])
 b,a=[(p/n).read_text().rsplit(')',1)[1].split() for n in ('cpu-before.stat','cpu-after.stat')]
 assert b[19]==a[19]==str(tail['root_starttime_ticks'])
 ticks=[int(a[i])-int(b[i]) for i in (11,12,13,14)]; assert all(t>=0 for t in ticks)
 hz=scope['clock_ticks_per_second'];result.update(cpu_ticks=sum(ticks),cpu_us_per_query=sum(ticks)/hz*1e6/count,cpu_tick_quantum_us_per_query=1e6/hz/count)
 result['throughput_queries_per_second']=load['measurement']['correct']/20
 sender=json.loads((p/'client-cpu.json').read_text());result['sender_cpu_percent']=100*(sender['user_seconds']+sender['system_seconds'])/(sender['elapsed_ns']/1e9)
 if row['observer']=='stat':
  result['pmu']=stat_counts((p/'perf-stat.csv').read_text(),(p/'perf-stat.stderr').read_text(),process['pid'],count)
  assert result['pmu']['all_unscaled']
  events=result['pmu']['events'];result['user_ipc']=events['instructions:u']['raw_count']/events['cycles:u']['raw_count']
 elif row['observer']=='strace':
  trace=parse((p/'syscalls.txt').open(),process['pid']); assert not trace['unparsed_lines'] and not trace['execs']
  result['syscalls']={'whole_tree':aggregate(trace['calls'],set(trace['calls']),count),'parents':trace['parents'],'incomplete':trace['incomplete_entries'],'exited':trace['exited']}
 else:
  lat=list(struct.iter_unpack('<QQQHHBBBB',(p/'client.latencies.bin').read_bytes())); lr=list(struct.iter_unpack('<QQ',(p/'client.send-lag.bin').read_bytes()));lag=dict(lr)
  assert len(lat)==len(lr)==len(lag)==load['measurement']['sent'] and {r[0] for r in lat}==set(lag)
  assert all(r[5]==0 and r[6]==1 and r[8]==0 for r in lat)
  result['latency_us']=quantiles([r[1]/1000 for r in lat]);result['send_lag_us']=quantiles([lag[r[0]]/1000 for r in lat]);result['scheduled_latency_us']=quantiles([(r[1]+lag[r[0]])/1000 for r in lat])
 result['files']={f.name:{'bytes':f.stat().st_size,'sha256':sha(f)} for f in p.iterdir() if f.is_file() and f.name!='dnsmasq-rs'}
 report['rows'].append(result)
for load in sorted({r['load'] for r in report['rows']}):
 rows=[r for r in report['rows'] if r['load']==load]
 plain={s:sorted([r for r in rows if r['side']==s and r['observer']=='none'],key=lambda r:r['pair']) for s in ('F',right)}
 assert all(len(v)==5 for v in plain.values())
 get=lambda side,key:[r[key] for r in plain[side]]
 cpu=compare(get('F','cpu_us_per_query'),get(right,'cpu_us_per_query'),[get('F','cpu_ticks'),get(right,'cpu_ticks')] if load=='low' else None)
 if load=='high':
  cpu['scope']='Variable-query saturation diagnostic; W/direction only, not fixed-cohort acceptance or a tick precision pass'
  cpu['precision_ok']=None
 throughput=compare(get('F','throughput_queries_per_second'),get(right,'throughput_queries_per_second'))
 throughput['direction']=('higher' if throughput['relative_change_pct']>0 else 'lower') if throughput['discernible'] else 'within_variation_or_resolution'
 item={'cpu':cpu,'throughput':throughput,'sender_cpu_percent':{s:get(s,'sender_cpu_percent') for s in plain},'latency':{},'send_lag':{},'pmu':{}}
 for q in ('p50','p95'):
  for key,target in [('latency_us','latency'),('send_lag_us','send_lag')]:
   item[target][q]=compare([r[key][q] for r in plain['F']],[r[key][q] for r in plain[right]])
 for side in plain:
  stats=[r for r in rows if r['side']==side and r['observer']=='stat']; assert len(stats)==3
  item['pmu'][side]={e:statistics.median(r['pmu']['events'][e]['per_operation'] for r in stats) for e in stats[0]['pmu']['events']}
  item['pmu'][side]['user_ipc']=statistics.median(r['user_ipc'] for r in stats)
 report['summaries'][load]=item
output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report['summaries'],indent=2))
