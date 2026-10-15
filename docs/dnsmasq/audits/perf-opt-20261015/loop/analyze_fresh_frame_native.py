from pathlib import Path
import hashlib,json,statistics,sys
sys.path.insert(0,'tools/dnsmasq')
from perf_opt_analyze import compare
root=Path('private/perf-opt-20261015/next-cache-native-results/fresh-frame'); path=root/'native-result.json';x=json.loads(path.read_text())
planpath=Path('docs/dnsmasq/audits/perf-opt-20261015/dns/fresh-frame-native-plan.json');plan=json.loads(planpath.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert x['plan_sha256']==sha(planpath) and x['runner_sha256']==sha(Path('docs/dnsmasq/audits/perf-opt-20261015/dns/run_layout_native_screen.py'))
assert x['status']=='complete' and len(x['rows'])==240 and len(x['commands'])==244 and all(c['returncode']==0 for c in x['commands'])
summary={'scope':'Independent F/fresh-frame native hot15 screen, whole-process counts/CPU; prior data separate; not SDK or device acceptance','raw_result_sha256':sha(path),'plan_sha256':x['plan_sha256'],'runner_sha256':x['runner_sha256'],'artifacts':x['artifacts'],'rows':x['rows'],'summaries':[]}
for c in plan['phase_order']:
 for s in plan['scenes']:
  rows=[r for r in x['rows'] if r['candidate']==c and r['scene']==s]
  sides={side:sorted([r for r in rows if r['side']==side and r['observer']=='plain'],key=lambda r:r['pair']) for side in ('F',c)}
  assert all(len(v)==5 for v in sides.values())
  cpu=compare([r['cpu_ns']/r['probe']['operations'] for r in sides['F']],[r['cpu_ns']/r['probe']['operations'] for r in sides[c]])
  stats={side:[r for r in rows if r['side']==side and r['observer']=='stat'] for side in ('F',c)};assert all(len(v)==3 for v in stats.values())
  pmu={side:{event:statistics.median(r['stat']['events'][event]['per_operation'] for r in v) for event in ('instructions:u','cycles:u')} for side,v in stats.items()}
  for side,v in stats.items():pmu[side]['ipc']=statistics.median(r['stat']['user_ipc'] for r in v)
  change={event:(pmu[c][event]/pmu['F'][event]-1)*100 for event in pmu['F']}
  summary['summaries'].append({'candidate':c,'scene':s,'cpu_ns_per_operation':cpu,'pmu_medians':pmu,'pmu_relative_change_pct':change})
  print(c,s, 'CPU %',round(cpu['relative_change_pct'],3), 'W',round(cpu['W_pct'],3),'same',cpu['same_direction_pairs'],'decision',cpu['direction'],'cycle %',round(change['cycles:u'],3),'inst %',round(change['instructions:u'],3),'ipc',round(pmu['F']['ipc'],3),round(pmu[c]['ipc'],3))
(root/'native-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
