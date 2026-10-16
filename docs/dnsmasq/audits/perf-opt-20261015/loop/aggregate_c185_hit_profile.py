"""Combine existing single-window analyzer outputs using the original C/E formulas.
No raw perf parsing, symbolization, new estimator, measurement or retry.
"""
from collections import Counter
import argparse,hashlib,json,math,statistics
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
plan=json.loads((args.inputs/'plan.json').read_text());root=Path(plan['paths']['raw_root']);post=json.loads((args.inputs/'postflight.json').read_text());assert post['status']=='PASS_CAPTURE_ANALYSIS_AND_RAW_POSTFLIGHT';assert not args.output.exists()
stat=[];samples=[]
for window in plan['windows']:
 path=Path(window['output'])/'analysis.json';item=json.loads(path.read_text());assert item['completed_operations']==5000
 item['window']={k:v for k,v in window.items() if k not in ('argv','analysis_argv','output')};item['analysis_file_sha256']=sha(path)
 (stat if window['observer']=='stat' else samples).append(item)
assert len(stat)==12 and len(samples)==4
medians={}
for mode in ('udp','tcp'):
 for side in ('C','185'):
  rows=[r for r in stat if r['window']['mode']==mode and r['window']['side']==side];assert len(rows)==3
  results={}
  for event in ('instructions:u','instructions:k','cycles:u','cycles:k'):
   values=[r['events'][event]['per_operation'] for r in rows]
   results[event]={'values_per_query':values,'median':statistics.median(values),'minimum':min(values),'maximum':max(values)}
  for privilege in ('u','k'):
   values=[r['events']['instructions:'+privilege]['reported_count']/r['events']['cycles:'+privilege]['reported_count'] for r in rows]
   results['ipc:'+privilege]={'values':values,'median':statistics.median(values),'minimum':min(values),'maximum':max(values)}
  medians[mode+'-'+side]=results
for item in samples:
 key=item['window']['mode']+'-'+item['window']['side'];value=medians[key]['cycles:u']['median'];total=item['totals']['period'];assert total>0
 assert sum(row['period'] for row in item['ranges'])==total
 categories=Counter()
 for row in item['ranges']:
  categories[row['category']]+=row['period'];assert math.isclose(row['percent_all_period'],100*row['period']/total)
  row['cross_run_estimated_user_cycles_per_query']=row['period']/total*value
 assert math.isclose(sum(row['cross_run_estimated_user_cycles_per_query'] for row in item['ranges']),value)
 item['separate_stat_median_user_cycles_per_query']=value;item['category_periods']=dict(categories)
 item['sample_event_attributes']=post['sample_event_attributes'][item['window']['id']]
 item['perf_data_sha256']=post['raw_files'][item['window']['id']]['perf.data']
result={'scope':'Fresh exact-image C/immutable185 stat and user-cycle diagnostic; not frozen performance acceptance.','plan_sha256':sha(args.inputs/'plan.json'),'analysis_binding_sha256':sha(args.inputs/'analysis-binding.json'),'postflight_sha256':sha(args.inputs/'postflight.json'),'aggregator_sha256':sha(__file__),'raw_root':str(root),'stat_windows':stat,'medians_and_ranges':medians,'samples':samples,'estimate_formula':'sample period / all sample period * median(NEW same-side/transport independent stat user cycles / 5000 completed operations); cross-run estimate, not counted function cycles','failed_preflight_retained':sha(args.inputs/'preflight-attempt1-failure.json'),'all_stat_events_unscaled':all(x['all_unscaled'] for x in stat),'limitations':['Historical E measurements are not pooled or substituted.','One sample per side/transport identifies candidate hotspots, not stable function precision or causality.','Unknown/non-user/overlap periods remain in the full denominator.','Counter/scaling details and complete three-window ranges are retained.','IPC is computed from matching counters in each stat window.']}
args.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'output':str(args.output),'sha256':sha(args.output),'stat_windows':len(stat),'cycle_windows':len(samples),'all_stat_events_unscaled':result['all_stat_events_unscaled']}))
