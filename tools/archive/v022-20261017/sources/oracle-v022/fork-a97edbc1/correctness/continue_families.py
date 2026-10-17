import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/fork-a97edbc1';HERE=BASE/'correctness';SOURCE=ROOT/'source-a97edbc1';USE=BASE/'pgo/train-stage/use'
sys.path.insert(0,str(HERE));import run_family_gates as gate
sha=gate.sha
previous=json.loads((HERE/'families/result.json').read_text());assert json.loads((HERE/'families/state.json').read_text())['state']=='failed'
assert {x['family'] for x in previous['families']}=={'m5_dns_cache','m5_listeners','logging-all-scopes'}
assert {x['family'] for x in previous['families'] if not x['passed']}=={'logging-all-scopes'}
registry_path=SOURCE/'tools/dnsmasq/m5_final_families.draft.json';registry=json.loads(registry_path.read_text());assert len(registry['families'])==44
logging=next(f for f in registry['families'] if f['id']=='logging-all-scopes');expected=logging['steps'][0]['inventory']['ids']
old=HERE/'families/logging-all-scopes/logging-all-scopes';new=HERE/'logging-keepcaps-corrected';a=json.loads((old/'result.json').read_text());b=json.loads((new/'result.json').read_text())
assert len(a['scenarios'])==len(expected)==329 and {r['id'] for r in a['scenarios']}==set(expected)
assert len(b['scenarios'])==1 and b['scenarios'][0]['id']=='credential-fault-keepcaps' and not b['failures']
assert {r['id'] for r in a['scenarios'] if r['failures']}=={'credential-fault-keepcaps'}
assert all(v['rust_sha256']=='bd72ec58df820714800b5de2cbb8a84dfb3e45a901c634bada25191d95a073f7' and v['source_commit']=='a97edbc1382fc92b83110ed0822284aafeee7461' and v['c_sha256']=='097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87' for v in (a,b))
traces={}
for side in ('c','rust'):
 op=old/'credential-fault-keepcaps'/side;np=new/'credential-fault-keepcaps'/side
 assert json.loads((op/'fixture.json').read_text())==json.loads((np/'fixture.json').read_text())
 before=json.loads((op/'fault.json').read_text());after=json.loads((np/'fault.json').read_text());assert after['injected'] and len(after['events'])==1
 event=after['events'][0];assert event['number']==167 and event['args'][:2]==[8,1] and event['injected_result']==-1
 traces[side]={'original_args':before['events'][0]['args'],'corrected_args':event['args'],'corrected_trace_sha256':sha(np/'fault.json')}
assert traces['rust']['original_args'][0]==0x41555856 and traces['c']['original_args'][:2]==[8,1]
correction={'status':'qualified-after-injection-selector-correction','source_commit':a['source_commit'],'source_digest':'c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671','elf_sha256':a['rust_sha256'],'original_result':str(old/'result.json'),'original_result_sha256':sha(old/'result.json'),'original_job_exit':1,'original_scenarios':329,'unchanged_passing_scenarios_reused':328,'corrected_scenarios_rerun':1,'corrected_result':str(new/'result.json'),'corrected_result_sha256':sha(new/'result.json'),'tool_commit':'e89e436832093bb85e8447c1929d5bfb50a58365','output_comparator_unchanged':True,'fault_selector':'prctl syscall167 andoption8/value1; no unrelatedauxv interception','traces':traces,'unresolved_differences':0,'original_failure_retained':True}
gate.save(HERE/'logging-qualification.json',correction)
old_passed={r['family']:r for r in previous['families'] if r['passed']};excluded=set(old_passed)|{'logging-all-scopes'};remaining=[f for f in registry['families'] if f['id'] not in excluded];assert len(remaining)==41
out=HERE/'families-continuation';out.mkdir()
args=argparse.Namespace(source=SOURCE,elf=USE/'dnsmasq-rs',link_map=USE/'link.map',base_identity=ROOT/'private/correctness-inputs/family-base-v022-root.json',out=out,commit=a['source_commit'],jobs=3)
identities={str(p):sha(p) for p in (args.elf,args.link_map,args.base_identity,registry_path,SOURCE/'tools/dnsmasq/audit_20261011_families.py',SOURCE/'tools/dnsmasq/m5_final_validation.py')}
expected_jobs={f['id']+'-'+s['id'] for f in remaining for s in f['steps']} - {'m5_dns_endpoints-local-archive-gate'};assert len(expected_jobs)==53
report={'source':str(SOURCE),'commit':args.commit,'elf_sha256':sha(args.elf),'identities':identities,'expected_families':[f['id'] for f in remaining],'expected_jobs':sorted(expected_jobs),'passed':False,'families':[],'pauses':[],'scope':'remaining41original families only; no completed families rerun; keepcaps one corrected scenario separately qualified'}
completed=gate.supervise(args,remaining,identities,report)
assert len(report['families'])==41 and completed==expected_jobs and all(r['passed'] for r in report['families'])
report['passed']=True;report['completed_jobs']=len(completed);gate.save(out/'result.json',report);gate.save(out/'state.json',{'state':'complete','families':41,'jobs':53})
all_jobs=set(completed)|{j for r in old_passed.values() for j in r['job_ids']}|{'logging-all-scopes-paired'}
full_expected={f['id']+'-'+s['id'] for f in registry['families'] for s in f['steps']}-{'m5_dns_endpoints-local-archive-gate'};assert len(all_jobs)==67 and all_jobs==full_expected
summary={'status':'qualified','source_commit':args.commit,'source_digest':correction['source_digest'],'elf_sha256':sha(args.elf),'families':44,'jobs':67,'strict_original_jobs_passed':66,'job_qualified_after_one_fixture_selector_correction':1,'all_original_jobs_exit_zero':False,'unresolved_differences':0,'original_results_retained':True,'initial_result':str(HERE/'families/result.json'),'initial_result_sha256':sha(HERE/'families/result.json'),'continuation_result':str(out/'result.json'),'continuation_result_sha256':sha(out/'result.json'),'logging_correction':str(HERE/'logging-qualification.json'),'logging_correction_sha256':sha(HERE/'logging-qualification.json'),'job_ids':sorted(all_jobs)}
gate.save(HERE/'qualification.json',summary);print(json.dumps(summary),flush=True)
