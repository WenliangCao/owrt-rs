from pathlib import Path
import json,hashlib
b=Path('/dev/shm/full-f10-dhcp-20261014/private')
sha='2692c760be3719b15f4bcadb6c5a1445a9f37993a11c1369619550218e4c76eb'
records=[]
for group in ['candidate-final238e-hup','candidate-final238e-inotify']:
 path=b/group/'result.json';data=json.loads(path.read_text())
 for r in data['runs']:
  case=r['case'];incremental=group.endswith('-inotify')
  ptr={'lease.test','alias.test'} if incremental and case=='infinite' else ({'lease.test'} if incremental else ({'x.test','y.test'} if case=='infinite' else {'x.test'}))
  a=[['192.0.2.1']] if incremental else ([['192.0.3.186','192.0.3.185'],['192.0.3.185','192.0.3.186']] if case=='cross-alias' else [['192.0.3.186','192.0.3.185']])
  checks={'identity':r['identity']['sha256']==sha and r['rust_sha256']==sha,'process_healthy':r['alive'] and r['exit']==0 and not r.get('error'),'a_order_within_recorded_contract':r['after_a']['answer_order'] in a}
  observations=r['ptr_track_udp']+r['ptr_track_tcp'] if incremental else [r['after_ptr'],r['after_tcp_ptr']]
  if incremental:
   checks['six_observations']=len(r['ptr_track_udp'])==3 and len(r['ptr_track_tcp'])==3
  for index,o in enumerate(observations):
   rr=[x for x in o['semantics']['records'] if x['section']=='answer']
   checks[f'ptr{index}_complete_exact_fields']=(set(o['answer_order'])==ptr and len(o['answer_order'])==len(ptr) and o['semantics']['questions']==[['1.2.0.192.in-addr.arpa',12,1]] and o['semantics']['flags']==34176 and o['answer_count']==len(ptr) and all(x['name']=='1.2.0.192.in-addr.arpa' and x['type']==12 and x['class']==1 and x['ttl']==37 for x in rr))
  checks['one_stable_full_wire_track']=all(o['response_wire']==observations[0]['response_wire'] for o in observations)
  records.append({'group':group,'case':case,'raw_result_path':str(path),'raw_result_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'fixture_sha256':r['fixture_sha256'],'after_a':r['after_a']['answer_order'],'ordered_ptr_track':[o['answer_order'] for o in observations],'checks':checks,'passed_exact_membership_fields_and_track':all(checks.values()),'cross_process_order_proposal_pending':incremental and case=='infinite'})
report={'source_commit':'238e7ca4374b1889696f91816c1c239d7fe32baa','candidate_path':'/dev/shm/full-f10-product-20261014/private/release-238e/dnsmasq-rs','rust_sha256':sha,'c_sha256':'097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87','scope':'Five agreed retained-DHCP cases. Complete answer fields and within-process full tracks checked. The incremental infinite case requires separately reviewed source-bound cross-process PTR order qualification; this report does not claim broad wire equivalence.','cases':records,'passed_exact_membership_fields_and_track':all(r['passed_exact_membership_fields_and_track'] for r in records),'ordered_wire_qualification_status':'proposed-needs-root-and-independent-review','tools':{name:hashlib.sha256((b/name).read_bytes()).hexdigest() for name in ['candidate_final238e_hup.py','inotify_same_name_track.py']}}
assert len(records)==5 and report['passed_exact_membership_fields_and_track']
(b/'candidate-final238e-summary.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'cases':len(records),'passed_exact_membership_fields_and_track':True,'ordered_wire_qualification_status':report['ordered_wire_qualification_status']}))
