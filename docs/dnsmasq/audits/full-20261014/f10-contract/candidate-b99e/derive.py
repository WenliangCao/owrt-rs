import collections,hashlib,json,os
from pathlib import Path
base=Path('/dev/shm/full-f10-contract-20261014/private')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda name:json.loads((base/name).read_text())
raw=read('candidate-b99e/result.json')
identity=read('candidate-b99e.identity.json')
receipt=read('candidate-b99e.receipt.json')
baseline=read('baseline-summary.json')
refs={r['case']:r for r in read('repeat-c/result.json')['cases']}
cases=[]
for row in raw['cases']:
    diffs=[d for d in raw['differences'] if d['case']==row['case']]
    strict=[d for d in diffs if d['kind']!='ptr-order-only']
    checks={'completed':row['completed'],'exit_zero':row['exit']==0,'alive_before_cleanup':row['exit_before_cleanup'] is None,
      'elf_matches':row['process_sha256']==identity['candidate_sha256'],'ready_after':row['ready_after']==['192.0.2.41'],
      'observation_count_matches':len(row['observations'])==len(refs[row['case']]['observations']),
      'set_header_ttl_count_tc_and_forward_order_match':not strict}
    if 'truncation_checks' in row:checks.update(row['truncation_checks'])
    if 'dhcp' in row:checks['dhcp_ack']=row['dhcp']['decoded']['message_type']==5
    cases.append({'case':row['case'],'passed':all(checks.values()),'checks':checks,'observations':len(row['observations']),
      'difference_counts':dict(collections.Counter(d['kind'] for d in diffs)),
      'strict_failures':strict,'ptr_order_differences':diffs if not strict else [d for d in diffs if d['kind']=='ptr-order-only']})
processes=[]
for proc in Path('/proc').iterdir():
    if proc.name.isdigit():
        try:
            root=os.readlink(proc/'root')
            if root.startswith(str(base/'candidate-b99e')):processes.append({'pid':int(proc.name),'root':root})
        except OSError:pass
mounts=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() if str(base/'candidate-b99e') in line]
cleanup={'fixture_processes':processes,'host_mounts':mounts,'clean':not processes and not mounts}
summary={'passed':all(row['passed'] for row in cases) and cleanup['clean'] and receipt['exit']==0 and receipt['candidate_unchanged'],
  'identity':identity,'receipt':receipt,'cleanup':cleanup,'cases':cases,'case_count':len(cases),
  'dns_observation_count':sum(row['observations'] for row in cases),
  'matches_c_including_ptr_order':raw['matches_c'],'set_and_forward_order_match_c':raw['set_and_forward_order_match_c'],
  'difference_counts':raw['difference_counts'],'strict_failures':[d for d in raw['differences'] if d['kind']!='ptr-order-only'],
  'ptr_order_control':{name:{k:v for k,v in value.items() if k!='cases'} for name,value in baseline['comparisons'].items() if name.startswith('c_repeat')},
  'negative_control':{k:v for k,v in baseline['comparisons']['negative_340ed'].items() if k!='cases'},
  'raw_result_sha256':sha(base/'candidate-b99e/result.json'),'scope':'Only the planned 13 finite F10 cases; original C/340ed evidence retained, no rolling/memory/router work.'}
write=lambda name,value:(base/name).write_text(json.dumps(value,indent=2)+'\n')
write('candidate-b99e.summary.json',summary)
selected=[base/'candidate-b99e',base/'tools-b99e']+[base/name for name in ('candidate-b99e.identity.json','candidate-b99e.command.json','candidate-b99e.receipt.json','candidate-b99e.log','candidate-b99e.summary.json','run_candidate_b99e.py','derive_candidate_b99e.py')]
files=[]
for path in selected:files.extend(path.rglob('*') if path.is_dir() else [path])
index={str(path.relative_to(base)):{'sha256':sha(path),'bytes':path.stat().st_size} for path in sorted(files) if path.is_file() and not path.is_symlink()}
write('candidate-b99e.raw-index.json',index)
print(json.dumps({'passed':summary['passed'],'cases':summary['case_count'],'observations':summary['dns_observation_count'],'differences':summary['difference_counts'],'raw_files':len(index)}))
assert summary['passed']
