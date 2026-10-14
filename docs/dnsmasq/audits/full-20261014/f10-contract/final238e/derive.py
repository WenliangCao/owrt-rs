import collections,hashlib,json,os
from pathlib import Path
base=Path('/dev/shm/full-f10-contract-20261014/private')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda name:json.loads((base/name).read_text())
raw=read('final238e/result.json')
check=raw['contract_check']
identity=read('final238e.identity.json')
receipt=read('final238e.receipt.json')
source=Path(identity['source_path'])/'tools/dnsmasq'
identity['checker_probe_match_source']={name:sha(source/name)==identity['tools'][name] for name in ('f10_contract_check.py','f10_contract_probe.py')}
processes=[]
for proc in Path('/proc').iterdir():
    if proc.name.isdigit():
        try:
            root=os.readlink(proc/'root')
            if root.startswith(str(base/'final238e')):processes.append({'pid':int(proc.name),'root':root})
        except OSError:pass
mounts=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() if str(base/'final238e') in line]
cases=[]
for row in raw['cases']:
    failures=[d for d in check['failures'] if d.get('case')==row['case']]
    qualified=[d for d in check['qualified_ptr_order'] if d['case']==row['case']]
    assert row['completed'] and row['exit']==0 and row['exit_before_cleanup'] is None
    assert row['process_sha256']==identity['candidate_sha256']
    cases.append({'case':row['case'],'runtime_complete':True,'observations':len(row['observations']),
      'contract_passed':not failures,'failure_count':len(failures),'qualified_ptr_order':len(qualified)})
summary={'passed':check['passed'],'identity':identity,'receipt':receipt,
  'cases':cases,'case_count':len(cases),'dns_observation_count':sum(row['observations'] for row in cases),
  'runtime_errors':raw['errors'],'difference_counts':raw['difference_counts'],
  'failures':check['failures'],'qualified_ptr_order':check['qualified_ptr_order'],
  'ptr_sequence_checks':check['ptr_sequence_checks'],
  'same_state_repeated_families':sum(len(row['same_state_repeats']) for row in check['ptr_sequence_checks']),
  'cleanup':{'fixture_processes':processes,'host_mounts':mounts,'clean':not processes and not mounts},
  'raw_result_sha256':sha(base/'final238e/result.json'),
  'scope':'One planned 13-case run with --require-contract and unchanged 11-track/23-state observed C/C manifest. No added C runs.'}
assert not processes and not mounts
assert receipt['exit']==1 and not summary['passed']
assert receipt['candidate_unchanged'] and receipt['tool_snapshot_unchanged']
assert identity['source_bound_entries_used'] is False and check['source_bound_checks'] == []
write=lambda name,value:(base/name).write_text(json.dumps(value,indent=2)+'\n')
write('final238e.summary.json',summary)
selected=[base/'final238e',base/'tools-final238e']+[base/name for name in ('final238e.identity.json','final238e.command.json','final238e.receipt.json','final238e.log','final238e.summary.json','run_final238e.py','derive_final238e.py')]
files=[]
for path in selected:files.extend(path.rglob('*') if path.is_dir() else [path])
index={str(path.relative_to(base)):{'sha256':sha(path),'bytes':path.stat().st_size} for path in sorted(files) if path.is_file() and not path.is_symlink()}
write('final238e.raw-index.json',index)
print(json.dumps({'passed':summary['passed'],'cases':summary['case_count'],'observations':summary['dns_observation_count'],'failures':len(check['failures']),'raw_files':len(index)}))
