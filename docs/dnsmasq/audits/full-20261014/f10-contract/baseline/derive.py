import collections,hashlib,json,os
from pathlib import Path
base=Path('/dev/shm/full-f10-contract-20261014/private')
paths=('baseline-c','baseline-rust','repeat-c','extra-rust','extra-repeat-c')
runs={name:json.loads((base/name/'result.json').read_text()) for name in paths}
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def normalized(value):
    value=dict(value)
    value['records']=sorted(json.dumps(rr,sort_keys=True) for rr in value['records'])
    return value

def compare(left,right):
    references={row['case']:row for row in left['cases']}
    rows=[]
    details=[]
    for actual in right['cases']:
        if actual['case'] not in references:
            continue
        expected=references[actual['case']]
        assert len(expected['observations'])==len(actual['observations'])
        counts=collections.Counter()
        for c,r in zip(expected['observations'],actual['observations']):
            assert c['label']==r['label']
            if c['semantics']!=r['semantics']:
                kind=('ptr-order-only' if c['type']==12 else 'forward-order-only') if normalized(c['semantics'])==normalized(r['semantics']) else 'rrset-ttl-count-or-header'
                counts[kind]+=1
                details.append({'case':actual['case'],'label':c['label'],'kind':kind,'c':c['semantics'],'actual':r['semantics']})
            elif c['response_wire']!=r['response_wire']:
                counts['wire-only']+=1
        rows.append({'case':actual['case'],'observations':len(actual['observations']),'differences':dict(counts)})
    total=collections.Counter()
    for row in rows:total.update(row['differences'])
    return {'case_count':len(rows),'observation_count':sum(row['observations'] for row in rows),'differences':dict(total),'cases':rows,'details':details}

joined={'cases':runs['baseline-rust']['cases']+runs['extra-rust']['cases']}
comparisons={'c_repeat_original':compare(runs['baseline-c'],runs['repeat-c']),
             'c_repeat_extra':compare(runs['repeat-c'],runs['extra-repeat-c']),
             'negative_340ed':compare(runs['repeat-c'],joined)}
for name,value in comparisons.items():
    (base/(name+'-differences.json')).write_text(json.dumps(value,indent=2)+'\n')
    value.pop('details')
processes=[]
for proc in Path('/proc').iterdir():
    if proc.name.isdigit():
        try:
            root=os.readlink(proc/'root')
            if root.startswith(str(base)):processes.append({'pid':int(proc.name),'root':root})
        except OSError:pass
mounts=[line for line in Path('/proc/self/mountinfo').read_text().splitlines() if str(base) in line]
summary={'source_commit':'340ed73e83e58ba845e0a645eb21e9ead0d0f108','negative_candidate_sha256':'edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d',
         'c_sha256':'097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
         'cases':list(dict.fromkeys(c['case'] for c in joined['cases'])),'comparisons':comparisons,
         'runs':{name:{'result_path':str(base/name/'result.json'),'result_sha256':sha(base/name/'result.json'),'case_count':value['case_count'],'driver_sha256':value['driver_sha256'],'errors':value['errors']} for name,value in runs.items()},
         'cleanup':{'fixture_processes':processes,'host_mounts':mounts},
         'scope':'Finite F10 semantic controls only; no 188/6020 rolling, memory gate, router access or product modification.'}
assert not processes and not mounts
assert all(not run['errors'] for run in runs.values())
assert set(comparisons['c_repeat_original']['differences'])<={'ptr-order-only'}
assert set(comparisons['c_repeat_extra']['differences'])<={'ptr-order-only'}
(base/'baseline-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
index={str(path.relative_to(base)):{'sha256':sha(path),'bytes':path.stat().st_size} for path in sorted(base.rglob('*')) if path.is_file() and not path.is_symlink() and path.name!='baseline-raw-index.json'}
(base/'baseline-raw-index.json').write_text(json.dumps(index,indent=2)+'\n')
print(json.dumps({'comparisons':{name:{'observations':value['observation_count'],'differences':value['differences']} for name,value in comparisons.items()},'raw_files':len(index)}))
