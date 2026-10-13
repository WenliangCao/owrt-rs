#!/usr/bin/env python3
"""Offline derivation and strict counter checks after the frozen run completes."""
import hashlib
import json
from pathlib import Path
import statistics

R=Path('/home/ubuntu/dnsmasq-fix3-repair-20261013/private')
OUT=R/'performance-types-01'
def read(path):return json.loads(Path(path).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def receipt(path):return dict(path=str(path),sha256=sha(path),bytes=Path(path).stat().st_size)
def counters(value):
    if isinstance(value,dict):
        if 'nr_throttled' in value:yield {k:value[k] for k in ('nr_throttled','throttled_usec')}
        for child in value.values():yield from counters(child)
    elif isinstance(value,list):
        for child in value:yield from counters(child)
plan=read(OUT/'plan.json');run=read(OUT/'run.json');summary=read(OUT/'summary.json');inv=read(OUT/'driver-invocation.json')
assert run['status']=='complete' and inv['returncode']==0
assert sha(R/'launch_performance_phase.py')==inv['launcher_sha256']
assert summary['complete'] and not summary['errors']
assert len(plan['windows'])==32
assert [w['id'] for w in plan['windows']]==[w['id'] for w in run['windows']]==[w['id'] for w in summary['windows']]
assert all(w['returncode']==0 for w in run['windows'])
check=dict(windows=[],totals={k:0 for k in ('scheduled','sent','correct','wrong','timeout','transport_error','scheduled_skipped')},
    cgroup_samples=0,maximum_nr_throttled=0,maximum_throttled_usec=0,pair_config_checks=[])
pairs={}
raw=dict(schema='dnsmasq-fix3-types-performance-raw-index-v1',source_commit=plan['source_commit'],
    plan=receipt(OUT/'plan.json'),ready=receipt(OUT/'ready-receipt.json'),run=receipt(OUT/'run.json'),
    invocation=receipt(OUT/'driver-invocation.json'),driver_log=receipt(OUT/'driver.log'),
    launcher=receipt(R/'launch_performance_phase.py'),full_summary=receipt(OUT/'summary.json'),windows=[])
for spec,row in zip(plan['windows'],summary['windows']):
    folder=OUT/spec['id'];data=read(folder/'result.json');load=data['measurement']['load']
    assert data['accepted'] and data['measurement_valid'] and row['valid_for_comparison']
    identity=read(folder/'process-identity.json');assert identity['sha256']==plan['groups'][spec['variant']]['sha256']
    foreign=read(OUT/(spec['id']+'.foreign-before.json'));assert not foreign
    config_sha=sha(folder/'config');pairs.setdefault((spec['profile'],spec['pair']),{})[spec['variant']]=config_sha
    proof=read(folder/'cache-proof.json');upstream=read(folder/'upstream.json')
    assert proof['capacity']==proof['filled_names']==proof['validated_names']==len(proof['rows'])==4096
    assert all(p['correct'] for p in proof['rows']) and proof['upstream_disabled'] and upstream['disabled']
    assert upstream['disabled_requests']==upstream['phases']['steady']['requests']==0
    phases={}
    for phase in ('warmup','measurement'):
        values=load[phase]
        assert values['scheduled']==values['sent']==values['correct']
        assert all(values[k]==0 for k in ('wrong','timeout','transport_error','scheduled_skipped'))
        phases[phase]={k:values[k] for k in check['totals']}
        for key in check['totals']:check['totals'][key]+=values[key]
    for point in counters(data):
        check['cgroup_samples']+=1
        for key in ('nr_throttled','throttled_usec'):
            check['maximum_'+key]=max(check['maximum_'+key],point[key])
    check['windows'].append(dict(id=spec['id'],actual_elf_sha256=identity['sha256'],config_sha256=config_sha,
        proof={k:v for k,v in proof.items() if k!='rows'},upstream_disabled_requests=0,
        tcp_connections=load['tcp_connections'],tcp_reconnections=load['tcp_reconnections'],phases=phases))
    files=row.pop('raw_files');controller=row.pop('controller_evidence')
    for name,digest in files.items():assert sha(folder/name)==digest,name
    for record in controller.values():assert sha(record['path'])==record['sha256']
    raw['windows'].append(dict(id=spec['id'],directory=str(folder),files=files,controller=controller))
for (profile,pair),config in pairs.items():
    assert config['main']==config['fix']
    check['pair_config_checks'].append(dict(profile=profile,pair=pair,sha256=config['main'],identical=True))
assert check['cgroup_samples']>0 and check['maximum_nr_throttled']==check['maximum_throttled_usec']==0
assert read(OUT/'foreign-after.json')==[]
check['foreign_after']=[]
summary['secondary_descriptive']=[]
for profile in dict.fromkeys(w['profile'] for w in plan['windows']):
    rows=[w for w in summary['windows'] if w['profile']==profile]
    for metric in ('cpu_us_per_correct','user_usec','system_usec','p95_ns','pss_kib','rss_kib','fd_count'):
        groups={v:[w['metrics'][metric] for w in rows if w['variant']==v] for v in ('main','fix')}
        a,b=(statistics.median(groups[v]) for v in ('main','fix'))
        summary['secondary_descriptive'].append(dict(profile=profile,metric=metric,values=groups,
            main_median=a,fix_median=b,median_ratio=b/a if a else None,
            interpretation='descriptive medians; no secondary inferential or cross-profile causal claim'))
summary.update(artifact_groups=plan['groups'],source_commit=plan['source_commit'],main_commit=plan['main_commit'],
    measured_artifact='Oracle release; full behavior families used separately identified SDK payload',
    result_scope='Oracle synthetic fixed-rate workloads. N4 primary comparisons and descriptive controls; not blanket performance equivalence.',
    ready=read(OUT/'ready-receipt.json'),controller=inv,counts_summary={k:v for k,v in check.items() if k not in ('windows','pair_config_checks')},
    collector=receipt(__file__))
for name,value in [('performance-types-derived.json',summary),('performance-types-raw-index.json',raw),('performance-types-counter-check.json',check)]:
    (R/name).write_text(json.dumps(value,indent=2)+'\n')
    print(json.dumps(dict(path=str(R/name),sha256=sha(R/name))))
