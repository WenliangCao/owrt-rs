#!/usr/bin/env python3
"""Run fixed R131 memory windows or verify their retained evidence offline."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HEALTH = ('passed', 'cleanup_verified', 'same_boot', 'same_config',
          'same_production_identity', 'same_host_mounts')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    return json.loads(path.read_text())

def verify_inputs(plan):
    for item in [*plan['subjects'].values(), *plan['files'].values()]:
        assert sha(ROOT / item['path']) == item['sha256'], item['path']

def verify_window(out, spec, plan):
    window = out / spec['name']
    r = load(window / 'result.json')
    assert all(r[k] is True for k in HEALTH)
    assert r['installed'] is False and r['production_mode'] == 'stock' and r['exit'] == 0
    assert r['candidate_sha256'] == plan['subjects'][spec['subject']]['sha256']
    for key in ('driver','guard','recovery_gate'):
        assert r[key+'_sha256'] == plan['files'][key]['sha256']
    assert r['benchmark_sha256'] == plan['files'][spec['kind']+'_helper']['sha256']
    assert r['workload_sha256'] == plan['files'][spec['kind']+'_workload']['sha256']
    assert (window/'raw/COMPLETE').exists()
    for phase in ('before','after'):
        assert load(window/f'health-{phase}.json')['boot_id'] == plan['boot_id']
    rows = list(csv.DictReader((window/'raw/memory.csv').open()))
    assert len(rows) == (5 if spec['kind']=='idle' else 21)
    if spec['kind'] != 'idle':
        expected = [1024,8192,32768] if spec['kind']=='fanout' else [32768,262144,786432]
        count = 8 if spec['kind']=='fanout' else 1
        for size in expected:
            folder=window/'raw'/str(size)
            phases=[json.loads(s) for s in (folder/'helper.jsonl').read_text().splitlines()]
            assert [x['phase'] for x in phases] == ['READY','DELIVERED','CLOSED']
            assert all(x['payload_checked'] and x['listener_barrier'] for x in phases)
            assert all(x['received']==count for x in phases)
            assert [x['total_received'] for x in phases]==[count,count*2,count*2]
            assert phases[-1]['handlers_removed'] and not phases[-1]['holding']
            assert (folder/'COMPLETE').exists()
    return {**spec, 'memory': rows, 'raw_archive_sha256':sha(window/'raw.tar.gz'),
            'result_sha256':sha(window/'result.json')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['run','report'])
    p.add_argument('plan',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args(); plan=load(a.plan); verify_inputs(plan)
    if a.mode=='run':
        a.output.mkdir(parents=True,exist_ok=False)
        (a.output/'plan.json').write_bytes(a.plan.read_bytes())
        for spec in plan['runs']:
            verify_inputs(plan)
            subject=plan['subjects'][spec['subject']]; files=plan['files']
            cmd=[sys.executable,str(ROOT/files['driver']['path']),'ubusd',str(ROOT/subject['path']),str(a.output/spec['name']),
                 '--pilot','--iterations',str(spec['order']),'--implementation','c' if spec['subject']=='c' else 'rs']
            for flag,key in [('recovery-gate','recovery_gate'),('guard','guard'),('benchmark',spec['kind']+'_helper'),('workload-script',spec['kind']+'_workload')]:
                cmd+=['--'+flag,str(ROOT/files[key]['path'])]
            print('START',spec['name'],flush=True)
            with (a.output/(spec['name']+'.log')).open('xb') as log:
                subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,check=True,cwd=ROOT)
            verify_window(a.output,spec,plan)
            print('VERIFIED',spec['name'],flush=True)
        (a.output/'COMPLETE').touch()
    assert (a.output/'COMPLETE').exists()
    assert load(a.output/'plan.json')==plan
    windows=[verify_window(a.output,x,plan) for x in plan['runs']]
    report={'scope':'Physical AX3000T R131 idle, large-event and eight-handler batch residency',
            'plan_sha256':sha(a.plan),'windows':windows,'verified_windows':len(windows),
            'limits':['Snapshots, not allocator peak or kernel socket accounting.',
                      'Two runs per subject and workload; deterministic residency guard only, not statistical superiority.']}
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('COMPLETE',len(windows),flush=True)

if __name__=='__main__': main()
