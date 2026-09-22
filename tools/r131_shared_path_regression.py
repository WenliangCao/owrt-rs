#!/usr/bin/env python3
"""Reuse the strict R130 evidence verifier for R131 registration/lookup/invoke guards."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
import r130_registration_report as evidence

ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=['run','report']);p.add_argument('plan',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();plan=evidence.read(a.plan)
    for key,path in plan['paths'].items():
        expected=plan['subjects'][key] if key in plan['subjects'] else plan[key+'_sha256']
        evidence.check(evidence.digest(ROOT/path)==expected,f'{key}: artifact identity')
    if a.mode=='run':
        a.output.mkdir(parents=True,exist_ok=False)
        (a.output/'plan.json').write_bytes(a.plan.read_bytes())
        for run in plan['runs']:
            name=f'{run["index"]:02d}-{run["label"]}'
            cmd=[sys.executable,str(ROOT/plan['paths']['driver']),'ubusd',str(ROOT/plan['paths'][run['label']]),str(a.output/name),'--pilot','--iterations','5000','--implementation','c' if run['label']=='c' else 'rs']
            for flag,key in [('recovery-gate','recovery_gate'),('guard','guard'),('benchmark','benchmark'),('workload-script','workload')]:cmd+=['--'+flag,str(ROOT/plan['paths'][key])]
            print('START',name,flush=True)
            with (a.output/(name+'.log')).open('xb') as log:subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,check=True)
            evidence.verify_window(a.output,plan,run)
            print('VERIFIED',name,flush=True)
        (a.output/'COMPLETE').touch()
    evidence.check((a.output/'COMPLETE').exists(),'incomplete series')
    evidence.check(evidence.read(a.output/'plan.json')==plan,'plan changed')
    rows=[evidence.verify_window(a.output,plan,x) for x in plan['runs']]
    comparisons={}; failures=[]
    for baseline in ('r124','c'):
        comparisons[baseline]={}
        for lane in evidence.LANES:
            comparisons[baseline][lane]={}
            for metric in evidence.METRICS:
                values=[]
                for block in range(1,7):
                    group={row['subject']:row for row in rows if row['block']==block}
                    values.append(100*(group['r131']['lanes'][lane]['metrics'][metric]/group[baseline]['lanes'][lane]['metrics'][metric]-1))
                s=evidence.summarize(values);comparisons[baseline][lane][metric]=s
                if baseline=='r124' and s['clear_regression']:failures.append(f'{lane}/{metric}')
    report={'scope':'R131 shared reply helper regression guard; no event workload here','plan_sha256':evidence.digest(a.plan),'windows':rows,'comparisons':comparisons,
            'decision':{'passed':not failures,'failures':failures,'rule':plan['acceptance']},
            'limits':['Six paired complete windows, not independent per-operation experiments.','No nine-component deployment or integration claim.']}
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print('COMPLETE',json.dumps(report['decision']),flush=True)
if __name__=='__main__':main()
