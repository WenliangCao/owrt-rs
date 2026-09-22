#!/usr/bin/env python3
"""Collect the frozen R115 touched-interest CPU ablation on the router."""
import argparse,json,subprocess,sys
from pathlib import Path
from r105_user_event_paired_report import verify_window
from r113_memory_runner import REPO, HEALTH, digest, read

def verify_inputs(plan):
    for p,h in plan['files'].items(): assert digest(REPO/p)==h,(p,'changed')
    for root in plan['preflights']:
        r=read(REPO/root/'result.json')
        assert r['passed'] and r['cleanup_verified'] and r['same_boot'] and r['same_config'] and r['same_production_identity'] and r['same_host_mounts']
        assert r['candidate_sha256']==plan['candidate_sha256'] and r['exit']==0 and not r['installed'] and r['production_mode']=='stock'
    g=read(REPO/plan['oracle_gates']); assert g['passed'] and g['finished']
    assert {x['name'] for x in g['results']}==set(plan['required_gates']) and all(x['required'] and x['exit']==0 for x in g['results'])
    assert g['binary_sha256']['ubusd-rs']==plan['candidate_sha256']

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--plan',type=Path,default=REPO/'docs/reviews/r115-cpu-plan.json');ap.add_argument('--out',type=Path,default=REPO/'private/r115-event-interest/cpu');a=ap.parse_args()
    pp=a.plan.resolve();plan=read(pp);ph=digest(pp);verify_inputs(plan);out=a.out.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700);(out/'plan.json').write_bytes(pp.read_bytes())
    for n,s in plan['measurements'].items():(out/n).mkdir();(out/n/'plan.json').write_text(json.dumps(s,indent=2)+'\n')
    window=None
    try:
      for step in plan['schedule']:
        assert digest(pp)==ph;verify_inputs(plan);name=step['measurement'];spec=plan['measurements'][name];block=next(b for b in spec['blocks'] if b['block']==step['block']);window=out/name/f'{step["block"]:02d}'; control=plan['artifacts'][spec['subjects'][block['slots']['a']]];cand=plan['artifacts'][spec['subjects'][block['slots']['b']]]
        cmd=[sys.executable,str(REPO/'tools/r95_device_smoke.py'),'ubusd',str(REPO/cand),str(window),'--pilot','--iterations',str(spec['iterations']),'--before-candidate',str(REPO/control),'--benchmark',str(REPO/plan['benchmark_path']),'--workload-script',str(REPO/spec['workload_script']),'--guard',str(REPO/plan['guard_path']),'--recovery-gate',str(REPO/plan['recovery_gate_path'])]
        print('START',name,flush=True)
        with window.with_suffix('.log').open('wb') as log:subprocess.run(cmd,cwd=REPO,stdout=log,stderr=subprocess.STDOUT,check=True)
        verify_window(window,spec,block);assert digest(pp)==ph;verify_inputs(plan);print('VERIFIED',name,flush=True)
      reports={}
      for n,s in plan['measurements'].items():
        root=out/n;(root/'COMPLETE').touch();subprocess.run([sys.executable,str(REPO/'tools/r105_user_event_paired_report.py'),str(root),str(root/'plan.json'),str(root/'report.json')],cwd=REPO,check=True);reports[n]=read(root/'report.json')
      (out/'report.json').write_text(json.dumps({'plan_sha256':ph,'reports':reports,'acceptance':None,'all_windows_cleaned_and_stock':True,'scope':plan['scope']},indent=2)+'\n');(out/'COMPLETE').touch();print('COMPLETE no acceptance',flush=True)
    except BaseException as e:
      (out/'FAILED.json').write_text(json.dumps({'window':str(window),'type':type(e).__name__,'error':str(e)},indent=2)+'\n');raise
if __name__=='__main__':main()
