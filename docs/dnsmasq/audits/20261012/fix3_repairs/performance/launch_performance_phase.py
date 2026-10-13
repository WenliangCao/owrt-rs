#!/usr/bin/env python3
"""Start one frozen phase after its supplied completion receipt is verified."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('phase','plan-sha','ready-sha'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]*',args.phase):raise ValueError('simple phase label required')
    if any(not re.fullmatch(r'[0-9a-f]{64}',v) for v in (args.plan_sha,args.ready_sha)):
        raise ValueError('exact plan and ready SHA256 required')
    root=Path('/home/ubuntu/dnsmasq-fix3-repair-20261013/private')
    out=root/f'performance-{args.phase}-01'
    ready=root/f'performance-{args.phase}-ready.json'
    driver=root/'paired_tcp_records_phase.py'
    def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    assert sha(ready)==args.ready_sha and sha(out/'plan.json')==args.plan_sha
    assert not (out/'run.json').exists() and not (out/'driver-invocation.json').exists()
    argv=['sudo','-n','python3',str(driver),'run','--phase',args.phase,'--out',str(out),'--ready-receipt',str(ready)]
    record=dict(phase=args.phase,argv=argv,started_ns=time.time_ns(),driver_sha256=sha(driver),
        plan_sha256=args.plan_sha,ready_receipt_sha256=args.ready_sha,launcher_sha256=sha(__file__))
    def save():
        path=out/'driver-invocation.json';temporary=path.with_suffix('.tmp')
        temporary.write_text(json.dumps(record,indent=2)+'\n');temporary.replace(path)
    with (out/'driver.log').open('wb') as log:
        process=subprocess.Popen(argv,stdout=log,stderr=log)
        record['pid']=process.pid;save()
        record['returncode']=process.wait();record['ended_ns']=time.time_ns();save()
    raise SystemExit(record['returncode'])


if __name__=='__main__':main()
