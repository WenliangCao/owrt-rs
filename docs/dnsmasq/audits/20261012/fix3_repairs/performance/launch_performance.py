#!/usr/bin/env python3
"""Run the already frozen plan and retain the real controller exit status."""
import hashlib
import json
from pathlib import Path
import subprocess
import time
R=Path('/home/ubuntu/dnsmasq-fix3-repair-20261013/private')
OUT=R/'performance-paired-01'
READY=R/'performance-ready.json'
DRIVER=R/'paired_tcp_records.py'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
assert sha(READY)=='ebbccd0a2b5a61ac5fed8cd7969d20dc8e77e35bed24aa63b29d3a7f75846544'
assert sha(OUT/'plan.json')=='6f52ba6de35fb7d81707ed9c1937bd61eb23bfd5f4141a52a98bd677a5837c82'
assert not (OUT/'run.json').exists() and not (OUT/'driver-invocation.json').exists()
argv=['sudo','-n','python3',str(DRIVER),'run','--out',str(OUT),'--ready-receipt',str(READY)]
record=dict(argv=argv,started_ns=time.time_ns(),driver_sha256=sha(DRIVER),plan_sha256=sha(OUT/'plan.json'),
            ready_receipt_sha256=sha(READY),launcher_sha256=sha(__file__))
def save():
    path=OUT/'driver-invocation.json';temp=path.with_suffix('.tmp')
    temp.write_text(json.dumps(record,indent=2)+'\n');temp.replace(path)
with (OUT/'driver.log').open('wb') as log:
    process=subprocess.Popen(argv,stdout=log,stderr=log)
    record['pid']=process.pid;save()
    record['returncode']=process.wait();record['ended_ns']=time.time_ns();save()
raise SystemExit(record['returncode'])
