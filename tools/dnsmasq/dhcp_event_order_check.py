#!/usr/bin/env python3
"""Assert the real local provider's C-source order before file/DNS/send.

This is an instrumented Rust check against dhcp.c/rfc2131.c ordering, not an
external notification-arrival differential. The separate source-field C gate
validates the actual notification arguments and presence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--probe",type=Path,required=True);parser.add_argument("--output",type=Path,required=True)
parser.add_argument("--inject-failure",action="store_true");args=parser.parse_args()
assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip","-j","link"]))}=={"lo"}
subprocess.run(["ip","address","add","192.0.2.1/24","dev","lo"],check=True)
out=args.output.resolve();assert "private" in out.parts;out.mkdir(parents=True,exist_ok=False)
try:
    run=subprocess.run([str(args.probe.resolve()),str(out/"observer")],capture_output=True,text=True,timeout=5)
except (OSError,subprocess.TimeoutExpired) as error:
    run=SimpleNamespace(returncode=None,stdout="",stderr=repr(error))
(out/"stdout.log").write_text(run.stdout);(out/"stderr.log").write_text(run.stderr)
checks=[{"check":"probe-exit","expected":0,"actual":run.returncode}]
if run.returncode==0:
    observed=json.loads((out/"observer/result.json").read_text())
    expected=["ack","dns","send-failure","release","dns"]
    if args.inject_failure:expected[0],expected[1]=expected[1],expected[0]
    checks.extend([{"check":"source-order","expected":expected,"actual":observed["trace"]},
        {"check":"final-file-empty","expected":True,"actual":observed["lease_file_empty"]}])
report={"planned":3,"unexecuted":3-len(checks),"checks":checks,"passed":sum(row["expected"]==row["actual"] for row in checks),
    "failed":sum(row["expected"]!=row["actual"] for row in checks),
    "probe_sha256":hashlib.sha256(args.probe.read_bytes()).hexdigest() if args.probe.is_file() else None}
(out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report));raise SystemExit(bool(report["failed"]))
