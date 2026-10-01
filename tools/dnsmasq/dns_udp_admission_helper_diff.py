#!/usr/bin/env python3
"""Compare the admission helper with preserved actual-C UDP wire replies."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline",type=Path,required=True)
    parser.add_argument("--rust",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    assert "private" in out.parts and not out.exists();out.mkdir(parents=True)
    report=json.loads((args.baseline / "result.json").read_text());assert not report["failures"]
    trace=json.loads((args.baseline / "c/trace.json").read_text());assert trace["status"]=="ok"
    rows=[]
    for index,row in enumerate(trace["rows"]):
        if index < report["query_cases"]:
            operation="I"
            if row["response"] is None: expected="DROP"
            elif struct.unpack_from("!H",bytes.fromhex(row["response"]),2)[0]&15==0: expected="CONTINUE"
            else: expected=row["response"]
        elif row["label"].startswith("full-") or row["label"]=="invalid-while-full":
            operation="F";expected=row["response"]
        else: continue
        rows.append({"label":row["label"],"command":operation+" "+row["request"],"expected":expected})
    wire="\n".join(row["command"] for row in rows)+"\n";(out / "input").write_text(wire)
    run=subprocess.run([str(args.rust.resolve())],input=wire,text=True,capture_output=True)
    (out / "rust.stdout").write_text(run.stdout);(out / "rust.stderr").write_text(run.stderr)
    actual=run.stdout.splitlines();assert run.returncode==0 and len(actual)==len(rows)
    failures=[{"label":row["label"],"c_expected":row["expected"],"rust":result}
        for row,result in zip(rows,actual,strict=True) if row["expected"]!=result]
    result={"scope":"stateless UDP admission helper against actual C UDP; pending table recovery remains the real daemon gate",
        "reference":report["reference"],"rust_sha256":hashlib.sha256(args.rust.read_bytes()).hexdigest(),
        "observations":len(rows),"failures":failures,"rows":rows}
    (out / "result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="rows"}));return int(bool(failures))


if __name__=="__main__": raise SystemExit(main())
