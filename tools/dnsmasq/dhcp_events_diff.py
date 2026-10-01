#!/usr/bin/env python3
"""Compare exact C log_packet source calls to the real Rust local provider.

The C link wrapper observes ubus_event_bcast arguments without changing the
rfc2131 object. This gate is source notification intent, not delivery by ubusd.
No lease crosses expiry in this corpus; wire TTLs remain separate gates.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

import dhcp_message_metrics_diff as metrics
import local_answer_diff


def wire(kind,*,name=None,clid=None,**kwargs):
    data=metrics.packet(kind,**kwargs)[:-1]
    for code,value in [(12,name),(61,clid)]:
        if value is not None:data+=bytes([code,len(value)])+value
    return data+b"\xff"


def corpus():
    server="192.0.2.1";address="192.0.2.10"
    ack=lambda **kw:wire(3,requested=address,server=server,**kw)
    release=lambda **kw:wire(7,ciaddr=address,server=server,**kw)
    regular=[ack(name=b"client1"),wire(3,ciaddr=address),release(),release(),
        wire(7,ciaddr=address,server="192.0.2.2"),wire(7,ciaddr=address),
        wire(1,requested=address),wire(3,requested="192.0.2.99",server=server)]
    for label,extra in [("normal",""),("quiet","quiet-dhcp\n"),("quiet-log","quiet-dhcp\nlog-dhcp\n")]:
        yield label,extra,regular
    yield "configured-name","dhcp-host=02:00:00:00:00:01,192.0.2.10,fixed\n",[ack(name=b"client1"),release()]
    yield "inform-name-source","",[ack(name=b"client1"),
        wire(8,ciaddr=address),wire(8,ciaddr=address,client=2,name=b"other"),
        wire(8,ciaddr="192.0.2.11",client=2,name=b"standalone"),wire(8),
        wire(8,ciaddr="192.0.2.11",htype=0,hlen=0)]
    for label,htype,clid in [("cid-hardware",0,b"\0\xaa\xbb\xcc"),
            ("cid-whole",1,b"\x42\xaa\xbb\xcc"),("cid-eui64",24,b"\x1b\xaa\xbb\xcc")]:
        yield label,"",[ack(htype=htype,hlen=0,clid=clid,name=b"cid"),release(htype=htype,hlen=0,clid=clid)]
    yield "ignored-client","dhcp-host=02:00:00:00:00:01,ignore\n",[
        ack(name=b"client1"),wire(8,ciaddr=address),release()]


def build(reference,out):
    obj=reference/"dnsmasq";local_answer_diff.validate_reference_variant(obj)
    for name,expected in metrics.HASHES.items():assert metrics.digest(obj/name)==expected
    renamed=local_answer_diff.rename_main(obj,out)
    objects=sorted(path for path in obj.glob("*.o") if path.name not in ("lease.o","dnsmasq.o","dnsmasq-renamed.o"))
    deps=reference/"deps/lib";binary=out/"c-oracle"
    command=["cc",*local_answer_diff.REFERENCE_COPTS,"-O2","-Wall","-Wextra","-Werror",f"-I{obj}",
        f"-I{reference/'deps/include'}",str(Path(__file__).with_name("dhcp_events_driver.c")),
        *map(str,objects),str(renamed),f"-L{deps}",f"-Wl,-rpath,{deps}","-Wl,--wrap=ubus_event_bcast","-lubus","-lubox","-o",str(binary)]
    run=subprocess.run(command,text=True,capture_output=True)
    (out/"build.json").write_text(json.dumps({"command":command,"exit":run.returncode,"stdout":run.stdout,"stderr":run.stderr},indent=2)+"\n")
    run.check_returncode();return binary


def traces(stdout,planned):
    rows=[];pending=[]
    for line in stdout.splitlines():
        if line.startswith("EVENT "):pending.append(line)
        elif line.startswith("P "):rows.append(pending);pending=[]
        else:raise AssertionError("unexpected observer output")
    assert not pending and len(rows)==planned
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path,required=True);parser.add_argument("--rust",type=Path)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--inject-failure",action="store_true")
    args=parser.parse_args();assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert {row["ifname"] for row in json.loads(subprocess.check_output(["ip","-j","link"]))}=={"lo"}
    subprocess.run(["ip","address","add","192.0.2.1/24","dev","lo"],check=True)
    out=args.output.resolve();assert "private" in out.parts;out.mkdir(parents=True,exist_ok=False)
    oracle=build(args.reference_build.resolve(),out);cases=list(corpus())
    report={"scenarios":len(cases),"planned":sum(len(row[2]) for row in cases),"compared":0,"matched":0,"failures":[],"rows":[]}
    for label,extra,packets in cases:
        folder=out/label;folder.mkdir();config=folder/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nno-ping\nleasefile-ro\nport=0\ndhcp-authoritative\n"
            "dhcp-range=192.0.2.10,192.0.2.20,255.255.255.0,600s\n"+extra)
        payload="\n".join(metrics.send(packet) for packet in packets)+"\n";(folder/"input").write_text(payload)
        expected=None
        for side,binary in [("c",oracle),("rust",args.rust)]:
            if binary is None:continue
            run=subprocess.run([str(binary.resolve()),"-C",str(config)],input=payload,text=True,capture_output=True,timeout=10)
            (folder/f"{side}.stdout").write_text(run.stdout);(folder/f"{side}.stderr").write_text(run.stderr)
            if run.returncode:
                report["failures"].append({"scenario":label,"side":side,"exit":run.returncode});continue
            values=traces(run.stdout,len(packets))
            if side=="c":
                expected=values
                if label=="normal":assert len(values[0])==1 and len(values[2])==len(values[3])==1
                if label=="quiet":assert sum(map(len,values))==1 and len(values[3])==1
            elif expected is not None:
                if args.inject_failure and label=="normal":values[0]=[]
                for index,(left,right) in enumerate(zip(expected,values,strict=True)):
                    report["compared"]+=1;report["matched"]+=left==right
                    if left!=right:report["failures"].append({"scenario":label,"step":index,"c":left,"rust":right})
        report["rows"].append({"scenario":label,"steps":len(packets),"reference_events":None if expected is None else sum(map(len,expected))})
    report["unexecuted"]=None if args.rust is None else report["planned"]-report["compared"]
    report["c_sha256"]=metrics.digest(oracle);report["rust_sha256"]=None if args.rust is None else metrics.digest(args.rust)
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ("rows","failures")}|{"failures":len(report["failures"])}))
    return int(bool(report["failures"]))


if __name__=="__main__":raise SystemExit(main())
