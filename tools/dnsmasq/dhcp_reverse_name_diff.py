#!/usr/bin/env python3
"""Actual C static reverse hosts names on DHCP ACK/INFORM, with no ubus assumption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
from dhcp_boot_service_diff import run
from dhcp_options_service_diff import packet
from dns_udp_refusal_diff import verify_reference


def fixtures():
    events=[{"label":"ack-client-name","kind":3,"name":b"client".hex(),"prl":[12,15]},
        {"label":"inform-no-client-name","kind":8,"ciaddr":"127.0.0.40","prl":[12,15]},
        {"label":"inform-explicit-client-name","kind":8,"ciaddr":"127.0.0.40","name":b"inform".hex(),"prl":[12,15]},
        {"label":"ack-without-client-name","kind":3,"prl":[12,15]}]
    for label,host,configured in [("short-host","fromhosts",None),
        ("matching-domain","fromhosts.pool.test",None),("case-domain","FromHosts.POOL.TEST",None),
        ("wrong-domain","fromhosts.other.test",None),("invalid-hostname","_invalid",None),
        ("configured-name-wins","fromhosts","fixed"),("no-static-host",None,None)]:
        extra="" if host is None else f"host-record={host},127.0.0.40\n"
        yield label,extra,configured,events


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--c",type=Path,required=True)
    p.add_argument("--c-identity",type=Path,help="Validated exact-image runner identity")
    p.add_argument("--rust",type=Path);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--inject-failure",action="store_true");args=p.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1" and sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,args.c_identity);out=args.output.resolve();assert "private" in out.parts
    out.mkdir(parents=True,exist_ok=False);cases=list(fixtures());(out/"plan.json").write_text(json.dumps(cases,indent=2)+"\n")
    report={"reference":identity,"planned":sum(len(row[3]) for row in cases),"compared":0,"matched":0,"failures":[],"runs":[]}
    for label,extra,configured,events in cases:
        folder=out/label;folder.mkdir();config=folder/"dnsmasq.conf"
        host="dhcp-host=02:00:00:00:00:01,127.0.0.40"+(f",{configured}" if configured else "")+",600s\n"
        config.write_text("no-hosts\nno-resolv\nno-ping\nleasefile-ro\nlisten-address=127.0.0.1\nport=53\n"
            "dhcp-authoritative\ndomain=pool.test\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n"
            +f"dhcp-leasefile={folder/'leases'}\n"+host+extra)
        expected=None
        for side,binary in [("c",args.c),("rust",args.rust)]:
            if binary is None:continue
            value=run(binary,config,folder/side,events,dns_port=53,request_builder=packet)
            report["runs"].append({"scenario":label,"side":side,**{k:v for k,v in value.items() if k!="rows"}})
            if value["status"]!="ok":report["failures"].append({"scenario":label,"side":side,"error":value.get("error")});continue
            assert len(value["rows"])==len(events)
            if side=="c":
                expected=value["rows"]
                if label=="short-host":assert [v for code,v in expected[0]["options"] if code==12]==[b"fromhosts".hex()]
            elif expected is not None:
                actual=value["rows"]
                if args.inject_failure and label=="short-host":actual[0]["reply"]=""
                for index,(left,right) in enumerate(zip(expected,actual,strict=True)):
                    report["compared"]+=1;report["matched"]+=left==right
                    if left!=right:report["failures"].append({"scenario":label,"step":index,"c":left,"rust":right})
    report["unexecuted"]=None if args.rust is None else report["planned"]-report["compared"]
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("runs","failures")}|{"failures":len(report["failures"])}))
    return int(bool(report["failures"]))


if __name__=="__main__":raise SystemExit(main())
