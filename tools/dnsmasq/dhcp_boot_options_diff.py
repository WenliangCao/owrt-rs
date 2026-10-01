#!/usr/bin/env python3
"""Actual C options 66/67 versus dhcp-boot fields, PRL, force and capacity."""
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
    normal="dhcp-option=66,option.test\ndhcp-option=67,option.img\n"
    boot="dhcp-boot=boot.img,boot.test,127.0.0.9\n"
    common=[{"label":"legacy-offer","kind":1},{"label":"empty-prl","kind":1,"prl":[]},
        {"label":"both-requested","kind":1,"prl":[66,67]},
        {"label":"ack-both","kind":3,"prl":[66,67]},
        {"label":"only-66","kind":1,"prl":[66]},
        {"label":"only-67","kind":1,"prl":[67]},
        {"label":"bootp-prl-ignored","kind":0,"prl":[66,67]},
        {"label":"nak","kind":3,"address":"127.0.0.99","prl":[66,67]}]
    yield "ordinary",normal,common
    yield "named-aliases","dhcp-option=option:tftp-server,option.test\ndhcp-option=option:bootfile-name,option.img\n",common[:4]+common[6:7]
    yield "force-both",normal.replace("dhcp-option=","dhcp-option-force="),common
    yield "force-only-server","dhcp-option-force=66,option.test\ndhcp-option=67,option.img\n",common[:3]+common[4:7]
    yield "force-only-file","dhcp-option=66,option.test\ndhcp-option-force=67,option.img\n",common[:3]+common[4:7]
    yield "no-override",normal+"dhcp-no-override\n",common[:3]+common[4:7]
    yield "boot-and-options",boot+normal,common
    yield "boot-force-no-override",boot+normal.replace("dhcp-option=","dhcp-option-force=")+"dhcp-no-override\n",common[:3]+common[4:7]
    yield "empty-boot-masks-fixed-fallback","dhcp-boot=\n"+normal,common[:3]+common[6:7]
    yield "file-only-boot","dhcp-boot=boot.img\n"+normal,common[:3]+common[6:7]
    yield "empty-no-argument","dhcp-option=66\ndhcp-option=67\n",common[:3]+common[6:7]
    yield "empty-strings","dhcp-option=66,\ndhcp-option=67,\n",common[:3]+common[6:7]
    yield "force-empty-no-argument","dhcp-option-force=66\ndhcp-option-force=67\n",common[:3]+common[6:7]
    yield "force-empty-strings","dhcp-option-force=66,\ndhcp-option-force=67,\n",common[:3]+common[6:7]
    yield "empty-options-under-boot",boot+"dhcp-option=66,\ndhcp-option=67\n",common[:3]+common[6:7]
    yield "field-boundaries","dhcp-option=66,"+"s"*64+"\ndhcp-option=67,"+"f"*128+"\n",common[:3]+common[6:7]
    yield "long-options","dhcp-option=66,"+"s"*255+"\ndhcp-option=67,"+"f"*254+"\n",[
        common[0],common[2],common[6],{"label":"larger-capacity","kind":1,"prl":[66,67],"maximum":1500}]
    yield "boot-and-long-options",boot+"dhcp-option=66,"+"s"*255+"\ndhcp-option=67,"+"f"*254+"\n",[
        common[0],common[2],common[6],{"label":"larger-capacity","kind":1,"prl":[66,67],"maximum":1500}]
    yield "fixed-file-reserves-overload","dhcp-option=66,"+"s"*255+"\ndhcp-option=67,option.img\n",[
        {"label":"sname-and-domain","kind":1,"prl":[66,15]}]
    yield "fqdn-does-not-disable-boot-nul",normal,[
        {"label":"fqdn-normal","kind":1,"prl":[66,67,81],"fqdn":b"\0\0\0fixed.pool.test".hex()},
        {"label":"fqdn-with-nul","kind":3,"prl":[66,67,81],"fqdn":b"\0\0\0fixed.pool.test\0".hex()},
        {"label":"legacy-cookie","kind":0,"cookie":"01020304","prl":[]},
    ]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--rust",type=Path)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--inject-failure",action="store_true")
    args=parser.parse_args();assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,None);out=args.output.resolve();assert "private" in out.parts
    out.mkdir(parents=True,exist_ok=False);cases=list(fixtures())
    (out/"plan.json").write_text(json.dumps(cases,indent=2)+"\n")
    report={"reference":identity,"planned_scenarios":len(cases),"planned_events":sum(len(row[-1]) for row in cases),
        "compared":0,"mismatches":[],"runs":[],"reference_events":0,"calibration":{}}
    for name,extra,events in cases:
        folder=out/name;folder.mkdir();config=folder/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=53\nno-ping\nleasefile-ro\n"
            "dhcp-authoritative\ndomain=pool.test\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n"
            "dhcp-host=02:00:00:00:00:01,127.0.0.40,fixed,600s\n"+f"dhcp-leasefile={folder/'leases'}\n"+extra)
        left=run(args.c,config,folder/"c",events,dns_port=53,request_builder=packet)
        report["runs"].append({"scenario":name,"side":"c",**{key:value for key,value in left.items() if key!="rows"}})
        report["reference_events"]+=len(left["rows"])
        if left["status"]!="ok":continue
        assert len(left["rows"])==len(events)
        if name=="ordinary":
            first=bytes.fromhex(left["rows"][0]["reply"])
            assert first[44:56]==b"option.test\0" and first[108:119]==b"option.img\0"
            assert all(code not in (66,67) for code,_ in left["rows"][0]["options"])
            assert [bytes.fromhex(value) for code,value in left["rows"][2]["options"] if code==66]==[b"option.test\0"]
            report["calibration"]["fixed_fields_and_nul_option"]=1
        if name=="boot-and-options":
            assert [bytes.fromhex(value) for code,value in left["rows"][2]["options"] if code==66]==[b"boot.test\0",b"option.test\0"]
            report["calibration"]["boot_does_not_suppress_configured_duplicate"]=1
        if args.rust:
            right=run(args.rust,config,folder/"rust",events,dns_port=53,request_builder=packet)
            report["runs"].append({"scenario":name,"side":"rust",**{key:value for key,value in right.items() if key!="rows"}})
            if right["status"]!="ok":continue
            assert len(right["rows"])==len(events)
            if args.inject_failure and name=="ordinary":right["rows"][0]["reply"]=""
            for index,(c,rust) in enumerate(zip(left["rows"],right["rows"],strict=True)):
                report["compared"]+=1
                if c!=rust:report["mismatches"].append({"scenario":name,"event":index,"c":c,"rust":rust})
    report["failures"]=[row for row in report["runs"] if row["status"]!="ok"]
    report["matched"]=report["compared"]-len(report["mismatches"])
    report["unexecuted"]=None if args.rust is None else report["planned_events"]-report["compared"]
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    report["tool_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ("runs","mismatches")}|{"mismatches":len(report["mismatches"])}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__=="__main__":raise SystemExit(main())
