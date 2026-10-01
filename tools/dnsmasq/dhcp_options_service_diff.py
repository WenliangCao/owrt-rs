#!/usr/bin/env python3
"""Actual exact C untagged DHCP default overrides/suppression, PRL and BOOTP.

Scope: options 1/3/6/12/15/28 and bounded four-byte T1/T2. No tag/vendor,
encapsulation or other option types are implicitly accepted by this gate.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

from dhcp_boot_service_diff import packet as boot_packet,run
from dns_udp_refusal_diff import verify_reference

CODES=[1,3,6,12,15,28,58,59]


def packet(item,xid):
    wire=boot_packet(item,xid)
    for key,code in [("name",12),("fqdn",81)]:
        if key in item:
            name=bytes.fromhex(item[key]);wire=wire[:-1]+bytes([code,len(name)])+name+b"\xff"
    if "ciaddr" in item:wire=wire[:12]+socket.inet_aton(item["ciaddr"])+wire[16:]
    return wire


def fixtures():
    ordinary=[{"label":"offer-no-prl","kind":1},
        {"label":"offer-empty-prl","kind":1,"prl":[]},
        {"label":"offer-all","kind":1,"prl":CODES},
        {"label":"ack-all","kind":3,"prl":CODES},
        {"label":"only-netmask","kind":1,"prl":[1]},
        {"label":"only-router","kind":1,"prl":[3]},
        {"label":"bootp-empty-prl","kind":0,"prl":[]},
        {"label":"nak-no-options","kind":3,"address":"127.0.0.99","prl":CODES}]
    yield "defaults","",ordinary
    full="dhcp-option=1,255.255.0.0\ndhcp-option=3,0.0.0.0,127.0.0.254\ndhcp-option=6,0.0.0.0\ndhcp-option=12,wire-name\ndhcp-option=15,wire.test\ndhcp-option=28,127.0.255.255\ndhcp-option=58,180\ndhcp-option=59,420\n"
    yield "all-overrides",full,ordinary
    yield "inform-no-timers",full,[{"label":"inform","kind":8,"ciaddr":"127.0.0.40","prl":CODES}]
    yield "fqdn-independent","dhcp-option=12,wire-name\ndhcp-option=15,wire.test\n",[
        {"label":"fqdn-overrules-hostname-nul","kind":1,"prl":CODES+[81],
            "name":b"fixed\0".hex(),"fqdn":b"\0\0\0fixed.pool.test".hex()},
        {"label":"fqdn-null-termination","kind":3,"prl":CODES+[81],
            "fqdn":b"\0\0\0fixed.pool.test\0".hex()},
        {"label":"bootp-ignores-fqdn","kind":0,"prl":[],
            "fqdn":b"\0\0\0fixed.pool.test\0".hex()}]
    yield "all-suppressed","".join(f"dhcp-option={code}\n" for code in CODES[:6]),ordinary
    yield "empty-name-values","dhcp-option=12,\ndhcp-option=15,\n",ordinary[:4]+ordinary[6:7]
    yield "duplicate-router","dhcp-option=3,127.0.0.8\ndhcp-option=3,127.0.0.9\n",ordinary[:4]+ordinary[6:]
    yield "forced-overrides",full.replace("dhcp-option=","dhcp-option-force="),ordinary[:4]+ordinary[6:]
    yield "forced-then-suppressed","dhcp-option-force=3,127.0.0.9\ndhcp-option=3\n",ordinary[:4]+ordinary[6:7]
    yield "suppressed-then-forced","dhcp-option=3\ndhcp-option-force=3,127.0.0.9\n",ordinary[:4]+ordinary[6:7]
    yield "named-options","dhcp-option=option:netmask,255.255.0.0\ndhcp-option=option:router,127.0.0.9\ndhcp-option=option:dns-server,0.0.0.0,127.0.0.8\ndhcp-option=option:domain-name,named.test\ndhcp-option=option:T1,3m\ndhcp-option=option:T2,7m\n",ordinary[:4]+ordinary[6:7]
    yield "timer-bounds","dhcp-option=58,600\ndhcp-option=59,1\n",ordinary[:4]+ordinary[6:7]
    yield "timer-order","dhcp-option=58,300\ndhcp-option=59,120\n",ordinary[:4]+ordinary[6:7]
    yield "string-quoting",'dhcp-option=12,"wire,name"\ndhcp-option=15,"wire,domain"\n',ordinary[:4]+ordinary[6:7]
    yield "broken-client-nul","dhcp-option=12,wire-name\ndhcp-option=15,wire.test\n",[
        {"label":"offer-client-nul","kind":1,"name":b"fixed\0".hex(),"prl":[12,15]},
        {"label":"ack-client-nul","kind":3,"name":b"fixed\0".hex(),"prl":[12,15]},
        {"label":"bootp-client-nul-ignored","kind":0,"name":b"fixed\0".hex(),"prl":[]}]
    yield "bounded-vendor-capacity","dhcp-option=15,"+"d"*48+"\ndhcp-option=12,short-name\n",ordinary[:4]+ordinary[6:7]
    yield "long-strings","dhcp-option=12,"+"h"*255+"\ndhcp-option=15,"+"d"*255+"\n",[
        ordinary[2],ordinary[6],{"label":"larger-capacity","kind":1,"prl":CODES,"maximum":1500},
        {"label":"nul-at-255","kind":3,"name":b"fixed\0".hex(),"prl":CODES,"maximum":1500}]


def parser_cases():
    return [
        ("bad-address","dhcp-option=3,invalid\n"),
        ("empty-address-after-comma","dhcp-option=3,\n"),
        ("trailing-empty-address","dhcp-option=6,127.0.0.1,\n"),
        ("quoted-address",'dhcp-option=3,"127.0.0.1"\n'),
        ("internal-hostname-name","dhcp-option=option:hostname,wire\n"),
        ("internal-broadcast-name","dhcp-option=option:broadcast,127.255.255.255\n"),
        ("string-too-long","dhcp-option=15,"+"x"*256+"\n"),
    ]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--rust",type=Path)
    parser.add_argument("--output",type=Path,required=True);parser.add_argument("--inject-failure",action="store_true")
    args=parser.parse_args();assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,None);out=args.output.resolve();assert "private" in out.parts
    out.mkdir(parents=True,exist_ok=False);cases=list(fixtures());negative=parser_cases()
    (out/"plan.json").write_text(json.dumps({"service":cases,"parser":negative},indent=2)+"\n")
    report={"reference":identity,"planned_scenarios":len(cases),"planned_events":sum(len(row[-1]) for row in cases),
        "planned_parser_cases":len(negative),"compared":0,"mismatches":[],"runs":[],"reference_events":0,"calibration":{}}
    for name,extra,events in cases:
        folder=out/name;folder.mkdir();config=folder/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=53\nno-ping\nleasefile-ro\n"
            "dhcp-authoritative\ndomain=pool.test\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n"
            "dhcp-host=02:00:00:00:00:01,127.0.0.40,fixed,600s\n"+f"dhcp-leasefile={folder/'leases'}\n"+extra)
        left=run(args.c,config,folder/"c",events,dns_port=53,request_builder=packet)
        left["duplicate_warnings"]=(folder/"c/daemon.log").read_text().count("Ignoring duplicate dhcp-option ")
        report["runs"].append({"scenario":name,"side":"c",**{key:value for key,value in left.items() if key!="rows"}})
        report["reference_events"]+=len(left["rows"])
        if left["status"]!="ok":continue
        assert len(left["rows"])==len(events)
        if name=="all-suppressed":
            assert all(code not in CODES[:6] for row in left["rows"] for code,_ in row["options"])
            report["calibration"]["configured_empty_suppresses_defaults"]=1
        if name=="all-overrides":
            assert [value for code,value in left["rows"][2]["options"] if code==3]==["7f0000017f0000fe"]
            assert all(code not in CODES[:6] for code,_ in left["rows"][1]["options"])
            report["calibration"]["self_address_and_empty_prl"]=1
        if args.rust:
            right=run(args.rust,config,folder/"rust",events,dns_port=53,request_builder=packet)
            right["duplicate_warnings"]=(folder/"rust/daemon.log").read_text().count("Ignoring duplicate dhcp-option ")
            report["runs"].append({"scenario":name,"side":"rust",**{key:value for key,value in right.items() if key!="rows"}})
            if right["status"]!="ok":continue
            assert len(right["rows"])==len(events)
            report["compared"]+=1
            if left["duplicate_warnings"]!=right["duplicate_warnings"]:
                report["mismatches"].append({"scenario":name,"event":"duplicate-warnings","c":left["duplicate_warnings"],"rust":right["duplicate_warnings"]})
            if args.inject_failure and name=="all-overrides":right["rows"][0]["reply"]=""
            for index,(c,rust) in enumerate(zip(left["rows"],right["rows"],strict=True)):
                report["compared"]+=1
                if c!=rust:report["mismatches"].append({"scenario":name,"event":index,"c":c,"rust":rust})
    for name,extra in negative:
        folder=out/name;folder.mkdir();config=folder/"dnsmasq.conf";config.write_text(extra)
        codes=[]
        for side,binary in [("c",args.c),("rust",args.rust)]:
            if binary is None:continue
            result=subprocess.run([str(binary.resolve()),"--test","-C",str(config)],capture_output=True,timeout=3)
            (folder/f"{side}.stdout").write_bytes(result.stdout);(folder/f"{side}.stderr").write_bytes(result.stderr)
            codes.append(result.returncode)
        assert codes[0]==1,(name,codes)
        if args.rust:
            report["compared"]+=1
            if codes[1]!=codes[0]:report["mismatches"].append({"scenario":name,"event":"parser-rejection","c":codes[0],"rust":codes[1]})
    report["failures"]=[row for row in report["runs"] if row["status"]!="ok"]
    report["matched"]=report["compared"]-len(report["mismatches"])
    report["planned_observations"]=report["planned_events"]+len(cases)+len(negative)
    report["unexecuted"]=None if args.rust is None else report["planned_observations"]-report["compared"]
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    report["tool_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ("runs","mismatches")}|{"mismatches":len(report["mismatches"])}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__=="__main__":raise SystemExit(main())
