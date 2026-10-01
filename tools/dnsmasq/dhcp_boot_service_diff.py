#!/usr/bin/env python3
"""Exact C ordinary dhcp-boot response contract in a loopback-only namespace.

Synthetic boot metadata only; no boot files are served or fetched. The packet
comparison retains every response byte, including fields, option placement and
omission. Selecting ACK avoids renewal fuzz. BOOTP preserves arbitrary cookies.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from dns_udp_refusal_diff import verify_reference


def fixtures():
    basic = "dhcp-boot=synthetic.img,boot.test,127.0.0.9\n"
    events = [
        {"label":"offer-legacy","kind":1},
        {"label":"offer-empty-prl","kind":1,"prl":[]},
        {"label":"offer-66-67","kind":1,"prl":[66,67]},
        {"label":"ack-66-67","kind":3,"prl":[66,67]},
        {"label":"offer-66","kind":1,"prl":[66]},
        {"label":"offer-67","kind":1,"prl":[67]},
        {"label":"bootp","kind":0},
        {"label":"bootp-prl-ignored","kind":0,"prl":[66,67]},
        {"label":"bootp-legacy-cookie","kind":0,"cookie":"01020304"},
        {"label":"nak-clears-boot","kind":3,"prl":[66,67],"address":"127.0.0.99"},
    ]
    yield "basic",basic,events
    yield "no-override",basic+"dhcp-no-override\n",events[:8]
    for label,config in [
        ("file-only","dhcp-boot=synthetic.img\n"),
        ("empty-fields","dhcp-boot=,,127.0.0.9\n"),
        ("zero-next-server","dhcp-boot=synthetic.img,,0.0.0.0\n"),
        ("last-directive-wins",basic+"dhcp-boot=last.img,last.test,127.0.0.8\n"),
        ("quoted-comma",'dhcp-boot="synthetic,one.img","boot,name",127.0.0.9\n'),
        ("fixed-field-boundary","dhcp-boot="+"f"*128+","+"s"*64+",127.0.0.9\n"),
        ("option-254","dhcp-boot="+"f"*254+","+"s"*40+",127.0.0.9\n"),
        ("option-255","dhcp-boot="+"f"*70+","+"s"*255+",127.0.0.9\n"),
    ]:
        yield label,config,[events[i] for i in (0,2,3,6)]
    yield "large-capacity","dhcp-boot="+"f"*255+","+"s"*255+",127.0.0.9\n",[
        {"label":"both-long-default","kind":1,"prl":[66,67]},
        {"label":"both-long-1500","kind":1,"prl":[66,67],"maximum":1500},
    ]
    yield "occupied-file-overload","dhcp-boot="+"f"*128+","+"s"*255+",127.0.0.9\ndomain=boot.pool.test\n",[
        {"label":"only-sname-requested","kind":1,"prl":[66]},
        {"label":"fixed-file-blocks-overload","kind":1,"prl":[66,15]},
    ]


def packet(item, xid):
    data=bytearray(240);data[:3]=bytes([1,1,6]);data[4:8]=struct.pack("!I",xid)
    data[10:12]=b"\x80\0";data[28:34]=bytes([2,0,0,0,0,1])
    data[20:24]=socket.inet_aton("127.0.0.77")
    data[44:51]=b"oldname";data[108:115]=b"oldfile"
    data[236:240]=bytes.fromhex(item.get("cookie","63825363"))
    if item["kind"]:data.extend(bytes([53,1,item["kind"]]))
    if item["kind"]==3:
        data.extend(bytes([50,4])+socket.inet_aton(item.get("address","127.0.0.40")))
        data.extend(bytes([54,4])+socket.inet_aton("127.0.0.1"))
    if "prl" in item:data.extend(bytes([55,len(item["prl"])])+bytes(item["prl"]))
    if "maximum" in item:data.extend(bytes([57,2])+struct.pack("!H",item["maximum"]))
    data.append(255)
    return bytes(data)


def options(packet):
    result=[]
    def region(data):
        cursor=0
        while cursor<len(data):
            code=data[cursor];cursor+=1
            if code==255:return
            if code==0:continue
            assert cursor<len(data),"truncated TLV length"
            length=data[cursor];cursor+=1
            assert cursor+length<=len(data),"truncated TLV value"
            result.append([code,data[cursor:cursor+length].hex()]);cursor+=length
        raise AssertionError("missing END")
    region(packet[240:])
    overload=next((int(value,16) for code,value in result if code==52),0)
    if overload&1:region(packet[108:236])
    if overload&2:region(packet[44:108])
    return result


def run(binary,config,folder,events):
    folder.mkdir();trace={"status":"failed","rows":[]};process=None
    with (folder/"daemon.log").open("w") as log, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.bind(("0.0.0.0",68));client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        client.setsockopt(socket.SOL_SOCKET,25,b"lo\0");client.settimeout(.5)
        try:
            process=subprocess.Popen([str(binary.resolve()),"-d","-C",str(config)],stdout=log,stderr=log)
            deadline=time.monotonic()+5
            while True:
                assert process.poll() is None,"daemon exited before readiness"
                try:
                    with socket.create_connection(("127.0.0.1",5300),.03):break
                except OSError:assert time.monotonic()<deadline,"readiness timeout";time.sleep(.01)
            for index,item in enumerate(events):
                request=packet(item,0xa100+index);(folder/f"{index:02}.request").write_bytes(request)
                client.sendto(request,("255.255.255.255",67));response,peer=client.recvfrom(65535)
                (folder/f"{index:02}.response").write_bytes(response)
                assert len(response)>=300 and response[0]==2 and response[4:8]==request[4:8]
                assert response[236:240]==request[236:240]
                decoded=options(response);kind=next((value for code,value in decoded if code==53),None)
                expected=None if item["kind"]==0 else "02" if item["kind"]==1 else "06" if "address" in item else "05"
                assert kind==expected,(kind,expected)
                if not item["kind"]:assert len(response)==300
                trace["rows"].append({"label":item["label"],"request":request.hex(),"reply":response.hex(),"peer":list(peer),"options":decoded})
            trace["status"]="ok"
        except Exception as error:trace["error"]=repr(error)
        finally:
            if process is not None:
                if process.poll() is None:process.send_signal(signal.SIGTERM)
                try:process.wait(3)
                except subprocess.TimeoutExpired:process.kill();process.wait(3)
                trace["exit"]=process.returncode;trace["reaped"]=not Path(f"/proc/{process.pid}").exists()
                if trace["exit"]!=0 or not trace["reaped"]:trace["status"]="failed"
            (folder/"trace.json").write_text(json.dumps(trace,indent=2)+"\n")
    return trace


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--c-identity",type=Path)
    parser.add_argument("--rust",type=Path);parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--inject-failure",action="store_true");args=parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1" and sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,args.c_identity);out=args.output.resolve()
    assert "private" in out.parts and not out.exists();out.mkdir(parents=True)
    cases=list(fixtures());(out/"plan.json").write_text(json.dumps(cases,indent=2)+"\n")
    report={"reference":identity,"planned_scenarios":len(cases),"planned_events":sum(len(events) for _,_,events in cases),
        "compared":0,"mismatches":[],"runs":[],"reference_events":0,"calibration":{}}
    for name,extra,events in cases:
        folder=out/name;folder.mkdir();config=folder/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=5300\nno-ping\nleasefile-ro\n"
            "dhcp-authoritative\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n"
            "dhcp-host=02:00:00:00:00:01,127.0.0.40,600s\n"+f"dhcp-leasefile={folder/'leases'}\n"+extra)
        expected=run(args.c,config,folder/"c",events)
        report["runs"].append({"scenario":name,"side":"c",**{key:value for key,value in expected.items() if key!="rows"}})
        report["reference_events"]+=len(expected["rows"])
        if expected["status"]!="ok":continue
        assert len(expected["rows"])==len(events)
        if name=="basic":
            first=bytes.fromhex(expected["rows"][0]["reply"])
            assert first[108:122]==b"synthetic.img\0" and first[44:54]==b"boot.test\0"
            assert first[20:24]==socket.inet_aton("127.0.0.9")
            mutated=copy.deepcopy(expected["rows"]);mutated[0]["reply"]=""
            assert sum(a!=b for a,b in zip(expected["rows"],mutated,strict=True))==1
            report["calibration"]={"known_boot_fields":1,"one_mutation_detected":1}
        if args.rust:
            actual=run(args.rust,config,folder/"rust",events)
            report["runs"].append({"scenario":name,"side":"rust",**{key:value for key,value in actual.items() if key!="rows"}})
            if actual["status"]!="ok":continue
            assert len(actual["rows"])==len(events)
            if args.inject_failure and name=="basic":actual["rows"][0]["reply"]=""
            for index,(left,right) in enumerate(zip(expected["rows"],actual["rows"],strict=True)):
                report["compared"]+=1
                if left!=right:report["mismatches"].append({"scenario":name,"event":index,"c":left,"rust":right})
    report["failures"]=[row for row in report["runs"] if row["status"]!="ok"]
    report["matched"]=report["compared"]-len(report["mismatches"])
    report["unexecuted"]=None if args.rust is None else report["planned_events"]-report["compared"]
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    report["tool_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ("runs","mismatches")}|{"mismatches":len(report["mismatches"])}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__=="__main__":raise SystemExit(main())
