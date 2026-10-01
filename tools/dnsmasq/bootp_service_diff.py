#!/usr/bin/env python3
"""Ordinary BOOTP main-service behavior against exact C in a private netns.

Raw replies, committed lease files, and immediately visible DNS come from the
actual C daemon. C runs first with the same configuration and concrete inputs.
PXE, relay, tagged bootp-dynamic and main/ubus metric publication remain distinct.
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

from dhcp_daemon_smoke import decode
from dhcp_lease_lifecycle import rows
from dns_service_probe import query as dns_query, semantics as dns_semantics
from dns_udp_refusal_diff import verify_reference

# Frozen from actual C c-baseline-01 before the paired implementation gate.
C_COUNTS={"static-named":(6,4),"static-no-configured-name":(2,2),"tagless-dynamic":(4,4),
    "dynamic-lease-capacity":(3,2),"static-occupied":(1,0),"bootp-does-not-steal-static-mac":(3,2),
    "dynamic-restored":(2,2),"bootp-disabled-and-invalid-hardware":(3,0),"client-id-does-not-authorize-bootp":(1,0)}


def event(label, client=1, **extra): return {"label":label,"client":client,**extra}


def packet(item, xid):
    data=bytearray(240);data[:3]=bytes([1,item.get("htype",1),item.get("hlen",6)])
    data[4:8]=struct.pack("!I",xid);data[10:12]=struct.pack("!H",0x8000 if item.get("broadcast",True) else 0)
    if item.get("ciaddr"):data[12:16]=socket.inet_aton(item["ciaddr"])
    data[28:34]=bytes([2,0,0,0,0,item["client"]])
    data[236:240]=bytes.fromhex(item.get("cookie","63825363"))
    options=bytearray()
    if item.get("release"):
        options+=bytes([53,1,7,54,4])+socket.inet_aton("127.0.0.1")
    for key,code in [("prl",55),("name",12),("fqdn",81),("clid",61)]:
        if key in item:
            value=bytes(item[key]) if key=="prl" else bytes.fromhex(item[key])
            options+=bytes([code,len(value)])+value
    data.extend(options+b"\xff")
    return bytes(data)


def fixtures(now):
    named="dhcp-host=02:00:00:00:00:01,127.0.0.40,fixed,900\n"
    yield "static-named",named,b"",4,[
        event("static-broadcast",dns=[("fixed",1),("fixed.pool.test",1),("40.0.0.127.in-addr.arpa",12)]),
        event("same-mac-unicast",broadcast=False,ciaddr="127.0.0.40",dns=[("fixed.pool.test",1)]),
        event("bootp-ignores-empty-prl",prl=[],dns=[("fixed",1)]),
        event("legacy-cookie-preserved",cookie="01020304",dns=[("fixed",1)]),
        event("unknown-mac-rejected",client=2,dns=[("fixed.pool.test",1)]),
        event("release-removes-name",release=True,broadcast=False,ciaddr="127.0.0.40",dns=[("fixed",1),("fixed.pool.test",1),("40.0.0.127.in-addr.arpa",12)]),
    ]
    yield "static-no-configured-name","dhcp-host=02:00:00:00:00:01,127.0.0.40\n",b"",4,[
        event("client-hostname-not-a-bootp-name",name=b"guest".hex(),dns=[("guest",1),("guest.pool.test",1)]),
        event("client-fqdn-not-a-bootp-name",fqdn=(b"\0\0\0other.pool.test").hex(),dns=[("other",1),("other.pool.test",1)]),
    ]
    yield "tagless-dynamic","bootp-dynamic\n",b"",4,[
        event("dynamic-client-name-ignored",name=b"guest".hex(),dns=[("guest",1),("guest.pool.test",1)]),
        event("dynamic-retry-empty-prl",prl=[]),
        event("second-dynamic-client",client=2),
        event("third-dynamic-client",client=3),
    ]
    yield "dynamic-lease-capacity","bootp-dynamic\n",b"",1,[
        event("first-lease"),event("capacity-refusal",client=2),event("same-mac-still-served"),
    ]
    yield "static-occupied",named,b"0 02:00:00:00:00:08 127.0.0.40 occupant *\n",4,[
        event("occupied-static-refusal",dns=[("occupant",1),("occupant.pool.test",1)]),
    ]
    shared="dhcp-host=02:00:00:00:00:01,02:00:00:00:00:02,127.0.0.40,shared,infinite\n"
    yield "bootp-does-not-steal-static-mac",shared,b"",4,[
        event("first-static-mac",dns=[("shared.pool.test",1)]),
        event("other-configured-mac-is-refused",client=2,dns=[("shared.pool.test",1)]),
        event("original-mac-retry"),
    ]
    yield "dynamic-restored", "bootp-dynamic\n",f"{now+600} 02:00:00:00:00:01 127.0.0.10 restored 01:02:03\n".encode(),4,[
        event("restored-becomes-infinite",name=b"replacement".hex(),dns=[("restored.pool.test",1),("replacement.pool.test",1)]),
        event("restored-mac-retry",dns=[("restored",1)]),
    ]
    yield "bootp-disabled-and-invalid-hardware","",b"",4,[
        event("tagless-not-enabled"),event("missing-hardware",htype=0,hlen=0),event("zero-hardware-length",hlen=0),
    ]
    yield "client-id-does-not-authorize-bootp","dhcp-host=id:client,127.0.0.40,clid\n",b"",4,[
        event("client-id-only-refusal",clid=b"client".hex(),dns=[("clid",1),("clid.pool.test",1)]),
    ]


def ask(host,kind,ident):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(1);packet=dns_query(host,kind,ident);client.sendto(packet,("127.0.0.1",53))
        reply=client.recv(65535)
    return {"request":packet.hex(),"wire":reply.hex(),"semantics":dns_semantics(reply)}


def run(binary,config,leasefile,folder,events,initial):
    folder.mkdir();leasefile.write_bytes(initial);(folder/"initial.leases").write_bytes(initial)
    trace={"rows":[],"status":"failed"};process=None;client=None
    last_replies={}
    with (folder/"daemon.log").open("w") as log:
        try:
            client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.bind(("0.0.0.0",68))
            client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);client.setsockopt(socket.SOL_SOCKET,25,b"lo\0")
            process=subprocess.Popen([str(binary.resolve()),"-d","-C",str(config)],stdout=log,stderr=log)
            deadline=time.monotonic()+5
            while True:
                assert process.poll() is None,"daemon exited before readiness"
                try:
                    with socket.create_connection(("127.0.0.1",53),.03):break
                except OSError:assert time.monotonic()<deadline,"DNS listener readiness timeout";time.sleep(.01)
            for index,item in enumerate(events):
                request=packet(item,0x8100+index);sent=time.time()
                client.sendto(request,("255.255.255.255" if item.get("broadcast",True) else "127.0.0.1",67))
                client.settimeout(.25)
                try:response,peer=client.recvfrom(4096)
                except socket.timeout:response=None;peer=None
                received=time.time()
                (folder/f"{index:02}.request").write_bytes(request)
                if response is not None:
                    (folder/f"{index:02}.response").write_bytes(response)
                    assert len(response)==300 and response[0]==2 and response[4:8]==request[4:8]
                    assert response[236:240]==request[236:240],"BOOTP cookie was replaced"
                    assert 53 not in decode(response,0x8100+index),"BOOTP response became DHCP"
                    last_replies[socket.inet_ntoa(response[16:20])] = (sent,received)
                # Immediately after a reply: no extra wait may conceal delayed
                # lease-file commit or DHCP-to-DNS publication.
                file_bytes=leasefile.read_bytes();(folder/f"{index:02}.leases").write_bytes(file_bytes)
                normalized=[]
                for row in rows(leasefile):
                    row=dict(row)
                    if row["expiry"] and row["address"] in last_replies:
                        lower,upper=last_replies[row["address"]]
                        assert int(lower)+899<=row["expiry"]<=int(upper)+901,"static duration changed"
                        row["expiry"]="last-bootp+900s"
                    normalized.append(row)
                dns=[ask(host,kind,0x9000+index*8+slot) for slot,(host,kind) in enumerate(item.get("dns",[]))]
                trace["rows"].append({"label":item["label"],"request":request.hex(),
                    "reply":None if response is None else response.hex(),"peer":None if peer is None else list(peer),
                    "leases":normalized,"dns":dns,"sent":sent,"received":received})
            trace["status"]="ok"
        except Exception as error:trace["error"]=repr(error)
        finally:
            if client is not None:client.close()
            if process is not None:
                if process.poll() is None:process.send_signal(signal.SIGTERM)
                try:process.wait(3)
                except subprocess.TimeoutExpired:process.kill();process.wait(3)
                trace["exit"]=process.returncode;trace["reaped"]=not Path(f"/proc/{process.pid}").exists()
                if trace["exit"]!=0 or not trace["reaped"]:
                    trace["status"]="failed";trace["error"]="daemon did not shut down cleanly"
            (folder/"trace.json").write_text(json.dumps(trace,indent=2)+"\n")
    return trace


def normalized(trace):
    result=copy.deepcopy(trace["rows"])
    for row in result:
        row.pop("sent");row.pop("received")
        for reply in row["dns"]:reply.pop("wire")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c",type=Path,required=True);parser.add_argument("--c-identity",type=Path)
    parser.add_argument("--rust",type=Path);parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--inject-failure",action="store_true")
    args=parser.parse_args();assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    assert sorted(name for _,name in socket.if_nameindex())==["lo"]
    identity=verify_reference(args.c,args.c_identity);out=args.output.resolve()
    assert "private" in out.parts and not out.exists();out.mkdir(parents=True)
    scenarios=list(fixtures(int(time.time())))
    (out/"plan.json").write_text(json.dumps([{"scenario":name,"config":extra,"initial":initial.hex(),"capacity":capacity,"events":events}
        for name,extra,initial,capacity,events in scenarios],indent=2)+"\n")
    report={"scope":"ordinary BOOTP main service packets, file and immediate DNS; counters retain the separate producer gate until main metrics publication",
        "reference":identity,"planned_scenarios":len(scenarios),"planned_events":sum(len(case[4]) for case in scenarios),
        "compared":0,"mismatches":[],"runs":[]}
    for label,extra,initial,capacity,events in scenarios:
        folder=out/label;folder.mkdir();leasefile=folder/"leases";config=folder/"dnsmasq.conf"
        config.write_text("no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport=53\ncache-size=0\nno-ping\nlocal-ttl=37\n"
            "dhcp-authoritative\ndomain=pool.test\ndhcp-range=127.0.0.10,127.0.0.12,255.0.0.0,127.255.255.255,600s\n"
            f"dhcp-lease-max={capacity}\ndhcp-leasefile={leasefile}\nhost-record=ready.test,127.0.0.9\n"+extra)
        expected=run(args.c,config,leasefile,folder/"c",events,initial)
        report["runs"].append({"scenario":label,"side":"c","status":expected["status"],"events":len(expected["rows"]),"error":expected.get("error"),"exit":expected.get("exit"),"reaped":expected.get("reaped")})
        if expected["status"]!="ok":continue
        assert (len(expected["rows"]),sum(row["reply"] is not None for row in expected["rows"]))==C_COUNTS[label]
        if label=="static-named":
            first=bytes.fromhex(expected["rows"][0]["reply"])
            assert socket.inet_ntoa(first[16:20])=="127.0.0.40" and 53 not in decode(first,0x8100)
            calibration=normalized(expected);changed=copy.deepcopy(calibration);changed[0]["reply"]=None
            assert sum(a!=b for a,b in zip(calibration,changed,strict=True))==1
        if args.rust:
            actual=run(args.rust,config,leasefile,folder/"rust",events,initial)
            report["runs"].append({"scenario":label,"side":"rust","status":actual["status"],"events":len(actual["rows"]),"error":actual.get("error"),"exit":actual.get("exit"),"reaped":actual.get("reaped")})
            if actual["status"]!="ok":continue
            left,right=normalized(expected),normalized(actual);assert len(left)==len(right)==len(events)
            if args.inject_failure and label=="static-named":right[0]["reply"]=None
            for index,(c,rust) in enumerate(zip(left,right,strict=True)):
                report["compared"]+=1
                if c!=rust:report["mismatches"].append({"scenario":label,"event":index,"c":c,"rust":rust})
    report["failures"]=[row for row in report["runs"] if row["status"]!="ok"]
    report["reference_events"]=sum(row["events"] for row in report["runs"] if row["side"]=="c")
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    report["matched"]=report["compared"]-len(report["mismatches"])
    report["unexecuted"]=None if args.rust is None else report["planned_events"]-report["compared"]
    report["calibration"]={"real_static_bootp":1,"wrong_reply_detected":1,"frozen_c_event_reply_counts":1,"injected_reply_difference":int(args.inject_failure)}
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("runs","mismatches")}|{"mismatches":len(report["mismatches"])}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__=="__main__":raise SystemExit(main())
