#!/usr/bin/env python3
"""Exact C F_HOSTS next-server lookup, round-robin, DNS interleave and HUP gate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from dhcp_boot_service_diff import packet,options
from dns_service_probe import query
from dns_udp_refusal_diff import verify_reference


def fixtures():
    repeated=[{"label":f"bootp-{index}","kind":0} for index in range(4)]
    sequence=[repeated[0],{"label":"dns-interleave","dns":"boot.test"},repeated[1],
        {"label":"offer","kind":1,"prl":[66,67]},
        {"label":"ack","kind":3,"prl":[66,67]},repeated[2]]
    yield "host-record","boot.test","host-record=boot.test,127.0.0.9\n",None,5300,repeated
    yield "zero-host-record","boot.test","host-record=boot.test,0.0.0.0\n",None,5300,repeated[:2]
    multi="host-record=boot.test,127.0.0.9\nhost-record=boot.test,127.0.0.8\nhost-record=boot.test,127.0.0.7\n"
    yield "shared-round-robin","BOOT.test",multi,None,5300,sequence
    yield "no-round-robin","boot.test",multi+"no-round-robin\n",None,5300,sequence
    yield "ipv6-only","boot.test","host-record=boot.test,::1\n",None,5300,repeated[:2]
    yield "missing","absent.test","",None,5300,repeated[:2]
    yield "trailing-dot-not-canonicalised","boot.test.",multi,None,5300,repeated[:2]
    yield "cname-is-not-hosts-address","alias.test","host-record=boot.test,127.0.0.9\ncname=alias.test,boot.test\n",None,5300,repeated[:2]
    yield "dhcp-name-is-not-hosts","lease.test","domain=test\ndhcp-host=02:00:00:00:00:01,127.0.0.40,lease.test,600s\n",None,5300,[
        {"label":"commit-lease","kind":3},{"label":"prove-dns-name","dns":"lease.test"},repeated[0]]
    yield "dns-disabled","boot.test",multi,None,0,repeated[:2]
    yield "dns-disabled-does-not-open-hosts","boot.test","", "FIFO",0,repeated[:2]
    initial="127.0.0.9 boot.test\n127.0.0.8 boot.test\n::1 boot.test\n127.0.0.6 reload.marker\n"
    replacement="127.0.0.7 boot.test\n127.0.0.5 reload.marker\n"
    yield "hosts-reload","boot.test","",initial,5300,sequence+[
        {"label":"reload","reload":replacement,"marker":"127.0.0.5"},repeated[3]]


def dns_ask(name,ident):
    request=query(name,1,ident)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(.5);client.sendto(request,("127.0.0.1",5300));response=client.recv(65535)
    return response


def run(binary,config,folder,events,host_file,initial):
    folder.mkdir();trace={"status":"failed","rows":[]};process=None
    if initial is not None:
        if host_file.exists():host_file.unlink()
        if initial=="FIFO":os.mkfifo(host_file)
        else:host_file.write_text(initial)
    with (folder/"daemon.log").open("w") as log, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.bind(("0.0.0.0",68));client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        client.setsockopt(socket.SOL_SOCKET,25,b"lo\0");client.settimeout(.5)
        try:
            process=subprocess.Popen([str(binary.resolve()),"-d","-C",str(config)],stdout=log,stderr=log)
            deadline=time.monotonic()+5
            while True:
                assert process.poll() is None,"daemon exited before readiness"
                ports=[row.split()[1].split(':')[1] for row in Path('/proc/net/udp').read_text().splitlines()[1:]]
                if '0043' in ports:break
                assert time.monotonic()<deadline,"DHCP readiness timeout";time.sleep(.01)
            for index,item in enumerate(events):
                if "reload" in item:
                    host_file.write_text(item["reload"]);process.send_signal(signal.SIGHUP);deadline=time.monotonic()+3
                    while True:
                        response=dns_ask("reload.marker",0xb100+index)
                        if response.endswith(socket.inet_aton(item["marker"])):break
                        assert time.monotonic()<deadline,"reload generation not published";time.sleep(.01)
                    trace["rows"].append({"label":item["label"],"generation":response.hex()});continue
                if "dns" in item:
                    response=dns_ask(item["dns"],0xb100+index)
                    trace["rows"].append({"label":item["label"],"dns":response.hex()});continue
                request=packet(item,0xa100+index);(folder/f"{index:02}.request").write_bytes(request)
                client.sendto(request,("255.255.255.255",67));response,peer=client.recvfrom(65535)
                (folder/f"{index:02}.response").write_bytes(response)
                assert response[0]==2 and response[4:8]==request[4:8]
                options(response)
                trace["rows"].append({"label":item["label"],"reply":response.hex(),"peer":list(peer),
                    "next_server":socket.inet_ntoa(response[20:24])})
            trace["status"]="ok"
        except Exception as error:trace["error"]=repr(error)
        finally:
            if process is not None:
                if process.poll() is None:process.send_signal(signal.SIGTERM)
                try:process.wait(3)
                except subprocess.TimeoutExpired:process.kill();process.wait(3)
                trace["exit"]=process.returncode;trace["reaped"]=not Path(f"/proc/{process.pid}").exists()
                if trace["exit"]!=0 or not trace["reaped"]:trace["status"]="failed"
            trace["missing_host_warnings"]=(folder/"daemon.log").read_text().count("No IPv4 address found for ")
            (folder/"trace.json").write_text(json.dumps(trace,indent=2)+"\n")
    return trace


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
    for name,server,extra,initial,port,events in cases:
        folder=out/name;folder.mkdir();config=folder/"dnsmasq.conf";host_file=folder/"hosts"
        config.write_text(f"no-hosts\nno-resolv\nlisten-address=127.0.0.1\nport={port}\nno-ping\nleasefile-ro\nlocal-ttl=37\n"
            "dhcp-authoritative\ndhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n"
            +("dhcp-host=02:00:00:00:00:01,127.0.0.40,600s\n" if "dhcp-host=" not in extra else "")+f"dhcp-leasefile={folder/'leases'}\n"
            +f"dhcp-boot=synthetic.img,display.test,{server}\n"+(f"addn-hosts={host_file}\n" if initial is not None else "")+extra)
        left=run(args.c,config,folder/"c",events,host_file,initial)
        report["runs"].append({"scenario":name,"side":"c",**{key:value for key,value in left.items() if key!="rows"}})
        report["reference_events"]+=len(left["rows"])
        if left["status"]!="ok":continue
        assert len(left["rows"])==len(events)
        if name=="host-record":
            assert {row["next_server"] for row in left["rows"]}=={"127.0.0.9"}
            report["calibration"]["fixed_host_record"]=1
        if name in ("ipv6-only","missing","trailing-dot-not-canonicalised",
                "cname-is-not-hosts-address","dhcp-name-is-not-hosts","dns-disabled",
                "dns-disabled-does-not-open-hosts"):
            assert {row["next_server"] for row in left["rows"] if "next_server" in row}=={"0.0.0.0"}
            assert left["missing_host_warnings"]==sum("reply" in row for row in left["rows"])
        else:assert left["missing_host_warnings"]==0
        if name=="dhcp-name-is-not-hosts":
            assert bytes.fromhex(left["rows"][1]["dns"]).endswith(socket.inet_aton("127.0.0.40"))
            report["calibration"]["dynamic_dns_does_not_authorize_boot_host"]=1
        if args.rust:
            right=run(args.rust,config,folder/"rust",events,host_file,initial)
            report["runs"].append({"scenario":name,"side":"rust",**{key:value for key,value in right.items() if key!="rows"}})
            if right["status"]!="ok":continue
            assert len(right["rows"])==len(events)
            report["compared"]+=1
            if left["missing_host_warnings"]!=right["missing_host_warnings"]:
                report["mismatches"].append({"scenario":name,"event":"warning-count",
                    "c":left["missing_host_warnings"],"rust":right["missing_host_warnings"]})
            if args.inject_failure and name=="host-record":right["rows"][0]["next_server"]="0.0.0.0"
            for index,(c,rust) in enumerate(zip(left["rows"],right["rows"],strict=True)):
                report["compared"]+=1
                if c!=rust:report["mismatches"].append({"scenario":name,"event":index,"c":c,"rust":rust})
    report["failures"]=[row for row in report["runs"] if row["status"]!="ok"]
    report["matched"]=report["compared"]-len(report["mismatches"])
    report["planned_observations"]=report["planned_events"]+report["planned_scenarios"]
    report["unexecuted"]=None if args.rust is None else report["planned_observations"]-report["compared"]
    report["rust_sha256"]=None if args.rust is None else hashlib.sha256(args.rust.read_bytes()).hexdigest()
    report["tool_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key not in ("runs","mismatches")}|{"mismatches":len(report["mismatches"])}))
    return int(bool(report["failures"] or report["mismatches"]))


if __name__=="__main__":raise SystemExit(main())
