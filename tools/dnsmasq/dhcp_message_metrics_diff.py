#!/usr/bin/env python3
"""Actual C dhcp_reply message-counter baseline and ordered comparison.

All DHCP execution is offline inside an isolated network namespace. The C
driver calls unchanged rfc2131/lease code; no listeners or send success are
used to manufacture expected counters. Wire replies are retained separately.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

import local_answer_diff

ROOT=Path(__file__).resolve().parents[2]
HASHES={
    "rfc2131.c":"14f2e10792ef6108aeb7b69e551f089ba287c8c84d39ea178a5f33acd2038c2c",
    "lease.c":"4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763",
    "dhcp-common.c":"9139906c5d3a438853fe84e90387cfc299c3c28e7b16a23c7d0d6922847ccc79",
    "dhcp.c":"600dc068b0516d7edebcde9b02ae2091a278fc154551106823ddc388170d7001",
    "dnsmasq.h":"318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228",
}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def packet(message,client=1,requested=None,server=None,ciaddr=None,rapid=False,htype=1,hlen=6):
    data=bytearray(240);data[:3]=bytes([1,htype,hlen]);data[4:8]=struct.pack("!I",client*100+message)
    data[12:16]=ipaddress.IPv4Address(ciaddr or "0.0.0.0").packed
    data[28:34]=bytes([2,0,0,0,0,client]);data[236:240]=bytes([99,130,83,99])
    if message:data.extend([53,1,message])
    if requested:data.extend(bytes([50,4])+ipaddress.IPv4Address(requested).packed)
    if server:data.extend(bytes([54,4])+ipaddress.IPv4Address(server).packed)
    if rapid:data.extend([80,0])
    data.append(255);return bytes(data)


def send(data,now=100,unicast=True): return f"P {now} {int(unicast)} {data.hex()}"


def select(client=1,last=10,server="192.0.2.1"):
    return packet(3,client,requested=f"192.0.2.{last}",server=server)


def corpus():
    yield "calibration",{},[send(packet(1,requested="192.0.2.10")),send(select()),
        send(packet(3,ciaddr="192.0.2.10"),101),"H",send(packet(7,server="192.0.2.1",ciaddr="192.0.2.10"),102)]
    yield "request-early-return-and-nak",{},[send(select(server="192.0.2.2")),send(packet(3,requested="192.0.2.10")),
        send(packet(3,ciaddr="192.0.2.10"),unicast=False),send(packet(3,ciaddr="192.0.2.10"))]
    yield "authoritative-request-decisions",{"authoritative":True,"static_clients":[3]},[
        send(packet(3,requested="192.0.2.10")),send(select(2,11,"192.0.2.2")),send(select(2,99)),
        send(select(2,15)),send(packet(3,requested="192.0.2.11",server="192.0.2.1",htype=0,hlen=0))]
    yield "discover-exhausted-range-and-identity",{"range_end":10},[
        send(select()),send(packet(1,2,requested="192.0.2.10")),send(packet(1,3,htype=0,hlen=0))]
    yield "rapid-success-and-failed-allocation",{"rapid":True,"capacity":1},[
        send(select()),send(packet(1,2,requested="192.0.2.11")),
        send(packet(1,2,requested="192.0.2.11",rapid=True)),
        send(packet(7,server="192.0.2.1",ciaddr="192.0.2.10")),
        send(packet(1,2,requested="192.0.2.11",rapid=True))]
    for quiet in [False,True]:
        yield f"ignored-client-quiet-{int(quiet)}",{"ignored":True,"quiet":quiet},[
            send(packet(1)),send(select()),send(packet(8,ciaddr="192.0.2.10")),send(packet(8)),send(packet(0)),
            send(packet(4,requested="192.0.2.10",server="192.0.2.1")),
            send(packet(7,server="192.0.2.1",ciaddr="192.0.2.10")),"H"]
    yield "inform-with-and-without-client-address",{},[send(select()),send(packet(8,ciaddr="192.0.2.10")),
        send(packet(8,2,ciaddr="192.0.2.11")),send(packet(8,2,ciaddr="203.0.113.7")),send(packet(8))]
    yield "decline-validation-and-unknown-lease",{},[send(packet(4,requested="192.0.2.10")),
        send(packet(4,requested="192.0.2.10",server="192.0.2.2")),send(packet(4,server="192.0.2.1")),
        send(packet(4,requested="192.0.2.10",server="192.0.2.1")),"H"]
    yield "release-validation-and-unknown-lease",{},[send(packet(7,ciaddr="192.0.2.10")),
        send(packet(7,server="192.0.2.2",ciaddr="192.0.2.10")),send(packet(7,server="192.0.2.1")),
        send(packet(7,server="192.0.2.1",ciaddr="192.0.2.10")),"H"]
    yield "bootp-disabled-and-early-hardware-return",{},[send(packet(0)),send(packet(0,htype=0,hlen=0)),send(packet(0,hlen=0))]
    yield "bootp-dynamic-and-capacity",{"bootp_dynamic":True,"capacity":1},[send(packet(0)),send(packet(0,2)),send(packet(0)),"H"]
    yield "bootp-static-address-in-use",{"static_clients":[1,2]},[send(packet(0)),send(packet(0,2)),send(packet(0))]
    yield "no-initial-context",{"no_context":True},[send(packet(kind,ciaddr="192.0.2.10")) for kind in [0,1,3,4,7,8]]
    malformed=[]
    for at,value in [(0,2),(2,17),(1,0),(236,0)]:
        data=bytearray(packet(1));data[at]=value;malformed.append(send(bytes(data)))
    malformed.append(send(packet(1)[:235]))
    malformed.extend(send(packet(kind)) for kind in [2,5,6,9,42])
    yield "pre-message-malformed-and-client-only-types",{},malformed
    yield "counter-wrap-and-reload",{},["M 4 4294967295",send(packet(1,requested="192.0.2.10")),
        "M 7 4294967295",send(packet(1,requested="192.0.2.10")),"M 2 4294967295",send(select()),
        "M 0 4294967295",send(packet(0,2)),"H"]


def config(model):
    lines=["port=0","no-hosts","no-resolv","no-ping","leasefile-ro",f"dhcp-lease-max={model.get('capacity',4)}"]
    if not model.get("no_context"):
        lines.append(f"dhcp-range=192.0.2.10,192.0.2.{model.get('range_end',20)},255.255.255.0,120s")
    for flag,option in [("authoritative","dhcp-authoritative"),("rapid","dhcp-rapid-commit"),("quiet","quiet-dhcp"),("bootp_dynamic","bootp-dynamic")]:
        if model.get(flag):lines.append(option)
    if model.get("ignored"):lines.append("dhcp-host=02:00:00:00:00:01,ignore")
    if model.get("static_clients"):
        lines.append("dhcp-host="+",".join(f"02:00:00:00:00:{client:02x}" for client in model["static_clients"])+",192.0.2.15")
    return "\n".join(lines)+"\n"


def build(reference,out):
    obj=reference / "dnsmasq";local_answer_diff.validate_reference_variant(obj)
    for filename,expected in HASHES.items():assert digest(obj / filename)==expected
    renamed=local_answer_diff.rename_main(obj,out)
    objects=sorted(path for path in obj.glob("*.o") if path.name not in ("lease.o","dnsmasq.o","dnsmasq-renamed.o"))
    deps=reference / "deps/lib";binary=out / "c-oracle"
    command=["cc",*local_answer_diff.REFERENCE_COPTS,"-O2","-Wall","-Wextra","-Werror",f"-I{obj}",
        f"-I{reference / 'deps/include'}",str(Path(__file__).with_name("dhcp_message_metrics_driver.c")),
        *map(str,objects),str(renamed),f"-L{deps}",f"-Wl,-rpath,{deps}","-lubus","-lubox","-o",str(binary)]
    run=subprocess.run(command,text=True,capture_output=True)
    (out / "build.json").write_text(json.dumps({"command":command,"exit":run.returncode,"stdout":run.stdout,"stderr":run.stderr},indent=2)+"\n")
    run.check_returncode()
    identity={"source":{name:digest(obj/name) for name in [*HASHES,"config.h"]},
        "objects":{path.name:digest(path) for path in [*objects,renamed]},"copts":local_answer_diff.REFERENCE_COPTS,
        "libraries":{path.name:digest(path) for path in deps.glob("*.so*") if path.is_file()},"elf":digest(binary)}
    (out / "identity.json").write_text(json.dumps(identity,indent=2)+"\n");return binary,identity


def compare(args,out):
    baseline=args.compare_baseline.resolve();reference=json.loads((baseline/"result.json").read_text())
    assert not reference["failures"] and digest(baseline/"identity.json")==reference["reference_identity_sha256"]
    assert digest(baseline/"c-oracle")==reference["c_elf_sha256"]
    binary=out/"rust-probe";shutil.copy2(args.rust.resolve(),binary)
    rows=[];failures=[];compared=matched=0
    injected=False
    for case in reference["rows"]:
        index=case["case"];conf=out/f"{index:02}.conf";source=out/f"{index:02}.input"
        shutil.copy2(baseline/conf.name,conf);shutil.copy2(baseline/source.name,source)
        wire=source.read_text();commands=wire.splitlines()
        run=subprocess.run([str(binary),"-C",str(conf)],input=wire,text=True,capture_output=True)
        (out/f"{index:02}.rust.stdout").write_text(run.stdout);(out/f"{index:02}.rust.stderr").write_text(run.stderr)
        expected=(baseline/f"{index:02}.stdout").read_text();(out/f"{index:02}.c.stdout").write_text(expected)
        actual=run.stdout.splitlines();expected=expected.splitlines()
        if run.returncode or len(actual)!=len(commands):
            failures.append({"case":index,"label":case["label"],"exit":run.returncode,"expected_count":len(commands),"observed_count":len(actual)})
            continue
        if args.inject_failure and not injected:
            fields=actual[0].split();fields[3]=str((int(fields[3])+1)&0xffffffff)
            actual[0]=" ".join(fields);injected=True
        case_failed=0
        for step,(left,right) in enumerate(zip(expected,actual,strict=True)):
            compared+=1;matched+=left==right
            if left!=right:
                case_failed+=1;failures.append({"case":index,"label":case["label"],"step":step,"command":commands[step],"c":left,"rust":right})
        rows.append({"case":index,"label":case["label"],"observations":len(actual),"mismatches":case_failed})
    calibration=["P 2 0 0 0 0 0 1 0 0 1 0 0 0"]
    mutated=["P 2 0 0 0 0 0 2 0 0 1 0 0 0"]
    assert sum(a!=b for a,b in zip(calibration,mutated,strict=True))==1
    assert sum(a!=b for a,b in zip(calibration,calibration,strict=True))==0
    report={"scope":"ordinary DHCP/BOOTP state producer metrics; rapid/BOOTP primitive coverage does not enable unsupported daemon modes",
        "planned_scenarios":len(reference["rows"]),"executed_scenarios":len(rows),"planned_observations":reference["observations"],
        "compared":compared,"matched":matched,"unexecuted":reference["observations"]-compared,
        "failures":failures,"rows":rows,"calibration":{"equal":1,"changed_counter_rejected":1,"injected_failure":int(injected)},
        "c_elf_sha256":reference["c_elf_sha256"],"reference_identity_sha256":reference["reference_identity_sha256"],"rust_elf_sha256":digest(binary),
        "rust_source_sha256":{str(path.relative_to(ROOT)):digest(path) for path in
            [ROOT/"components/dnsmasq/src/dhcp"/name for name in ("state.rs","runtime.rs","message_counters.rs","daemon.rs","lease.rs")]}}
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("rows","failures","rust_source_sha256")}|{"failures":len(failures)}))
    return int(bool(failures))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path)
    parser.add_argument("--compare-baseline",type=Path)
    parser.add_argument("--rust",type=Path)
    parser.add_argument("--inject-failure",action="store_true")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve()
    assert "private" in out.parts and not out.exists()
    out.mkdir(parents=True)
    if args.compare_baseline:
        if not args.rust:parser.error("--compare-baseline requires --rust")
        return compare(args,out)
    assert os.environ.get("DNSMASQ_TEST_ISOLATED")=="1"
    if not args.reference_build:parser.error("baseline requires --reference-build")
    binary,identity=build(args.reference_build.resolve(),out)
    rows=[];failures=[]
    for index,(label,model,commands) in enumerate(corpus()):
        conf=out/f"{index:02}.conf";conf.write_text(config(model))
        (out/f"{index:02}.model.json").write_text(json.dumps(model,indent=2)+"\n")
        wire="\n".join(commands)+"\n";(out/f"{index:02}.input").write_text(wire)
        run=subprocess.run([str(binary),"-C",str(conf)],input=wire,text=True,capture_output=True)
        (out/f"{index:02}.stdout").write_text(run.stdout);(out/f"{index:02}.stderr").write_text(run.stderr)
        row={"case":index,"label":label,"exit":run.returncode,"planned":len(commands),"observed":len(run.stdout.splitlines())}
        rows.append(row)
        if run.returncode or row["observed"]!=row["planned"]:failures.append(row)
        elif index==0:
            assert run.stdout.splitlines()[0]=="P 2 0 0 0 0 0 1 0 0 1 0 0 0", "DISCOVER/OFFER calibration"
            assert run.stdout.splitlines()[1]=="P 5 1 0 0 1 0 1 0 0 1 0 1 0", "REQUEST/ACK calibration"
    report={"scope":"C-only full dhcp_reply message counters, offline caller boundary; no Rust or main/ubus equivalence yet",
        "cases":len(rows),"observations":sum(row["observed"] for row in rows),"rows":rows,"failures":failures,
        "reference_identity_sha256":digest(out/"identity.json"),"c_elf_sha256":identity["elf"]}
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n");print(json.dumps({k:v for k,v in report.items() if k!="rows"}))
    return int(bool(failures))


if __name__=="__main__":raise SystemExit(main())
