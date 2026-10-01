#!/usr/bin/env python3
"""Exact-C DHCP-name publication/cache-answer contract discovery.

This first stage records an independently generated C baseline. No Rust
expectation, listener, lease file from a device or production state is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
HASHES = {"cache.c":"51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c",
          "rfc1035.c":"231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222"}


def name(text):
    return b"".join(bytes([len(label)]) + label.encode() for label in text.split(".")) + b"\0"


def query(host, kind=1, flags=0x100):
    return struct.pack("!6H",0x2930,flags,1,0,0,0)+name(host)+struct.pack("!HH",kind,1)


def negative(host, kind=1, nxdomain=True):
    q=query(host,kind)
    return q[:2]+struct.pack("!5H",0x8183 if nxdomain else 0x8180,1,0,0,0)+q[12:]


def positive(host, data, kind=1):
    q=query(host,kind)
    return q[:2]+struct.pack("!5H",0x8180,1,1,0,0)+q[12:]+b"\xc0\x0c"+struct.pack("!HHIH",kind,1,90,len(data))+data


def commands(records, queried, times=(995,999,1000,1001)):
    lines=["R"]+[f"D {expiry} {address} {host}" for host,address,expiry in records]+["E"]
    for now in times:
        for host,kind in queried:
            lines += [f"Q {now} {query(host,kind).hex()}",f"K {now} {query(host,kind).hex()}"]
    lines += ["R","E"]
    return lines


def corpus():
    record=("lease.example","192.0.2.7",1000)
    questions=[("lease.example",1),("lease.example",28),("lease.example",255),
               ("lease.example",5),("example",1),("7.2.0.192.in-addr.arpa",12)]
    rows=[]
    for config in ("local-ttl=0", "local-ttl=37", "local-ttl=37\ndhcp-ttl=9"):
        rows.append(("ttl-expiry",config,commands([record],questions)))
    rows += [
        ("fqdn-first", "local-ttl=37",commands([record,("lease","192.0.2.7",1000)],questions+[("lease",1)])),
        ("infinite", "local-ttl=37",commands([("lease.example","192.0.2.7",0)],questions)),
        ("parent-longest-child", "local-ttl=37",commands([record,("other.example","192.0.2.8",1010)],questions,times=(999,1000,1009,1010))),
        ("static-same", "local-ttl=37\nhost-record=lease.example,192.0.2.7",commands([record],questions)),
        ("static-different", "local-ttl=37\nhost-record=lease.example,192.0.2.9",commands([record],questions)),
        ("static-other-family", "local-ttl=37\nhost-record=lease.example,2001:db8::7",commands([record],questions)),
        ("static-ptr-owner", "local-ttl=37\nhost-record=static.example,192.0.2.7",commands([record],questions)),
        ("static-cname", "local-ttl=37\ncname=lease.example,target.example\nhost-record=target.example,192.0.2.9",commands([record],questions)),
    ]
    for label,packet in [
        ("prior-forward-nxdomain",negative("lease.example")),
        ("prior-forward-nodata",negative("lease.example",nxdomain=False)),
        ("prior-forward-address",positive("lease.example",bytes([192,0,2,99]))),
        ("prior-reverse-positive",positive("7.2.0.192.in-addr.arpa",name("cached.example"),12)),
        ("prior-reverse-nxdomain",negative("7.2.0.192.in-addr.arpa",12)),
        ("prior-reverse-nodata",negative("7.2.0.192.in-addr.arpa",12,False)),
    ]:
        sequence=[f"P 970 {packet.hex()}","E"]+commands([record],questions)
        rows.append((label,"local-ttl=37",sequence))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path,required=True)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(); output=args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/"private"):
        parser.error("new private output directory required")
    for filename,expected in HASHES.items():
        if hashlib.sha256((args.source/"src"/filename).read_bytes()).hexdigest()!=expected:
            parser.error(f"source identity differs: {filename}")
    output.mkdir(parents=True)
    local_answer_diff.DRIVER=Path(__file__).with_name("lease_names_driver.c")
    binary=local_answer_diff.build_oracle(args.reference_build,output)
    rows=[]
    for index,(label,extra,lines) in enumerate(corpus()):
        config=output/f"{index:02}.conf"
        config.write_text("no-hosts\nno-resolv\ncache-size=64\nneg-ttl=60\nno-round-robin\n"+extra+"\n")
        wire="\n".join(lines)+"\n"; (output/f"{index:02}.input").write_text(wire)
        run=subprocess.run([str(binary),"-C",str(config)],input=wire,text=True,capture_output=True)
        (output/f"{index:02}.stdout").write_text(run.stdout);(output/f"{index:02}.stderr").write_text(run.stderr)
        if index == 0:
            assert "E lease.example 192.0.2.7 1 " in run.stdout, "C publication calibration missing its real DHCP entry"
        rows.append({"case":index,"label":label,"exit":run.returncode,"commands":len(lines)})
    invalid=output/"invalid.conf";invalid.write_text("not-a-real-dnsmasq-option=1\n")
    rejected=subprocess.run([str(binary),"-C",str(invalid)],input="R\n",text=True,capture_output=True)
    (output/"negative-calibration.stderr").write_text(rejected.stderr)
    assert rejected.returncode != 0, "C invocation failure calibration accepted invalid configuration"
    report={"scope":"C-only lease-name/state/answer baseline; no Rust equivalence claim","cases":len(rows),
            "calibration":{"real_dhcp_entry":1,"invalid_config_rejected":1,"invalid_exit":rejected.returncode},
            "c_oracle_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"source_sha256":HASHES,
            "rows":rows,"failures":[row for row in rows if row["exit"]]}
    (output/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key!="rows"}))
    return int(bool(report["failures"]))


if __name__=="__main__":
    raise SystemExit(main())
