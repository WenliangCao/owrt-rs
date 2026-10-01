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
import shutil

import local_answer_diff

ROOT = Path(__file__).resolve().parents[2]
HASHES = {"cache.c":"51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c",
          "rfc1035.c":"231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222"}


def name(text):
    labels = [label.encode() for label in text.split(".")]
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\0"


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
        ("cname-to-lease", "local-ttl=37\ncname=alias.example,lease.example,19",commands([record],questions+[("alias.example",kind) for kind in (1,28,5,255,65280)])),
        ("stale-two-seconds", "local-ttl=37\nuse-stale-cache=2",commands([record],questions,times=(999,1000,1001,1002))),
        ("stale-forever", "local-ttl=37\nuse-stale-cache",commands([record],questions,times=(999,1000,1001,1009))),
        ("real-parent-extended", "local-ttl=37", commands([("example","192.0.2.8",1000),record[:-1]+(1010,)],questions+[("example",1),("8.2.0.192.in-addr.arpa",12)],times=(999,1000,1009,1010))),
        ("real-parent-infinite-child", "local-ttl=37", commands([("example","192.0.2.8",1000),record[:-1]+(0,)],questions+[("example",1),("8.2.0.192.in-addr.arpa",12)])),
        ("static-same-among-different", "local-ttl=37\nhost-record=lease.example,192.0.2.9\nhost-record=lease.example,192.0.2.7",commands([record],questions)),
        ("static-publication-round-robin", "local-ttl=37\nhost-record=first.example,192.0.2.9\nhost-record=second.example,192.0.2.8\nhost-record=lease.example,192.0.2.9\nhost-record=lease.example,192.0.2.8",commands([record],questions)),
        ("ptr-no-promotion", "local-ttl=37", commands([record,("other.example","192.0.2.7",1010)],questions+[("other.example",1)],times=(999,1000,1009,1010))),
        ("self-mx-lease-and-parent", "local-ttl=37\nselfmx",commands([record],questions+[("lease.example",15),("example",15)])),
        ("self-mx-cname-terminal", "local-ttl=37\nselfmx\ncname=alias.example,lease.example",commands([record],questions+[("alias.example",15),("alias.example",255)])),
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


def observations(commands, output):
    """Keep flags/TTLs/record order; only unordered cache inventory is sorted."""
    lines = iter(output.splitlines())
    results = []
    for command in commands:
        line = next(lines)
        if command == "E":
            entries = []
            while line != "END":
                fields = line.split()
                if len(fields) != 13 or fields[0] != "E":
                    raise ValueError(f"invalid cache inventory row: {line}")
                if fields[3] == "1":  # independently tagged C F_DHCP
                    entries.append(line)
                line = next(lines)
            results.append(sorted(entries))
        elif command.startswith("Q "):
            results.append(local_answer_diff.dns_semantics(line))
        else:
            results.append(line)
    if next(lines, None) is not None:
        raise ValueError("extra output after final command")
    return results


def compare(args, output):
    baseline = args.compare_baseline.resolve()
    identity = json.loads((baseline / "result.json").read_text())
    if identity["failures"]:
        raise SystemExit("reference baseline contains failed invocations")
    if hashlib.sha256((baseline / "local-answer-oracle").read_bytes()).hexdigest() != identity["c_oracle_sha256"]:
        raise SystemExit("reference executable identity differs")
    rows, deferred, mismatches = [], [], []
    compared = queries = inventories = 0
    for case in identity["rows"]:
        index = case["case"]
        commands = (baseline / f"{index:02}.input").read_text().splitlines()
        if any(command.startswith("P ") for command in commands):
            deferred.append({"case": index, "label": case["label"], "reason": "forward-cache publication is tested by lease_cache_diff, not this local snapshot probe"})
            continue
        config = output / f"{index:02}.conf"
        shutil.copy2(baseline / f"{index:02}.conf", config)
        wire = "\n".join(commands)+"\n"
        (output / f"{index:02}.input").write_text(wire)
        expected_wire = (baseline / f"{index:02}.stdout").read_text()
        run = subprocess.run([str(args.rust.resolve()), "-C", str(config)], input=wire, text=True, capture_output=True)
        (output / f"{index:02}.rust.stdout").write_text(run.stdout)
        (output / f"{index:02}.rust.stderr").write_text(run.stderr)
        (output / f"{index:02}.c.stdout").write_text(expected_wire)
        expected = observations(commands, expected_wire)
        actual = observations(commands, run.stdout) if not run.returncode else []
        if run.returncode:
            mismatches.append({"case": index, "label": case["label"], "exit": run.returncode})
        else:
            for step, (left, right) in enumerate(zip(expected, actual, strict=True)):
                compared += 1
                queries += commands[step].startswith("Q ")
                inventories += commands[step] == "E"
                if left != right:
                    mismatches.append({"case":index,"label":case["label"],"step":step,"command":commands[step],"c":left,"rust":right})
        rows.append({"case": index, "label": case["label"], "exit": run.returncode, "commands": len(commands)})
    # A controlled wrong result must increase the comparator's failure count.
    expected = observations(["Q 0 " + query("calibration.example").hex()], "NONE\n")
    corrupted = observations(["Q 0 " + query("calibration.example").hex()], positive("calibration.example",bytes([192,0,2,7])).hex()+"\n")
    assert sum(a != b for a,b in zip(expected,corrupted,strict=True)) == 1
    report = {"scope":"exact C DHCP inventory, local DNS answers and known-local presence; forwarded cache scenarios deferred",
        "c_oracle_sha256":identity["c_oracle_sha256"],"rust_sha256":hashlib.sha256(args.rust.read_bytes()).hexdigest(),
        "cases":len(rows),"compared":compared,"queries":queries,"inventories":inventories,
        "mismatches":mismatches,"deferred":deferred,"rows":rows,
        "calibration":{"injected_wrong_answer_detected":1,"invalid_c_config_rejected":identity["calibration"]["invalid_config_rejected"]}}
    (output/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("rows","mismatches","deferred")}|{"mismatches":len(mismatches),"deferred":len(deferred)}))
    return int(bool(mismatches))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path)
    parser.add_argument("--source",type=Path)
    parser.add_argument("--compare-baseline",type=Path)
    parser.add_argument("--rust",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args(); output=args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/"private"):
        parser.error("new private output directory required")
    if args.compare_baseline:
        if not args.rust:
            parser.error("--compare-baseline requires --rust")
        output.mkdir(parents=True)
        return compare(args,output)
    if not args.reference_build or not args.source:
        parser.error("C baseline requires --reference-build and --source")
    for filename,expected in HASHES.items():
        if hashlib.sha256((args.source/"src"/filename).read_bytes()).hexdigest()!=expected:
            parser.error(f"source identity differs: {filename}")
    output.mkdir(parents=True)
    local_answer_diff.DRIVER=Path(__file__).with_name("lease_names_driver.c")
    binary=local_answer_diff.build_oracle(args.reference_build,output)
    rows=[]
    for index,(label,extra,lines) in enumerate(corpus()):
        config=output/f"{index:02}.conf"
        config.write_text("no-hosts\nno-resolv\ncache-size=64\nneg-ttl=60\n"+
                          ("" if label == "static-publication-round-robin" else "no-round-robin\n")+extra+"\n")
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
