#!/usr/bin/env python3
"""Frozen-clock actual C upstream insertion with live hosts/DHCP blockers.

P invokes extract_addresses; Q invokes answer_request. N counts only dynamic
records returned by the real typed lookup, detecting hidden cache residency.
R/D are complete lease publication generations; S calls actual cache_reload.
The Rust driver calls production daemon helpers without opening listeners.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

import lease_names_diff as names
import local_answer_diff
import rust_lib_probe

ROOT = Path(__file__).resolve().parents[2]
TEST = "dns::daemon::lease_cache_tests::exact_c_lease_cache_driver"


def request(owner, kind=1, now=101, operation="Q"):
    return f"{operation} {now} {names.query(owner, kind).hex()}"


def response(owner, records, kind=1, rcode=0):
    wire = struct.pack("!6H", 0x2930, 0x8180 | rcode, 1, len(records), 0, 0)
    wire += names.name(owner) + struct.pack("!HH", kind, 1)
    for name, rrtype, ttl, data in records:
        wire += names.name(name) + struct.pack("!HHIH", rrtype, 1, ttl, len(data)) + data
    return wire


def put(owner="lease", address=7, now=100, alias=None, kind=1):
    records = []
    query = alias or owner
    if alias:
        records.append((alias, 5, 60, names.name(owner)))
    data = bytes([192, 0, 2, address]) if kind == 1 else bytes.fromhex("20010db8000000000000000000000007")
    records.append((owner, kind, 90, data))
    return f"P {now} {response(query, records, kind).hex()}"


def corpus():
    before = ["R", "D 130 192.0.2.7 lease"]
    inspect = [request("lease"), request("lease", operation="N")]
    release = ["R", request("lease", now=102), request("lease", now=102, operation="N")]
    yield "calibration-miss-hit-expiry", "", [request("lease", now=100), put(), request("lease"),
        request("lease", operation="N"), request("lease", now=190), request("lease", now=190, operation="N")]
    for address in (7, 99):
        label = "same" if address == 7 else "different"
        yield f"late-dhcp-{label}-address", "", before + [put(address=address)] + inspect + release
        yield f"late-hosts-{label}-address", "host-record=lease,192.0.2.7\n", [put(address=address)] + inspect + ["S"] + inspect
    for addresses in ((7,99), (99,7)):
        packet = response("lease", [("lease",1,90,bytes([192,0,2,address])) for address in addresses])
        yield f"dhcp-multi-address-{addresses[0]}-first", "", before + [f"P 100 {packet.hex()}"] + inspect + release
    yield "other-family-coexists-after-release", "", before + [put(kind=28),request("lease",28),request("lease",28,operation="N"),"R",request("lease",28,now=102)]
    yield "local-nonterminal-is-not-address-blocker", "", ["R","D 130 192.0.2.7 child.lease",put(address=99)] + inspect + release
    yield "expired-untouched-local-blocks", "", before + [put(address=99,now=131),request("lease",operation="N",now=131),"R",request("lease",now=132)]
    yield "expired-looked-up-local-no-longer-blocks", "", before + [request("lease",now=130),put(address=99,now=131),request("lease",now=132),request("lease",operation="N",now=132)]
    for source, config, start in [
        ("dhcp", "", before), ("hosts", "host-record=lease,192.0.2.7\n", []),
    ]:
        for address in (7, 99):
            label = "same" if address == 7 else "different"
            yield f"alias-to-{source}-{label}-address", config, start + [put(alias="alias",address=address),
                request("alias"), request("alias",5),request("alias",operation="N",kind=5),request("lease",operation="N")]
    yield "alias-to-lease-release", "", before + [put(alias="alias"),request("alias"),"R",request("alias",5,now=102),request("alias",now=102),request("alias",5,now=102,operation="N")]
    yield "alias-to-lease-expiry", "", before + [put(alias="alias"),request("alias",now=129),request("alias",now=130),request("alias",5,now=131),request("alias",5,now=131,operation="N")]
    for name, address in [("lease",7),("renamed",7),("other",8)]:
        yield f"alias-target-republished-as-{name}", "", before + [put(alias="alias"),request("alias"),"R",f"D 160 192.0.2.{address} {name}",request("alias",now=102),request("alias",5,now=102),request("alias",5,now=102,operation="N"),request(name,now=102)]
    yield "alias-target-hosts-reload", "host-record=lease,192.0.2.7\n", [put(alias="alias"),request("alias"),"S",request("alias",now=102),request("alias",5,now=102,operation="N"),request("lease",now=102)]
    yield "alias-target-dhcp-hup-republication", "", before + [put(alias="alias"),request("alias"),"S","R","D 160 192.0.2.7 lease",request("alias",now=102),request("alias",5,now=102,operation="N"),request("lease",now=102)]
    yield "local-config-cname-blocks-address", "cname=lease,static\nhost-record=static,192.0.2.7\n", [put(alias="alias"),request("alias"),request("alias",5,operation="N"),request("lease")]
    chain = response("alias", [("alias",5,60,names.name("middle")),("middle",5,45,names.name("lease")),("lease",1,90,bytes([192,0,2,7]))])
    yield "two-cnames-to-local-target", "", before + [f"P 100 {chain.hex()}",request("alias"),request("middle"),request("alias",5),request("middle",5),request("lease",operation="N")]
    # NXDOMAIN has no IPv4 bit and can coexist with a lease; replacing that
    # source must not silently clear the surviving name-wide negative entry.
    nx = f"P 100 {names.negative('lease').hex()}"
    yield "prior-nxdomain-survives-publication", "", [nx]+before+[request("lease"),request("lease",28),"R",request("lease",now=102)]
    yield "late-nxdomain-coexists-with-lease", "", before+[nx,request("lease"),request("lease",28),"R",request("lease",now=102)]
    fqdn = ["R","D 130 192.0.2.7 lease.example","D 130 192.0.2.7 lease",put(owner="lease.example",alias="alias"),request("alias")]
    for label, replacement in [
        ("same", ["D 160 192.0.2.7 lease.example","D 160 192.0.2.7 lease"]),
        ("new-leaf", ["D 160 192.0.2.7 renamed.example","D 160 192.0.2.7 renamed"]),
        ("new-domain", ["D 160 192.0.2.7 lease.other","D 160 192.0.2.7 lease"]),
        ("newest-other-lease", ["D 170 192.0.2.8 other.example","D 170 192.0.2.8 other",
            "D 160 192.0.2.7 lease.example","D 160 192.0.2.7 lease"]),
    ]:
        yield f"fqdn-short-republication-{label}", "", fqdn+["R"]+replacement+[request("alias",now=102),request("alias",5,now=102),request("alias",5,now=102,operation="N")]
    for reverse in (True, False):
        config = "cname=lease,static\nhost-record=static,192.0.2.9\n"
        if not reverse: config += "host-record=owner,192.0.2.7\n"
        config += "host-record=lease,192.0.2.7\n"
        yield f"alias-local-cname-with-{'reverse' if reverse else 'nonreverse'}-host", config, [
            put(alias="alias"),request("alias",5,operation="N"),request("alias"),request("alias",5),request("lease")]
    yield "replacement-suppressed-by-static-does-not-reuse-target", "host-record=static,192.0.2.9\n", before+[
        put(alias="alias"),request("alias"),"R","D 160 192.0.2.9 static",request("alias",5,now=102),request("alias",now=102),request("alias",5,now=102,operation="N")]
    yield "alias-local-other-family-any-and-unknown", "", before+[
        put(alias="alias"),request("alias",28),request("alias",255),request("alias",65280)]
    yield "alias-local-configured-cname-other-types", "cname=lease,static\nhost-record=static,192.0.2.9\nhost-record=lease,192.0.2.7\n", [
        put(alias="alias"),request("alias",28),request("alias",255),request("alias",65280)]
    # Lease-file recovery retains name bytes, so publication is not restricted
    # to Name::from_ascii's input domain. Wire lengths count encoded bytes.
    opaque = "lÿase"
    yield "restored-byte-name-invalidates-prior-address", "", [
        put(owner=opaque,address=99),"R",f"D 130 192.0.2.7 {opaque}",request(opaque),"R",request(opaque,now=102)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repeat_reference(args, out):
    baseline=args.repeat_reference.resolve()
    identity=json.loads((baseline / "result.json").read_text())
    binary=baseline / "local-answer-oracle"
    assert digest(binary)==identity["c_oracle_sha256"] and not identity["failures"]
    cases=[row for row in identity["rows"] if row["label"].startswith("fqdn-short-republication-")]
    assert cases and args.rounds>0
    plan={"rounds":args.rounds,"cases":[row["case"] for row in cases],"c_oracle_sha256":digest(binary),
        "source_sha256":identity["source_sha256"],"selection":"all predeclared FQDN/short-name reuse cases, every round retained",
        "inputs":{str(row["case"]):{"commands":digest(baseline / f'{row["case"]:02}.input'),
            "config":digest(baseline / f'{row["case"]:02}.conf')} for row in cases}}
    (out / "plan.json").write_text(json.dumps(plan,indent=2)+"\n")
    summaries=[];failures=[]
    for case in cases:
        index=case["case"];config=baseline / f"{index:02}.conf";source=baseline / f"{index:02}.input"
        shutil.copy2(config,out / config.name);shutil.copy2(source,out / source.name)
        commands=source.read_text().splitlines();wire="\n".join(commands)+"\n"
        original_targets={}
        for command in commands:
            if command.startswith("P "):
                packet=local_answer_diff.dns_semantics(command.split()[2])
                for rr in packet["sections"][0][1]:
                    if rr[1]==5: original_targets[rr[0]]=rr[4][0]
        variants={};changed_targets=[]
        for round_number in range(args.rounds):
            run=subprocess.run([str(binary),"-C",str(config)],input=wire,text=True,capture_output=True)
            prefix=out / f"{index:02}-round-{round_number:02}"
            prefix.with_suffix(".stdout").write_text(run.stdout);prefix.with_suffix(".stderr").write_text(run.stderr)
            if run.returncode:
                failures.append({"case":index,"round":round_number,"exit":run.returncode});continue
            observed=names.observations(commands,run.stdout)
            key=json.dumps(observed,sort_keys=True)
            variants.setdefault(key,[]).append(round_number)
            for step,result in enumerate(observed):
                if isinstance(result,dict):
                    for rr in result["sections"][0][1]:
                        if rr[1]==5 and rr[0] in original_targets and rr[4][0]!=original_targets[rr[0]]:
                            changed_targets.append({"round":round_number,"step":step,"owner":rr[0],
                                "target_from_upstream_input":original_targets[rr[0]],"observed_target":rr[4][0]})
        summaries.append({"case":index,"label":case["label"],"distinct_outputs":len(variants),
            "variants":[{"rounds":rounds,"observations":json.loads(key)} for key,rounds in variants.items()],
            "changed_targets":changed_targets})
    report={"scope":"C/C across processes with identical concrete input, config, source and ELF; no Rust expected outputs",
        **plan,"results":summaries,"failures":failures,
        "runs":args.rounds*len(cases),"cases_with_drift":sum(row["distinct_outputs"]>1 for row in summaries),
        "changed_target_answers":sum(len(row["changed_targets"]) for row in summaries)}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("results","inputs","source_sha256")}))
    return int(bool(failures))


def compare(args, out):
    # Retain legacy local invocation; Oracle always requires a copied probe.
    if not (args.rust_test_binary or args.rust_build_receipt):
        args.local_native = True
    probe, source_root, binding = rust_lib_probe.selection(args, ROOT, out)
    baseline = args.compare_baseline.resolve()
    identity = json.loads((baseline / "result.json").read_text())
    assert not identity["failures"] and digest(baseline / "local-answer-oracle") == identity["c_oracle_sha256"]
    inputs = [source_root / "components/dnsmasq/src/dns" / name for name in
        ("daemon.rs","daemon_lease_cache_tests.rs","cache_engine.rs","cache.rs","cache_reply.rs","local.rs","lease_names.rs","service.rs","wire.rs")]
    source_identity = {str(path.relative_to(source_root)):digest(path) for path in inputs}
    frozen = probe
    if probe is None:
        build = subprocess.run([args.cargo,"test","--manifest-path",str(source_root / "components/dnsmasq/Cargo.toml"),
            "--lib","--no-run","--message-format=json"],text=True,capture_output=True)
        (out / "rust-build.stdout").write_text(build.stdout);(out / "rust-build.stderr").write_text(build.stderr)
        assert build.returncode == 0, "Rust driver build failed; see captured build logs"
        assert source_identity == {str(path.relative_to(source_root)):digest(path) for path in inputs}, "Rust source changed during driver build"
        binaries = [Path(row["executable"]) for line in build.stdout.splitlines() if line.startswith("{")
            for row in [json.loads(line)] if row.get("executable") and row.get("profile",{}).get("test")]
        assert len(binaries)==1
        frozen = out / "rust-driver";shutil.copy2(binaries[0],frozen)
    command = rust_lib_probe.argv(frozen, TEST)
    mismatches, rows = [], []
    counts = {"commands":0,"queries":0,"dynamic_lookups":0,"c_hits":0,"rust_hits":0,"c_misses":0,"rust_misses":0}
    for case in identity["rows"]:
        rust_lib_probe.recheck(binding)
        index = case["case"]
        config = out / f"{index:02}.conf"; source = out / f"{index:02}.input"
        shutil.copy2(baseline / config.name,config);shutil.copy2(baseline / source.name,source)
        commands = source.read_text().splitlines()
        env = {**os.environ,"DNSMASQ_LEASE_CACHE_CONFIG":str(config),"DNSMASQ_LEASE_CACHE_INPUT":str(source)}
        run = subprocess.run(command,text=True,capture_output=True,env=env)
        (out / f"{index:02}.rust.stdout").write_text(run.stdout);(out / f"{index:02}.rust.stderr").write_text(run.stderr)
        expected_wire = (baseline / f"{index:02}.stdout").read_text()
        (out / f"{index:02}.c.stdout").write_text(expected_wire)
        actual_wire = "\n".join(line.removeprefix("LEASE_CACHE_ORACLE ")
            for line in rust_lib_probe.records(run.stdout, TEST, "LEASE_CACHE_ORACLE "))+"\n"
        rust_lib_probe.recheck(binding)
        if run.returncode:
            mismatches.append({"case":index,"label":case["label"],"exit":run.returncode})
            continue
        rust_lib_probe.require_one_test(run.stdout, TEST)
        expected = names.observations(commands,expected_wire);actual = names.observations(commands,actual_wire)
        for step,(left,right) in enumerate(zip(expected,actual,strict=True)):
            counts["commands"] += 1
            if commands[step].startswith("Q "):
                counts["queries"] += 1
                counts["c_misses" if left is None else "c_hits"] += 1
                counts["rust_misses" if right is None else "rust_hits"] += 1
            if commands[step].startswith("N "): counts["dynamic_lookups"] += 1
            if left != right:
                mismatches.append({"case":index,"label":case["label"],"step":step,"command":commands[step],"c":left,"rust":right})
        rows.append({"case":index,"label":case["label"],"exit":run.returncode,"commands":len(commands)})
    assert counts["c_hits"] + counts["c_misses"] == counts["queries"]
    assert counts["rust_hits"] + counts["rust_misses"] == counts["queries"]
    # Verify comparison sensitivity to a real C TTL field and row count.
    values = names.observations((baseline / "00.input").read_text().splitlines(),(baseline / "00.stdout").read_text())
    mutated = json.loads(json.dumps(values));mutated[2]["sections"][0][1][0][3] += 1
    assert sum(a != b for a,b in zip(values,mutated,strict=True)) == 1
    try: names.observations(["R","R"],"R\n")
    except StopIteration: pass
    else: raise AssertionError("truncated output must fail count calibration")
    report={"scope":"actual C cache insertion/local blocking and subsequent local/cache answers; no listeners or performance claim",
        "cases":len(rows),**counts,"mismatches":mismatches,"rows":rows,
        "cohorts":{"ordinary_insertion_mismatches":sum(not row["label"].startswith("fqdn-short-republication-") for row in mismatches),
            "layout_reuse_mismatches":sum(row["label"].startswith("fqdn-short-republication-") for row in mismatches)},
        "rust_driver_sha256":digest(frozen),"rust_source_sha256":source_identity,"rust_probe":binding,
        "c_oracle_sha256":identity["c_oracle_sha256"],"calibration":{"ttl_mutation_detected":1,"short_count_rejected":1,"c_miss_hit_expiry":1,"invalid_c_config_rejected":1}}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k not in ("rows","mismatches")}|{"mismatches":len(mismatches)}))
    return int(bool(mismatches))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path)
    parser.add_argument("--compare-baseline",type=Path)
    parser.add_argument("--repeat-reference",type=Path)
    parser.add_argument("--rounds",type=int,default=8)
    parser.add_argument("--cargo",default=shutil.which("cargo"))
    parser.add_argument("--output",type=Path,required=True)
    rust_lib_probe.add_arguments(parser)
    args=parser.parse_args();out=args.output.resolve()
    assert out.is_relative_to(ROOT / "private") and not out.exists();out.mkdir(parents=True)
    if args.repeat_reference: return repeat_reference(args,out)
    if args.compare_baseline: return compare(args,out)
    if not args.reference_build: parser.error("baseline requires --reference-build")
    reference=args.reference_build.resolve();obj=reference / "dnsmasq"
    if not obj.is_dir(): obj=reference
    for name,expected in names.HASHES.items(): assert digest(obj / name) == expected
    local_answer_diff.DRIVER=Path(__file__).with_name("lease_names_driver.c")
    binary=local_answer_diff.build_oracle(reference,out)
    rows=[]
    for index,(label,extra,commands) in enumerate(corpus()):
        config=out / f"{index:02}.conf"
        config.write_text("no-hosts\nno-resolv\nno-round-robin\ncache-size=64\nneg-ttl=60\nlocal-ttl=37\n"+extra)
        wire="\n".join(commands)+"\n";(out / f"{index:02}.input").write_text(wire)
        run=subprocess.run([str(binary),"-C",str(config)],input=wire,text=True,capture_output=True)
        (out / f"{index:02}.stdout").write_text(run.stdout);(out / f"{index:02}.stderr").write_text(run.stderr)
        result=names.observations(commands,run.stdout)
        if index==0:
            assert result[0] is None and result[1]=="P 0" and result[2]["sections"][0][1][0][3]==89
            assert result[3]=="N 1" and result[4] is None and result[5]=="N 0"
        rows.append({"case":index,"label":label,"commands":len(commands),"exit":run.returncode})
    invalid=out / "invalid.conf";invalid.write_text("not-a-real-dnsmasq-option=1\n")
    rejected=subprocess.run([str(binary),"-C",str(invalid)],input="R\n",text=True,capture_output=True)
    (out / "invalid.stderr").write_text(rejected.stderr);assert rejected.returncode
    report={"scope":"C-only defined local insertion and CNAME lifetime baseline; names retained by fixture after unhash",
        "cases":len(rows),"rows":rows,"failures":[row for row in rows if row["exit"]],"source_sha256":names.HASHES,
        "c_oracle_sha256":digest(binary),"calibration":{"miss_hit_expiry":1,"dynamic_count":1,"invalid_config_rejected":1}}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="rows"}));return int(bool(report["failures"]))


if __name__=="__main__":
    raise SystemExit(main())
