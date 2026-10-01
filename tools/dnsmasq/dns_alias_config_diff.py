#!/usr/bin/env python3
"""Exact native read_opts/doctor oracle for static IPv4 alias configuration.

State and --test acceptance are separate from Rust's runtime readiness gate.
Queries are complete single-A packets through the existing doctor primitive;
no listener or ubus connection is opened.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import dhcp_config_diff as base
import local_answer_diff

ROOT = base.ROOT
HASHES = {"option.c": base.OPTION_SHA,
          "rfc1035.c": "231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222",
          "dnsmasq.h": "318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228",
          "util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973"}
C_DRIVER = r'''
#include "dnsmasq.h"
#include <assert.h>
int main(int argc,char **argv) {
  rand_init();read_opts(argc,argv,"alias-config-state");
  unsigned int i=0;
  for(struct doctor *d=daemon->doctors;d;d=d->next) {
    char from[16],end[16],to[16],mask[16];
    inet_ntop(AF_INET,&d->in,from,sizeof(from));inet_ntop(AF_INET,&d->end,end,sizeof(end));
    inet_ntop(AF_INET,&d->out,to,sizeof(to));inet_ntop(AF_INET,&d->mask,mask,sizeof(mask));
    printf("alias=%u from=%s end=%s to=%s mask=%s\n",i++,from,end,to,mask);
  }
  char line[64];struct in_addr address;
  while(scanf("%63s",line)==1) {
    assert(inet_pton(AF_INET,line,&address)==1);
    unsigned char packet[]={0x29,0x30,0x84,0,0,1,0,1,0,0,0,0,
      7,'e','x','a','m','p','l','e',4,'t','e','s','t',0,0,1,0,1,
      0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,0,0,0,0};
    memcpy(packet+sizeof(packet)-4,&address,4);
    int changed=do_doctor((struct dns_header *)packet,sizeof(packet),daemon->namebuff);
    memcpy(&address,packet+sizeof(packet)-4,4);char result[16];
    inet_ntop(AF_INET,&address,result,sizeof(result));
    printf("rewrite=%s to=%s changed=%d flags=%02x%02x ttl=%u\n",line,result,changed,packet[2],packet[3],
      (unsigned)packet[36]*16777216U+(unsigned)packet[37]*65536U+(unsigned)packet[38]*256U+packet[39]);
  }
  return 0;
}
'''
RUST_DRIVER = r'''
#[path="CONFIG"] mod config;
#[path="HOSTS"] mod hosts;
mod dns {
 #[path="WIRE"] pub mod wire;
 #[path="DOCTOR"] pub mod doctor;
}
use std::{io::{self,BufRead},net::Ipv4Addr,path::Path};
fn main() {
 let mut dns=config::dns::DnsConfig::default();
 let mut args:Vec<_>=std::env::args_os().skip(1).collect();
 let gate=args.first().is_some_and(|s|s=="--runtime-gate");if gate {args.remove(0);}
 let result=(|| {
  let action=config::loader::load(&args,Path::new("/etc/dnsmasq.conf"),|d,_|{
   if dns.apply(d)? {Ok(())} else {Err(config::Error("unhandled probe option"))}
  }).map_err(|error|error.to_string())?;
  dns.finalize().map_err(|error|error.to_string())?;
  if gate {dns.validate_ready().map_err(|error|error.to_string())?;}
  Ok::<_,String>(action)
 })();
 let action=match result {Ok(value)=>value,Err(error)=>{eprintln!("{error}");std::process::exit(1);}};
 if action==config::loader::Action::Test {return;}
 for (i,d) in dns.aliases.iter().enumerate() {
  println!("alias={i} from={} end={} to={} mask={}",d.from,d.end,d.to,d.mask);
 }
 let aliases:Vec<_>=dns.aliases.iter().map(|d|dns::doctor::Alias{from:d.from,end:d.end,to:d.to,mask:d.mask}).collect();
 for line in io::stdin().lock().lines() {
  let line=line.unwrap();let address:Ipv4Addr=line.parse().unwrap();
  let mut packet=vec![0x29,0x30,0x84,0,0,1,0,1,0,0,0,0,7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',4,b't',b'e',b's',b't',0,0,1,0,1,0xc0,0x0c,0,1,0,1,0,0,0,30,0,4,0,0,0,0];
  let end=packet.len();packet[end-4..].copy_from_slice(&address.octets());
  let result=dns::doctor::apply(&mut packet,&aliases,None);assert!(result.stopped.is_none());
  let address=Ipv4Addr::from(<[u8;4]>::try_from(&packet[end-4..]).unwrap());
  println!("rewrite={line} to={address} changed={} flags={:02x}{:02x} ttl={}",u8::from(result.clear_cache_secure),packet[2],packet[3],u32::from_be_bytes(packet[36..40].try_into().unwrap()));
 }
}
'''


def cases():
    f, t, mask = "192.0.2.10", "198.51.100.20", "255.255.255.0"
    values = [f"{f},{t}", f"{f},{t},{mask}", f"{f},{t},255.255.255.255", f"{f},{t},0.0.0.0",
              f"{f},{t},255.0.255.0", "0.0.0.0,255.255.255.255", "255.255.255.255,0.0.0.0",
              f"192.0.2.10-192.0.2.20,{t},{mask}", f"{f}-{f},{t}", f"{f}-192.0.2.20,{t}",
              f"192.0.2.20-192.0.2.10,{t},{mask}", f"192.0.2.10-192.0.3.20,{t},{mask}",
              f"192.0.2.10-192.1.2.20,{t},255.0.255.0", "0.0.0.0-0.0.0.0,203.0.113.0,0.0.0.0",
              "0.0.0.0-255.255.255.255,203.0.113.0,0.0.0.0", "255.255.255.255-255.255.255.255,0.0.0.0",
              "", f, f + ",", "," + t, f + "," + t + ",", f + ",," + mask,
              f + "," + t + "," + mask + ",extra", f + "," + t + "," + mask + ",",
              f"{f}-,{t},{mask}", f"-{f},{t},{mask}", f"{f}-bad,{t},{mask}",
              f"{f}-{f}-{f},{t},{mask}", f"{f}/24,{t}", f"{f},{t},24",
              f"{f},2001:db8::1", f"2001:db8::1,{t}", f"{f},{t},ffff:ffff::",
              f"192.0.2.256,{t}", f"{f},198.51.100.256", f"{f},{t},255.255.999.0",
              f"192.0.2.010,{t}", f"{f},198.51.100.020", f"127.1,{t}",
              f"{f},{t},{mask} # comment", f"{f},{t}#suffix",
              f'"{f}",{t}', f'{f},"{t}"', f'{f},{t},"{mask}"',
              f'"{f},{t}"', f'{f},"{t},{mask}"', f'{f},"{t},{mask},extra"',
              f'{f}," {t}"', f'{f},"{t} "', f'{f},{t}," {mask}"', f'{f},{t},"{mask} "',
              f"  {f}  ,  {t}  ,  {mask}  ", f"{f} - 192.0.2.20 , {t}, {mask}",
              f'{f},"{t}', f'{f},"198.51.100.2\\t0"']
    yield "empty", "", []
    for index, value in enumerate(values): yield f"config-{index:02}", "alias=" + value + "\n", []
    for name, body in [
        ("duplicate", f"alias={f},{t}\nalias={f},{t}\n"),
        ("newest", f"alias={f},{t}\nalias={f},203.0.113.10\n"),
        ("network-then-point", f"alias=192.0.2.0,198.51.100.0,{mask}\nalias={f},203.0.113.10\n"),
        ("point-then-network", f"alias={f},203.0.113.10\nalias=192.0.2.0,198.51.100.0,{mask}\n"),
        ("no-cascade", f"alias={f},{t}\nalias={t},203.0.113.10\n"),
        ("no-cascade-reversed", f"alias={t},203.0.113.10\nalias={f},{t}\n"),
    ]: yield name, body, []
    for index, arguments in enumerate([
        ["--alias=" + f + "," + t], ["--alias", f + "," + t], ["-V", f + "," + t], ["-V" + f + "," + t],
        ["--alias"], ["-V"], ["--alias="], ["--alias", f + "," + t + "," + mask],
        ["--alias", f + "," + t, "--alias", f + ",203.0.113.10"],
    ]): yield f"cli-{index:02}", "", arguments
    yield "cli-before-file", f"alias={f},203.0.113.10\n", ["--alias", f + "," + t]


def queries():
    return "\n".join(["0.0.0.0", "0.0.0.1", "1.0.0.0", "10.0.0.7", "127.0.0.1", "192.0.2.0",
                      "192.0.2.1", "192.0.2.9", "192.0.2.10", "192.0.2.11", "192.0.2.19", "192.0.2.20",
                      "192.0.2.21", "192.0.2.255", "192.0.3.1", "192.1.2.20", "192.1.2.21",
                      "198.51.100.0", "198.51.100.20", "198.51.100.21", "203.0.113.10", "255.255.255.255"]) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--inject-error", action="store_true")
    parser.add_argument("--expect-runtime-alias-rejection", action="store_true",
                        help="reproduce the historical parser-only consumer gate")
    args = parser.parse_args()
    if args.c_only and args.inject_error: parser.error("--inject-error requires a paired run")
    out=args.out.resolve(); assert out.is_relative_to(ROOT / "private"); out.mkdir(parents=True,exist_ok=False)
    base.C_DRIVER = C_DRIVER
    base.RUST_DRIVER = RUST_DRIVER.replace("WIRE",str(ROOT / "components/dnsmasq/src/dns/wire.rs")).replace("DOCTOR",str(ROOT / "components/dnsmasq/src/dns/doctor.rs"))
    local_answer_diff.validate_reference_variant(args.reference_build.resolve() / "dnsmasq")
    for name, expected in HASHES.items():
        for path in [args.source / "src" / name, args.reference_build / "dnsmasq" / name]:
            assert base.sha(path)==expected, path
    base.build(args,out)
    data=queries().encode(); (out / "queries").write_bytes(data); rows=[]
    for index,(name,body,arguments) in enumerate(cases()):
        config=out / f"{index:03}.conf";config.write_text(body)
        observed=[]
        for side in (["c"] if args.c_only else ["c","rust"]):
            command=[str(out / (side+"-state")),"-C",str(config),*arguments]
            value=subprocess.run(command,input=data,capture_output=True)
            test=subprocess.run([*command,"--test"],capture_output=True)
            for suffix,payload in [("stdout",value.stdout),("stderr",value.stderr),("test.stderr",test.stderr)]:
                (out / f"{index:03}.{side}.{suffix}").write_bytes(payload)
            gate=None
            if side=="rust" and value.returncode==0:
                gate=subprocess.run([command[0],"--runtime-gate",*command[1:]],input=b"",capture_output=True)
                (out / f"{index:03}.rust.gate.stderr").write_bytes(gate.stderr)
            observed.append((value,test,gate))
        c,test,_=observed[0]
        row={"case":index,"name":name,"c_exit":c.returncode,"c_test_exit":test.returncode,
             "aliases":c.stdout.count(b"alias="),"queries":c.stdout.count(b"rewrite=")}
        assert test.returncode==c.returncode
        if c.returncode==0:
            assert row["queries"]==22 and all(line.endswith(b"ttl=30") for line in c.stdout.splitlines() if line.startswith(b"rewrite="))
        if name=="empty":
            expected=b"".join(f"rewrite={address} to={address} changed=0 flags=8400 ttl=30\n".encode() for address in queries().splitlines())
            assert c.stdout==expected, "C no-rule calibration"
        if name=="config-00":
            assert c.stdout.splitlines()[0]==b"alias=0 from=192.0.2.10 end=0.0.0.0 to=198.51.100.20 mask=255.255.255.255"
            assert b"rewrite=192.0.2.10 to=198.51.100.20 changed=1 flags=8000 ttl=30\n" in c.stdout
        if name=="config-13":
            assert c.stdout.count(b"changed=1 flags=8000 ttl=30")==22, "C zero-end/zero-mask sentinel"
        if name=="newest":
            assert b"rewrite=192.0.2.10 to=203.0.113.10 changed=1 flags=8000 ttl=30\n" in c.stdout
        if name=="no-cascade":
            assert b"rewrite=192.0.2.10 to=198.51.100.20 changed=1 flags=8000 ttl=30\n" in c.stdout
        if not args.c_only:
            rust,rtest,gate=observed[1]
            if args.inject_error and index==1:
                rust.stdout=rust.stdout.replace(b"to=198.51.100.20",b"to=198.51.100.21",1)
            row.update(rust_exit=rust.returncode,rust_test_exit=rtest.returncode,
                       match=base.matches(c,rust) and test.returncode==rtest.returncode,
                       runtime_exit=gate.returncode if gate else None,
                       runtime_gate=(gate.returncode==int(args.expect_runtime_alias_rejection and row["aliases"]!=0)) if gate else None)
        rows.append(row)
    assert (len(rows),sum(row["c_exit"]==0 for row in rows),sum(row["queries"] for row in rows))==(72,34,748), "frozen C corpus counts"
    failed=[] if args.c_only else [row for row in rows if not row["match"] or row["runtime_gate"] is False]
    report={"cases":len(rows),"c_accepted":sum(row["c_exit"]==0 for row in rows),"failed":len(failed),
            "matches":None if args.c_only else len(rows)-len(failed),"failures":failed,"rows":rows,
            "queries_per_accepted_case":len(data.splitlines()),"c_sha256":base.sha(out / "c-state"),
            "doctor_mapping_observations":sum(row["queries"] for row in rows),
            "runtime_alias_rejections":None if args.c_only else sum(row.get("runtime_exit")==1 and row["aliases"]>0 for row in rows),
            "runtime_alias_accepted":None if args.c_only else sum(row.get("runtime_exit")==0 and row["aliases"]>0 for row in rows),
            "expect_runtime_alias_rejection":args.expect_runtime_alias_rejection,
            "tool_sha256":base.sha(Path(__file__)),
            "source_sha256":HASHES,"scope":"read_opts alias state/--test, runtime readiness and actual single-A doctor semantics; service equivalence requires the separate daemon gate"}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({key:value for key,value in report.items() if key!="rows"},indent=2))
    return int(bool(failed))


if __name__=="__main__": raise SystemExit(main())
