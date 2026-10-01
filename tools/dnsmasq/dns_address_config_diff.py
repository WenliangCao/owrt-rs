#!/usr/bin/env python3
"""Exact read_opts oracle for bogus-nxdomain and ignore-address prefixes.

No listener is opened. Defined nonnegative C int values only: overflow in
C atoi is outside this differential contract and Rust rejects it explicitly.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import dhcp_config_diff as base
import local_answer_diff

C_DRIVER = r'''
#include "dnsmasq.h"
int main(int argc,char **argv) {
 rand_init();read_opts(argc,argv,"dns-address-state");
 for(int kind=0;kind<2;kind++) {
  unsigned i=0;
  for(struct bogus_addr *p=kind?daemon->ignore_addr:daemon->bogus_addr;p;p=p->next) {
   printf("%c %u %u %d ",kind?'i':'b',i++,p->is6?6:4,p->prefix);
   unsigned char *data=p->is6?(unsigned char *)&p->addr.addr6:(unsigned char *)&p->addr.addr4;
   for(int byte=0;byte<(p->is6?16:4);byte++){printf("%02x",data[byte]);}
   puts("");
  }
 }
 return 0;
}
'''
RUST_DRIVER = r'''
#[path="CONFIG"] mod config;
#[path="HOSTS"] mod hosts;
use std::{net::IpAddr,path::Path};
fn main() {
 let mut dns=config::dns::DnsConfig::default();
 let args:Vec<_>=std::env::args_os().skip(1).collect();
 let action=match config::loader::load(&args,Path::new("/etc/dnsmasq.conf"),|d,_| {
  if dns.apply(d)? {Ok(())}else{Err(config::Error("unsupported probe directive"))}
 }) {Ok(action)=>action,Err(error)=>{eprintln!("{error}");std::process::exit(error.exit_code);}};
 if action==config::loader::Action::Test{return;}
 for (kind,rules) in [('b',&dns.bogus_addresses),('i',&dns.ignore_addresses)] {
  for (index,rule) in rules.iter().enumerate() {
   let (family,data)=match rule.address {IpAddr::V4(a)=>(4,a.octets().to_vec()),IpAddr::V6(a)=>(6,a.octets().to_vec())};
   print!("{kind} {index} {family} {} ",rule.prefix);for byte in data{print!("{byte:02x}");}println!();
  }
 }
}
'''


def corpus():
    values = ["192.0.2.7", "192.0.2.7/32", "192.0.2.7/24", "192.0.2.7/0", "192.0.2.7/",
              "192.0.2.7/33", "192.0.2.7/128", "192.0.2.7/2147483647", "192.0.2.7/-1", "192.0.2.7/+1",
              "192.0.2.7/00024", "192.0.2.7/24/1", "192.0.2.7/24,1", "192.0.2.7/255.255.255.0",
              "192.0.2.7 / 24", '"192.0.2.7/24"', '192.0.2.7/"24"', '"192.0.2.7"/24',
              '" 192.0.2.7"/24', '192.0.2.7/"24 "', "", "/", "0.0.0.0", "255.255.255.255/32",
              "127.1", "192.0.2.007", "192.0.2.256", "::", "::/0", "::/", "::1/128", "::1/129",
              "2001:db8::7/64", "::ffff:192.0.2.7/120", "2001:db8::7/32", "2001:db8::7/000128",
              "fe80::1%lo", "[2001:db8::7]", "2001:db8::bad::1", "192.0.2.7,198.51.100.7"]
    yield "empty", "", []
    for option in ("bogus-nxdomain", "ignore-address"):
        for index,value in enumerate(values):
            yield f"{option}-{index}", option + "=" + value + "\n", []
        yield option + "-newest", f"{option}=192.0.2.7/24\n{option}=2001:db8::7/64\n{option}=192.0.2.7/24\n", []
        yield option + "-cli", "", ["--" + option, "192.0.2.7/24"]
        yield option + "-missing", "", ["--" + option]
        yield option + "-cli-before-file", option + "=2001:db8::7/64\n", ["--" + option + "=192.0.2.7/24"]
    yield "short", "", ["-B192.0.2.7/24", "-B", "2001:db8::7/64"]
    yield "separate-lists", "bogus-nxdomain=192.0.2.7/24\nignore-address=2001:db8::7/64\n", []


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--reference-build",type=Path,required=True)
    parser.add_argument("--rustc",default=shutil.which("rustc") or "rustc")
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--c-only",action="store_true")
    parser.add_argument("--inject-error",action="store_true")
    args=parser.parse_args()
    if args.c_only and args.inject_error:parser.error("negative control needs paired run")
    out=args.out.resolve();assert out.is_relative_to(base.ROOT / "private") and not out.exists();out.mkdir(parents=True)
    base.C_DRIVER=C_DRIVER;base.RUST_DRIVER=RUST_DRIVER
    local_answer_diff.validate_reference_variant(args.reference_build.resolve() / "dnsmasq")
    base.build(args,out)
    rows=[];injected=False
    for index,(label,body,cli) in enumerate(corpus()):
        config=out / f"{index:03}.conf";config.write_text(body);observed=[]
        for side in (["c"] if args.c_only else ["c","rust"]):
            command=[str(out / (side+"-state")),"-C",str(config),*cli]
            run=subprocess.run(command,capture_output=True)
            test=subprocess.run([*command,"--test"],capture_output=True)
            for suffix,payload in [("stdout",run.stdout),("stderr",run.stderr),("test.stderr",test.stderr)]:
                (out / f"{index:03}.{side}.{suffix}").write_bytes(payload)
            observed.append((run,test))
        c,ctest=observed[0];assert c.returncode==ctest.returncode
        if label=="bogus-nxdomain-0":assert c.stdout==b"b 0 4 32 c0000207\n"
        if label=="ignore-address-4":assert c.stdout==b"i 0 4 0 c0000207\n"
        row={"label":label,"c_exit":c.returncode,"state_rows":len(c.stdout.splitlines())}
        if not args.c_only:
            rust,rtest=observed[1]
            if args.inject_error and not injected and c.stdout:
                rust.stdout+=b"wrong\n";injected=True
            row.update(rust_exit=rust.returncode,match=base.matches(c,rust) and ctest.returncode==rtest.returncode)
        rows.append(row)
    assert len(rows)==91
    failures=[] if args.c_only else [row for row in rows if not row["match"]]
    report={"cases":len(rows),"c_accepted":sum(row["c_exit"]==0 for row in rows),"matches":None if args.c_only else len(rows)-len(failures),
            "failed":len(failures),"failures":failures,"rows":rows,"tool_sha256":base.sha(Path(__file__)),"option_sha256":base.OPTION_SHA,
            "scope":"defined-int read_opts prefix address state/order and CLI --test; no service semantics"}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="rows"}));return int(bool(failures))


if __name__=="__main__":raise SystemExit(main())
