#!/usr/bin/env python3
"""Exact native option.c/find_config oracle for scoped ordinary dhcp-host rules.

No listener or system lease file is opened. Raw configuration, generated drivers
and observations are kept below ignored private/. Unsupported selectors remain
separate boundary checks; they never count as successful semantic comparisons.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

import dhcp_config_diff as base

ROOT = base.ROOT
HASHES = {
    "option.c": base.OPTION_SHA,
    "dhcp-common.c": "9139906c5d3a438853fe84e90387cfc299c3c28e7b16a23c7d0d6922847ccc79",
    "util.c": "33920165ef3e92f65d1cab75fe8da7772ad7389b37da79ba881957080f12f973",
}

C_DRIVER = r'''
#include "dnsmasq.h"
static void bytes(const unsigned char *p, int n) {
  if (!p) putchar('-'); else for(int i=0;i<n;i++) printf("%02x",p[i]);
}
static int decode(const char *s, unsigned char *out) {
  if(!strcmp(s,"-")) return 0;
  int n=strlen(s)/2;
  for(int i=0;i<n;i++) { unsigned int x; if(sscanf(s+2*i,"%2x",&x)!=1) abort(); out[i]=x; }
  return n;
}
int main(int argc, char **argv) {
  rand_init(); read_opts(argc,argv,"dhcp-host-state");
  int index=0;
  for(struct dhcp_config *c=daemon->dhcp_conf;c;c=c->next,index++) {
    char addr[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&c->addr,addr,sizeof(addr));
    printf("host=%d addr=%s time=",index,(c->flags&CONFIG_ADDR)?addr:"-");
    if(c->flags&CONFIG_TIME) printf("%u",c->lease_time); else putchar('-');
    printf(" ignore=%d noclid=%d id=",!!(c->flags&CONFIG_DISABLE),!!(c->flags&CONFIG_NOCLID));
    bytes((c->flags&CONFIG_CLID)?c->clid:NULL,(c->flags&CONFIG_CLID)?c->clid_len:0);
    printf(" name="); bytes((unsigned char *)c->hostname,c->hostname?strlen(c->hostname):0);
    printf(" domain="); bytes((unsigned char *)c->domain,c->domain?strlen(c->domain):0);
    printf(" hw=");
    for(struct hwaddr_config *h=c->hwaddr;h;h=h->next) { printf("%d:",h->hwaddr_type);bytes(h->hwaddr,h->hwaddr_len);putchar(';'); }
    putchar('\n');
  }
  char context[8192], clid[8192], hardware[8192]; unsigned int type;
  while(scanf("%8191s %8191s %u %8191s",context,clid,&type,hardware)==4) {
    struct dhcp_context contexts[16]={0}, *ctx=NULL; int count=0;
    if(strcmp(context,"-")) {
      for(char *p=strtok(context,";");p;p=strtok(NULL,";")) {
        if(count>=16) abort();
        char *mask=strchr(p,'/'); if(!mask) abort(); *mask++=0;
        if(inet_pton(AF_INET,p,&contexts[count].start)!=1 || inet_pton(AF_INET,mask,&contexts[count].netmask)!=1) abort();
        if(count) contexts[count-1].current=&contexts[count];
        count++;
      }
      ctx=contexts;
    }
    unsigned char cb[4096], hb[4096]; int cn=decode(clid,cb),hn=decode(hardware,hb);
    struct dhcp_config *match=find_config(daemon->dhcp_conf,ctx,strcmp(clid,"-")?cb:NULL,cn,
      strcmp(hardware,"-")?hb:NULL,hn,type,NULL,NULL);
    index=0; for(struct dhcp_config *c=daemon->dhcp_conf;c && c!=match;c=c->next)index++;
    printf("match=%d\n",match?index:-1);
  }
  return 0;
}
'''

RUST_DRIVER = r'''
#[path = "CONFIG"] mod config;
#[path = "HOSTS"] mod hosts;
use config::{dhcp::DhcpConfig, loader};
use std::{path::Path, io::{self,BufRead},net::Ipv4Addr};
fn hex(bytes:Option<&[u8]>)->String {bytes.map_or_else(||"-".into(),|v|v.iter().map(|b|format!("{b:02x}")).collect())}
fn decode(s:&str)->Option<Vec<u8>> {if s=="-" {None} else {Some((0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect())}}
fn main() {
 let mut dhcp=DhcpConfig::default(); let args:Vec<_>=std::env::args_os().skip(1).collect();
 if let Err(error)=loader::load(&args,Path::new("/etc/dnsmasq.conf"),|d,_| {if dhcp.apply(d)? {Ok(())} else {Err(config::Error("unhandled probe option"))}}) {eprintln!("{error}");std::process::exit(error.exit_code);}
 for (i,c) in dhcp.hosts.iter().enumerate() {
   print!("host={i} addr={} time={} ignore={} noclid={} id={} name={} domain={} hw=",c.address.map_or_else(||"-".into(),|a|a.to_string()),c.lease_time.map_or_else(||"-".into(),|v|v.to_string()),u8::from(c.ignore),u8::from(c.ignore_client_id),hex(c.client_id.as_deref()),hex(c.hostname.as_deref()),hex(c.domain.as_deref()));
   for h in &c.hardware {print!("{}:{};",h.kind,hex(Some(&h.address)));} println!();
 }
 for line in io::stdin().lock().lines() {let line=line.unwrap();let words:Vec<_>=line.split_whitespace().collect();
   let contexts:Option<Vec<(Ipv4Addr,Ipv4Addr)>>=(words[0]!="-").then(||words[0].split(';').map(|v|{let(a,m)=v.split_once('/').unwrap();(a.parse().unwrap(),m.parse().unwrap())}).collect());
   let clid=decode(words[1]);let hw=decode(words[3]);
   let found=dhcp.find_host(clid.as_deref(),words[2].parse().unwrap(),hw.as_deref(),|address|contexts.as_ref().is_none_or(|cs|cs.iter().any(|(start,mask)|u32::from(address)&u32::from(*mask)==u32::from(*start)&u32::from(*mask))));
   println!("match={}",found.map_or(-1,|i|i as i64));
 }
}
'''


def corpus():
    mac = "02:00:00:00:00:01"
    rows = [("contract", "dhcp-host=" + value) for value in [
        mac, mac + ",192.0.2.40", mac + ",fixed", mac + ",FiXeD.example.test,1h",
        mac + ",192.0.2.40,ignore", mac + ",id:*", mac + ",id:*suffix",
        "id:client,192.0.2.41", "ID:client,name", "Id:00:61:62,192.0.2.42",
        "id:,192.0.2.42", "id:client,id:other,192.0.2.42",
        mac + ",02:00:00:00:00:02,192.0.2.43",
        "01-" + mac + ",typed", "06-" + mac + ",typed",
        "020000:000001,compact", "2:0:0:0:0:1,short", mac + ",192.0.2.44,192.0.2.45",
        mac + ",", "," + mac, mac + ",,fixed", mac + ",h", mac + ",m",
        mac + ',"quoted.name"', mac + ",fixed.", mac + ",bad name", mac + ",-bad",
        mac + ",fixed,another", mac + ",bad:name", mac + ",255.255.999.0",
        "gg:00:00:00:00:01,name", "id:gg:00,name", mac + ",2147483647",
        "id:\"a,b\",quoted", '"02:00:00:00:00:01",name',
        ":,empty", "01-:,empty", "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:zz,limit",
    ]]
    rows += [("contract", f"dhcp-host={mac},{duration}") for duration in
             ["0", "1", "119", "120", "121", "000120", "infinite", "INFINITE", "-1", "+1", "1 2h", "12x"]
             + [n + suffix for n in ("0", "1", "2") for suffix in "sSmMhHdDwW"]]
    rows += [("contract", body) for body in [
        f"dhcp-host={mac},192.0.2.40\ndhcp-host=02:00:00:00:00:02,192.0.2.40",
        f"dhcp-host={mac},192.0.2.40\ndhcp-host={mac},192.0.2.41",
        f"dhcp-host=id:client,192.0.2.40\ndhcp-host={mac},192.0.2.41",
        f"dhcp-host={mac},198.51.100.40\ndhcp-host={mac},192.0.2.41",
        f"dhcp-host={mac},name\ndhcp-host={mac},192.0.2.41",
        f"dhcp-host={mac},192.0.2.40\ndhcp-host={mac},192.0.2.41,192.0.2.40",
    ]]
    rows += [("unsupported", "dhcp-host=" + value) for value in [
        mac + ",set:known,192.0.2.40", mac + ",net:known", mac + ",tag:known",
        "02:00:00:00:00:*,192.0.2.40", "named,192.0.2.40", "192.0.2.40", "ignore", "",
    ]]
    return rows


def queries():
    contexts = ["-", "192.0.2.10/255.255.255.0", "198.51.100.10/255.255.255.0",
                "203.0.113.10/255.255.255.0", "198.51.100.10/255.255.255.0;192.0.2.10/255.255.255.0"]
    clients = ["-", b"client".hex(), b"\0client".hex(), b"other".hex(), "006162", "6162"]
    hardware = ["020000000001", "020000000002", "020000000003", "-", ""]
    return "".join(f"{ctx} {clid} {kind} {hw}\n" for ctx in contexts for clid in clients
                   for kind in (1, 6) for hw in hardware if hw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / "private") or out.exists():
        parser.error("--out must be new and below private/")
    out.mkdir(parents=True)
    for name, expected in HASHES.items():
        for path in (args.source / "src" / name, args.reference_build / "dnsmasq" / name):
            if base.sha(path) != expected:
                raise SystemExit(f"source identity mismatch: {path}")
    base.C_DRIVER = C_DRIVER
    base.RUST_DRIVER = RUST_DRIVER
    base.build(args, out)
    stdin = queries().encode()
    (out / "queries.txt").write_bytes(stdin)
    rows = []
    for index, (scope, body) in enumerate(corpus()):
        conf = out / f"{index:03}.conf"
        conf.write_text(body + "\n")
        observed = []
        for binary in (["c-state"] if args.c_only else ["c-state", "rust-state"]):
            run = subprocess.run([str(out / binary), "-C", str(conf)], input=stdin, capture_output=True)
            for stream in ("stdout", "stderr"):
                (out / f"{index:03}.{binary}.{stream}").write_bytes(getattr(run, stream))
            observed.append(run)
        c = observed[0]
        row = {"case": index, "scope": scope, "c_exit": c.returncode,
               "c_matches": c.stdout.count(b"match="), "input": body}
        if not args.c_only:
            rust = observed[1]
            row.update(rust_exit=rust.returncode, match=base.matches(c, rust),
                       boundary_checked=scope == "unsupported" and c.returncode == 0 and rust.returncode != 0)
        rows.append(row)
    accepted = sum(row["c_exit"] == 0 for row in rows)
    # Frozen from native C-only observations before Rust implementation.
    assert (len(rows), accepted, len(stdin.splitlines())) == (94, 83, 240)
    ok = subprocess.CompletedProcess([], 0, b"host=0 addr=192.0.2.40\nmatch=0\n")
    assert base.matches(ok, ok)
    assert not base.matches(ok, subprocess.CompletedProcess([], 0, b"host=0 addr=192.0.2.41\nmatch=0\n"))
    assert not base.matches(ok, subprocess.CompletedProcess([], 0, b"host=0 addr=192.0.2.40\nmatch=-1\n"))
    assert not base.matches(ok, subprocess.CompletedProcess([], 1, b""))
    assert not base.matches(subprocess.CompletedProcess([], 1, b""), subprocess.CompletedProcess([], 2, b""))
    failures = [] if args.c_only else [row for row in rows if not
        (row["boundary_checked"] if row["scope"] == "unsupported" else row["match"])]
    report = {"scope": "dhcp-host native parser and find_config ordinary CLID/exact MAC/subnet matching",
              "cases": len(rows), "c_accepted": accepted, "c_rejected": len(rows) - accepted,
              "queries_per_accepted_config": len(stdin.splitlines()), "failures": failures,
              "contract_matches": None if args.c_only else sum(r["scope"] == "contract" and r["match"] for r in rows),
              "unsupported_boundary_checks": None if args.c_only else sum(r["boundary_checked"] for r in rows),
              "source_sha256": HASHES, "c_oracle_sha256": base.sha(out / "c-state"),
              "calibration": "positive count, address, match index, accept/reject and error status checks",
              "full_functional_equivalence": False, "rows": rows}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "rows"}, indent=2))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
