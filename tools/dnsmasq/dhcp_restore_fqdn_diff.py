#!/usr/bin/env python3
"""Extract the exact startup lease_calc_fqdns, then compare restored Rust names.

The address-domain lookup is injected at the C caller boundary. Configuration
domain selection has its own oracle; this checks startup reconstruction and
dirty-state preservation. No listener or system lease path is opened.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from dhcp_reply_diff import extract
from dhcp_destination_diff import calibrate, compare

ROOT = Path(__file__).resolve().parents[2]
LEASE_SHA = "4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763"
C_PREFIX = r'''
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct dhcp_lease { struct dhcp_lease *next; struct in_addr addr; char *hostname,*fqdn; };
static struct dhcp_lease *leases;
static char *suffix;
static unsigned int lookups;
static int file_dirty,dns_dirty;
static char *get_domain(struct in_addr address) { (void)address;lookups++;return suffix; }
static void *safe_malloc(size_t n) { void *p=malloc(n);if(!p)abort();return p; }
static char *decode(char *in) {
  if(!strcmp(in,"-"))return NULL;
  size_t n=strlen(in)/2;char *out=safe_malloc(n+1);
  for(size_t i=0;i<n;i++){unsigned int b;if(sscanf(in+2*i,"%2x",&b)!=1)abort();out[i]=b;}
  out[n]=0;return out;
}
'''
C_MAIN = r'''
int main(void) {
  char name[1024],domain[1024];
  while(scanf("%1023s %1023s",name,domain)==2) {
    struct dhcp_lease lease={0};lease.hostname=decode(name);suffix=decode(domain);
    leases=&lease;lookups=0;file_dirty=0;dns_dirty=1;
    lease_calc_fqdns();
    if(!lease.fqdn)putchar('-');
    else for(unsigned char *p=(unsigned char *)lease.fqdn;*p;p++)printf("%02x",*p);
    printf(" %u %d %d\n",lookups,file_dirty,dns_dirty);
    free(lease.hostname);free(lease.fqdn);free(suffix);
  }
  return 0;
}
'''
RUST = r'''
use dnsmasq_rs::dhcp::{lease::LeaseStore,lease_file};
use std::{io::{self,BufRead},net::Ipv4Addr};
fn decode(s:&str)->Option<Vec<u8>> {
 if s=="-" {None} else {Some((0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).unwrap()).collect())}
}
fn main() {
 for line in io::stdin().lock().lines() {
  let line=line.unwrap();let mut words=line.split_whitespace();
  let name=decode(words.next().unwrap());let domain=decode(words.next().unwrap());
  let mut input=b"0 02:00:00:00:00:01 192.0.2.10 ".to_vec();
  input.extend_from_slice(name.as_deref().unwrap_or(b"*"));input.extend_from_slice(b" *\n");
  let mut store=LeaseStore::new(1);store.restore(lease_file::parse(&input).records,100).unwrap();
  let mut lookups=0;store.initialize_fqdns(|_|{lookups+=1;domain.as_deref()});
  let lease=store.get(Ipv4Addr::new(192,0,2,10)).unwrap();
  let value=lease.fqdn.as_ref().map_or_else(||"-".into(),|s|s.iter().map(|b|format!("{b:02x}")).collect::<String>());
  println!("{value} {lookups} {} {}",u8::from(store.changes().file),u8::from(store.changes().dns));
 }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / "private")
    out.mkdir(parents=True, exist_ok=False)
    source = (args.source / "lease.c").read_bytes()
    assert hashlib.sha256(source).hexdigest() == LEASE_SHA
    (out / "oracle.c").write_text(C_PREFIX + extract(source.decode(), "lease_calc_fqdns") + C_MAIN)
    subprocess.run(["cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                    str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    inputs = [f"{name.hex() if name else '-'} {domain.hex() if domain else '-'}"
              for name in (None, b"Node", b"node-2", b"node_3", b"n" * 63)
              for domain in (None, b"pool.test", b"changed.test", b"MiXeD.test")]
    payload = "\n".join(inputs) + "\n"
    (out / "input.txt").write_text(payload)
    run = subprocess.run([str(out / "oracle")], input=payload, text=True, capture_output=True)
    (out / "c.stdout").write_text(run.stdout); (out / "c.stderr").write_text(run.stderr)
    run.check_returncode()
    expected = run.stdout.splitlines()
    assert len(expected) == 20
    assert expected[:4] == ["- 0 0 1"] * 4
    assert expected[4] == "- 1 0 1"
    assert expected[5] == "4e6f64652e706f6f6c2e74657374 1 0 1"
    calibrate()
    result = {"mode": "C-only calibrated baseline", "cases": len(inputs), "source_sha256": LEASE_SHA,
              "scope": "startup FQDN reconstruction; caller-injected address domain; dirty-state preservation"}
    if not args.c_only:
        manifest = ROOT / "components/dnsmasq/Cargo.toml"
        subprocess.run([args.cargo, "build", "--lib", "--manifest-path", str(manifest)], check=True)
        target = manifest.parent / "target/debug"
        (out / "probe.rs").write_text(RUST)
        subprocess.run([args.rustc, "--edition=2021", str(out / "probe.rs"), "--extern",
                        "dnsmasq_rs=" + str(target / "libdnsmasq_rs.rlib"), "-L",
                        "dependency=" + str(target / "deps"), "-o", str(out / "probe")], check=True)
        run = subprocess.run([str(out / "probe")], input=payload, text=True, capture_output=True)
        (out / "rust.stdout").write_text(run.stdout); (out / "rust.stderr").write_text(run.stderr)
        run.check_returncode()
        result.update(compare(inputs, expected, run.stdout.splitlines()), mode="C/Rust differential")
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return int(bool(result.get("error_count", 0)))


if __name__ == "__main__":
    raise SystemExit(main())
