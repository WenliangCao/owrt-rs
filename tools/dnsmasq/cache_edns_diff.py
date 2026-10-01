#!/usr/bin/env python3
"""Frozen-time exact C cache-answer/receive-query OPT composition differential.

No sockets. C supplies expected packets, stale flags and misses. Both callers
use equal cache capacity, TTL/stale policy, input packets and EDNS limits.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shutil
import struct
import subprocess

import cache_answer_diff as base
import local_answer_diff

ROOT = base.ROOT
C_DRIVER = r'''
#include "dnsmasq.h"
#include <assert.h>
int main(int argc,char **argv) {
 rand_init();read_opts(argc,argv,"cache-edns");daemon->pipe_to_parent=-1;
 daemon->packet_buff_sz=66000;daemon->packet=safe_malloc(66000);
 cache_init();blockdata_init();cache_reload();
 char *line=NULL;size_t capacity=0;
 while(getline(&line,&capacity,stdin)>=0) {
  if(!strcmp(line,"RESET\n")){cache_reload();puts("RESET");continue;}
  char op,hex[131072];long long now;unsigned maximum;
  assert(sscanf(line,"%c %lld %u %131071s",&op,&now,&maximum,hex)==4);
  size_t length=strlen(hex)/2;assert(length>=12&&length<=65535&&maximum<=65535);
  memset(daemon->packet,0,66000);daemon->edns_pktsz=maximum;
  for(size_t i=0;i<length;i++){unsigned byte;assert(sscanf(hex+2*i,"%2x",&byte)==1);daemon->packet[i]=byte;}
  struct dns_header *header=(struct dns_header *)daemon->packet;
  if(op=='P'){assert(extract_addresses(header,length,daemon->namebuff,now,NULL,NULL,0,0,0)==0);puts("P");continue;}
  assert(op=='Q');unsigned char *sizep=NULL;
  int has_opt=find_pseudoheader(header,length,NULL,&sizep,NULL,NULL)!=NULL;
  unsigned limit=512;
  if(has_opt){limit=((unsigned)sizep[0]<<8)|sizep[1];if(limit>maximum)limit=maximum;else if(limit<512)limit=512;}
  int stale=0,filtered=0;
  size_t answer=answer_request(header,daemon->packet+limit,length,(struct in_addr){0},(struct in_addr){0},now,0,0,0,&stale,&filtered);
  if(answer&&has_opt){
   if(stale){u16 ede=htons(EDE_STALE);answer=add_pseudoheader(header,answer,maximum,EDNS0_OPTION_EDE,(unsigned char *)&ede,2,0,0);}
   else answer=add_pseudoheader(header,answer,maximum,0,NULL,0,0,0);
  }
  printf("T %d ",stale);
  if(!answer)puts("NONE");else{for(size_t i=0;i<answer;i++)printf("%02x",(unsigned char)daemon->packet[i]);puts("");}
 }
 free(line);return 0;
}
'''
RUST_DRIVER = r'''
fn cache_edns_probe_insert<R: Random>(daemon: &mut DnsDaemon<R>, packet: &[u8], now: i64) {
 let Ok(header)=super::wire::Header::parse(packet) else{return};
 let Some(cache)=daemon.cache.as_mut() else{return};
 CacheContext{cache,counters:&mut daemon.cache_counters,negative_cache:daemon.negative_cache,negative_ttl:daemon.negative_ttl}
  .insert_reply_with_policy(packet,now,&daemon.local,&Default::default(),header.rcode().into(),true);
}
pub fn cache_edns_probe_main() {
 use std::io::BufRead;
 struct Fixed;impl Random for Fixed{fn next_u32(&mut self)->io::Result<u32>{Ok(7)}}
 let mut config=DnsConfig::default();config.no_resolv=true;config.no_round_robin=true;
 let mut daemon=DnsDaemon::with_random(config.clone(),super::local::configured_hosts(&config,0),&[],DaemonOptions{max_udp:65535,..Default::default()},Fixed).unwrap();
 daemon.enable_cache(100,0,0,StalePolicy::Seconds(60));daemon.enable_negative_cache(30,true);
 for line in std::io::stdin().lock().lines(){
  let line=line.unwrap();if line=="RESET"{daemon.enable_cache(100,0,0,StalePolicy::Seconds(60));println!("RESET");continue;}
  let words:Vec<_>=line.split_whitespace().collect();let now:i64=words[1].parse().unwrap();
  daemon.edns_packet_max=words[2].parse().unwrap();let hex=words[3];
  let packet:Vec<_>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
  if words[0]=="P"{cache_edns_probe_insert(&mut daemon,&packet,now);println!("P");continue;}
  let question=super::forward::Question::parse(&packet).unwrap();
  let answer=daemon.cached_answer_at_with_local(&packet,&question,now,None).unwrap();
  print!("T {} ",u8::from(answer.stale));
  if let Some(packet)=answer.packet{for byte in packet{print!("{byte:02x}");}println!();}else{println!("NONE");}
 }
}
'''


def opt_query(host, kind, advertised):
    packet = bytearray(base.packet(host, kind))
    if advertised is not None:
        packet[10:12] = b"\0\1"
        packet += b"\0" + struct.pack("!HHIH", 41, advertised, 0, 0)
    return bytes(packet)


def corpus():
    rows=[]
    def emit(label,op,packet=b"",now=100,maximum=1232):
        rows.append((label,"RESET" if op=="RESET" else f"{op} {now} {maximum} {packet.hex()}"))
    for family,kind,data in [("a",1,bytes([192,0,2,7])),
                             ("aaaa",28,ipaddress.ip_address("2001:db8::7").packed),
                             ("aaaa-overlong",28,bytes.fromhex("20010db800000000000000000000000007")),
                             ("a-overlong",1,bytes([192,0,2,7,255]))]:
        host="cached.test";emit(f"{family}-reset","RESET")
        emit(f"{family}-insert","P",base.packet(host,kind,0x8180,[(host,kind,10,data)]))
        # A compressed owner is two bytes plus ten fixed bytes and address.
        reply_length=len(base.packet(host,kind))+12+(4 if kind==1 else 16)
        for now in (100,111):
            for maximum in (reply_length+14,reply_length+15,reply_length+16,reply_length+17,512,1232):
                emit(f"{family}-boundary-{now}-{maximum}","Q",opt_query(host,kind,512),now,maximum)
            for advertised in (None,0,511,512,600,1232,4096,65535):
                emit(f"{family}-size-{now}-{advertised}","Q",opt_query(host,kind,advertised),now)
        emit(f"{family}-expired","Q",opt_query(host,kind,1232),170)
    hosts=["alias.test"]+["x"*60+"."+"y"*55+str(index)+".test" for index in range(4)]
    chain=[(hosts[i],5,10,base.name(hosts[i+1])) for i in range(4)]+[(hosts[-1],1,10,bytes([192,0,2,7]))]
    emit("chain-reset","RESET");emit("chain-insert","P",base.packet(hosts[0],1,0x8180,chain))
    for now in (100,111):
        for maximum in (512,600,1232):
            for advertised in (512,600,1232):
                emit(f"chain-{now}-{maximum}-{advertised}","Q",opt_query(hosts[0],1,advertised),now,maximum)
    emit("negative-reset","RESET");emit("negative-insert","P",base.packet("missing.test",1,0x8183))
    for now in (100,131,190):
        for advertised in (None,512,1232):
            emit(f"negative-{now}-{advertised}","Q",opt_query("missing.test",1,advertised),now)
    return rows


def build(args,out):
    local_answer_diff.validate_reference_variant(args.reference_build / "dnsmasq")
    for file,expected in base.HASHES.items():assert base.digest(args.reference_build / "dnsmasq" / file)==expected
    c_source=out/"driver.c";c_source.write_text(C_DRIVER);local_answer_diff.DRIVER=c_source
    c=local_answer_diff.build_oracle(args.reference_build,out)
    if args.c_only:return c,None
    source=out/"rust-source"
    for component in ("dnsmasq","ubus"):
        shutil.copytree(ROOT/f"components/{component}/src",source/component/"src")
        shutil.copy2(ROOT/f"components/{component}/Cargo.toml",source/component/"Cargo.toml")
    shutil.copy2(ROOT/"components/dnsmasq/Cargo.lock",source/"dnsmasq/Cargo.lock")
    with (source/"dnsmasq/src/dns/daemon.rs").open("a") as stream:stream.write(RUST_DRIVER)
    binary=source/"dnsmasq/src/bin/cache-edns-probe.rs";binary.parent.mkdir(exist_ok=True)
    binary.write_text("fn main(){dnsmasq_rs::dns::daemon::cache_edns_probe_main();}\n")
    with (out/"rust-build.log").open("w") as log:
        subprocess.run([args.cargo,"build","--frozen","--manifest-path",str(source/"dnsmasq/Cargo.toml"),"--bin","cache-edns-probe","--target-dir",str(out/"target")],stdout=log,stderr=subprocess.STDOUT,check=True)
    return c,out/"target/debug/cache-edns-probe"


def matches(left,right):
    if left==right:return True
    if not left.startswith("T ") or not right.startswith("T "):return False
    _,c_stale,c=left.split(" ",2);_,r_stale,r=right.split(" ",2)
    if c_stale!=r_stale or "NONE" in (c,r):return False
    # Compression representation may vary; record order, TTL, flags, errors,
    # addresses and OPT/EDE contents remain exact at this frozen clock.
    return local_answer_diff.dns_semantics(c)==local_answer_diff.dns_semantics(r)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--cargo",default=shutil.which("cargo") or "cargo")
    parser.add_argument("--c-only",action="store_true")
    parser.add_argument("--inject-error",action="store_true")
    args=parser.parse_args();out=args.out.resolve()
    assert out.is_relative_to(ROOT/"private") and not out.exists();out.mkdir(parents=True)
    if args.c_only and args.inject_error:parser.error("negative control needs Rust")
    c,rust=build(args,out)
    config=out/"cache.conf";config.write_text("no-hosts\nno-resolv\nno-round-robin\ncache-size=100\nneg-ttl=30\nuse-stale-cache=60\n")
    rows=corpus();data="".join(command+"\n" for _,command in rows)
    (out/"commands.txt").write_text(data);outputs={}
    for side,binary in [("c",c),("rust",rust)]:
        if binary is None:continue
        result=subprocess.run([str(binary),"-C",str(config)],input=data,text=True,capture_output=True)
        (out/(side+".stdout")).write_text(result.stdout);(out/(side+".stderr")).write_text(result.stderr)
        result.check_returncode();outputs[side]=result.stdout.splitlines();assert len(outputs[side])==len(rows)
    assert len(rows)==155 and outputs["c"][0:2]==["RESET","P"]
    assert sum(line.startswith("T 1 ") for line in outputs["c"])==68
    assert sum(line.endswith("NONE") for line in outputs["c"])==7
    _,stale,wire=outputs["c"][2].split(" ",2)
    mutated=bytearray.fromhex(wire);mutated[3]^=1
    bad=f"T {stale} {mutated.hex()}"
    assert matches(outputs["c"][2],outputs["c"][2]) and not matches(outputs["c"][2],bad)
    if args.inject_error:
        outputs["rust"][2]=bad
    failures=[] if not rust else [{"label":label,"c":left,"rust":right} for (label,_),left,right in zip(rows,outputs["c"],outputs["rust"]) if not matches(left,right)]
    report={"commands":len(rows),"queries":sum(command.startswith("Q ") for _,command in rows),"matches":None if not rust else len(rows)-len(failures),"failures":failures,
            "c_stale":sum(line.startswith("T 1 ") for line in outputs["c"]),"c_misses":sum(line.endswith("NONE") for line in outputs["c"]),
            "tool_sha256":base.digest(Path(__file__)),"corpus_sha256":hashlib.sha256(data.encode()).hexdigest(),
            "c_sha256":base.digest(c),"rust_sha256":base.digest(rust) if rust else None,"source_sha256":base.HASHES,
            "scope":"ordinary empty-OPT cache lookup, frozen-time TTL/stale/EDE3, advertised/configured output limits; no DO/AD/option cache metadata"}
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n");print(json.dumps(report));return int(bool(failures))


if __name__=="__main__":raise SystemExit(main())
