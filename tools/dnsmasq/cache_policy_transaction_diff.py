#!/usr/bin/env python3
"""Exact-C process_reply cache transaction ordering at a frozen clock.

Compare actual reply semantics, insertion/eviction counters and later lookups.
No sockets or physical devices; malformed packet corpora and ELFs stay private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import cache_answer_diff as base
import cache_edns_diff as builder
import cache_clipped_diff as clipped
import local_answer_diff
import tcp_caller_diff as source
import m6b_primitive_assets as assets

ROOT = base.ROOT
C_DRIVER = r'''
#include "dnsmasq.h"
#include <assert.h>
#include "cache-process-exact.inc"
int main(int argc,char **argv) {
 rand_init();read_opts(argc,argv,"cache-policy");daemon->pipe_to_parent=-1;
 daemon->packet_buff_sz=66000;daemon->packet=safe_malloc(66000);
 cache_init();blockdata_init();build_server_array();cache_reload();
 char *line=NULL;size_t capacity=0;
 while(getline(&line,&capacity,stdin)>=0) {
  if(!strcmp(line,"RESET\n")){cache_reload();puts("RESET");continue;}
  char op,hex[131072];long long now;
  assert(sscanf(line,"%c %lld %131071s",&op,&now,hex)==3);
  size_t length=strlen(hex)/2;assert(length>=12&&length<=65535);
  memset(daemon->packet,0,66000);
  for(size_t i=0;i<length;i++){unsigned byte;assert(sscanf(hex+2*i,"%2x",&byte)==1);daemon->packet[i]=byte;}
  struct dns_header *header=(struct dns_header *)daemon->packet;
  if(op=='P') {
   assert(extract_request(header,length,daemon->namebuff,NULL,NULL));
   struct server server;memset(&server,0,sizeof(server));server.flags=SERV_WARNED_RECURSIVE;
   union mysockaddr peer;memset(&peer,0,sizeof(peer));peer.in.sin_family=AF_INET;
   length=process_reply(header,now,&server,length,
      option_bool(OPT_NO_REBIND)&&!domain_no_rebind(daemon->namebuff),
      0,0,0,0,0,1,&peer,1232,EDE_UNSET);
  } else {
   assert(op=='Q');int stale=0,filtered=0;
   length=answer_request(header,daemon->packet+1232,length,(struct in_addr){0},(struct in_addr){0},now,0,0,0,&stale,&filtered);
  }
  printf("%c %u %u ",op,(unsigned)daemon->metrics[METRIC_DNS_CACHE_INSERTED],(unsigned)daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
  if(!length)puts("NONE");else{for(size_t i=0;i<length;i++)printf("%02x",(unsigned char)daemon->packet[i]);puts("");}
 }
 free(line);return 0;
}
'''
RUST_DRIVER = r'''
pub fn cache_edns_probe_main() {
 use std::io::BufRead;
 use super::wire::{Header,Question as WireQuestion};
 struct Fixed;impl Random for Fixed{fn next_u32(&mut self)->io::Result<u32>{Ok(7)}}
 let mut config=DnsConfig::default();let mut scalar=crate::config::ScalarConfig::default();
 let args:Vec<_>=std::env::args_os().skip(1).collect();
 crate::config::loader::load(&args,std::path::Path::new("/etc/dnsmasq.conf"),|d,_|{
  if scalar.apply(d)?||config.apply(d)?{Ok(())}else{Err(crate::config::Error("unsupported probe option"))}
 }).unwrap();config.finalize().unwrap();
 let mut daemon=DnsDaemon::with_random(config.clone(),super::local::configured_hosts(&config,0),&[],DaemonOptions::default(),Fixed).unwrap();
 daemon.enable_cache(scalar.cache_size as usize,0,0,StalePolicy::Disabled);
 daemon.enable_negative_cache(scalar.negative_ttl,!config.no_negative_cache);
 for line in std::io::stdin().lock().lines(){
  let line=line.unwrap();if line=="RESET"{daemon.enable_cache(scalar.cache_size as usize,0,0,StalePolicy::Disabled);println!("RESET");continue;}
  let words:Vec<_>=line.split_whitespace().collect();let now:i64=words[1].parse().unwrap();let hex=words[2];
  let packet:Vec<_>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
  let answer=if words[0]=="P"{
   let question=WireQuestion::parse(&packet,12).unwrap();let header=Header::parse(&packet).unwrap();
   let recipient=super::forward::Recipient{original_id:header.id,question_name:question.name,
    client:Client{source:"127.0.0.1:53000".parse().unwrap(),destination:"127.0.0.1".parse().unwrap(),interface:0,listener:None,reply_requested:true,udp_limit:1232,log_id:1}};
   let mut reply=UncheckedReply{packet,truncated:false,server:super::forward::ServerId(1),flags:super::forward::Flags::default(),cache_eligible:true,recipients:vec![]};
   let rcode=daemon.process_completed_reply(&mut reply,now,None,&mut None).unwrap();
   daemon.recipient_packet(&reply,&recipient,rcode).unwrap()
  }else{
   assert_eq!(words[0],"Q");let question=super::forward::Question::parse(&packet).unwrap();
   daemon.cached_answer_at_with_local(&packet,&question,now,None).unwrap().packet
  };
  print!("{} {} {} ",words[0],daemon.cache_counters.inserted,daemon.cache_counters.live_freed);
  if let Some(packet)=answer{for byte in packet{print!("{byte:02x}");}println!();}else{println!("NONE");}
 }
}
'''


def fixtures():
    host, other, target = "replace.test", "unrelated.test", "target.test"
    def address(owner, value): return (owner, 1, 53, bytes(map(int, value.split("."))))
    old = [address(host, "8.8.8.7")]
    public = address(host, "8.8.8.8"); private = address(host, "10.0.0.9")
    bogus = address(host, "12.0.0.99"); alias = (host, 5, 60, base.name(target))
    def reply(answers, *, tail=False, flags=0x8180):
        packet = base.packet(host, 1, flags, answers)
        return clipped.clipped(packet, "answer") if tail else packet
    cases = []
    def add(label, answers, config="", *, tail=True, previous=old, lookup=(host,), capacity=100):
        cases.append({"label": label, "config": config, "capacity": capacity,
                      "old": reply(previous), "new": reply(answers, tail=tail), "lookup": lookup})
    add("replacement-before-clipped", [public])
    add("clipped-before-replacement", [])
    add("unrelated-owner-before-clipped", [address(other, "8.8.8.8")])
    add("unrelated-type-before-clipped", [(host, 28, 53, bytes.fromhex("20014860486000000000000000008888"))])
    add("cname-before-clipped", [alias], lookup=(host, target))
    add("old-rrset-before-clipped", [public], previous=old+[address(host, "8.8.4.7")])
    add("cname-target-before-clipped", [alias, address(target, "8.8.8.8")], lookup=(host, target))
    add("cname-pressure-before-clipped", [alias, address(target, "8.8.8.8")], lookup=(host, target), capacity=2)
    add("rebind-first", [private, public], "stop-dns-rebind\n", tail=False)
    add("public-before-rebind", [public, private], "stop-dns-rebind\n", tail=False)
    add("rebind-before-clipped", [private], "stop-dns-rebind\n")
    add("cname-before-rebind", [alias, address(target, "10.0.0.9")], "stop-dns-rebind\n", tail=False, lookup=(host, target))
    add("bogus-before-clipped", [bogus], "bogus-nxdomain=12.0.0.99\n")
    add("public-before-bogus", [public, bogus], "bogus-nxdomain=12.0.0.99\n", tail=False)
    add("bogus-unrelated-owner", [public, address(other, "12.0.0.99")], "bogus-nxdomain=12.0.0.99\n", lookup=(host, other))
    add("bogus-target-after-cname", [alias, address(target, "12.0.0.99")], "bogus-nxdomain=12.0.0.99\n", tail=False, lookup=(host, target))
    add("bogus-target-pressure", [address(target, "12.0.0.99")], "bogus-nxdomain=12.0.0.99\n", lookup=(host, target), capacity=2)
    add("doctor-rebind-first", [public], "stop-dns-rebind\nalias=8.8.8.8,10.0.0.9\n")
    add("doctor-rebind-after-public", [address(host, "8.8.4.4"), public], "stop-dns-rebind\nalias=8.8.8.8,10.0.0.9\n")
    add("doctor-unblocks-before-clipped", [private], "stop-dns-rebind\nalias=10.0.0.9,8.8.8.8\n")
    add("doctor-bogus-before-clipped", [public], "bogus-nxdomain=12.0.0.99\nalias=8.8.8.8,12.0.0.99\n")
    add("zero-ttl-before-clipped", [(host, 1, 0, public[3])])
    add("zero-ttl-before-valid-prefix", [(host, 1, 0, public[3]), public])
    add("cname-invalid-target", [(host, 5, 60, b"\xc0\xff")], tail=False)
    add("cname-cycle", [alias, (target, 5, 60, base.name(host))], tail=False, lookup=(host, target))
    add("public-before-cname", [public, alias, address(target, "8.8.4.4")], tail=False, lookup=(host, target))
    add("public-before-cname-before-clipped", [public, alias, address(target, "8.8.4.4")], lookup=(host, target))
    add("bogus-no-negcache", [bogus], "bogus-nxdomain=12.0.0.99\nno-negcache\n")
    add("rebind-domain-exception", [private], "stop-dns-rebind\nrebind-domain-ok=/replace.test/\n")
    # Preserve an independent healthy name while deleting only the affected RRset.
    rows=[]
    for case in cases:
        commands=[("reset","RESET"),("old-insert",f'P 100 {case["old"].hex()}'),
                  ("other-insert",f'P 100 {base.packet(other,1,0x8180,[address(other,"9.9.9.9")]).hex()}'),
                  ("old-hit",f'Q 100 {base.packet(host,1).hex()}'),("incoming",f'P 100 {case["new"].hex()}')]
        for moment in (100,105,160):
            for owner in dict.fromkeys((*case["lookup"],other)):
                commands.append((f"lookup-{owner}-{moment}",f'Q {moment} {base.packet(owner,1).hex()}'))
                if moment == 100:
                    commands.append((f"lookup-aaaa-{owner}",f'Q {moment} {base.packet(owner,28).hex()}'))
        commands += [("recovery-insert", f'P 161 {reply([address(host, "8.8.4.5")]).hex()}'),
                     ("recovery-hit", f'Q 161 {base.packet(host,1).hex()}')]
        rows.append({**case,"commands":commands})
    assert len(rows)==29
    return rows


def equivalent(left,right):
    if left==right:return True
    if left=="RESET" or right=="RESET":return False
    a=left.split(" ",3);b=right.split(" ",3)
    if a[:3]!=b[:3] or "NONE" in (a[3],b[3]):return False
    try:return local_answer_diff.dns_semantics(a[3])==local_answer_diff.dns_semantics(b[3])
    except (ValueError,IndexError):return a[3]==b[3]


def compare(commands,left,right):
    if len(left)!=len(commands) or len(right)!=len(commands):raise ValueError("observation count mismatch")
    return [{"operation":label,"c":a,"rust":b}
            for (label,_),a,b in zip(commands,left,right) if not equivalent(a,b)]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--cargo",default=shutil.which("cargo") or "cargo")
    parser.add_argument("--c-only",action="store_true")
    parser.add_argument("--inject-error",action="store_true")
    assets.add_arguments(parser)
    args=parser.parse_args();out=args.out.resolve();assert 'private' in out.parts and not out.exists();out.mkdir(parents=True)
    args.rust_probe_name = 'm6b-cache-policy'
    forward=args.reference_build/"dnsmasq/forward.c";assert base.digest(forward)==source.FORWARD_SHA
    text=forward.read_text();(out/"cache-process-exact.inc").write_text(source.extract(text,"static int domain_no_rebind(")+source.extract(text,"static size_t process_reply("))
    builder.C_DRIVER=C_DRIVER;builder.RUST_DRIVER=RUST_DRIVER;c,rust=builder.build(args,out)
    if args.c_only and args.inject_error:parser.error("negative control needs Rust")
    cases=fixtures();failures=[];commands=0;counts=[];corpus=hashlib.sha256()
    for case in cases:
        work=out/case["label"];work.mkdir();config=work/"dnsmasq.conf"
        config.write_text(f'no-hosts\nno-resolv\nno-round-robin\ncache-size={case["capacity"]}\nneg-ttl=30\n'+case["config"])
        data="".join(command+"\n" for _,command in case["commands"]);(work/"commands.txt").write_text(data);observed={}
        corpus.update(config.read_bytes());corpus.update(data.encode())
        for side,binary in (("c",c),("rust",rust)):
            if binary is None:continue
            if side == 'rust': assets.unchanged_binary(binary, args.rust_binding)
            run=subprocess.run([str(binary),"-C",str(config)],input=data,text=True,capture_output=True)
            (work/f"{side}.stdout").write_text(run.stdout);(work/f"{side}.stderr").write_text(run.stderr);run.check_returncode()
            observed[side]=run.stdout.splitlines();assert len(observed[side])==len(case["commands"])
            if side == 'rust': assets.unchanged_binary(binary, args.rust_binding)
        expected=observed["c"];assert expected[0]=="RESET" and expected[1].startswith("P ") and not expected[3].endswith("NONE")
        assert not expected[-1].endswith("NONE"), "recovery must commit after an aborted transaction"
        if case["label"] == "replacement-before-clipped":
            assert expected[4].startswith("P 2 0 ") and expected[5] == "Q 2 0 NONE"
            assert not expected[7].endswith("NONE"), "unrelated RRset must survive"
        if case["label"] == "cname-pressure-before-clipped":
            assert expected[4].startswith("P 2 1 ")
            assert expected[5:11] == ["Q 2 1 NONE"] * 6
        if case["label"] == "bogus-before-clipped":
            assert expected[4].startswith("P 3 0 ")
            assert int(expected[6].split(" ",3)[3][6:8],16) & 15 == 3, "bogus owner must have NXDOMAIN for absent type"
        assert not compare(case["commands"],expected,expected)
        changed=list(expected);parts=changed[3].split(" ",3);parts[1]=str(int(parts[1])+1);changed[3]=" ".join(parts)
        assert len(compare(case["commands"],expected,changed))==1
        try:compare(case["commands"],expected,expected[:-1])
        except ValueError:pass
        else:raise AssertionError("missing observation calibration")
        if args.inject_error and case["label"] == "replacement-before-clipped":
            parts=observed["rust"][4].split(" ",3);parts[2]=str(int(parts[2])+1);observed["rust"][4]=" ".join(parts)
        mismatches=[] if rust is None else [{"case":case["label"],**row} for row in compare(case["commands"],expected,observed["rust"])]
        failures.extend(mismatches);commands+=len(expected)
        counts.append({"case":case["label"],"commands":len(expected),"mismatches":len(mismatches)})
    report={"cases":counts,"commands":commands,"mismatches":len(failures),"failures":failures,
            "rust_binding":args.rust_binding,"c_build":args.c_binding,"image_daemon_qualification":False,
            "calibration":{"old_cache_hit":1,"recovery_hit":1,"reference_state_counters":1,"equal":1,"changed_counter":1,"missing_observation":1},
            "injected_error":args.inject_error,"tool_sha256":base.digest(Path(__file__)),"corpus_sha256":corpus.hexdigest(),
            "c_sha256":base.digest(c),"rust_sha256":None if rust is None else base.digest(rust),
            "source_sha256":{**base.HASHES,"forward.c":source.FORWARD_SHA},
            "scope":"frozen process_reply/cache insertion order and side effects with rebind, bogus and static doctor; no dynamic UBus or sockets"}
    if rust and assets.validate(args, 'm6b-cache-policy') != args.rust_binding:
        raise ValueError('Rust primitive binding changed during run')
    if local_answer_diff.verify_c_build(out,c) != args.c_binding:
        raise ValueError('C primitive build binding changed during run')
    (out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="failures"}));return int(bool(failures))


if __name__=="__main__":raise SystemExit(main())
