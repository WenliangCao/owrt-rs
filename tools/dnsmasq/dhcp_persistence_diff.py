#!/usr/bin/env python3
"""Exact-C lease file/DNS/expiry sequencing oracle, with bounded I/O faults.

C-only mode calibrates the reference before a Rust adapter is supplied. The
file stream is instrumented: rendered bytes are not a claim of durability or
an emulation of every libc buffering detail. No lease pathname is opened.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
from dhcp_reply_diff import extract
from dhcp_destination_diff import compare, calibrate

ROOT=Path(__file__).resolve().parents[2]
EXPECTED={"lease.c":"4260039af27b40084cbe6dbbae2bb9417fa3a91806ea53f3f6bdd20234cad763",
          "dnsmasq.c":"d4bb7cde522376200a0293427b0812625ebc457f10dc9d3e2bef243ccba8ccd1",
          "config.h":"dacbe1f8d0e03d93e53a81901956b07ab7a5059d1e5db3225150a9688a1122da"}
PREFIX=r'''
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define ARPHRD_ETHER 1
#define LEASE_RETRY 60
#define ADDRSTRLEN 64
#define MS_DHCP 0
#define LOG_ERR 0
#define OPT_DHCP_FQDN 1
#define _(x) (x)
#define EVENT_ALARM 1
union all_addr {struct in_addr addr4;};
struct dhcp_lease {struct dhcp_lease *next;struct in_addr addr;time_t expires;
 int hwaddr_type,hwaddr_len,clid_len,agent_id_len,vendorclass_len;
 unsigned char hwaddr[16],*clid,*agent_id,*vendorclass;char *hostname,*fqdn;};
static struct {FILE *lease_stream;char *lease_file;char addrbuff[64];unsigned int soa_sn;int port;} state;
#define daemon (&state)
static struct dhcp_lease *leases;
static int file_dirty,dns_dirty,fqdn_only,failure,wrote,pipewrite;
static char trace[4096],rendered[4096];static size_t trace_len,rendered_len;
static time_t requested_alarm,current_alarm,clock_now;static int queued_alarm,logs;
static void event(const char *format,...) {va_list args;va_start(args,format);
 int n=vsnprintf(trace+trace_len,sizeof(trace)-trace_len,format,args);va_end(args);
 if(n<0||(size_t)n>=sizeof(trace)-trace_len)abort();trace_len+=n;}
static int option_bool(int option){(void)option;return fqdn_only;}
static void file_rewind(FILE *stream){(void)stream;event("rewind;");if(failure==1)errno=ESPIPE;}
static int file_fileno(FILE *stream){(void)stream;return 42;}
static int file_truncate(int fd,off_t size){(void)fd;(void)size;event("truncate;");
 if(failure==2){errno=EACCES;return -1;}rendered_len=0;return 0;}
static int file_print(FILE *stream,const char *format,va_list args){(void)stream;
 if(!wrote){event("write;");wrote=1;}char text[1024];int n=vsnprintf(text,sizeof(text),format,args);
 if(n<0||(size_t)n>=sizeof(text)||rendered_len+(size_t)n>=sizeof(rendered))abort();
 if(failure==3&&rendered_len+(size_t)n>16){size_t count=rendered_len<16?16-rendered_len:0;
 memcpy(rendered+rendered_len,text,count);rendered_len+=count;errno=ENOSPC;return -1;}
 memcpy(rendered+rendered_len,text,n);rendered_len+=n;return n;}
static int file_flush(FILE *stream){(void)stream;event("flush;");if(failure==4){errno=ENOSPC;return -1;}return 0;}
static int file_sync(int fd){(void)fd;event("sync;");if(failure==5){errno=EIO;return -1;}return 0;}
static void my_syslog(int priority,const char *format,...){(void)priority;(void)format;logs++;event("log;");}
static unsigned int fake_alarm(unsigned int seconds){current_alarm=clock_now+seconds;event("arm:%u;",seconds);return 0;}
static void send_event(int fd,int type,int value,const char *message){(void)fd;(void)type;(void)value;(void)message;queued_alarm++;event("immediate;");}
static void reference_send_alarm(time_t event,time_t now);
static void schedule_alarm(time_t event_time,time_t now){requested_alarm=event_time;event("alarm:%lld;",(long long)event_time);reference_send_alarm(event_time,now);}
static void cache_unhash_dhcp(void){event("unhash;");}
static void cache_add_dhcp_entry(char *name,int protocol,union all_addr *address,time_t expires){
 char text[64];inet_ntop(protocol,address,text,sizeof(text));event("dns:%s:%s:%lld;",name,text,(long long)expires);}
#define rewind file_rewind
#define fileno file_fileno
#define ftruncate file_truncate
#define vfprintf file_print
#define fflush file_flush
#define fsync file_sync
#define alarm fake_alarm
'''
MAIN=r'''
int main(void){
 char line[1024];
 while(fgets(line,sizeof(line),stdin)){
  long long now,expiry;int stream,force,reply;
  if(sscanf(line,"%lld %d %lld %d %d %d %d %d %d %d",&now,&failure,&expiry,&file_dirty,&dns_dirty,&stream,&state.port,&fqdn_only,&force,&reply)!=10)return 2;
  struct dhcp_lease first={0},second={0};
  first.next=&second;inet_pton(AF_INET,"192.0.2.10",&first.addr);inet_pton(AF_INET,"192.0.2.11",&second.addr);
  first.expires=expiry;first.hwaddr_type=second.hwaddr_type=1;first.hwaddr_len=second.hwaddr_len=6;
  first.hwaddr[0]=second.hwaddr[0]=2;first.hwaddr[5]=1;second.hwaddr[5]=2;
  first.hostname="first";first.fqdn="first.test";second.hostname="second";
  unsigned char clid[]={1,2},agent[]={3,4},vendor[]={5};first.clid=clid;first.clid_len=2;
  first.agent_id=agent;first.agent_id_len=2;second.vendorclass=vendor;second.vendorclass_len=1;
  leases=&first;state.lease_stream=stream?(FILE *)(uintptr_t)1:NULL;state.lease_file="fixture.leases";state.soa_sn=7;
  trace_len=0;trace[0]=0;memcpy(rendered,"old",3);rendered_len=3;wrote=queued_alarm=logs=0;
  requested_alarm=-1;current_alarm=777;clock_now=now;errno=0;
  event("state;");lease_update_file(now);lease_update_dns(force);if(reply)event("send;");
  printf("%d %d %u %lld %lld %d %d ",file_dirty,dns_dirty,state.soa_sn,(long long)requested_alarm,(long long)current_alarm,queued_alarm,logs);
  for(size_t i=0;i<rendered_len;i++)printf("%02x",(unsigned char)rendered[i]);printf(" %s\n",trace);
 }
 return 0;
}
'''


def oracle(sources):
    return (PREFIX+"\n#define send_alarm reference_send_alarm\n"+extract(sources["dnsmasq.c"],"send_alarm")+
            "\n#undef send_alarm\n#define send_alarm schedule_alarm\n"+
            extract(sources["lease.c"],"ourprintf")+extract(sources["lease.c"],"lease_update_file")+
            extract(sources["lease.c"],"lease_update_dns")+MAIN)


def cases():
    rows=[]
    for failure in range(6):rows.append(f"100 {failure} 200 1 1 1 53 0 0 1")
    rows += ["100 0 200 0 1 1 53 0 0 0", "100 0 200 1 1 0 53 0 0 1",
             "100 0 200 1 1 1 0 0 0 1", "100 0 200 0 0 1 53 1 1 0",
             "100 5 120 1 1 1 53 0 0 1", "100 0 0 1 1 1 53 0 0 1",
             "100 0 100 1 1 1 53 0 0 0", "0 0 0 0 0 0 0 0 0 0"]
    rng=random.Random(0x2931f1)
    for _ in range(300):
        now=rng.choice([0,100,200])
        # dhcp_packet/EVENT_ALARM prune before update_file. Do not invent an
        # expired active lease in its retry-error branch outside that contract.
        expiry=rng.choice([0,now+1,now+20,now+60,now+100])
        rows.append(f"{now} {rng.randrange(6)} {expiry} {rng.randrange(2)} {rng.randrange(2)} {rng.randrange(2)} {rng.choice([0,53])} {rng.randrange(2)} {rng.randrange(2)} {rng.randrange(2)}")
    return rows


def calibrate_c(lines):
    fields=[line.split() for line in lines]
    assert fields[0][:7]==["0","0","8","200","200","0","0"]
    assert fields[1][0]=="1" and fields[1][3]=="160" and "truncate;" not in fields[1][-1]
    assert all(fields[index][0]=="1" for index in range(1,6))
    assert "sync;" not in fields[4][-1] and "flush;sync;" in fields[5][-1]
    assert "send;" in fields[5][-1] and fields[5][-1].index("unhash;")<fields[5][-1].index("send;")
    assert fields[7][0]=="1" and "rewind;" not in fields[7][-1]
    assert fields[8][1]=="1" and "unhash;" not in fields[8][-1]
    assert fields[11][4]=="777" # event=0 leaves an existing alarm alone.


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=ROOT/"private/dnsmasq-rewrite/reference/dnsmasq-2.93/src")
    parser.add_argument("--out",type=Path,required=True);parser.add_argument("--rust-probe",type=Path)
    args=parser.parse_args();calibrate();out=args.out.resolve();assert out.is_relative_to(ROOT/"private")
    out.mkdir(parents=True,exist_ok=False);sources={}
    for name,expected in EXPECTED.items():
        raw=(args.source/name).read_bytes();assert hashlib.sha256(raw).hexdigest()==expected;sources[name]=raw.decode()
    assert "#define LEASE_RETRY 60" in sources["config.h"]
    (out/"oracle.c").write_text(oracle(sources))
    subprocess.run([shutil.which("cc"),"-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all",str(out/"oracle.c"),"-o",str(out/"oracle")],check=True)
    inputs=cases();payload="\n".join(inputs)+"\n";(out/"input.txt").write_text(payload)
    run=subprocess.run([str(out/"oracle")],input=payload,text=True,capture_output=True)
    (out/"c.stdout").write_text(run.stdout);(out/"c.stderr").write_text(run.stderr);run.check_returncode()
    expected=run.stdout.splitlines();assert len(expected)==len(inputs);calibrate_c(expected)
    result={"mode":"C-only calibrated baseline","cases":len(inputs),"source_sha256":EXPECTED,
            "scope":"instrumented lease_update_file/lease_update_dns/send_alarm; no actual file path, libc-buffering or full service claim"}
    if args.rust_probe:
        run=subprocess.run([str(args.rust_probe)],input=payload,text=True,capture_output=True)
        (out/"rust.stdout").write_text(run.stdout);(out/"rust.stderr").write_text(run.stderr);run.check_returncode()
        result.update(compare(inputs,expected,run.stdout.splitlines()),mode="C/Rust differential")
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="mismatches"}));return int(result.get("error_count",0)!=0)


if __name__=="__main__":raise SystemExit(main())
