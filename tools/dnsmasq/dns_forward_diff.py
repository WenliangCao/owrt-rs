#!/usr/bin/env python3
"""Exact-C UDP forwarding state oracle; all send/receive dependencies are in-memory.

Extracts complete forward_query/get_new_frec/lookup_frec/free_frec/fast_retry
functions and wire name functions. Domain routing and socket allocation are
controlled dependencies, not a second implementation of the state machine.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'private/dnsmasq-rewrite/reference/dnsmasq-2.93/src'
HASHES={'forward.c':'ac05784d4233ed10bd166da5fe91e464afecf2883d3c2a0063305d3e81692f95','rfc1035.c':'231f0b4989039ff4963f3916df22871dd13025dde65769465b2b3052ad807222','dnsmasq.h':'318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228','dns-protocol.h':'4c6ed1c818c6a9b00bcdc1193bd364129780a3ef2b88c29475ee7bd6f6a826fe'}


def func(text,name):
    # Function bodies end at a column-zero brace in the exact reference source.
    match=re.search(r'^\w[^;{}\n]*\b'+re.escape(name)+r'\([^;{}]*?\)\n\{',text,re.MULTILINE)
    if not match:raise ValueError(f'function definition not found: {name}')
    start=match.start()
    return text[start:text.index('\n}',start)+2]+'\n'


def build(out,rustc):
    actual={f:hashlib.sha256((SOURCE/f).read_bytes()).hexdigest() for f in HASHES}
    assert actual==HASHES,'reference identity mismatch'
    f=(SOURCE/'forward.c').read_text();r=(SOURCE/'rfc1035.c').read_text();h=(SOURCE/'dnsmasq.h').read_text()
    c=r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
#include "dns-protocol.h"
#define daemon dns_state
#define EXTR_NAME_EXTRACT 1
#define EXTR_NAME_COMPARE 2
#define EXTR_NAME_NOCASE 3
#define EXTR_NAME_FLIP 4
#define TIMEOUT 10
#define FORWARD_TEST 50
#define FORWARD_TIME 20
#define LOG_WARNING 1
#define _(x) x
#define OPT_ORDER 1
#define OPT_ALL_SERVERS 2
#define OPT_NODOTS_LOCAL 4
#define OPT_DO_0x20 8
#define OPT_NO_0x20 16
#define OPT_NOWILD 32
#define OPT_CLEVERBIND 64
#define METRIC_DNS_QUERIES_FORWARDED 0
#define METRIC_DNS_LOCAL_ANSWERED 1
#define METRIC_DNS_UNANSWERED_QUERY 2
struct blockdata {size_t size; unsigned char *data;};
static struct blockdata *blockdata_alloc(char *p,size_t n) {struct blockdata *b=calloc(1,sizeof(*b));assert(b);b->data=malloc(n);assert(b->data);b->size=n;memcpy(b->data,p,n);return b;}
static void blockdata_free(struct blockdata *b) {free(b->data);free(b);}
static void *blockdata_retrieve(struct blockdata *b,size_t n,void *to) {assert(b && n<=b->size);if(to) {memcpy(to,b->data,n);return to;}return b->data;}
union mysockaddr {struct sockaddr sa;struct sockaddr_in in;struct sockaddr_in6 in6;};
union all_addr {struct in_addr addr4;struct in6_addr addr6;};
struct server {union mysockaddr addr;int arrayposn,group,last_server,forwardcount;time_t forwardtime;unsigned retrys,failed_queries,queries;char *domain;};
struct randfd_list {struct randfd_list *next;};
'''
    c+=h[h.index('#define FREC_NOREBIND'):h.index('/* flags in top of length field')]
    c+=h[h.index('#define F_IMMORTAL'):h.index('#define UID_NONE')]
    c+=r'''
static struct {struct frec *frec_list;struct frec_src *free_frec_src;int frec_src_count,ftabsize;unsigned log_id,log_display_id;union mysockaddr *log_source_addr;char namebuff[MAXDNAMESTR+1],workspacename[MAXDNAMESTR+1];struct server *serverarray[6],*srv_save;unsigned char packet[65536];size_t packet_len;int fd_save,edns_pktsz,fast_retry_time,fast_retry_timeout;unsigned metrics[3];} storage,*daemon=&storage;
static unsigned options,random_counter,millis,fail_mask;
static int active_group;
static struct server servers[6];
static int option_bool(unsigned flag) {return !!(options&flag);}
static void *whine_malloc(size_t n) {void *p=calloc(1,n);assert(p);return p;}
static unsigned short rand16(void) {return ++random_counter;}
static u32 rand32(void) {return ++random_counter;}
static u32 dnsmasq_milliseconds(void) {return millis;}
static int sockaddr_isequal(const union mysockaddr *a,const union mysockaddr *b) {return a->in.sin_family==b->in.sin_family && a->in.sin_addr.s_addr==b->in.sin_addr.s_addr && a->in.sin_port==b->in.sin_port;}
static int server_samegroup(struct server *a,struct server *b) {return a->group==b->group;}
static void my_syslog(int p,const char *m,...) {(void)p;(void)m;}
static void log_query_mysockaddr(unsigned f,char *n,union mysockaddr *a,char *s,unsigned short t) {(void)f;(void)n;(void)a;(void)s;(void)t;}
static int domain_no_rebind(char *n) {(void)n;return 0;}
static int lookup_domain(char *n,unsigned g,int *first,int *last) {(void)n;(void)g;*first=active_group*3;*last=*first+3;return 1;}
static unsigned is_local_answer(time_t t,int first,char *n) {(void)t;(void)first;(void)n;return 0;}
static int check_for_local_domain(char *n,time_t t) {(void)n;(void)t;return 0;}
static int filter_servers(int seed,unsigned f,int *first,int *last) {(void)f;*first=seed/3*3;*last=*first+3;return 1;}
static size_t add_pseudoheader(struct dns_header *h,size_t n,size_t out,unsigned short code,unsigned char *data,size_t len,int bit,int replace) {(void)h;(void)out;(void)code;(void)data;(void)len;(void)bit;(void)replace;return n;}
static int allocate_rfd(struct randfd_list **p,struct server *s) {(void)p;return 100+s->arrayposn;}
static void free_rfds(struct randfd_list **p) {*p=NULL;}
static int retry_send(ssize_t result) {(void)result;return 0;}
static ssize_t fake_sendto(int fd,const void *p,size_t n,int flags,const struct sockaddr *s,socklen_t len) {(void)flags;(void)s;(void)len;unsigned id=ntohs(((struct dns_header *)p)->id);int index=fd-100;if(fail_mask&(1u<<index)) {errno=EHOSTUNREACH;return -1;}printf(" S%u:%d",id,index);errno=0;return n;}
#define sendto fake_sendto
static socklen_t sa_len(union mysockaddr *s) {(void)s;return sizeof(struct sockaddr_in);}
static size_t make_local_answer(unsigned flags,unsigned got,size_t n,struct dns_header *h,char *name,size_t limit,int first,int last,int ede) {(void)flags;(void)got;(void)n;(void)h;(void)name;(void)limit;(void)first;(void)last;(void)ede;printf(" R");return 0;}
static int send_from(int fd,int nw,char *p,size_t n,union mysockaddr *a,union all_addr *d,unsigned i) {(void)fd;(void)nw;(void)p;(void)n;(void)a;(void)d;(void)i;abort();}
static struct frec *get_new_frec(time_t now,struct server *serv,int force);
static struct frec *lookup_frec(time_t now,char *target,int cls,int typ,int id,int flags,int mask);
static void free_frec(struct frec *f);
static void query_full(time_t now,char *domain);
static unsigned short get_id(void);
'''
    c+=func(r,'extract_name')+func(r,'extract_request')
    for name in ['free_frec','get_new_frec','query_full','lookup_frec','get_id','forward_query','fast_retry']:
        c+=func(f,name)
    # Preserve the real reply error/retry block; response/source validation is
    # separately tested by lookup_frec and Rust socket/endpoint fixed tests.
    c+='static void response(struct frec *forward,int code,time_t now) { struct dns_header *header=(void *)daemon->packet; SET_RCODE(header,code);\n'
    a=f.index('  if ((RCODE(header) == REFUSED || RCODE(header) == SERVFAIL) && forward->forwardall == 0)')
    b=f.index('  forward->sentto = server;',a)
    c+=f[a:b]+'printf(" D%u",forward->new_id);free_frec(forward);}\n'
    c+=r'''
static int compare_frec(const void *a,const void *b) {return (*(struct frec **)a)->new_id-(*(struct frec **)b)->new_id;}
static void snapshot(void) {
 struct frec *list[65536];size_t count=0;for(struct frec *p=daemon->frec_list;p;p=p->next)if(p->sentto)list[count++]=p;qsort(list,count,sizeof(list[0]),compare_frec);
 printf(" |A");for(size_t i=0;i<count;i++) {struct frec *p=list[i];printf(" %u:%lld:%d:%d:%d:%u",p->new_id,(long long)p->time,p->sentto->arrayposn,p->forwardall,p->forward_delay,p->forward_timestamp);
 for(struct frec_src *s=&p->frec_src;s;s=s->next) {unsigned char packet[65536];char name[MAXDNAMESTR+1];blockdata_retrieve(p->stash,p->stash_len,packet);extract_name((void *)packet,p->stash_len,NULL,(char *)(s->encode_bigmap?s->encode_bigmap:&s->encode_bitmap),EXTR_NAME_FLIP,s->encode_bigmap?s->encode_bitmap:1);assert(extract_name((void *)packet,p->stash_len,NULL,name,EXTR_NAME_EXTRACT,0));printf("/%u,%u,%s",s->orig_id,ntohs(s->source.in.sin_port),name);}
 }puts("");
}
int main(int argc,char **argv) {
 assert(argc==6);daemon->ftabsize=atoi(argv[1]);options=atoi(argv[2]);daemon->fast_retry_time=atoi(argv[3]);daemon->fast_retry_timeout=atoi(argv[4]);random_counter=atoi(argv[5]);daemon->edns_pktsz=1232;
 for(int i=0;i<6;i++) {servers[i].arrayposn=i;servers[i].group=i/3;servers[i].last_server=-1;servers[i].domain="";servers[i].addr.in.sin_family=AF_INET;daemon->serverarray[i]=&servers[i];}
 char *line=NULL;size_t cap=0;while(getline(&line,&cap,stdin)>0) {
 char op=line[0];long long now;unsigned ms,id,type,cls,flags,port,group,code,server;char name[504];
 if(op=='Q') {char hex[131073];assert(sscanf(line,"Q %lld %u %u %u %u %131072s",&now,&ms,&group,&port,&flags,hex)==6);size_t n=strlen(hex)/2;for(size_t i=0;i<n;i++){unsigned v;sscanf(hex+2*i,"%2x",&v);daemon->packet[i]=v;}active_group=group;millis=ms;
 union mysockaddr source={0};source.in.sin_family=AF_INET;source.in.sin_addr.s_addr=htonl(0xc0000201);source.in.sin_port=htons(port);union all_addr dest={0};forward_query(1,&source,&dest,2,(void *)daemon->packet,n,512,now,NULL,flags,0);
 }else if(op=='R') {assert(sscanf(line,"R %lld %u %u %u %u",&now,&ms,&id,&code,&server)==5);millis=ms;struct frec *p;for(p=daemon->frec_list;p;p=p->next)if(p->sentto && p->new_id==id)break;if(p){int first=p->sentto->group*3;if(code!=5)servers[first].last_server=server;else if(servers[first].last_server==(int)server)servers[first].last_server=-1;response(p,code,now);}}
 else if(op=='M') {assert(sscanf(line,"M %lld %u %u %u %503s",&now,&id,&type,&cls,name)==5);struct frec *p=lookup_frec(now,name,cls,type,id,FREC_ANSWER,0);printf(" M%d",p?p->new_id:-1);}
 else if(op=='C') {assert(sscanf(line,"C %u",&id)==1);for(struct frec *p=daemon->frec_list;p;p=p->next)if(p->sentto && p->new_id==id){free_frec(p);break;}}
 else if(op=='T') {assert(sscanf(line,"T %lld %u",&now,&ms)==2);millis=ms;int result=fast_retry(now);printf(" T%d",result);}
 else if(op=='F') {assert(sscanf(line,"F %u",&fail_mask)==1);}
 else abort();snapshot();
 }free(line);return 0;
}
'''
    (out/'oracle.c').write_text(c)
    subprocess.run(['cc','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',str(SOURCE),str(out/'oracle.c'),'-o',str(out/'oracle')],check=True)
    rust=RUST_DRIVER.replace('WIRE',str(ROOT/'components/dnsmasq/src/dns/wire.rs')).replace('FORWARD',str(ROOT/'components/dnsmasq/src/dns/forward.rs'))
    (out/'driver.rs').write_text(rust)
    subprocess.run([rustc,'--edition=2021','-A','dead_code',str(out/'driver.rs'),'-o',str(out/'driver')],check=True)


RUST_DRIVER=r'''
#[path="WIRE"] mod wire;
#[path="FORWARD"] mod forward;
use forward::*;use std::io::{self,BufRead};use std::net::{SocketAddr,IpAddr};
struct Counter(u32);impl Random for Counter {fn next_u32(&mut self)->io::Result<u32>{self.0+=1;Ok(self.0)}}
fn flags(n:u32)->Flags{Flags{checking_disabled:n&2!=0,no_cache:n&4!=0,ad_requested:n&32!=0,dnssec_ok:n&64!=0,had_opt:n&128!=0}}
fn send(table:&mut ForwardTable,id:QueryId,group:&mut ServerGroup,reason:SendReason,now:i64,ms:u32,fail:u32){
 let Some(plan)=table.plan(id,group,reason,now)else{return};if plan.exhausted{return}
 let mut sent=false;for server in plan.candidates{if fail&(1<<server.0)!=0{continue}print!(" S{}:{}",table.get(id).unwrap().upstream_id,server.0);table.note_sent(id,server,SocketToken(100+server.0),ms);sent=true;if !plan.send_all{break}}
 if !sent {table.cancel(id);if reason!=SendReason::UpstreamError && reason!=SendReason::FastRetry{print!(" R");}}
}
fn main(){let a:Vec<u32>=std::env::args().skip(1).map(|s|s.parse().unwrap()).collect();let mut rng=Counter(a[4]);let mut table=ForwardTable::new(Options{forward_max:a[0]as usize,case_randomization:a[1]&8!=0,fast_retry_ms:a[2],fast_retry_timeout_s:a[3]as i64});
 let mut groups:Vec<_>=(0..2).map(|g|ServerGroup::new(GroupId(g),(g*3..g*3+3).map(|i|Server{id:ServerId(i),address:SocketAddr::from(([192,0,2,10+i as u8],53)),bound_socket:None}).collect(),a[1]&1!=0,a[1]&2!=0)).collect();
 let mut live=Vec::<QueryId>::new();let mut fail=0;
 for line in io::stdin().lock().lines(){let line=line.unwrap();let w:Vec<_>=line.split_whitespace().collect();let n=|i:usize|w[i].parse::<u32>().unwrap();let now=|i:usize|w[i].parse::<i64>().unwrap();
 match w[0]{
 "Q"=>{let packet:Vec<u8>=(0..w[6].len()).step_by(2).map(|i|u8::from_str_radix(&w[6][i..i+2],16).unwrap()).collect();let group=n(3)as usize;let client=Client{source:SocketAddr::from(([192,0,2,1],n(4)as u16)),destination:IpAddr::from([192,0,2,53]),interface:2,listener:Some(SocketToken(1)),udp_limit:512,log_id:1};match table.submit(&packet,client,GroupId(group as u64),flags(n(5)),Scope::Shared,now(1),&mut rng){Ok(s)=>{if s.kind==SubmissionKind::New{live.push(s.id)}if s.kind!=SubmissionKind::Coalesced{let reason=match s.kind{SubmissionKind::New=>SendReason::New,SubmissionKind::ClientRetry=>SendReason::ClientRetry,_=>SendReason::LateDuplicate};let group=table.get(s.id).unwrap().group.0 as usize;send(&mut table,s.id,&mut groups[group],reason,now(1),n(2),fail);}},Err(_)=>print!(" R")}}
 "R"=>{if let Some(id)=live.iter().copied().find(|id|table.get(*id).is_some_and(|p|p.upstream_id==n(3)as u16)){let group=table.get(id).unwrap().group.0 as usize;groups[group].note_reply(ServerId(n(5)as u64),n(4)as u8);match table.on_reply(id,ServerId(n(5)as u64),n(4)as u8).unwrap(){ReplyAction::Retry=>send(&mut table,id,&mut groups[group],SendReason::UpstreamError,now(1),n(2),fail),ReplyAction::Wait=>{},ReplyAction::Deliver=>{print!(" D{}",n(3));table.finish(id);}}}}
 "C"=>{if let Some(id)=live.iter().copied().find(|id|table.get(*id).is_some_and(|p|p.upstream_id==n(1)as u16)){table.cancel(id);}}
 "M"=>{let mut found=-1;for id in &live{if let Some(p)=table.get(*id){if p.upstream_id!=n(2)as u16{continue}let mut packet=vec![0;12];wire::Header{id:p.upstream_id,flags:0x8180,questions:1,..wire::Header::default()}.write(&mut packet).unwrap();packet.extend_from_slice(wire::Name::from_ascii(w[5]).unwrap().as_wire());packet.extend_from_slice(&(n(3)as u16).to_be_bytes());packet.extend_from_slice(&(n(4)as u16).to_be_bytes());let group=&groups[p.group.0 as usize];if table.accept_reply(&packet,group.servers[0].address,SocketToken(100+p.sent_to.unwrap().0),group,now(1)).is_some(){found=p.upstream_id as i32;}}}print!(" M{found}");}
 "T"=>{let schedule=table.fast_retries(now(1),n(2));let mut next=schedule.next_ms;for id in schedule.due{let group=table.get(id).unwrap().group.0 as usize;send(&mut table,id,&mut groups[group],SendReason::FastRetry,now(1),n(2),fail);table.retry_finished(id);if let Some(p)=table.get(id){next=Some(next.unwrap_or(u32::MAX).min(p.retry_delay_ms));}}print!(" T{}",next.map_or(-1,|v|v as i64));}
 "F"=>fail=n(1),_=>panic!()}
 live.retain(|id|table.get(*id).is_some());let mut sorted=live.clone();sorted.sort_by_key(|id|table.get(*id).unwrap().upstream_id);print!(" |A");for id in sorted{let p=table.get(id).unwrap();print!(" {}:{}:{}:{}:{}:{}",p.upstream_id,p.created,p.sent_to.unwrap().0,p.forward_all,p.retry_delay_ms,p.last_sent_ms);for r in &p.recipients{let name=String::from_utf8(r.question_name.dnsmasq_bytes()).unwrap();print!("/{},{},{}",r.original_id,r.client.source.port(),name);}}println!();table.take_released();
 }
}
'''


def question(name,id=1,typ=1,cls=1):
    return (struct.pack('!6H',id,0x100,1,0,0,0)+b''.join(bytes([len(s)])+s.encode() for s in name.split('.') if s)+b'\0'+struct.pack('!2H',typ,cls)).hex()


def scenarios():
    def q(name='a.test',id=1,port=1000,now=100,flags=0,group=0):return f'Q {now} {now*1000} {group} {port} {flags} {question(name,id)}'
    yield 'calibration',[1,0,0,10,0],[q(),q('A.TEST',2,1001),q('b.test',3),'M 100 1 1 1 A.TEST','M 100 1 28 1 a.test','R 100 100001 1 0 0']
    yield 'duplicates',[2,0,0,10,0],[q('Mixed.test'),q('MIXED.test'),q('mixed.TEST',2,1001,101),q('MiXeD.test',3,1002,102),q('mixed.test',4,1003,103),q('mixed.test',4,1003,110)]
    yield 'strict-errors',[3,1,0,10,0],[q(), 'R 100 100010 1 5 0','R 100 100020 1 2 1','R 100 100030 1 5 2',q(now=101),'R 101 101010 1 0 2']
    yield 'all-errors',[3,2,0,10,0],[q(),'R 100 100010 1 5 0','R 100 100020 1 5 1','R 100 100030 1 5 2',q('b.test',2),'R 100 100010 2 2 0']
    yield 'capacity',[1,0,0,10,0],[q(),q('b.test',2),q('b.test',2,group=1),'C 2',q('c.test',3,now=110),q('d.test',4,now=110),q('e.test',5,now=150)]
    # Expiring one old frec must preserve another transaction and its later
    # successful reply. The exact C free_frec path emits no local error reply.
    yield 'independent-expiry',[3,0,0,10,0],[q('slow.test'),q('good.test',2,1001,130),
        q('trigger.test',3,1002,140),'M 140 1 1 1 slow.test','M 140 2 1 1 good.test',
        'R 140 140001 2 0 0','C 3']
    yield 'flags',[20,0,0,10,0],[q(flags=f,id=i,port=i) for i,f in enumerate([0,2,32,64,128,4,4,34,98,130,132])]
    yield 'send-failures',[3,1,0,10,0],['F 1',q(),'F 7',q('b.test',2),'F 0',q('b.test',3)]
    yield 'case-match',[10,8,0,10,0],[q('abc.test'),'M 100 1 1 1 aBc.test','M 100 1 1 1 abc.test','M 100 1 28 1 aBc.test','M 140 1 1 1 aBc.test',q('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN.test',4,1004,140)]
    long='abcdefghijklmnopqrstuvwxyzabcdefghijklmn.test'
    yield 'long-case-duplicates',[5,8,0,10,0],[q(long),q(long[:35]+long[35:].upper(),2,1001,101),q(long[:31].upper()+long[31]+long[32:].upper(),3,1002,101)]
    yield 'fast-retry',[3,0,100,5,0],[q(),'T 100 100099','T 100 100100','T 100 100299','T 100 100300','T 101 101000','T 105 105000']
    for seed in range(4):
        rng=random.Random(seed);now=100;commands=[]
        for _ in range(300):
            now+=rng.randrange(2)
            commands.append(q(rng.choice(['a.test','A.TEST','b.test','c.test','d.test']),rng.randrange(1,6),rng.randrange(1000,1004),now,rng.choice([0,2,32,128,4]),rng.randrange(2)))
        yield f'random-{seed}',[5,seed%2,0,10,0],commands


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--rustc',required=True);p.add_argument('--output',type=Path,default=ROOT/'private/dnsmasq-rs/forward/differential');a=p.parse_args();out=a.output.resolve();assert out.is_relative_to((ROOT/'private').resolve());out.mkdir(parents=True,exist_ok=True)
    build(out,a.rustc);summaries=[];mismatches=[]
    for name,config,commands in scenarios():
        inputs='\n'.join(commands)+'\n';(out/f'{name}.input').write_text(inputs);outputs={}
        for binary in ['oracle','driver']:
            run=subprocess.run([str(out/binary),*map(str,config)],input=inputs,text=True,capture_output=True)
            (out/f'{name}.{binary}.stdout').write_text(run.stdout);(out/f'{name}.{binary}.stderr').write_text(run.stderr)
            if run.returncode:raise RuntimeError(f'{name}/{binary}: {run.returncode}')
            outputs[binary]=run.stdout.splitlines();assert len(outputs[binary])==len(commands)
            if name=='calibration':
                base=' |A 1:100:2:4:0:100000/1,1000,a.test'
                duplicate=base+'/2,1001,A.TEST'
                expected=[' S1:0 S1:1 S1:2'+base,duplicate,' R'+duplicate,' M1'+duplicate,' M-1'+duplicate,' D1 |A']
                assert outputs[binary]==expected,f'{binary}: fixed success/failure calibration failed'
        bad=[{'scenario':name,'line':i,'command':command,'c':c,'rust':r} for i,(command,c,r) in enumerate(zip(commands,outputs['oracle'],outputs['driver'])) if c!=r]
        mismatches+=bad;summaries.append({'name':name,'config':config,'commands':len(commands),'mismatches':len(bad),'input_sha256':hashlib.sha256(inputs.encode()).hexdigest()})
    summary={'source_sha256':HASHES,'scenarios':summaries,'commands':sum(s['commands'] for s in summaries),'mismatches':len(mismatches),'sanitizers':True,'scope':'forwarding/coalescing/case/get_new_frec/retry state with in-memory socket/domain dependencies; no daemon sockets, EDNS mutation or process_reply'}
    (out/'mismatches.json').write_text(json.dumps(mismatches,indent=2)+'\n');(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2));return bool(mismatches)

if __name__=='__main__':raise SystemExit(main())
