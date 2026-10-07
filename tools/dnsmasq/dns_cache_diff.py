#!/usr/bin/env python3
"""Differential dynamic forward-cache transitions; exact C functions, no sockets."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'private/dnsmasq-rewrite/reference/dnsmasq-2.93/src'
EXPECTED_SOURCE = {
    'cache.c': '51379b75a3dcc80b629a3d92a5710b43b2a6c04fd13f4d7f56d01f5e7836255c',
    'dnsmasq.h': '318942419598f037a97611efbdea5aebba1e384b9a1ba5f7eded091c86e0e228',
}


def function(source, signature):
    start = source.index(signature + '\n{')
    return source[start:source.index('\n}', start) + 2] + '\n'


def rust_modules(root):
    lease_path = root / 'components/dnsmasq/src/dns/lease_names.rs'
    lease_api = ''
    if lease_path.exists():
        lease_source = lease_path.read_text()
        start = lease_source.rfind('#[derive', 0, lease_source.index('pub enum BlockerKind'))
        lease_api = lease_source[start:lease_source.index('/// Appropriate only')]
    # cache.rs calls this local-only reverse-name predicate.  The primitive
    # driver does not compile the full local service, so keep the shim
    # conservative: forward/name scenarios must not accidentally classify an
    # arbitrary name as reverse. Reverse-cache gates use their dedicated
    # driver instead.
    local_shim = 'mod local { pub fn arpa_address(_: &[u8]) -> Option<std::net::IpAddr> { None } }\n'
    return (local_shim + 'mod lease_names { use std::net::Ipv4Addr; ' + lease_api + ' }\n'
            + '#[path=' + json.dumps(str(root / 'components/dnsmasq/src/dns/wire.rs')) + '] mod wire;\n'
            + '#[path=' + json.dumps(str(root / 'components/dnsmasq/src/dns/cache.rs')) + '] mod cache;\n')


def primitive_rust_source():
    """Actual-crate example source for the locked, frozen primitive bridge."""
    return 'use dnsmasq_rs::dns::{cache, wire};\n' + r'''
use std::io::{self,BufRead}; use cache::*;
fn kind(t:u32)->Kind {match t {1=>Kind::Ipv4,28=>Kind::Ipv6,5=>Kind::Cname,65536=>Kind::NxDomain,_=>Kind::Generic(t as u16)}}
fn main() {
 let a:Vec<i64>=std::env::args().skip(1).map(|s|s.parse().unwrap()).collect();
 let policy=Policy{min_ttl:a[1] as u64,max_ttl:a[2] as u64,stale:match a[3]{-1=>StalePolicy::Forever,0=>StalePolicy::Disabled,v=>StalePolicy::Seconds(v as u32)},max_reply_ttl:a[4] as u64};
 let mut cache=Cache::new(a[0] as usize,policy); let mut ids=Vec::new();
 for line in io::stdin().lock().lines() {let line=line.unwrap();let w:Vec<_>=line.split_whitespace().collect();let n=|i:usize| w[i].parse::<u32>().unwrap();
 match w[0] {
 "B"=>{cache.start_insert();println!("B");},
 "C"=>println!("C {}",u8::from(cache.commit())),
 "I"=>{let id=cache.insert(Record{name:wire::Name::from_ascii(w[1]).unwrap(),kind:kind(n(2)),negative:n(5)!=0,data:vec![n(4) as u8]},w[6].parse().unwrap(),n(3));println!("I {}",u8::from(id.is_ok()));ids.push(id.ok());},
 "L"=>{let ok=match (ids[n(1) as usize],ids[n(2) as usize]){(Some(a),Some(b))=>cache.set_cname_target(a,b),_=>false};println!("L {}",u8::from(ok));},
 "Q"=>{let now=w[3].parse().unwrap();let found=cache.lookup(&wire::Name::from_ascii(w[1]).unwrap(),&[kind(n(2))],now,n(4)!=0);print!("Q");for id in found {let e=cache.get(id).unwrap();let t=match e.record.kind{Kind::Ipv4=>1,Kind::Ipv6=>28,Kind::Cname=>5,Kind::NxDomain=>65536,Kind::ReverseIpv4|Kind::ReverseIpv6=>0,Kind::Generic(t)=>t as u32};let v=if t==5 {0}else{e.record.data[0]};print!(" {t}:{v}:{}:{}:{}:{}",u8::from(e.record.negative),e.expires,e.reply_ttl(now,policy),u8::from(e.is_stale(now)));}println!();},_=>panic!()}
 }
}
'''


def build(output, rustc=None, source_root=None, *, rust_binary=None, reference_source=None, cc="cc"):
    reference_source = reference_source or SOURCE
    hashes = {file: hashlib.sha256((reference_source/file).read_bytes()).hexdigest() for file in EXPECTED_SOURCE}
    if hashes != EXPECTED_SOURCE:
        raise RuntimeError('reference source identity differs from the verified patched 2.93 tree')
    source = (reference_source / 'cache.c').read_text()
    header = (reference_source / 'dnsmasq.h').read_text()
    preamble = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <assert.h>
#include <arpa/inet.h>
#define daemon dnsmasq_state
#define SMALLDNAME 75
#define MAXDNAMESTR 503
#define C_IN 1
#define INADDRSZ 4
#define IN6ADDRSZ 16
#define OPT_NORR 1
#define METRIC_DNS_CACHE_LIVE_FREED 0
#define METRIC_DNS_CACHE_INSERTED 1
#define PIPE_OP_INSERT 1
#define RW_WRITE 1
#define LOG_ERR 1
#define _(x) x
static struct { int cachesize, cache_max_expiry, pipe_to_parent; unsigned max_cache_ttl, min_cache_ttl; unsigned long metrics[2]; } state, *daemon = &state;
static int option_bool(int option) { (void)option; return 0; }
static int hostname_isequal(const char *a, const char *b) { return strcasecmp(a,b)==0; }
static void *whine_malloc(size_t n) { return calloc(1,n); }
static void *safe_malloc(size_t n) { void *p=whine_malloc(n); assert(p); return p; }
static void blockdata_free(void *p) { free(p); }
static void blockdata_write(void *p, size_t n, int fd) { (void)p;(void)n;(void)fd;abort(); }
static void read_write(int fd, void *p, size_t n, int mode) { (void)fd;(void)p;(void)n;(void)mode;abort(); }
static void my_syslog(int priority, const char *s) { (void)priority; fprintf(stderr,"%s\n",s); abort(); }
'''
    preamble += header[header.index('union all_addr {'):header.index('#define RR_IMDATALEN')]
    preamble += 'union bigname { char name[MAXDNAMESTR+1]; union bigname *next; };\n'
    preamble += header[header.index('struct crec {'):header.index('#define SIZEOF_BARE_CREC')]
    preamble += header[header.index('#define F_IMMORTAL'):header.index('/* Values of uid in crecs')]
    preamble += '''
static struct crec *cache_head, *cache_tail, **hash_table, *new_chain;
static int insert_error, bignames_left, hash_size;
static union bigname *big_free;
static void dump_cache_entry(struct crec *c, time_t now) { (void)c;(void)now;abort(); }
static void cache_free(struct crec *);
static void cache_unlink(struct crec *);
static void cache_link(struct crec *);
static void rehash(int);
static void cache_hash(struct crec *);
char *cache_get_name(struct crec *);
static struct crec *really_insert(char *, union all_addr *, unsigned short, time_t, unsigned long, unsigned int);
'''
    start = source.index('static const struct {')
    preamble += source[start:source.index('static void cache_free', start)]
    signatures = [
        'void next_uid(struct crec *crecp)', 'void cache_init(void)', 'static void rehash(int size)',
        'static struct crec **hash_bucket(char *name)', 'static void cache_hash(struct crec *crecp)',
        'static void cache_blockdata_free(struct crec *crecp)', 'static void cache_free(struct crec *crecp)',
        'static void cache_link(struct crec *crecp)', 'static void cache_unlink (struct crec *crecp)',
        'char *cache_get_name(struct crec *crecp)', 'static int is_outdated_cname_pointer(struct crec *crecp)',
        'static int is_expired(time_t now, struct crec *crecp)',
        source[source.index('static struct crec *cache_scan_free('):source.index('\n{', source.index('static struct crec *cache_scan_free('))],
        'void cache_start_insert(void)',
        source[source.index('struct crec *cache_insert('):source.index('\n{', source.index('struct crec *cache_insert('))],
        source[source.index('static struct crec *really_insert(', source.index('struct crec *cache_insert(')):source.index('\n{', source.index('static struct crec *really_insert(', source.index('struct crec *cache_insert(')))],
        'void cache_end_insert(void)',
        'struct crec *cache_find_by_name(struct crec *crecp, char *name, time_t now, unsigned int prot)',
    ]
    preamble += ''.join(function(source, sig) for sig in signatures)
    preamble += r'''
static unsigned flags(unsigned type) { return type==1 ? F_IPV4 : type==28 ? F_IPV6 : type==5 ? F_CNAME : type==65536 ? F_NXDOMAIN : F_RR; }
static unsigned type_of(struct crec *c) { return c->flags&F_IPV4 ? 1 : c->flags&F_IPV6 ? 28 : c->flags&F_CNAME ? 5 : c->flags&F_NXDOMAIN ? 65536 : c->addr.rrdata.rrtype; }
int main(int argc,char **argv) {
  assert(argc==6); state.cachesize=atoi(argv[1]); state.min_cache_ttl=atoi(argv[2]);state.max_cache_ttl=atoi(argv[3]); state.cache_max_expiry=atoi(argv[4]); unsigned max_reply=atoi(argv[5]); state.pipe_to_parent=-1;cache_init();
  struct crec *ids[200000]; size_t id_count=0;
  char line[4096],name[504],op; unsigned type,ttl,value,neg;long long now;
  while(fgets(line,sizeof(line),stdin)) {
    assert(sscanf(line,"%c",&op)==1);
    if(op=='B') { cache_start_insert(); puts("B"); }
    else if(op=='C') { cache_end_insert(); printf("C %d\n",!insert_error); }
    else if(op=='I') {
      assert(sscanf(line,"I %503s %u %u %u %u %lld",name,&type,&ttl,&value,&neg,&now)==6);
      union all_addr addr={0}; if(type==1 || type==28) addr.addr4.s_addr=value;
      else if(type!=5) {addr.rrdata.rrtype=type;addr.rrdata.data[0]=value;}
      struct crec *c=cache_insert(name,type==5?NULL:&addr,C_IN,now,ttl,F_FORWARD|flags(type)|(neg?F_NEG:0));
      if(c && type==5) {c->addr.cname.target.cache=NULL;c->addr.cname.is_name_ptr=0;}
      ids[id_count++]=c; printf("I %d\n",c!=NULL);
    } else if(op=='L') {
      unsigned a,b;assert(sscanf(line,"L %u %u",&a,&b)==2);assert(a<id_count && b<id_count);
      int ok=ids[a] && ids[b] && (ids[a]->flags&F_CNAME);
      if(ok) {next_uid(ids[b]);ids[a]->addr.cname.target.cache=ids[b];ids[a]->addr.cname.uid=ids[b]->uid;}
      printf("L %d\n",ok);
    } else if(op=='Q') {
      unsigned rr;assert(sscanf(line,"Q %503s %u %lld %u",name,&type,&now,&rr)==4);
      struct crec *c=NULL; printf("Q");
      while((c=cache_find_by_name(c,name,now,flags(type)|(rr?0:F_NO_RR)))) {
        unsigned t=type_of(c),v=t==5?0 : t==1||t==28?c->addr.addr4.s_addr:(unsigned char)c->addr.rrdata.data[0];
        long long remain=c->ttd-now; unsigned out=remain<0?0:remain;if(max_reply && out>max_reply)out=max_reply;
        printf(" %u:%u:%u:%lld:%u:%d",t,v,!!(c->flags&F_NEG),(long long)c->ttd,out,now>c->ttd);
      } puts("");
    } else abort();
  }
  return 0;
}
'''
    (output/'oracle.c').write_text(preamble)
    c_flags = ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all']
    c_argv = [cc, *c_flags, str(output/'oracle.c'), '-o', str(output/'oracle')]
    run = subprocess.run(c_argv, capture_output=True)
    (output/'c-build.stdout').write_bytes(run.stdout)
    (output/'c-build.stderr').write_bytes(run.stderr)
    run.check_returncode()
    version = subprocess.run([cc, '--version'], check=True, capture_output=True)
    abi = subprocess.run([cc, '-dM', '-E', '-'], input=b'', check=True, capture_output=True)
    (output/'c-compiler-version').write_bytes(version.stdout)
    (output/'c-compiler-macros').write_bytes(abi.stdout)
    if rust_binary is not None:
        shutil.copy2(rust_binary, output/'driver')
        rust_mode = 'locked actual-crate primitive example'
    else:
        # Explicit local-only legacy mode. The Oracle must use primitive-probes.
        if rustc is None or source_root is None:
            raise ValueError('local-native requires explicit rustc and source root')
        if any(str(path.resolve()).startswith('/home/ubuntu/') for path in [output, source_root]):
            raise ValueError('Oracle primitive builds require oracle_build.sh and copied ELF')
        rust = rust_modules(source_root) + primitive_rust_source().split('\n', 1)[1]
        (output/'driver.rs').write_text(rust)
        subprocess.run([rustc, '--edition=2021', '-A', 'dead_code', str(output/'driver.rs'), '-o', str(output/'driver')], check=True)
        rust_mode = 'explicit local-native standalone legacy adapter; no Oracle qualification'
    metadata = {
        'source_sha256': hashes,
        'reference_scope': 'hash-pinned extracted C cache functions; native source/ABI comparison, not image daemon ELF',
        'c_argv': c_argv,
        'c_harness_sha256': hashlib.sha256((output/'oracle.c').read_bytes()).hexdigest(),
        'c_binary_sha256': hashlib.sha256((output/'oracle').read_bytes()).hexdigest(),
        'c_compiler_version_sha256': hashlib.sha256(version.stdout).hexdigest(),
        'c_compiler_macros_sha256': hashlib.sha256(abi.stdout).hexdigest(),
        'rust_mode': rust_mode,
        'rust_binary_sha256': hashlib.sha256((output/'driver').read_bytes()).hexdigest(),
    }
    (output/'primitive-build.json').write_text(json.dumps(metadata, indent=2)+'\n')
    return metadata


def scenarios():
    yield 'calibration', [1,0,0,0,0], ['B','I a.test 1 2 7 0 100','C','Q a.test 1 100 0','Q a.test 1 102 0','B','I b.test 1 0 1 0 102','C','B','I c.test 5 10 0 0 102','L 2 1','C','Q c.test 5 102 0']
    yield 'ordering', [8,0,0,0,0], ['B','I a.test 1 60 1 0 100','I a.test 1 60 2 0 100','I a.test 1 60 3 0 100','C'] + ['Q A.TEST 1 100 1']*4 + ['Q a.test 1 100 0']*3
    yield 'abort', [4,0,0,0,0], ['B','I a.test 1 60 1 0 100','C','B','I a.test 1 60 2 0 100','I b.test 1 0 3 0 100','C','Q a.test 1 100 0','B','I b.test 1 60 4 0 100','C','Q b.test 1 100 0']
    yield 'cname', [8,0,0,0,0], ['B','I alias.test 5 100 0 0 100','I target.test 1 60 1 0 100','L 0 1','C','Q alias.test 5 100 0','B','I target.test 1 60 2 0 110','C','Q alias.test 5 110 0','Q target.test 1 110 0','Q target.test 1 170 0','Q alias.test 5 170 0','B','I dangling.test 5 60 0 0 180','C','Q dangling.test 5 180 0']
    yield 'capacity', [2,0,0,0,0], ['B','I a.test 1 60 1 0 100','I a.test 1 60 2 0 100','C','B','I b.test 1 60 3 0 100','C','Q a.test 1 100 0','Q b.test 1 100 0','B','I c.test 1 60 4 0 100','I d.test 1 60 5 0 100','I e.test 1 60 6 0 100','C','Q c.test 1 100 0','B']
    long='a'*50+'.'+'b'*30
    yield 'long-name', [10,0,0,0,0], ['B',f'I {long} 1 60 1 0 100',f'I x.{long} 1 60 2 0 100','C','B',f'I {long} 1 60 3 0 100','C',f'Q {long} 1 100 0']
    for stale in [0,5,-1]:
        for minttl,maxttl in [(0,0),(10,20),(30,20)]:
            commands=['B']+[f'I n{i}.test 1 {ttl} {i} 0 100' for i,ttl in enumerate([0,1,10,60])]+['C']
            commands += [f'Q n{i}.test 1 {now} 0' for now in [100,101,110,120,125,130,135,160,165,200] for i in range(4)]
            yield f'ttl-{stale}-{minttl}-{maxttl}',[10,minttl,maxttl,stale,15],commands
    for seed in range(6):
        rng=random.Random(seed); commands=[]; now=100
        # Capacity exceeds committed names/types to separate transition correctness
        # from unspecified expired-victim ordering of C's address-dependent hash.
        for _ in range(500):
            now+=rng.randrange(3);commands.append('B')
            for _ in range(rng.randrange(1,5)):
                commands.append(f'I n{rng.randrange(10)}.test {rng.choice([1,28,16,33,65536])} {rng.choice([0,1,10,60])} {rng.randrange(255)} {rng.randrange(2)} {now}')
            if rng.randrange(8):commands.append('C')
            commands += [f'Q n{rng.randrange(10)}.test {rng.choice([1,28,16,65536])} {now} {rng.randrange(2)}' for _ in range(3)]
        yield f'random-{seed}',[100,0,0,rng.choice([-1,0,5]),0],commands


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,default=ROOT/'private/dnsmasq-rs/cache/differential')
    p.add_argument('--rust-source-root',type=Path,required=True,help='explicit frozen Rust source root')
    p.add_argument('--rust-binary',type=Path,help='immutable copied m6b-cache-core example')
    p.add_argument('--rust-source-receipt',type=Path)
    p.add_argument('--rust-build-receipt',type=Path)
    p.add_argument('--reference-source',type=Path,default=SOURCE,help='hash-pinned matching C src directory')
    p.add_argument('--c-compiler',default='cc')
    p.add_argument('--local-native',action='store_true',help='explicit legacy local adapter; no Oracle qualification')
    p.add_argument('--rustc',help='only used with --local-native')
    args=p.parse_args()
    source_root=args.rust_source_root.resolve()
    if args.local_native:
        if not args.rustc or any([args.rust_binary,args.rust_source_receipt,args.rust_build_receipt]):
            p.error('local-native requires rustc and prohibits copied-ELF arguments')
        binding={'qualified':False,'scope':'explicit local-native legacy adapter'}
    else:
        if not all([args.rust_binary,args.rust_source_receipt,args.rust_build_receipt]) or args.rustc:
            p.error('copied ELF, source receipt and build receipt required; rustc prohibited')
        from m6b_primitive_assets import validate_binary
        binding=validate_binary(args.rust_binary,source_root,args.rust_source_receipt,args.rust_build_receipt,'m6b-cache-core')
    out=args.output.resolve()
    if 'private' not in out.parts or out.exists():
        p.error('fresh private output required')
    out.mkdir(parents=True)
    (out/'rust-binding.json').write_text(json.dumps(binding,indent=2)+'\n')
    metadata=build(out,args.rustc,source_root,rust_binary=args.rust_binary,
                   reference_source=args.reference_source.resolve(),cc=args.c_compiler)
    if not args.local_native and metadata['rust_binary_sha256'] != binding['binary_sha256']:
        raise ValueError('copied primitive ELF changed after binding validation')
    results=[];errors=[];order_variations=[]
    for name,config,commands in scenarios():
        inputs='\n'.join(commands)+'\n';(out/f'{name}.input').write_text(inputs);observed={}
        for binary in ['oracle','driver']:
            run=subprocess.run([str(out/binary),*map(str,config)],input=inputs,text=True,capture_output=True,timeout=120)
            (out/f'{name}.{binary}.stdout').write_text(run.stdout);(out/f'{name}.{binary}.stderr').write_text(run.stderr)
            if run.returncode:
                (out/'failure.json').write_text(json.dumps({'scenario':name,'binary':binary,'exit':run.returncode,'passed':False},indent=2)+'\n')
                raise RuntimeError(f'{name}/{binary}: exit {run.returncode}')
            observed[binary]=run.stdout.splitlines();assert len(observed[binary])==len(commands)
            if name == 'calibration':
                expected=['B','I 1','C 1','Q 1:7:0:102:2:0','Q','B','I 0','C 0','B','I 1','L 0','C 1','Q']
                assert observed[binary] == expected, f'{binary}: calibration failed'
        mismatch=[]
        for i,(command,c,r) in enumerate(zip(commands,observed['oracle'],observed['driver'])):
            if c == r: continue
            item={'line':i,'command':command,'c':c,'rust':r}
            # The F_RR iterator returns all generic types; answer_request filters
            # actual rrtype before emitting. Their relative groups are irrelevant
            # to output, but order within one RR type remains exact and checked.
            generic=command.startswith('Q ') and int(command.split()[2]) not in [1,28,5,65536]
            group=lambda row: sorted(row.split()[1:],key=lambda item:int(item.split(':')[0]))
            if generic and group(c)==group(r):
                order_variations.append({'scenario':name,**item})
            else: mismatch.append(item)
        errors.extend({'scenario':name,**item} for item in mismatch)
        results.append({'scenario':name,'config':config,'commands':len(commands),'mismatches':len(mismatch),'input_sha256':hashlib.sha256(inputs.encode()).hexdigest()})
    if any(hashlib.sha256((out/binary).read_bytes()).hexdigest() != metadata[key]
           for binary,key in [('oracle','c_binary_sha256'),('driver','rust_binary_sha256')]):
        raise ValueError('primitive executable changed while scenarios ran')
    (out/'mismatches.json').write_text(json.dumps(errors,indent=2)+'\n')
    (out/'cross-type-order-variations.json').write_text(json.dumps(order_variations,indent=2)+'\n')
    summary={'source_sha256':metadata['source_sha256'],'primitive_build':metadata,'rust_binding':binding,'scenarios':results,'commands':sum(r['commands'] for r in results),'mismatches':len(errors),'cross_type_order_variations':len(order_variations),'normalization':'Only relative order across generic RR types is grouped; ordering within each type, data, expiry, negative status, reply TTL and stale flag compare exactly. C answer_request filters by actual rrtype.','scope':'dynamic forward-cache transitions; no packet extraction, local records, reverse, TCP IPC, allocation failure or performance evidence','sanitizers':True,'image_daemon_qualification':False}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2));return bool(errors)

if __name__=='__main__': raise SystemExit(main())
