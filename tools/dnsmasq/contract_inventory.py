#!/usr/bin/env python3
"""Index the exact dnsmasq option contract; indexing is not implementation coverage."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / 'private/network-research-20260929/dns/dnsmasq-2.93-openwrt'
EXCLUDED = {
    'dhcp-luascript': ('Lua', 'parse-time rejection'),
    'ipset': ('ipset', 'parse-time rejection'),
    'nftset': ('nftset', 'parse-time rejection'),
    'connmark-allowlist': ('conntrack', 'parse-time rejection'),
    'connmark-allowlist-enable': ('conntrack', 'parse-time rejection'),
    'enable-dbus': ('DBus', 'startup rejection after --test'),
    'conntrack': ('conntrack', 'startup rejection after --test'),
    'dnssec': ('DNSSEC validation', 'startup rejection after --test'),
    'dnssec-check-unsigned': ('DNSSEC validation', 'parse-time rejection'),
    'dnssec-timestamp': ('DNSSEC validation', 'parse-time rejection'),
    'dnssec-limits': ('DNSSEC validation', 'parse-time rejection'),
    'trust-anchor': ('DNSSEC validation', 'parse-time rejection'),
    'dnssec-debug': ('DNSSEC validation', 'accepted flag; no validator compiled'),
    'dnssec-no-timecheck': ('DNSSEC validation', 'accepted flag; no validator compiled'),
    'enable-ra': ('DHCPv6/RA', 'accepted flag; no RA engine compiled'),
    'quiet-ra': ('DHCPv6/RA', 'accepted flag; no RA engine compiled'),
    'quiet-dhcp6': ('DHCPv6/RA', 'accepted flag; no DHCPv6 engine compiled'),
    'no-dhcpv6-interface': ('DHCPv6/RA', 'accepted interface list; no DHCPv6 engine compiled'),
    'dhcp-duid': ('DHCPv6/RA', 'parse-time rejection'),
    'ra-param': ('DHCPv6/RA', 'parse-time rejection'),
    'auth-zone': ('authoritative DNS', 'startup rejection after --test'),
    'auth-server': ('authoritative DNS', 'accepted configuration; no authoritative engine compiled'),
    'auth-ttl': ('authoritative DNS', 'accepted configuration; no authoritative engine compiled'),
    'auth-soa': ('authoritative DNS', 'accepted configuration; no authoritative engine compiled'),
    'auth-sec-servers': ('authoritative DNS', 'accepted configuration; no authoritative engine compiled'),
    'auth-peer': ('authoritative DNS', 'accepted configuration; no authoritative engine compiled'),
}
TRACED = set('version test help conf-file conf-dir conf-script cache-size port min-port max-port dns-forward-max log-queries log-async local-service edns-packet-max query-port port-limit local-ttl neg-ttl max-ttl min-cache-ttl max-cache-ttl dhcp-ttl fast-dns-retry use-stale-cache max-tcp-connections pid-file resolv-file enable-ubus user group dhcp-leasefile'.split())
CONTROL = set('version help test conf-file conf-dir conf-script'.split())
DIFFERENTIAL = set('port cache-size edns-packet-max fast-dns-retry use-stale-cache min-cache-ttl local-ttl max-tcp-connections query-port port-limit'.split()) | CONTROL
SCALARS = set('cache-size port min-port max-port dns-forward-max edns-packet-max query-port port-limit local-ttl neg-ttl max-ttl min-cache-ttl max-cache-ttl dhcp-ttl fast-dns-retry use-stale-cache max-tcp-connections'.split())

DNS_TYPED = set('server local address rev-server listen-address interface except-interface resolv-file servers-file addn-hosts hostsdir host-record domain domain-suffix local-service rebind-domain-ok no-hosts no-resolv no-poll expand-hosts bind-interfaces bind-dynamic domain-needed bogus-priv strict-order all-servers no-negcache no-round-robin stop-dns-rebind rebind-localhost-ok localise-queries proxy-dnssec no-0x20-encode do-0x20-encode'.split())
RR_TYPED = set('cname txt-record ptr-record mx-host mx-target localmx selfmx srv-host naptr-record caa-record dns-rr'.split())
TRACED |= DNS_TYPED | RR_TYPED
DIFFERENTIAL |= set('server local address rev-server listen-address interface except-interface local-service resolv-file no-poll no-resolv host-record domain no-hosts expand-hosts rebind-domain-ok proxy-dnssec bind-dynamic'.split()) | RR_TYPED

def index(source):
    path = source / 'src/option.c'
    text = path.read_text()
    lines = text.splitlines()
    option_start = text.index('    { "version"')
    option_end = text.index('    { NULL, 0, 0, 0 }', option_start)
    usage_start = text.index('} usage[]') if '} usage[]' in text else text.index('usage[]')
    usage_end = text.index('/* We hide metacharacters', usage_start)
    usage = {}
    for match in re.finditer(r"\{\s*('[^']'|LOPT_\w+)\s*,\s*(ARG_DUP|ARG_ONE|OPT_\w+|0)\s*,", text[usage_start:usage_end]):
        usage[match[1]] = (match[2], text.count('\n', 0, usage_start + match.start()) + 1)
    cases = {}
    for n,line in enumerate(lines,1):
        match = re.match(r"\s*case\s+('[^']'|LOPT_\w+)\s*:", line)
        if match:
            cases.setdefault(match[1], []).append(n)
    short = re.search(r'#define OPTSTRING "([^"]+)"', text)[1]
    rows = []
    for match in re.finditer(r'\{\s*"([^"]+)"\s*,\s*([012])\s*,\s*0\s*,\s*(\'[^\']\'|LOPT_\w+)\s*}', text[option_start:option_end]):
        name, arity, ident = match.groups()
        repeat, usage_line = usage[ident]
        excluded = EXCLUDED.get(name)
        rows.append({
            'name': name,
            'id': ident,
            'argument': ['none', 'required', 'optional'][int(arity)],
            'short': ident[1] if ident.startswith("'") else None,
            'repeat': {'ARG_DUP':'repeatable', 'ARG_ONE':'once-per-origin'}.get(repeat, 'boolean'),
            'boolean': repeat if repeat.startswith('OPT_') else None,
            'variant': 'excluded-capability' if excluded else 'available',
            'feature': excluded[0] if excluded else 'target-variant',
            'c_gate': excluded[1] if excluded else 'configuration-specific validation applies',
            'source': {'option': f'src/option.c:{text.count(chr(10), 0, option_start + match.start()) + 1}', 'usage': f'src/option.c:{usage_line}', 'cases': [f'src/option.c:{n}' for n in cases.get(ident, [])]},
            'research': 'traced' if name in TRACED else 'indexed; case and dependent engine review pending',
            'rust': 'scalar parser implemented; engine integration pending' if name in SCALARS else ('startup input control implemented; runtime integration pending' if name in CONTROL else ('typed DNS configuration implemented; platform resolution and runtime integration pending' if name in DNS_TYPED or name in RR_TYPED else 'metadata only; semantics not implemented')),
            'differential': 'listed input acceptance corpus passed against exact patched C; full semantic coverage pending' if name in DIFFERENTIAL else 'pending',
        })
    assert len(rows) == len(set(x['name'] for x in rows))
    return {'schema': 1, 'baseline': {'package':'dnsmasq 2.93-r1', 'variant':'nodhcpv6', 'openwrt_revision':'f0a60eee2fe051741c643ea6118718aae1ef17fb', 'archive_sha256':'0c00d4e5c97c8306e5fb932b348b34269c9c29a0e7df0e8e82958b407092bc19', 'option_c_sha256':hashlib.sha256(path.read_bytes()).hexdigest(), 'copts':['HAVE_UBUS','HAVE_POLL_H','NO_DHCP6','NO_AUTH','NO_IPSET','NO_ID'], 'note':'IPv6 target Linux; no LOCALEDIR or external optional feature libraries'}, 'short_options': short, 'options':rows}

def rust(data):
    out = ['// Generated by tools/dnsmasq/contract_inventory.py from exact patched 2.93.', '// Metadata membership does not claim runtime support.', 'use super::{Argument, OptionSpec, Repeat};', '', '#[rustfmt::skip]', 'pub const OPTIONS: &[OptionSpec] = &[']
    for row in sorted(data['options'], key=lambda r:r['name']):
        name = json.dumps(row['name'])
        ident = json.dumps(row['id'])
        arity = {'none':'None','required':'Required','optional':'Optional'}[row['argument']]
        repeat = {'boolean':'Boolean','repeatable':'Repeatable','once-per-origin':'OncePerOrigin'}[row['repeat']]
        short = 'None' if row['short'] is None else f"Some(b'{row['short']}')"
        available = str(row['variant'] == 'available').lower()
        out.append(f'    OptionSpec {{ name: {name}, id: {ident}, argument: Argument::{arity}, repeat: Repeat::{repeat}, short: {short}, available: {available} }},')
    out += ['];', '']
    return '\n'.join(out)

C_STATE_PROBE = r"""
#include "dnsmasq.h"
static void hx(const unsigned char *s, size_t n) {
 if (!s) { putchar('-'); return; }
 if (!n) { putchar('_'); return; }
 for (size_t i=0;i<n;i++) printf("%02x",s[i]);
}
static void hs(const char *s) { hx((const unsigned char *)s,s?strlen(s):0); }
int main(int argc,char **argv) {
 rand_init(); read_opts(argc,argv,"state-probe");
 printf("scalar %d %d %d %u %d %d %d %d %d %lu %lu %lu %lu %lu %lu %d %d %d %d %d\n",daemon->cachesize,daemon->port,daemon->ftabsize,daemon->edns_pktsz,daemon->query_port,daemon->osport,daemon->min_port,daemon->max_port,daemon->randport_limit,daemon->local_ttl,daemon->neg_ttl,daemon->max_ttl,daemon->min_cache_ttl,daemon->max_cache_ttl,daemon->dhcp_ttl,(int)daemon->use_dhcp_ttl,daemon->fast_retry_time,daemon->fast_retry_timeout,daemon->cache_max_expiry,daemon->max_procs);
 for (struct cname *r=daemon->cnames;r;r=r->next) { printf("cname ");hs(r->alias);putchar(' ');hs(r->target);printf(" %d\n",r->ttl); }
 for (struct txt_record *r=daemon->txt;r;r=r->next) { printf("txt ");hs(r->name);putchar(' ');hx(r->txt,r->len);putchar('\n'); }
 for (struct txt_record *r=daemon->rr;r;r=r->next) { printf("raw ");hs(r->name);printf(" %u ",r->class);hx(r->txt,r->len);putchar('\n'); }
 for (struct ptr_record *r=daemon->ptr;r;r=r->next) { printf("ptr ");hs(r->name);putchar(' ');hs(r->ptr);putchar('\n'); }
 for (struct mx_srv_record *r=daemon->mxnames;r;r=r->next) { printf(r->issrv?"srv ":"mx ");hs(r->name);putchar(' ');hs(r->target);if(r->issrv)printf(" %d %d %d\n",r->srvport,r->priority,r->weight);else printf(" %d\n",r->weight); }
 for (struct naptr *r=daemon->naptr;r;r=r->next) { printf("naptr ");hs(r->name);printf(" %u %u ",r->order,r->pref);hs(r->flags);putchar(' ');hs(r->services);putchar(' ');hs(r->regexp);putchar(' ');hs(r->replace);putchar('\n'); }
 unsigned i=0; for (struct host_record *r=daemon->host_records;r;r=r->next,i++) { char a[INET6_ADDRSTRLEN],b[INET6_ADDRSTRLEN];strcpy(a,"-");strcpy(b,"-");if(r->flags&HR_4)inet_ntop(AF_INET,&r->addr,a,sizeof(a));if(r->flags&HR_6)inet_ntop(AF_INET6,&r->addr6,b,sizeof(b));printf("host %u %s %s %d\n",i,a,b,r->ttl);unsigned j=0;for(struct name_list*n=r->names;n;n=n->next,j++){printf("host-name %u %u ",i,j);hs(n->name);putchar('\n');} }
 return 0;
}
"""

def state_differential(reference, work):
    """Link a read_opts-only probe to exact existing objects; never start listeners."""
    reference = reference.resolve()
    work.mkdir(parents=True, exist_ok=True)
    work = work.resolve()
    build = reference/'dnsmasq'
    deps = reference/'deps'
    (work/'state_probe.c').write_text(C_STATE_PROBE)
    flags = ['-DHAVE_UBUS','-DHAVE_POLL_H','-DNO_DHCP6','-DNO_AUTH','-DNO_IPSET','-DNO_ID']
    subprocess.run(['objcopy','--redefine-sym','main=reference_main',str(build/'dnsmasq.o'),str(work/'dnsmasq-without-main.o')],check=True)
    objects = [str(path) for path in sorted(build.glob('*.o')) if path.name!='dnsmasq.o']
    subprocess.run(['cc','-O2','-Werror=format',*flags,'-I'+str(build),'-I'+str(deps/'include'),str(work/'state_probe.c'),str(work/'dnsmasq-without-main.o'),*objects,'-L'+str(deps/'lib'),'-Wl,-rpath,'+str(deps/'lib'),'-lubus','-lubox','-o',str(work/'c-state')],check=True)
    rustc = shutil.which('rustc')
    if not rustc:
        candidates = sorted((Path.home()/'.rustup/toolchains').glob('1.98.1-*/bin/rustc'))
        if not candidates: raise SystemExit('rustc 1.98.1 missing')
        rustc = str(next((p for p in candidates if 'aarch64' in str(p)), candidates[0]))
    subprocess.run([rustc,'--edition=2021','-A','dead_code','-A','unused_imports',str(ROOT/'components/dnsmasq/src/config/state_probe.rs'),'-o',str(work/'rust-state')],check=True)
    cases = [b'', b'port=\ncache-size=5000001\nedns-packet-max=65536\nmin-cache-ttl=4000',
        b'query-port=0\nlocal-ttl=100\nneg-ttl=10\nmax-ttl=20\nmin-cache-ttl=30\nmax-cache-ttl=40\ndhcp-ttl=50\nmin-port=0\nmax-port=65000\nport-limit=4\ndns-forward-max=321\nmax-tcp-connections=12',
        b'fast-dns-retry=50,1999\nuse-stale-cache=0',b'fast-dns-retry\nuse-stale-cache',b'fast-dns-retry=50,\nuse-stale-cache=100',
        b'host-record=First.test,alias.test,192.0.2.1,2001:db8::1,60\nlocal-ttl=12',
        b'host-record="192.0.2.1","123",192.0.2.2\nhost-record=second.test,',
        b'cname=a.test,b.test,target.test,30\ncname=target.test,final.test\nlocal-ttl=123',
        b'txt-record=test,"a,b", c,,\ntxt-record=empty', b'txt-record=test,'+b'x'*256,
        b'dns-rr=test,65400,a:bcd:ef\ndns-rr=test,65536,ab:*:cd\ndns-rr=zero,1,',
        b'caa-record=test,256,issue,ca.test,extra',b'ptr-record=root.test\nptr-record=empty.test,\nptr-record=other.test,target.test',
        b'mx-host=test,target.test,10\nsrv-host=_sip._tcp,target.test,5060,10,20\ndomain=lan',
        b'srv-host=test\nnaptr-record=test,10,20,u,E2U+sip,"!^.*$!sip:info@example.test!",.',
        b'port=65536',b'cname=a.test,b.test\ncname=b.test,a.test',b'dns-rr=test,1,"abcd"']
    results=[]
    accepted=rejected=0
    for index,body in enumerate(cases):
        fixture=work/f'{index:03}.conf';fixture.write_bytes(body)
        outputs=[]
        for binary in ['c-state','rust-state']:
            result=subprocess.run([str(work/binary),'-C',str(fixture)],capture_output=True)
            (work/f'{index:03}.{binary}.stdout').write_bytes(result.stdout)
            (work/f'{index:03}.{binary}.stderr').write_bytes(result.stderr)
            outputs.append(result)
        a,b=outputs
        equal=(a.returncode==0)==(b.returncode==0) and (a.returncode!=0 or sorted(a.stdout.splitlines())==sorted(b.stdout.splitlines()))
        accepted+=a.returncode==0;rejected+=a.returncode!=0
        results.append({'case':index,'c_status':a.returncode,'rust_status':b.returncode,'match':equal})
    report={'scope':'read_opts scalar and local-record state; no listeners; record row order normalized except host/PTR name order explicitly indexed','cases':len(cases),'accepted':accepted,'rejected':rejected,'failures':[r for r in results if not r['match']],'results':results,'reference_binary_sha256':hashlib.sha256((build/'dnsmasq').read_bytes()).hexdigest()}
    (work/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='results'}))
    if accepted<10 or rejected<2 or report['failures']: raise SystemExit(1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=DEFAULT)
    p.add_argument('--check', action='store_true', help='Fail if committed inventory or Rust metadata is stale')
    p.add_argument('--state-differential', action='store_true')
    p.add_argument('--reference-build', type=Path)
    p.add_argument('--work', type=Path)
    args = p.parse_args()
    if args.state_differential:
        if args.reference_build is None or args.work is None:
            p.error('--state-differential requires --reference-build and --work')
        state_differential(args.reference_build, args.work)
        return
    data = index(args.source)
    outputs = {ROOT/'docs/dnsmasq/options.json':json.dumps(data, indent=2)+'\n', ROOT/'components/dnsmasq/src/config/options.rs':rust(data)}
    for path, body in outputs.items():
        if args.check:
            if not path.exists() or path.read_text() != body:
                raise SystemExit(f'stale generated file: {path.relative_to(ROOT)}')
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
    print(f'{len(data["options"])} options indexed; {sum(r["variant"] == "available" for r in data["options"])} target capability entries; metadata is not runtime coverage')

if __name__ == '__main__':
    main()
