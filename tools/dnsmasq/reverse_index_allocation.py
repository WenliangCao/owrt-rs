#!/usr/bin/env python3
"""Untimed, pre-modelled cost of adding reverse entries to the name index."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import dns_cache_diff

ROOT = Path(__file__).resolve().parents[2]
COMMITS = {'old': '62894d657341827f3ea1e903375a6263dbe4de82',
           'fixed': '0eaaef813893ac71954f56c379f8fc6b5eb24064'}
CACHE_HASHES = {'old': '959592939af416989e4d7821a01f7ce54fcb368c8fdc9b85d3501f0cbd8d7f44',
                'fixed': '5d62b11382abcb2c59cef411a060365f1675ebeca839101c1cb194d26e9160d2'}
CASES = ['empty', 'single-v4', 'single-v6', 'shared-forward-name', 'three-targets',
         'four-targets', 'repeated-target', 'expiry-and-reuse']
ZERO = [0] * 6
SINGLE = [3, 0, 245, 245, 0, 0]
MODELS = {
    'empty': {},
    'single-v4': {'commit': SINGLE, 'drop': [0, 0, 0, -245, 3, 245]},
    'single-v6': {'commit': SINGLE, 'drop': [0, 0, 0, -245, 3, 245]},
    'shared-forward-name': {'commit': [1, 0, 9, 0, 1, 9], 'forward-lookup': [0, 0, 8, 0, 0, 8]},
    'three-targets': {'commit': [7, 0, 327, 327, 0, 0], 'drop': [0, 0, 0, -327, 7, 327]},
    'four-targets': {'commit': [10, 0, 768, 564, 1, 204], 'drop': [0, 0, 0, -564, 9, 564]},
    'repeated-target': {'commit': [4, 0, 254, 245, 1, 9], 'drop': [0, 0, 0, -245, 3, 245]},
    'expiry-and-reuse': {'commit': SINGLE, 'expire': [1, 0, 9, -41, 3, 50],
                         'recommit': [2, 0, 41, 41, 0, 0], 'drop': [0, 0, 0, -245, 3, 245]},
}
ACCESSOR = r'''
// Read-only measurement accessor on a generated source copy.
pub fn footprint_layout() -> [usize; 4] {
    [std::mem::size_of::<Cache>(), std::mem::size_of::<Slot>(),
     std::mem::size_of::<Entry>(), std::mem::size_of::<Record>()]
}
impl Cache {
    pub fn footprint_shape(&self) -> [usize; 5] {
        [self.names.len(), self.names.capacity(),
         self.names.keys().map(|key| key.capacity()).sum(),
         self.names.values().map(|slots| slots.capacity()).sum(),
         self.slots.iter().filter(|slot| slot.entry.as_ref().is_some_and(|entry| entry.committed)).count()]
    }
}
'''
DRIVER = r'''
use cache::{Cache, CacheCounters, Kind, Policy, Record};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
const V4: [u8;4] = [192,0,2,1];
const V6: [u8;16] = [0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1];
#[derive(Clone,Copy)]
struct Event { name: &'static str, delta: [i64;6], shape: [usize;5], counters: [u32;2] }
fn snapshot() -> [i64;6] {
    let a=allocation::snapshot(); let d=allocation::drops();
    [a[0],a[1],a[2],a[3],d[0] as i64,d[1] as i64]
}
fn delta(a:[i64;6],b:[i64;6])->[i64;6] { std::array::from_fn(|i|a[i]-b[i]) }
fn record(index:usize,kind:Kind)->Record {
    let names=["n0.test","n1.test","n2.test","n3.test"];
    Record {name:wire::Name::from_ascii(names[index]).unwrap(),kind,negative:false,
            data:if kind==Kind::ReverseIpv6 {V6.to_vec()}else{V4.to_vec()} }
}
fn reverse_lookup(cache:&mut Cache,address:IpAddr,now:i64,count:usize) {
    let ids=cache.lookup_reverse(address,now);
    std::hint::black_box(&ids);
    assert_eq!(ids.len(),count);
    drop(ids);
}
fn main() {
    assert_eq!(std::mem::size_of::<usize>(),8);
    let args:Vec<_>=std::env::args().collect(); let case=args[1].as_str();
    let mut events=[Event{name:"",delta:[0;6],shape:[0;5],counters:[0;2]};12];
    let mut used=0usize; let mut counters=CacheCounters::default();
    let start=snapshot(); let mut cache=Cache::new(8,Policy::default());
    events[used]=Event{name:"create",delta:delta(snapshot(),start),shape:cache.footprint_shape(),counters:[0;2]}; used+=1;
    macro_rules! measure { ($name:literal,$body:expr) => {{
        let before=snapshot(); let result=$body; let after=snapshot();
        events[used]=Event{name:$name,delta:delta(after,before),shape:cache.footprint_shape(),
                          counters:[counters.inserted,counters.live_freed]}; used+=1; result
    }}; }
    if case=="shared-forward-name" {
        measure!("seed",{cache.start_insert();cache.insert_counted(record(0,Kind::Ipv4),100,60,&mut counters).unwrap();assert!(cache.commit_counted(&mut counters));});
    }
    let count=match case {"empty"=>0,"three-targets"=>3,"four-targets"=>4,"repeated-target"=>2,
                        "single-v4"|"single-v6"|"shared-forward-name"|"expiry-and-reuse"=>1,_=>panic!()};
    let kind=if case=="single-v6"{Kind::ReverseIpv6}else{Kind::ReverseIpv4};
    let address=if case=="single-v6"{IpAddr::V6(Ipv6Addr::from(V6))}else{IpAddr::V4(Ipv4Addr::from(V4))};
    let ttl=if case=="expiry-and-reuse"{10}else{60};
    measure!("insert",{
        cache.start_insert();
        for index in 0..count {
            let index=if case=="repeated-target"{0}else{index};
            cache.insert_counted(record(index,kind),100,ttl,&mut counters).unwrap();
        }
    });
    measure!("commit",assert!(cache.commit_counted(&mut counters)));
    measure!("reverse-lookup",reverse_lookup(&mut cache,address,101,count));
    if case=="shared-forward-name" {
        measure!("forward-lookup",{
            let name=wire::Name::from_ascii("n0.test").unwrap();
            let ids=cache.lookup(&name,&[Kind::Ipv4],101,false);
            std::hint::black_box(&ids); assert_eq!(ids.len(),1); drop(ids); drop(name);
        });
    }
    if case=="expiry-and-reuse" {
        measure!("expire",reverse_lookup(&mut cache,address,110,0));
        measure!("reinsert",{cache.start_insert();cache.insert_counted(record(0,kind),111,60,&mut counters).unwrap();});
        measure!("recommit",assert!(cache.commit_counted(&mut counters)));
    }
    let inserted=match case {"empty"=>0,"shared-forward-name"|"repeated-target"|"expiry-and-reuse"=>2,
                            "three-targets"=>3,"four-targets"=>4,_=>1};
    assert_eq!(counters.inserted,inserted); assert_eq!(counters.live_freed,0);
    std::hint::black_box(&cache);
    let before=snapshot(); drop(cache); let final_stats=snapshot();
    events[used]=Event{name:"drop",delta:delta(final_stats,before),shape:[0;5],counters:[counters.inserted,counters.live_freed]};used+=1;
    let total=delta(final_stats,start); assert_eq!(total[3],0);
    println!("{{\"case\":{case:?},\"layout\":{:?},\"total\":{total:?},\"events\":[",cache::footprint_layout());
    for (index,e) in events[..used].iter().enumerate() {
        if index!=0 {println!(",");}
        print!("{{\"name\":{:?},\"delta\":{:?},\"shape\":{:?},\"counters\":{:?}}}",e.name,e.delta,e.shape,e.counters);
    }
    println!("]}}");
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def allocator_source():
    text = (ROOT / 'tools/dnsmasq/cache_expiry_screen.rs').read_text()
    text = text[text.index('#[cfg(allocation_tracking)]'):text.index('#[repr(C)]')]
    text = replace_once(text, '    static CALLS:', '''    static DEALLOCS: AtomicU64 = AtomicU64::new(0);
    static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
    pub fn drops() -> [u64; 2] { [DEALLOCS.load(Relaxed), DEALLOC_BYTES.load(Relaxed)] }
    static CALLS:''')
    return replace_once(text, '            LIVE.fetch_sub(layout.size() as i64, Relaxed);', '''            DEALLOCS.fetch_add(1, Relaxed);
            DEALLOC_BYTES.fetch_add(layout.size() as u64, Relaxed);
            LIVE.fetch_sub(layout.size() as i64, Relaxed);''')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--old-source', type=Path, required=True)
    p.add_argument('--fixed-source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--rustc', default='/home/ubuntu/.cargo/bin/rustc')
    args = p.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    meter = allocator_source()
    report = {'scope': __doc__, 'commits': COMMITS, 'tool_sha256': sha(Path(__file__)),
              'plan_sha256': sha(ROOT / 'docs/dnsmasq/REVERSE_INDEX_ALLOCATION_PLAN.md'),
              'meter_sha256': hashlib.sha256(meter.encode()).hexdigest(), 'models': MODELS,
              'runs': [], 'failures': [], 'binaries': {}}
    report['rustc'] = subprocess.check_output([args.rustc, '+1.98.1', '-vV'], text=True)
    for label, source in [('old', args.old_source.resolve()), ('fixed', args.fixed_source.resolve())]:
        folder = out / label
        folder.mkdir()
        cache = source / 'components/dnsmasq/src/dns/cache.rs'
        assert sha(cache) == CACHE_HASHES[label]
        instrumented = folder / 'cache_probe.rs'
        instrumented.write_bytes(cache.read_bytes() + ACCESSOR.encode())
        modules = replace_once(dns_cache_diff.rust_modules(source), json.dumps(str(cache)), json.dumps(str(instrumented)))
        driver = folder / 'driver.rs'
        driver.write_text(modules + meter + DRIVER)
        binary = folder / 'probe'
        command = [args.rustc, '+1.98.1', '--edition=2021', '-A', 'dead_code', '-O',
                   '--cfg', 'allocation_tracking', str(driver), '-o', str(binary)]
        build = subprocess.run(command, text=True, capture_output=True)
        (folder / 'build.stdout').write_text(build.stdout)
        (folder / 'build.stderr').write_text(build.stderr)
        save(folder / 'build-command.json', {'argv': command, 'exit': build.returncode})
        assert build.returncode == 0, (label, 'build failed; logs retained')
        report['binaries'][label] = {'sha256': sha(binary), 'driver_sha256': sha(driver),
            'source_files': {name: sha(source / 'components/dnsmasq/src/dns' / name)
                             for name in ['cache.rs', 'wire.rs', 'lease_names.rs']},
            'instrumented_cache_sha256': sha(instrumented)}
    for case in CASES:
        pair = {}
        for label in ['old', 'fixed']:
            folder = out / label
            command = [str(folder / 'probe'), case]
            run = subprocess.run(command, capture_output=True, text=True)
            (folder / f'{case}.stdout').write_text(run.stdout)
            (folder / f'{case}.stderr').write_text(run.stderr)
            save(folder / f'{case}.command.json', {'argv': command, 'exit': run.returncode})
            row = {'source': label, 'case': case, 'exit': run.returncode}
            if run.returncode == 0:
                try:
                    row.update(json.loads(run.stdout))
                    pair[label] = row
                except Exception as error:
                    report['failures'].append({'case': case, 'source': label, 'error': repr(error)})
            else:
                report['failures'].append({'case': case, 'source': label, 'error': 'probe failed'})
            report['runs'].append(row)
            save(out / 'partial-result.json', report)
        if len(pair) == 2:
            for label, row in pair.items():
                if row['layout'] != [168, 160, 120, 56] or row['total'][3] != 0:
                    report['failures'].append({'case': case, 'source': label, 'error': 'layout or balance differs'})
            old = {row['name']: row for row in pair['old']['events']}
            fixed = {row['name']: row for row in pair['fixed']['events']}
            assert old.keys() == fixed.keys()
            for phase in old:
                difference = [a-b for a, b in zip(fixed[phase]['delta'], old[phase]['delta'])]
                expected = MODELS[case].get(phase, ZERO)
                if difference != expected:
                    report['failures'].append({'case': case, 'phase': phase, 'expected': expected, 'observed': difference})
            assert pair['old']['events'][-1]['counters'] == pair['fixed']['events'][-1]['counters']
    for label, source in [('old', args.old_source.resolve()), ('fixed', args.fixed_source.resolve())]:
        for name, digest in report['binaries'][label]['source_files'].items():
            assert sha(source / 'components/dnsmasq/src/dns' / name) == digest
    report['source_reverified'] = True
    report['status'] = 'model-matched' if not report['failures'] else 'model-or-probe-failure'
    save(out / 'result.json', report)
    print(json.dumps({'status': report['status'], 'runs': len(report['runs']), 'failures': report['failures']}))
    return bool(report['failures'])


if __name__ == '__main__':
    raise SystemExit(main())
