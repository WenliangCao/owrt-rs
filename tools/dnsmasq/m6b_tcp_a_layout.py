#!/usr/bin/env python3
"""Measure Scheme A's actual layout and clone/detach requested allocations.

All instrumentation is appended to an ignored diagnostic source copy. The
product source and allocator remain unchanged. Native scope allocation data
describe object sizes, not Oracle CPU, musl fragmentation or PSS.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


PROBE = r'''
pub fn m6b_a_probe(start: fn(), finish: fn() -> (i64, usize)) -> String {
    let mut parent = Cache::new(4096, Policy::default());
    for index in 0..4096u32 {
        parent.start_insert();
        parent.insert(Record {
            name: Name::from_ascii(&format!("q{index:04x}.m6a.test")).unwrap(),
            kind: Kind::Ipv4, negative: false,
            data: vec![198, 18, (index >> 8) as u8, index as u8],
        }, 100, 3600).unwrap();
        assert!(parent.commit());
    }
    start();
    let mut child = parent.snapshot();
    let cloned = finish();
    let shard_lengths: Vec<_> = parent.names.iter().map(|s| s.len()).collect();
    let shard_capacities: Vec<_> = parent.names.iter().map(|s| s.capacity()).collect();
    let index_capacities: usize = parent.names.iter().flat_map(|s| s.values()).map(Vec::capacity).sum();
    let key_bytes: usize = parent.names.iter().flat_map(|s| s.keys()).map(|s| s.len()).sum();
    start();
    let hit = child.lookup(&Name::from_ascii("q0000.m6a.test").unwrap(), &[Kind::Ipv4], 100, false);
    let hit_scope = finish();
    drop(hit);
    assert!(parent.content.iter().zip(&child.content).all(|(a,b)| Arc::ptr_eq(a,b)));
    assert!(parent.names.iter().zip(&child.names).all(|(a,b)| Arc::ptr_eq(a,b)));
    start();
    for shard in &mut child.names { Arc::make_mut(shard); }
    let detached_names = finish();
    let detached_index_capacities: usize = child.names.iter().flat_map(|s| s.values()).map(Vec::capacity).sum();
    start();
    for block in &mut child.content { Arc::make_mut(block); }
    let detached_content = finish();
    let owner_bytes = child.slots.capacity() * std::mem::size_of::<Slot>();
    let root_bytes = (child.content.capacity() + child.names.capacity()) * std::mem::size_of::<Arc<ContentBlock>>();
    let lengths = format!("{:?}", shard_lengths);
    let capacities = format!("{:?}", shard_capacities);
    start();
    drop(child);
    let drop_scope = finish();
    format!("{{\"capacity\":4096,\"owner_slots_requested_bytes\":{owner_bytes},\"root_vectors_requested_bytes\":{root_bytes},\"snapshot_net_requested_bytes\":{},\"snapshot_allocations\":{},\"ordinary_hit_net_requested_bytes\":{},\"ordinary_hit_allocations\":{},\"all_index_detach_net_requested_bytes\":{},\"all_index_detach_allocations\":{},\"all_content_detach_net_requested_bytes\":{},\"all_content_detach_allocations\":{},\"child_drop_net_requested_bytes\":{},\"child_drop_allocations\":{},\"parent_singleton_index_capacity_sum\":{index_capacities},\"detached_singleton_index_capacity_sum\":{detached_index_capacities},\"shared_key_payload_bytes\":{key_bytes},\"shard_lengths\":{lengths},\"shard_capacities\":{capacities}}}",
            cloned.0, cloned.1, hit_scope.0, hit_scope.1,
            detached_names.0, detached_names.1, detached_content.0, detached_content.1,
            drop_scope.0, drop_scope.1)
}
'''

EXAMPLE = r'''
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
struct Meter;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicIsize = AtomicIsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
// SAFETY: every request and allocation is forwarded to System unchanged;
// counters are atomics and do not allocate or recursively enter the allocator.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc supplies a valid allocation layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && ACTIVE.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ACTIVE.load(Ordering::Relaxed) {
            BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        }
        // SAFETY: ownership and the allocation's original layout are unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;
fn begin() {
    BYTES.store(0, Ordering::Relaxed); ALLOCS.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
}
fn end() -> (i64, usize) {
    ACTIVE.store(false, Ordering::Relaxed);
    (BYTES.load(Ordering::Relaxed) as i64, ALLOCS.load(Ordering::Relaxed))
}
fn main() { println!("{}", dnsmasq_rs::dns::cache::m6b_a_probe(begin, end)); }
'''


def command(argv, cwd, out, stem):
    run = subprocess.run(argv, cwd=cwd, text=True, capture_output=True)
    (out / (stem + '.stdout')).write_text(run.stdout)
    (out / (stem + '.stderr')).write_text(run.stderr)
    (out / (stem + '-command.json')).write_text(json.dumps({'argv': argv, 'exit': run.returncode}, indent=2) + '\n')
    run.check_returncode()
    return run.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    repo, out = args.repository.resolve(), args.out.resolve()
    if 'private' not in out.parts:
        parser.error('diagnostic output must be under ignored private/')
    out.mkdir(parents=True, exist_ok=False)
    commit = subprocess.check_output(['git', 'rev-parse', args.source], cwd=repo, text=True).strip()
    source = out / 'source'
    inputs = {}
    for part in ['dnsmasq', 'ubus']:
        paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit, 'components/' + part], cwd=repo, text=True).splitlines()
        for name in paths:
            value = subprocess.check_output(['git', 'show', f'{commit}:{name}'], cwd=repo)
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            inputs[name] = hashlib.sha256(value).hexdigest()
    cache = source / 'components/dnsmasq/src/dns/cache.rs'
    text = cache.read_text()
    for name in ['Slot', 'Entry', 'Record', 'ContentBlock', 'Cache']:
        text += f'\n#[used]\n#[no_mangle]\npub static M6B_A_SIZE_{name}: [u8; std::mem::size_of::<{name}>()] = [0; std::mem::size_of::<{name}>()];\n'
    cache.write_text(text)
    manifest = source / 'components/dnsmasq/Cargo.toml'
    target_dir = out / 'target'
    command(['cargo', 'rustc', '--release', '--manifest-path', str(manifest), '--lib', '--target', 'aarch64-unknown-linux-musl', '--target-dir', str(target_dir), '--', '--emit=llvm-ir'], source, out, 'target-layout')
    irs = list((target_dir / 'aarch64-unknown-linux-musl/release/deps').glob('dnsmasq_rs-*.ll'))
    if len(irs) != 1:
        raise RuntimeError(f'expected one LLVM IR, got {irs}')
    ir = irs[0].read_text()
    sizes = {}
    for name in ['Slot', 'Entry', 'Record', 'ContentBlock', 'Cache']:
        values = re.findall(r'^@M6B_A_SIZE_' + name + r' = .*?\[(\d+) x i8\]', ir, re.MULTILINE)
        if len(values) != 1:
            raise RuntimeError('missing layout ' + name)
        sizes[name] = int(values[0])
    cache.write_text(cache.read_text() + PROBE)
    example = source / 'components/dnsmasq/examples/m6b_a_layout.rs'
    example.parent.mkdir(parents=True, exist_ok=True)
    example.write_text(EXAMPLE)
    native = command(['cargo', 'run', '--release', '--manifest-path', str(manifest), '--target-dir', str(target_dir), '--example', 'm6b_a_layout'], source, out, 'native-scopes')
    result = {'source_commit': commit, 'source_inputs': inputs, 'target': 'aarch64-unknown-linux-musl', 'type_sizes': sizes,
              'native_requested_scopes': json.loads(native), 'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
              'method': 'AArch64 LLVM sizeof globals plus System-forwarding native requested-allocation scopes; no product change; not Oracle CPU/PSS or allocator metadata'}
    (out / 'layout.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'source_inputs'}, indent=2))


if __name__ == '__main__':
    main()
