#!/usr/bin/env python3
"""Measure Scheme A's actual layout and clone/detach requested allocations.

All instrumentation is appended to an ignored diagnostic source copy. The
product source and allocator remain unchanged. Native scope allocation data
describe object sizes, not Oracle CPU, musl fragmentation or PSS.
"""
import argparse
import difflib
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

SIZES = {'Slot': 'Slot', 'Entry': 'Entry', 'Record': 'Record', 'ContentBlock': 'ContentBlock',
         'Cache': 'Cache', 'SlotIndices': 'SlotIndices', 'NameIndex': 'NameIndex',
         'NameIndexEntry': '(Arc<[u8]>, SlotIndices)'}


PROBE = r'''
fn m6b_index_heap_indices(indices: &SlotIndices) -> usize {
    match indices { SlotIndices::Many(values) => values.capacity(), _ => 0 }
}

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
    let mut child = std::hint::black_box(parent.snapshot());
    let cloned = finish();
    let shard_lengths: Vec<_> = parent.names.iter().map(|s| s.len()).collect();
    let shard_capacities: Vec<_> = parent.names.iter().map(|s| s.capacity()).collect();
    let index_capacities: usize = parent.names.iter().flat_map(|s| s.values()).map(m6b_index_heap_indices).sum();
    let key_bytes: usize = parent.names.iter().flat_map(|s| s.keys()).map(|s| s.len()).sum();
    start();
    let hit = std::hint::black_box(child.lookup(&Name::from_ascii("q0000.m6a.test").unwrap(), &[Kind::Ipv4], 100, false));
    let hit_scope = finish();
    drop(hit);
    assert!(parent.content.iter().zip(&child.content).all(|(a,b)| Arc::ptr_eq(a,b)));
    assert!(parent.names.iter().zip(&child.names).all(|(a,b)| Arc::ptr_eq(a,b)));
    start();
    for shard in &mut child.names { std::hint::black_box(Arc::make_mut(shard)); }
    let detached_names = finish();
    let detached_index_capacities: usize = child.names.iter().flat_map(|s| s.values()).map(m6b_index_heap_indices).sum();
    start();
    for block in &mut child.content { std::hint::black_box(Arc::make_mut(block)); }
    let detached_content = finish();
    let owner_bytes = child.slots.capacity() * std::mem::size_of::<Slot>();
    let root_bytes = (child.content.capacity() + child.names.capacity()) * std::mem::size_of::<Arc<ContentBlock>>();
    let lengths = format!("{:?}", shard_lengths);
    let capacities = format!("{:?}", shard_capacities);
    start();
    drop(child);
    let drop_scope = finish();
    start();
    let mut single = SlotIndices::default();
    single.push(7);
    std::hint::black_box(&single);
    let singleton_scope = finish();
    start();
    single.push(9);
    std::hint::black_box(&single);
    let one_to_many = finish();
    let many: SlotIndices = [7, 2, 9, 5].into_iter().collect();
    start();
    let mut inherited = many.clone();
    std::hint::black_box(&inherited);
    let many_clone = finish();
    start();
    inherited.rotate_matches(&[7, 9, 5]);
    std::hint::black_box(&inherited);
    let many_rotation = finish();
    assert_eq!(&*many, &[7, 2, 9, 5]);
    assert_eq!(&*inherited, &[9, 5, 7, 2]);
    start();
    inherited.rotate_matches(&[9, 5, 7]);
    std::hint::black_box(&inherited);
    let unique_rotation = finish();
    start();
    inherited.remove(5);
    std::hint::black_box(&inherited);
    let many_remove = finish();
    let mut growth = Vec::new();
    for size in [2usize, 3, 64, 1024] {
        let mut value = SlotIndices::default();
        start();
        for slot in 0..size { value.push(std::hint::black_box(slot)); }
        std::hint::black_box(&value);
        let build = finish();
        start();
        let mut copy = value.clone();
        std::hint::black_box(&copy);
        let shared_clone = finish();
        start();
        copy.push(size);
        std::hint::black_box(&copy);
        let shared_push = finish();
        start();
        copy.remove(size);
        std::hint::black_box(&copy);
        let unique_remove = finish();
        growth.push(format!("{{\"rrset\":{size},\"build_bytes\":{},\"build_allocations\":{},\"clone_bytes\":{},\"clone_allocations\":{},\"shared_push_bytes\":{},\"shared_push_allocations\":{},\"unique_remove_bytes\":{},\"unique_remove_allocations\":{},\"result_capacity\":{}}}",
            build.0, build.1, shared_clone.0, shared_clone.1, shared_push.0, shared_push.1,
            unique_remove.0, unique_remove.1, m6b_index_heap_indices(&copy)));
    }
    let growth = growth.join(",");
    let helper = format!("{{\"singleton_bytes\":{},\"singleton_allocations\":{},\"one_to_many_bytes\":{},\"one_to_many_allocations\":{},\"many_clone_bytes\":{},\"many_clone_allocations\":{},\"many_first_rotation_bytes\":{},\"many_first_rotation_allocations\":{},\"many_unique_rotation_bytes\":{},\"many_unique_rotation_allocations\":{},\"many_remove_net_bytes\":{},\"many_remove_allocations\":{}}}",
        singleton_scope.0, singleton_scope.1, one_to_many.0, one_to_many.1,
        many_clone.0, many_clone.1, many_rotation.0, many_rotation.1,
        unique_rotation.0, unique_rotation.1, many_remove.0, many_remove.1);
    format!("{{\"capacity\":4096,\"owner_slots_requested_bytes\":{owner_bytes},\"root_vectors_requested_bytes\":{root_bytes},\"snapshot_net_requested_bytes\":{},\"snapshot_allocations\":{},\"ordinary_hit_net_requested_bytes\":{},\"ordinary_hit_allocations\":{},\"all_index_detach_net_requested_bytes\":{},\"all_index_detach_allocations\":{},\"all_content_detach_net_requested_bytes\":{},\"all_content_detach_allocations\":{},\"child_drop_net_requested_bytes\":{},\"child_drop_allocations\":{},\"parent_index_heap_indices\":{index_capacities},\"detached_index_heap_indices\":{detached_index_capacities},\"shared_key_payload_bytes\":{key_bytes},\"shard_lengths\":{lengths},\"shard_capacities\":{capacities},\"ordered_index_helper_scopes\":{helper},\"many_growth_scopes\":[{growth}]}}",
            cloned.0, cloned.1, hit_scope.0, hit_scope.1,
            detached_names.0, detached_names.1, detached_content.0, detached_content.1,
            drop_scope.0, drop_scope.1)
}
'''

EXAMPLE = r'''
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
struct Meter;
#[derive(Clone, Copy)]
struct Scope { active: bool, bytes: isize, requests: usize }
thread_local! {
    // Const POD TLS has no heap initialization/destructor. Other harness
    // threads remain inactive and cannot be counted in this probe scope.
    static SCOPE: Cell<Scope> = const { Cell::new(Scope { active: false, bytes: 0, requests: 0 }) };
}
fn account(bytes: isize, requests: usize) {
    let _ = SCOPE.try_with(|state| {
        let mut value = state.get();
        if value.active { value.bytes += bytes; value.requests += requests; state.set(value); }
    });
}
// SAFETY: every request and allocation is forwarded to System unchanged;
// the const POD TLS counters do not allocate or recursively enter the allocator.
// try_with safely excludes destruction-time calls after TLS becomes unavailable.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc supplies a valid allocation layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() { account(layout.size() as isize, 1); }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forward the valid GlobalAlloc layout to System unchanged.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() { account(layout.size() as isize, 1); }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: caller supplies the live System allocation/original layout
        // and valid new size. Failed realloc retains its original ownership.
        let resized = unsafe { System.realloc(ptr, layout, new_size) };
        if !resized.is_null() { account(new_size as isize - layout.size() as isize, 1); }
        resized
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        account(-(layout.size() as isize), 0);
        // SAFETY: ownership and the allocation's original layout are unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Meter = Meter;
fn begin() {
    SCOPE.with(|state| state.set(Scope { active: true, bytes: 0, requests: 0 }));
}
fn end() -> (i64, usize) {
    SCOPE.with(|state| {
        let mut value = state.get(); value.active = false; state.set(value);
        (value.bytes as i64, value.requests)
    })
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


def source_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for part in ['dnsmasq', 'ubus'] for path in sorted((root / 'components' / part).rglob('*'))
            if path.is_file() and 'target' not in path.relative_to(root).parts}


def save_fresh(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def prepare_probe(source, out, commit, inputs, repository):
    cache = source / 'components/dnsmasq/src/dns/cache.rs'
    lib = source / 'components/dnsmasq/src/lib.rs'
    before = {str(path.relative_to(source)): path.read_text() for path in [cache, lib]}
    identity = hashlib.sha256(json.dumps({'source': commit, 'inputs': inputs,
        'probe': PROBE, 'meter': EXAMPLE, 'types': SIZES}, sort_keys=True).encode()).hexdigest()
    archive = out / 'product-components.tar'
    with archive.open('wb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', commit, 'components/dnsmasq', 'components/ubus'],
                       cwd=repository, stdout=stream, check=True)
    if '#[global_allocator]' in lib.read_text():
        raise ValueError('product library already has an allocator')
    meter = EXAMPLE[:EXAMPLE.index('fn main()')]
    meter = meter.replace('fn begin()', 'pub(crate) fn begin()').replace('fn end()', 'pub(crate) fn end()')
    meter_path = source / 'components/dnsmasq/src/m6b_layout_meter.rs'
    meter_path.write_text(meter)
    lib.write_text(lib.read_text() + '\n#[cfg(test)]\nmod m6b_layout_meter;\n')
    fields = ','.join('\\"' + name + '\\":{}' for name in SIZES)
    sizes = ', '.join('std::mem::size_of::<' + expression + '>()' for expression in SIZES.values())
    harness = ('\n#[test]\n#[ignore = "source-bound diagnostic probe only"]\nfn layout() {\n'
               '    let values = m6b_a_probe(crate::m6b_layout_meter::begin, crate::m6b_layout_meter::end);\n'
               '    let sizes = format!("{{' + fields + '}}", ' + sizes + ');\n'
               '    println!("M6B_A_LAYOUT_JSON {{\\"source_commit\\":\\"' + commit + '\\",'
               '\\"probe_identity\\":\\"' + identity + '\\",\\"arch\\":\\"{}\\",\\"musl\\":{},'
               '\\"type_sizes\\":{},\\"native_requested_scopes\\":{}}}", '
               'std::env::consts::ARCH, cfg!(target_env = "musl"), sizes, values);\n}\n')
    cache.write_text(cache.read_text() + '\n#[cfg(test)]\nmod m6b_layout_tests {\nuse super::*;\n'
                     + PROBE + harness + '}\n')
    modified = source_hashes(source)
    patch = []
    for relative in sorted(modified):
        if modified[relative] != inputs.get(relative):
            patch.extend(difflib.unified_diff(before.get(relative, '').splitlines(keepends=True),
                (source / relative).read_text().splitlines(keepends=True), 'a/' + relative, 'b/' + relative))
    (out / 'probe.patch').write_text(''.join(patch))
    save_fresh(out / 'probe-receipt.json', {'source_commit': commit, 'source_root': str(source), 'probe_identity': identity,
        'product_source_inputs': inputs, 'probe_source_inputs': modified,
        'patch_sha256': hashlib.sha256((out / 'probe.patch').read_bytes()).hexdigest(),
        'product_archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'test': 'dns::cache::m6b_layout_tests::layout', 'build_kind': 'probe-tests',
        'status': 'prepared-not-built-not-run', 'qualification': False,
        'method': 'ignored release lib-test; const POD TLS excludes harness-thread allocations; System forwarded unchanged'})
    print(json.dumps({'source': str(source), 'receipt': str(out / 'probe-receipt.json'),
                      'status': 'prepared-not-built-not-run'}))


def probe_binding(args):
    receipt = json.loads(args.receipt.read_text())
    for path, expected in [(Path(__file__), receipt['tool_sha256']),
            (args.receipt.parent / 'probe.patch', receipt['patch_sha256']),
            (args.receipt.parent / 'product-components.tar', receipt['product_archive_sha256'])]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('probe tool/patch/original archive changed')
    with tarfile.open(args.receipt.parent / 'product-components.tar') as archive:
        if archive.pax_headers.get('comment') != receipt['source_commit']:
            raise ValueError('original Git component archive differs')
        original = {member.name: hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                    for member in archive.getmembers() if member.isfile()}
    if original != receipt['product_source_inputs']:
        raise ValueError('original frozen component inputs differ')
    build = json.loads(args.build_json.read_text())
    source = (args.probe_source_root or Path(receipt['source_root'])).resolve()
    if source_hashes(source) != receipt['probe_source_inputs']:
        raise ValueError('generated probe source changed')
    elf_sha = hashlib.sha256(args.test_elf.read_bytes()).hexdigest()
    if (build.get('source') != str(source) or build.get('kind') != 'probe-tests'
            or build.get('opt_level') != '3' or build.get('features') != ''
            or build.get('cargo_target_dir') != '/home/ubuntu/dnsmasq-cargo-target'
            or build.get('source_files') != receipt['probe_source_inputs']
            or build.get('artifacts') != [{'path': 'lib-dnsmasq_rs', 'bytes': args.test_elf.stat().st_size, 'sha256': elf_sha}]):
        raise ValueError('expected locked shared-target feature-off opt3 lib-probe build')
    before = args.build_json.parent / 'probe-source-before.json'
    if (hashlib.sha256(before.read_bytes()).hexdigest() != build.get('source_before_sha256')
            or json.loads(before.read_text()) != receipt['probe_source_inputs']):
        raise ValueError('locked build-time inputs differ')
    return receipt, build, elf_sha


def probe_argv(test_elf):
    return [str(test_elf.resolve()), '--exact', 'dns::cache::m6b_layout_tests::layout',
            '--ignored', '--test-threads=1', '--nocapture']


def run_probe(args):
    receipt, _, elf_sha = probe_binding(args)
    for path in [args.test_log, args.test_stderr, args.run_receipt]:
        if path.exists():
            raise ValueError('probe run outputs must be fresh')
    argv = probe_argv(args.test_elf)
    timed_out = False
    with args.test_log.open('xb') as stdout, args.test_stderr.open('xb') as stderr:
        try:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=60)
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            timed_out = True; exit_code = None
    after = hashlib.sha256(args.test_elf.read_bytes()).hexdigest()
    save_fresh(args.run_receipt, {'source_commit': receipt['source_commit'], 'argv': argv,
        'exit': exit_code, 'timed_out': timed_out, 'timeout_seconds': 60,
        'test_elf_before': elf_sha, 'test_elf_after': after,
        'prep_receipt_sha256': hashlib.sha256(args.receipt.read_bytes()).hexdigest(),
        'build_sha256': hashlib.sha256(args.build_json.read_bytes()).hexdigest(),
        'stdout_sha256': hashlib.sha256(args.test_log.read_bytes()).hexdigest(),
        'stderr_sha256': hashlib.sha256(args.test_stderr.read_bytes()).hexdigest()})
    if timed_out or exit_code != 0 or after != elf_sha:
        raise ValueError('probe failed or copied executable changed; evidence retained')


def collect_probe(args):
    receipt, _, elf_sha = probe_binding(args)
    run = json.loads(args.run_receipt.read_text())
    if (run.get('source_commit') != receipt['source_commit'] or run.get('argv') != probe_argv(args.test_elf)
            or run.get('exit') != 0 or run.get('timed_out') is not False or run.get('timeout_seconds') != 60
            or run.get('test_elf_before') != elf_sha or run.get('test_elf_after') != elf_sha
            or run.get('prep_receipt_sha256') != hashlib.sha256(args.receipt.read_bytes()).hexdigest()
            or run.get('build_sha256') != hashlib.sha256(args.build_json.read_bytes()).hexdigest()
            or run.get('stdout_sha256') != hashlib.sha256(args.test_log.read_bytes()).hexdigest()
            or run.get('stderr_sha256') != hashlib.sha256(args.test_stderr.read_bytes()).hexdigest()):
        raise ValueError('exact executed probe/ELF/log binding differs')
    log = args.test_log.read_text()
    # libtest may print "test ... " before uncaptured output on the same
    # line. The exact marker still has to occur once with a complete JSON row.
    rows = re.findall(r'(?:^| )M6B_A_LAYOUT_JSON (.+)$', log, re.MULTILINE)
    if len(rows) != 1 or 'test result: ok. 1 passed; 0 failed' not in log:
        raise ValueError('one complete exact probe execution required')
    measured = json.loads(rows[0])
    if (measured.get('source_commit') != receipt['source_commit'] or measured.get('probe_identity') != receipt['probe_identity']
            or measured.get('arch') != 'aarch64' or measured.get('musl') is not True or set(measured['type_sizes']) != set(SIZES)):
        raise ValueError('actual target probe/layout inventory differs')
    if any(type(value) is not int or value <= 0 for value in measured['type_sizes'].values()):
        raise ValueError('numeric target type sizes required')
    scopes = measured['native_requested_scopes']
    numeric = ['capacity', 'owner_slots_requested_bytes', 'root_vectors_requested_bytes',
        'snapshot_net_requested_bytes', 'snapshot_allocations', 'ordinary_hit_net_requested_bytes',
        'ordinary_hit_allocations', 'all_index_detach_net_requested_bytes', 'all_index_detach_allocations',
        'all_content_detach_net_requested_bytes', 'all_content_detach_allocations', 'child_drop_net_requested_bytes',
        'child_drop_allocations', 'parent_index_heap_indices', 'detached_index_heap_indices', 'shared_key_payload_bytes']
    if any(type(scopes.get(key)) is not int for key in numeric):
        raise ValueError('complete numeric allocation scopes required')
    for key in ['shard_lengths', 'shard_capacities']:
        if len(scopes.get(key, [])) != 64 or any(type(value) is not int or value < 0 for value in scopes[key]):
            raise ValueError('all 64 highbit shard observations required')
    growth = scopes.get('many_growth_scopes', [])
    if [row.get('rrset') for row in growth] != [2, 3, 64, 1024]:
        raise ValueError('all ordered-Many growth probes required')
    helper_keys = {'singleton_bytes', 'singleton_allocations', 'one_to_many_bytes', 'one_to_many_allocations',
        'many_clone_bytes', 'many_clone_allocations', 'many_first_rotation_bytes', 'many_first_rotation_allocations',
        'many_unique_rotation_bytes', 'many_unique_rotation_allocations', 'many_remove_net_bytes', 'many_remove_allocations'}
    growth_keys = {'rrset', 'build_bytes', 'build_allocations', 'clone_bytes', 'clone_allocations',
        'shared_push_bytes', 'shared_push_allocations', 'unique_remove_bytes', 'unique_remove_allocations', 'result_capacity'}
    helper = scopes.get('ordered_index_helper_scopes', {})
    if set(helper) != helper_keys or any(set(row) != growth_keys for row in growth):
        raise ValueError('complete helper/growth scope inventory required')
    for row in [helper, *growth]:
        if any(type(value) is not int for value in row.values()):
            raise ValueError('numeric helper scope observations required')
    result = {'source_commit': receipt['source_commit'], 'type_sizes': measured['type_sizes'],
              'native_requested_scopes': scopes, 'probe_identity': measured['probe_identity'],
              'receipt_sha256': hashlib.sha256(args.receipt.read_bytes()).hexdigest(),
              'build_sha256': hashlib.sha256(args.build_json.read_bytes()).hexdigest(),
              'test_elf_sha256': elf_sha, 'test_log_sha256': hashlib.sha256(args.test_log.read_bytes()).hexdigest(),
              'run_receipt_sha256': hashlib.sha256(args.run_receipt.read_bytes()).hexdigest(),
              'probe_source_inputs': receipt['probe_source_inputs'], 'method': receipt['method'],
              'cpu_or_product_pss_qualification': False}
    save_fresh(args.report, result)
    print(json.dumps({key: value for key, value in result.items() if key != 'probe_source_inputs'}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--source')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--prepare-probe', action='store_true', help='export ignored release lib-test; no build/run')
    parser.add_argument('--run-probe', action='store_true', help='execute only the separately built copied lib-probe')
    parser.add_argument('--collect-probe', action='store_true')
    parser.add_argument('--local-native', action='store_true', help='legacy direct cargo mode; local machine only')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--probe-source-root', type=Path)
    parser.add_argument('--build-json', type=Path)
    parser.add_argument('--test-elf', type=Path)
    parser.add_argument('--test-log', type=Path)
    parser.add_argument('--test-stderr', type=Path)
    parser.add_argument('--run-receipt', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if args.collect_probe or args.run_probe:
        if (args.prepare_probe or args.local_native or args.collect_probe and args.run_probe
                or not all([args.receipt, args.build_json, args.test_elf, args.test_log, args.test_stderr, args.run_receipt])
                or args.collect_probe and not args.report):
            parser.error('run/collect requires receipt/build/test-elf/log/stderr/run-receipt (collect also report)')
        return collect_probe(args) if args.collect_probe else run_probe(args)
    if not all([args.repository, args.source, args.out]):
        parser.error('source preparation requires repository/source/out')
    repo, out = args.repository.resolve(), args.out.resolve()
    if not args.prepare_probe and (not args.local_native or str(repo).startswith('/home/ubuntu') or str(out).startswith('/home/ubuntu')):
        parser.error('legacy cargo requires explicit local-native; Oracle must use probe-tests')
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
    if args.prepare_probe:
        return prepare_probe(source, out, commit, inputs, repo)
    cache = source / 'components/dnsmasq/src/dns/cache.rs'
    text = cache.read_text()
    types = SIZES
    for name, expression in types.items():
        text += f'\n#[used]\n#[no_mangle]\npub static M6B_A_SIZE_{name}: [u8; std::mem::size_of::<{expression}>()] = [0; std::mem::size_of::<{expression}>()];\n'
    cache.write_text(text)
    manifest = source / 'components/dnsmasq/Cargo.toml'
    target_dir = out / 'target'
    command(['cargo', 'rustc', '--release', '--manifest-path', str(manifest), '--lib', '--target', 'aarch64-unknown-linux-musl', '--target-dir', str(target_dir), '--', '--emit=llvm-ir'], source, out, 'target-layout')
    irs = list((target_dir / 'aarch64-unknown-linux-musl/release/deps').glob('dnsmasq_rs-*.ll'))
    if len(irs) != 1:
        raise RuntimeError(f'expected one LLVM IR, got {irs}')
    ir = irs[0].read_text()
    sizes = {}
    for name in types:
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
