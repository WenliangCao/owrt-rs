#!/usr/bin/env python3
"""Build a private source-bound UDP socket-factory bridge; syscall counts only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return {str(path.relative_to(root)): sha(path) for path in sorted(root.rglob('*')) if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--release', action='store_true')
    parser.add_argument('--allocations', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    copied = out / 'input/components'
    copied.mkdir(parents=True)
    for component in ('dnsmasq', 'ubus'):
        shutil.copytree(args.source / 'components' / component, copied / component,
                        ignore=shutil.ignore_patterns('target', 'fuzz'))
    source_files = manifest(copied)
    configured = 'pub fn bind_config(' in (copied / 'dnsmasq/src/listeners.rs').read_text()
    examples = copied / 'dnsmasq/examples'
    examples.mkdir(exist_ok=True)
    harness = Path(__file__).with_suffix('.rs')
    text = harness.read_text()
    replacements = {
        'DNS_RECEIVE_BIND': ('DnsSocket::bind_config(address, &config, &interfaces).unwrap()' if configured
                             else 'let _ = (&config, &interfaces); DnsSocket::bind(address).unwrap()'),
        'CONFIGURED_BIND': str(configured).lower(),
        'ALLOCATION_METER': 'fn allocation_counts() -> [u64; 3] { [0; 3] }',
    }
    if args.allocations:
        replacements['ALLOCATION_METER'] = '''
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
struct Meter;
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed); BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        REALLOCS.fetch_add(1, Relaxed); BYTES.fetch_add(size as u64, Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static METER: Meter = Meter;
fn allocation_counts() -> [u64; 3] {
    [ALLOCS.load(Relaxed), REALLOCS.load(Relaxed), BYTES.load(Relaxed)]
}
'''
    for marker, replacement in replacements.items():
        assert text.count('/* ' + marker + ' */') == 1
        text = text.replace('/* ' + marker + ' */', replacement)
    (examples / 'loop-source-socket-screen.rs').write_text(text)
    instrumented_files = manifest(copied)
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
    argv = ['/home/ubuntu/.cargo/bin/cargo', '+1.98.1', 'build', '--frozen', '--jobs', '1',
            '--manifest-path', str(copied / 'dnsmasq/Cargo.toml'),
            '--example', 'loop-source-socket-screen', '--message-format=json']
    if args.release:
        argv.append('--release')
    result = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (out / 'build.stdout').write_text(result.stdout)
    (out / 'build.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    assert manifest(copied) == instrumented_files, 'source changed during build'
    artifacts = [json.loads(line) for line in result.stdout.splitlines()]
    binaries = [row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row.get('executable') and row['target']['name'] == 'loop-source-socket-screen']
    assert len(binaries) == 1
    shutil.copy2(binaries[0], out / 'socket-factory')
    report = {'argv': argv, 'harness_sha256': sha(harness), 'driver_sha256': sha(Path(__file__)),
              'source_commit': args.source_commit, 'source_files': source_files,
              'instrumented_files': instrumented_files,
              'configured_dns_bind': configured, 'counting_allocator': args.allocations,
              'factory_sha256': sha(copied / 'dnsmasq/src/dns/source_sockets.rs'),
              'elf_sha256': sha(out / 'socket-factory'), 'timing_prohibited': True}
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
