#!/usr/bin/env python3
"""Prepare/build private actual-owner allocation instrumentation; never time it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest(copied):
    files = {path.relative_to(copied.parent).as_posix(): sha(path)
             for path in sorted(copied.rglob('*')) if path.is_file()}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True,
                                      separators=(',', ':')).encode()).hexdigest()
    return files, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cargo', default='/home/ubuntu/.cargo/bin/cargo')
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--instructions', action='store_true',
                        help='optimized perf-stat harness without the counting allocator')
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.source_commit):
        parser.error('--source-commit must be a full lowercase SHA1')
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    copied = out / 'input/components'
    copied.mkdir(parents=True)
    for component in ('dnsmasq', 'ubus'):
        shutil.copytree(args.source / 'components' / component, copied / component,
                        ignore=shutil.ignore_patterns('target', 'fuzz'))
    source_files, source_digest = source_manifest(copied)
    main_rs = copied / 'dnsmasq/src/main.rs'
    original_sha = sha(main_rs)
    harness = Path(__file__).with_suffix('.rs')
    daemon_source = copied / 'dnsmasq/src/dns/daemon.rs'
    retirement = 'pub fn retire_cache_for_process_exit(' in daemon_source.read_text()
    harness_text = harness.read_text().replace('/* RETIRE_CACHE */',
        'daemon.retire_cache_for_process_exit();' if retirement else '')
    if args.instructions:
        hook = '#[global_allocator]\n    static METER: Meter = Meter;'
        assert harness_text.count(hook) == 1
        harness_text = harness_text.replace(hook, '')
    readiness_source = copied / 'dnsmasq/src/owner_readiness.rs'
    readiness = readiness_source.is_file()
    if readiness:
        readiness_source.write_text(readiness_source.read_text() + '''
// Private measurement accessors; never included in a release artifact.
#[cfg(test)]
impl OwnerReadiness {
    pub(super) fn measurement_resources(&self) -> [usize; 9] {
        use std::mem::size_of;
        [size_of::<Self>(), size_of::<Key>(), size_of::<Registration>(),
         size_of::<Event>(), self.tags.capacity() * size_of::<(usize, Key)>(),
         self.desired.capacity() * size_of::<Registration>(),
         self.registered.capacity() * size_of::<Registration>(),
         self.direct.capacity() * size_of::<PollFd>(),
         self.events.capacity() * size_of::<Event>()]
    }
    pub(super) fn measurement_state(&self) -> [usize; 3] {
        [self.epoll.is_some() as usize, self.registered.len(), self.oversized as usize]
    }
}
''')
        readiness_helpers = '''
    fn readiness_resources(owner: &SinglePoll) -> [usize; 9] {
        owner.readiness.measurement_resources()
    }
    fn readiness_state(owner: &SinglePoll) -> [usize; 3] {
        owner.readiness.measurement_state()
    }
'''
    else:
        readiness_helpers = '''
    fn readiness_resources(_owner: &SinglePoll) -> [usize; 9] { [0; 9] }
    fn readiness_state(_owner: &SinglePoll) -> [usize; 3] { [0; 3] }
'''
    if harness_text.count('/* READINESS_RESOURCES */') != 1:
        raise ValueError('harness must have exactly one READINESS_RESOURCES marker')
    harness_text = harness_text.replace('/* READINESS_RESOURCES */', readiness_helpers)
    main_rs.write_text(main_rs.read_text() + '\n' + harness_text)
    instrumented_files, instrumented_digest = source_manifest(copied)
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
    argv = [args.cargo, '+1.98.1', 'test', '--frozen', '--jobs', '1',
            '--manifest-path', str(copied / 'dnsmasq/Cargo.toml'), '--bin', 'dnsmasq-rs',
            '--no-run', '--message-format=json']
    if args.instructions:
        argv.append('--release')
    built = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (out / 'build.stdout').write_text(built.stdout)
    (out / 'build.stderr').write_text(built.stderr)
    if built.returncode:
        raise RuntimeError(built.stderr)
    if source_manifest(copied) != (instrumented_files, instrumented_digest):
        raise RuntimeError('instrumented source changed during build')
    artifacts = [json.loads(line) for line in built.stdout.splitlines()]
    binaries = [row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row.get('executable') and row.get('profile', {}).get('test')]
    assert len(binaries) == 1
    executable = out / ('owner-instructions' if args.instructions else 'owner-allocation')
    shutil.copy2(binaries[0], executable)
    report = {'source_commit': args.source_commit, 'driver_sha256': sha(Path(__file__)),
              'source_files': source_files, 'source_digest': source_digest,
              'instrumented_files': instrumented_files,
              'instrumented_digest': instrumented_digest,
              'owner_readiness': readiness,
              'original_main_sha256': original_sha, 'harness_sha256': sha(harness),
              'instrumented_main_sha256': sha(main_rs), 'argv': argv,
              'elf_sha256': sha(executable), 'executable': executable.name,
              'counting_allocator': not args.instructions, 'timing_prohibited': True,
              'terminal_cache_retirement': retirement,
              'daemon_sha256': sha(daemon_source)}
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
