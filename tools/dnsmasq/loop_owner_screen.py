#!/usr/bin/env python3
"""Prepare/build private actual-owner allocation instrumentation; never time it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cargo', default='/home/ubuntu/.cargo/bin/cargo')
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts
    out.mkdir(parents=True, exist_ok=False)
    copied = out / 'input/components'
    copied.mkdir(parents=True)
    for component in ('dnsmasq', 'ubus'):
        shutil.copytree(args.source / 'components' / component, copied / component,
                        ignore=shutil.ignore_patterns('target', 'fuzz'))
    main_rs = copied / 'dnsmasq/src/main.rs'
    original_sha = sha(main_rs)
    harness = Path(__file__).with_suffix('.rs')
    daemon_source = copied / 'dnsmasq/src/dns/daemon.rs'
    retirement = 'pub fn retire_cache_for_process_exit(' in daemon_source.read_text()
    harness_text = harness.read_text().replace('/* RETIRE_CACHE */',
        'daemon.retire_cache_for_process_exit();' if retirement else '')
    main_rs.write_text(main_rs.read_text() + '\n' + harness_text)
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
    argv = [args.cargo, '+1.98.1', 'test', '--frozen', '--jobs', '1',
            '--manifest-path', str(copied / 'dnsmasq/Cargo.toml'), '--bin', 'dnsmasq-rs',
            '--no-run', '--message-format=json']
    built = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (out / 'build.stdout').write_text(built.stdout)
    (out / 'build.stderr').write_text(built.stderr)
    if built.returncode:
        raise RuntimeError(built.stderr)
    artifacts = [json.loads(line) for line in built.stdout.splitlines()]
    binaries = [row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row.get('executable') and row.get('profile', {}).get('test')]
    assert len(binaries) == 1
    shutil.copy2(binaries[0], out / 'owner-allocation')
    report = {'original_main_sha256': original_sha, 'harness_sha256': sha(harness),
              'instrumented_main_sha256': sha(main_rs), 'argv': argv,
              'elf_sha256': sha(out / 'owner-allocation'), 'timing_prohibited': True,
              'terminal_cache_retirement': retirement,
              'daemon_sha256': sha(daemon_source)}
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
