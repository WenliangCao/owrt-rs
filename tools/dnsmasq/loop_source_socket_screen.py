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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    copied = out / 'input/components'
    copied.mkdir(parents=True)
    for component in ('dnsmasq', 'ubus'):
        shutil.copytree(args.source / 'components' / component, copied / component,
                        ignore=shutil.ignore_patterns('target', 'fuzz'))
    examples = copied / 'dnsmasq/examples'
    examples.mkdir(exist_ok=True)
    harness = Path(__file__).with_suffix('.rs')
    shutil.copy2(harness, examples / 'loop-source-socket-screen.rs')
    environment = os.environ.copy()
    environment['CARGO_TARGET_DIR'] = str(args.target_dir.resolve())
    argv = ['/home/ubuntu/.cargo/bin/cargo', '+1.98.1', 'build', '--frozen', '--jobs', '1',
            '--manifest-path', str(copied / 'dnsmasq/Cargo.toml'),
            '--example', 'loop-source-socket-screen', '--message-format=json']
    result = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (out / 'build.stdout').write_text(result.stdout)
    (out / 'build.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr)
    artifacts = [json.loads(line) for line in result.stdout.splitlines()]
    binaries = [row['executable'] for row in artifacts if row.get('reason') == 'compiler-artifact'
                and row.get('executable') and row['target']['name'] == 'loop-source-socket-screen']
    assert len(binaries) == 1
    shutil.copy2(binaries[0], out / 'socket-factory')
    report = {'argv': argv, 'harness_sha256': sha(harness),
              'factory_sha256': sha(copied / 'dnsmasq/src/dns/source_sockets.rs'),
              'elf_sha256': sha(out / 'socket-factory'), 'timing_prohibited': True}
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
