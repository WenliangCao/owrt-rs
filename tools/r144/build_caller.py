#!/usr/bin/env python3
"""Build one private caller snapshot at the historical R135 source path."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess

CANONICAL = '/home/ubuntu/r135/repo'
RECIPE_SHA = '1fb454a9c3ce2e8973c160e1a1184679f693790f976fe2f2a2aa3f8ca08b4167'
NAMESPACE = r'''set -euo pipefail
source=$1 recipe=$2 out=$3 host_ns=$4
[[ $(id -u) == 0 && $(readlink /proc/self/ns/mnt) != "$host_ns" ]]
[[ $(findmnt --noheadings --output PROPAGATION /) == private ]]
mount --bind "$source" /home/ubuntu/r135/repo
trap 'umount /home/ubuntu/r135/repo' EXIT
cd /home/ubuntu
sudo -n -u ubuntu -- bash "$recipe"
sudo -n -u ubuntu -- python3 - "$out" <<'PY'
import json,os,sys
from pathlib import Path
out=Path(sys.argv[1])
fingerprints={str(p.relative_to(out)):json.loads(p.read_text()) for p in sorted(out.rglob('*.json')) if p.name in ('lib-owrt_ubus.json','bin-owrt-benchmark.json')}
(out/'namespace.json').write_text(json.dumps({'mount_namespace':os.readlink('/proc/self/ns/mnt'),'build_uid':os.geteuid(),'canonical_source_root':'/home/ubuntu/r135/repo','cargo_fingerprints':fingerprints},indent=2)+'\n')
PY
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--tests', action='store_true')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    assert pwd.getpwuid(os.geteuid()).pw_name == 'ubuntu'
    assert not output.exists() and source != Path(CANONICAL)
    assert source not in output.parents and not any(c.isspace() for c in str(output))
    sources = tree(source)
    assert len(sources) == 18 and 'components/ubus/src/conn.rs' in sources
    root = Path(__file__).resolve().parents[2]
    original = root / 'tools/r135/build_benchmark.sh'
    assert sha(original) == RECIPE_SHA
    recipe = original.read_text()
    old = 'out=/home/ubuntu/r135/benchmark-01'
    assert recipe.count(old) == 1
    recipe = recipe.replace(old, f'out={output}/artifacts')
    if args.tests:
        recipe += '''
# Separate test ELF; same target and RUSTFLAGS, with caller release profile.
CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_LTO=true CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 CARGO_PROFILE_RELEASE_STRIP=true \\
cargo test --release --locked --manifest-path "$src/components/ubus/Cargo.toml" \\
    --target aarch64-unknown-linux-musl --target-dir "$out/unit-target" -- --test-threads=1 \\
    > "$out/tests.log" 2>&1
'''
    output.mkdir(parents=True, exist_ok=False)
    (output / 'recipe.sh').write_text(recipe)
    (output / 'namespace.sh').write_text(NAMESPACE)
    compiler = subprocess.check_output(['/home/ubuntu/.rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin/rustc', '-vV'], text=True)
    assert 'release: 1.98.1' in compiler and 'LLVM version: 22.1.8' in compiler
    expected_flags = ['--remap-path-prefix=' + CANONICAL + '=/build', '-Clink-arg=-fuse-ld=bfd',
                      '-Clink-arg=-Wl,-z,max-page-size=4096', '-Clink-arg=-Wl,-z,now',
                      '-Clink-arg=-Wl,-z,relro', '-Clink-arg=-Wl,-z,pack-relative-relocs']
    write(output / 'plan.json', {'schema': 1, 'source_root': str(source), 'source_sha256': sources,
          'canonical_source_root': CANONICAL, 'original_recipe_sha256': RECIPE_SHA,
          'recipe_sha256': sha(output / 'recipe.sh'), 'namespace_script_sha256': sha(output / 'namespace.sh'),
          'builder_sha256': sha(Path(__file__)), 'expected_sha256': args.expected_sha256,
          'tests': args.tests, 'expected_rustflags': expected_flags, 'rustc_verbose': compiler})
    command = ['sudo', '-n', 'unshare', '--mount', '--pid', '--fork', '--kill-child', '--propagation', 'private',
               'bash', str(output / 'namespace.sh'), str(source), str(output / 'recipe.sh'),
               str(output / 'artifacts'), os.readlink('/proc/self/ns/mnt')]
    write(output / 'command.json', command)
    with (output / 'build.log').open('x') as log:
        code = subprocess.run(command, cwd='/home/ubuntu', stdout=log, stderr=subprocess.STDOUT).returncode
    record = {'schema': 1, 'passed': False, 'exit': code, 'plan_sha256': sha(output / 'plan.json'),
              'source_unchanged': tree(source) == sources, 'log_sha256': sha(output / 'build.log')}
    if code == 0:
        binary = output / 'artifacts/owrt-benchmark'
        ns = json.loads((output / 'artifacts/namespace.json').read_text())
        flags_ok = bool(ns['cargo_fingerprints']) and all(x['rustflags'] == expected_flags for x in ns['cargo_fingerprints'].values())
        record.update({'sha256': sha(binary), 'size': binary.stat().st_size, 'namespace': ns,
                       'effective_flags_match': flags_ok, 'tests_log_sha256': sha(output / 'artifacts/tests.log') if args.tests else None})
        record['passed'] = record['source_unchanged'] and flags_ok and (args.expected_sha256 is None or record['sha256'] == args.expected_sha256)
        shutil.copy2(binary, output / 'owrt-benchmark')
    write(output / 'result.json', record)
    print(json.dumps({k: v for k, v in record.items() if k != 'namespace'}), flush=True)
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
