#!/usr/bin/env python3
"""Assemble a new immutable idle/Renew bundle on Linux; never run subjects.

The source tree must be the archived benchmark files from TOOL_COMMIT. The
candidate path and SHA are explicit; the old full-profile candidate is unused.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess

TOOL_COMMIT = '3c0fdb7ceb4a8301d2b2ec14add2c73d1e308ef2'
C_SHA = '53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82'
HELPER_SHA = '683073d8dde7cf32a0e584b23ff966dcb8fb8ca33a174bc4768c66e60461d4b6'
SOURCE_HASHES = {
    'odhcpd_device_ab.sh': '37e4c6253efa465499dd115a0d0747bcf15668f4005d879b9a7455364e1f5152',
    'odhcpd_device_probe.c': '5e82583b033019e3ddb77925b08ddb1bd64d04ad76df8af6d9000bd96087b31c',
    'odhcpd_device_analyze.py': '6413d4a98a5a99f48c2fabec2d1012f8b619fadaa5737e4a0541c9b6a817ba3e',
    'test_odhcpd_device_analyze.py': '8debc1b2cd7d612174085888a4dc7716d7301b0a434fbdc33261d10c5b844922',
    'odhcpd_device_provider.uc': '61e82dda4ff61bc4f19ce12343c7556dfc57bf97398b4e35d2caca623fdf8290',
    'odhcpd_device_update.sh': '5f7901c68dc029eb9793bebee2cfafeb85d033c0a519c8fa0e585d631796597f',
    'odhcpd_device_lease_trigger.sh': '5cf87cba3396efba1b3e5fbb7a68dc0e10682aed693050cdb40228b6d25a6997',
    'ns_exec.c': '05eecba76e7e245a68cd7fd80f5474a0b5bcca7df58cc4c1d492354c5a8c25a3',
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_file(path, expected):
    if sha256(path) != expected:
        raise ValueError(f'identity mismatch: {path}')


def assemble(args):
    if platform.system() != 'Linux' or platform.machine() != 'aarch64':
        raise ValueError('assembly requires the Linux AArch64 host')
    if not re.fullmatch(r'[0-9a-f]{64}', args.candidate_sha):
        raise ValueError('candidate SHA256 must be 64 lowercase hex digits')
    source = args.source_tree / 'tools' / 'benchmark'
    for name, expected in SOURCE_HASHES.items():
        checked_file(source / name, expected)
    checked_file(args.candidate, args.candidate_sha)
    checked_file(args.reference, C_SHA)
    checked_file(args.ns_exec, HELPER_SHA)
    args.output.mkdir(mode=0o700)  # Refuse every existing output, including failures.
    bundle = args.output
    archived = bundle / 'sources'
    archived.mkdir()
    for name in SOURCE_HASHES:
        shutil.copyfile(source / name, archived / name)
    shutil.copyfile(Path(__file__), archived / Path(__file__).name)
    (bundle / 'source-commit.txt').write_text(TOOL_COMMIT + '\n')
    for origin, name in ((args.candidate, 'odhcpd-rs'), (args.reference, 'odhcpd-c'),
                         (args.ns_exec, 'ns-exec')):
        shutil.copyfile(origin, bundle / name)
        (bundle / name).chmod(0o755)
    for name in ('odhcpd_device_ab.sh', 'odhcpd_device_provider.uc',
                 'odhcpd_device_update.sh', 'odhcpd_device_analyze.py'):
        shutil.copyfile(archived / name, bundle / name)
        (bundle / name).chmod(0o755)
    shutil.copyfile(archived / 'odhcpd_device_lease_trigger.sh', bundle / 'lease-trigger')
    (bundle / 'lease-trigger').chmod(0o755)
    build = ['cc', '-O2', '-static', '-Wall', '-Wextra', '-Werror',
             '-o', str(bundle / 'odhcpd-probe'), str(archived / 'odhcpd_device_probe.c')]
    subprocess.run(build, check=True)
    compiler = subprocess.run(['cc', '--version'], check=True, capture_output=True, text=True).stdout
    (bundle / 'probe-build.json').write_text(json.dumps({
        'command': build, 'compiler': compiler, 'tool_source_commit': TOOL_COMMIT,
        'probe_sha256': sha256(bundle / 'odhcpd-probe'),
        'reused_helper_sha256': HELPER_SHA,
    }, indent=2) + '\n')
    contract = subprocess.run([
        'python3', '-B', str(bundle / 'odhcpd_device_analyze.py'), '--contract',
        '--profile', 'idle-renew', '--candidate-sha', args.candidate_sha,
    ], check=True, capture_output=True, text=True).stdout
    (bundle / 'analysis-contract.json').write_text(contract)
    (bundle / 'candidate.sha256').write_text(args.candidate_sha + '\n')
    (bundle / 'sources.sha256').write_text(''.join(
        f'{sha256(path)}  {path.relative_to(bundle)}\n' for path in sorted(archived.iterdir())))
    files = sorted(path for path in bundle.rglob('*') if path.is_file())
    (bundle / 'bundle.sha256').write_text(''.join(
        f'{sha256(path)}  {path.relative_to(bundle)}\n' for path in files))
    subprocess.run(['sha256sum', '-c', 'bundle.sha256'], cwd=bundle, check=True,
                   stdout=subprocess.DEVNULL)
    return {'bundle': str(bundle), 'candidate_sha256': args.candidate_sha,
            'probe_sha256': sha256(bundle / 'odhcpd-probe'),
            'helper_sha256': HELPER_SHA, 'reference_sha256': C_SHA,
            'tool_source_commit': TOOL_COMMIT, 'manifest_sha256': sha256(bundle / 'bundle.sha256')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-tree', 'candidate', 'reference', 'ns-exec', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--candidate-sha', required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args), indent=2))


if __name__ == '__main__':
    main()
