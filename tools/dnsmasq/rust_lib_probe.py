#!/usr/bin/env python3
"""Bind copied, feature-off opt3 lib-test probes; never build or run a probe."""
import hashlib
import json
from pathlib import Path
import re
import struct

ORACLE_HOME = Path('/home/ubuntu')
SHARED_TARGET = ORACLE_HOME / 'dnsmasq-cargo-target'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_files(source):
    files = {}
    components = source / 'components'
    if components.is_symlink():
        raise ValueError('probe source components must not be symlinks')
    for part in ('dnsmasq', 'ubus'):
        root = components / part
        if root.is_symlink() or not root.is_dir():
            raise ValueError('probe source component must be an actual directory: ' + part)
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(source)
            if 'target' in relative.parts:
                continue
            if path.is_symlink():
                raise ValueError('probe source symlink forbidden: ' + str(relative))
            if path.is_file():
                files[str(relative)] = digest(path)
    return files


def add_arguments(parser):
    parser.add_argument('--rust-test-binary', type=Path, help='copied oracle_build.sh probe-tests lib-dnsmasq_rs')
    parser.add_argument('--rust-source-root', type=Path, help='explicit immutable source of the copied probe')
    parser.add_argument('--rust-build-receipt', type=Path, help='probe-tests build.json; source-before sibling required')
    parser.add_argument('--rust-cargo-target-dir', type=Path,
                        help='explicit absolute cache path expected in the copied probe receipt; default: ' + str(SHARED_TARGET))
    parser.add_argument('--local-native', action='store_true', help='explicit legacy local cargo mode; rejected on Oracle')


def local_only(root, output, source, cargo):
    paths = (Path(root), Path(output), Path(source), Path(cargo), Path.cwd(), Path.home())
    if SHARED_TARGET.exists() or any(path.resolve().is_relative_to(ORACLE_HOME.resolve()) for path in paths):
        raise ValueError('legacy native build is forbidden on Oracle; use copied oracle_build.sh probe-tests')


def validate(binary, source, receipt, cargo_target_dir=SHARED_TARGET):
    cargo_target_dir = Path(cargo_target_dir)
    if not cargo_target_dir.is_absolute():
        raise ValueError('probe Cargo cache path must be absolute')
    binary, source, receipt = map(lambda path: Path(path).resolve(), (binary, source, receipt))
    if ('private' not in binary.parts or binary.is_relative_to(SHARED_TARGET.resolve())
            or binary.is_relative_to(cargo_target_dir.resolve())):
        raise ValueError('probe must be an immutable private copy, not shared Cargo output')
    build = json.loads(receipt.read_text())
    files = source_files(source)
    header = binary.read_bytes()[:64]
    if len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', header, 18)[0] != 183:
        raise ValueError('copied probe requires ELF64 little-endian AArch64, e_machine=183')
    elf_sha = digest(binary)
    before = receipt.parent / 'probe-source-before.json'
    if (not files or build.get('kind') != 'probe-tests' or build.get('source') != str(source)
            or build.get('opt_level') != '3' or build.get('features') != ''
            or build.get('cargo_target_dir') != str(cargo_target_dir) or build.get('diagnostic_only') is not True
            or build.get('source_files') != files
            or build.get('artifacts') != [{'path': 'lib-dnsmasq_rs', 'bytes': binary.stat().st_size, 'sha256': elf_sha}]
            or not re.fullmatch('[0-9a-f]{64}', str(build.get('source_before_sha256', '')))
            or digest(before) != build['source_before_sha256'] or json.loads(before.read_text()) != files):
        raise ValueError('expected source-bound locked shared-target feature-off opt3 probe-tests build')
    return {'mode': 'copied-release-lib-test', 'diagnostic_only': True, 'source_root': str(source),
            'source_files': files, 'test_binary': str(binary), 'test_binary_sha256': elf_sha,
            'test_binary_bytes': binary.stat().st_size, 'build_receipt': str(receipt),
            'build_receipt_sha256': digest(receipt), 'source_before_sha256': digest(before),
            'verifier_sha256': digest(Path(__file__)),
            'build_kind': build['kind'], 'opt_level': build['opt_level'], 'features': build['features'],
            'cargo_target_dir': build['cargo_target_dir']}


def selection(args, root, output):
    supplied = (args.rust_test_binary, args.rust_source_root, args.rust_build_receipt)
    if args.rust_test_binary or args.rust_build_receipt:
        if not all(supplied) or args.local_native:
            raise ValueError('copied probe requires test-binary/source-root/build-receipt together, without local-native')
        binding = validate(*supplied, args.rust_cargo_target_dir or SHARED_TARGET)
        return Path(binding['test_binary']), Path(binding['source_root']), binding
    if not args.local_native:
        raise ValueError('choose copied probe inputs or explicit local-native; no implicit cargo build')
    if args.rust_cargo_target_dir:
        raise ValueError('rust-cargo-target-dir binds a copied probe, not a local-native build')
    source = (args.rust_source_root or Path(root)).resolve()
    local_only(root, output, source, args.cargo)
    return None, source, {'mode': 'local-native-legacy', 'diagnostic_only': True,
                          'verifier_sha256': digest(Path(__file__)),
                          'source_root': str(source), 'source_files': source_files(source)}


def recheck(binding):
    if binding['mode'] == 'copied-release-lib-test':
        current = validate(binding['test_binary'], binding['source_root'], binding['build_receipt'],
                           binding['cargo_target_dir'])
        if current != binding:
            raise ValueError('frozen probe/source/build identity changed during comparison')
    elif source_files(Path(binding['source_root'])) != binding['source_files']:
        raise ValueError('local-native source changed during comparison')


def argv(binary, test):
    return [str(Path(binary).resolve()), test, '--ignored', '--exact', '--nocapture', '--test-threads=1']


def records(stdout, test, prefixes):
    # Serial libtest may place its status prefix on the first uncaptured line.
    # Remove only this exact harness wrapper; oracle payload bytes stay intact.
    header = 'test ' + test + ' ... '
    lines = [line.removeprefix(header) for line in stdout.splitlines()]
    return [line for line in lines if line.startswith(prefixes)]


def require_one_test(stdout, test):
    if ('running 1 test' not in stdout.splitlines()
            or not re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured;', stdout, re.MULTILINE)):
        raise ValueError('expected exactly one executed ignored libtest ' + test + '; zero-test matches are invalid')
