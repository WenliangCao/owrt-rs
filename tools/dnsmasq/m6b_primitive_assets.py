#!/usr/bin/env python3
"""Explicit, build-free Rust primitive assets for the shared Oracle builder.

prepare exports a named commit to ignored source, adds four static examples and
two private-module driver bridges. validate never generates or compiles Rust.
Matching-source native C primitive observations are not image-daemon evidence.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ABI = {
    'm6b-cache-core': 'cache-core-ascii-v1',
    'm6b-cache-policy': 'cache-policy-operation-counters-wire-v1',
    'm6b-cache-edns': 'cache-edns-frozen-clock-opt-wire-v1',
    'm6b-cache-lease': 'cache-lease-publication-ascii-v1',
}
TARGET = '/home/ubuntu/dnsmasq-cargo-target'
DRIVERS = ('cache_policy_transaction_diff.py', 'cache_edns_diff.py',
           'lease_cache_probe.rs', 'dns_cache_diff.py')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_base_archive(receipt, source_receipt):
    archive = Path(source_receipt).parent / 'base-source.tar'
    if archive.is_symlink() or digest(archive) != receipt.get('base_source_archive_sha256'):
        raise ValueError('frozen base source archive changed')
    files = {}
    with tarfile.open(archive) as stream:
        if stream.pax_headers.get('comment') != receipt['source_commit']:
            raise ValueError('base source archive commit differs')
        for member in stream:
            path = Path(member.name)
            parts = path.parts
            component = (len(parts) > 2 and parts[:2] in
                         [('components', 'dnsmasq'), ('components', 'ubus')]
                         and 'target' not in parts)
            root_input = ((len(parts) > 1 and parts[0] == '.cargo')
                          or member.name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'])
            if (not component and not root_input) or member.isdir():
                continue
            if path.is_absolute() or '..' in parts or not member.isfile() or member.name in files:
                raise ValueError('invalid frozen base compile input: ' + member.name)
            files[member.name] = hashlib.sha256(stream.extractfile(member).read()).hexdigest()
    if files != receipt.get('base_compile_inputs'):
        raise ValueError('base source archive compilation inputs differ')


def source_files(root):
    root = Path(root)
    names = []
    for component in ['dnsmasq', 'ubus']:
        prefix = root / 'components' / component
        if not prefix.is_dir(): raise ValueError('complete component export required: ' + component)
        names += [path for path in sorted(prefix.rglob('*')) if 'target' not in path.relative_to(root).parts]
    if (root / '.cargo').is_dir(): names += sorted((root / '.cargo').rglob('*'))
    for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']:
        if (root / name).is_file(): names.append(root / name)
    for example in ABI:
        path = root / 'components/dnsmasq/examples' / (example + '.rs')
        if path.exists(): names.append(path)
    result = {}
    for path in names:
        if path.is_symlink(): raise ValueError('primitive input symlink is not allowed: ' + str(path))
        if path.is_file(): result[str(path.relative_to(root))] = digest(path)
    return result


def add_arguments(parser):
    parser.add_argument('--rust-binary', type=Path)
    parser.add_argument('--rust-source-root', type=Path)
    parser.add_argument('--rust-source-receipt', type=Path)
    parser.add_argument('--rust-build-receipt', '--rust-build-json', dest='rust_build_receipt', type=Path)
    parser.add_argument('--local-native', action='store_true',
                        help='explicit historical desktop-only build; never an Oracle acceptance path')


def validate(args, probe_name):
    return validate_binary(args.rust_binary, args.rust_source_root, args.rust_source_receipt,
                           args.rust_build_receipt, probe_name)


def validate_binary(binary, source_root, source_receipt, build_receipt, probe_name):
    if probe_name not in ABI or any(value is None for value in [binary, source_root, source_receipt, build_receipt]):
        raise ValueError('explicit binary/source-root/source-receipt/build-receipt and static probe name required')
    binary, root, source_receipt, build_receipt = [Path(value).resolve()
                                                for value in [binary, source_root, source_receipt, build_receipt]]
    receipt = json.loads(source_receipt.read_text())
    build = json.loads(build_receipt.read_text())
    if (receipt.get('schema') != 1 or receipt.get('kind') != 'm6b-primitive-probe-source'
            or not re.fullmatch('[0-9a-f]{40}', receipt.get('source_commit', ''))
            or set(receipt.get('examples', {})) != set(ABI)):
        raise ValueError('complete frozen primitive source receipt required')
    if receipt.get('generator_sha256') != digest(Path(__file__)):
        raise ValueError('primitive asset generator changed')
    validate_base_archive(receipt, source_receipt)
    if set(receipt.get('driver_inputs', {})) != set(DRIVERS):
        raise ValueError('complete frozen primitive driver inputs required')
    for name, expected in receipt['driver_inputs'].items():
        if digest(HERE / name) != expected:
            raise ValueError('frozen primitive fixture/driver changed: ' + name)
    actual = source_files(root)
    if actual != receipt['generated_compile_inputs'] or actual != build.get('source_files'):
        raise ValueError('primitive source/build input SHA differs')
    before = build_receipt.parent / 'probe-source-before.json'
    if digest(before) != build.get('source_before_sha256') or json.loads(before.read_text()) != actual:
        raise ValueError('locked pre-build source witness differs')
    if (build.get('kind') != 'primitive-probes' or Path(build['source']).resolve() != root
            or build.get('cargo_target_dir') != TARGET or str(build.get('opt_level')) != '3'
            or build.get('features') != ''):
        raise ValueError('locked shared-target feature-off opt3 primitive build required')
    for name, abi in ABI.items():
        example = receipt['examples'][name]
        expected = 'components/dnsmasq/examples/' + name + '.rs'
        if example.get('path') != expected or example.get('abi') != abi or digest(root / expected) != example['sha256']:
            raise ValueError('primitive example/command ABI differs: ' + name)
    artifacts = build['artifacts']
    if len(artifacts) != len(ABI) or {row.get('path') for row in artifacts} != set(ABI):
        raise ValueError('complete static primitive artifact set required')
    for row in artifacts:
        path = build_receipt.parent / row['path']
        if path.is_symlink() or digest(path) != row['sha256'] or path.stat().st_size != row['bytes']:
            raise ValueError('primitive artifact changed: ' + row['path'])
    rows = [row for row in artifacts if row.get('path') == probe_name]
    if len(rows) != 1 or rows[0]['sha256'] != digest(binary) or rows[0]['bytes'] != binary.stat().st_size:
        raise ValueError('primitive ELF artifact differs')
    header = binary.read_bytes()[:64]
    if len(header) != 64 or header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', header, 18)[0] != 183:
        raise ValueError('Oracle primitive must be ELF64 little-endian AArch64')
    return {'source_commit': receipt['source_commit'], 'source_root': str(root),
            'prepared_source_root': receipt['source_root'], 'binary_sha256': rows[0]['sha256'],
            'binary_bytes': rows[0]['bytes'], 'source_receipt_sha256': digest(source_receipt),
            'build_receipt_sha256': digest(build_receipt), 'example': probe_name, 'abi': ABI[probe_name],
            'elf_abi': {'class': 64, 'endianness': 'little', 'machine': 183},
            'scope': 'actual Rust crate / matching-source native C primitive, not image daemon'}


def local_native_allowed(args):
    locations = [HERE.parents[1], Path(args.out if hasattr(args, 'out') else args.output)]
    if args.rust_source_root is not None: locations.append(args.rust_source_root)
    if (not args.local_native or Path(TARGET).exists()
            or any(str(Path(path).resolve()).startswith('/home/ubuntu/') for path in locations)):
        raise ValueError('provide frozen Rust primitive assets; direct local-native builds are forbidden on Oracle')


def unchanged_binary(binary, binding):
    if digest(binary) != binding['binary_sha256']:
        raise ValueError('frozen primitive ELF changed during execution')


def copy_binary(binary, destination, binding):
    destination = Path(destination)
    if destination.exists(): raise ValueError('fresh primitive binary copy required')
    unchanged_binary(binary, binding)
    shutil.copy2(binary, destination)
    unchanged_binary(destination, binding)
    return destination


def rust_driver(path):
    tree = ast.parse(path.read_text())
    rows = [ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'RUST_DRIVER'
                                                   for target in node.targets)]
    if len(rows) != 1 or not isinstance(rows[0], str): raise ValueError('one literal RUST_DRIVER required: ' + str(path))
    return rows[0]


def prepare(args):
    repository, out = args.repository.resolve(), args.out.resolve()
    commit = args.source_commit
    if not re.fullmatch('[0-9a-f]{40}', commit) or out.exists() or not out.is_relative_to(repository / 'private'):
        raise ValueError('full commit and fresh ignored private output required')
    if subprocess.check_output(['git', 'rev-parse', commit + '^{commit}'], cwd=repository, text=True).strip() != commit:
        raise ValueError('source commit identity differs')
    out.mkdir(parents=True); archive = out / 'base-source.tar'
    with archive.open('wb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', commit], cwd=repository, stdout=stream, check=True)
    source = out / 'source'; source.mkdir()
    with tarfile.open(archive) as stream:
        if stream.pax_headers.get('comment') != commit: raise ValueError('archive commit differs')
        stream.extractall(source, filter='data')
    base = source_files(source)
    if any('components/dnsmasq/examples/' + name + '.rs' in base for name in ABI):
        raise ValueError('base already contains these generated examples')
    drivers = {name: digest(HERE / name) for name in DRIVERS}
    policy = rust_driver(HERE / DRIVERS[0])
    old = 'pub fn cache_edns_probe_main()'
    if policy.count(old) != 1 or policy.count('question_name:question.name,') != 1 or policy.count('UncheckedReply{packet,truncated:') != 1:
        raise ValueError('policy bridge API anchors changed')
    policy = policy.replace(old, 'pub fn m6b_cache_policy_main()')
    policy = policy.replace('question_name:question.name,', 'question_name:question.name.clone(),')
    policy = policy.replace('UncheckedReply{packet,truncated:', 'UncheckedReply{packet,upstream_name:question.name,truncated:')
    edns = rust_driver(HERE / DRIVERS[1])
    context = 'negative_ttl:daemon.negative_ttl}'
    if edns.count(old) != 1 or edns.count(context) != 1:
        raise ValueError('EDNS bridge API anchors changed')
    edns = edns.replace(old, 'pub fn m6b_cache_edns_main()').replace('cache_edns_probe_insert', 'm6b_cache_edns_insert')
    edns = edns.replace(context, 'negative_ttl:daemon.negative_ttl,filter_rr:&daemon.filter_rr}')
    daemon = source / 'components/dnsmasq/src/dns/daemon.rs'
    before = daemon.read_text()
    if 'pub upstream_name: Name,' not in (source / 'components/dnsmasq/src/dns/upstream.rs').read_text():
        raise ValueError('frozen UncheckedReply API differs')
    if "pub filter_rr: &'a [u16]," not in (source / 'components/dnsmasq/src/dns/cache_engine.rs').read_text():
        raise ValueError('frozen CacheContext API differs')
    daemon.write_text(before + '\n' + policy + '\n' + edns)
    spec = importlib.util.spec_from_file_location('m6b_core_export', HERE / 'dns_cache_diff.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    if not hasattr(module, 'primitive_rust_source'):
        raise ValueError('core adapter primitive_rust_source is required; no shim fallback')
    generated = {'m6b-cache-core': module.primitive_rust_source(),
                 'm6b-cache-policy': 'fn main() { dnsmasq_rs::dns::daemon::m6b_cache_policy_main(); }\n',
                 'm6b-cache-edns': 'fn main() { dnsmasq_rs::dns::daemon::m6b_cache_edns_main(); }\n',
                 'm6b-cache-lease': (HERE / 'lease_cache_probe.rs').read_text()}
    examples = {}; directory = source / 'components/dnsmasq/examples'; directory.mkdir(exist_ok=True)
    for name, code in generated.items():
        path = directory / (name + '.rs'); path.write_text(code)
        examples[name] = {'path': str(path.relative_to(source)), 'sha256': digest(path), 'abi': ABI[name]}
    receipt = {'schema': 1, 'kind': 'm6b-primitive-probe-source', 'status': 'prepared-not-built-not-run',
               'source_commit': commit, 'source_root': str(source), 'base_source_archive_sha256': digest(archive),
               'base_compile_inputs': base, 'generated_compile_inputs': source_files(source),
               'examples': examples, 'driver_inputs': drivers, 'generator_sha256': digest(Path(__file__)),
               'narrow_api_adaptations': ['distinct daemon entrypoints', 'UncheckedReply upstream_name', 'CacheContext filter_rr'],
               'product_source_modified': False, 'image_daemon_qualification': False}
    (out / 'source-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'source_root': str(source), 'receipt': str(out / 'source-receipt.json'), 'built': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--out', type=Path, required=True)
    prepare(parser.parse_args())


if __name__ == '__main__': main()
