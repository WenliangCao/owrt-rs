#!/usr/bin/env python3
"""Prepare a source-bound, ignored TCP A diagnostic companion; never build/run.

The generated copy adds System-forwarding allocation meters, bounded scalar
owner rows and source-bound root version hooks. Product files are untouched.
`bind` records a separately built companion after the exclusive window ends.
Neither action grants functional, CPU, performance or product PSS qualification.
"""
import argparse
import difflib
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATES = ['m6b_resource_meter.rs', 'm6b_resource_roots.rs', 'm6b_resource_main.rs']
CONTROL_ASSETS = ['tools/dnsmasq/oracle_build.sh', 'docs/dnsmasq/M6B_PROTOCOL.md',
                  'docs/dnsmasq/M6B_TCP_MEMORY_DESIGN.md', 'rust-toolchain.toml']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def files(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if any(part in ['private', 'target', '__pycache__', '.git'] for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            raise ValueError('source symlink requires an explicit export policy: ' + str(path))
        if path.is_file():
            result[str(path.relative_to(root))] = sha(path)
    return result


def compilation_files(root):
    """Bin/lib inputs, independent of unrelated repository docs/examples/fuzz."""
    result = {}
    for component in ['dnsmasq', 'ubus']:
        crate = root / 'components' / component
        if not (crate / 'Cargo.toml').is_file() or not (crate / 'src').is_dir():
            raise ValueError('complete product crate required: ' + component)
        for name in ['Cargo.toml', 'Cargo.lock', 'build.rs']:
            path = crate / name
            if path.is_file(): result[str(path.relative_to(root))] = sha(path)
        for name in ['src', '.cargo']:
            directory = crate / name
            if directory.is_dir():
                result.update({str(directory.relative_to(root) / Path(name)): digest
                               for name, digest in files(directory).items()})
    for name in ['Cargo.toml', 'Cargo.lock']:
        path = root / name
        if path.is_file(): result[name] = sha(path)
    if (root / '.cargo').is_dir():
        result.update({'.cargo/' + name: digest for name, digest in files(root / '.cargo').items()})
    return result


def normalized_flags(record):
    normalized = record.get('rustflags', '').replace(record['source'], 'FROZEN_SOURCE')
    return re.sub(r'-Clink-arg=-Wl,-Map(?:=|,)\S+', '-Clink-arg=-Wl,-Map=LINK_MAP', normalized)


def prepare(args):
    repository = args.repository.resolve()
    commit = args.source_commit
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('explicit full source commit required')
    actual = subprocess.check_output(['git', 'rev-parse', commit + '^{commit}'], cwd=repository, text=True).strip()
    if actual != commit or not re.fullmatch('[0-9a-f]{64}', args.product_sha256):
        raise ValueError('source/product identity malformed')
    out = args.out.resolve()
    if not out.is_relative_to(repository / 'private') or out.exists():
        raise ValueError('fresh ignored output under repository/private required')
    out.mkdir(parents=True)
    archive = out / 'product-source.tar'
    with archive.open('wb') as stream:
        subprocess.run(['git', 'archive', '--format=tar', commit], cwd=repository, stdout=stream, check=True)
    source = out / 'source'; source.mkdir()
    with tarfile.open(archive) as stream:
        if stream.pax_headers.get('comment') != commit:
            raise ValueError('Git archive identity differs')
        stream.extractall(source, filter='data')
    original = files(source)
    compilation = compilation_files(source)
    originals = {name: (source / name).read_text() for name in original if name.endswith('.rs')}
    if any('#[global_allocator]' in value for name, value in originals.items() if name in compilation):
        raise ValueError('product already declares a global allocator')
    edits = {}; anchors = []

    def replace(name, label, before, after, count=1):
        path = source / 'components/dnsmasq/src' / name
        value = edits.get(str(path), path.read_text())
        seen = value.count(before)
        if seen != count:
            raise ValueError(f'{name}:{label}: expected {count} anchors, got {seen}')
        edits[str(path)] = value.replace(before, after)
        anchors.append({'file': name, 'label': label, 'expected': count, 'observed': seen})

    replace('lib.rs', 'allocator-module', 'pub mod listeners;',
            'pub mod listeners;\npub mod m6b_resource_diag;')
    replace('main.rs', 'global-System-meter', 'use dnsmasq_rs::config::dhcp::DhcpConfig;',
            '#[global_allocator]\nstatic M6B_RESOURCE_ALLOC: dnsmasq_rs::m6b_resource_diag::Meter = dnsmasq_rs::m6b_resource_diag::Meter;\n'
            'use dnsmasq_rs::config::dhcp::DhcpConfig;')
    replace('main.rs', 'trace-init', '    while !STOP_REQUESTED.load(Ordering::Acquire) {',
            '    dnsmasq_rs::m6b_resource_diag::init()?;\n    while !STOP_REQUESTED.load(Ordering::Acquire) {')
    replace('main.rs', 'owner-after-step', '        poll.step()?;',
            '        poll.step()?;\n        poll.m6b_resource_sample()?;')
    replace('main.rs', 'normal-sampler-timer',
            '            let timeout = owner_poll_timeout(deadline, Instant::now(), runnable);',
            '            deadline = dnsmasq_rs::m6b_resource_diag::deadline(deadline);\n'
            '            let timeout = owner_poll_timeout(deadline, Instant::now(), runnable);')
    # Deliberately do not clamp the nested DHCP probe wait: it cannot sample
    # until the outer step returns, so a due diagnostic timer there would spin.
    replace('dns/cache.rs', 'new-content-root', 'Arc::new(ContentBlock {', 'm6b_root_new(0, ContentBlock {')
    replace('dns/cache.rs', 'new-index-roots', 'Arc::new(NameIndex::new())', 'm6b_root_new(1, NameIndex::new())', 2)
    replace('dns/cache.rs', 'content-detach', 'Arc::make_mut(&mut self.content[', 'm6b_root_mut(0, &mut self.content[', 2)
    replace('dns/cache.rs', 'index-detach', 'Arc::make_mut(&mut self.names[', 'm6b_root_mut(1, &mut self.names[', 2)
    replace('dns/daemon.rs', 'parent-before-snapshot', '        self.cache.as_ref().map(Cache::snapshot)',
            '        self.cache.as_ref().map(|cache| { cache.m6b_mark_parent_roots(); cache.snapshot() })')
    replace('dns/daemon.rs', 'parent-cache-observer', '    pub fn pending_count(&self) -> usize {',
            '    pub fn m6b_observe_parent_cache(&self) {\n'
            '        if let Some(cache) = &self.cache { cache.m6b_observe_roots(true); }\n'
            '    }\n    pub fn pending_count(&self) -> usize {')
    replace('dns/service.rs', 'framer-capacity', 'impl TcpFramer {',
            'impl TcpFramer {\n    pub fn m6b_capacity(&self) -> usize { self.bytes.capacity() }')
    replace('dns/tcp_exchange.rs', 'exchange-capacity', 'impl Exchange {',
            'impl Exchange {\n    pub(super) fn m6b_bytes(&self) -> usize { self.frame.capacity() + self.reply.capacity() }')
    replace('dns/tcp_upstream.rs', 'upstream-capacity', 'impl TcpUpstream {',
            'impl TcpUpstream {\n    pub fn m6b_bytes(&self) -> usize { self.pending.as_ref().map_or(0, |exchange| exchange.m6b_bytes()) }')
    replace('dns/tcp_service.rs', 'TCP-pending-capacity', 'impl TcpDnsService {',
            'impl TcpDnsService {\n    pub fn m6b_pending(&self) -> bool { self.pending_query.is_some() }\n'
            '    pub fn m6b_bytes(&self) -> usize { self.pending_query.as_ref().map_or(0, Vec::capacity) + self.upstream.m6b_bytes() }')
    replace('logging.rs', 'accepted-log-capacity', 'impl Logger {',
            'impl TcpLogContext {\n    pub fn m6b_capacities(&self) -> (usize, usize) {\n'
            '        (self.queue.iter().map(|record| record.bytes.capacity()).sum(),\n'
            '         self.queue.capacity() * std::mem::size_of::<Record>())\n'
            '    }\n}\nimpl Logger {')
    for path, value in edits.items():
        Path(path).write_text(value)
    (source / 'components/dnsmasq/src/m6b_resource_diag.rs').write_bytes((HERE / TEMPLATES[0]).read_bytes())
    for name, template in [('dns/cache.rs', TEMPLATES[1]), ('main.rs', TEMPLATES[2])]:
        path = source / 'components/dnsmasq/src' / name
        path.write_text(path.read_text() + '\n' + (HERE / template).read_text())
    modified = files(source)
    changed = sorted(name for name in modified if original.get(name) != modified[name])
    diff = []
    for name in changed:
        before = originals.get(name, '').splitlines(keepends=True)
        after = (source / name).read_text().splitlines(keepends=True)
        diff.extend(difflib.unified_diff(before, after, 'a/' + name, 'b/' + name))
    patch = out / 'diagnostic.patch'; patch.write_text(''.join(diff))
    receipt = {'schema': 1, 'status': 'prepared-not-built-not-validated', 'source_commit': commit,
               'source_root': str(source), 'product_elf_sha256': args.product_sha256,
               'product_source_archive_sha256': sha(archive), 'original_source_files': original,
               'original_compilation_files': compilation,
               'control_assets': {name: original[name] for name in CONTROL_ASSETS if name in original},
               'diagnostic_source_files': modified, 'changed_files': changed, 'anchors': anchors,
               'patch_sha256': sha(patch), 'generator_sha256': sha(Path(__file__)),
               'templates': {name: sha(HERE / name) for name in TEMPLATES},
               'diagnostic_elf': None, 'product_functional_qualification': False,
               'cpu_or_product_pss_qualification': False, 'balance_qualification': 'unproven',
               'extra_regular_trace_fd': 1, 'sample_hz': 1, 'drain_seconds': [0, 1, 5, 15, 60],
               'physical_router': False}
    save(out / 'receipt.json', receipt)
    print(json.dumps({'status': receipt['status'], 'receipt': str(out / 'receipt.json'), 'changed_files': changed}))


def bind(args):
    receipt = json.loads(args.receipt.read_text())
    source = (args.diagnostic_source_root or Path(receipt['source_root'])).resolve()
    if files(source) != receipt['diagnostic_source_files']:
        raise ValueError('diagnostic source changed after generation')
    if sha(args.product_elf) != receipt['product_elf_sha256']:
        raise ValueError('product ELF binding differs')
    product_build = json.loads(args.product_build_json.read_text())
    if (product_build.get('kind') != 'release'
            or compilation_files(Path(product_build['source'])) != receipt['original_compilation_files']
            or not any(row.get('sha256') == receipt['product_elf_sha256']
                       and row.get('bytes') == args.product_elf.stat().st_size
                       for row in product_build.get('artifacts', []))):
        raise ValueError('product build does not bind this same frozen compilation inputs/ELF')
    for name, expected in receipt['control_assets'].items():
        if sha(source / name) != expected:
            raise ValueError('frozen tool/protocol asset changed: ' + name)
        exported = Path(product_build['source']) / name
        if exported.is_file() and sha(exported) != expected:
            raise ValueError('product export tool/protocol asset differs: ' + name)
    diagnostic_sha = sha(args.diagnostic_elf)
    if diagnostic_sha == receipt['product_elf_sha256']:
        raise ValueError('diagnostic ELF must be distinct from product')
    build = json.loads(args.build_json.read_text())
    if (build.get('source') != str(source) or build.get('kind') != 'release'
            or build.get('cargo_target_dir') != '/home/ubuntu/dnsmasq-cargo-target'
            or not any(row.get('sha256') == diagnostic_sha and row.get('bytes') == args.diagnostic_elf.stat().st_size
                       for row in build.get('artifacts', []))):
        raise ValueError('diagnostic build must bind exact source/ELF and shared-target oracle_build.sh')
    for key in ['opt_level', 'features', 'cargo_target_dir']:
        if build.get(key) != product_build.get(key):
            raise ValueError('diagnostic/product build settings differ: ' + key)
    if normalized_flags(build) != normalized_flags(product_build):
        raise ValueError('diagnostic/product rustflags differ beyond source/map paths')
    for path, record in [(args.build_json, build), (args.product_build_json, product_build)]:
        mapping = record.get('link_map')
        if not mapping or sha(path.parent / mapping['path']) != mapping['sha256']:
            raise ValueError('both fresh builds need their verified link map')
    result = {**receipt, 'status': 'built-not-validated', 'preparation_source_root': receipt['source_root'],
              'source_root': str(source),
              'diagnostic_elf': {'path': str(args.diagnostic_elf), 'sha256': diagnostic_sha,
                                 'bytes': args.diagnostic_elf.stat().st_size},
              'build_json_sha256': sha(args.build_json), 'product_build_json_sha256': sha(args.product_build_json)}
    if args.out.exists():
        raise ValueError('fresh bound receipt required; preparation receipt stays unchanged')
    save(args.out, result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--repository', type=Path, required=True)
    prep.add_argument('--source-commit', required=True)
    prep.add_argument('--product-sha256', required=True)
    prep.add_argument('--out', type=Path, required=True)
    identity = sub.add_parser('bind')
    identity.add_argument('--diagnostic-source-root', type=Path,
                          help='explicit relocation; every source SHA must still match preparation')
    for name in ['receipt', 'build-json', 'product-build-json', 'product-elf', 'diagnostic-elf', 'out']:
        identity.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    return prepare(args) if args.action == 'prepare' else bind(args)


if __name__ == '__main__':
    main()
