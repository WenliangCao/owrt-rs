#!/usr/bin/env python3
"""Build the existing state probe against the complete frozen crate.

Only the probe's obsolete module imports and the old tool's Rust build invocation
are adapted. The C probe, nineteen inputs and comparison code are unchanged.
This native GNU helper is separate from the immutable SDK daemon artifact.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference-build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve()
    original_probe = source / 'components/dnsmasq/src/config/state_probe.rs'
    original_tool = source / 'tools/dnsmasq/contract_inventory.py'
    probe_text = original_probe.read_text()
    old_imports = '#[path = "mod.rs"]\nmod config;\n#[path = "../hosts.rs"]\nmod hosts;'
    new_imports = 'use dnsmasq_rs::{config, hosts};'
    assert probe_text.count(old_imports) == 1
    adapted_probe = probe_text.replace(old_imports, new_imports)
    assert adapted_probe.split(new_imports, 1)[1] == probe_text.split(old_imports, 1)[1]
    project = args.out / 'cargo-probe'
    (project / 'src').mkdir(parents=True)
    (project / 'src/main.rs').write_text(adapted_probe)
    manifest = ('[package]\nname = "dnsmasq-config-state"\nversion = "0.0.0"\n'
                'edition = "2021"\n[workspace]\n[dependencies]\n'
                'dnsmasq-rs = { path = ' + json.dumps(str(source / 'components/dnsmasq'))
                + ', default-features = false }\n')
    (project / 'Cargo.toml').write_text(manifest)
    environment = dict(os.environ, RUSTUP_HOME='/home/ubuntu/.rustup', CARGO_HOME='/home/ubuntu/.cargo',
                       CARGO_TARGET_DIR=str(args.out / 'cargo-target'))
    for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                 'CARGO_BUILD_TARGET', 'RUSTUP_TOOLCHAIN'):
        environment.pop(name, None)
    cargo = '/home/ubuntu/.cargo/bin/cargo'
    rustc = '/home/ubuntu/.cargo/bin/rustc'
    command = [cargo, '+1.98.1', 'build', '--offline', '--manifest-path', str(project / 'Cargo.toml'),
               '--target', 'aarch64-unknown-linux-gnu', '--message-format=json']
    with (args.out / 'cargo-build.stdout').open('wb') as out, (args.out / 'cargo-build.stderr').open('wb') as err:
        subprocess.run(command, env=environment, cwd=source, stdout=out, stderr=err, check=True)
    binary = args.out / 'cargo-target/aarch64-unknown-linux-gnu/debug/dnsmasq-config-state'
    assert binary.is_file()
    # A private copy preserves the original C compilation, corpus, fixture writes
    # and assertions verbatim. Its two substitutions are recorded in a diff.
    tool_text = original_tool.read_text()
    old_root = 'ROOT = Path(__file__).resolve().parents[2]'
    old_compile = "subprocess.run([rustc,'--edition=2021','-A','dead_code','-A','unused_imports',str(ROOT/'components/dnsmasq/src/config/state_probe.rs'),'-o',str(work/'rust-state')],check=True)"
    assert tool_text.count(old_root) == tool_text.count(old_compile) == 1
    adapted_tool = tool_text.replace(old_root, 'ROOT = Path(' + repr(str(source)) + ')')
    adapted_tool = adapted_tool.replace(old_compile, 'shutil.copy2(' + repr(str(binary)) + ",work/'rust-state')")
    private_tool = args.out / 'contract_inventory-adapted.py'
    private_tool.write_text(adapted_tool)
    (args.out / 'probe-imports.diff').write_text(''.join(difflib.unified_diff(
        probe_text.splitlines(True), adapted_probe.splitlines(True), fromfile=str(original_probe), tofile=str(project / 'src/main.rs'))))
    (args.out / 'tool-adapter.diff').write_text(''.join(difflib.unified_diff(
        tool_text.splitlines(True), adapted_tool.splitlines(True), fromfile=str(original_tool), tofile=str(private_tool))))
    versions = {name: subprocess.check_output([str(path), '+1.98.1', '-Vv'], env=environment, text=True).strip()
                for name, path in (('cargo', cargo), ('rustc', rustc))}
    invocation = [os.sys.executable, str(private_tool), '--state-differential',
                  '--reference-build', str(args.reference_build), '--work', str(args.out)]
    receipt = {'source': str(source), 'target': 'aarch64-unknown-linux-gnu', 'profile': 'dev', 'features': '',
        'scope': 'native configuration-only probes; not SDK daemon or performance artifacts',
        'cargo_argv': command, 'state_argv': invocation, 'versions': versions,
        'original_probe_sha256': sha(original_probe), 'adapted_probe_sha256': sha(project / 'src/main.rs'),
        'original_tool_sha256': sha(original_tool), 'adapted_tool_sha256': sha(private_tool),
        'cargo_manifest_sha256': sha(project / 'Cargo.toml'), 'cargo_lock_sha256': sha(project / 'Cargo.lock'),
        'cargo_probe_sha256': sha(binary), 'probe_imports_only': True, 'C_corpus_and_comparison_unchanged': True}
    (args.out / 'adapter-identity.json').write_text(json.dumps(receipt, indent=2) + '\n')
    subprocess.run(invocation, env=environment, cwd=source, check=True)
    assert sha(args.out / 'rust-state') == receipt['cargo_probe_sha256']


if __name__ == '__main__':
    main()
