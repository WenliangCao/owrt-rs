#!/usr/bin/env python3
"""Build profile-use only after the frozen training receipt validates its profile."""
import hashlib
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(plan, mode, argv, env):
    if mode != 'use' or plan['allowed_modes'] != ['use']:
        raise ValueError('this frozen training plan permits only profile-use')
    build = Path(plan['build_slot'])
    manifest = str(build / 'dnsmasq/Cargo.toml')
    clean = ['clean', '--manifest-path', manifest, '-p', 'dnsmasq-rs',
             '--release', '--target', 'aarch64-unknown-linux-musl']
    compile_args = ['build', '--release', '--frozen', '--manifest-path', manifest,
                    '--bin', 'dnsmasq-rs', '--target-dir', str(build / 'dnsmasq/target')]
    if argv == ['--version'] or argv == clean:
        return None
    if argv != compile_args:
        raise ValueError('unexpected Cargo command; preserve the exact SDK recipe invocation')
    expected = {
        'RUSTUP_TOOLCHAIN': '1.98.1',
        'CARGO_HOME': '/home/ubuntu/.cargo',
        'RUSTUP_HOME': '/home/ubuntu/.rustup',
        'CARGO_BUILD_TARGET': 'aarch64-unknown-linux-musl',
        'CARGO_PROFILE_RELEASE_PANIC': 'abort',
        'DNSMASQ_STATIC_PIE_CC': plan['map_cc'],
        'PERF_SDK_CC': plan['sdk_cc'],
        'PERF_LINK_MAP': str(Path(plan['outputs'][mode]) / 'link.map'),
        'RUSTFLAGS': plan['recipe_rustflags'],
    }
    for key, value in expected.items():
        if env.get(key) != value:
            raise ValueError('unexpected recipe environment: ' + key)
    blocked = {'CARGO_ENCODED_RUSTFLAGS', 'RUSTC', 'RUSTC_WRAPPER',
               'RUSTC_WORKSPACE_WRAPPER', 'LLVM_PROFILE_FILE', 'CARGO_TARGET_DIR'}
    for key, value in env.items():
        if value and (key in blocked or
                      key.startswith('CARGO_PROFILE_') and key != 'CARGO_PROFILE_RELEASE_PANIC'):
            raise ValueError('unexpected compiler/profile override: ' + key)
    linker = env.get('CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER', '')
    if not Path(linker).is_absolute() or sha(linker) != plan['static_pie_linker_sha256']:
        raise ValueError('static PIE linker identity differs')
    profile = json.loads(Path(plan['profile_receipt']).read_text())
    merged = Path(plan['merged_profile'])
    if not merged.is_absolute() or 'private' not in merged.parts or any(c.isspace() for c in str(merged)):
        raise ValueError('absolute private merged profile path required')
    if profile['status'] != 'training-complete' or profile['merged_profile']['path'] != str(merged):
        raise ValueError('completed matching training profile required')
    if profile['generate_elf_sha256'] != plan['generate_elf']['sha256']:
        raise ValueError('training used a different generate artifact')
    if sha(merged) != profile['merged_profile']['sha256']:
        raise ValueError('merged training profile identity differs')
    extra = '-Cprofile-use=' + str(merged) + ' -Cllvm-args=-pgo-warn-missing-function'
    return {
        'mode': mode, 'argv': argv, 'recipe_rustflags': env['RUSTFLAGS'],
        'added_rustflags': extra,
        'effective_rustflags': env['RUSTFLAGS'] + (' ' + extra if extra else ''),
        'recipe_environment': expected, 'static_pie_linker': linker,
        'static_pie_linker_sha256': sha(linker),
        'profile': profile,
    }


def main():
    plan_path = Path(os.environ['PGO_SMOKE_PLAN'])
    plan = json.loads(plan_path.read_text())
    if sha(__file__) != plan['wrapper_sha256']:
        raise ValueError('Cargo wrapper identity differs from the frozen plan')
    mode = os.environ['PGO_SMOKE_MODE']
    argv = sys.argv[1:]
    receipt = prepare(plan, mode, argv, os.environ)
    if receipt is not None and mode == 'use':
        if receipt['profile']['plan_sha256'] != sha(plan_path):
            raise ValueError('training and use plans differ')
    cargo = plan['cargo']
    if not Path(cargo).is_absolute() or not Path(plan['rustc']).is_absolute():
        raise ValueError('absolute Cargo and pinned rustc paths required')
    if receipt is not None:
        receipt.update(scope=plan['scope'],
                       plan_sha256=sha(plan_path), wrapper_sha256=sha(__file__),
                       cargo_sha256=sha(cargo), rustc_sha256=sha(plan['rustc']),
                       rustc_environment=plan['rustc'])
        # One recipe build invocation per fresh output. Never replace evidence.
        with Path(plan['invocation_receipts'][mode]).open('x') as stream:
            json.dump(receipt, stream, indent=2)
            stream.write('\n')
        os.environ['RUSTFLAGS'] = receipt['effective_rustflags']
    # Cargo clean also probes rustc. Pin discovery independently of SSH PATH
    # and rustup installation layout, without changing any codegen option.
    os.environ['RUSTC'] = plan['rustc']
    os.execv(cargo, [cargo, *argv])


if __name__ == '__main__':
    main()
