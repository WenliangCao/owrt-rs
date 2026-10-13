#!/usr/bin/env python3
"""Acquire or verify an SDK source-built ELF at one frozen source/build path.

This never supplies OWRT_DNSMASQ_FROZEN_ELF. Size-budget failure remains a
nonzero result even when source compilation and the requested identity pass.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import sys
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'sdk', 'workspace', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--source-date-epoch', required=True)
    parser.add_argument('--expected-source-digest', required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--acquire', action='store_true')
    mode.add_argument('--expected-elf-sha256')
    args = parser.parse_args()
    source, sdk, workspace, out = (getattr(args, name).resolve()
                                  for name in ('source', 'sdk', 'workspace', 'out'))
    sys.path.insert(0, str(source / 'tools/dnsmasq'))
    import build_package as p

    for path in (source, sdk, workspace, out):
        p.safe_path(path)
    p.require(re.fullmatch(r'[0-9a-f]{40}', args.source_commit), 'full source commit required')
    p.require(args.source_date_epoch.isdigit(), 'source timestamp required')
    p.require(re.fullmatch(r'[0-9a-f]{64}', args.expected_source_digest), 'source digest required')
    p.require(args.acquire or re.fullmatch(r'[0-9a-f]{64}', args.expected_elf_sha256),
              'full expected ELF digest required')
    p.require('/private/' in str(out) and '/private/' in str(workspace), 'private paths required')
    p.require(not out.is_relative_to(workspace) and not workspace.is_relative_to(out),
              'fixed workspace and evidence output must be separate')
    out.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'status': 'building', 'build_mode': 'compile-and-package',
              'frozen_elf': False, 'physical_router': False, 'activation': 'unvalidated-package',
              'scope': 'SDK source build and identity only; runtime and deployment qualification are separate',
              'source_commit': args.source_commit, 'source_date_epoch': args.source_date_epoch,
              'expected_source_digest': args.expected_source_digest,
              'expected_elf_sha256': args.expected_elf_sha256, 'acquire': args.acquire,
              'fixed_workspace': str(workspace), 'argv': sys.argv,
              'driver_sha256': p.sha(Path(__file__).resolve()), 'commands': [], 'stages': {}}
    # Persist the requested identities before any SDK command runs.
    (out / 'plan.json').write_text(json.dumps(report, indent=2) + '\n')
    previous_signals = {}
    def interrupted(number, frame):
        raise InterruptedError(f'build interrupted by signal {number}')
    for number in (signal.SIGTERM, signal.SIGINT):
        previous_signals[number] = signal.signal(number, interrupted)
    try:
        with Path('/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock').open('a') as global_lock:
            fcntl.flock(global_lock, fcntl.LOCK_EX)
            source_files = p.inputs(source)
            digest = hashlib.sha256(json.dumps(source_files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            p.require(digest == args.expected_source_digest, 'source differs from frozen digest')
            report.update(source_files=source_files, source_digest=digest)
            budget_path = source / 'tools/dnsmasq/m5_final_budget.json'
            budget = p.read_budget(budget_path)
            p.require(budget['sha256'] == 'e63d182761eaa4b115bf67e7e16ce5afaa70a56de09992accef7c32d92280b43',
                      'the unchanged original size budget is required')
            shutil.copy2(budget_path, out / 'budget.json')
            p.require(p.sha(out / 'budget.json') == budget['sha256'], 'budget changed while copying')
            report['budget'] = budget
            archive_name, archive_sha = json.loads((source / 'manifests/release-25.12.5.json').read_text())['inputs']['sdk'].split(' sha256 ')
            p.require(sdk.name == archive_name.removesuffix('.tar.zst'), 'SDK name differs from pinned release')
            p.require(p.sha(sdk.parent / archive_name) == archive_sha, 'SDK archive differs from pinned release')
            sdk_files = p.sdk_inputs(sdk)
            report['sdk'] = {'path': str(sdk), 'archive_sha256': archive_sha, 'files': sdk_files}
            freeze = {'source_commit': args.source_commit, 'source_date_epoch': args.source_date_epoch,
                      'source_digest': digest, 'source_files': source_files,
                      'sdk_archive_sha256': archive_sha, 'sdk_files': sdk_files, 'budget': budget}
            copied, build = workspace / 'source', workspace / 'package-build'
            freeze_path, candidate_path = workspace / 'freeze.json', workspace / 'candidate.json'
            if workspace.exists():
                p.require(json.loads(freeze_path.read_text()) == freeze, 'workspace freeze changed')
                p.require(p.inputs(copied) == source_files, 'fixed source copy changed')
            else:
                p.require(args.acquire, 'verification requires a prior acquisition workspace')
                workspace.mkdir(parents=True)
                p.snapshot(source, copied, source_files)
                freeze_path.write_text(json.dumps(freeze, indent=2) + '\n')
            if args.acquire:
                p.require(not candidate_path.exists(), 'workspace already has a candidate; use identity verification')
            else:
                candidate = json.loads(candidate_path.read_text())
                p.require(candidate['elf']['sha256'] == args.expected_elf_sha256,
                          'expected digest differs from acquired candidate')
                p.require(p.sha(Path(candidate['elf']['path'])) == args.expected_elf_sha256,
                          'acquired candidate changed')
                p.require(p.sha(Path(candidate['artifact']['path'])) == candidate['artifact']['sha256'],
                          'acquired APK changed')
            report.update(fixed_source_path=str(copied), fixed_build_path=str(build))
            toolchain = sdk / f'staging_dir/toolchain-{p.ARCH}_gcc-14.3.0_musl'
            cargo = Path('/home/ubuntu/.cargo/bin/cargo')
            env = os.environ.copy()
            for name in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTC',
                         'RUSTFLAGS', 'CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR', 'CARGO_PROFILE_RELEASE_OPT_LEVEL'):
                env.pop(name, None)
            env.update(RUSTUP_TOOLCHAIN=tomllib.loads((copied / 'rust-toolchain.toml').read_text())['toolchain']['channel'],
                       SOURCE_DATE_EPOCH=args.source_date_epoch)
            for name, argv in [('cargo-version', [str(cargo), '--version']),
                               ('rustc-version', [str(cargo.with_name('rustc')), '-Vv']),
                               ('target-cc-version', [str(toolchain / 'bin/aarch64-openwrt-linux-musl-gcc'), '--version'])]:
                report[name] = p.run(argv, out / f'{name}.log', env=env).strip()
            output = out / 'sdk-output'
            make_vars = ['V=s', '-j1', 'V1_PACKAGE_RELEASE=3', f'OWRT_COMPONENTS_SOURCE={copied / "components"}',
                         f'OWRT_DNSMASQ_BUILD_DIR={build}', f'OWRT_DNSMASQ_OUTPUT_DIR={output}',
                         f'V1_CARGO={cargo}', 'V1_CARGO_HOME=/home/ubuntu/.cargo', 'V1_RUSTUP_HOME=/home/ubuntu/.rustup']
            with (sdk / '.owrt-dnsmasq-build.lock').open('a') as sdk_lock:
                fcntl.flock(sdk_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if build.exists():
                    archived = out / 'previous-build-tree'
                    shutil.move(str(build), archived)
                    report['prior_build_tree_archived'] = str(archived)
                with p.package_recipe(sdk, copied / 'packaging/openwrt/owrt-dnsmasq', out, report):
                    target = Path(report['sdk_recipe_path']).relative_to(sdk).as_posix()
                    for stage in ('prepare', 'compile'):
                        argv = ['make', f'{target}/{stage}', *make_vars]
                        report['commands'].append(argv)
                        p.run(argv, out / f'{stage}.log', cwd=sdk, env=env)
                        report['stages'][stage] = {'exit_code': 0}
                        if stage == 'prepare':
                            prepared = {name.removeprefix('components/'): sha for name, sha in source_files.items()
                                        if name.startswith('components/')}
                            for name, expected in prepared.items():
                                p.require(p.sha(build / name) == expected, f'SDK prepare changed source: {name}')
                            report['prepared_source_files'] = prepared
            artifact = output / f'packages/{p.ARCH}/base/dnsmasq-2.93-r3.apk'
            p.require(list(output.rglob('dnsmasq-*.apk')) == [artifact], 'unexpected APK inventory')
            saved_apk = out / artifact.name
            shutil.copy2(artifact, saved_apk)
            payload = out / 'payload'
            payload.mkdir()
            apk = sdk / 'staging_dir/host/bin/apk'
            p.run([str(apk), 'extract', '--allow-untrusted', '--no-network', '--no-chown',
                   '--destination', str(payload), str(saved_apk)], out / 'extract.log')
            report['payload_files'] = p.audit_payload(payload)
            elf = payload / 'usr/sbin/dnsmasq'
            readelf = p.run([str(toolchain / 'bin/aarch64-openwrt-linux-musl-readelf'), '-W', '-h', '-l', '-d', str(elf)],
                            out / 'elf-readelf.log', env=dict(os.environ, LC_ALL='C'))
            if hasattr(p, 'audit_elf'):
                report['elf_layout'] = p.audit_elf(elf.read_bytes(), readelf)
            else:
                data = elf.read_bytes()
                p.require(data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HH', data, 16) == (2, 183), 'main is not static AArch64 ET_EXEC')
                p.require('INTERP' not in readelf and '(NEEDED)' not in readelf, 'main static layout changed')
                report['elf_layout'] = {'type': 'ET_EXEC', 'machine': 'AArch64', 'interpreter': None, 'needed': []}
            metadata = p.run([str(apk), 'adbdump', str(saved_apk)], out / 'apk-metadata.log')
            report['apk_metadata'] = p.audit_metadata(metadata, '3')
            report['artifact'] = {'path': str(saved_apk), 'sha256': p.sha(saved_apk), 'size': saved_apk.stat().st_size}
            report['elf'] = {'path': str(elf), 'sha256': p.sha(elf), 'size': elf.stat().st_size}
            # The matching SDK autoremove deletes the Cargo target after packaging.
            # .pkgdir retains the installed pre-strip file; save it outside the mutable build tree.
            prestrip = out / 'dnsmasq-pre-strip'
            shutil.copy2(build / '.pkgdir/dnsmasq/usr/sbin/dnsmasq', prestrip)
            report['pre_sdk_strip_elf'] = {'path': str(prestrip), 'sha256': p.sha(prestrip), 'size': prestrip.stat().st_size}
            stripped = out / 'dnsmasq-sdk-sstrip'
            shutil.copy2(prestrip, stripped)
            strip_argv = [str(sdk / 'staging_dir/host/bin/sstrip'), '-z', str(stripped)]
            p.run(strip_argv, out / 'sstrip-check.log')
            p.require(p.sha(stripped) == p.sha(elf), 'SDK sstrip output differs from APK payload')
            report.update(postprocess_command=strip_argv, sdk_strip_payload_identity_verified=True)
            p.require(p.inputs(source) == source_files and p.inputs(copied) == source_files, 'source changed during build')
            p.require(p.sdk_inputs(sdk) == sdk_files, 'SDK inputs changed during build')
            report.update(source_build_passed=True, sdk_inputs_unchanged=True, source_inputs_unchanged=True)
            if not args.acquire:
                p.require(p.sha(elf) == args.expected_elf_sha256, 'rebuilt ELF differs from predeclared candidate SHA')
                p.require(p.sha(saved_apk) == candidate['artifact']['sha256'], 'rebuilt APK differs from acquired candidate')
                report.update(artifact_identity_verified=True, apk_byte_identical=True)
            p.require(p.sha(budget_path) == budget['sha256'], 'budget changed during build')
            # Keep the existing budget gate, including its rejected status.
            try:
                p.audit_sizes(report)
            except ValueError as error:
                p.require(report.get('failure_boundary') == 'size-target', 'unexpected budget exception')
                report['budget_error'] = str(error)
            if args.acquire:
                candidate_path.write_text(json.dumps({'source_commit': args.source_commit, 'source_digest': digest,
                    'elf': report['elf'], 'artifact': report['artifact'], 'qualification': 'runtime validation pending'}, indent=2) + '\n')
            suffix = 'candidate-acquired' if args.acquire else 'identity-verified'
            report['status'] = 'source-build-' + suffix + ('-budget-rejected' if report.get('budget_error') else '')
    except (OSError, ValueError, KeyError) as error:
        report['status'] = 'failed'
        report['error'] = str(error)
    finally:
        for number, handler in previous_signals.items():
            signal.signal(number, handler)
        (out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({name: report[name] for name in ('status', 'error', 'source_build_passed', 'artifact_identity_verified',
                      'elf', 'artifact', 'budget_checks', 'budget_error') if name in report}))
    return int(report['status'] == 'failed' or bool(report.get('budget_error')))


if __name__ == '__main__':
    raise SystemExit(main())
