#!/usr/bin/env python3
"""Local verification of final source identities and retained SDK build receipts.

Does not access Oracle, run a build, or claim a fresh hash of remote artifacts.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[6]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(value, label):
    if not value:
        raise ValueError(label)


def git_hashes(revision, names):
    query = ''.join(revision + ':' + name + '\n' for name in names).encode()
    result = subprocess.run(['git', 'cat-file', '--batch'], input=query, cwd=ROOT,
                            check=True, capture_output=True)
    stream, hashes = io.BytesIO(result.stdout), {}
    for name in names:
        header = stream.readline().split()
        need(len(header) == 3 and header[1] == b'blob', 'Git input is not a blob: ' + name)
        data = stream.read(int(header[2]))
        need(stream.read(1) == b'\n', 'Git batch framing')
        hashes[name] = hashlib.sha256(data).hexdigest()
    need(not stream.read(), 'unexpected Git batch output')
    return hashes


def check(summary, identity, directory):
    expected = identity['source_files']
    need(len(expected) == identity['source_input_count'] == summary['source_input_count'] == 178, '178 source inputs')
    roots = ['rust-toolchain.toml', 'manifests/release-25.12.5.json', 'packaging/openwrt/owrt-dnsmasq',
             'tools/dnsmasq/build_package.sh', 'tools/dnsmasq/build_package.py', 'components/dnsmasq/Cargo.lock']
    roots += [f'components/{component}/{suffix}' for component in ('dnsmasq', 'ubus') for suffix in ('Cargo.toml', 'src')]
    files = [path for name in roots for path in ([ROOT / name] if (ROOT / name).is_file() else (ROOT / name).rglob('*'))
             if path.is_file()]
    need(all(not path.is_symlink() for path in files), 'plain source input files')
    worktree = {str(path.relative_to(ROOT)): sha(path) for path in files}
    need(worktree == expected, 'current worktree input inventory/hashes match freeze')
    commit = identity['source_commit']
    need(git_hashes(commit, list(expected)) == expected, 'frozen commit blobs match all inputs')
    need(git_hashes('HEAD', list(expected)) == expected, 'current Git blobs match all inputs')
    digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    need(digest == identity['source_digest'] == summary['source_digest'], 'recomputed source digest')
    need(sha(directory / 'final-identity.json') == summary['source_identity']['sha256'], 'identity receipt hash')
    epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', commit], cwd=ROOT, text=True).strip()
    need(epoch == identity['source_date_epoch'] == summary['controller']['source_date_epoch'], 'source date epoch')
    controller = summary['controller']
    need(controller['passed'] and controller['source_commit'] == summary['source_commit'] == commit, 'controller source identity')
    need(controller['source_digest'] == digest and controller['identity_sha256'] == summary['source_identity']['sha256'],
         'controller freezes identical inputs')
    drivers = {
        directory / 'freeze_source.py': identity['freeze_driver_sha256'],
        directory / 'collect_build.py': summary['collector']['sha256'],
        ROOT / 'docs/dnsmasq/audits/20261012/fix3_repairs/build/build_phase.py': controller['controller_sha256'],
        ROOT / 'docs/dnsmasq/audits/20261012/fix3_repairs/build/sdk_source_build.py': controller['sdk_driver_sha256'],
    }
    need(all(sha(path) == expected_hash for path, expected_hash in drivers.items()), 'retained build-driver identities')
    commands = {row['name']: row for row in controller['commands']}
    need(len(commands) == 6 and set(commands) == {'release-build', 'tests-build', 'lib-dnsmasq_rs',
         'bin-dnsmasq-rs', 'sdk-acquire', 'sdk-verify'}, 'complete build sequence')
    unit_totals = {key: sum(commands[name]['counts'][key] for name in ('lib-dnsmasq_rs', 'bin-dnsmasq-rs'))
                   for key in ('passed', 'failed', 'ignored', 'measured', 'filtered_out')}
    need(unit_totals == controller['ordinary_units'] == summary['summary']['ordinary_units']
         == {'passed': 854, 'failed': 0, 'ignored': 23, 'measured': 0, 'filtered_out': 0}, '854 units, 23 ignored')
    for artifact in summary['tests']['artifacts']:
        need(commands[artifact['path']]['elf_sha256'] == artifact['sha256'], 'executed unit ELF identity')
    need(all(commands[name]['returncode'] == 0 for name in ('release-build', 'tests-build', 'lib-dnsmasq_rs', 'bin-dnsmasq-rs')),
         'release and unit commands succeeded')
    builds = summary['sdk']
    need(len(builds) == summary['summary']['sdk_source_builds'] == 2, 'two SDK source builds')
    budget_path = ROOT / 'tools/dnsmasq/m5_final_budget.json'
    budget = json.loads(budget_path.read_text())
    for label, build in zip(('sdk-acquire', 'sdk-verify'), builds):
        need(build['build_mode'] == 'compile-and-package' and build['frozen_elf'] is False, 'source compile, no frozen ELF')
        need(build['source_commit'] == commit and build['source_digest'] == build['expected_source_digest'] == digest,
             'SDK uses final source revision/digest')
        need(build['source_input_count'] == 178 and build['sdk_input_count'] == 106, 'SDK input inventories')
        need(build['stages'] == {'prepare': {'exit_code': 0}, 'compile': {'exit_code': 0}}, 'SDK prepare and compile succeeded')
        need([row[:2] for row in build['commands']] == [['make', 'package/owrt-dnsmasq/prepare'],
             ['make', 'package/owrt-dnsmasq/compile']], 'actual prepare/compile commands recorded')
        need(not any('FROZEN_ELF' in value for row in build['commands'] for value in row), 'no frozen ELF command override')
        need(all(build[key] for key in ('source_build_passed', 'source_inputs_unchanged', 'sdk_inputs_unchanged',
             'sdk_recipe_restored', 'sdk_strip_payload_identity_verified')), 'SDK completion and identity controls')
        need(build['budget'] == {key: budget[key] for key in ('schema', 'elf_max_bytes', 'apk_max_bytes')}
             | {'sha256': sha(budget_path)}, 'original size budget unchanged')
        need(build['failure_boundary'] == 'size-target' and not build.get('error'), 'failure only at size target')
        for artifact, limit in (('elf', 'elf_max_bytes'), ('artifact', 'apk_max_bytes')):
            need(build[artifact]['size'] > budget[limit], 'reported artifact exceeds original budget')
        need(build['budget_checks'] == {'apk': False, 'elf': False} and commands[label]['returncode'] == 1,
             'size failure remains nonzero, not a source compilation failure')
        need(commands[label]['manifest_sha256'] == build['manifest']['sha256'], 'manifest receipt crosscheck')
        need(build['driver_sha256'] == controller['sdk_driver_sha256'], 'SDK driver identity')
        need(build['physical_router'] is False and build['activation'] == 'unvalidated-package', 'no physical activation')
    need(builds[0]['acquire'] and builds[0]['expected_elf_sha256'] is None, 'first build acquired fresh candidate')
    need(not builds[1]['acquire'] and builds[1]['expected_elf_sha256'] == builds[0]['elf']['sha256'], 'second build verifies candidate')
    need(builds[1]['prior_build_tree_archived'] and builds[1]['artifact_identity_verified'] and builds[1]['apk_byte_identical'],
         'second clean source build identity verified')
    for key in ('elf', 'artifact'):
        need(all(builds[0][key][field] == builds[1][key][field] for field in ('sha256', 'size')), 'both SDK artifacts identical')
    need(builds[1]['link_map'] == controller['exact_sdk_link_map'], 'map bound to exact SDK ELF')
    need(summary['summary']['original_size_budget_passed'] is False and summary['summary']['deployed'] is False,
         'budget and deployment limitations retained')
    return {'source_input_count': len(expected), 'source_digest': digest, 'git_commit_and_HEAD_and_worktree_match': True,
            'unit_results': unit_totals, 'sdk_source_builds': 2, 'sdk_prepare_compile_records_passed': True,
            'frozen_elf': False, 'two_sdk_elf_apk_identities_match': True,
            'sdk_elf': {key: builds[0]['elf'][key] for key in ('sha256', 'size')},
            'sdk_apk': {key: builds[0]['artifact'][key] for key in ('sha256', 'size')},
            'original_budget_passed': False, 'failure_boundary': 'size-target', 'deployed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(not args.output.exists(), 'output must be fresh')
    paths = {name: args.directory / name for name in ('final-summary.json', 'final-identity.json')}
    receipt = {'schema': 1, 'script_sha256': sha(Path(__file__)),
               'input_sha256': {name: sha(path) for name, path in paths.items()},
               'scope': 'Independent local source/Git hashes and build-receipt consistency; no Oracle access, build rerun, or fresh remote ELF/APK/log hash'}
    try:
        receipt['checks'] = check(*(json.loads(paths[name].read_text()) for name in paths), args.directory)
        receipt['status'] = 'passed'
    except Exception as error:
        receipt.update(status='failed', error=repr(error))
        raise
    finally:
        args.output.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'output': str(args.output), 'status': receipt['status'], 'sha256': sha(args.output)}))
