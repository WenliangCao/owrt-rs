#!/usr/bin/env python3
"""Local, fail-closed binding gate for isolated v0.2.2 device execution.

This module never contacts a host. A separately issued root release binds the
complete qualification file; passing tests alone never enables device work.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from safe_v022_device_plan import BUNDLE_SHA256, K_SHA256, verify_bundle


REQUIRED_CHECKS = ('native', 'correctness', 'shipping', 'source_corpora',
                   'no_proc', 'startup_tools', 'pressure_tools')
SOURCE_ONLY = {'native', 'source_corpora'}
REQUIRED_FILES = (
    'research_cpu_clock_probe', 'm6a_loadgen', 'm6a_upstream',
    'm6a_upstream_mixed_cohort', 'device_perf_guard', 'device_perf_netns',
    'device_perf_lifecycle', 'device_perf_resource_probe', 'nice10',
    'safe_v022_full_case.sh', 'safe_v022_public_case.sh', 'safe_v022_dual_case.sh',
    'safe_v022_group.sh', 'device_selfexec_lifecycle',
    'safe_v022_startup_group.sh', 'safe_v022_startup_case.sh',
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hex_value(value, length, name):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value),
            'invalid ' + name)
    return value


def checked_file(row, base, name):
    require(isinstance(row, dict), name + ': file declaration required')
    path = Path(row['local'])
    if not path.is_absolute():
        path = base / path
    require(not path.is_symlink(), name + ': local symlink is not allowed')
    path = path.resolve()
    require(path.is_file(), name + ': regular local file required')
    require(type(row['bytes']) is int and row['bytes'] >= 0, name + ': invalid file length')
    hex_value(row['sha256'], 64, name + ' sha256')
    require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], name + ': file identity differs')
    return {**row, 'local': str(path)}


def load_qualification(path, bundle, plan):
    """Validate all immutable inputs and the separate explicit execution release.

Receipts are preserved files. Their normalized conclusions are deliberate
review decisions in this binding, not inferred by counting arbitrary JSON
success strings. The issuer must resolve original differences before marking
a check qualified. The release binds every normalized decision and receipt.
"""
    path, bundle, plan = Path(path).resolve(), Path(bundle).resolve(), Path(plan).resolve()
    value = json.loads(path.read_text())
    require(value.get('schema') == 1 and value.get('status') == 'qualified', 'qualification is not complete')
    require(value.get('plan_sha256') == sha(plan), 'plan binding differs')
    require(value.get('prefix') == json.loads(plan.read_text())['prefix'], 'prefix binding differs')
    require(value.get('bundle_manifest_sha256') == BUNDLE_SHA256, 'bundle binding differs')
    recovered = verify_bundle(bundle)
    for key, filename in (('driver_sha256', 'safe_v022_device_run.py'),
                          ('startup_runner_sha256', 'safe_v022_startup_run.py')):
        require(value.get(key) == sha(Path(__file__).with_name(filename)), 'host code binding differs: ' + key)
    source = value['source']
    hex_value(source['commit'], 40, 'source commit')
    hex_value(source['inputs_digest'], 64, 'source inputs digest')
    require(set(value['artifacts']) == {'k', 'candidate'}, 'exact K/candidate artifact roles required')
    artifacts = {}
    for role, entry in value['artifacts'].items():
        require(entry.get('name') == 'artifact-' + role, 'immutable artifact name differs')
        artifacts[role] = checked_file(entry, path.parent, role)
    require(artifacts['k']['sha256'] == K_SHA256, 'baseline is not exact accepted K')
    candidate = artifacts['candidate']
    require(candidate['sha256'] != K_SHA256, 'candidate must be independently built')
    require(candidate['bytes'] <= 2_500_000, 'candidate ELF exceeds budget')
    package = checked_file(value['package'], path.parent, 'package')
    require(package['bytes'] <= 1_400_000, 'candidate package exceeds budget')
    pgo = value['pgo']
    require(pgo.get('status') == 'qualified', 'fresh PGO has not qualified')
    require(pgo.get('source_commit') == source['commit'] and
            pgo.get('source_inputs_digest') == source['inputs_digest'], 'PGO source binding differs')
    require(pgo.get('elf_sha256') == candidate['sha256'] and
            pgo.get('apk_sha256') == package['sha256'], 'PGO output binding differs')
    require(pgo.get('profile_mismatch_warnings') == 0 and pgo.get('compiler_warnings') == 0,
            'PGO warning gate failed')
    checked_file(pgo['profile'], path.parent, 'PGO profile')
    checked_file(pgo['receipt'], path.parent, 'PGO receipt')
    require(set(REQUIRED_CHECKS) <= set(value['checks']), 'required qualification checks are missing')
    for name in REQUIRED_CHECKS:
        check = value['checks'][name]
        require(check.get('status') == 'qualified' and
                check.get('source_commit') == source['commit'] and
                check.get('source_inputs_digest') == source['inputs_digest'], name + ': source qualification differs')
        if name not in SOURCE_ONLY:
            require(check.get('elf_sha256') == candidate['sha256'], name + ': final PGO ELF qualification differs')
        checked_file(check['receipt'], path.parent, name + ' receipt')
    correctness = value['checks']['correctness']
    require(correctness.get('families') == 44 and correctness.get('jobs') == 67 and
            correctness.get('unresolved_differences') == 0 and
            correctness.get('original_results_retained') is True, 'original correctness matrix is incomplete')
    require(value['checks']['no_proc'].get('negative_control_verified') is True and
            value['checks']['no_proc'].get('helper_and_runtime_lookup') is True,
            'no-proc helper/runtime lookup positive and negative controls required')
    startup = value['startup_boundary']
    require(startup.get('helper_proc') == 'absent' and startup.get('resolver_proc') == 'present' and
            startup.get('nofile_soft') == 1024 and startup.get('nofile_hard') == 4096,
            'startup boundary differs from the frozen comparison')
    checked_file(startup['production_limits_receipt'], path.parent, 'production NOFILE receipt')
    checked_file(startup['k_no_proc_lookup_negative'], path.parent, 'K no-proc lookup negative control')
    require(set(REQUIRED_FILES) <= set(value['files']), 'required device files are missing')
    files = {}
    historical = json.loads((bundle / 'manifest.json').read_text())['support_binaries']
    for name, entry in value['files'].items():
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]*', name) is not None,
                'unsafe remote filename')
        require(name not in {'artifact-k', 'artifact-candidate', 'dnsmasq-c', 'dnsmasq-rust'},
                'tool shadows an artifact or working slot')
        files[name] = checked_file(entry, path.parent, name)
        if name in historical:
            require(entry['sha256'] == historical[name]['expected_historical_artifact']['sha256'],
                    name + ': original support binary identity differs')
        if 'runtime/' + name in recovered:
            require(entry['sha256'] == recovered['runtime/' + name], name + ': reconstructed runtime identity differs')
    # New fixture identities are tied to their independent rehearsal receipts.
    check = value['checks']['startup_tools']
    require(isinstance(check.get('tool_sha256'), dict) and check['tool_sha256'], 'startup tool identities required')
    for tool, expected in check['tool_sha256'].items():
        require(tool in files and files[tool]['sha256'] == expected, 'qualified startup tool identity differs')
    # Pressure runs on Oracle. Its Python files must never be staged to router
    # merely to satisfy a provenance check.
    check = value['checks']['pressure_tools']
    require(isinstance(check.get('local_tools'), dict) and check['local_tools'], 'Oracle pressure tool identities required')
    for name, entry in check['local_tools'].items():
        checked_file(entry, path.parent, 'Oracle pressure tool ' + name)
    for group, limits in value.get('fd_growth_limits', {}).items():
        require(re.fullmatch(r'[a-z0-9-]+', group) is not None, 'unsafe FD limit group')
        require(set(limits) == {'tree_fd_peak', 'parent_fd_peak'} and
                all(type(v) is int and 0 <= v <= 16 for v in limits.values()), 'invalid declared FD growth budget')
    release_path = Path(value['release_file'])
    if not release_path.is_absolute():
        release_path = path.parent / release_path
    release = json.loads(release_path.read_text())
    require(release.get('execution_authorized') is True and
            release.get('scope') == 'isolated device performance only', 'root has not released device execution')
    require(release.get('qualification_sha256') == sha(path) and
            release.get('plan_sha256') == sha(plan) and
            release.get('source_commit') == source['commit'] and
            release.get('elf_sha256') == candidate['sha256'], 'execution release identity differs')
    require(bool(release.get('root_instruction')), 'explicit root instruction reference required')
    return {**value, 'artifacts': artifacts, 'package': package, 'files': files,
            'qualification_sha256': sha(path), 'release_sha256': sha(release_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args()
    value = load_qualification(args.qualification, args.bundle, args.plan)
    print(json.dumps({'qualified': True, 'qualification_sha256': value['qualification_sha256'],
                      'candidate_sha256': value['artifacts']['candidate']['sha256']}))


if __name__ == '__main__':
    main()
