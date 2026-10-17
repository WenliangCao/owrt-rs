#!/usr/bin/env python3
"""Prepare and replay final M5 checks against one immutable product ELF.

Preparation only hashes inputs and writes commands. Each run uses fresh outputs;
failed attempts remain intact. Package size rejection retains its audited APK
for isolated lifecycle testing and never becomes a user size exception.

Fuzz runs three independent instrumented targets concurrently for at least
1800 real seconds each, totaling at least 90 target-minutes. These are M5
robustness checks; explicit M6b functional mode excludes new fuzz windows.
Formal M6 performance is outside this controller.
"""
from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import fcntl
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time

import build_package
from dns_udp_refusal_diff import TARGET_FILES, verify_reference
from m2_rootfs import STOCK_SHA256
from m4_package_lifecycle import M5_BASELINE

TARGET = Path('/home/ubuntu/dnsmasq-cargo-target')
PHASES = ['families', 'm2', 'fuzz-build', 'fuzz', 'resources', 'pressure', 'package', 'lifecycle']
M6B_PHASES = ['families', 'm2', 'perf-guard', 'resources', 'pressure', 'package', 'lifecycle']
DNS = ['udp-cache', 'expiry', 'tcp', 'failure-recovery', 'strict-order', 'all-servers', 'representative-mix']
FUZZ = ['dns_wire', 'dhcp_packet', 'config_line']
FUZZ_SECONDS = 1800


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def atomic_save(path, value):
    temporary = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    save(temporary, value); os.replace(temporary, path)


def digest(path):
    return build_package.sha(Path(path))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cargo_target(spec):
    target = Path(spec.get('cargo_target_dir', TARGET))
    require(target.is_absolute(), 'cargo_target_dir must be an absolute cache path')
    return target


def required_phases(spec):
    """The milestone selects a fixed qualification chain, never a caller subset."""
    mode = spec.get('validation_mode', 'm5')
    require(mode in ('m5', 'm6b'), 'validation_mode must be m5 or m6b')
    phases = M6B_PHASES if mode == 'm6b' else PHASES
    require(spec.get('phases', phases) == phases, 'manifest phases differ from fixed validation mode')
    return list(phases)


def validate_qualification_build(mode, build):
    # opt-s is a performance comparison group, never the M6b functional ELF.
    # M5's original build policy is unchanged.
    if mode == 'm6b':
        require(build.get('features') == '', 'M6b final qualification requires a feature-off product build')
        require(build.get('opt_level') == '3', 'M6b final qualification requires opt-level 3')


def bind_guard(spec, path, expected_sha):
    """Bind the measured guard after 135 windows, without changing identity.json."""
    require(spec.get('validation_mode') == 'm6b', 'late guard binding is only for M6b')
    path = Path(path).resolve()
    require(re.fullmatch('[0-9a-f]{64}', expected_sha or '')
            and digest(path) == expected_sha, 'explicit guard plan SHA differs')
    require(not spec.get('perf_guard_plan') or Path(spec['perf_guard_plan']).resolve() == path,
            'cannot replace the guard in the original freeze')
    from m6b_perf_guard import inputs as guard_inputs
    tools = Path(spec.get('tools_root', spec['source_root'] + '/tools/dnsmasq'))
    _, _, assets = guard_inputs(path, tools)
    return {'path': str(path), 'sha256': expected_sha, 'assets': assets}


def verify_guard_binding(spec, binding):
    require(binding == bind_guard(spec, binding['path'], binding['sha256']),
            'guard assets differ from the phase freeze')


def prepare_schedule(spec, out):
    return {phase: (commands(spec, phase, out / 'runs' / phase / 'attempt-1')
                    if phase != 'perf-guard' or spec.get('perf_guard_plan') else
                    {'status': 'pending-measured-plan', 'required': True})
            for phase in required_phases(spec)}


def package_inputs(mode, spec):
    release = '3' if mode == 'm6b' else '2'
    require(spec.get('package_release', release) == release, 'milestone package release differs')
    if mode != 'm6b':
        require(not spec.get('previous_package'), 'M5 keeps the original stock lifecycle scope')
        return release, None
    previous = spec.get('previous_package', {})
    require({key: previous.get(key) for key in M5_BASELINE} == M5_BASELINE,
            'M6b requires the accepted M5 r2 package/ELF/source identity')
    path = Path(previous.get('path', '')).resolve()
    require(path.is_file() and digest(path) == M5_BASELINE['apk_sha256'], 'accepted M5 APK bytes differ')
    return release, dict(M5_BASELINE, path=str(path))


def phase_prerequisites(spec, phase):
    phases = required_phases(spec)
    require(phase in phases or phase == 'full-cache-600', 'phase is excluded-not-required in this validation mode')
    if phase in ('package', 'lifecycle'):
        return phases[:phases.index(phase)]
    if phase == 'fuzz':
        return ['fuzz-build']
    if phase == 'full-cache-600':
        return ['resources']
    return []


def completion_status(spec, completed):
    phases = required_phases(spec)
    excluded = {phase: {'status': 'excluded-not-required', 'passed': None,
                        'reason': 'M6b final functional scope does not require new M5 fuzz build/90 target-minute windows'}
                for phase in PHASES if phase not in phases}
    return {'required_phases': phases, 'excluded_phases': excluded,
            'missing_phases': [phase for phase in phases if completed.get(phase, {}).get('passed') is not True]}


def file_map(root):
    return {str(path.relative_to(root)): digest(path) for path in sorted(root.rglob('*'))
            if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts}


def field(value, name):
    for part in name.split('.'):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def check_result(path, checks, inventory=None):
    value = json.loads(path.read_text())
    for name, expected in checks.items():
        actual = field(value, name)
        require(type(actual) is type(expected) and actual == expected,
                f'{path}: {name} differs from {expected!r}')
    if inventory:
        names = inventory.get('fields') or [inventory['field']]
        rows = [row for name in names for row in field(value, name)]
        if inventory.get('side_key'):
            actual = [(row[inventory['key']], row[inventory['side_key']]) for row in rows]
            expected = [(name, side) for name in inventory['ids'] for side in inventory['sides']]
        else:
            actual = [row[inventory['key']] if inventory.get('key') else row for row in rows]
            expected = inventory['ids']
        require(expected and len(expected) == len(set(expected)), 'invalid frozen case inventory')
        require(len(actual) == len(expected) and set(actual) == set(expected), f'{path}: complete frozen case inventory differs')
    return value


def verify_command_results(records):
    require(records, 'completion has no executed commands')
    for record in records:
        require(record.get('passed') is True and record.get('returncode') == 0,
                'family command did not complete successfully')
        result = Path(record['result'])
        require(record.get('result_sha256') == digest(result), 'completed result changed: ' + str(result))
        check_result(result, record['checks'], record.get('inventory'))


def package_artifact(report, returncode, expected_sha, manifest, package_release="2"):
    size_only = report.get('status') == 'failed' and report.get('failure_boundary') == 'size-target' \
        and report.get('artifact_identity_verified') is True
    require(report.get('sdk_recipe_restored') is True, 'SDK recipe was not restored')
    require(returncode == 0 or size_only, 'package failed outside size target')
    require(report['elf']['sha256'] == expected_sha, 'APK payload ELF differs')
    if package_release == '3':
        require(report.get('package_release') == '3' and report.get('apk_metadata', {}).get('version') == '2.93-r3',
                'M6b APK release differs from frozen r3')
    path = manifest.parent / report['artifact']['name']
    require(digest(path) == report['artifact']['sha256'], 'reviewable APK artifact changed')
    return {'size_acceptance': 'pending-user-after-report' if size_only else 'target-met', 'artifact': str(path)}


def ubus_assets(spec):
    bindings = spec.get('bindings', {})
    names = ['ubus_reference_build', 'ubus_native_c_sha', 'ubus_image_runner', 'ubus_image_identity']
    require(all(bindings.get(name) for name in names), 'exact-image UBus runner and independent helper build bindings required')
    runner, identity = (Path(bindings[name]).resolve() for name in ['ubus_image_runner', 'ubus_image_identity'])
    reference = verify_reference(runner, identity)
    require(reference['kind'] == 'image-aarch64-musl' and reference['elf_sha256'] == STOCK_SHA256,
            'native C is a UBus helper input, never behavioural authority')
    native = Path(bindings['ubus_reference_build']).resolve()
    require(digest(native / 'dnsmasq/dnsmasq') == bindings['ubus_native_c_sha'], 'native UBus helper build identity differs')
    assets = {str(identity.parent / name): expected for name, expected in TARGET_FILES.items()}
    assets.update({str(path): digest(path) for path in [runner, identity, native / 'dnsmasq/dnsmasq']})
    assets.update({str(path): digest(path) for path in (native / 'deps/lib').glob('*.so*') if path.is_file()})
    return assets, {'root': str(native / 'deps'), 'files': file_map(native / 'deps'), 'reference': reference}


def verify_release_map(spec, build):
    path = Path(spec.get('bindings', {}).get('link_map', '')).resolve()
    require(path == Path(spec['build_json']).resolve().parent / 'link.map'
            and build.get('link_map') == {'path': 'link.map', 'sha256': digest(path)},
            'link map must belong to this exact release build')


def prepare(args):
    require(sys.flags.optimize == 0 and not os.environ.get('PYTHONOPTIMIZE'), 'assertion-enabled Python required by original drivers')
    spec = json.loads(args.inputs.read_text())
    phases = required_phases(spec)
    mode = spec.get('validation_mode', 'm5')
    source = Path(spec['source_root']).resolve()
    out = args.out.resolve()
    require(out.is_relative_to(source / 'private') and not out.exists(), 'fresh output under frozen source/private required')
    require(re.fullmatch('[0-9a-f]{40}', spec['source_commit']), 'full source commit required')
    elf = Path(spec['elf']).resolve()
    require(digest(elf) == spec['elf_sha256'], 'final ELF identity mismatch')
    build = json.loads(Path(spec['build_json']).read_text())
    require(build['kind'] == 'release' and build['source'] == str(source)
            and build['cargo_target_dir'] == str(cargo_target(spec)), 'ELF must come from shared-target oracle_build.sh release')
    require(any(row['path'] == 'dnsmasq-rs' and row['sha256'] == spec['elf_sha256']
                and row['bytes'] == elf.stat().st_size for row in build['artifacts']), 'build receipt does not identify ELF')
    image, runtime, sdk = (Path(spec[name]).resolve() for name in ['image_root', 'runtime_root', 'sdk'])
    require(digest(image / 'usr/sbin/dnsmasq') == STOCK_SHA256, 'exact image C ELF required')
    plan = json.loads(Path(spec['dhcp_plan']).read_text())
    require(digest(runtime / 'var/etc/dnsmasq.conf.cfg01411c') == plan['source_config_sha256'], 'captured DHCP plan input changed')
    require(len(plan['profiles']) == 4, 'complete four-profile M2 DHCP plan required')
    budget = build_package.read_budget(Path(spec['budget']))
    require('user_accepted_elf' not in budget and budget['elf_max_bytes'] == 1000000,
            'new ELF cannot reuse M4 acceptance or invent an exception')
    require(len(spec['variant_apks']) == 2 and len(spec['variant_dependency_apks']) == 5,
            'both actual variants and their five frozen solver dependencies required')
    package_release, previous_package = package_inputs(mode, spec)
    families = json.loads(Path(spec['family_plan']).read_text())
    require(families['schema'] == 1 and families['complete'] is True and families['families'],
            'complete reviewed family replay registry required')
    require(len({row['id'] for row in families['families']}) == len(families['families']), 'duplicate family IDs')
    require(all(len({step['id'] for step in row['steps']}) == len(row['steps']) for row in families['families']), 'duplicate family step IDs')
    require(all(row['steps'] and all(step.get('result') and step.get('checks') for step in row['steps'])
                for row in families['families']), 'every family step needs a retained result and explicit completion checks')
    canonical = source / 'tools/dnsmasq/m5_final_families.draft.json'
    require(families == json.loads(canonical.read_text()), 'family registry differs from reviewed frozen source')
    if mode == 'm6b':
        require(len(families['families']) == 44, 'M6b requires all 44 frozen M5 families')
    require(len(spec['cpus']) == 2 and spec['cpus'][0] != spec['cpus'][1]
            and set(spec['cpus']) <= os.sched_getaffinity(0), 'two available distinct CPU cores required')
    for name in ['deferred_review', 'safety_review']:
        review = json.loads(Path(spec[name]).read_text())
        require(review['source_commit'] == spec['source_commit'] and review['complete'] is True
                and review['ordinary_unresolved'] == [], f'{name}: completed review of exact final source required')
    release = json.loads((source / 'manifests/release-25.12.5.json').read_text())
    archive_name, archive_sha = release['inputs']['sdk'].split(' sha256 ')
    require(digest(sdk.parent / archive_name) == archive_sha, 'pinned SDK archive changed')
    require(sdk.name == archive_name.removesuffix('.tar.zst'), 'SDK release differs')
    assets = {str(Path(spec[name]).resolve()): digest(Path(spec[name])) for name in
              ['build_json', 'dhcp_plan', 'budget', 'family_plan', 'deferred_review', 'safety_review', 'stock_apk']}
    assets.update({str(Path(path).resolve()): digest(Path(path)) for path in spec['variant_apks'] + spec['variant_dependency_apks']})
    if previous_package:
        assets[previous_package['path']] = previous_package['apk_sha256']
    for path in spec.get('bindings', {}).values():
        if Path(path).is_file(): assets[str(Path(path).resolve())] = digest(path)
    pinned_ubus, ubus_helpers = ubus_assets(spec)
    assets.update(pinned_ubus)
    verify_release_map(spec, build)
    validate_qualification_build(mode, build)
    if mode == 'm6b' and spec.get('perf_guard_plan'):
        from m6b_perf_guard import inputs as guard_inputs
        _, _, guard_assets = guard_inputs(Path(spec['perf_guard_plan']).resolve(), source / 'tools/dnsmasq')
        assets.update(guard_assets)
    reference_source = Path(spec.get('bindings', {}).get('reference_source', '')).resolve()
    require(reference_source.is_dir() and (reference_source / 'option.c').is_file(), 'matching upstream source binding required')
    source_reference = {'root': str(reference_source), 'files': file_map(reference_source)}
    tools = source / 'tools/dnsmasq'
    spec.update(schema=1, status='prepared-not-executed', source_root=str(source), output=str(out),
                elf=str(elf), elf_bytes=elf.stat().st_size, assets=assets,
                source_files=build_package.inputs(source), tools=file_map(tools),
                fuzz_inputs=file_map(source / 'components/dnsmasq/fuzz'), runtime_files=file_map(runtime),
                image_files=file_map(image),
                sdk_archive_sha256=archive_sha, sdk_files=build_package.sdk_inputs(sdk),
                family_registry=families, dhcp_profiles=list(plan['profiles']),
                ubus_helpers=ubus_helpers,
                reference_source=source_reference,
                validation_mode=mode, phases=phases, physical_router=False, size_acceptance='pending-user-after-report',
                package_release=package_release, previous_package=previous_package,
                m4_baseline={'elf_bytes': 1159280, 'full_cache_rss_kib': 2676},
                resource_seconds=300, fuzz_seconds_per_target=1800 if mode == 'm5' else None)
    archive = Path(spec['source_archive']).resolve()
    with tarfile.open(archive) as stream:
        require(stream.pax_headers.get('comment') == spec['source_commit'], 'source archive commit differs')
        archived = {member.name: hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                    for member in stream.getmembers() if member.isfile()}
    locked = {**spec['source_files'], **{'tools/dnsmasq/' + name: sha for name, sha in spec['tools'].items()},
              **{'components/dnsmasq/fuzz/' + name: sha for name, sha in spec['fuzz_inputs'].items()}}
    require(all(archived.get(name) == sha for name, sha in locked.items()), 'final source does not match its exact commit archive')
    spec['assets'][str(archive)] = digest(archive)
    schedule = prepare_schedule(spec, out)
    out.mkdir(parents=True)
    save(out / 'identity.json', spec)
    save(out / 'commands.json', schedule)
    print(json.dumps({'status': spec['status'], 'identity': str(out / 'identity.json'), 'executed': False}))


def context(spec, output, family=None):
    tools = spec.get('family_tool_overrides', {}).get(family, {}).get('root',
                spec.get('tools_root', spec['source_root'] + '/tools/dnsmasq'))
    return {**spec.get('bindings', {}), 'python': sys.executable, 'source': spec['source_root'], 'tools': tools,
            'image': spec['image_root'], 'runtime': spec['runtime_root'], 'elf': spec['elf'],
            'elf_sha': spec['elf_sha256'], 'commit': spec['source_commit'], 'out': str(output),
            'sdk': spec.get('sdk', ''),
            'ubus_image_runner_sha': spec.get('ubus_helpers', {}).get('reference', {}).get('runner_sha256', ''),
            'ubus_image_identity_sha': spec.get('ubus_helpers', {}).get('reference', {}).get('identity_sha256', '')}


def expand(value, values):
    return value.format_map(values)


def commands(spec, phase, output):
    values = context(spec, output)
    py, tools = values['python'], values['tools']
    package_release = spec.get('package_release', '3' if spec.get('validation_mode') == 'm6b' else '2')
    isolated = ['sh', tools + '/run_isolated.sh', py]
    image_elf = ['--image-root', spec['image_root'], '--rust-binary', spec['elf']]
    jobs = []
    def job(name, argv, result=None, checks=None, timeout=1800):
        jobs.append(dict(id=name, argv=argv, result=result, checks=checks or {}, timeout_seconds=timeout))
    if phase == 'families':
        for family in spec['family_registry']['families']:
            if spec.get('selected_families') and family['id'] not in spec['selected_families']: continue
            current = context(spec, output / family['id'], family['id'])
            for step in family['steps']:
                job(family['id'] + '-' + step['id'], [expand(item, current) for item in step['argv']],
                    expand(step['result'], current) if step.get('result') else None,
                    {key: expand(value, current) if isinstance(value, str) else value
                     for key, value in step.get('checks', {}).items()}, step.get('timeout_seconds', 3600))
                jobs[-1]['family'] = family['id']
                if step.get('inventory'): jobs[-1]['inventory'] = step['inventory']
    elif phase == 'm2':
        for profile in DNS:
            path = output / ('dns-' + profile)
            job('dns-' + profile, isolated + [tools + '/m2_dns_diff.py', '--image-root', spec['image_root'],
                '--runtime-root', spec['runtime_root'], '--rust', spec['elf'], '--profile', profile, '--out', str(path)],
                str(path / 'result.json'), {'differences': [], 'failures': [], 'unexecuted': 0})
        path = output / 'dhcp'
        job('dhcp-four-profiles', [py, tools + '/m2_dhcp_suite.py', *image_elf, '--runtime-root', spec['runtime_root'],
            '--plan', spec['dhcp_plan'], '--label', 'final', '--out', str(path)], timeout=2400)
        for side in ['c', 'rust']:
            path = output / ('lifecycle-' + side)
            job('lifecycle-' + side, isolated + [tools + '/actual_config_network.py',
                '--source-root', spec['runtime_root'], '--router-cidr', '192.168.1.1/24',
                '--output', str(output / ('lifecycle-' + side + '-network')), '--',
                py, tools + '/m2_lifecycle.py', *image_elf,
                '--implementation', side, '--output', str(path)], str(path / 'result.json'), {'passed': True})
    elif phase == 'perf-guard':
        require(spec.get('validation_mode') == 'm6b' and spec.get('perf_guard_plan'), 'M6b frozen guard plan required')
        path = output / 'cache-guard'
        job('performance-regression-guard', [py, tools + '/m6b_perf_guard.py',
            '--inputs', spec['perf_guard_plan'], '--expected-plan-sha', digest(Path(spec['perf_guard_plan'])),
            '--elf', spec['elf'], '--expected-elf-sha', spec['elf_sha256'], '--build-json', spec['build_json'],
            '--source-commit', spec['source_commit'], '--image-root', spec['image_root'], '--out', str(path)],
            str(path / 'result.json'), {'passed': True, 'source_commit': spec['source_commit'],
                'elf_sha256': spec['elf_sha256'], 'plan_sha256': digest(Path(spec['perf_guard_plan']))}, 420)
    elif phase == 'fuzz-build':
        cache_env = ['env', 'ORACLE_BUILD_TARGET_DIR=' + str(cargo_target(spec))] if 'cargo_target_dir' in spec else []
        job('native-fuzz-build', ['runuser', '-u', 'ubuntu', '--', *cache_env, 'sh', tools + '/oracle_build.sh', spec['source_root'],
            str(output / 'build'), 'fuzz'], str(output / 'build/build.json'), {'kind': 'fuzz'}, 3600)
    elif phase == 'fuzz':
        for target in FUZZ:
            path = output / target
            build = spec.get('fuzz_build_directory', str(Path(spec['output']) / 'runs/fuzz-build/attempt-1/build'))
            job(target, [str(Path(build) / target), str(path / 'corpus'),
                '-seed=29302026', '-max_len=4096', '-max_total_time=1800', '-timeout=10',
                '-artifact_prefix=' + str(path / 'artifacts') + '/'], timeout=1920)
    elif phase in ['resources', 'full-cache-600']:
        cpus = ['--cpus', *map(str, spec['cpus'])]
        if phase == 'resources':
            path = output / 'mixed-300'
            job('mixed-300', [py, tools + '/m3_soak.py', 'pair', *image_elf, *cpus,
                '--duration-seconds', '300', '--sample-seconds', '1', '--clients', '20',
                '--seed', '29302026', '--out', str(path)], str(path / 'result.json'), {'accepted': True}, 540)
        seconds = 300 if phase == 'resources' else 600
        path = output / ('full-cache-' + str(seconds))
        job('full-cache-' + str(seconds), [py, tools + '/cache_full_resource.py', 'pair', *image_elf, *cpus,
            '--source-commit', spec['source_commit'], '--expected-rust-sha', spec['elf_sha256'],
            '--duration-seconds', str(seconds), '--out', str(path)], str(path / 'result.json'), {'accepted': True}, seconds + 240)
    elif phase == 'pressure':
        path = output / 'enospc-emfile'
        job('enospc-emfile', isolated + [tools + '/m3_soak.py', 'pressure', *image_elf,
            '--scenario', 'enospc', '--scenario', 'emfile', '--duration-seconds', '300',
            '--timeout-seconds', '3600', '--out', str(path)], str(path / 'result.json'), {'accepted': True}, 3620)
    elif phase == 'package':
        path = output / 'build'
        job('package', ['runuser', '-u', 'ubuntu', '--', py, tools + '/build_package.py', spec['sdk'], str(path), '--budget', spec['budget'],
            '--frozen-elf', spec['elf'], '--freeze-manifest', str(Path(spec['output']) / 'package-freeze.json'),
            '--source-commit', spec['source_commit'], '--source-date-epoch', str(spec['source_date_epoch']),
            '--expected-source-digest', hashlib.sha256(json.dumps(spec['source_files'], sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(), '--expected-elf-sha256', spec['elf_sha256'], '--package-release', package_release],
            str(path / 'manifest.json'), timeout=1800)
    elif phase == 'lifecycle':
        artifact = spec.get('package_artifact', str(Path(spec['output']) / f'runs/package/attempt-1/build/dnsmasq-2.93-r{package_release}.apk'))
        path = output / 'apk'
        argv = isolated + [tools + '/m4_package_lifecycle.py', '--rootfs', spec['image_root'],
            '--stock-apk', spec['stock_apk'], '--candidate-apk', artifact, '--out', str(path),
            '--candidate-elf-sha256', spec['elf_sha256'], '--source-commit', spec['source_commit'],
            '--package-release', package_release]
        for flag, name in [('variant-apk', 'variant_apks'), ('variant-dependency-apk', 'variant_dependency_apks')]:
            for value in spec[name]: argv += ['--' + flag, value]
        checks = {'status': 'passed'}
        if spec.get('validation_mode') == 'm6b':
            previous = spec['previous_package']
            argv += ['--previous-apk', previous['path'], '--previous-apk-sha256', previous['apk_sha256'],
                     '--previous-elf-sha256', previous['elf_sha256'], '--previous-source-commit', previous['source_commit']]
            checks.update({'candidate_package_id': '2.93-r3', 'previous_upgrade.passed': True,
                           'previous_upgrade.apk_sha256': previous['apk_sha256'],
                           'previous_upgrade.elf_sha256': previous['elf_sha256'],
                           'previous_upgrade.source_commit': previous['source_commit']})
        job('apk-lifecycle', argv, str(path / 'result.json'), checks, 900 if package_release == '3' else 600)
        if spec.get('validation_mode') == 'm6b':
            previous_stages = ['stock-to-m5-baseline', 'm5-to-candidate-upgrade', 'direct-m5-downgrade',
                'm5-to-candidate-for-removal', 'candidate-remove-for-m5-rollback', 'm5-rollback-after-removal']
            jobs[-1]['checks']['previous_upgrade.stages'] = previous_stages
            jobs[-1]['inventory'] = {'field': 'stages', 'key': 'name', 'ids': [
                'stock-to-candidate-upgrade', 'candidate-reinstall', 'candidate-uninstall',
                'candidate-fresh-install', 'candidate-remove-for-rollback', 'stock-rollback-after-removal',
                'candidate-upgrade-for-downgrade', 'direct-stock-downgrade', *previous_stages]}
    return jobs


def verify_identity(spec):
    required_phases(spec)
    require(sys.flags.optimize == 0 and not os.environ.get('PYTHONOPTIMIZE'), 'driver assertions were disabled')
    require(digest(spec['elf']) == spec['elf_sha256'], 'ELF changed after freeze')
    require(build_package.inputs(Path(spec['source_root'])) == spec['source_files'], 'product/packaging source changed')
    require(file_map(Path(spec.get('tools_root', spec['source_root'] + '/tools/dnsmasq'))) == spec['tools'], 'frozen tools changed')
    known_families = {row['id'] for row in spec['family_registry']['families']}
    for family, override in spec.get('family_tool_overrides', {}).items():
        require(family in known_families, 'unknown family tool override')
        root = Path(override['root'])
        require(root.parent == Path(spec['source_root']) / 'private'
                and root != Path(spec.get('tools_root', spec['source_root'] + '/tools/dnsmasq')),
                'family tools must use a separate private tree')
        require(root.is_dir() and not root.is_symlink()
                and not any(path.is_symlink() for path in root.rglob('*')), 'family override contains symlinks')
        require(file_map(root) == override['files'], 'family override tools changed')
        require(digest(override['archive']) == override['archive_sha256'], 'family override archive changed')
        with tarfile.open(override['archive']) as stream:
            require(stream.pax_headers.get('comment') == override['commit'], 'family override archive commit changed')
            archived = {member.name.removeprefix('tools/dnsmasq/'): hashlib.sha256(stream.extractfile(member).read()).hexdigest()
                        for member in stream.getmembers() if member.isfile() and member.name.startswith('tools/dnsmasq/')}
        require(archived == override['files'], 'family override differs from Git archive')
    require(file_map(Path(spec['runtime_root'])) == spec['runtime_files'], 'runtime evidence changed')
    require(file_map(Path(spec['image_root'])) == spec['image_files'], 'exact image files changed')
    require(build_package.sdk_inputs(Path(spec['sdk'])) == spec['sdk_files'], 'SDK tools changed')
    require(file_map(Path(spec['ubus_helpers']['root'])) == spec['ubus_helpers']['files'], 'independent UBus helper inputs changed')
    require(file_map(Path(spec['reference_source']['root'])) == spec['reference_source']['files'], 'matching upstream source changed')
    for path, expected in spec['assets'].items(): require(digest(path) == expected, f'frozen asset changed: {path}')


def family_processes(excluded):
    rows = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit() or int(path.name) in excluded: continue
        try:
            argv = (path / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
            if re.search(r'(?:^|[/ ])(?:cargo(?:-fuzz)?|rustc|make|clang|gcc|dnsmasq(?:-rs)?|m[2345]_[A-Za-z_]+\.py|build_package\.py|cache_full_resource\.py|dns_wire|dhcp_packet|config_line)(?: |$)', argv):
                rows.append({'pid': int(path.name), 'argv': argv})
        except (FileNotFoundError, ProcessLookupError, PermissionError): pass
    return rows


def related_processes():
    relations = {}
    for path in Path('/proc').glob('[0-9]*/status'):
        try: relations[int(path.parent.name)] = int(re.search(r'^PPid:\s+(\d+)', path.read_text(), re.M)[1])
        except (FileNotFoundError, ProcessLookupError, TypeError): pass
    excluded = {os.getpid()}; cursor = os.getpid()
    while relations.get(cursor):
        cursor = relations[cursor]; excluded.add(cursor)
    descendants = {os.getpid()}
    while True:
        added = {pid for pid, parent in relations.items() if parent in descendants} - descendants
        if not added: break
        descendants |= added
    return excluded | descendants


def exclusive_busy_processes():
    """Recheck ancestry for children born after the initial exclusion scan."""
    busy = family_processes(related_processes())
    if busy:
        related = related_processes()
        busy = [row for row in busy if row['pid'] not in related]
    return busy


def process_tree():
    """Linux PID generation witnesses, including detached child sessions."""
    rows = {}
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rpartition(')')[2].split()
            rows[int(path.parent.name)] = {'parent': int(fields[1]), 'starttime': int(fields[19]),
                                           'state': fields[0]}
        except (FileNotFoundError, ProcessLookupError, PermissionError): pass
    return rows


def remember_job_processes(process, known):
    rows = process_tree()
    owned = {pid for pid, value in known.items()
             if rows.get(pid, {}).get('starttime') == value['starttime']}
    if process.pid not in known and process.pid in rows:
        owned.add(process.pid)
    while True:
        added = {pid for pid, value in rows.items() if value['parent'] in owned} - owned
        if not added: break
        owned |= added
    for pid in owned: known[pid] = rows[pid]
    return {pid: rows[pid] for pid in owned if rows[pid]['state'] != 'Z'}


def stop_job_processes(process, known, grace_seconds=5):
    """Stop only witnessed job PIDs, even after their parent/group exits."""
    if not sys.platform.startswith('linux'):
        if process.poll() is None:
            from m3_soak import stop_process_group
            stop_process_group(process, grace_seconds)
        return
    def stop(sig):
        active = remember_job_processes(process, known)
        for pid in reversed(list(active)):
            try:
                current = (Path('/proc') / str(pid) / 'stat').read_text().rpartition(')')[2].split()
                if int(current[19]) == known[pid]['starttime']:
                    os.kill(pid, sig)
            except (FileNotFoundError, ProcessLookupError): pass
    # Capture detached groups before TERM can orphan them.
    stop(signal.SIGTERM)
    deadline = time.monotonic() + grace_seconds
    while remember_job_processes(process, known) and time.monotonic() < deadline:
        process.poll(); time.sleep(.02)
    stop(signal.SIGKILL)
    process.wait(grace_seconds)
    deadline = time.monotonic() + grace_seconds
    while remember_job_processes(process, known) and time.monotonic() < deadline:
        time.sleep(.02)
    require(not remember_job_processes(process, known), 'job descendants survived cleanup')


def publish(spec, manifest_sha, result):
    """Independent family groups publish under one lock without losing phases."""
    root = Path(spec['output'])
    with (root / '.completed.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = root / 'completed.json'
        completed = json.loads(path.read_text()) if path.exists() else {}
        if result['phase'] == 'families':
            for family in spec['family_registry']['families']:
                records = [row for row in result['commands'] if row.get('family') == family['id']]
                expected = {family['id'] + '-' + step['id'] for step in family['steps']}
                selected = result.get('selected_families') or [row['id'] for row in spec['family_registry']['families']]
                if not records and family['id'] not in selected: continue
                if len(records) != len(expected) or {row['id'] for row in records} != expected or not all(row.get('passed') is True for row in records):
                    completed.pop('family:' + family['id'], None); completed.pop('families', None)
                    continue
                try:
                    verify_command_results(records)
                except (ValueError, OSError, KeyError) as error:
                    completed.pop('family:' + family['id'], None); completed.pop('families', None)
                    result['passed'] = False
                    result['failures'].append('completion result validation: ' + repr(error))
                    atomic_save(Path(result['attempt']) / 'result.json', result)
                    continue
                receipt = dict(result, phase='family:' + family['id'], passed=True, failures=[], commands=records)
                receipt_path = Path(result['attempt']) / (family['id'] + '.result.json')
                receipt['receipt'] = str(receipt_path); atomic_save(receipt_path, receipt)
                completed['family:' + family['id']] = receipt
            needed = ['family:' + row['id'] for row in spec['family_registry']['families']]
            if all(completed.get(key, {}).get('passed') is True
                   and completed[key].get('manifest_sha256') == manifest_sha
                   and completed[key].get('elf_sha256') == spec['elf_sha256']
                   and completed[key].get('source_commit') == spec['source_commit'] for key in needed):
                aggregate = root / 'aggregates/families'; aggregate.mkdir(parents=True, exist_ok=True)
                receipt = {'phase': 'families', 'passed': True, 'failures': [], 'commands': [], 'attempt': str(aggregate),
                           'elf_sha256': spec['elf_sha256'], 'source_commit': spec['source_commit'], 'manifest_sha256': manifest_sha,
                           'family_receipts': {key: completed[key]['receipt'] for key in needed}}
                atomic_save(aggregate / 'result.json', receipt); completed['families'] = receipt
            else:
                completed.pop('families', None)
        elif result['passed']:
            completed[result['phase']] = result
        atomic_save(path, completed)


def prerequisite(spec, manifest_sha, completed, phase):
    record = completed.get(phase, {})
    require(record.get('passed') is True and record.get('manifest_sha256') == manifest_sha
            and record.get('source_commit') == spec['source_commit'] and record.get('elf_sha256') == spec['elf_sha256'],
            phase + ': complete result from this exact freeze required')
    receipt = Path(record.get('receipt', str(Path(record['attempt']) / 'result.json')))
    require(json.loads(receipt.read_text()) == record, phase + ': receipt changed')
    if phase == 'perf-guard':
        require(record.get('guard_binding'), 'measured guard binding is missing')
        verify_guard_binding(spec, record['guard_binding'])
        bound = dict(spec, perf_guard_plan=record['guard_binding']['path'])
        expected = commands(bound, phase, Path(record['attempt']))
        require(len(record['commands']) == len(expected), 'guard command count differs')
        for actual, wanted in zip(record['commands'], expected):
            require(all(actual.get(key) == value for key, value in wanted.items()),
                    'guard command differs from the bound schedule')
        verify_command_results(record['commands'])
    if record.get('imported_from'):
        from m5_fixture_revision import verify_import
        verify_import(spec, record)
        return record
    if phase == 'families':
        expected = {'family:' + row['id'] for row in spec['family_registry']['families']}
        require(set(record.get('family_receipts', {})) == expected, 'aggregate misses frozen families')
        for name, path in record['family_receipts'].items():
            child = prerequisite(spec, manifest_sha, completed, name)
            require(child['receipt'] == path, 'aggregate points to another family receipt')
    elif phase.startswith('family:'):
        family = phase.removeprefix('family:')
        expected = commands(dict(spec, selected_families=[family]), 'families', Path(record['attempt']))
        observed = record['commands']
        require(len(observed) == len(expected), 'family completion step count differs')
        for actual, wanted in zip(observed, expected):
            require(all(actual.get(key) == value for key, value in wanted.items()),
                    'completion command differs from frozen family schedule')
        verify_command_results(record['commands'])
    return record


def fuzz_target(spec, attempt, job, cancelled):
    """One independent target retains its receipt even when execution fails."""
    folder = attempt / job['id']
    record = copy.deepcopy(job)
    record.update(passed=False, failures=[], returncode=None, elapsed_seconds=0,
                  started_at_unix_ns=None, finished_at_unix_ns=None,
                  log=str(attempt / (job['id'] + '.log')),
                  corpus_directory=str(folder / 'corpus'), artifact_directory=str(folder / 'artifacts'))
    process = None; started = None
    try:
        (folder / 'artifacts').mkdir(parents=True); (folder / 'corpus').mkdir()
        seeds = Path(spec['source_root']) / 'components/dnsmasq/fuzz/corpus' / job['id']
        if seeds.exists(): shutil.copytree(seeds, folder / 'corpus', dirs_exist_ok=True)
        else: (folder / 'corpus/seed').write_bytes(b'port=53\n')
        with Path(record['log']).open('wb') as log:
            build = json.loads((Path(spec['fuzz_build_directory']) / 'build.json').read_text())
            record['instrumented_target_sha256'] = digest(job['argv'][0])
            require(any(row['path'] == job['id'] and row['sha256'] == record['instrumented_target_sha256']
                        for row in build['artifacts']), 'instrumented target changed')
            require(not cancelled.is_set(), 'fuzz phase interrupted')
            started = time.monotonic(); record['started_at_unix_ns'] = time.time_ns()
            process = subprocess.Popen(job['argv'], cwd=spec['source_root'], stdout=log, stderr=log, start_new_session=True)
            record['pid'] = process.pid
            save(attempt / (job['id'] + '.json'), record)
            while process.poll() is None:
                require(not cancelled.is_set(), 'fuzz phase interrupted')
                remaining = job['timeout_seconds'] - (time.monotonic() - started)
                require(remaining > 0, 'job timeout')
                try: process.wait(timeout=min(1, remaining))
                except subprocess.TimeoutExpired: pass
    except Exception as error:
        record['failures'].append(repr(error))
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    from m3_soak import stop_process_group
                    stop_process_group(process)
                except Exception as error:
                    record['failures'].append('target cleanup failed: ' + repr(error))
            record.update(returncode=process.returncode, elapsed_seconds=time.monotonic() - started,
                          finished_at_unix_ns=time.time_ns())
        if record['returncode'] != 0:
            record['failures'].append(f'{job["id"]} exited {record["returncode"]}')
        if record['elapsed_seconds'] > job['timeout_seconds'] and not any('job timeout' in error for error in record['failures']):
            record['failures'].append('job timeout')
        if record['elapsed_seconds'] < FUZZ_SECONDS:
            record['failures'].append('fuzz stopped before the actual 30-minute window')
        try:
            record['final_corpus'] = file_map(folder / 'corpus')
            record['artifact_entries'] = sorted(path.name for path in (folder / 'artifacts').iterdir())
            record['final_artifacts'] = file_map(folder / 'artifacts')
            require(not record['artifact_entries'], 'fuzz produced artifacts')
        except Exception as error:
            record['failures'].append(repr(error))
        try:
            require(digest(job['argv'][0]) == record.get('instrumented_target_sha256'), 'instrumented target changed while running')
        except Exception as error:
            record['failures'].append(repr(error))
        record['passed'] = not record['failures']
        save(attempt / (job['id'] + '.json'), record)
    return record


def run_fuzz(spec, attempt, jobs):
    """Run all three targets concurrently; a failed target does not stop peers."""
    require(len(jobs) == len(FUZZ) and {job['id'] for job in jobs} == set(FUZZ), 'complete three-target fuzz inventory required')
    records = [dict(copy.deepcopy(job), passed=False, returncode=None) for job in jobs]
    save(attempt / 'commands.json', records)
    cancelled = threading.Event(); interruptions = []
    with ThreadPoolExecutor(max_workers=len(FUZZ)) as pool:
        futures = {pool.submit(fuzz_target, spec, attempt, job, cancelled): index for index, job in enumerate(jobs)}
        def retain(future):
            index = futures[future]
            try: records[index] = future.result()
            except Exception as error:
                records[index].update(failures=['target worker failed: ' + repr(error)])
            atomic_save(attempt / 'commands.json', records)
        try:
            for future in as_completed(futures):
                retain(future)
        except KeyboardInterrupt as error:
            cancelled.set(); interruptions.append(repr(error))
            for future in futures: retain(future)
    failures = interruptions + [record['id'] + ': ' + error for record in records for error in record['failures']]
    return records, failures


def run(args):
    require(os.geteuid() == 0, 'use sudo for the controller; build workers run as ubuntu')
    spec = json.loads(args.manifest.read_text()); verify_identity(spec)
    root = Path(spec['output']); phase = args.phase
    manifest_sha = digest(args.manifest)
    guard_binding = None
    guard_path = getattr(args, 'perf_guard_plan', None)
    require(not guard_path or phase == 'perf-guard', '--perf-guard-plan applies only to perf-guard')
    if phase == 'perf-guard':
        guard_path = guard_path or spec.get('perf_guard_plan')
        require(guard_path, 'run perf-guard only after freezing the measured plan')
        guard_sha = getattr(args, 'expected_guard_sha', None)
        if spec.get('perf_guard_plan') and not guard_sha:
            guard_sha = spec['assets'][str(Path(guard_path).resolve())]
        guard_binding = bind_guard(spec, guard_path, guard_sha)
        spec['perf_guard_plan'] = guard_binding['path']
        spec['assets'].update(guard_binding['assets'])
    selected = getattr(args, 'family', None) or []
    require(not selected or phase == 'families', '--family applies only to families phase')
    available = {row['id'] for row in spec['family_registry']['families']}
    require(len(selected) == len(set(selected)) and set(selected) <= available, 'unknown or duplicate family ID')
    spec['selected_families'] = selected
    completed = json.loads((root / 'completed.json').read_text()) if (root / 'completed.json').exists() else {}
    for name in phase_prerequisites(spec, phase):
        receipt = prerequisite(spec, manifest_sha, completed, name)
        if name == 'fuzz-build':
            spec['fuzz_build_directory'] = receipt['artifact_directory']
    folder = root / 'runs' / phase
    if selected:
        selection = hashlib.sha256('\n'.join(sorted(selected)).encode()).hexdigest()[:12]
        folder /= 'group-' + selection
    attempt = folder / ('attempt-' + str(args.attempt))
    require(not attempt.exists(), 'attempt output exists; choose a fresh attempt number')
    attempt.mkdir(parents=True)
    if phase in ['fuzz-build', 'package']:
        account = pwd.getpwnam('ubuntu'); os.chown(attempt, account.pw_uid, account.pw_gid)
    records = []; failures = []; lock = None; identity_verified = False
    try:
        if phase == 'perf-guard':
            require(args.exclusive_window, 'root must coordinate an exclusive load-free guard window')
            os.sched_setaffinity(0, {3})
        if phase in ['resources', 'full-cache-600', 'pressure']:
            require(args.exclusive_window, 'root must coordinate an exclusive load-free window')
            lock = (cargo_target(spec) / '.dnsmasq-build.lock').open('a'); fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            busy = exclusive_busy_processes(); save(attempt / 'window-before.json', busy)
            require(not busy, 'other build/test processes are active; retain this unexecuted attempt')
        if phase == 'package':
            freeze = {key: spec[key] for key in ['source_commit', 'source_date_epoch', 'source_files', 'sdk_archive_sha256', 'sdk_files']}
            freeze.update(schema=1, frozen=True, pending=[], rust_elf_sha256=spec['elf_sha256'],
                package_release=spec.get('package_release', '2'),
                postprocess={'mode': 'none', 'input_sha256': spec['elf_sha256'], 'output_sha256': spec['elf_sha256'],
                             'reason': 'package exact validated oracle_build.sh stripped ELF without further codegen/stripping'})
            save(root / 'package-freeze.json', freeze)
        if phase == 'lifecycle':
            spec['package_artifact'] = completed['package']['artifact']
        jobs = commands(spec, phase, attempt)
        if phase == 'fuzz':
            records, failures = run_fuzz(spec, attempt, jobs)
            jobs = []
        for job in jobs:
            record = copy.deepcopy(job); started = time.monotonic()
            records.append(record); save(attempt / 'commands.json', records)
            with (attempt / (job['id'] + '.log')).open('wb') as log:
                process = subprocess.Popen(job['argv'], cwd=spec['source_root'], stdout=log, stderr=log, start_new_session=True)
                descendants = {}
                remember_job_processes(process, descendants)
                try:
                    while process.poll() is None:
                        remember_job_processes(process, descendants)
                        if lock:
                            busy = exclusive_busy_processes()
                            require(not busy, f'exclusive window contaminated: {busy}')
                        require(time.monotonic() - started < job['timeout_seconds'], 'job timeout')
                        try: process.wait(timeout=1)
                        except subprocess.TimeoutExpired: pass
                finally:
                    stop_job_processes(process, descendants)
                    record.update(returncode=process.returncode, elapsed_seconds=time.monotonic() - started)
            if phase == 'package':
                report = json.loads(Path(job['result']).read_text())
                record.update(package_artifact(report, process.returncode, spec['elf_sha256'], Path(job['result']), spec.get('package_release', '2')))
            else:
                require(process.returncode == 0, f'{job["id"]} exited {process.returncode}')
                if job['result']:
                    check_result(Path(job['result']), job['checks'], job.get('inventory'))
                    record['result_sha256'] = digest(Path(job['result']))
            if phase == 'm2' and job['id'] == 'dhcp-four-profiles':
                for profile in spec['dhcp_profiles']:
                    result = Path(job['argv'][-1]) / ('final-' + profile + '-comparison.json')
                    report = check_result(result, {'errors': []})
                    require(report['c_binary'] and set(report['c_binary']) == {STOCK_SHA256}
                            and report['rust_binary'] and set(report['rust_binary']) == {spec['elf_sha256']}, 'DHCP comparisons used another ELF')
            record['passed'] = True
            save(attempt / 'commands.json', records)
        verify_identity(spec)
        require(digest(args.manifest) == manifest_sha, 'manifest changed while phase was running')
        identity_verified = True
    except (Exception, KeyboardInterrupt) as error:
        failures.append(repr(error))
    finally:
        if lock: lock.close()
        if not identity_verified:
            try:
                verify_identity(spec); require(digest(args.manifest) == manifest_sha, 'manifest changed while phase was running')
                identity_verified = True
            except Exception as error: failures.append('final identity check failed: ' + repr(error))
        result = {'phase': phase, 'passed': not failures, 'failures': failures, 'commands': records,
                  'elf_sha256': spec['elf_sha256'], 'source_commit': spec['source_commit'], 'attempt': str(attempt),
                  'selected_families': selected, 'manifest_sha256': manifest_sha}
        if guard_binding:
            result['guard_binding'] = guard_binding
        if phase == 'fuzz':
            result['target_seconds'] = sum(record.get('elapsed_seconds', 0) for record in records)
            result['required_target_seconds'] = len(FUZZ) * FUZZ_SECONDS
        if phase == 'package' and records and records[-1].get('artifact'):
            result['artifact'] = records[-1]['artifact']
        if phase == 'fuzz-build' and records and result['passed']:
            result['artifact_directory'] = str(Path(records[-1]['result']).parent)
        save(attempt / 'result.json', result)
        if identity_verified: publish(spec, manifest_sha, result)
    print(json.dumps(result)); return bool(failures)


def summary(args):
    spec = json.loads(args.manifest.read_text()); verify_identity(spec)
    root = Path(spec['output']); completed = json.loads((root / 'completed.json').read_text())
    status = completion_status(spec, completed)
    missing = status['missing_phases']
    if 'families' not in missing: prerequisite(spec, digest(args.manifest), completed, 'families')
    if 'perf-guard' in completed: prerequisite(spec, digest(args.manifest), completed, 'perf-guard')
    for phase, record in completed.items():
        require(record['elf_sha256'] == spec['elf_sha256'] and record['source_commit'] == spec['source_commit'], 'phase used another identity')
        require(record['manifest_sha256'] == digest(args.manifest), 'phase used another frozen tools/input identity')
        receipt = Path(record.get('receipt', str(Path(record['attempt']) / 'result.json')))
        require(json.loads(receipt.read_text()) == record, 'completed phase receipt changed')
    report = {'source_commit': spec['source_commit'], 'elf_sha256': spec['elf_sha256'], 'elf_bytes': spec['elf_bytes'],
              'validation_mode': spec.get('validation_mode', 'm5'), **status,
              'elf_delta_from_m4_bytes': spec['elf_bytes'] - 1159280,
              'functional_validation_passed': not missing, 'size_acceptance': 'pending-user-after-report',
              'm6_performance_executed': False, 'physical_router': False, 'phases': completed}
    if completed.get('resources', {}).get('passed'):
        path = Path(completed['resources']['attempt']) / 'full-cache-300/result.json'
        cache = json.loads(path.read_text()); rss = cache['differences']['full_window_rss_q4']
        report['full_cache_rss'] = {**rss, 'rust_delta_from_m4_kib': rss['rust_kib'] - 2676,
                                    'scope': '4096 proven live dynamic A entries, fixed short names, actual 300-second window'}
    report['package_release'] = spec.get('package_release', '3' if spec.get('validation_mode') == 'm6b' else '2')
    report['expected_package_id'] = build_package.package_id(report['package_release'])
    report['previous_package'] = spec.get('previous_package')
    if completed.get('lifecycle', {}).get('passed'):
        lifecycle = json.loads(Path(completed['lifecycle']['commands'][0]['result']).read_text())
        report['package_lifecycle'] = {'status': lifecycle['status'],
            'candidate_package_id': lifecycle.get('candidate_package_id', report['expected_package_id']),
            'previous_upgrade': lifecycle.get('previous_upgrade'),
            'stages': [stage['name'] for stage in lifecycle['stages']]}
    if completed.get('package', {}).get('passed'):
        package = json.loads(Path(completed['package']['commands'][0]['result']).read_text())
        report['apk'] = package['artifact']; report['size_targets'] = package['budget_checks']
    save(root / 'summary.json', report)
    mode = spec.get('validation_mode', 'm5')
    title = 'M6b 功能复验' if mode == 'm6b' else 'M5 最终验收'
    exclusions = ('M6b 范围未要求新的 fuzz-build/fuzz；两项为 excluded-not-required，不是通过。\n\n'
                  if mode == 'm6b' else '')
    performance_scope = ('本控制器只给出 M6b 功能资格；正式性能窗口由独立冻结协议和报告给出。'
                         if mode == 'm6b' else 'M6 仅准备协议草稿，尚未执行正式性能窗口。')
    text = (f"# {title}报告草稿\n\n源码 `{spec['source_commit']}`，ELF `{spec['elf_sha256']}`，"
            f"{spec['elf_bytes']:,} 字节；相对 M4 {report['elf_delta_from_m4_bytes']:+,} 字节。\n\n"
            f"完整冻结资格：{'已执行全部阶段' if not missing else '未完成：' + ', '.join(missing)}。"
            "各阶段的原始命令、身份、结果及失败保存在本次 fresh evidence。\n\n"
            + exclusions +
            "新增 ELF/APK 体积尚待用户在报告后决定；未复用 M4 例外。"
            "APK size-target 失败与生命周期资格分别报告。\n\n"
            "满缓存 RSS 和增长：见 summary.json 的实际 4096 live A 记录结果；"
            "与 M4 2,676 KiB 比较，不将资源收集解释为性能收益。\n\n"
            "补齐人工结论：全部功能族结果、deferred 每项处理/精确 C 位置/理由、"
            "SAFETY 与网络/定时 unwrap/expect/Mutex 审查、资源趋势及失败归因。\n\n"
            + performance_scope + "物理路由器未操作；未经 M7 不称生产验收。\n")
    (root / ('M6B_FUNCTIONAL_REPORT.draft.md' if mode == 'm6b' else 'M5_REPORT.draft.md')).write_text(text)
    print(json.dumps({'functional_validation_passed': not missing, 'missing_phases': missing,
                      'size_acceptance': report['size_acceptance']})); return bool(missing)


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='action', required=True)
    prep = sub.add_parser('prepare'); prep.add_argument('--inputs', type=Path, required=True); prep.add_argument('--out', type=Path, required=True)
    execute = sub.add_parser('run'); execute.add_argument('--manifest', type=Path, required=True)
    execute.add_argument('--phase', choices=PHASES + ['perf-guard', 'full-cache-600'], required=True); execute.add_argument('--attempt', type=int, default=1)
    execute.add_argument('--exclusive-window', action='store_true')
    execute.add_argument('--family', action='append', help='independent fresh family group; repeat for several families')
    execute.add_argument('--perf-guard-plan', type=Path, help='measured M6b plan, bound only when running perf-guard')
    execute.add_argument('--expected-guard-sha', help='explicit SHA256 for a late-bound guard plan')
    report = sub.add_parser('summary'); report.add_argument('--manifest', type=Path, required=True)
    revision = sub.add_parser('fixture-revision')
    revision.add_argument('--manifest', type=Path, required=True)
    revision.add_argument('--tools-root', type=Path, required=True)
    revision.add_argument('--tools-archive', type=Path, required=True)
    revision.add_argument('--tools-commit', required=True)
    revision.add_argument('--family', action='append', help='replace tools only for selected families; keep the default frozen tree')
    revision.add_argument('--out', type=Path, required=True)
    refresh = sub.add_parser('import-unchanged'); refresh.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.action in ['fixture-revision', 'import-unchanged']:
        from m5_fixture_revision import revise, import_unchanged
        return revise(args) if args.action == 'fixture-revision' else import_unchanged(args.manifest)
    return {'prepare': prepare, 'run': run, 'summary': summary}[args.action](args)


if __name__ == '__main__': raise SystemExit(main())
