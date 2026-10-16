#!/usr/bin/env python3
"""Serial calls to the original SDK builder and unchanged allocation controls."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time

plan_path = Path(sys.argv[1]).resolve()
plan = json.loads(plan_path.read_text())
inputs = plan_path.parent
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
state_path = inputs / 'state.json'
assert plan['status'] == 'FROZEN_AUTHORIZED_SERIAL_SDK_AFTER_ACTUAL961_AND_QUIET'
assert sha(__file__) == plan['controller_sha256']
assert not state_path.exists()
state = {'scope': plan['scope'], 'pid': os.getpid(), 'started_epoch': time.time(),
         'plan_sha256': sha(plan_path), 'commands': [], 'builds': [], 'complete': False}


def save():
    temporary = state_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(state_path)


def verify():
    assert sha(plan['builder']['path']) == plan['builder']['sha256']
    assert sha(plan['builder']['helper']) == plan['builder']['helper_sha256']
    gate = plan['related_gate']
    assert sha(gate['path']) == gate['sha256']
    verified = json.loads(Path(gate['path']).read_text())
    assert verified['status'] == 'PASS_FRESH_ORIGINAL_FIVE_RELATED_GROUPS_AND_QUIET'
    assert verified['source_commit'] == plan['sources'][1]['source_commit']
    assert verified['source'] == plan['sources'][1]['planned_remote_source']
    assert verified['total_passed'] == 961 and verified['research'] == [] and verified['wrapper_exited']
    assert {r['gate']: r['passed'] for r in verified['groups']} == {
        'lib': 840, 'bin': 82, 'allocations': 17, 'lib-ignored-live': 18, 'bin-ignored-live': 4}
    assert all(r['exit'] == r['failed'] == 0 and r['listed_names_match_actual_log'] for r in verified['groups'])
    assert verified['git_identity_sha256'] == plan['sources'][1]['git_identity_sha256']
    assert verified['source_files_rehashed'] == 179
    assert verified['source_manifest_sha256'] == plan['sources'][1]['source_manifest_sha256']
    assert sha(plan['quiet']['path']) == plan['quiet']['sha256']
    quiet = json.loads(Path(plan['quiet']['path']).read_text())
    assert quiet['status'] == 'QUIET_RELEASE_TO_DNS_SERIAL_SDK'
    assert quiet['related_verified_sha256'] == gate['sha256']
    assert quiet['research_including_exact_image_C'] == []
    for row in plan['sources']:
        source = Path(row['planned_remote_source'])
        assert sha(source / 'research-git-identity.json') == row['git_identity_sha256']
        identity = json.loads((source / 'research-git-identity.json').read_text())
        assert identity['commit'] == row['source_commit'] and identity['epoch'] == row['source_date_epoch']
        assert len(identity['git_blob_sha1']) == len(row['source_files']) == row['source_file_count']
        assert set(identity['git_blob_sha1']) == set(row['source_files'])
        assert all(sha(source / name) == digest for name, digest in row['source_files'].items())
        assert sha(source / row['map_wrapper']['path']) == row['map_wrapper']['sha256']
        assert os.access(source / row['map_wrapper']['path'], os.X_OK)
    for name, digest in plan['controls']['files_sha256'].items():
        assert sha(inputs / 'meter-tools' / name) == digest
    for name, digest in plan['controls']['source_sha256'].items():
        assert sha(Path(plan['sources'][0]['planned_remote_source']) / name) == digest
    assert sha(inputs / 'expected-meter-control.json') == plan['controls']['expected_meter_sha256']
    for name, digest in plan['accepted_G']['files_sha256'].items():
        assert sha(Path(plan['accepted_G']['directory']) / name) == digest
    assert not any(k.startswith('CARGO_PROFILE_RELEASE_') for k in os.environ)


def run(name, argv, cwd=None, environment=None):
    stdout = inputs / (name + '.stdout')
    stderr = inputs / (name + '.stderr')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=out, stderr=err)
        row = {'name': name, 'argv': argv, 'cwd': str(cwd) if cwd else None,
               'pid': process.pid, 'started_epoch': time.time()}
        state['commands'].append(row)
        state['active'] = name
        save()
        status = process.wait()
    row.update(returncode=status, finished_epoch=time.time(),
               stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    state['active'] = None
    save()
    assert status == 0, name


def check_build(row):
    out = Path(row['planned_remote_output'])
    built = json.loads((out / 'build.json').read_text())
    assert built['status'] == 'built-unqualified' and built['source_unchanged'] and built['sdk_recipe_restored']
    assert built['source_commit'] == row['source_commit'] and built['source'] == row['planned_remote_source']
    assert built['source_date_epoch'] == row['source_date_epoch']
    assert built['source_files'] == row['source_files'] and built['git_identity_sha256'] == row['git_identity_sha256']
    assert built['builder_sha256'] == plan['builder']['sha256']
    assert built['build_helper_sha256'] == plan['builder']['helper_sha256']
    assert built['toolchain']['map_wrapper_sha256'] == row['map_wrapper']['sha256']
    assert built['features'] == '' and built['opt_level'] == '3'
    layout = built['elf_layout']
    assert layout['type'] == 'ET_DYN' and layout['machine'] == 'AArch64'
    assert layout['linkage'] == 'static-pie' and layout['interpreter'] is None and not layout['needed']
    assert all(layout[k] for k in ('pie', 'bind_now', 'gnu_relro', 'nx_stack'))
    assert not layout['writable_executable_load']
    for artifact in built['artifacts'] + [dict(path=built['artifact']['name'], **{
            k: built['artifact'][k] for k in ('bytes', 'sha256')})]:
        assert sha(out / artifact['path']) == artifact['sha256']
        assert (out / artifact['path']).stat().st_size == artifact['bytes']
    assert sha(out / 'link.map') == built['link_map']['sha256']
    assert built['budget'] == {'elf_max_bytes': 2200000, 'apk_max_bytes': 1200000}
    fits = (out / 'dnsmasq-rs').stat().st_size <= 2200000 and built['artifact']['bytes'] <= 1200000
    assert built['within_existing_budget'] == fits
    if row['name'] == 'post185-combined':
        assert fits, 'product experiment exceeds unchanged release budget'
    result = {'name': row['name'], 'source_commit': row['source_commit'],
              'build_receipt_sha256': sha(out / 'build.json'), 'artifacts': built['artifacts'],
              'apk': built['artifact'], 'link_map': built['link_map'], 'elf_layout': layout,
              'within_existing_budget': fits, 'source_files_verified': len(row['source_files']),
              'scope': row['purpose']}
    state['builds'].append(result)
    save()


try:
    verify()
    assert all(not Path(row['planned_remote_output']).exists() for row in plan['sources'])
    for index, row in enumerate(plan['sources']):
        run(row['name'] + '-sdk', row['build_argv'])
        check_build(row)
        verify()
        if index == 0:
            env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.1')
            run('meter-rustc-version', ['/home/ubuntu/.cargo/bin/rustc', '-vV'], environment=env)
            version = (inputs / 'meter-rustc-version.stdout').read_text()
            assert 'release: 1.98.1' in version
            fixture = str(Path(row['planned_remote_source']) / 'tools/dnsmasq/udp_allocation_meter_check.rs')
            binary = inputs / 'meter-check'
            report = inputs / 'meter-check.json'
            assert not binary.exists() and not report.exists()
            run('meter-control-build', ['/home/ubuntu/.cargo/bin/rustc', '--edition=2021', '-O', fixture,
                                        '-o', str(binary)], environment=env)
            env['DNSMASQ_UDP_ALLOC_OUT'] = str(report)
            run('meter-control-run', [str(binary)], environment=env)
            expected = json.loads((inputs / 'expected-meter-control.json').read_text())
            assert json.loads(report.read_text()) == expected
            run('meter-parser-controls', ['python3', '-m', 'unittest', 'test_udp_allocation_device_run', '-v'],
                cwd=inputs / 'meter-tools')
            text = (inputs / 'meter-parser-controls.stderr').read_text()
            assert re.search(r'Ran 4 tests\b', text) and re.search(r'^OK\s*$', text, re.M)
            assert all(name in text for name in plan['controls']['test_names'])
            state['controls'] = {'rustc_version': version, 'binary_sha256': sha(binary),
                                 'report_sha256': sha(report), 'original_json_equal': True,
                                 'original_parser_tests_passed': 4,
                                 'scope': 'Original standalone host GlobalAlloc controls only; no musl SDK timing/size inference.'}
            save()
    verify()
    state.update(complete=True, finished_epoch=time.time())
    save()
except BaseException as error:
    state.update(error=repr(error), failed_epoch=time.time())
    save()
    raise
