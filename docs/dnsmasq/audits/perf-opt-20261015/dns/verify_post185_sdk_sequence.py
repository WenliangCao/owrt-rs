#!/usr/bin/env python3
"""Rehash the frozen serial SDK outputs and record the quiet handoff."""
from pathlib import Path
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


inputs = Path(sys.argv[1]).resolve()
plan = json.loads((inputs / 'plan.json').read_text())
state = json.loads((inputs / 'state.json').read_text())
assert sha(inputs / 'plan.json') == '3489608499a712c5a8fe513c0ccab05e5e35c1e1f3f33d7a18ae64526f0d578f'
assert sha(inputs / 'controller.py') == plan['controller_sha256']
assert state['complete'] and not state.get('error') and state['active'] is None
assert [row['name'] for row in state['commands']] == [
    'cached-zero-frame-allocation-sdk', 'meter-rustc-version', 'meter-control-build',
    'meter-control-run', 'meter-parser-controls', 'post185-combined-sdk']
assert all(row['returncode'] == 0 for row in state['commands'])
for row in state['commands']:
    for stream in ('stdout', 'stderr'):
        assert sha(inputs / (row['name'] + '.' + stream)) == row[stream + '_sha256']
assert state['controls']['original_json_equal']
assert state['controls']['original_parser_tests_passed'] == 4
assert sha(inputs / 'meter-check.json') == plan['controls']['expected_meter_sha256']
assert sha(inputs / 'meter-check') == state['controls']['binary_sha256']
assert sha(plan['builder']['path']) == plan['builder']['sha256']
assert sha(plan['builder']['helper']) == plan['builder']['helper_sha256']
spec = importlib.util.spec_from_file_location('original_sdk_helper', plan['builder']['helper'])
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

builds = []
for source_row, completed in zip(plan['sources'], state['builds'], strict=True):
    source = Path(source_row['planned_remote_source'])
    out = Path(source_row['planned_remote_output'])
    built = json.loads((out / 'build.json').read_text())
    assert sha(out / 'build.json') == completed['build_receipt_sha256']
    assert built['source_commit'] == source_row['source_commit']
    assert built['source_files'] == source_row['source_files'] == helper.inputs(source)
    assert sha(source / 'research-git-identity.json') == source_row['git_identity_sha256']
    assert built['source_unchanged'] and built['sdk_recipe_restored']
    assert built['status'] == 'built-unqualified'
    assert built['builder_sha256'] == plan['builder']['sha256']
    assert built['build_helper_sha256'] == plan['builder']['helper_sha256']
    assert built['features'] == '' and built['opt_level'] == '3'
    sdk = Path(source_row['build_argv'][source_row['build_argv'].index('--sdk') + 1])
    assert helper.sdk_inputs(sdk) == built['sdk']['files']
    recipe = Path(built['sdk_recipe_path'])
    assert not (sdk / ('.dnsmasq-backup-' + out.name)).exists()
    recipe_files = {str(path.relative_to(recipe)): sha(path)
                    for path in sorted(recipe.rglob('*')) if path.is_file()}
    layout = helper.audit_elf((out / 'dnsmasq-rs').read_bytes(), (out / 'readelf.log').read_text())
    assert layout == built['elf_layout']
    assert layout['type'] == 'ET_DYN' and layout['machine'] == 'AArch64'
    assert layout['linkage'] == 'static-pie' and not layout['needed'] and layout['interpreter'] is None
    assert all(layout[key] for key in ('pie', 'bind_now', 'gnu_relro', 'nx_stack'))
    assert not layout['writable_executable_load']
    assert helper.audit_payload(out / 'payload') == built['payload_files']
    for artifact in built['artifacts']:
        path = out / artifact['path']
        assert sha(path) == artifact['sha256'] and path.stat().st_size == artifact['bytes']
    apk = out / built['artifact']['name']
    assert sha(apk) == built['artifact']['sha256'] and apk.stat().st_size == built['artifact']['bytes']
    assert sha(out / 'link.map') == built['link_map']['sha256']
    assert sha(out / 'dnsmasq-prestrip') == built['prestrip']['sha256']
    assert (out / 'dnsmasq-prestrip').stat().st_size == built['prestrip']['bytes']
    assert built['budget'] == {'elf_max_bytes': 2200000, 'apk_max_bytes': 1200000}
    fits = (out / 'dnsmasq-rs').stat().st_size <= 2200000 and apk.stat().st_size <= 1200000
    assert fits == built['within_existing_budget']
    if source_row['name'] == 'post185-combined':
        assert fits
    inventory = {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)}
                 for p in sorted(out.iterdir()) if p.is_file()}
    builds.append({'name': source_row['name'], 'source_commit': source_row['source_commit'],
                   'source_files_verified': len(source_row['source_files']),
                   'source_manifest_sha256': source_row['source_manifest_sha256'],
                   'git_identity_sha256': source_row['git_identity_sha256'],
                   'remote_output': str(out), 'files': inventory,
                   'elf_layout': layout, 'budget': built['budget'],
                   'within_existing_budget': fits,
                   'budget_scope': 'diagnostic descriptive/excluded' if source_row['name'].endswith('allocation') else 'original product budget',
                   'sdk_inputs_unchanged': True, 'sdk_recipe_restored': built['sdk_recipe_restored'],
                   'sdk_recipe_backup_absent': True, 'sdk_recipe_current_files': recipe_files,
                   'sdk_recipe_restore_basis': 'Unchanged canonical helper completed its finally restore; current files recorded, no pre-build recipe hash snapshot asserted.'})

for name, digest in plan['accepted_G']['files_sha256'].items():
    assert sha(Path(plan['accepted_G']['directory']) / name) == digest
for row in (plan['related_gate'], plan['quiet']):
    assert sha(row['path']) == row['sha256']

research = []
sdk_services = []
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) == os.getpid():
        continue
    try:
        fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
        args = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        comm = (proc / 'comm').read_text().strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if fields[0] == 'Z':
        continue
    if comm in ('dnsmasq', 'dnsmasq-rs', 'lib-dnsmasq_rs', 'bin-dnsmasq-rs', 'hosts_allocations',
                'm6a_loadgen', 'm6a_upstream', 'perf', 'cargo', 'rustc', 'device_perf_netns') or \
            '/home/ubuntu/dnsmasq-perf-20261015' in args or '/home/ubuntu/dnsmasq-image-bases/' in args:
        research.append({'pid': int(proc.name), 'comm': comm, 'args': args})
    if 'openwrt-sdk-25.12.5' in args:
        assert int(proc.name) == 564010 and fields[0] == 'S' and fields[1] == '1'
        assert args.rstrip().endswith('/staging_dir/host/bin/.faked.bin')
        assert not (proc / 'task' / proc.name / 'children').read_text().strip()
        sdk_services.append({'pid': int(proc.name), 'state': fields[0], 'ppid': 1,
                             'cpu_ticks': int(fields[11]) + int(fields[12]), 'args': args})
assert not research, research
controller = Path('/proc') / str(state['pid'])
controller_exited = not controller.exists() or (controller / 'stat').read_text().rsplit(')', 1)[1].split()[0] == 'Z'
assert controller_exited
locks = json.loads(Path(plan['quiet']['path']).read_text())['locks_available']
for path in locks:
    with Path(path).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

receipt = {'status': 'PASS_FROZEN_SERIAL_SDK_ORIGINAL_CONTROLS_AND_QUIET',
           'epoch': time.time(), 'controller_exited': controller_exited,
           'plan_sha256': sha(inputs / 'plan.json'), 'state_sha256': sha(inputs / 'state.json'),
           'related_gate_sha256': plan['related_gate']['sha256'], 'builds': builds,
           'controls': state['controls'], 'accepted_G_unchanged': True,
           'research_including_exact_image_C': research, 'locks_available': locks,
           'sdk_background_services': sdk_services, 'timing_started': False,
           'scope': 'Build/source/static hardening/old controls only; runtime hardening and performance remain unverified.'}
destination = inputs / 'postflight.json'
with destination.open('x') as output:
    output.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'path': str(destination), 'sha256': sha(destination), 'status': receipt['status']}))
