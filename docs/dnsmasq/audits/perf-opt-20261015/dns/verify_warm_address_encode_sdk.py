"""Rehash the single warm6dad canonical SDK build and quiet state."""
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


root = Path('/home/ubuntu/dnsmasq-perf-20261015')
inputs = root / 'dns/private/warm-address-encode-execution-20261016'
plan_path = root / 'correctness/private/warm-address-encode-execution-plan.json'
assert sha(plan_path) == 'd3edf2b7339fe85aecb527569382ccb60573d5f3aa15ef8140eeb9dcd56e2418'
plan = json.loads(plan_path.read_text())
command = json.loads((inputs / 'sdk-command.json').read_text())
assert command['status'] == 'SDK_COMMAND_FINISHED' and command['returncode'] == 0
assert command['argv'] == plan['canonical_sdk_argv']
for stream in ('stdout', 'stderr'):
    assert sha(inputs / ('sdk.' + stream)) == command[stream + '_sha256']
gate = root / 'correctness/private/warm-address-encode-related-verified.json'
assert sha(gate) == command['related_verified_sha256']
builder_path = Path(plan['canonical_sdk_argv'][1])
assert sha(builder_path) == plan['canonical_builder']['sha256']
assert sha(builder_path.with_name('build_package.py')) == plan['canonical_builder']['helper_sha256']
sys.path.insert(0, str(builder_path.parent))
spec = importlib.util.spec_from_file_location('unchanged_canonical_builder', builder_path)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
helper = builder.audit
source = Path(plan['planned_remote_source'])
out = Path(plan['planned_remote_sdk_output'])
built = json.loads((out / 'build.json').read_text())
assert built['status'] == 'built-unqualified' and built['source_unchanged'] and built['sdk_recipe_restored']
assert built['source'] == str(source) and built['source_commit'] == plan['source_commit']
assert built['source_date_epoch'] == plan['source_date_epoch']
assert built['source_files'] == plan['source_files'] == helper.inputs(source)
assert built['git_identity_sha256'] == sha(source / 'research-git-identity.json') == plan['git_identity_sha256']
assert built['builder_sha256'] == plan['canonical_builder']['sha256']
assert built['build_helper_sha256'] == plan['canonical_builder']['helper_sha256']
assert built['opt_level'] == '3' and built['features'] == ''
sdk = Path(plan['canonical_sdk_argv'][plan['canonical_sdk_argv'].index('--sdk') + 1])
assert helper.sdk_inputs(sdk) == built['sdk']['files']
assert not (sdk / ('.dnsmasq-backup-' + out.name)).exists()
recipe = Path(built['sdk_recipe_path'])
recipe_files = {str(p.relative_to(recipe)): sha(p) for p in sorted(recipe.rglob('*')) if p.is_file()}
layout = helper.audit_elf((out / 'dnsmasq-rs').read_bytes(), (out / 'readelf.log').read_text())
assert layout == built['elf_layout']
assert layout['type'] == 'ET_DYN' and layout['machine'] == 'AArch64' and layout['linkage'] == 'static-pie'
assert layout['interpreter'] is None and not layout['needed'] and not layout['writable_executable_load']
assert all(layout[k] for k in ('pie', 'bind_now', 'gnu_relro', 'nx_stack'))
assert helper.audit_payload(out / 'payload') == built['payload_files']
for artifact in built['artifacts']:
    assert sha(out / artifact['path']) == artifact['sha256']
    assert (out / artifact['path']).stat().st_size == artifact['bytes']
assert sha(out / 'link.map') == built['link_map']['sha256']
assert sha(out / 'dnsmasq-prestrip') == built['prestrip']['sha256']
assert (out / 'dnsmasq-prestrip').stat().st_size == built['prestrip']['bytes']
apk = out / built['artifact']['name']
assert sha(apk) == built['artifact']['sha256'] and apk.stat().st_size == built['artifact']['bytes']
assert built['budget'] == plan['budget'] == {'elf_max_bytes': 2200000, 'apk_max_bytes': 1200000}
fits = (out / 'dnsmasq-rs').stat().st_size <= 2200000 and apk.stat().st_size <= 1200000
assert built['within_existing_budget'] == fits and fits
release = Path(plan['exclusive_slot_release']['path'])
assert sha(release) == plan['exclusive_slot_release']['sha256']
accepted_G = {'dnsmasq-rs': '9109e9871e83f652788621b2fbd5845f7d63e4bf7d05593b5098f741c31d7f99',
              'link.map': 'e1c8638fbb2ff229d736d697dae78a519a914beb975cbf017f7666dd1dbe314f',
              'build.json': 'dfb42af12c623b3eb7551bd9e821ef6fb0d63922f02a8714e7475623b9483f10'}
for name, digest in accepted_G.items():
    assert sha(root / 'root/private/sdk-cached-zero-frame' / name) == digest
research = []
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
            str(root) in args or '/home/ubuntu/dnsmasq-image-bases/' in args:
        research.append({'pid': int(proc.name), 'comm': comm, 'args': args})
assert not research, research
for pid in (command['controller_pid'], command['builder_pid']):
    assert not (Path('/proc') / str(pid)).exists()
locks = json.loads(gate.read_text())['locks_available']
for path in locks:
    with Path(path).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
inventory = {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)}
             for p in sorted(out.iterdir()) if p.is_file()}
receipt = {'status': 'PASS_ACTUAL_WARM6DAD_CANONICAL_SDK_STATIC_BUDGET_SOURCE_AND_QUIET',
           'epoch': time.time(), 'source_commit': plan['source_commit'],
           'source_files_verified': 179, 'source_manifest_sha256': plan['source_manifest_sha256'],
           'git_identity_sha256': plan['git_identity_sha256'], 'remote_output': str(out),
           'plan_sha256': sha(plan_path), 'related_verified_sha256': sha(gate),
           'command_receipt_sha256': sha(inputs / 'sdk-command.json'), 'files': inventory,
           'unchanged_canonical_builder_verified': True, 'original_opt_level': '3',
           'elf_layout': layout, 'budget': built['budget'], 'within_existing_budget': fits,
           'sdk_inputs_unchanged': True, 'sdk_recipe_restored': True,
           'sdk_recipe_restore_basis': 'Unchanged helper completed finally restoration; backup absent; current recipe files recorded without inventing a prebuild hash snapshot.',
           'sdk_recipe_current_files': recipe_files, 'accepted_G_unchanged': True,
           'controller_and_builder_exited': True, 'research_including_exact_image_C': research,
           'locks_available': locks, 'runtime_hardening_verified': False,
           'performance_timing_started': False, 'independent_review_pending': True}
destination = inputs / 'sdk-postflight.json'
with destination.open('x') as file:
    file.write(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({'path': str(destination), 'sha256': sha(destination),
                  'status': receipt['status'], 'ELF': inventory['dnsmasq-rs'], 'APK': built['artifact']}))
