"""Stage the named Git archive and verify original gate prerequisites; no build."""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import sys
import tarfile
import time

sha = lambda data: hashlib.sha256(data).hexdigest()
root = Path('/home/ubuntu/dnsmasq-perf-20261015')
inputs = root / 'loop/private/g-udp-stage-inputs'
source = root / 'root/source-g-udp-stage'
release_path = root / 'correctness/private/owner-ready-frames-release-to-root.json'
release_sha = '7420a7cc401c2a28b6d14f1c38b400f050aee155d9f7133e156e2ce30bd66c8d'
assert sha(release_path.read_bytes()) == release_sha
assert not inputs.exists() and not source.exists()
raw = sys.stdin.buffer.read()
assert sha(raw) == sys.argv[1]
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
    members = tar.getmembers()
    assert len(members) == len({m.name for m in members})
    for member in members:
        path = PurePosixPath(member.name)
        assert member.isfile() and not path.is_absolute() and '..' not in path.parts
    files = {m.name: tar.extractfile(m).read() for m in members}
assert set(files) == {'source.tar.gz', 'manifest.json', 'commands.json',
                      'run_g_udp_stage_related.py', 'source-files.json'}
plan = json.loads(files['manifest.json'])
assert plan['source_commit'] == 'a34e73107bc15f29b29b83499ceb0e0bc746d915'
assert plan['root_explicit_quiet']['actual_sha256'] == release_sha
assert plan['root_explicit_quiet']['root_authorized_non_timing_execution']
assert sha(files['source.tar.gz']) == plan['full_archive']['sha256']
assert sha(files['source-files.json']) == plan['source_manifest_sha256']
assert json.loads(files['source-files.json']) == plan['source_files']
assert sha(files['run_g_udp_stage_related.py']) == plan['adapted_related_runner']['sha256']
assert json.loads(files['commands.json']) == plan['related_commands']
for path in [root / 'loop/private/g-udp-stage-linux-gates-20261016',
             root / 'root/private/sdk-g-udp-stage']:
    assert not path.exists()
builder = Path(plan['canonical_builder']['remote_path'])
assert sha(builder.read_bytes()) == plan['canonical_builder']['sha256']
assert sha(builder.with_name('build_package.py').read_bytes()) == plan['canonical_builder']['helper_sha256']

excluded = {os.getpid()}
cursor = os.getpid()
while cursor > 1:
    cursor = int((Path('/proc') / str(cursor) / 'stat').read_text().rsplit(')', 1)[1].split()[1])
    excluded.add(cursor)
research = []
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) in excluded:
        continue
    try:
        state = (proc / 'stat').read_text().rsplit(')', 1)[1].split()[0]
        command = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
    if state != 'Z' and any(marker in command for marker in [str(root), '/home/ubuntu/dnsmasq-image-bases/',
                                                            'dnsmasq-image-runner', '/home/ubuntu/dnsmasq-cargo-target']):
        research.append({'pid': int(proc.name), 'command': command})
assert not research, research
locks = ['/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/.owrt-dnsmasq-build.lock',
         str(root / 'root/private/native-hit-build.lock'), '/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock']
for path in locks:
    with Path(path).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(lock, fcntl.LOCK_UN)
image = Path('/home/ubuntu/dnsmasq-image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c/usr/sbin/dnsmasq')
assert sha(image.read_bytes()) == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
assert sha((root / 'correctness/private/image-runner/dnsmasq-image-runner').read_bytes()) == '38ab1fe2268a4efdd6dbf718d528f89cf2bbfb8d5e877f233b3752c023e81cfd'

with tarfile.open(fileobj=io.BytesIO(files['source.tar.gz']), mode='r:gz') as tar:
    members = tar.getmembers()
    assert len(members) == len({m.name for m in members})
    assert sum(m.isfile() for m in members) == plan['full_archive']['regular_files_including_identity']
    for member in members:
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts and (member.isfile() or member.isdir())
        assert member.mode in (0o644, 0o755)
    source.mkdir()
    for member in members:
        target = source / member.name
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            data = tar.extractfile(member).read()
            target.write_bytes(data)
            assert target.read_bytes() == data
        target.chmod(member.mode)
identity = json.loads((source / 'research-git-identity.json').read_text())
assert sha((source / 'research-git-identity.json').read_bytes()) == plan['git_identity_sha256']
assert identity['commit'] == plan['source_commit'] and identity['epoch'] == plan['source_date_epoch']
assert set(identity['git_blob_sha1']) == set(plan['source_files']) and len(plan['source_files']) == 180
for name, digest in plan['source_files'].items():
    data = (source / name).read_bytes()
    assert sha(data) == digest
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == identity['git_blob_sha1'][name]
for name, digest in plan['original_tools'].items():
    assert sha((source / name).read_bytes()) == digest
assert os.access(source / 'tools/dnsmasq/perf_opt_map_cc.py', os.X_OK)
(source / 'private').mkdir(exist_ok=False)
inputs.mkdir()
for name, data in files.items():
    (inputs / name).write_bytes(data)
state = {'scope': 'Exact G excluded diagnostic source staged and rehashed; no build/test/timing yet.',
         'epoch': time.time(), 'prepared': {'g-udp-stage': {'source': str(source), 'commit': plan['source_commit'],
         'verified_inputs': 180, 'identity_sha256': plan['git_identity_sha256']}}, 'builds': []}
(inputs / 'state.json').write_text(json.dumps(state, indent=2) + '\n')
account = pwd.getpwnam('ubuntu')
for base in [source, inputs]:
    for path in [base, *base.rglob('*')]:
        os.chown(path, account.pw_uid, account.pw_gid)
receipt = {'status': 'PASS_EXACT_G_STAGE_SOURCE_AND_ORIGINAL_GATE_PREFLIGHT', 'epoch': time.time(),
           'source_commit': plan['source_commit'], 'source_files_rehashed': 180,
           'source_archive_sha256': plan['full_archive']['sha256'], 'git_identity_sha256': plan['git_identity_sha256'],
           'manifest_sha256': sha(files['manifest.json']), 'runner_sha256': sha(files['run_g_udp_stage_related.py']),
           'state_sha256': sha((inputs / 'state.json').read_bytes()), 'root_quiet_sha256': release_sha,
           'research': research, 'locks_available': locks, 'source_owner_uid': source.stat().st_uid,
           'original_tools': plan['original_tools'], 'build_test_or_measurement_started': False}
path = inputs / 'preflight.json'
path.write_text(json.dumps(receipt, indent=2) + '\n')
os.chown(path, account.pw_uid, account.pw_gid)
print(json.dumps(receipt))
