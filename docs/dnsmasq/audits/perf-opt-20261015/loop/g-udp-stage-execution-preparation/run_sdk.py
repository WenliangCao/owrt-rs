"""Run the original canonical SDK argv once after the original related gates."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

inputs = Path('/home/ubuntu/dnsmasq-perf-20261015/loop/private/g-udp-stage-inputs')
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
plan = json.loads((inputs / 'manifest.json').read_text())
assert os.getuid() == 1001 and os.sched_getaffinity(0) == {1}
assert not [name for name in os.environ if name.startswith('CARGO_PROFILE_RELEASE_')]
assert sha(inputs / 'related-verified.json') == '72a760276ef92bd9555e8aca5674cc708909d81de79b7f2afe1bb5a30d026825'
gate = json.loads((inputs / 'related-verified.json').read_text())
assert gate['status'] == 'PASS_FRESH_G_STAGE_ORIGINAL_THREE_RELATED_SELECTIONS'
assert gate['source_commit'] == plan['source_commit'] and gate['controller_exited']
assert not Path('/proc/1034063').exists()
builder = Path(plan['canonical_builder']['remote_path'])
assert sha(builder) == plan['canonical_builder']['sha256']
assert sha(builder.with_name('build_package.py')) == plan['canonical_builder']['helper_sha256']
source = Path(plan['planned_remote_source'])
assert sha(source / 'research-git-identity.json') == plan['git_identity_sha256']
for name, digest in plan['source_files'].items():
    assert sha(source / name) == digest
assert not Path(plan['planned_remote_sdk_output']).exists()
lock_path = Path('/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/.owrt-dnsmasq-build.lock')
with lock_path.open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(lock, fcntl.LOCK_UN)
argv = plan['sdk_argv']
(inputs / 'sdk-command.json').write_text(json.dumps(argv, indent=2) + '\n')
started = time.time()
with (inputs / 'sdk.stdout').open('xb') as out, (inputs / 'sdk.stderr').open('xb') as err:
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
receipt = {'returncode': result.returncode, 'started_epoch': started, 'finished_epoch': time.time(),
           'argv': argv, 'source_commit': plan['source_commit'], 'related_receipt_sha256': sha(inputs / 'related-verified.json'),
           'scope': 'Original canonical SDK diagnostic build once; no device or timing action.'}
(inputs / 'sdk-exit.json').write_text(json.dumps(receipt, indent=2) + '\n')
assert result.returncode == 0
print(json.dumps(receipt))
