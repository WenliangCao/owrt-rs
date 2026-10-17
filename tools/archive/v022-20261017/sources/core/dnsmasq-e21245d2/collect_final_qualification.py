#!/usr/bin/env python3
"""Collect finished Oracle observations; keep backing roots on Oracle."""
import hashlib
import json
from pathlib import Path
import subprocess

LOCAL = Path(__file__).resolve().parent
REMOTE = '/srv/owrt-archive/unified-work/private/dnsmasq-final'
out = LOCAL / 'final-qualification'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
# Read only at the controller exit event. Never use this as a status poll.
read = subprocess.run(['ssh', 'owrt-build-host', 'cat ' + REMOTE + '/qualification.json'], check=True, capture_output=True, text=True)
final = json.loads(read.stdout)
assert final['status'] != 'running', 'controller has not reached its terminal state'
subprocess.run(['rsync', '-a', '--rsync-path=sudo -n rsync', '--exclude=rootfs/',
                '--exclude=rootfs-overlay/', '--exclude=__pycache__/',
                'owrt-build-host:' + REMOTE + '/', str(out) + '/'], check=True)
assert json.loads((out / 'qualification.json').read_text()) == final
verified = {}
for name, row in final['receipts'].items():
    remote = row['path']
    if remote.startswith(REMOTE + '/'):
        path = out / remote.removeprefix(REMOTE + '/')
    elif name == 'native':
        path = LOCAL / 'native/summary.json'
    elif name == 'source-corpus-reuse':
        path = LOCAL / 'corpus-reuse.json'
    else:
        raise ValueError('unexpected receipt ' + remote)
    assert sha(path) == row['sha256'], name
    verified[name] = {'path': str(path), 'sha256': sha(path)}
preview = out / 'startup/preview-result.json'
if preview.exists():
    runtime = json.loads(preview.read_text())['runtime_root']
    assert runtime.startswith('/tmp/owrt-archive-core-slot-01') and runtime.rsplit('-', 1)[-1] == '39048357460'
    destination = out / 'startup-raw'
    destination.mkdir(exist_ok=False)
    subprocess.run(['rsync', '-a', '--rsync-path=sudo -n rsync', '--exclude=rootfs/',
                    '--exclude=rootfs-overlay/', 'owrt-build-host:' + runtime + '/', str(destination) + '/'], check=True)
summary = {'status': final['status'], 'source_commit': final['source_commit'],
           'elf_sha256': final['elf_sha256'], 'qualification_sha256': sha(out / 'qualification.json'),
           'verified_receipts': verified,
           'scope': 'Original receipts, raw observations, inputs and logs collected; duplicate backing rootfs trees remain on Oracle.',
           'oracle_root': REMOTE, 'local_root': str(out)}
with (LOCAL / 'final-qualification-collection.json').open('x') as stream:
    json.dump(summary, stream, indent=2)
    stream.write('\n')
print(json.dumps(summary, indent=2))
