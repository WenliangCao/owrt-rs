#!/usr/bin/env python3
"""Read-only final source/artifact/evidence check, after all workload processes exit."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, required=True)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
assert not a.out.exists(), 'fresh output required'
manifest = json.loads(a.manifest.read_text())
failures = []
for name, expected in manifest['files'].items():
    if not Path(name).is_file() or sha(name) != expected:
        failures.append(name)
locks = []
for path in manifest['locks']:
    with Path(path).open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locks.append({'path': path, 'available': True})
            fcntl.flock(lock, fcntl.LOCK_UN)
        except BlockingIOError:
            locks.append({'path': path, 'available': False})
ancestors = {os.getpid()}
pid = os.getppid()
while pid and pid not in ancestors:
    ancestors.add(pid)
    try:
        status = Path(f'/proc/{pid}/status').read_text()
        pid = int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
    except (FileNotFoundError, StopIteration):
        break
remaining = []
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit() or int(proc.name) in ancestors:
        continue
    try:
        command = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
        executable = os.readlink(proc / 'exe')
    except (OSError, PermissionError):
        continue
    if str(a.root) in command or str(a.root) in executable:
        remaining.append({'pid': int(proc.name), 'command': command, 'executable': executable})
result = dict(manifest_sha256=sha(a.manifest), controller_sha256=sha(__file__),
              verified_file_count=len(manifest['files']), hash_failures=failures,
              locks=locks, remaining_task_processes=remaining)
result['passed'] = not failures and not remaining and all(item['available'] for item in locks)
a.out.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
raise SystemExit(not result['passed'])
