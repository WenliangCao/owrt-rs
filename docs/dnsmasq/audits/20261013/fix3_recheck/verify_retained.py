#!/usr/bin/env python3
"""Rehash retained repair evidence; does not rerun or reinterpret its tests."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
assert not a.out.exists()
base = a.source / 'docs/dnsmasq/audits/20261012/fix3_repairs'
files = {}
indices = {}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


for name in ('functional/validation-types-raw-index.json',
             'functional/hosts-compat-supplement-raw-index.json',
             'performance/types-raw-index.json'):
    path = base / name
    indices[name] = sha(path)
    data = json.loads(path.read_text())
    for row in data.get('files', []):
        files[row['path']] = row['sha256']
    for row in data.values():
        if isinstance(row, dict) and 'path' in row and 'sha256' in row:
            files[row['path']] = row['sha256']
    for window in data.get('windows', []):
        for name, expected in window['files'].items():
            files[str(Path(window['directory']) / name)] = expected
failed = []
for path, expected in files.items():
    if not Path(path).is_file() or sha(path) != expected:
        failed.append(path)
result = dict(scope=__doc__, controller_sha256=sha(__file__), indices=indices,
              checked_files=len(files), files=files, failures=failed, passed=not failed)
a.out.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'checked_files': len(files), 'failures': failed, 'passed': not failed}))
raise SystemExit(bool(failed))
