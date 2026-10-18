#!/usr/bin/env python3
"""Run the unchanged explicit suite in four shards and verify exact coverage."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

base = Path('/home/ubuntu/netifd-keep-v023-20261017')
suite = base / 'tools-final/netifd_suite.sh'
candidate = base / 'target-fixed/aarch64-unknown-linux-musl/release/netifd-rs'
examples = candidate.parent / 'examples'
rootfs = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
out = base / 'suite-final-7c7f527e'
out.mkdir(exist_ok=False)
source = suite.read_text()
cases = [line.split('|')[0] for line in source.split("CASES='", 1)[1].split("'", 1)[0].splitlines()
         if line.strip()]
assert len(cases) == 33 and len(set(cases)) == 33


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


identity = {'candidate': sha(candidate), 'suite': sha(suite),
            'renewal_probe': sha(suite.parent / 'netifd_renewal_keep.py')}


def run_shard(index):
    selected = cases[index::4]
    logfile = out / f'shard-{index}.log'
    env = dict(os.environ, SUBSET=' '.join(selected),
               NETWORK_CONFIG=str(base / 'private/config-input/network'),
               WIRELESS_CONFIG=str(base / 'private/config-input/wireless'))
    with logfile.open('w') as log:
        process = subprocess.run(['bash', str(suite), str(rootfs), str(candidate),
                                  str(out / f'shard-{index}'), str(examples)],
                                 env=env, stdout=log, stderr=subprocess.STDOUT)
    results = re.findall(r'^(\S+)\s+(ok|FAILED)\s+(\d+)s', logfile.read_text(), re.MULTILINE)
    names = [name for name, _, _ in results]
    valid = process.returncode == 2 and names == selected and all(v == 'ok' for _, v, _ in results)
    return {'shard': index, 'selected': selected, 'results': results,
            'returncode': process.returncode, 'passed': valid}


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    shards = list(executor.map(run_shard, range(4)))
covered = [name for shard in shards for name, _, _ in shard['results']]
identity_after = {'candidate': sha(candidate), 'suite': sha(suite),
                  'renewal_probe': sha(suite.parent / 'netifd_renewal_keep.py')}
passed = all(shard['passed'] for shard in shards) and sorted(covered) == sorted(cases) and identity == identity_after
summary = {'all_passed': passed, 'cases': len(cases), 'covered': len(covered),
           'identity': identity, 'identity_unchanged': identity == identity_after, 'shards': shards}
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'all_passed': passed, 'cases': len(cases), 'covered': len(covered),
                  'identity': identity}, sort_keys=True))
sys.exit(0 if passed else 1)
