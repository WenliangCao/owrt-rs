#!/usr/bin/env python3
"""Combine 26 isolated results with seven serial r60 results, no omissions."""
import hashlib
import json
from pathlib import Path
import re

base = Path('/home/ubuntu/netifd-keep-v023-20261017')
parallel_dir = base / 'suite-final-7c7f527e'
parallel = json.loads((parallel_dir / 'summary.json').read_text())
case_source = (base / 'tools-final/netifd_suite.sh').read_text()
cases = [line.split('|')[0] for line in case_source.split("CASES='", 1)[1].split("'", 1)[0].splitlines()
         if line.strip()]
wireless = [name for name in cases if name.startswith('r60_')]
assert len(wireless) == 7
serial_text = (base / 'r60-serial-final.log').read_text()
serial = re.findall(r'^(\S+)\s+(ok|FAILED)\s+(\d+)s', serial_text, re.MULTILINE)
assert [name for name, _, _ in serial] == wireless
assert 'SUITE: 7 of 33 run -- 7 passed, 0 failed, 26 not selected' in serial_text
results = [{'name': name, 'status': status, 'seconds': int(seconds),
            'evidence': f'suite-final-7c7f527e/shard-{shard["shard"]}/{name}.log'}
           for shard in parallel['shards'] for name, status, seconds in shard['results']
           if name not in wireless]
results += [{'name': name, 'status': status, 'seconds': int(seconds),
             'evidence': f'r60-serial-final/{name}.log'} for name, status, seconds in serial]
assert len(results) == 33 and sorted(r['name'] for r in results) == sorted(cases)
assert all(r['status'] == 'ok' for r in results)
identity = {
    'candidate': hashlib.sha256((base / 'target-fixed/aarch64-unknown-linux-musl/release/netifd-rs').read_bytes()).hexdigest(),
    'suite': hashlib.sha256((base / 'tools-final/netifd_suite.sh').read_bytes()).hexdigest(),
    'renewal_probe': hashlib.sha256((base / 'tools-final/netifd_renewal_keep.py').read_bytes()).hexdigest(),
}
assert parallel['identity_unchanged'] and identity == parallel['identity']
summary = {'all_passed': True, 'cases': 33, 'unique_coverage': 33,
           'identity': identity, 'results': results,
           'invalidated_parallel_cases': wireless,
           'invalidation_reason': 'The r60 variants share /tmp/r60-stub.sh and overwrite each other across mount namespaces; all seven parallel r60 results were discarded and run serially with the unchanged scripts.',
           'unchanged_comparators': True}
(base / 'final-suite-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'all_passed': True, 'cases': 33, 'candidate': identity['candidate']}, sort_keys=True))
