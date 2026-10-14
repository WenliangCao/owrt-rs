#!/usr/bin/env python3
"""Replay retained endpoint, chain, wire-boundary and negative-cache probes.

The original four-way generators retain their historical main/before controls.
Only this run's exact-image C and frozen candidate determine current equivalence.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--rust', type=Path, required=True)
    p.add_argument('--rust-sha256', required=True)
    a = p.parse_args()
    assert sha(a.rust) == a.rust_sha256
    root, source = a.root, a.root / 'source'
    private = root / 'private'
    release = private / 'release'
    release.mkdir()
    (release / 'dnsmasq-rs').symlink_to(a.rust)
    audit = source / 'docs/dnsmasq/audits/20261014/fix7'
    image = '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'
    isolated = ['sudo', '-n', 'sh', str(source / 'tools/dnsmasq/run_isolated.sh'), 'python3']
    negative = isolated + [str(audit / 'negative/negative_final.py'), '--source', str(source),
        '--image', image, '--fix', str(a.rust), '--fix-sha256', a.rust_sha256,
        '--out', str(private / 'negative')]
    plans = [
        ('regression', ['python3', str(audit / 'regression/run.py'), '--root', str(root),
                        '--fix-sha', a.rust_sha256, '--jobs', '2']),
        ('boundary', ['python3', str(audit / 'root/run_boundary.py'), '--root', str(root)]),
        ('negative', negative),
    ]
    receipt = dict(runner_sha256=sha(__file__), rust_sha256=a.rust_sha256, runs=[])

    def execute(plan):
        label, argv = plan
        log = private / (label + '-driver.log')
        start = time.time()
        with log.open('xb') as handle:
            proc = subprocess.run(argv, stdout=handle, stderr=subprocess.STDOUT, timeout=900)
        return dict(label=label, argv=argv, exit=proc.returncode, started=start,
                    ended=time.time(), log_sha256=sha(log))

    with ThreadPoolExecutor(max_workers=2) as pool:
        for row in pool.map(execute, plans):
            receipt['runs'].append(row)
            (private / 'history-invocations.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print(json.dumps(row), flush=True)
    assert all(row['exit'] == 0 for row in receipt['runs'])
    large = isolated + [str(audit / 'negative/soa_large_terminal.py'), '--source', str(source),
        '--image', image, '--fix', str(a.rust), '--fix-sha256', a.rust_sha256,
        '--config-evidence', str(private / 'negative/negative/summary.json'),
        '--out', str(private / 'large-soa')]
    row = execute(('large-soa', large))
    receipt['runs'].append(row)
    (private / 'history-invocations.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(row), flush=True)
    assert row['exit'] == 0
    assert sha(a.rust) == a.rust_sha256


if __name__ == '__main__':
    main()
