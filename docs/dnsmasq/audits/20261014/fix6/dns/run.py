#!/usr/bin/env python3
"""Run the unchanged FIX5 DNS fixtures against the FIX6 frozen release.

Run on Oracle, outside namespaces; each recorded command creates its own.
Raw logs and rootfs overlays remain in the private output tree.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--only', help='Comma-separated group names')
    parser.add_argument('--extra-profiles', type=Path)
    args = parser.parse_args()
    root = args.root
    source = root / 'source'
    old = source / 'docs/dnsmasq/audits/20261014/fix5/dns'
    plan = json.loads((old / 'invocations.json').read_text())
    for invocation in plan:
        invocation['argv'] = [s.replace('dnsmasq-audit-fix5-20261014', root.name)
                              for s in invocation['argv']]
    common = ['sudo', '-n', 'sh', str(source / 'tools/dnsmasq/run_isolated.sh'),
              'python3', str(old / 'terminal_extended.py'),
              '--source', str(source), '--image',
              '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files',
              '--main', '/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs',
              '--before', '/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs',
              '--fix', str(root / 'private/release/dnsmasq-rs')]
    extended = []
    for name, profile, extra in [
        ('f2-01', 'cname-profiles.json', ['--upstream-cnames']),
        ('f2-02', 'cname-profiles.json', ['--upstream-cnames']),
        ('f2-anchor', 'cname-profiles.json', ['--upstream-cnames', '--host-anchor']),
        ('candidate-anchor', 'candidate-profiles.json', ['--host-anchor']),
        ('extended-controls', 'controls-profiles.json', []),
    ]:
        extended.append({'name': name, 'argv': common + ['--profiles', str(old / profile),
                         '--out', str(root / 'private' / name)] + extra})
    plan = extended + plan
    if args.extra_profiles:
        for name, extra in [('chain-dynamic', []), ('chain-anchor', ['--host-anchor'])]:
            plan.append({'name': name, 'argv': common + ['--profiles', str(args.extra_profiles),
                         '--out', str(root / 'private' / name)] + extra})
    if args.only:
        names = args.only.split(',')
        plan = [item for item in plan if item['name'] in names]
        assert len(plan) == len(names)
    receipt_dir = root / 'dns'
    receipt_dir.mkdir(exist_ok=True)
    tag = args.only or 'all'
    (receipt_dir / (tag + '-invocations.json')).write_text(json.dumps(plan, indent=2) + '\n')
    results = []
    for item in plan:
        name, argv = item['name'], item['argv']
        start = time.time()
        log = root / 'private' / (name + '.driver.log')
        with log.open('xb') as output:
            process = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT)
        result = {'name': name, 'exit': process.returncode, 'elapsed_seconds': time.time() - start,
                  'log_private_path': str(log), 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
        results.append(result)
        (receipt_dir / (tag + '-results.json')).write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if process.returncode:
            raise SystemExit(process.returncode)


if __name__ == '__main__':
    main()
