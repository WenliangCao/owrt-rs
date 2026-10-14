#!/usr/bin/env python3
"""Fresh FIX6 F3 reproduction and adjacent controls on the isolated Oracle."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def profiles():
    result = []
    for family in ('txt', 'dual', 'opaque'):
        for size in (193, 201, 220):
            host = 'host-record=example,192.0.2.20'
            if family == 'dual':
                host += ',2001:db8::20'
            config = ('host-record=target.example,192.0.2.77\n' + host + '\n'
                      'mx-host=target.example,example,10\n')
            if family == 'opaque':
                config += ('dns-rr=target.example,65401,' + '11' * 500 + '\n') * 31
                config += 'dns-rr=target.example,65401,' + '22' * (size + 209) + '\n'
            else:
                config += ''.join('txt-record=target.example,' + f'{i:03d}' + 'x' * 252 + '\n'
                                  for i in range(60))
                config += 'txt-record=target.example,' + 'z' * size + '\n'
            result.append([f'{family}-{size}', config, [255]])
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    root, source = args.root, args.root / 'source'
    out = root / 'private/boundary'
    out.mkdir(exist_ok=False)
    original = source / 'docs/dnsmasq/audits/20261014/fix5/dns/terminal_extended.py'
    direct = out / 'direct-target.py'
    text = original.read_text()
    assert text.count("w.query('alias.example', kind)") == 2
    direct.write_text(text.replace("w.query('alias.example', kind)", "w.query('target.example', kind)"))
    report = {'runner_sha256': sha(__file__), 'runs': []}
    for name, driver, values in [('alias', original, profiles()),
                                 ('direct', direct, [p for p in profiles() if p[0].endswith('-220')])]:
        profile = out / (name + '-profiles.json')
        profile.write_text(json.dumps(values, indent=2) + '\n')
        argv = ['sudo', '-n', 'sh', str(source / 'tools/dnsmasq/run_isolated.sh'),
                'python3', str(driver), '--source', str(source), '--image',
                '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files',
                '--main', '/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs',
                '--before', '/home/ubuntu/dnsmasq-audit-fix6-20261014/private/root-release-recheck/dnsmasq-rs',
                '--fix', str(root / 'private/release/dnsmasq-rs'),
                '--profiles', str(profile), '--out', str(out / name)]
        started = time.time()
        log = out / (name + '.log')
        with log.open('xb') as output:
            process = subprocess.run(argv, stdout=output, stderr=output, timeout=300)
        row = {'name': name, 'argv': argv, 'exit': process.returncode,
               'elapsed_seconds': time.time() - started,
               'files': {str(p): sha(p) for p in (driver, profile, log, out / name / 'result.json')}}
        report['runs'].append(row)
        (out / 'invocation.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(row), flush=True)
        assert process.returncode == 0


if __name__ == '__main__':
    main()
