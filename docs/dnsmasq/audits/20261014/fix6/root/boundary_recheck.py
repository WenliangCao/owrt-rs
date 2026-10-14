#!/usr/bin/env python3
"""Fresh TXT boundary and valid below-limit controls; run on Oracle."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

root = Path('/home/ubuntu/dnsmasq-audit-fix6-20261014')
source = root / 'source'
out = root / 'private/root-boundary-recheck'
out.mkdir(exist_ok=False)
profiles = []
for size in (193, 201, 220):
    config = ('host-record=target.example,192.0.2.77\n'
              'host-record=example,192.0.2.20\n'
              'mx-host=target.example,example,10\n')
    config += ''.join('txt-record=target.example,' + f'{i:03d}' + 'x' * 252 + '\n'
                      for i in range(60))
    config += 'txt-record=target.example,' + 'z' * size + '\n'
    profiles.append([f'txt-tail-{size}', config, [255]])
profile = out / 'profiles.json'
profile.write_text(json.dumps(profiles, indent=2) + '\n')
argv = ['sudo', '-n', 'sh', str(source / 'tools/dnsmasq/run_isolated.sh'),
        'python3', str(source / 'docs/dnsmasq/audits/20261014/fix5/dns/terminal_extended.py'),
        '--source', str(source), '--image',
        '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files',
        '--main', '/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs',
        '--before', '/home/ubuntu/dnsmasq-audit-fix5-20261014/private/release/dnsmasq-rs',
        '--fix', str(root / 'private/root-release-recheck/dnsmasq-rs'),
        '--profiles', str(profile), '--out', str(out / 'dns')]
started = time.time()
with (out / 'driver.log').open('xb') as log:
    process = subprocess.run(argv, stdout=log, stderr=log, check=True)
receipt = {'argv': argv, 'exit': process.returncode, 'elapsed_seconds': time.time() - started,
           'files': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in (profile, out / 'driver.log', out / 'dns/result.json', Path(__file__))}}
(out / 'invocation.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt))
