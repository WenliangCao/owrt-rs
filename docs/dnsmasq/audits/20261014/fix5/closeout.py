#!/usr/bin/env python3
"""Read-only FIX5 Oracle artifact/source/remaining-process closeout."""
import fcntl
import hashlib
import json
from pathlib import Path
import time

root = Path('/home/ubuntu/dnsmasq-audit-fix5-20261014')
inputs = json.loads((root / 'closeout-input.json').read_text())
sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
for name, expected in inputs['source_inputs'].items():
    assert sha(root / 'source' / name) == expected, name
paths = {
    'c': '/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files/usr/sbin/dnsmasq',
    'main': '/home/ubuntu/dnsmasq-audit-fix3-20261013/private/release-main/dnsmasq-rs',
    'before_sdk': '/home/ubuntu/dnsmasq-fix4-repair-20261013/private/sdk-verify-final/payload/usr/sbin/dnsmasq',
    'before_release': str(root / 'private/release-before/dnsmasq-rs'),
    'head_release': str(root / 'private/release/dnsmasq-rs'),
}
expected = [
    '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87',
    'ad103449368b6f6f94a988163165b24557af54f35eb9db9a8decdfef600fd863',
    '55ea363f626f3e14279f280b1dba708a1d751877ab22a3503d312985c9efd6ca',
    '45375655c62112c6d99fd1f46034352f1b37350fa92c38b0ccd8fcbdff301827',
    '7a56d4302dc8fbd3df8d5c441d2b910c0cf2222d9d3b105ef599ad4ca2150f7c',
]
artifacts = {}
for (key, path), digest in zip(paths.items(), expected):
    assert sha(path) == digest, key
    artifacts[key] = {'path': path, 'sha256': digest}
remaining = []
for proc in Path('/proc').glob('[0-9]*'):
    try:
        comm = (proc / 'comm').read_text().strip()
        if comm in {'dnsmasq', 'dnsmasq-rs', 'dnsmasq-main', 'dnsmasq-before', 'cargo', 'rustc'}:
            remaining.append({'pid': int(proc.name), 'comm': comm})
    except (OSError, ProcessLookupError):
        pass
assert not remaining, remaining
lock = '/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock'
with open(lock, 'r') as handle:
    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(handle, fcntl.LOCK_UN)
print(json.dumps({'passed': True, 'timestamp': time.time(), 'product_head': inputs['head'],
                  'source_inputs_checked': len(inputs['source_inputs']), 'artifacts': artifacts,
                  'remaining_service_or_build_processes': remaining,
                  'build_lock_obtained_and_released': lock}, indent=2))
