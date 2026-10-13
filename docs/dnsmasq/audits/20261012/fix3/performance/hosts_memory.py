#!/usr/bin/env python3
"""Fresh main/fix/C comparison of 48 MiB ordinary addn-hosts comments.

Per-process address-space/HWM evidence, not timing: other builds may coexist.
Retain failed startup cases instead of stopping the entire baseline matrix.
"""
from pathlib import Path
import hashlib
import json
import os
import sys

ROOT = Path('/home/ubuntu/dnsmasq-audit-fix3-20261013')
SOURCE = ROOT / 'source-fix'
OUT = ROOT / 'private/performance-hosts-memory'
IMAGE = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
sys.path.insert(0, str(SOURCE / 'tools/dnsmasq'))
from audit_20261011_hosts_memory import run_case
from m2_rootfs import image_elf_command

assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
OUT.mkdir(exist_ok=False)
binaries = {'main': ROOT / 'private/release-main/dnsmasq-rs',
            'fix': ROOT / 'private/release-fix/dnsmasq-rs',
            'c-image': IMAGE / 'usr/sbin/dnsmasq'}
result = dict(scope='48 MiB short comments + one valid host; fresh release main/fix and exact-image C; memory only, no timing claims',
              binary_sha256={name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
              helper_sha256=hashlib.sha256((SOURCE / 'tools/dnsmasq/audit_20261011_hosts_memory.py').read_bytes()).hexdigest(),
              cases=[])
for limit, reload in ((0, False), (32, False), (32, True)):
    for name, binary in binaries.items():
        try:
            row = run_case(name, image_elf_command(IMAGE, binary), OUT, limit, reload)
        except Exception as error:
            row = dict(implementation=name, address_space_limit_mib=limit, reload=reload,
                       error=str(error).replace(str(OUT), '<out>'))
        result['cases'].append(row)
        (OUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
