#!/usr/bin/env python3
"""One isolated recovery-negative-control; never starts a daemon or touches flash.

Pre-experiment: hypothesis = recovery checks an allowlisted 12/13-line set but
does not bind the set to the image layout or stock_manifest_sha256. Prediction:
removing only odhcpd from native-eleven stock.sha256 returns zero, restores ten
programs, and leaves odhcpd Rust. Exact hashes/exit code are the instrument; no
performance metric, timing selection, new build, or physical runtime is involved.
The exact final rootfs and its BusyBox script are used. One case, fresh directory.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


source = Path('/home/ubuntu/odhcpd-image-v024-20261018/rootfs')
out = Path(sys.argv[1])
assert os.geteuid() == 0 and not Path('/etc/openwrt_release').exists()
out.mkdir(parents=True, exist_ok=False)
release = json.loads((source / 'usr/share/owrt-control-plane/release.json').read_text())
assert release['layout'] == 'native-eleven'
paths = ['usr/share/owrt-control-plane/release.json',
         'usr/share/owrt-control-plane/stock.sha256', 'usr/sbin/owrt-recover-c']
paths += [c['path'].lstrip('/') for c in release['components'].values()]
paths += [c['recovery_path'].lstrip('/') for c in release['components'].values()]
source_before = {p: sha(source / p) for p in paths}
root = out / 'rootfs'
subprocess.run(['cp', '-a', str(source), str(root)], check=True)
sums = root / 'usr/share/owrt-control-plane/stock.sha256'
original = sums.read_text()
rows = [line for line in original.splitlines() if not line.endswith(' /usr/libexec/owrt-stock/usr/sbin/odhcpd')]
assert len(rows) == 12 and len(original.splitlines()) == 13
sums.write_text('\n'.join(rows) + '\n')
script = '''set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
exec chroot "$root" /usr/sbin/owrt-recover-c
'''
result = subprocess.run(['unshare', '--mount', '--net', '--pid', '--uts', '--ipc', '--fork', '--kill-child',
                         '/bin/sh', '-c', script, 'sh', str(root)], capture_output=True, text=True, timeout=30)
states = {name: ('stock' if sha(root / c['path'].lstrip('/')) == c['stock_sha256'] else
                 'rust' if sha(root / c['path'].lstrip('/')) == c['rust_sha256'] else 'other')
          for name, c in release['components'].items()}
source_after = {p: sha(source / p) for p in paths}
receipt = {'source_commit': release['source_commit'], 'layout': release['layout'],
           'source_before_sha256': source_before, 'source_unchanged': source_before == source_after,
           'stock_manifest_expected_sha256': release['stock_manifest_sha256'],
           'stock_manifest_supplied_sha256': sha(sums), 'returncode': result.returncode,
           'stdout': result.stdout, 'stderr': result.stderr, 'component_states': states,
           'physical_router_accessed': False}
(out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: v for k, v in receipt.items() if k != 'source_before_sha256'}, indent=2))
assert source_before == source_after
assert result.returncode == 0 and states['odhcpd'] == 'rust'
assert all(value == 'stock' for key, value in states.items() if key != 'odhcpd')
