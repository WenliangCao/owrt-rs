#!/usr/bin/env python3
"""Independent bounded recheck of recovery finding only, on disposable roots.

Pre-experiment: the added manifest digest/layout binding should reject the same
missing-odhcpd input before staging any path; exact historic ten and final eleven
sets should still restore. Prediction: missing exits nonzero, all active hashes
unchanged; each positive exits zero and all active targets equal stock hashes.
Hashes, modes and exit codes are exact correctness signals; no timing or build.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


assert os.geteuid() == 0 and not Path('/etc/openwrt_release').exists()
out, fixed_script = map(Path, sys.argv[1:])
expected_script = '96d6677abebc2a14012f1ab43f885cf614c96f73bcc189005674bfbda0d81abc'
assert sha(fixed_script) == expected_script
out.mkdir(parents=True, exist_ok=False)
sources = {
    'eleven': Path('/home/ubuntu/odhcpd-image-v024-20261018/rootfs'),
    'ten': Path('/home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs'),
}
metadata = 'usr/share/owrt-control-plane/'
script = '''set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs -o mode=0755 tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
exec chroot "$root" /usr/sbin/owrt-recover-c
'''
results = []
for case, source_kind in [('missing-odhcpd', 'eleven'), ('normal-eleven', 'eleven'), ('historical-ten', 'ten')]:
    source = sources[source_kind]
    release = json.loads((source / (metadata + 'release.json')).read_text())
    assert release['layout'] == 'native-' + source_kind
    items = [*release['components'].values(), *release['integration_files'].values()]
    watched = [item['path'].lstrip('/') for item in items]
    watched += [item['recovery_path'].lstrip('/') for item in items]
    watched += [metadata + 'release.json', metadata + 'stock.sha256', 'usr/sbin/owrt-recover-c']
    before = {p: sha(source / p) for p in watched}
    case_out = out / case
    case_out.mkdir()
    root = case_out / 'rootfs'
    subprocess.run(['cp', '-a', str(source), str(root)], check=True)
    shutil.copyfile(fixed_script, root / 'usr/sbin/owrt-recover-c')
    (root / 'usr/sbin/owrt-recover-c').chmod(0o755)
    active_before = {item['path']: sha(root / item['path'].lstrip('/')) for item in items}
    sums = root / (metadata + 'stock.sha256')
    if case == 'missing-odhcpd':
        rows = [line for line in sums.read_text().splitlines()
                if not line.endswith(' /usr/libexec/owrt-stock/usr/sbin/odhcpd')]
        assert len(rows) == 12
        sums.write_text('\n'.join(rows) + '\n')
    result = subprocess.run(['unshare', '--mount', '--net', '--pid', '--uts', '--ipc', '--fork', '--kill-child',
                             '/bin/sh', '-c', script, 'sh', str(root)], capture_output=True, text=True, timeout=30)
    active_after = {item['path']: sha(root / item['path'].lstrip('/')) for item in items}
    record = {'case': case, 'source': str(source), 'source_commit': release['source_commit'],
              'layout': release['layout'], 'fixed_script_sha256': sha(root / 'usr/sbin/owrt-recover-c'),
              'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
              'active_before': active_before, 'active_after': active_after,
              'source_unchanged': before == {p: sha(source / p) for p in watched},
              'no_staging_files': not list(root.rglob('*.owrt-recovery-new'))}
    (case_out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    assert record['source_unchanged'] and record['no_staging_files']
    if case == 'missing-odhcpd':
        assert result.returncode != 0 and active_before == active_after
        assert 'stock recovery manifest identity mismatch' in result.stderr
    else:
        assert result.returncode == 0
        for item in items:
            active = root / item['path'].lstrip('/')
            recovery = root / item['recovery_path'].lstrip('/')
            assert active_after[item['path']] == item['stock_sha256']
            assert active.stat().st_mode == recovery.stat().st_mode
    summary = {key: value for key, value in record.items() if key not in ('active_before', 'active_after')}
    summary['active_target_count'] = len(active_after)
    summary['active_hashes_unchanged'] = active_before == active_after
    results.append(summary)
receipt = {'results': results, 'physical_router_accessed': False, 'product_built': False}
(out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps(receipt, indent=2))
