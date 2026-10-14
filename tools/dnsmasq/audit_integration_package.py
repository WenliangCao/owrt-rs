#!/usr/bin/env python3
"""Observe exact-image APK activation and ENOSPC rollback boundaries.

Run with sudo through run_isolated.sh; outputs must be below a private/ folder.
The ENOSPC cases use a tmpfs overlay upper, not physical flash or UBIFS.
"""
import sys
import os
import json
import time
import shutil
import subprocess
from pathlib import Path
import argparse
from m2_rootfs import prepare, image_path, sha256, STOCK_SHA256
from m4_package_lifecycle import Scenario, DHCP_CONFIG, database, descendants
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--rootfs', type=Path, required=True)
parser.add_argument('--stock-apk', type=Path, required=True)
parser.add_argument('--candidate-apk', type=Path, required=True)
parser.add_argument('--candidate-elf-sha256', required=True)
parser.add_argument('--source-commit', required=True)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--scenario', choices=('activation', 'full-upgrade', 'full-rollback', 'full-stock-reinstall'), required=True)
parser.add_argument('--free-bytes', type=int, default=131072)
args = parser.parse_args()
if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
    parser.error('root inside run_isolated.sh required')
(IMAGE, STOCK, RUST, out) = (p.resolve() for p in (args.rootfs, args.stock_apk, args.candidate_apk, args.out))
if 'private' not in out.parts or out.exists() or args.free_bytes < 0:
    parser.error('fresh private output and nonnegative free bytes required')
(RSHA, mode) = (args.candidate_elf_sha256, args.scenario)
out.mkdir(parents=True, exist_ok=False)
stage = out / 'stage'
stage.mkdir()
if mode.startswith('full-'):
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=16M', 'package-fault-upper', str(stage)], check=True)
root = prepare(IMAGE, None, stage, IMAGE / 'usr/sbin/dnsmasq')
image_path(root, 'usr/sbin/dnsmasq-rs').unlink()
image_path(root, 'etc/config/dhcp').write_text(DHCP_CONFIG)
image_path(root, 'etc/dnsmasq.conf').write_text('# isolated audit config\n')
(root / 'm4').mkdir(exist_ok=True)
for (a, b) in ((STOCK, 'stock.apk'), (RUST, 'candidate.apk')):
    shutil.copy2(a, root / 'm4' / b)
report = {'mode': mode, 'source_commit': args.source_commit, 'stock_elf': STOCK_SHA256, 'rust_elf': RSHA, 'observations': [], 'argv': sys.argv, 'script_sha256': sha256(Path(__file__)), 'helpers': {name: sha256(Path(__file__).with_name(name)) for name in ('m2_rootfs.py', 'm4_package_lifecycle.py')}, 'stock_apk_sha256': sha256(STOCK), 'candidate_apk_sha256': sha256(RUST), 'scope': 'isolated exact-image APK; synthetic no-LAN config; disk fault uses bounded tmpfs overlay upper, not UBIFS'}
case = Scenario(root, out, report)

def observe(label):
    row = {'label': label, 'packages': {k: v for (k, v) in database(root).items() if k == 'dnsmasq'}, 'binary': None, 'processes': []}
    p = root / 'usr/sbin/dnsmasq'
    if p.exists():
        row['binary'] = {'sha256': sha256(p), 'bytes': p.stat().st_size}
    row['service'] = case.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True})
    for instance in row['service'].get('dnsmasq', {}).get('instances', {}).values():
        pid = instance.get('pid')
        if pid:
            for child in {pid} | descendants(pid):
                try:
                    row['processes'].append({'pid': child, 'sha256': sha256(Path(f'/proc/{child}/exe')), 'exe': os.readlink(f'/proc/{child}/exe')})
                except OSError:
                    pass
    row['check'] = case.run(['/usr/bin/apk', '--no-network', '--allow-untrusted', 'audit', '--system'], 'audit-' + label, False)
    report['observations'].append(row)
    return row
try:
    case.start_support()
    case.run(['/etc/init.d/dnsmasq', 'start'], 'stock-start')
    report['stock_service'] = case.service(STOCK_SHA256, 'stock')
    if mode == 'activation':
        case.apk(['add', '/m4/candidate.apk'], 'upgrade')
        time.sleep(1)
        observe('after-upgrade-no-restart')
        case.activate_after_transaction('upgrade')
        case.service(RSHA, 'rust')
        case.apk(['add', '/m4/stock.apk'], 'rollback')
        time.sleep(1)
        observe('after-rollback-no-restart')
        case.activate_after_transaction('rollback')
        case.service(STOCK_SHA256, 'c-restored')
        observe('after-rollback-restart')
    else:
        if mode == 'full-rollback':
            case.apk(['add', '/m4/candidate.apk'], 'pre-fault-upgrade')
            case.activate_after_transaction('pre-fault-upgrade')
            case.service(RSHA, 'rust')
        observe('before-space-fault')
        fs = os.statvfs(root)
        free = fs.f_bavail * fs.f_frsize
        remaining = args.free_bytes
        filler = root / 'audit-space-filler'
        with filler.open('wb') as stream:
            left = max(0, free - remaining)
            block = b'x' * 65536
            while left:
                size = min(left, len(block))
                stream.write(block[:size])
                left -= size
        fs = os.statvfs(root)
        report['space_fault'] = {'available_bytes': fs.f_bavail * fs.f_frsize, 'filler_bytes': filler.stat().st_size}
        target = '/m4/stock.apk' if mode in ('full-rollback', 'full-stock-reinstall') else '/m4/candidate.apk'
        options = ['add'] + (['--force-reinstall'] if mode == 'full-stock-reinstall' else []) + [target]
        report['transaction'] = case.apk(options, 'low-space-transaction', False)
        time.sleep(1)
        observe('after-low-space-transaction')
        report['restart'] = case.run(['/etc/init.d/dnsmasq', 'restart'], 'after-low-space-restart', False)
        time.sleep(2)
        observe('after-low-space-restart')
        filler.unlink()
        report['freeing_space'] = {'available_bytes': os.statvfs(root).f_bavail * os.statvfs(root).f_frsize}
        report['repair_transaction'] = case.apk(['add', '--force-reinstall', '/m4/stock.apk'], 'repair-stock', False)
        case.activate_after_transaction('repair-stock')
        case.service(STOCK_SHA256, 'stock-repair')
        observe('after-space-released-c-repair')
    report['completed'] = True
except Exception as ex:
    report['error'] = repr(ex)
    raise
finally:
    report['cleanup'] = case.cleanup()
    for name in ['rootfs-identity.json']:
        shutil.copy2(stage / name, out / name)
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    subprocess.run(['umount', '--recursive', str(root)], capture_output=True)
    if mode.startswith('full-'):
        subprocess.run(['umount', str(stage)], capture_output=True)
    print(json.dumps({'mode': mode, 'completed': report.get('completed'), 'error': report.get('error'), 'out': str(out)}))
