#!/usr/bin/env python3
"""Recheck audit B inputs on Oracle; only a fresh private output is written."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import subprocess
import tarfile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    result = {}
    for directory, folders, names in os.walk(root, followlinks=False):
        for name in folders + names:
            path = Path(directory, name)
            key = str(path.relative_to(root))
            if key.startswith('dev/'):
                continue
            if path.is_symlink():
                result[key] = {'symlink': str(path.readlink())}
            elif path.is_file():
                result[key] = {'sha256': sha(path)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--image-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    identity = json.loads(args.identity.read_text())
    source = Path(identity['retained_source'])
    assert all(sha(source / name) == value for name, value in identity['inputs'].items())
    image = args.image_dir / 'input/openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin'
    assert sha(image) == 'a94ac2c7177b451a29c576970cb19ed2d669031f65aca2ded80fc71ae91b9eea'
    squashfs = args.image_dir / 'extracted/sysupgrade-xiaomi_mi-router-ax3000t/root'
    assert sha(squashfs) == '3f315cf686c9cd951b24881a3a8e0c78448acaad6fd20d2ab6f1003a0e85b1cc'
    with tarfile.open(image) as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith('/root')]
        assert len(members) == 1
        assert hashlib.sha256(archive.extractfile(members[0]).read()).hexdigest() == sha(squashfs)
    fresh = args.out / 'rootfs-check'
    with (args.out / 'unsquashfs.log').open('w') as log:
        subprocess.run(['unsquashfs', '-excludes', '-d', str(fresh), str(squashfs), 'dev/*'],
                       stdout=log, stderr=subprocess.STDOUT, check=True)
    root = args.image_dir / 'extracted/rootfs-files'
    actual, expected = tree(root), tree(fresh)
    assert all(actual.get(name) == value for name, value in expected.items())
    extras = {name: value for name, value in actual.items() if name not in expected}
    # The shared historical extraction has two inert old test ELFs in /tmp.
    # Keep this deviation visible; the freshly extracted tree has neither.
    assert extras == {
        'tmp/r131-ubusd': {'sha256': 'c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a'},
        'tmp/r134-ubusd': {'sha256': '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0'},
    }
    elf = Path(identity['retained_elf'])
    assert sha(elf) == 'e475163a4cd95d4146767d8a6f9d1c26097d80ef7b9bc88b4349b2da5ec233e9'
    assert sha(root / 'usr/sbin/dnsmasq') == '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
    reference = Path('/home/ubuntu/dnsmasq-rewrite-20260929/reference')
    reference_identity = reference / 'identity.json'
    assert sha(reference_identity) == '62cec0e9dda0265cb9c4f6af27f7d23067aed967afab3c74e37370149a8326e9'
    reference_manifest = json.loads(reference_identity.read_text())
    for name, digest in reference_manifest['patched_files'].items():
        assert sha(reference / 'dnsmasq-2.93' / name) == digest
    selected = ['usr/sbin/dnsmasq', 'etc/init.d/dnsmasq', 'etc/init.d/odhcpd',
                'lib/functions.sh', 'lib/functions/procd.sh', 'etc/rc.common',
                'sbin/procd', 'sbin/ubusd', 'sbin/ujail', 'sbin/logd', 'sbin/rpcd',
                'usr/sbin/odhcpd', 'usr/share/acl.d/dnsmasq_acl.json',
                'usr/lib/dnsmasq/dhcp-script.sh', 'lib/apk/db/installed']
    report = dict(audit_head=identity['audit_head'], inputs_verified=len(identity['inputs']),
                  image_sha256=sha(image), squashfs_sha256=sha(squashfs),
                  rootfs=str(root), all_image_files_and_symlinks_match=True,
                  shared_extraction_extras=extras, clean_rootfs=str(fresh),
                  regular_files=sum('sha256' in value for value in expected.values()),
                  symlinks=sum('symlink' in value for value in expected.values()),
                  rootfs_manifest_sha256=hashlib.sha256(json.dumps(actual, sort_keys=True).encode()).hexdigest(),
                  selected={name: sha(root / name) for name in selected},
                  rust=dict(path=str(elf), sha256=sha(elf), bytes=elf.stat().st_size),
                  reference=dict(path=str(reference / 'dnsmasq-2.93'),
                                 identity_sha256=sha(reference_identity),
                                 files_verified=len(reference_manifest['patched_files']),
                                 recipe_revision=reference_manifest['recipe_revision']),
                  scope='File contents and symlinks; no device state or kernel execution verified.')
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
