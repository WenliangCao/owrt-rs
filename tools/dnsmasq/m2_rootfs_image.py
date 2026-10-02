#!/usr/bin/env python3
"""Verify and extract the already archived deployment image for offline M2."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

from m2_rootfs import STOCK_SHA256, sha256


IMAGE_SHA256 = '144c1283da1fb3ead5e4ee7b8b55f66b7d9e872f785892f87cadf9fca6ed0720'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    digest = sha256(args.image)
    assert digest == IMAGE_SHA256 == manifest['firmware']['sha256']
    assert args.image.stat().st_size == manifest['firmware']['bytes']
    assert 'private' in args.output.resolve().parts
    args.output.mkdir(parents=True, exist_ok=True)
    root = args.output / 'rootfs'
    assert not root.exists()
    with tarfile.open(args.image) as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith('/root')]
        assert len(members) == 1
        payload = archive.extractfile(members[0]).read()
    squashfs = args.output / 'root.squashfs'
    squashfs.write_bytes(payload)
    subprocess.run(['unsquashfs', '-d', str(root), str(squashfs)], check=True)
    checked = {}
    for label, component in manifest['components'].items():
        actual = sha256(root / component['path'].lstrip('/'))
        assert actual == component['rust_sha256'], label
        checked[label] = {'path': component['path'], 'sha256': actual}
    assert sha256(root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    files = {str(path.relative_to(root)): sha256(path)
             for path in sorted(root.rglob('*')) if path.is_file() and not path.is_symlink()}
    symlinks = {str(path.relative_to(root)): str(path.readlink())
                for path in sorted(root.rglob('*')) if path.is_symlink()}
    identity = {'image_sha256': digest, 'manifest_sha256': sha256(args.manifest),
                'squashfs_sha256': hashlib.sha256(payload).hexdigest(),
                'release_tag': manifest['release_tag'], 'components': checked,
                'dnsmasq_sha256': STOCK_SHA256, 'files': files, 'symlinks': symlinks}
    (args.output / 'image-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    print(json.dumps({'rootfs': str(root), 'image_sha256': digest, 'verified_components': len(checked),
                      'regular_files': len(files), 'symlinks': len(symlinks)}))


if __name__ == '__main__':
    main()
