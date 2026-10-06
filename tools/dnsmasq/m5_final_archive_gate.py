#!/usr/bin/env python3
"""Await local full-fidelity archive verification before endpoint source-row audit."""
import argparse
import json
import os
from pathlib import Path
import socket
import time

from m2_rootfs import sha256


def verify(root, names):
    receipts = []
    for name in names:
        path = root / (name + '.local-verification.json')
        receipt = json.loads(path.read_text())
        archive = root / (name + '.tar.gz')
        manifest = root / (name + '.manifest.json')
        inventory = json.loads(manifest.read_text())
        prune = json.loads((root / (name + '.prune.json')).read_text())
        if (receipt.get('verified') is not True or receipt.get('local_full_metadata_verified') is not True
                or not receipt.get('verifier_host') or receipt['verifier_host'] == socket.gethostname()
                or receipt.get('archive_sha256') != sha256(archive)
                or receipt.get('manifest_sha256') != sha256(manifest)
                or inventory['archive_sha256'] != receipt['archive_sha256']
                or prune.get('archive_sha256') != receipt['archive_sha256']):
            raise ValueError('local archive/prune proof differs: ' + name)
        raw = root / name / 'result.json'
        if sha256(raw) != inventory['entries']['result.json']['sha256']:
            raise ValueError('retained plain report differs from verified archive: ' + name)
        receipts.append({'run': name, 'receipt_sha256': sha256(path), 'archive_sha256': receipt['archive_sha256']})
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['wait', 'verify-local'])
    parser.add_argument('--evidence-root', type=Path)
    parser.add_argument('--run', action='append')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--plain', type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=3600)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'verify-local':
        import m5_option_matrix_archive as archive
        if args.out.exists(): raise ValueError('fresh local verification receipt required')
        result = archive.verify(args.archive, args.manifest, args.plain)
        result.update(local_full_metadata_verified=True, verifier_host=socket.gethostname(),
                      manifest_sha256=sha256(args.manifest))
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps(result))
        return
    if not args.run or args.evidence_root is None: raise ValueError('run names and evidence root required')
    if args.out.exists() or 'private' not in args.evidence_root.resolve().parts:
        raise ValueError('fresh private gate output required')
    ready = {'status': 'awaiting-local-archive-verification', 'executed': False,
             'runs': args.run, 'remote_host': socket.gethostname(), 'pid': os.getpid()}
    args.out.with_suffix('.ready.json').write_text(json.dumps(ready, indent=2) + '\n')
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        try:
            receipts = verify(args.evidence_root, args.run)
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise TimeoutError('local archive proof was not supplied; family remains incomplete')
            time.sleep(.2)
    result = {'qualified': True, 'locally_verified_runs': len(receipts), 'receipts': receipts}
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
