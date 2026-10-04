#!/usr/bin/env python3
"""Preserve and verify a finished matrix run, including overlay upper metadata.

`pack` runs on Oracle as root; `verify` runs locally without extracting special
files. `prune` is used only after local verification, and rechecks the unchanged
remote tree. Plain evidence is copied out for review; the tar remains the full
fidelity source for devices, whiteouts, xattrs, links and ownership.
"""
from __future__ import annotations

import argparse
import base64
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(run):
    result = {}
    for path in [run, *sorted(run.rglob('*'))]:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode): kind = 'file'
        elif stat.S_ISDIR(info.st_mode): kind = 'directory'
        elif stat.S_ISLNK(info.st_mode): kind = 'symlink'
        elif stat.S_ISCHR(info.st_mode): kind = 'character'
        elif stat.S_ISBLK(info.st_mode): kind = 'block'
        elif stat.S_ISFIFO(info.st_mode): kind = 'fifo'
        else: raise ValueError(f'unarchivable live/special object: {path}')
        row = {'kind': kind, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid,
               'gid': info.st_gid, 'mtime_ns': info.st_mtime_ns,
               'xattrs': {key: base64.b64encode(os.getxattr(path, key, follow_symlinks=False)).decode()
                         for key in sorted(os.listxattr(path, follow_symlinks=False))}}
        if kind == 'file': row['sha256'] = digest(path)
        elif kind == 'symlink': row['target'] = os.readlink(path)
        elif kind in ('character', 'block'):
            row['device'] = [os.major(info.st_rdev), os.minor(info.st_rdev)]
        result[str(path.relative_to(run))] = row
    return result


def assert_finished(run):
    if 'private' not in run.parts or not run.is_dir() or run.is_symlink():
        raise ValueError('an explicit private run directory is required')
    ancestors = set()
    pid = os.getpid()
    while pid and pid not in ancestors:
        ancestors.add(pid)
        try:
            pid = int(next(line.split()[1] for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                           if line.startswith('PPid:')))
        except (FileNotFoundError, StopIteration): break
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) in ancestors: continue
        try:
            root = os.readlink(proc / 'root')
            args = (proc / 'cmdline').read_bytes().split(b'\0')
            cwd = Path(os.readlink(proc / 'cwd'))
            if root.startswith(str(run)) or any(str(run).encode() in arg for arg in args):
                raise RuntimeError(f'run still has an active process: {proc.name}')
            if any(arg.startswith(b'private/') and (cwd / os.fsdecode(arg)).resolve() == run for arg in args):
                raise RuntimeError(f'run controller is active: {proc.name}')
        except (FileNotFoundError, PermissionError, ProcessLookupError): pass


def pack(run, archive, manifest):
    assert_finished(run)
    if archive.exists() or manifest.exists() or archive.is_relative_to(run) or manifest.is_relative_to(run):
        raise ValueError('fresh archive/manifest outside the run are required')
    archive.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    entries = inventory(run)
    subprocess.run(['tar', '--format=pax', '--xattrs', '--xattrs-include=*', '--acls',
                    '--numeric-owner', '--sort=name', '-czf', str(archive),
                    '-C', str(run.parent), '--', run.name], check=True)
    if inventory(run) != entries:
        raise RuntimeError('run changed during archival')
    report = {'run': str(run), 'prefix': run.name, 'archive_name': archive.name,
              'archive_sha256': digest(archive), 'archive_bytes': archive.stat().st_size,
              'entries': entries}
    manifest.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return {'archive_sha256': report['archive_sha256'], 'entries': len(entries),
            'archive_bytes': report['archive_bytes']}


def verify(archive, manifest, plain):
    report = json.loads(manifest.read_text())
    if digest(archive) != report['archive_sha256']:
        raise ValueError('archive SHA256 mismatch')
    if plain is not None:
        if plain.exists(): raise ValueError('plain evidence destination must be fresh')
        plain.mkdir(parents=True)
    found = set()
    with tarfile.open(archive, 'r:*') as stream:
        for member in stream.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or path.parts[0] != report['prefix']:
                raise ValueError('unsafe/unexpected archive path')
            relative = str(path.relative_to(report['prefix']))
            if relative in found: raise ValueError('duplicate archive entry')
            found.add(relative)
            expected = report['entries'][relative]
            if member.isfile() or member.islnk(): kind = 'file'
            elif member.isdir(): kind = 'directory'
            elif member.issym(): kind = 'symlink'
            elif member.ischr(): kind = 'character'
            elif member.isblk(): kind = 'block'
            elif member.isfifo(): kind = 'fifo'
            else: raise ValueError('unexpected archive object')
            mtime_ns = int(Decimal(member.pax_headers.get('mtime', str(member.mtime))) * 1_000_000_000)
            xattrs = {key.removeprefix('SCHILY.xattr.'): base64.b64encode(value.encode('utf-8', 'surrogateescape')).decode()
                      for key, value in member.pax_headers.items() if key.startswith('SCHILY.xattr.')}
            actual = {'kind': kind, 'mode': member.mode, 'uid': member.uid, 'gid': member.gid,
                      'mtime_ns': mtime_ns, 'xattrs': xattrs}
            if kind == 'file':
                data = stream.extractfile(member).read()
                actual['sha256'] = hashlib.sha256(data).hexdigest()
                if plain is not None and 'rootfs-overlay' not in path.parts:
                    target = plain / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
            elif kind == 'symlink': actual['target'] = member.linkname
            elif kind in ('character', 'block'): actual['device'] = [member.devmajor, member.devminor]
            if actual != expected:
                raise ValueError({'entry': relative, 'expected': expected, 'actual': actual})
    if found != set(report['entries']):
        raise ValueError({'missing': sorted(set(report['entries']) - found)})
    result = {'verified': True, 'entries': len(found), 'archive_sha256': report['archive_sha256'],
              'regular_files': sum(row['kind'] == 'file' for row in report['entries'].values()),
              'scope': 'SHA256 plus type, mode, uid/gid, nanosecond mtime, symlink target, device ID and every xattr'}
    return result


def prune(run, manifest):
    assert_finished(run)
    report = json.loads(manifest.read_text())
    if str(run) != report['run'] or inventory(run) != report['entries']:
        raise ValueError('run no longer matches the verified archive manifest')
    allocated = sum(path.lstat().st_blocks * 512 for path in [run, *run.rglob('*')])
    shutil.rmtree(run)
    return {'removed': str(run), 'allocated_bytes_removed': allocated,
            'archive_sha256': report['archive_sha256']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['pack', 'verify', 'prune'])
    parser.add_argument('--run', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--plain', type=Path)
    args = parser.parse_args()
    if args.action == 'pack':
        result = pack(args.run.resolve(), args.archive.resolve(), args.manifest.resolve())
    elif args.action == 'verify':
        result = verify(args.archive, args.manifest, args.plain)
    else:
        result = prune(args.run.resolve(), args.manifest)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
