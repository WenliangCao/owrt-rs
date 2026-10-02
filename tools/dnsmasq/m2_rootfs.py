#!/usr/bin/env python3
"""Disposable exact-image filesystem for isolated M2 service comparisons.

The host Python driver remains outside chroot. Both service binaries execute
inside the same copied image; no host loader, libraries, configuration or bus is
substituted for the image. Call prepare only under run_isolated.sh.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


STOCK_SHA256 = '097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(root, binary, *args):
    """Return argv; binary is c, rust, or an absolute path inside the rootfs."""
    binary = {'c': '/usr/sbin/dnsmasq', 'rust': '/usr/sbin/dnsmasq-rs'}.get(str(binary), str(binary))
    if not binary.startswith('/'):
        raise ValueError('binary must be c, rust, or an absolute image path')
    return ['chroot', str(root), binary, *map(str, args)]


def image_path(root, relative, follow_leaf=True):
    """Resolve links as chroot would, never as the host filesystem would."""
    root = Path(root).resolve()
    pending = list(Path(str(relative).lstrip('/')).parts)
    resolved = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('image path escapes root')
            resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        if candidate.is_symlink() and (pending or follow_leaf):
            links += 1
            if links > 40:
                raise ValueError('image symlink loop')
            target = candidate.readlink()
            if target.is_absolute():
                resolved = []
            pending = list(Path(str(target).lstrip('/')).parts) + pending
        else:
            resolved.append(part)
    return root.joinpath(*resolved)


def _overlay(source, root, relative):
    """Overlay captured regular files without following destination symlinks."""
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            continue
        if path.is_dir():
            image_path(root, Path(relative) / path.relative_to(source)).mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            continue
        target = image_path(root, Path(relative) / path.relative_to(source), follow_leaf=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        shutil.copy2(path, target)


def prepare(image_root, runtime_root, evidence_dir, rust_binary):
    """Copy image and optional captured runtime, mount private proc/dev, return root.

    evidence_dir must be a fresh private directory (or have no rootfs child).
    Caller owns service lifetime. Mount namespace teardown releases proc/dev.
    Profiles may write files under the returned root; /m2 is a writable profile
    directory. Host evidence paths are intentionally not mounted into the image.
    """
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('root in run_isolated.sh is required')
    image_root, evidence_dir, rust_binary = map(Path, (image_root, evidence_dir, rust_binary))
    if 'private' not in evidence_dir.resolve().parts:
        raise ValueError('evidence must be stored under private')
    if sha256(image_root / 'usr/sbin/dnsmasq') != STOCK_SHA256:
        raise ValueError('stock image dnsmasq SHA-256 mismatch')
    provenance_file = image_root.parent / 'image-identity.json'
    provenance = json.loads(provenance_file.read_text()) if provenance_file.exists() else None
    if provenance:
        for relative, digest in provenance['files'].items():
            if sha256(image_path(image_root, relative)) != digest:
                raise ValueError(f'image file changed after extraction: {relative}')
        for relative, target in provenance['symlinks'].items():
            if str(image_path(image_root, relative, follow_leaf=False).readlink()) != target:
                raise ValueError(f'image symlink changed after extraction: {relative}')
    evidence_dir.mkdir(parents=True, exist_ok=True)
    root = evidence_dir.resolve() / 'rootfs'
    # Extracted /dev/console is a character device. copyfile would open the
    # build host console and block; the private /dev below replaces all devices.
    def skip_special(directory, names):
        return [name for name in names
                if not (Path(directory, name).is_symlink()
                        or Path(directory, name).is_file()
                        or Path(directory, name).is_dir())]

    shutil.copytree(image_root, root, symlinks=True, ignore=skip_special)
    if runtime_root is not None:
        runtime_root = Path(runtime_root)
        for relative in ('etc', 'tmp', 'var', 'usr/share'):
            source = runtime_root / relative
            if source.is_dir():
                _overlay(source, root, relative)
    shutil.copy2(rust_binary, image_path(root, 'usr/sbin/dnsmasq-rs'))
    image_path(root, 'usr/sbin/dnsmasq-rs').chmod(0o755)
    for relative in ('proc', 'dev', 'm2', 'tmp', 'tmp/run/ubus', 'tmp/run/dnsmasq',
                     'tmp/lock', 'tmp/state', 'tmp/etc', 'tmp/hosts', 'tmp/.uci'):
        image_path(root, relative).mkdir(parents=True, exist_ok=True)
    image_path(root, 'tmp').chmod(0o1777)
    os.chown(image_path(root, 'tmp/run/dnsmasq'), 453, 453)
    run = image_path(root, 'run', follow_leaf=False)
    if not run.exists() and not run.is_symlink():
        run.symlink_to('tmp/run')
    # ubusd rejects ACLs that are not owned by root; the image was extracted by
    # an unprivileged user, so restore the original root ownership in this copy.
    acl = image_path(root, 'usr/share/acl.d')
    if acl.exists():
        for path in [acl, *acl.rglob('*')]:
            os.chown(path, 0, 0, follow_symlinks=False)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'proc', 'proc', str(root / 'proc')], check=True)
    # OpenWrt mounts /tmp as tmpfs during boot. ujail's private bind setup
    # rejects an ordinary squashfs directory here (EINVAL), so reproduce that
    # mount boundary and restore captured files/empty directories into it.
    saved_tmp = root / '.m2-tmp-saved'
    shutil.move(root / 'tmp', saved_tmp)
    (root / 'tmp').mkdir()
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=1777', 'm2-tmp', str(root / 'tmp')], check=True)
    for entry in saved_tmp.iterdir():
        target = root / 'tmp' / entry.name
        if entry.is_dir() and not entry.is_symlink():
            shutil.copytree(entry, target, symlinks=True)
        else:
            shutil.copy2(entry, target, follow_symlinks=False)
    shutil.rmtree(saved_tmp)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'm2-dev', str(root / 'dev')], check=True)
    for name, minor in [('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)]:
        os.mknod(root / 'dev' / name, stat.S_IFCHR | 0o666, os.makedev(1, minor))
        (root / 'dev' / name).chmod(0o666)
    (root / 'dev/fd').symlink_to('/proc/self/fd')
    # chroot alone leaves the child root as an ordinary directory. ujail's
    # first operation is mount --make-rprivate /, which returns EINVAL unless
    # that directory is itself a mount point (as it is after a real boot).
    subprocess.run(['mount', '--bind', str(root), str(root)], check=True)
    subprocess.run(['mount', '--make-rprivate', str(root)], check=True)
    identity = {
        'image_root': str(image_root), 'runtime_root': str(runtime_root) if runtime_root else None,
        'image_provenance_sha256': sha256(provenance_file) if provenance else None,
        'image_sha256': provenance['image_sha256'] if provenance else None,
        'root': str(root), 'c_sha256': sha256(root / 'usr/sbin/dnsmasq'),
        'rust_source_path': str(rust_binary), 'rust_sha256': sha256(root / 'usr/sbin/dnsmasq-rs'),
        'kernel': os.uname().release, 'machine': os.uname().machine,
        'namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in ('mnt', 'net', 'pid')},
        'image_files': {str(path.relative_to(image_root)): sha256(path)
                        for relative in ('lib', 'usr/lib', 'etc/init.d', 'lib/functions')
                        for path in sorted((image_root / relative).rglob('*'))
                        if path.is_file() and not path.is_symlink()},
    }
    (evidence_dir / 'rootfs-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
    return root


def process_identity(root, pid):
    """Verify a running service actually uses this filesystem, record its ELF."""
    proc = Path('/proc') / str(pid)
    actual_root = os.path.realpath(proc / 'root')
    if actual_root != str(Path(root).resolve()):
        raise AssertionError(f'process root mismatch: {actual_root}')
    return {'pid': pid, 'root': actual_root, 'exe': os.readlink(proc / 'exe'),
            'sha256': sha256(proc / 'exe'),
            'cmdline': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(),
            'maps': (proc / 'maps').read_text()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--runtime-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = prepare(args.image_root, args.runtime_root, args.output, args.rust_binary)
    argv = args.command[1:] if args.command[:1] == ['--'] else args.command
    if argv:
        return subprocess.run(argv, env=dict(os.environ, DNSMASQ_M2_ROOTFS=str(root))).returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
