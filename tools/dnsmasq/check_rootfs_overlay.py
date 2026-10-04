#!/usr/bin/env python3
"""Verify image immutability, private writable layers and actual C/Rust service."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import shutil
import stat
import subprocess
import time

from dns_service_probe import name, semantics
from m2_rootfs import command, image_path, prepare, process_identity, sha256


def manifest(root):
    result = {}
    for directory, folders, files in os.walk(root, followlinks=False):
        for entry in folders + files:
            path = Path(directory) / entry
            info = path.lstat()
            row = {'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid}
            if stat.S_ISREG(info.st_mode):
                row['sha256'] = sha256(path)
            elif stat.S_ISLNK(info.st_mode):
                row['target'] = os.readlink(path)
            result[str(path.relative_to(root))] = row
    return result


def serve(root, side, folder, host, address, port):
    config = f'no-resolv\nno-hosts\nport={port}\ninterface=lo\nuser=root\n'
    config += f'host-record={host},{address}\npid-file=/m2/overlay.pid\n'
    (root / 'm2/overlay.conf').write_text(config)
    argv = command(root, side, '--test', '-C', '/m2/overlay.conf')
    syntax = subprocess.run(argv, capture_output=True, text=True, timeout=5)
    assert syntax.returncode == 0, syntax.stderr
    with (folder / f'{side}.log').open('w') as log:
        process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/overlay.conf'),
                                   stdout=log, stderr=log)
        try:
            query = bytes.fromhex('123401000001000000000000') + name(host) + b'\0\1\0\1'
            deadline = time.monotonic() + 5
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(.1)
                while True:
                    assert process.poll() is None, 'daemon exited'
                    client.sendto(query, ('127.0.0.1', port))
                    try:
                        response = client.recv(4096)
                        break
                    except socket.timeout:
                        assert time.monotonic() < deadline, 'daemon readiness timeout'
            decoded = semantics(response)
            assert [row['data'] for row in decoded['records'] if row['type'] == 1] == [address]
            identity = process_identity(root, process.pid)
        finally:
            process.terminate()
            process.wait(timeout=5)
    assert process.returncode == 0
    assert not (root / 'm2/overlay.pid').exists()
    return {'side': side, 'identity': identity, 'syntax': vars(syntax),
            'response': decoded, 'wire': response.hex(), 'cleanup_exit': process.returncode}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists() and 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True)
    before = manifest(args.image_root)
    roots = [prepare(args.image_root, None, args.out / side, args.rust) for side in ('one', 'two')]
    (roots[0] / 'm2/private-marker').write_text('one')
    assert not (roots[1] / 'm2/private-marker').exists()
    # Removing a lower file must create a whiteout in one overlay only.
    relative = 'usr/sbin/dnsmasq'
    original = image_path(args.image_root, relative)
    assert original.is_file()
    image_path(roots[0], relative).unlink()
    assert original.is_file() and image_path(roots[1], relative).is_file()
    assert not image_path(roots[0], relative).exists()
    shutil.copy2(original, image_path(roots[0], relative))
    lower = roots[0].parent / 'rootfs-overlay/lower'
    try:
        (lower / '.dnsmasq-overlay-write-check').write_text('must fail')
    except OSError as error:
        assert error.errno == errno.EROFS
    else:
        raise AssertionError('lower is writable')
    rows = []
    for index, root in enumerate(roots):
        for side in ('c', 'rust'):
            rows.append(serve(root, side, root.parent, f'overlay-{index}.test',
                              f'203.0.113.{index + 21}', 15353 + index))
    after = manifest(args.image_root)
    assert before == after, 'original image mutated'
    result = {'passed': True, 'lower_read_only': True, 'whiteout_isolated': True,
              'write_isolated': True, 'image_unchanged': True, 'image_entries': len(before),
              'rows': rows}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'rows'}))


if __name__ == '__main__':
    main()
