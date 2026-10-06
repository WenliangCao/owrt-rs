#!/usr/bin/env python3
"""Real Linux filesystem AF_UNIX entry and receive tests; no global cwd change."""
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

from m2_rootfs import bind_unix_socket


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux /proc/self/fd binding')
class UnixSocketPathTest(unittest.TestCase):
    def test_long_absolute_path_receives_after_directory_fd_is_closed(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory(prefix='dnsmasq-unix-') as directory:
            parent = Path(directory)/('a'*60)/('b'*60)
            parent.mkdir(parents=True)
            path = parent/'log'
            self.assertGreater(len(os.fsencode(path)), 108)
            for kind in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
                with socket.socket(socket.AF_UNIX, kind) as endpoint:
                    endpoint.settimeout(2)
                    bind_unix_socket(endpoint, path)
                    self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))
                    self.assertEqual([entry.name for entry in parent.iterdir()], ['log'])
                    address = os.fsdecode(endpoint.getsockname())
                    fd = int(address.split('/')[4])
                    with self.assertRaises(OSError): os.fstat(fd)
                    if kind == socket.SOCK_STREAM: endpoint.listen(1)
                    program = 'import socket; s=socket.socket(socket.AF_UNIX,' + str(kind) + '); s.connect("log"); s.sendall(b"same-directory-entry"); s.close()'
                    subprocess.run([sys.executable, '-c', program], cwd=parent, check=True, timeout=2)
                    if kind == socket.SOCK_STREAM:
                        with endpoint.accept()[0] as received: data = received.recv(128)
                    else: data = endpoint.recv(128)
                    self.assertEqual(data, b'same-directory-entry')
                    self.assertEqual(Path.cwd(), original)
                path.unlink()

    def test_short_path_is_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='unix-') as directory:
            path = Path(directory)/'log'
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as endpoint:
                bind_unix_socket(endpoint, path)
                self.assertEqual(endpoint.getsockname(), str(path))
                self.assertTrue(stat.S_ISSOCK(path.lstat().st_mode))


if __name__ == '__main__': unittest.main()
