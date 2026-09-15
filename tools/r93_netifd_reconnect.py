#!/usr/bin/env python3
"""netifd re-registration fault probe in an owned image/network namespace."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from r92_recovery_probe import attr, fields, digest, write
from r92_compat_probe import Fixture


class Proxy:
    def __init__(self, frontend, backend, reject_path):
        self.backend, self.reject_path = backend, reject_path
        self.disconnect = threading.Event()
        self.stopped = threading.Event()
        self.rejected = threading.Event()
        self.attempts = []
        self.connections = 0
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(frontend))
        self.listener.listen(8)
        self.listener.settimeout(.1)
        self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                front, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            index = self.connections
            self.connections += 1
            worker = threading.Thread(target=self.relay, args=(front, index), daemon=True)
            self.workers.append(worker)
            worker.start()

    def relay(self, front, index):
        with front, socket.socket(socket.AF_UNIX) as back:
            back.connect(str(self.backend))
            pending = bytearray()
            while not self.stopped.is_set():
                if index == 0 and self.disconnect.is_set():
                    return
                ready, _, _ = select.select([front, back], [], [], .02)
                for source in ready:
                    try:
                        data = source.recv(65536)
                        if not data:
                            return
                        if source is back:
                            front.sendall(data)
                            continue
                        pending.extend(data)
                        while len(pending) >= 12:
                            version, kind, seq, peer, length = struct.unpack('>BBHII', pending[:12])
                            assert 4 <= length <= 1048576
                            size = length + 8
                            if len(pending) < size:
                                break
                            frame = bytes(pending[:size])
                            del pending[:size]
                            path = dict(fields(frame[12:])).get(2, b'').rstrip(b'\0')
                            if kind == 6:
                                self.attempts.append({'connection': index, 'path': path.decode(errors='replace')})
                            if index > 0 and kind == 6 and path.decode(errors='replace') == self.reject_path and not self.rejected.is_set():
                                self.rejected.set()
                                body = attr(1, struct.pack('>I', 9))
                                front.sendall(struct.pack('>BBHII', 0, 1, seq, peer, len(body) + 4) + body)
                            else:
                                back.sendall(frame)
                    except (OSError, EOFError):
                        return

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for worker in self.workers:
            worker.join(timeout=1)


def inner(root, fault, expect_missing):
    f = Fixture(root, 'candidate', 'netifd')
    proxy = None
    checks = {}
    try:
        write(root / 'etc/config/network', "config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1/8'\n")
        write(root / 'etc/config/wireless', '')
        write(root / 'sbin/hotplug-call', '#!/bin/sh\nexit 0\n')
        (root / 'sbin/hotplug-call').chmod(0o755)
        f.start_bus()
        proxy = Proxy(root / 'tmp/r93-netifd.sock', f.sock, fault)
        f.start_subject('-s', '/tmp/r93-netifd.sock', obj='network.interface.loopback')
        client = f.connect()
        expected = {'network', 'network.device', 'network.interface', 'network.wireless', 'network.interface.loopback'}
        checks['initial_registration'] = expected <= set(client.paths())
        checks['identity'] = digest(Path(f'/proc/{f.subject.pid}/exe')) == digest(root / 'tmp/netifd-rs')
        before_address = subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', 'dev', 'lo']).decode()
        proxy.disconnect.set()
        assert f.wait(proxy.rejected.is_set, timeout=8), 'did not reach the injected registration error'
        if expect_missing:
            time.sleep(5)
            checks['old_failure_reproduced'] = fault not in client.paths()
        else:
            checks['complete_registration_recovered'] = f.wait(lambda: expected <= set(client.paths()), timeout=8)
            if checks['complete_registration_recovered']:
                checks['working_interface_object'] = client.invoke(client.lookup('network.interface.loopback'), 'status')[0] == 0
            checks['new_connection_retried'] = proxy.connections >= 3
        checks['same_netifd_alive'] = f.subject.poll() is None
        checks['address_preserved'] = before_address == subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', 'dev', 'lo']).decode()
    finally:
        if proxy:
            proxy.close()
        write(f.output / 'result.json', json.dumps({'checks': checks,
              'attempts': proxy.attempts if proxy else [],
              'connections': proxy.connections if proxy else 0}, indent=2))
        f.close()
    assert all(checks.values()), checks


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inner':
        inner(Path(sys.argv[2]), sys.argv[3], sys.argv[4] == 'red')
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('netifd', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--fault', choices=('network.device', 'network.interface.loopback'), default='network.interface.loopback')
    parser.add_argument('--expect-missing', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('requires root on the Linux build host')
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='r93-netifd-reconnect-') as temporary:
        root = Path(temporary) / 'root'
        shutil.copytree(args.rootfs, root, symlinks=True)
        for directory in ('out', 'run/ubus', 'lock', 'state', 'initd', 'rcd'):
            (root / 'tmp' / directory).mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.netifd, root / 'tmp/netifd-rs')
        with (args.output / 'driver.log').open('wb') as log:
            result = subprocess.run(['timeout', '-k', '3', '30', 'unshare', '--mount', '--net', '--pid', '--fork', '--kill-child', sys.executable, str(Path(__file__).resolve()), '--inner', str(root), args.fault, 'red' if args.expect_missing else 'green'], stdout=log, stderr=log)
        shutil.copytree(root / 'tmp/out', args.output / 'raw')
    path = args.output / 'raw/result.json'
    summary = {'binary_sha256': digest(args.netifd), 'probe_sha256': digest(Path(__file__)), 'exit': result.returncode,
               **(json.loads(path.read_text()) if path.exists() else {})}
    summary['passed'] = result.returncode == 0 and bool(summary.get('checks')) and all(summary['checks'].values())
    write(args.output / 'results.json', json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary['passed'] else 1)


if __name__ == '__main__':
    main()
