#!/usr/bin/env python3
"""Oracle-only monitor wire boundaries; fixed functional cases, no timing score."""
import argparse
import array
import importlib.util
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('identity_support', ROOT / 'tools/r134/ubusd_stress_oracle.py')
SUPPORT = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(SUPPORT)
R136 = 'ce3d1aa29e49a8ea51bb7afa2587846ccd7563aa4b7c983cf401a6b4d6de2330'


def field(kind, payload):
    length = len(payload) + 4
    return struct.pack('>I', kind << 24 | length) + payload + bytes((-length) % 4)


def blob(*fields):
    data = b''.join(fields)
    return struct.pack('>I', len(data) + 4) + data


def u32(kind, value):
    return field(kind, struct.pack('>I', value))


OK = blob(u32(1, 0))


class Conn:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(str(path))
        header, _ = self.recv()
        assert header[0] == 0
        self.client = header[2]
        self.sequence = 0
        self.request_sequence = 0

    def close(self):
        self.sock.close()

    def exact(self, count):
        data = bytearray()
        while len(data) < count:
            part, ancillary, flags, _ = self.sock.recvmsg(count - len(data), socket.CMSG_SPACE(16 * 4))
            received = []
            for level, kind, payload in ancillary:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    fds = array.array('i'); fds.frombytes(payload[:len(payload) // 4 * 4])
                    received.extend(fds)
            for fd in received:
                os.close(fd)
            assert not received and not ancillary and not flags & socket.MSG_CTRUNC, 'mirror/reply carried ancillary data'
            assert part, 'unexpected stream EOF'
            data.extend(part)
        return bytes(data)

    def recv(self, idle=None):
        self.sock.settimeout(3 if idle is None else idle)
        try:
            first = self.exact(1)
        except TimeoutError:
            if idle is not None:
                return None
            raise
        self.sock.settimeout(3)
        prefix = first + self.exact(11)
        version, kind, sequence, peer, length = struct.unpack('>BBHII', prefix)
        assert version == 0 and 4 <= (length & 0xffffff) <= 2097152
        body = prefix[8:] + self.exact((length & 0xffffff) - 4)
        return (kind, sequence, peer), body

    def send(self, header, body, fd=None):
        data = struct.pack('>BBHI', 0, *header) + body
        if fd is None:
            self.sock.sendall(data)
        else:
            count = self.sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
            assert count == len(data), 'small descriptor fixture short write'


def expected(monitor, client, header, body, send):
    monitor.sequence = (monitor.sequence + 1) & 0xffff
    kind, sequence, peer = header
    payload = blob(u32(0, client.client), u32(1, peer), u32(3, sequence),
                   u32(4, kind), field(2, bytes([send])), field(5, body[4:]))
    return (11, monitor.sequence, 0), payload


def action(monitor, method, observers):
    monitor.request_sequence += 1
    header = (5, monitor.request_sequence, 0)
    body = blob(u32(3, 3), field(4, method.encode() + b'\0'))
    mirrors = {observer: [expected(observer, monitor, header, body, 0)] for observer in observers}
    self_frames = mirrors.pop(monitor, [])
    monitor.send(header, body)
    status = (1, header[1], 0)
    if method == 'add':
        monitor.sequence = 0
        self_frames.append(expected(monitor, monitor, status, OK, 1))
    for observer, frames in mirrors.items():
        frames.append(expected(observer, monitor, status, OK, 1))
    for frame in self_frames:
        assert monitor.recv() == frame, f'{method}: own mirror differs'
    assert monitor.recv() == (status, OK), f'{method}: status differs'
    for observer, frames in mirrors.items():
        for frame in frames:
            assert observer.recv() == frame, f'{method}: observer mirror differs'


def ping(caller, sequence, size, fd=None):
    header = (3, sequence, 9)
    body = blob(field(7, bytes([sequence % 251]) * size))
    caller.send(header, body, fd)
    assert caller.recv() == ((2, sequence, 9), body)
    assert caller.recv() == ((1, sequence, 9), OK)
    return [(header, body, 0), ((2, sequence, 9), body, 1), ((1, sequence, 9), OK, 1)]


def lifecycle(path):
    a, b, caller = Conn(path), Conn(path), Conn(path)
    try:
        action(a, 'add', [])
        action(b, 'add', [a])
        action(a, 'add', [a, b])
        frames = ping(caller, 100, 511)
        for monitor in (a, b):
            for header, body, send in frames:
                assert monitor.recv() == expected(monitor, caller, header, body, send)
        action(a, 'remove', [a, b])
        for header, body, send in ping(caller, 101, 3):
            assert b.recv() == expected(b, caller, header, body, send)
        assert a.recv(idle=.1) is None, 'removed monitor still receives'
        action(a, 'add', [b])
        a.close()
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            frames = ping(caller, 102, 1023, read_fd)
            os.close(read_fd); read_fd = None
            for header, body, send in frames:
                assert b.recv() == expected(b, caller, header, body, send)
            # With clients still connected, EPIPE proves no daemon/mirror
            # reference to the witness read descriptor survived the PING.
            deadline = time.monotonic() + 3
            while True:
                try:
                    os.write(write_fd, b'x')
                except BrokenPipeError:
                    break
                assert time.monotonic() < deadline, 'witness descriptor retained'
                time.sleep(.01)
        finally:
            if read_fd is not None: os.close(read_fd)
            os.close(write_fd)
        action(b, 'remove', [b])
        ping(caller, 103, 1)
        assert b.recv(idle=.1) is None
        return {'passed': True, 'duplicate_add': True, 'remove_and_readd': True,
                'registered_disconnect': True, 'mirror_bytes_sequences_order': True,
                'no_ancillary_on_mirrors_or_replies': True, 'witness_released_while_connected': True}
    finally:
        for conn in (a, b, caller): conn.close()


def slow_reader(path):
    fast, slow, caller = Conn(path), Conn(path), Conn(path)
    try:
        action(fast, 'add', [])
        action(slow, 'add', [fast])
        wanted = []
        for sequence in range(1000, 1128):
            frames = ping(caller, sequence, 16384)
            for header, body, send in frames:
                assert fast.recv() == expected(fast, caller, header, body, send)
                wanted.append(expected(slow, caller, header, body, send))
        allowed = {frame[0][1]: (index, frame) for index, frame in enumerate(wanted)}
        received, previous = 0, -1
        while (frame := slow.recv(idle=.25)) is not None:
            index, original = allowed[frame[0][1]]
            assert index > previous and frame == original, 'queued mirror bytes/order differ'
            previous = index; received += 1
        assert 0 < received < len(wanted), 'fixed flood did not exercise bounded drops'
        for header, body, send in ping(caller, 1128, 3):
            for monitor in (fast, slow):
                assert monitor.recv() == expected(monitor, caller, header, body, send), 'monitor recovery differs'
        action(slow, 'remove', [fast, slow])
        action(fast, 'remove', [fast])
        return {'passed': True, 'pings': 128, 'payload_bytes': 16384, 'mirrors_expected': len(wanted),
                'slow_mirrors_received': received, 'bounded_drop_exercised': True,
                'survivor_bytes_order_sequences': True, 'fast_complete': True, 'recovery_mirrors': 3}
    finally:
        for conn in (fast, slow, caller): conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.geteuid() == 0
    rootfs = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
    assert rootfs.is_dir() and not Path('/etc/openwrt_release').exists()
    subjects = [('c', rootfs / 'sbin/ubusd', SUPPORT.STOCK_SHA),
                ('r136', Path('/home/ubuntu/r138/build-01/r136/ubusd-rs'), R136),
                ('monitor', args.candidate, args.candidate_sha256)]
    libraries = {str((rootfs / path.lstrip('/')).resolve()): sha for path, sha in SUPPORT.LIBRARIES.items()}
    assert all(SUPPORT.sha(path) == digest for path, digest in libraries.items())
    assert all(SUPPORT.sha(binary) == digest for _, binary, digest in subjects)
    args.output.mkdir(parents=True, exist_ok=False)
    SUPPORT.save(args.output / 'plan.json', {'script_sha256': SUPPORT.sha(__file__),
        'identity_support_sha256': SUPPORT.sha(SPEC.origin), 'subjects': {s: {'path': str(p), 'sha256': h} for s, p, h in subjects},
        'libraries': libraries, 'cases': ['lifecycle', 'slow_reader'], 'timing_gate': False,
        'slow_ping_count': 128, 'slow_payload_bytes': 16384, 'daemon_cpu': 1})
    records = []
    for label, binary, digest in subjects:
        for name, test in [('lifecycle', lifecycle), ('slow_reader', slow_reader)]:
            out = args.output / f'{label}-{name}'; out.mkdir()
            row = {'subject': label, 'case': name, 'passed': False}
            with tempfile.TemporaryDirectory(prefix='r142-monitor-') as tmp:
                path = Path(tmp) / 'bus.sock'
                command = [str(rootfs / 'lib/libc.so'), '--library-path', f'{rootfs}/lib:{rootfs}/usr/lib', '--argv0', '/sbin/ubusd', str(binary), '-s', str(path)] if label == 'c' else ['/sbin/ubusd', '-s', str(path)]
                SUPPORT.save(out / 'command.json', command)
                with (out / 'daemon.log').open('wb') as log:
                    process = subprocess.Popen(command, executable=None if label == 'c' else binary,
                        preexec_fn=lambda: os.sched_setaffinity(0, {1}), stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 5
                    while not path.exists():
                        assert process.poll() is None and time.monotonic() < deadline
                        time.sleep(.01)
                    planned = {str(binary.resolve()): digest, **(libraries if label == 'c' else {})}
                    before = SUPPORT.identity(process, out, 'before', planned)
                    fds = len(list(Path(f'/proc/{process.pid}/fd').iterdir()))
                    row['checks'] = test(path)
                    deadline = time.monotonic() + 3
                    while len(list(Path(f'/proc/{process.pid}/fd').iterdir())) != fds:
                        assert time.monotonic() < deadline, 'daemon FD baseline not restored'
                        time.sleep(.01)
                    assert before == SUPPORT.identity(process, out, 'after', planned)
                    row.update(passed=True, fd_baseline_restored=True, daemon_fd_baseline=fds)
                except BaseException as error:
                    row.update(error=repr(error))
                    raise
                finally:
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(); row.update(passed=False, error='daemon needed SIGKILL')
                    row['daemon_exit'] = process.returncode
                    if process.returncode not in (0, -15):
                        row.update(passed=False, error='unexpected daemon exit')
                    row['raw_sha256'] = {p.name: SUPPORT.sha(p) for p in out.iterdir() if p.is_file()}
                    SUPPORT.save(out / 'result.json', row)
            assert row['passed'] and not (out / 'daemon.log').read_bytes()
            records.append(row)
            print(label, name, 'PASS', flush=True)
    SUPPORT.save(args.output / 'result.json', {'schema': 1, 'passed': True, 'cases': records,
        'limits': ['Functional boundaries only; no timing/ranking.', 'Drop positions/counts can differ; survivors must be ordered, exact and descriptor-free.',
                   'Sequence wrap and forced short-write ownership are covered by the separate SDK unit regression.', 'No heap/RSS acceptance from this probe.']})
    (args.output / 'COMPLETE').touch()


if __name__ == '__main__': main()
