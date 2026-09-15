#!/usr/bin/env python3
"""Strict prefix LOOKUP delivery in disposable Linux build-host namespaces.

Full checks 64 exact large DATA payloads and STATUS after forced backpressure.
Pipeline additionally queues exact/unmatched LOOKUP and PING, then half-closes.
ACL revokes non-root access while parked and checks the newly hidden tail.
Each output retains strict failures, even for C/R89/source05. No timing claims.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from r92_compat_probe import Fixture
from r92_recovery_probe import Bus, attr, digest, message


def signature():
    return message('method', 2, b''.join(message(f'arg{i:05d}', 5, struct.pack('>I', 3)) for i in range(1024)))


def read_reply(client):
    head = client.exact(12)
    version, kind, seq, peer, length = struct.unpack('>BBHII', head)
    assert version == 0 and 4 <= length <= 1048576
    return kind, seq, peer, client.exact(length - 4)


def registered(fixture):
    owner = fixture.connect()
    sig = signature()
    expected = []
    for index in range(64):
        path = f'fixed.{index:05d}'.encode() + b'\0'
        code, replies = owner.request(6, attr(2, path) + attr(6, sig))
        assert code == 0 and len(replies) == 1
        ids = dict(replies[0][2])
        expected.append(attr(2, path) + attr(3, ids[3]) + attr(5, ids[5]) + attr(6, sig))
    return expected


def lookup_case(fixture, pipeline, result):
    expected = registered(fixture)
    client = fixture.connect()
    first = client.send(4, attr(2, b'fixed.*\0'), peer=101)
    time.sleep(.1)
    peek = len(client.sock.recv(1048576, socket.MSG_PEEK))
    assert 65536 < peek < sum(12 + len(item) for item in expected)
    result['initial_buffered_bytes'] = peek
    requests = {first: (expected, 0, 101)}
    exact = missing = None
    if pipeline:
        exact = client.send(4, attr(2, b'fixed.00063\0'), peer=102)
        missing = client.send(4, attr(2, b'absent.*\0'), peer=103)
        ping_data = attr(2, b'ping\0')
        ping = client.send(3, ping_data, peer=104)
        requests.update({exact: ([expected[-1]], 0, 102), missing: ([], 4, 103), ping: ([ping_data], 0, 104)})
        client.sock.shutdown(socket.SHUT_WR)
    counts = {seq: 0 for seq in requests}
    finished = []
    result['data_counts'] = counts
    result['status_order'] = finished
    while len(finished) < len(requests):
        kind, seq, peer, payload = read_reply(client)
        assert seq in requests and seq not in finished, (kind, seq)
        data, status, want_peer = requests[seq]
        assert peer == want_peer
        if kind == 2:
            index = counts[seq]
            assert index < len(data) and payload == data[index], ('payload', seq, index)
            if seq in (exact, missing):
                assert first in finished, 'later LOOKUP passed a parked request'
            counts[seq] += 1
        else:
            assert kind == 1 and payload == attr(1, struct.pack('>I', status)), ('status', seq)
            assert counts[seq] == len(data), ('incomplete', seq, counts[seq], len(data))
            if seq == missing:
                assert exact in finished
            finished.append(seq)
    if pipeline:
        assert client.sock.recv(1) == b'', 'half-close did not finish'
    result['complete_data_frames'] = sum(counts.values())
    result['serving'] = fixture.subject.poll() is None
    assert result['serving']


def denied(path):
    process = subprocess.run([sys.executable, __file__, '--denied', str(path)], capture_output=True,
                             timeout=5, user=65534, group=65534)
    assert process.returncode == 0, process.stderr
    return process.stdout == b'1'


def acl_child(channel, path):
    client = Bus(path)
    seq = client.send(4, attr(2, b'fixed.*\0'))
    channel.sendall(b'S')
    assert channel.recv(1) == b'R'
    payloads = []
    while True:
        kind, got, peer, payload = read_reply(client)
        assert got == seq and peer == 0
        if kind == 1:
            assert payload == attr(1, struct.pack('>I', 0))
            break
        assert kind == 2
        payloads.append(payload.hex())
    channel.sendall(json.dumps(payloads).encode())
    channel.shutdown(socket.SHUT_WR)


def acl_case(fixture, acl, result):
    expected = registered(fixture)
    parent, child = socket.socketpair()
    worker = subprocess.Popen([sys.executable, __file__, '--acl-child', str(child.fileno()), str(fixture.sock)],
                              pass_fds=(child.fileno(),), user=65534, group=65534)
    child.close()
    parent.settimeout(5)
    try:
        assert parent.recv(1) == b'S'
        time.sleep(.1)
        acl.write_text(json.dumps({'user': 'nobody', 'access': {}}))
        fixture.subject.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 3
        while not denied(fixture.sock):
            assert time.monotonic() < deadline, 'revocation not active'
            time.sleep(.01)
        parent.sendall(b'R')
        data = bytearray()
        while True:
            part = parent.recv(65536)
            if not part:
                break
            data.extend(part)
        assert worker.wait(timeout=5) == 0
        payloads = [bytes.fromhex(value) for value in json.loads(data)]
        result['delivered_before_revocation_count'] = len(payloads)
        assert 1 <= len(payloads) < 64
        assert payloads == expected[:len(payloads)], 'queued bytes changed or newly hidden objects delivered'
        assert denied(fixture.sock)
    finally:
        parent.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait()


def inner(root, case, output, sha256):
    assert os.geteuid() == 0 and os.environ.get('OWRT_BENCH_NAMESPACE') == '1'
    result = dict(case=case, passed=False, binary_sha256=sha256)
    acl = root / 'usr/share/acl.d/star-revoke.json'
    if case == 'acl':
        root.parent.chmod(0o755)
        root.chmod(0o755)
        acl.write_text(json.dumps({'user': 'nobody', 'access': {'fixed.*': {'methods': ['method']}}}))
        acl.chmod(0o644)
    fixture = Fixture(root, 'candidate', 'ubusd')
    try:
        fixture.start_bus()
        assert digest(Path(f'/proc/{fixture.subject.pid}/exe')) == sha256
        if case == 'acl':
            acl_case(fixture, acl, result)
        else:
            lookup_case(fixture, case == 'pipeline', result)
        result['passed'] = True
    except Exception as error:
        result['error'] = repr(error)
    finally:
        fixture.close()
        output.write_text(json.dumps(result, indent=2) + '\n')
    return result['passed']


def main():
    if sys.argv[1:2] == ['--acl-child']:
        acl_child(socket.socket(fileno=int(sys.argv[2])), Path(sys.argv[3]))
        return
    if sys.argv[1:2] == ['--denied']:
        client = Bus(Path(sys.argv[2]))
        code, replies = client.request(4, attr(2, b'fixed.00063\0'))
        sys.stdout.write('1' if code == 0 and replies == [] else '0')
        return
    if sys.argv[1:2] == ['--inner']:
        raise SystemExit(0 if inner(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), sys.argv[5]) else 1)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ns-exec', type=Path, required=True)
    parser.add_argument('--cases', nargs='+', choices=('full', 'pipeline', 'acl'), default=('full', 'pipeline', 'acl'))
    args = parser.parse_args()
    assert sys.platform == 'linux' and not Path('/etc/openwrt_release').exists()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    frozen = args.output / 'frozen-ubusd'
    shutil.copy2(args.binary, frozen)
    frozen.chmod(0o555)
    sha256 = digest(frozen)
    assert frozen.stat().st_ino != args.binary.stat().st_ino or frozen.stat().st_dev != args.binary.stat().st_dev
    dependencies = {name: Path(sys.modules[name].__file__) for name in ('r92_compat_probe', 'r92_recovery_probe', 'r92_httpd_probe')}
    result = dict(binary_sha256=sha256, original_ubusd_sha256=digest(args.rootfs / 'sbin/ubusd'),
                  tool_sha256=digest(Path(__file__)), ns_exec_sha256=digest(args.ns_exec),
                  dependency_sha256={name: digest(path) for name, path in dependencies.items()},
                  performance_claim=False, cases=[])
    for case in args.cases:
        destination = args.output / case
        destination.mkdir()
        with tempfile.TemporaryDirectory(prefix='r93-prefix-') as temporary:
            root = Path(temporary) / 'root'
            shutil.copytree(args.rootfs, root, symlinks=True)
            for directory in ('out', 'run/ubus', 'lock', 'state'):
                (root / 'tmp' / directory).mkdir(parents=True, exist_ok=True)
            assert digest(frozen) == sha256
            shutil.copy2(frozen, root / 'tmp/ubusd-rs')
            command = ['sudo', '-n', 'env', 'PYTHONPATH=' + str(Path(__file__).resolve().parent) + ':' + os.environ.get('PYTHONPATH', ''),
                       str(args.ns_exec), sys.executable, str(Path(__file__).resolve()), '--inner', str(root), case,
                       str(destination / 'result.json'), sha256]
            with (destination / 'driver.log').open('w') as log:
                process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
                try:
                    code = process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    code = 124
            shutil.copytree(root / 'tmp/out', destination / 'logs')
        row = json.loads((destination / 'result.json').read_text()) if (destination / 'result.json').exists() else {'passed': False, 'error': 'missing result'}
        row.update(case=case, exit=code)
        row['passed'] = row['passed'] and code == 0 and digest(frozen) == sha256
        result['cases'].append(row)
        (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(row), flush=True)
    result['passed'] = all(row['passed'] for row in result['cases'])
    (args.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.output / ('COMPLETE' if result['passed'] else 'FAILED')).touch()
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
