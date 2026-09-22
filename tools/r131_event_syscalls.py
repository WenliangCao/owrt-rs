#!/usr/bin/env python3
"""Oracle-only exact-ELF event frame/sendmsg accounting, never a timing result."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tempfile
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stop(process, sig=signal.SIGTERM):
    if process is not None and process.poll() is None:
        process.send_signal(sig)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def event_calls(trace):
    histogram = Counter()
    all_calls = 0
    for line in trace.splitlines():
        if not line.startswith('sendmsg('):
            continue
        all_calls += 1
        result = re.search(r' = ([0-9]+)$', line)
        assert result is not None, 'failed or unfinished sendmsg'
        parts = re.findall(r'iov_base="((?:\\x[0-9a-f]{2})*)", iov_len=([0-9]+)', line)
        assert parts, 'missing or truncated iovec'
        data = b''
        for encoded, length in parts:
            part = bytes.fromhex(encoded.replace('\\x', ''))
            assert len(part) == int(length), 'truncated iovec payload'
            data += part
        assert int(result[1]) == len(data), 'unexpected short write in unblocked fixture'
        assert 'msg_controllen=0' in line, 'event fixture must not carry ancillary data'
        offset, events = 0, 0
        while offset < len(data):
            assert len(data) - offset >= 12, 'incomplete wire prefix'
            length = int.from_bytes(data[offset + 8:offset + 12], 'big') & 0xffffff
            end = offset + 8 + length
            assert length >= 4 and end <= len(data), 'incomplete wire frame'
            if data[offset + 1] == 5 and b'bench.user\0' in data[offset + 12:end]:
                events += 1
            offset = end
        if events:
            histogram[events] += 1
    return all_calls, histogram


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-host-only', action='store_true', required=True)
    p.add_argument('--rootfs', type=Path, required=True)
    p.add_argument('--control', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--client', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    assert platform.machine() == 'aarch64' and not Path('/etc/openwrt_release').exists()
    assert sha(a.control) == '42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926'
    assert sha(a.candidate) == 'c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a'
    assert sha(a.client) == '2f58c60ddd6421476c140673cd7d4c4310c5f5eda71be1f4d7eab1a4d6c1efcf'
    loader = a.rootfs / 'lib/libc.so'
    libraries = {
        'lib/libc.so': '8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b',
        'lib/libubus.so.20251202': '2967f7ce6e29e290eac0b76e88fc6b5d639763fa78be1e1b889fb088d9acda04',
        'lib/libubox.so.20260213': 'a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063',
        'lib/libgcc_s.so.1': '33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c',
        'lib/libblobmsg_json.so.20260213': 'e6a2a2cdf07f453c28f703537c636516e92d17b63ad732ec606b5cd99bd5ef97',
        'usr/lib/libjson-c.so.5.4.0': '830799c5682eff7f75800482dabd65a1fe2e925374a19da2a25a2da708d8a153',
    }
    for path, expected in libraries.items():
        assert sha(a.rootfs / path) == expected, path
    command_prefix = [str(loader), '--library-path', f'{a.rootfs}/lib:{a.rootfs}/usr/lib', str(a.client)]
    a.out.mkdir(parents=True, exist_ok=False)
    n, warmup = 100, 20
    rows = []
    for listeners in (1, 8):
        for label, binary in (('r124', a.control), ('r131', a.candidate)):
            out = a.out / f'{label}-{listeners}'
            out.mkdir()
            daemon = tracer = None
            with tempfile.TemporaryDirectory(prefix='r131-trace-') as directory:
                sock = str(Path(directory) / 'bus.sock')
                with (out / 'daemon.log').open('wb') as log, (out / 'strace.log').open('wb') as trace_log:
                    try:
                        daemon = subprocess.Popen(['/sbin/ubusd', '-s', sock, '-A', directory],
                            executable=str(binary), stdout=log, stderr=subprocess.STDOUT)
                        os.sched_setaffinity(daemon.pid, {1})
                        deadline = time.monotonic() + 5
                        while not Path(sock).exists():
                            assert daemon.poll() is None and time.monotonic() < deadline
                            time.sleep(0.01)
                        assert os.sched_getaffinity(daemon.pid) == {1}
                        assert Path(f'/proc/{daemon.pid}/cmdline').read_bytes().split(b'\0')[0] == b'/sbin/ubusd'
                        assert sha(f'/proc/{daemon.pid}/exe') == sha(binary)
                        tracer = subprocess.Popen(['strace', '-qq', '-xx', '-s', '65535', '-e', 'trace=sendmsg',
                            '-o', str(out / 'trace.txt'), '-p', str(daemon.pid)], stdout=trace_log, stderr=subprocess.STDOUT)
                        deadline = time.monotonic() + 5
                        while int(re.search(r'TracerPid:\s+(\d+)', Path(f'/proc/{daemon.pid}/status').read_text())[1]) == 0:
                            assert tracer.poll() is None and time.monotonic() < deadline
                            time.sleep(0.01)
                        with (out / 'caller.json').open('wb') as caller, (out / 'caller.log').open('wb') as err:
                            subprocess.run(command_prefix + ['user-event', sock, str(listeners), '1', str(n),
                                str(warmup), str(daemon.pid)], stdout=caller, stderr=err, timeout=30, check=True)
                        stop(tracer, signal.SIGINT)
                        all_calls, histogram = event_calls((out / 'trace.txt').read_text())
                        expected = {1: (n + warmup) * listeners}
                        if label == 'r131' and listeners == 8:
                            expected = {1: n + warmup, 7: n + warmup}
                        assert histogram == expected, (histogram, expected)
                        result = json.loads((out / 'caller.json').read_text())
                        assert result['payload_checked'] and result['handlers_removed']
                        assert result['received'] == n * listeners
                        assert result['warmup_received'] == warmup * listeners
                        assert sha(f'/proc/{daemon.pid}/exe') == sha(binary)
                        rows.append({'subject': label, 'listeners': listeners, 'sha256': sha(binary),
                            'iterations': n, 'warmup': warmup, 'sendmsg_calls': all_calls,
                            'event_sendmsg_calls': sum(histogram.values()),
                            'event_frames': sum(k * v for k, v in histogram.items()),
                            'event_frames_per_sendmsg': dict(histogram),
                            'trace_sha256': sha(out / 'trace.txt'), 'caller_sha256': sha(out / 'caller.json')})
                    finally:
                        stop(tracer, signal.SIGINT)
                        stop(daemon)
            (out / 'COMPLETE').touch()
    result = {'scope': 'Oracle syscall/frame mechanism only; traced timing and CPU are excluded',
        'runner_sha256': sha(__file__), 'client_sha256': sha(a.client),
        'library_sha256': libraries, 'samples': rows}
    (a.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    (a.out / 'COMPLETE').touch()


if __name__ == '__main__':
    main()
