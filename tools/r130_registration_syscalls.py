#!/usr/bin/env python3
"""Oracle-only structural check; traced timings are never performance results."""
import argparse
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--oracle-host-only', action='store_true', required=True)
    p.add_argument('--control', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--benchmark', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    assert platform.machine() == 'aarch64' and not Path('/etc/openwrt_release').exists()
    assert sha(args.control) == '42435a31e2917186fb353e2c70143f4b3f6d82ec3dd53265bf6d826897b69926'
    assert sha(args.benchmark) == '984f6ec0926e7bc595a9fbe4f536446e7fec2bc7f10f752c895186adfb09cd1e'
    args.out.mkdir(parents=True, exist_ok=False)
    n, warmup = 100, 20
    cycles = n + warmup + 1  # The caller also performs one validated preflight cycle.
    rows = []
    for methods in (1, 16):
        for label, binary, calls_per_cycle in (('r124', args.control, 4), ('r130', args.candidate, 3)):
            out = args.out / f'{label}-{methods}'
            out.mkdir()
            daemon = tracer = None
            with tempfile.TemporaryDirectory(prefix='r130-trace-') as directory:
                sock = str(Path(directory) / 'ubus.sock')
                with (out / 'daemon.log').open('wb') as log, (out / 'strace.log').open('wb') as trace_log:
                    try:
                        daemon = subprocess.Popen([str(args.benchmark), 'exec-cpu-as', '1', str(binary),
                                                   '/sbin/ubusd', '-s', sock, '-A', directory],
                                                  stdout=log, stderr=subprocess.STDOUT)
                        deadline = time.monotonic() + 5
                        while not Path(sock).exists():
                            assert daemon.poll() is None and time.monotonic() < deadline
                            time.sleep(0.01)
                        assert os.sched_getaffinity(daemon.pid) == {1}
                        assert Path(f'/proc/{daemon.pid}/cmdline').read_bytes().split(b'\0')[0] == b'/sbin/ubusd'
                        assert sha(f'/proc/{daemon.pid}/exe') == sha(binary)
                        tracer = subprocess.Popen(['strace', '-qq', '-xx', '-s', '64', '-e', 'trace=sendmsg',
                                                   '-o', str(out / 'trace.txt'), '-p', str(daemon.pid)],
                                                  stdout=trace_log, stderr=subprocess.STDOUT)
                        deadline = time.monotonic() + 5
                        while int(re.search(r'TracerPid:\s+(\d+)', Path(f'/proc/{daemon.pid}/status').read_text())[1]) == 0:
                            assert tracer.poll() is None and time.monotonic() < deadline
                            time.sleep(0.01)
                        command = [str(args.benchmark), 'exec-cpu', '0', str(args.benchmark), 'register-cycle',
                                   sock, str(methods), '8', str(n), str(warmup), str(daemon.pid)]
                        with (out / 'caller.json').open('wb') as caller, (out / 'caller.log').open('wb') as err:
                            subprocess.run(command, stdout=caller, stderr=err, timeout=30, check=True)
                        stop(tracer, signal.SIGINT)
                        assert sha(f'/proc/{daemon.pid}/exe') == sha(binary)
                        trace = (out / 'trace.txt').read_text()
                        calls = [line for line in trace.splitlines() if line.startswith('sendmsg(')]
                        assert all(re.search(r' = [1-9][0-9]*$', line) for line in calls), 'failed or incomplete send'
                        # HELLO + combined exact LOOKUP + two empty LOOKUP statuses.
                        expected = calls_per_cycle * cycles + 4
                        row = {'subject': label, 'methods': methods, 'sha256': sha(binary),
                               'iterations': n, 'warmup': warmup, 'successful_adds': cycles,
                               'sendmsg_calls': len(calls), 'expected_sendmsg_calls': expected,
                               'trace_sha256': sha(out / 'trace.txt'), 'caller_sha256': sha(out / 'caller.json')}
                        (out / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
                        assert len(calls) == expected, row
                        rows.append(row)
                    finally:
                        stop(tracer, signal.SIGINT)
                        stop(daemon)
            (out / 'COMPLETE').touch()
    result = {'scope': 'Oracle syscall counts only; all traced latency/CPU excluded from performance claims',
              'runner_sha256': sha(__file__), 'benchmark_sha256': sha(args.benchmark), 'samples': rows}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.out / 'COMPLETE').touch()


if __name__ == '__main__':
    main()
