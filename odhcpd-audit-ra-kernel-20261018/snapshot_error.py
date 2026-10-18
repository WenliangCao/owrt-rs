#!/usr/bin/env python3
"""One controlled syscall error in the SDK daemon's runtime snapshot."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
from odhcpd_baseline import Fixture, run

parser = argparse.ArgumentParser()
parser.add_argument('--rootfs', required=True)
parser.add_argument('--out', required=True)
parser.add_argument('--daemon', required=True)
args = parser.parse_args()
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
Path(args.out).mkdir()
fixture = Fixture(args)
try:
    fixture.setup()
    fixture.start_daemon()
    time.sleep(1.2)
    fixture.request('live_before_injection', 'rs')
    tracer = fixture.spawn('strace', [
        'strace', '-tt', '-e', 'trace=recvfrom,sendto',
        '-e', 'inject=recvfrom:error=ENOBUFS:when=3',
        '-p', str(fixture.daemon.pid)])
    for _ in range(100):
        if 'attached' in (Path(args.out) / 'strace.log').read_text():
            break
        time.sleep(.01)
    else:
        raise RuntimeError('strace did not attach')
    run('ip', 'link', 'set', 'br-lan', 'mtu', '1499')
    result = {'exit_code': fixture.daemon.wait(timeout=3)}
    fixture.record('snapshot_error_result', result)
    print(json.dumps(result), flush=True)
finally:
    for process in reversed(fixture.children):
        if process.poll() is None:
            process.terminate()
    for process in reversed(fixture.children):
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
