#!/usr/bin/env python3
"""One offline RA correctness case; run under a private mount/net/pid namespace."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from odhcpd_baseline import Fixture, run


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rootfs', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--daemon')
    args = parser.parse_args()
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    Path(args.out).mkdir()
    fixture = Fixture(args)
    try:
        fixture.setup()
        run('sysctl', '-q', '-w', 'net.ipv6.conf.br-lan.hop_limit=64')
        fixture.start_daemon()
        time.sleep(.3)
        before = fixture.request('before', 'rs')['decoded']['hop_limit']
        run('sysctl', '-q', '-w', 'net.ipv6.conf.br-lan.hop_limit=123')
        after = fixture.request('after_sysctl', 'rs')['decoded']['hop_limit']
        fixture.daemon.send_signal(signal.SIGHUP)
        time.sleep(.3)
        reloaded = fixture.request('after_reload', 'rs')['decoded']['hop_limit']
        result = {'before': before, 'after_sysctl': after, 'after_reload': reloaded,
                  'kernel': Path('/proc/sys/net/ipv6/conf/br-lan/hop_limit').read_text().strip()}
        fixture.record('hop_limit_result', result)
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


if __name__ == '__main__':
    main()
