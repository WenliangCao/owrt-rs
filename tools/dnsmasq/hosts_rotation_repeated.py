#!/usr/bin/env python3
"""Diagnose repeated-address order with unchanged exact-image C/Rust ELFs.

Run through run_isolated.sh. Preserve warmup order and all diagnostic replies;
this is a semantic probe, not a performance or memory measurement.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from hosts_rotation_memory import address_order, connect, tcp, udp
from m2_rootfs import STOCK_SHA256, command, prepare, sha256


def run(args, label, binary):
    out = args.output / label
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', binary)

    def address(i, j):
        if args.unique_addresses:
            return f'10.{j + 1}.{i // 256}.{i % 256}'
        return f'192.0.{j + 2}.{i % 250 + 1}'

    (root / 'm2/hosts').write_text(''.join(
        f'{address(i, j)} host{i:06d}.test\n'
        for i in range(args.names) for j in (0, 1)))
    argv = command(root, 'c' if label.startswith('c-') else 'rust',
                   '-k', '--conf-file=', '--no-resolv', '--no-hosts',
                   '--user=root', '--group=root', '--listen-address=127.0.0.1',
                   '--bind-interfaces', '--port=15353', '--pid-file=/m2/pid',
                   '--host-record=ready.test,192.0.2.41',
                   '--addn-hosts=/m2/hosts', '--cache-size=1000',
                   '--log-facility=/dev/null')
    if args.c_cache_dump and label.startswith('c-'):
        argv[-1] = '--log-facility=/m2/diagnostic.log'
        argv.append('--log-queries')
    result = {'label': label, 'argv': argv, 'binary_sha256': sha256(binary),
              'hosts_sha256': sha256(root / 'm2/hosts'), 'warmup': {}, 'probes': {}}
    with (out / 'stderr').open('wb') as log:
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            for _ in range(100):
                assert process.poll() is None, 'startup exited'
                try:
                    udp('ready.test', 1)
                    break
                except (TimeoutError, ConnectionRefusedError):
                    time.sleep(0.02)
            else:
                raise RuntimeError('startup timeout')
            for i in range(args.names):
                name = f'host{i:06d}.test'
                result['warmup'][name] = udp(name).hex()
            for i in args.probe_names:
                name = f'host{i:06d}.test'
                rows = []
                for j in range(4):
                    wire = udp(name)
                    rows.append({'label': f'udp-{j}', 'wire': wire.hex(),
                                 'addresses': address_order(wire)})
                with connect() as client:
                    for j in range(4):
                        wire = tcp(client, name)
                        rows.append({'label': f'tcp-{j}', 'wire': wire.hex(),
                                     'addresses': address_order(wire)})
                result['probes'][name] = rows
            result['udp_after'] = udp('ready.test', 1).hex()
            result['exit_before_cleanup'] = process.poll()
            if args.c_cache_dump and label.startswith('c-'):
                process.send_signal(signal.SIGUSR1)
                cache_log = root / 'm2/diagnostic.log'
                for _ in range(150):
                    log_text = cache_log.read_text()
                    if log_text.count('4FRI') + log_text.count('4F I') >= args.names * 2:
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError('cache dump incomplete')
                shutil.copy2(cache_log, out / 'daemon.log')
                result['daemon_log_sha256'] = sha256(out / 'daemon.log')
                result['cache_dump'] = {
                    f'host{i:06d}.test': [line for line in log_text.splitlines()
                                         if f'host{i:06d}.test'.ljust(30) in line]
                    for i in args.probe_names}
        finally:
            process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--old-rust', type=Path, required=True)
    parser.add_argument('--fixed-rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--names', type=int, default=30000)
    parser.add_argument('--unique-addresses', action='store_true')
    parser.add_argument('--c-cache-dump', action='store_true')
    parser.add_argument('--probe-names', default='0,63,249,250,312,313,314,375,499,500,1935,1999')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert not args.output.exists()
    assert 1 <= args.names <= 65536
    args.probe_names = [int(i) for i in args.probe_names.split(',')]
    assert all(0 <= i < args.names for i in args.probe_names)
    exact_c = args.image_root / 'usr/sbin/dnsmasq'
    assert sha256(exact_c) == STOCK_SHA256
    args.output.mkdir(parents=True)
    (args.output / 'driver.py').write_bytes(Path(__file__).read_bytes())
    result = {'driver_sha256': sha256(Path(__file__)), 'names': args.names,
              'unique_addresses': args.unique_addresses, 'runs': []}
    for label, binary in [('c-first', exact_c), ('old-rust', args.old_rust),
                          ('fixed-rust', args.fixed_rust), ('c-repeat', exact_c)]:
        result['runs'].append(run(args, label, binary))
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(label, 'complete', flush=True)


if __name__ == '__main__':
    main()
