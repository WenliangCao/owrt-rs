#!/usr/bin/env python3
"""Independent exact-image reload headroom sweep, with pre-existing hosts.

Run through run_isolated.sh. The driver does not change physical router state.
After lifting the limit it probes both owner transports before another HUP.
Raw trace/log data remains in the required private output directory.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

from audit_integration_resources import safe_dns, status
from m2_rootfs import command, prepare, sha256, STOCK_SHA256


def probe(name, tcp=False):
    answer = safe_dns(name=name, tcp=tcp)
    return {'ok': answer['ok'], 'rcode': (answer['reply']['flags'] & 15) if answer['ok'] else None,
            'records': answer.get('reply', {}).get('records', []),
            'error': answer.get('error')}


def run(args, side, initial, headroom):
    out = args.output / f'{side}-initial{initial}-extra{headroom}'
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', args.rust)
    hosts = root / 'm2/hosts'
    hosts.write_text(''.join(f'192.0.2.{i % 250 + 1} old{i:06d}.test\n' for i in range(initial)))
    argv = ['-k', '--conf-file=', '--no-resolv', '--no-hosts', '--user=root',
            '--group=root', '--listen-address=127.0.0.1', '--port=15353',
            '--pid-file=/m2/pid', '--host-record=ready.test,192.0.2.41',
            '--addn-hosts=/m2/hosts', '--log-facility=/dev/null']
    row = {'side': side, 'initial_rows': initial, 'headroom_kib': headroom, 'argv': argv}
    tracer = None
    with (out / 'stderr').open('wb') as stderr:
        proc = subprocess.Popen(command(root, side, *argv), stdout=stderr, stderr=stderr)
        try:
            end = time.monotonic() + 12
            while time.monotonic() < end:
                if proc.poll() is not None:
                    raise RuntimeError(f'early exit {proc.returncode}')
                if probe(f'old{initial-1:06d}.test')['records']:
                    break
            else:
                raise TimeoutError('initial hosts not ready')
            row['initial'] = status(proc.pid)
            previous = resource.prlimit(proc.pid, resource.RLIMIT_AS)
            limit = (row['initial']['VmSize'] + headroom) * 1024
            row['limit_bytes'] = limit
            tracer = subprocess.Popen(['strace', '-f', '-qq', '-p', str(proc.pid),
                '-e', 'trace=memory,tgkill', '-o', str(out / 'syscalls')],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(.1)
            resource.prlimit(proc.pid, resource.RLIMIT_AS, (limit, previous[1]))
            hosts.write_text(''.join(f'192.0.2.{i % 250 + 1} new{i:06d}.test\n' for i in range(30000)))
            proc.send_signal(signal.SIGHUP)
            time.sleep(2)
            row['pressure_exit'] = proc.poll()
            if proc.poll() is None:
                row['pressure_udp'] = {name: probe(name) for name in ('ready.test', 'old000000.test', 'new029999.test')}
                row['pressure_status'] = status(proc.pid)
                resource.prlimit(proc.pid, resource.RLIMIT_AS, previous)
                row['after_release_no_hup'] = {transport: {name: probe(name, transport == 'tcp')
                    for name in ('ready.test', 'old000000.test', 'new029999.test')}
                    for transport in ('udp', 'tcp')}
                hosts.write_text('192.0.2.44 recovered.test\n')
                proc.send_signal(signal.SIGHUP)
                time.sleep(.3)
                row['after_hup'] = {transport: probe('recovered.test', transport == 'tcp')
                    for transport in ('udp', 'tcp')}
        except Exception as error:
            row['error'] = repr(error)
        finally:
            row['exit_before_stop'] = proc.poll()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            row['exit'] = proc.returncode
            if tracer:
                tracer.wait(3)
                row['enomem_count'] = (out / 'syscalls').read_text().count('ENOMEM')
                row['trace_sha256'] = sha256(out / 'syscalls')
    row['stderr_sha256'] = sha256(out / 'stderr')
    (out / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--initial-rows', default='1,2000')
    parser.add_argument('--headroom-kib', default='256,512,1024')
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert not args.output.exists() and 'private' in args.output.parts
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    assert sha256(args.rust) == args.rust_sha256
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.mkdir(parents=True)
    result = {'driver_sha256': sha256(Path(__file__)), 'c_sha256': STOCK_SHA256,
              'rust_sha256': args.rust_sha256, 'cases': []}
    for initial in map(int, args.initial_rows.split(',')):
        for headroom in map(int, args.headroom_kib.split(',')):
            for side in ('c', 'rust'):
                row = run(args, side, initial, headroom)
                result['cases'].append(row)
                (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                print(json.dumps({'side': side, 'initial': initial, 'headroom': headroom,
                                  'exit': row['exit'], 'enomem': row.get('enomem_count'),
                                  'error': row.get('error')}), flush=True)


if __name__ == '__main__':
    main()
