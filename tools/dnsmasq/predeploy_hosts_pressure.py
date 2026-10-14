#!/usr/bin/env python3
"""Exact-image hosts allocation failure, two reloads, TCP/UDP and DHCP recovery.

Run under run_isolated.sh. All files and processes remain in private namespaces.
The original B1 reproduction remains audit_integration_resources.py --kinds memory.
This adds hostsdir staging, expansion, repeated failures and DHCP health probes.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import time

from audit_20261011_dhcp import packet, decode
from audit_integration_resources import safe_dns, status
from m2_rootfs import command, prepare, sha256, STOCK_SHA256


def answers(name, address):
    result = {kind: safe_dns(name=name, tcp=kind == 'tcp') for kind in ('udp', 'tcp')}
    for reply in result.values():
        reply['expected_address'] = reply['ok'] and any(
            rr.get('data') == address for rr in reply['reply']['records'])
    return result


def dhcp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
        client.bind(('0.0.0.0', 68))
        client.settimeout(2)
        client.sendto(packet(3, 0x74131001, name='lease'), ('255.255.255.255', 67))
        return decode(client.recv(4096))


def wait_ready(proc):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        assert proc.poll() is None, f'daemon exited: {proc.returncode}'
        reply = safe_dns()
        if reply['ok'] and any(rr.get('data') == '192.0.2.41' for rr in reply['reply']['records']):
            return
    raise TimeoutError('configured ready host unavailable')


def run(args, side, source, expand):
    out = args.output / f'{source}-expand{int(expand)}-{side}'
    out.mkdir()
    root = prepare(args.image_root, None, out / 'stage', args.rust)
    data = root / 'm2'
    folder = data / 'hostsdir'
    folder.mkdir()
    hosts = folder / 'hosts'
    hosts.write_text('192.0.2.42 initial.test\n')
    configured = '--hostsdir=/m2/hostsdir' if source == 'directory' else '--addn-hosts=/m2/hostsdir/hosts'
    argv = ['-k', '--conf-file=', '--no-resolv', '--no-hosts', '--no-ping', '--user=root',
            '--group=root', '--listen-address=127.0.0.1', '--port=15353', '--pid-file=/m2/pid',
            '--host-record=ready.test,192.0.2.41', configured, '--log-facility=/dev/null',
            '--dhcp-authoritative', '--domain=test', '--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,1h',
            '--dhcp-host=02:00:00:00:00:01,127.0.0.30,lease', '--dhcp-leasefile=/m2/leases']
    if expand:
        argv.append('--expand-hosts')
    result = {'side': side, 'source': source, 'expand': expand, 'argv': argv,
              'binary_sha256': sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs')),
              'pressure_rounds': [], 'passed': False}
    tracer = None
    with (out / 'stderr.log').open('wb') as log:
        proc = subprocess.Popen(command(root, side, *argv), stdout=log, stderr=log)
        try:
            wait_ready(proc)
            result['initial_dhcp'] = dhcp()
            result['initial_lease_dns'] = answers('lease.test', '127.0.0.30')
            result['initial_memory'] = status(proc.pid)
            previous = resource.prlimit(proc.pid, resource.RLIMIT_AS)
            limit = result['initial_memory']['VmSize'] * 1024 + 1024 * 1024
            result['limit_bytes'] = limit
            resource.prlimit(proc.pid, resource.RLIMIT_AS, (limit, previous[1]))
            tracer = subprocess.Popen(['strace', '-f', '-qq', '-p', str(proc.pid), '-e',
                                       'trace=memory,tgkill', '-o', str(out / 'syscalls.log')],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(.1)
            for generation in ('h', 'j'):
                replacement = data / 'replacement'
                replacement.write_text(''.join(f'192.0.2.{i % 250 + 1} {generation}{i:06d}'
                    + ('' if expand else '.test') + '\n' for i in range(30000)))
                replacement.replace(hosts)
                if source == 'file':
                    proc.send_signal(signal.SIGHUP)
                time.sleep(2)
                wait_ready(proc)
                result['pressure_rounds'].append({'generation': generation, 'alive': proc.poll() is None,
                    'ready': answers('ready.test', '192.0.2.41'),
                    'lease_dns': answers('lease.test', '127.0.0.30'), 'dhcp': dhcp(),
                    'memory': status(proc.pid)})
            resource.prlimit(proc.pid, resource.RLIMIT_AS, previous)
            replacement = data / 'replacement'
            replacement.write_text('192.0.2.44 recovered.test\n')
            replacement.replace(hosts)
            proc.send_signal(signal.SIGHUP)
            time.sleep(.3)
            wait_ready(proc)
            result['recovered'] = answers('recovered.test', '192.0.2.44')
            result['recovered_dhcp'] = dhcp()
            # C can reject a TCP child under the same address-space ceiling;
            # measure it separately from the shared daemon-survival contract.
            result['pressure_tcp_healthy'] = all(
                row[key]['tcp']['expected_address']
                for row in result['pressure_rounds'] for key in ('ready', 'lease_dns'))
            result['passed'] = all(row[key]['udp']['expected_address']
                for row in result['pressure_rounds'] for key in ('ready', 'lease_dns'))
            result['passed'] &= all(row['dhcp']['message_type'] == 5 for row in result['pressure_rounds'])
            result['passed'] &= all(reply['expected_address'] for reply in result['recovered'].values())
            result['passed'] &= result['recovered_dhcp']['message_type'] == 5
        except Exception as error:
            result['error'] = repr(error)
        finally:
            result['exit_before_stop'] = proc.poll()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            result['exit'] = proc.returncode
            if tracer:
                tracer.wait(3)
                trace = (out / 'syscalls.log').read_text()
                result['enomem_count'] = trace.count('ENOMEM')
                result['syscalls_sha256'] = sha256(out / 'syscalls.log')
            result['passed'] &= result['exit_before_stop'] is None and result['exit'] == 0
            result['passed'] &= result.get('enomem_count', 0) > 0
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert not args.output.exists() and 'private' in args.output.parts
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.mkdir(parents=True)
    result = {'source_commit': args.source_commit, 'driver_sha256': sha256(Path(__file__)),
              'rust_sha256': sha256(args.rust), 'cases': []}
    for source in ('file', 'directory'):
        for expand in (False, True):
            for side in ('c', 'rust'):
                row = run(args, side, source, expand)
                result['cases'].append(row)
                print(json.dumps({'side': side, 'source': source, 'expand': expand,
                                  'passed': row['passed'], 'error': row.get('error')}), flush=True)
                (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    result['passed'] = all(row['passed'] for row in result['cases'])
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
