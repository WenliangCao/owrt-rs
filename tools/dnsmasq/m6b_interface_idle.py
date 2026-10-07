#!/usr/bin/env python3
"""Actual address/DAD actor gate with no DNS/TFTP requests before binding proof.

Prepared locally; run only in run_isolated.sh on the exact image. Fresh raw
samples, failures and cleanup remain private. This tool never touches a router.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import m5_listeners as fixture
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256

PORT = fixture.DNS_PORT
CASES = ('dynamic-dns-idle', 'dynamic-tftp-port0-idle', 'static-dad-idle', 'static-tftp-port0-dad-idle')


def save(path, value):
    fixture.save(path, value)


def wait_inventory(process, address, ports, present, out, label, seconds=3):
    rows = []
    deadline = time.monotonic() + seconds
    while True:
        if process.poll() is not None:
            raise RuntimeError('daemon exited before idle interface proof')
        observed = fixture.inventory(process.pid)
        found = {(row['transport'], row['port']) for row in observed if row['address'] == address}
        rows.append({'monotonic_ns': time.monotonic_ns(), 'sockets': observed})
        matched = ports <= found if present else not (ports & found)
        save(out / (label + '.json'), {'address': address, 'expected_ports': sorted(ports),
                                     'present': present, 'service_requests_sent': 0, 'samples': rows, 'passed': matched})
        if matched:
            return {'case': label, 'address': address, 'ports': sorted(found), 'service_requests_sent': 0}
        if time.monotonic() >= deadline:
            raise TimeoutError('address/DAD state never reached expected bindings without traffic')
        time.sleep(.02)


def side(args):
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('root in run_isolated.sh required')
    if 'private' not in args.out.resolve().parts:
        raise ValueError('fresh private evidence required')
    args.out.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.out / 'filesystem', args.rust_binary)
    (root / 'm2/tftp').mkdir(); (root / 'm2/tftp/boot.bin').write_bytes(b'idle interface proof\n')
    rows, failures = [], []
    for case in CASES:
        out = args.out / case; out.mkdir()
        process = net = None
        observations = []
        try:
            net = fixture.Network()
            dad = 'dad' in case
            port = 0 if 'port0' in case else PORT
            tftp = dad or 'tftp' in case
            mode = 'bind-interfaces' if dad else 'bind-dynamic'
            address = 'fd42:77::9' if dad else '10.77.0.9'
            ports = {('udp', 69)} if port == 0 else {('udp', port), ('tcp', port)}
            if tftp: ports.add(('udp', 69))
            if dad:
                Path('/proc/sys/net/ipv6/neigh/lan/retrans_time_ms').write_text('3000')
                Path('/proc/sys/net/ipv6/conf/lan/dad_transmits').write_text('1')
                fixture.ip('-6', 'addr', 'add', address + '/64', 'dev', 'lan')
            config = f'port={port}\nno-hosts\nno-resolv\nuser=root\ngroup=root\npid-file=/m2/pid\n{mode}\ninterface=lan\n'
            if tftp: config += 'enable-tftp\ntftp-root=/m2/tftp\n'
            (root / 'm2/idle.conf').write_text(config); (out / 'config').write_text(config)
            fixture.snapshot(out / 'network-start.json')
            with (out / 'daemon.log').open('wb') as log:
                process = subprocess.Popen(command(root, args.side, '-k', '-C', '/m2/idle.conf'),
                                           stdout=log, stderr=log, start_new_session=True)
                deadline = time.monotonic() + 4
                while not (root / 'm2/pid').exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('daemon readiness failed')
                    time.sleep(.01)
                identity = process_identity(root, process.pid)
                expected = STOCK_SHA256 if args.side == 'c' else sha256(args.rust_binary)
                if identity['sha256'] != expected: raise ValueError('ELF identity differs')
                save(out / 'identity.json', identity)
                if dad:
                    flags = next(row for link in json.loads(fixture.ip('-j', 'addr', 'show', 'dev', 'lan').stdout)
                                 for row in link['addr_info'] if row['local'] == address)
                    if not flags.get('tentative'): raise RuntimeError('DAD not tentative at startup witness')
                    observations.append(wait_inventory(process, address, ports, False, out, 'tentative-unbound'))
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        flags = next(row for link in json.loads(fixture.ip('-j', 'addr', 'show', 'dev', 'lan').stdout)
                                     for row in link['addr_info'] if row['local'] == address)
                        save(out / 'dad-flags.json', {'monotonic_ns': time.monotonic_ns(), 'flags': flags})
                        if flags.get('dadfailed'): raise RuntimeError('DAD unexpectedly failed')
                        if not flags.get('tentative'): break
                        time.sleep(.02)
                    else: raise TimeoutError('DAD never matured')
                    observations.append(wait_inventory(process, address, ports, True, out, 'dad-bound'))
                else:
                    observations.append(wait_inventory(process, address, ports, False, out, 'before-add'))
                    fixture.ip('addr', 'add', address + '/24', 'dev', 'lan')
                    observations.append(wait_inventory(process, address, ports, True, out, 'added-bound'))
                    fixture.ip('addr', 'del', address + '/24', 'dev', 'lan')
                    observations.append(wait_inventory(process, address, ports, False, out, 'removed-unbound'))
                    fixture.ip('addr', 'add', address + '/24', 'dev', 'lan')
                    observations.append(wait_inventory(process, address, ports, True, out, 'readded-bound'))
                rows.append({'case': case, 'observations': observations})
        except Exception as error:
            failure = {'case': case, 'error': repr(error)}; failures.append(failure); save(out / 'failure.json', failure)
        finally:
            ended = fixture.stop(process) if process else None
            peer = net.close() if net else None
            save(out / 'cleanup.json', {'daemon': ended, 'peer': peer})
            if ended and (ended['forced'] or ended['returncode'] != 0): failures.append({'case': case, 'cleanup': ended})
            (root / 'm2/pid').unlink(missing_ok=True)
    result = {'side': args.side, 'rows': rows, 'failures': failures, 'passed': not failures and len(rows) == len(CASES)}
    save(args.out / 'result.json', result); return 0 if result['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--side', choices=('c', 'rust', 'both'), default='both')
    args = parser.parse_args()
    args.out = args.out.resolve()
    if 'private' not in args.out.parts: raise ValueError('fresh private evidence required')
    if args.side != 'both': return side(args)
    args.out.mkdir(parents=True, exist_ok=False)
    reports, exits = {}, {}
    for name in ('c', 'rust'):
        command_line = ['sh', str(Path(__file__).with_name('run_isolated.sh')), sys.executable, __file__,
                        '--side', name, '--image-root', str(args.image_root), '--rust-binary', str(args.rust_binary),
                        '--out', str(args.out / name)]
        with (args.out / (name + '.log')).open('wb') as log:
            exits[name] = subprocess.run(command_line, stdout=log, stderr=log).returncode
        reports[name] = json.loads((args.out / name / 'result.json').read_text())
    passed = not any(exits.values()) and all(report['passed'] for report in reports.values()) and reports['c']['rows'] == reports['rust']['rows']
    save(args.out / 'result.json', {'passed': passed, 'exits': exits, 'reports': reports, 'physical_router': False})
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
