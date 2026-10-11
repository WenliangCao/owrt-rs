#!/usr/bin/env python3
"""Send one DHCPREQUEST while startup is blocked on a resolv FIFO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    sys.path.insert(0, str(args.source / 'tools/dnsmasq'))
    from m2_rootfs import image_elf_command, STOCK_SHA256
    from audit_20261011_dhcp import packet, decode, dns_answer
    stock = args.image_root / 'usr/sbin/dnsmasq'
    assert sha(stock) == STOCK_SHA256
    args.out.mkdir(parents=True, exist_ok=False)
    commands = {'c': image_elf_command(args.image_root, stock),
                'rust': image_elf_command(args.image_root, args.rust)}
    report = {'script_sha256': sha(__file__), 'c_sha256': sha(stock),
              'rust_sha256': sha(args.rust), 'observed': {}, 'passed': False}
    for side, command in commands.items():
        folder = args.out / side
        folder.mkdir()
        hosts, leases, resolver = [folder / name for name in ('hosts', 'leases', 'resolv.conf')]
        hosts.write_text('127.0.0.30 authoritative-one.test\n127.0.0.31 authoritative-two.test\n')
        leases.write_text('0 02:00:00:00:00:01 127.0.0.30 restored-one *\n'
                          '0 02:00:00:00:00:02 127.0.0.31 restored-two *\n')
        os.mkfifo(resolver)
        opened, release = threading.Event(), threading.Event()
        writer_state = {}
        def writer():
            with resolver.open('wb', buffering=0) as stream:
                writer_state['opened_monotonic_ns'] = time.monotonic_ns()
                stream.write(b'nameserver 127.0.0.1\n')
                opened.set()
                if not release.wait(5):
                    raise AssertionError('controller failed to release FIFO')
                replacement = resolver.with_suffix('.ready')
                replacement.write_bytes(b'nameserver 127.0.0.1\n')
                replacement.replace(resolver)
                writer_state['closing_monotonic_ns'] = time.monotonic_ns()
        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        argv = command + ['-C', '/dev/null', '-k', '--user=root', '--group=root', '--pid-file=',
            '--no-hosts', '--bind-interfaces', '--listen-address=127.0.0.1', '--port=15353',
            '--no-ping', '--dhcp-authoritative', '--domain=test',
            '--dhcp-range=127.0.0.30,127.0.0.31,255.0.0.0,infinite',
            '--addn-hosts=' + str(hosts), '--resolv-file=' + str(resolver),
            '--dhcp-leasefile=' + str(leases), '--log-facility=-', '--log-dhcp']
        row = {'argv': argv, 'writer': writer_state}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, (folder / 'daemon.log').open('wb') as log:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
            client.bind(('0.0.0.0', 68))
            proc = subprocess.Popen(argv, stdout=log, stderr=log,
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC'})
            try:
                if not opened.wait(3):
                    raise AssertionError('daemon did not open startup resolver')
                time.sleep(.05)
                request = packet(3, 0x77112233, name='supplied-wrong')
                row['request'] = request.hex()
                row['send_monotonic_ns'] = time.monotonic_ns()
                client.sendto(request, ('255.255.255.255', 67))
                client.settimeout(.25)
                try:
                    early = client.recv(4096)
                    assert early[4:8] == request[4:8] and early[28:34] == request[28:34]
                    row['early_reply'] = {'wire': early.hex(), 'decoded': decode(early), 'monotonic_ns': time.monotonic_ns()}
                except socket.timeout:
                    row['early_reply'] = None
                row['observation_end_monotonic_ns'] = time.monotonic_ns()
                assert 'closing_monotonic_ns' not in writer_state
                release.set()
                thread.join(timeout=2)
                assert not thread.is_alive()
                if row['early_reply'] is None:
                    client.settimeout(3)
                    reply = client.recv(4096)
                    assert reply[4:8] == request[4:8] and reply[28:34] == request[28:34]
                    row['reply_after_release'] = {'wire': reply.hex(), 'decoded': decode(reply), 'monotonic_ns': time.monotonic_ns()}
                else:
                    row['reply_after_release'] = None
                deadline = time.monotonic() + 3
                while True:
                    try:
                        row['dns_after'] = dns_answer('authoritative-one.test', 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                row['alive_before_stop'] = proc.poll() is None
                row['leases_before_stop'] = leases.read_text()
            finally:
                release.set()
                if proc.poll() is None:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
                row['exit'] = proc.returncode
                thread.join(timeout=1)
        row['log'] = (folder / 'daemon.log').read_text()
        report['observed'][side] = row
        (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    c, rust = report['observed']['c'], report['observed']['rust']
    report['checks'] = {'both_hold_DHCP_until_resolver_complete': c['early_reply'] is None and rust['early_reply'] is None,
        'both_healthy': all(r['alive_before_stop'] and r['exit'] == 0 for r in (c, rust)),
        'DNS_after_equal': c['dns_after'] == rust['dns_after'],
        'ACK_after_equal': c['reply_after_release'] is not None and rust['reply_after_release'] is not None and c['reply_after_release']['decoded'] == rust['reply_after_release']['decoded'],
        'C_returns_authoritative_name': c['reply_after_release'] is not None and c['reply_after_release']['decoded']['message_type'] == 5 and c['reply_after_release']['decoded']['hostname'] == 'authoritative-one'}
    report['passed'] = all(report['checks'].values())
    (args.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': report['checks'],
        'early_reply': {side: value['early_reply'] for side, value in report['observed'].items()}}, indent=2))
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
