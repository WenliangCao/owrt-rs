#!/usr/bin/env python3
"""Build a disposable OpenWrt-shaped network inside run_isolated.sh.

The supplied rootfs and router CIDR are private runtime evidence. The command
runs in the server network; use nsenter and the exported PIDs for its client
and controlled upstream. The original dnsmasq configuration is never edited.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import time


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--router-cidr', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    assert 'private' in args.output.resolve().parts
    router = ipaddress.IPv4Interface(args.router_cidr)
    args.output.mkdir(parents=True, exist_ok=False)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert command
    nameservers = []
    for line in (args.source_root / 'tmp/resolv.conf.d/resolv.conf.auto').read_text().splitlines():
        fields = line.split()
        if fields[:1] == ['nameserver']:
            nameservers.append(ipaddress.ip_address(fields[1]))
    children = []
    try:
        for label in ('client', 'upstream'):
            process = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
            children.append(process)
            deadline = time.monotonic() + 3
            while os.readlink(f'/proc/{process.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            run('nsenter', '-t', str(process.pid), '-n', 'ip', 'link', 'set', 'lo', 'up')
        client, upstream = (str(child.pid) for child in children)
        run('ip', 'link', 'add', 'br-lan', 'type', 'bridge')
        run('ip', 'addr', 'add', str(router), 'dev', 'br-lan')
        run('ip', 'link', 'set', 'br-lan', 'up')
        run('ip', 'link', 'add', 'lan-port', 'type', 'veth', 'peer', 'name', 'client0')
        run('ip', 'link', 'set', 'lan-port', 'master', 'br-lan')
        run('ip', 'link', 'set', 'lan-port', 'up')
        run('ip', 'link', 'set', 'client0', 'netns', client)
        run('nsenter', '-t', client, '-n', 'ip', 'link', 'set', 'client0', 'up')
        run('ip', 'link', 'add', 'wan', 'type', 'veth', 'peer', 'name', 'upstream0')
        run('ip', 'link', 'set', 'upstream0', 'netns', upstream)
        # Point-to-point documentation addresses are experiment plumbing only.
        run('ip', 'addr', 'add', '192.0.2.1/30', 'dev', 'wan')
        run('ip', 'link', 'set', 'wan', 'up')
        run('nsenter', '-t', upstream, '-n', 'ip', 'addr', 'add', '192.0.2.2/30', 'dev', 'upstream0')
        run('nsenter', '-t', upstream, '-n', 'ip', 'link', 'set', 'upstream0', 'up')
        run('ip', '-6', 'addr', 'add', '2001:db8::1/126', 'dev', 'wan', 'nodad')
        run('nsenter', '-t', upstream, '-n', 'ip', '-6', 'addr', 'add', '2001:db8::2/126', 'dev', 'upstream0', 'nodad')
        for address in nameservers:
            family = '-4' if address.version == 4 else '-6'
            prefix = 32 if address.version == 4 else 128
            run('nsenter', '-t', upstream, '-n', 'ip', family, 'addr', 'add', f'{address}/{prefix}', 'dev', 'lo')
            gateway = '192.0.2.2' if address.version == 4 else '2001:db8::2'
            run('ip', family, 'route', 'add', f'{address}/{prefix}', 'via', gateway, 'dev', 'wan')
        run('nsenter', '-t', upstream, '-n', 'ip', 'route', 'add', str(router.network), 'via', '192.0.2.1')
        topology = {'router': str(router), 'client_pid': int(client), 'upstream_pid': int(upstream),
                    'nameservers': list(map(str, nameservers)), 'server_interfaces': json.loads(run('ip', '-j', 'addr'))}
        (args.output / 'topology.json').write_text(json.dumps(topology, indent=2) + '\n')
        environment = dict(os.environ, DNSMASQ_CLIENT_PID=client, DNSMASQ_UPSTREAM_PID=upstream,
                           DNSMASQ_ROUTER_ADDRESS=str(router.ip), DNSMASQ_NETWORK_EVIDENCE=str(args.output.resolve()))
        return subprocess.run(command, env=environment).returncode
    finally:
        for child in children:
            child.terminate()
        for child in children:
            child.wait(3)


if __name__ == '__main__':
    raise SystemExit(main())
