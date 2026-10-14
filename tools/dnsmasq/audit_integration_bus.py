#!/usr/bin/env python3
"""Independent predeployment UBus/LuCI failure probe in an exact-image chroot.

Run through run_isolated.sh. --suite lifecycle additionally needs the veth
client namespace created by actual_config_network.py. All mutations stay in
fresh private overlays. Root-user / widened-ACL cases are diagnostic controls,
not deployment recommendations. Does not modify the source image or router.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

from dhcp_lease_lifecycle import packet
from dns_service_probe import query, semantics
from m2_rootfs import command, image_path, prepare


class Fixture:
    def __init__(self, args):
        self.out = args.output
        self.root = prepare(args.image_root, None, self.out, args.rust_binary)
        self.children = []
        self.logs = []
        self.acl = image_path(self.root, 'usr/share/acl.d/dnsmasq_acl.json')
        self.original_acl = self.acl.read_text()
        shutil.copy2(self.root / 'usr/sbin/dnsmasq', self.root / 'usr/sbin/dnsmasq.image-c')

    def path(self, name):
        return image_path(self.root, name)

    def run(self, *args):
        p = subprocess.run(command(self.root, *args), capture_output=True, text=True, timeout=15)
        return {'rc': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}

    def spawn(self, binary, *args, label):
        log = (self.out / (label + '.log')).open('w')
        self.logs.append(log)
        p = subprocess.Popen(command(self.root, binary, *args), stdout=log, stderr=log)
        self.children.append(p)
        return p

    @staticmethod
    def stop(p):
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(2)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def close(self):
        for p in reversed(self.children):
            self.stop(p)
        for log in self.logs:
            log.close()

    def call(self, *args):
        return self.run('/bin/ubus', '-t', '1', *args)

    def dns(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(.2)
            s.sendto(query('audit.lan'), ('127.0.0.1', 15353))
            try:
                return semantics(s.recv(4096))
            except OSError as error:
                return {'error': str(error)}

    def wait_registered(self):
        start = time.monotonic()
        while time.monotonic() - start < 2:
            self.dns()  # Both implementations retry after main-loop wakeups.
            value = self.call('call', 'dnsmasq', 'metrics')
            if value['rc'] == 0:
                return {'elapsed': round(time.monotonic() - start, 3), 'reply': value}
            time.sleep(.02)
        return {'elapsed': None, 'reply': value}

    def socket_stat(self):
        value = self.path('tmp/run/ubus/ubus.sock').stat()
        return {'mode': oct(value.st_mode & 0o777), 'uid': value.st_uid, 'gid': value.st_gid}

    def install_side(self, side):
        source = 'dnsmasq.image-c' if side == 'c' else 'dnsmasq-rs'
        shutil.copy2(self.root / 'usr/sbin' / source, self.root / 'usr/sbin/dnsmasq')

    def daemon(self, user, label):
        return self.spawn('/usr/sbin/dnsmasq', '--keep-in-foreground', '--conf-file=/m2/config',
                          '--user=' + user, '--group=' + user, '--log-facility=-',
                          '--pid-file=/var/run/dnsmasq/test.pid', label=label)


CONFIG = ('no-resolv\nno-hosts\nlisten-address=127.0.0.1\nport=15353\n'
          'enable-ubus=dnsmasq\naddress=/audit.lan/192.0.2.1\n')


def reconnect(f, results):
    for mode in ('stock-dnsmasq-user', 'root-user-control', 'acl-control'):
        for side in ('c', 'rust'):
            key = mode + '-' + side
            row = results[key] = {}
            f.install_side(side)
            acl = json.loads(f.original_acl)
            if mode == 'acl-control':
                acl['publish'].append('dnsmasq.dns')
            f.acl.write_text(json.dumps(acl) if mode == 'acl-control' else f.original_acl)
            row['acl'] = acl
            f.path('m2/config').write_text(CONFIG + 'bind-interfaces\n')
            bus = f.spawn('/sbin/ubusd', label=key + '-ubusd')
            time.sleep(.1)
            row['socket_initial'] = f.socket_stat()
            user = 'root' if mode == 'root-user-control' else 'dnsmasq'
            daemon = f.daemon(user, key + '-dnsmasq')
            row['initial'] = f.wait_registered()
            row['initial_list'] = f.call('-v', 'list', 'dnsmasq*')
            row['unknown_method'] = f.call('call', 'dnsmasq', 'reload')
            f.stop(bus)
            time.sleep(.1)
            row['absent_dns'] = f.dns()
            bus = f.spawn('/sbin/ubusd', label=key + '-ubusd-restarted')
            time.sleep(.1)
            row['socket_restarted'] = f.socket_stat()
            row['reconnect'] = f.wait_registered()
            row['post_restart_list'] = f.call('-v', 'list', 'dnsmasq*')
            row['post_restart_dns'] = f.dns()
            row['alive_after_bus_restart'] = daemon.poll() is None
            f.stop(daemon)
            daemon = f.daemon(user, key + '-dnsmasq-restarted')
            row['daemon_restart'] = f.wait_registered()
            row['daemon_restart_list'] = f.call('-v', 'list', 'dnsmasq*')
            f.stop(daemon)
            f.stop(bus)
    f.acl.write_text(f.original_acl)


def events_and_luci(f, results):
    for side in ('c', 'rust'):
        row = results[side] = {}
        f.install_side(side)
        f.path('tmp/dhcp.leases').write_text('')
        f.path('tmp/dhcp.leases').chmod(0o666)
        f.path('m2/config').write_text(CONFIG + 'no-ping\ndhcp-leasefile=/tmp/dhcp.leases\n'
                                      'dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s\n')
        bus = f.spawn('/sbin/ubusd', label=side + '-events-ubusd')
        time.sleep(.1)
        daemon = f.daemon('dnsmasq', side + '-events-dnsmasq')
        row['registration'] = f.wait_registered()
        subscriber = f.spawn('/bin/ubus', 'subscribe', 'dnsmasq', label=side + '-subscribe')
        time.sleep(.1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.bind(('0.0.0.0', 68))
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
            endpoint.settimeout(2)
            row['dhcp_replies'] = []
            for index, kind in enumerate((1, 3)):
                request = packet(kind, index + 1, address='127.0.0.10', selecting=kind == 3)
                endpoint.sendto(request, ('255.255.255.255', 67))
                response = endpoint.recv(4096)
                row['dhcp_replies'].append({'kind': kind, 'query': request.hex(), 'reply': response.hex()})
            time.sleep(.1)
            row['leasefile_ack'] = f.path('tmp/dhcp.leases').read_text()
            rpc = f.spawn('/sbin/rpcd', label=side + '-rpcd')
            time.sleep(.1)
            row['luci_leases_ack'] = f.call('call', 'luci-rpc', 'getDHCPLeases', '{}')
            row['luci_features'] = f.call('call', 'luci', 'getFeatures', '{}')
            f.stop(rpc)
            endpoint.sendto(packet(7, 3, address='127.0.0.10'), ('127.0.0.1', 67))
            time.sleep(.1)
            row['leasefile_release'] = f.path('tmp/dhcp.leases').read_text()
        f.stop(subscriber)
        row['events'] = (f.out / (side + '-subscribe.log')).read_text()
        row['metrics'] = f.call('call', 'dnsmasq', 'metrics')
        f.stop(daemon)
        f.stop(bus)


def lifecycle(args):
    # Reuse image/procd/netifd/DHCPv6 plumbing, but retain raw results and correct
    # the old harness's comparison of jailed pidfiles (both contain PID 1).
    from m2_lifecycle import Scenario
    args.skip_odhcpd = False
    args.jail_procfs = False
    scenario = Scenario(args)
    try:
        result = scenario.execute()
        before = result['initial_process']['inner_pid']
        after = result['after_apply_process']['inner_pid']
        result['audit_actual_uci_apply_restarted'] = before != after
        return result
    finally:
        scenario.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', choices=('bus', 'lifecycle'), default='bus')
    parser.add_argument('--implementation', choices=('c', 'rust'), default='rust')
    args = parser.parse_args()
    args.output = args.output.resolve()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('run through run_isolated.sh')
    if args.output.exists():
        parser.error('output must be fresh')
    if args.suite == 'lifecycle':
        result = lifecycle(args)
    else:
        fixture = Fixture(args)
        result = {'reconnect': {}, 'events_luci': {}}
        try:
            reconnect(fixture, result['reconnect'])
            events_and_luci(fixture, result['events_luci'])
        finally:
            fixture.close()
            (args.output / 'observed.json').write_text(json.dumps(result, indent=2) + '\n')
    (args.output / 'observed.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output / 'observed.json'), 'suite': args.suite}))


if __name__ == '__main__':
    main()
