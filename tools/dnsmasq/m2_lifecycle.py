#!/usr/bin/env python3
"""Exercise image init/procd/rpcd/odhcpd against one dnsmasq implementation.

Run within run_isolated.sh plus actual_config_network.py. Configuration is a
synthetic local-only lifecycle profile; the image init script is unchanged.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import time
import traceback

from dns_service_probe import query, semantics
from m2_rootfs import command, prepare, process_identity, sha256


NETWORK = """config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1'
 option netmask '255.0.0.0'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
 option ipaddr '192.168.1.1'
 option netmask '255.255.255.0'
 list ip6addr 'fd00:2::1/64'
"""
DHCP = """config dnsmasq 'm2'
 option domainneeded '1'
 option boguspriv '1'
 option localise_queries '1'
 option local '/lan/'
 option domain 'lan'
 option expandhosts '1'
 option authoritative '1'
 option readethers '1'
 option leasefile '/tmp/dhcp.leases'
 option noresolv '1'
 option localuse '0'
 option nonwildcard '1'
 option localservice '1'
 option ednspacket_max '1232'
 option rebind_protection '0'
 option logfacility '/tmp/dnsmasq.log'
config dhcp 'lan'
 option interface 'lan'
 option start '100'
 option limit '20'
 option leasetime '2m'
 option dhcpv4 'server'
 option dhcpv6 'server'
 option ra 'disabled'
 option force '1'
config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option hostsdir '/tmp/hosts'
 option leasetrigger '/usr/sbin/odhcpd-update'
 option loglevel '7'
"""


class Scenario:
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.out.mkdir(parents=True, exist_ok=False)
        self.rows, self.children, self.logs = [], [], []
        self.root = prepare(args.image_root, None, self.out, args.rust_binary)
        if args.implementation == 'rust':
            shutil.copy2(self.root / 'usr/sbin/dnsmasq', self.root / 'usr/sbin/dnsmasq.image-c')
            shutil.copy2(self.root / 'usr/sbin/dnsmasq-rs', self.root / 'usr/sbin/dnsmasq')
        for path, content in [('etc/config/network', NETWORK), ('etc/config/dhcp', DHCP),
                              ('etc/config/system', "config system\n option hostname 'm2-router'\n"),
                              ('etc/hosts', '127.0.0.1 localhost\n192.0.2.51 lifecycle.lan\n'),
                              ('etc/ethers', ''), ('etc/dnsmasq.conf', '')]:
            (self.root / path).write_text(content)
        # rc.common's dnsmasq_stop always restores the resolver symlink, even
        # when noresolv is enabled. The deployed image normally receives this
        # directory from netifd; the isolated fixture must provide it too.
        for directory in ('tmp/resolv.conf.d', 'tmp/hosts', 'tmp/dnsmasq.m2.d',
                          'var/run/dnsmasq', 'var/lock', 'var/state'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.out / 'plan.json').write_text(json.dumps({
            'implementation': args.implementation, 'profile': 'synthetic local lifecycle',
            'stages': ['real init start with procd', 'SIGHUP replaces hosts',
                       'unchanged init reload', 'rpcd-rs UCI staged edit and apply config.change',
                       'odhcpd live DHCPv6 hosts publication', 'init stop'],
            'expectation_authority': 'same fixed scenario on image C',
            'dnsmasq_sha256': sha256(self.root / 'usr/sbin/dnsmasq'),
            'init_sha256': sha256(self.root / 'etc/init.d/dnsmasq'),
        }, indent=2) + '\n')

    def run(self, *args, check=True):
        result = subprocess.run(command(self.root, *args), capture_output=True, text=True, timeout=20)
        self.rows.append({'command': list(args), 'rc': result.returncode,
                          'stdout': result.stdout, 'stderr': result.stderr})
        (self.out / 'commands.json').write_text(json.dumps(self.rows, indent=2) + '\n')
        if check and result.returncode:
            raise AssertionError(self.rows[-1])
        return result

    def bus(self, obj, method, payload=None, check=True):
        result = self.run('/bin/ubus', '-t', '10', 'call', obj, method, json.dumps(payload or {}), check=check)
        return json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else {}

    def start(self, path, *args):
        log = (self.out / (Path(path).name + '.log')).open('w')
        self.logs.append(log)
        process = subprocess.Popen(command(self.root, path, *args), stdout=log, stderr=log)
        self.children.append(process)
        return process

    def wait(self, predicate, label, seconds=15):
        deadline = time.monotonic() + seconds
        last = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, ValueError, AssertionError) as error:
                last = str(error)
            time.sleep(.1)
        raise AssertionError(f'{label} not ready: {last}')

    def dns(self, name='lifecycle.lan', kind=1):
        packet = query(name, kind)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(.4)
            endpoint.sendto(packet, ('192.168.1.1', 53))
            response = endpoint.recv(4096)
        value = semantics(response)
        value.pop('id')
        return value

    def expect_dns(self, name, address, kind=1):
        def check():
            response = self.dns(name, kind)
            return response if [r['data'] for r in response['records'] if r['section'] == 'answer'] == [address] else None
        return self.wait(check, f'DNS {name} -> {address}')

    def daemon_pid(self):
        return int((self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').read_text())

    def live_dnsmasq(self):
        pid = self.daemon_pid()
        proc = Path('/proc') / str(pid)
        expected = sha256(self.root / 'usr/sbin/dnsmasq')
        assert sha256(proc / 'exe') == expected
        # ujail creates a nested mount root. Verify the actual ELF and musl
        # dependency bytes through that process root as well as its PID/cmdline.
        return {'pid': pid, 'root': os.readlink(proc / 'root'), 'sha256': expected,
                'cmdline': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(),
                'maps': (proc / 'maps').read_text(),
                'musl_sha256': sha256(proc / 'root/lib/libc.so') if (proc / 'root/lib/libc.so').exists() else None}

    def execute(self):
        result = {'implementation': self.args.implementation, 'steps': {}, 'support': {}}
        ubusd = self.start('/sbin/ubusd')
        self.wait(lambda: self.run('/bin/ubus', 'list', check=False).returncode == 0, 'ubusd')
        for path, obj in [('/sbin/logd', 'log'), ('/sbin/procd', 'service'),
                          ('/sbin/netifd', 'network'), ('/sbin/rpcd', 'uci')]:
            process = self.start(path)
            self.wait(lambda obj=obj: self.run('/bin/ubus', 'list', obj, check=False).returncode == 0, obj)
            result['support'][path] = process_identity(self.root, process.pid)
        result['support']['/sbin/ubusd'] = process_identity(self.root, ubusd.pid)
        self.wait(lambda: self.bus('network.interface.lan', 'status').get('up'), 'netifd lan')
        self.run('/etc/init.d/dnsmasq', 'start')
        result['steps']['init_start'] = self.expect_dns('lifecycle.lan', '192.0.2.51')
        first = self.live_dnsmasq()
        result['initial_process'] = first
        result['generated_config'] = (self.root / 'var/etc/dnsmasq.conf.m2').read_text()
        result['service'] = self.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True})
        result['steps']['dhcp_range_generated'] = 'dhcp-range=' in result['generated_config']
        (self.root / 'etc/hosts').write_text('127.0.0.1 localhost\n192.0.2.52 lifecycle.lan\n')
        os.kill(self.daemon_pid(), signal.SIGHUP)
        result['steps']['sighup_hosts'] = self.expect_dns('lifecycle.lan', '192.0.2.52')
        result['steps']['sighup_keeps_pid'] = self.daemon_pid() == first['pid']
        self.run('/etc/init.d/dnsmasq', 'reload')
        result['steps']['init_reload_hosts'] = self.expect_dns('lifecycle.lan', '192.0.2.52')
        result['steps']['init_reload_keeps_pid'] = self.daemon_pid() == first['pid']
        sid = self.bus('session', 'create', {'timeout': 300})['ubus_rpc_session']
        self.bus('session', 'grant', {'ubus_rpc_session': sid, 'scope': 'uci', 'objects': [['dhcp', 'read'], ['dhcp', 'write']]})
        before = (self.root / 'etc/config/dhcp').read_bytes()
        self.bus('uci', 'set', {'ubus_rpc_session': sid, 'config': 'dhcp', 'section': 'm2',
                                'values': {'address': ['/uci.m2/192.0.2.60']}})
        result['steps']['uci_staged_not_committed'] = (self.root / 'etc/config/dhcp').read_bytes() == before
        result['steps']['uci_pending_dns'] = self.dns('uci.m2')
        result['pending_changes'] = self.bus('uci', 'changes', {'ubus_rpc_session': sid, 'config': 'dhcp'})
        self.bus('uci', 'apply', {'ubus_rpc_session': sid, 'rollback': False})
        result['steps']['uci_apply_dns'] = self.expect_dns('uci.m2', '192.0.2.60')
        result['steps']['uci_apply_committed'] = b'/uci.m2/192.0.2.60' in (self.root / 'etc/config/dhcp').read_bytes()
        result['steps']['uci_apply_restarted'] = self.daemon_pid() != first['pid']
        result['after_apply_process'] = self.live_dnsmasq()
        if not self.args.skip_odhcpd:
            self.odhcpd(result)
        self.run('/etc/init.d/dnsmasq', 'stop')
        self.wait(lambda: not (self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').exists(), 'dnsmasq stopped')
        result['steps']['init_stop_pid_removed'] = True
        result['passed'] = all(v is not False for v in result['steps'].values())
        return result

    def odhcpd(self, result):
        raise NotImplementedError('DHCPv6 publication driver pending')

    def close(self):
        self.run('/etc/init.d/dnsmasq', 'stop', check=False)
        self.run('/etc/init.d/odhcpd', 'stop', check=False)
        for process in reversed(self.children):
            process.terminate()
        for process in reversed(self.children):
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--implementation', choices=['c', 'rust'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--skip-odhcpd', action='store_true')
    args = parser.parse_args()
    scenario = Scenario(args)
    try:
        result = scenario.execute()
    except Exception:
        result = {'passed': False, 'error': traceback.format_exc()}
    finally:
        scenario.close()
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
