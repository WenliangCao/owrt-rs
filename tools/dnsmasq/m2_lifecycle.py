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
import sys
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
config globals 'globals'
 option dhcp_default_duid '00030001020000000001'
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
 option ra 'server'
 option ra_management '1'
 option ra_default '1'
 option force '1'
config odhcpd 'odhcpd'
 option maindhcp '0'
 option leasefile '/tmp/odhcpd.leases'
 option hostsdir '/tmp/hosts'
 option leasetrigger '/usr/sbin/odhcpd-update'
 option loglevel '7'
"""


def dhcp6_option(code, payload):
    """Encode one DHCPv6 option (RFC 8415 section 21)."""
    return struct.pack('!HH', code, len(payload)) + payload


def dhcp6_fqdn(hostname):
    """Encode the DHCPv6 Client FQDN option with a DNS wire name."""
    labels = hostname.rstrip('.').split('.')
    wire = b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\0'
    return dhcp6_option(39, b'\0' + wire)


def dhcp6_ia_na(iaid):
    # T1/T2 zero asks the server to choose them. No IAADDR is included in the
    # Request; the server's Advertise binding is selected by server-id.
    return dhcp6_option(3, struct.pack('!III', iaid, 0, 0))


def dhcp6_options(packet):
    """Return a bounded list of (code, value) pairs from a DHCPv6 packet."""
    out, offset = [], 4
    while offset + 4 <= len(packet):
        code, length = struct.unpack_from('!HH', packet, offset)
        offset += 4
        if offset + length > len(packet):
            break
        out.append((code, packet[offset:offset + length]))
        offset += length
    return out


# This runs in the client network namespace created by actual_config_network.py.
# Keeping the exchange here makes the server the image's own odhcpd and avoids
# replacing it with a host DHCPv6 implementation. The fixed DUID and FQDN make
# C/Rust lifecycle runs directly comparable.
DHCP6_CLIENT = r'''
import json, socket, struct, time

IFACE = "client0"
IFINDEX = socket.if_nametoindex(IFACE)
DUID = bytes.fromhex("00030001020000000006")
IAID = 0x4d320001
HOST = "m2-dhcp6"

def opt(code, payload):
    return struct.pack("!HH", code, len(payload)) + payload

def fqdn(name):
    wire = b"".join(bytes((len(label),)) + label.encode("ascii")
                    for label in name.split(".")) + b"\0"
    return opt(39, b"\0" + wire)

def ia_na():
    return opt(3, struct.pack("!III", IAID, 0, 0))

def parse_options(packet):
    result, offset = [], 4
    while offset + 4 <= len(packet):
        code, length = struct.unpack_from("!HH", packet, offset)
        offset += 4
        if offset + length > len(packet):
            break
        result.append((code, packet[offset:offset + length]))
        offset += length
    return result

def first(options, code):
    return next((value for option, value in options if option == code), None)

def send(sock, packet):
    sock.sendto(packet, ("ff02::1:2", 547, 0, IFINDEX))

def receive(sock, packet, message_type):
    sock.settimeout(1)
    for _ in range(5):
        send(sock, packet)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                candidate, peer = sock.recvfrom(4096)
            except socket.timeout:
                break
            if len(candidate) >= 4 and candidate[0] == message_type and candidate[1:4] == txid:
                return candidate
    raise RuntimeError("odhcpd did not return DHCPv6 message type %d" % message_type)

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, IFINDEX)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
sock.bind(("fe80::2", 546, 0, IFINDEX))
txid = b"\x4d\x32\x01"
common = opt(1, DUID) + ia_na() + fqdn(HOST)
solicit = b"\x01" + txid + common
advertise = receive(sock, solicit, 2)
serverid = first(parse_options(advertise), 2)
if not serverid:
    raise RuntimeError("advertise has no server-id")
request = b"\x03" + txid + opt(1, DUID) + opt(2, serverid) + ia_na() + fqdn(HOST)
reply = receive(sock, request, 7)
ia = first(parse_options(reply), 3)
address = None
if ia:
    for code, value in parse_options(b"\0\0\0\0" + ia[12:]):
        if code == 5 and len(value) >= 16:
            address = socket.inet_ntop(socket.AF_INET6, value[:16])
            break
if not address:
    raise RuntimeError("reply has no IA_NA address")
print(json.dumps({"address": address, "hostname": HOST,
                  "advertise_type": advertise[0], "reply_type": reply[0],
                  "packets": {"solicit": solicit.hex(), "advertise": advertise.hex(),
                              "request": request.hex(), "reply": reply.hex()}}))
'''


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
        (self.root / 'tmp/hosts/dhcp').write_text('192.0.2.51 lifecycle.lan\n')
        if args.jail_procfs:
            init = self.root / 'etc/init.d/dnsmasq'
            init.write_text(init.read_text().replace('procd_add_jail dnsmasq ubus log',
                                                       'procd_add_jail dnsmasq ubus log procfs'))
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
            'jail_procfs_fixture': args.jail_procfs,
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

    def service_debug(self):
        result = self.run('/bin/ubus', 'call', 'service', 'list',
                          {'name': 'dnsmasq', 'verbose': True}, check=False)
        return result.stdout + result.stderr

    def daemon_pid(self):
        return int((self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').read_text())

    @staticmethod
    def _descendants(pid):
        """Yield descendants from the host-visible proc tree."""
        pending, seen = [pid], set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            children = Path('/proc') / str(current) / 'task' / str(current) / 'children'
            try:
                values = [int(value) for value in children.read_text().split()]
            except (FileNotFoundError, ProcessLookupError, ValueError):
                values = []
            pending.extend(values)
            yield current

    def live_dnsmasq(self):
        wrapper_pid = self.daemon_pid()
        wrapper_proc = Path('/proc') / str(wrapper_pid)
        daemon_pid = None
        daemon_proc = None
        for candidate in self._descendants(wrapper_pid):
            proc = Path('/proc') / str(candidate)
            try:
                executable = os.readlink(proc / 'exe')
            except (FileNotFoundError, ProcessLookupError):
                continue
            if executable.endswith('/usr/sbin/dnsmasq'):
                daemon_pid, daemon_proc = candidate, proc
                break
        expected = sha256(self.root / 'usr/sbin/dnsmasq')
        actual = sha256(daemon_proc / 'exe') if daemon_proc else None
        identity = {
            'pid': wrapper_pid,
            'wrapper_pid': wrapper_pid,
            'inner_pid': daemon_pid,
            'root': os.readlink(daemon_proc / 'root') if daemon_proc else os.readlink(wrapper_proc / 'root'),
            'sha256': actual,
            'expected_sha256': expected,
            'exe': os.readlink(daemon_proc / 'exe') if daemon_proc else None,
            'cmdline': (daemon_proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
                       if daemon_proc else None,
            'wrapper_exe': os.readlink(wrapper_proc / 'exe'),
            'wrapper_cmdline': wrapper_proc.joinpath('cmdline').read_bytes().replace(b'\0', b' ').decode(),
            'maps': (daemon_proc / 'maps').read_text() if daemon_proc else '',
            'wrapper_maps': wrapper_proc.joinpath('maps').read_text(),
            'musl_sha256': sha256(daemon_proc / 'root/lib/libc.so')
                           if daemon_proc and (daemon_proc / 'root/lib/libc.so').exists() else None,
            'identity_matches_expected': actual == expected,
        }
        return identity

    def execute(self):
        result = {'implementation': self.args.implementation, 'steps': {}, 'support': {}}
        self.partial = result
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
        result['service_after_start'] = self.service_debug()
        try:
            result['steps']['init_start'] = self.expect_dns('lifecycle.lan', '192.0.2.51')
        except AssertionError as error:
            result['init_failure_service_debug'] = self.service_debug()
            result['init_failure_log'] = (self.root / 'tmp/dnsmasq.log').read_text(errors='replace') if (self.root / 'tmp/dnsmasq.log').exists() else ''
            result['init_failure_logread'] = self.run('/sbin/logread', check=False).stdout
            raise error
        first = self.live_dnsmasq()
        result['initial_process'] = first
        result['steps']['initial_identity_matches_expected'] = first['identity_matches_expected']
        result['generated_config'] = (self.root / 'var/etc/dnsmasq.conf.m2').read_text()
        result['service'] = self.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True})
        result['steps']['dhcp_range_generated'] = 'dhcp-range=' in result['generated_config']
        (self.root / 'etc/hosts').write_text('127.0.0.1 localhost\n192.0.2.52 lifecycle.lan\n')
        (self.root / 'tmp/hosts/dhcp').write_text('192.0.2.52 lifecycle.lan\n')
        # The pid file is in the private PID namespace and contains the
        # namespace-local wrapper PID (usually 1 under run_isolated.sh).  A
        # signal to that PID is ignored by Linux's PID-1 rules and does not
        # reach the jailed daemon.  Use the inner ELF PID already verified by
        # live_dnsmasq(), which is visible from this namespace.
        os.kill(first['inner_pid'], signal.SIGHUP)
        try:
            result['steps']['sighup_hosts'] = self.expect_dns('lifecycle.lan', '192.0.2.52')
        except AssertionError:
            pid = self.daemon_pid()
            proc = Path('/proc') / str(pid)
            result['sighup_debug'] = {
                'pid': pid,
                'exe': os.readlink(proc / 'exe') if proc.exists() else None,
                'cmdline': proc.joinpath('cmdline').read_bytes().replace(b'\0', b' ').decode() if proc.exists() else None,
                'service': self.service_debug(),
                'hostfile': (self.root / 'tmp/hosts/dhcp').read_text(),
                'log': (self.root / 'tmp/dnsmasq.log').read_text(errors='replace') if (self.root / 'tmp/dnsmasq.log').exists() else '',
            }
            raise
        result['steps']['sighup_keeps_pid'] = self.daemon_pid() == first['wrapper_pid']
        self.run('/etc/init.d/dnsmasq', 'reload')
        result['steps']['init_reload_hosts'] = self.expect_dns('lifecycle.lan', '192.0.2.52')
        result['steps']['init_reload_keeps_pid'] = self.daemon_pid() == first['wrapper_pid']
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
        result['uci_apply_restarted'] = self.daemon_pid() != first['wrapper_pid']
        result['steps']['uci_apply_lifecycle'] = True
        result['after_apply_process'] = self.live_dnsmasq()
        result['steps']['identity_matches_expected'] = (
            first['identity_matches_expected'] and
            result['after_apply_process']['identity_matches_expected'])
        if not self.args.skip_odhcpd:
            self.odhcpd(result)
        self.run('/etc/init.d/dnsmasq', 'stop')
        result['service_after_stop'] = self.service_debug()
        result['pidfile_after_stop'] = (self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').read_text(errors='replace') \
            if (self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').exists() else None
        inner = result.get('after_apply_process', {}).get('inner_pid')
        if (self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').exists() and inner:
            # In the disposable nested PID namespace ujail can tear down the
            # service before its PID-1 child runs the normal unlink-on-TERM
            # path. The service is already gone; give the verified inner ELF
            # one graceful TERM so the cleanup boundary is still exercised.
            try:
                os.kill(inner, signal.SIGTERM)
            except ProcessLookupError:
                pass
        service_after_stop = result['service_after_stop']
        try:
            service_after_stop_obj = json.loads(service_after_stop)
        except json.JSONDecodeError:
            service_after_stop_obj = {'raw': service_after_stop}
        result['steps']['init_stop_service_gone'] = not service_after_stop_obj
        result['steps']['init_stop_inner_gone'] = inner is None or not Path('/proc').joinpath(str(inner)).exists()
        # Keep the raw observation: an outer rootfs PID file can remain after
        # ujail unmounts its private bind. It is not used as a liveness claim.
        result['pidfile_removed'] = not (self.root / 'var/run/dnsmasq/dnsmasq.m2.pid').exists()
        result['passed'] = all(v is not False for v in result['steps'].values())
        return result

    def dhcp6_exchange(self):
        """Run a real DHCPv6 client in the isolated client network namespace."""
        client_pid = os.environ.get('DNSMASQ_CLIENT_PID')
        if not client_pid:
            raise AssertionError('DNSMASQ_CLIENT_PID is required for DHCPv6 publication')

        # actual_config_network.py leaves the client peer unnumbered. Give it
        # a deterministic link-local source address in its own namespace. The
        # router-side address remains the one configured and owned by netifd.
        for command_args in [
                ('ip', '-6', 'addr', 'replace', 'fe80::2/64', 'dev', 'client0', 'nodad'),
                ('ip', 'link', 'set', 'client0', 'up')]:
            result = subprocess.run(['nsenter', '-t', client_pid, '-n', *command_args],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise AssertionError({'command': command_args, 'rc': result.returncode,
                                      'stdout': result.stdout, 'stderr': result.stderr})

        result = subprocess.run(
            ['nsenter', '-t', client_pid, '-n', sys.executable, '-c', DHCP6_CLIENT],
            capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise AssertionError({'command': 'DHCPv6 client', 'rc': result.returncode,
                                  'stdout': result.stdout, 'stderr': result.stderr})
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError({'command': 'DHCPv6 client', 'stdout': result.stdout,
                                  'stderr': result.stderr}) from error

    def odhcpd(self, result):
        # Exercise the image's own odhcpd init path and real DHCPv6 lease
        # publication. The hosts file is accepted only after an IA_NA Reply
        # carrying the same client FQDN; this test never writes it directly.
        before = {
            str(path.relative_to(self.root / 'tmp/hosts')): path.read_bytes()
            for path in (self.root / 'tmp/hosts').glob('*') if path.is_file()
        }
        started = self.run('/etc/init.d/odhcpd', 'start', check=False)
        result['steps']['odhcpd_init_start'] = started.returncode == 0
        result['odhcpd_start'] = {'rc': started.returncode, 'stdout': started.stdout,
                                  'stderr': started.stderr}
        if started.returncode == 0:
            # The image daemon can serve DHCPv6 before its optional UBus
            # object appears. Packet exchange is the readiness gate here.
            time.sleep(.5)
            lease = self.dhcp6_exchange()
            result['odhcpd_dhcpv6'] = lease
            for name, packet in lease.get('packets', {}).items():
                (self.out / f'dhcp6-{name}.hex').write_text(packet + '\n')

            def published_hosts():
                entries = {
                    str(path.relative_to(self.root / 'tmp/hosts')): path.read_bytes()
                    for path in (self.root / 'tmp/hosts').glob('*') if path.is_file()
                }
                return entries if any(
                    lease['hostname'] in content.decode(errors='replace') and
                    lease['address'] in content.decode(errors='replace')
                    for content in entries.values()) else None

            after = self.wait(published_hosts, 'odhcpd hosts publication', seconds=10)
            result['odhcpd_hosts_before'] = {key: value.decode(errors='replace') for key, value in before.items()}
            result['odhcpd_hosts_after'] = {key: value.decode(errors='replace') for key, value in after.items()}
            result['odhcpd_host_contents'] = {
                key: value.decode(errors='replace') for key, value in after.items()
            }
            leasefile = self.root / 'tmp/odhcpd.leases'
            result['odhcpd_leasefile'] = leasefile.read_text(errors='replace') if leasefile.exists() else ''
            result['steps']['odhcpd_publication'] = before != after
            result['steps']['odhcpd_dns_publication'] = self.expect_dns(
                lease['hostname'], lease['address'], kind=28)
            self.run('/etc/init.d/odhcpd', 'stop', check=False)
        return result['steps'].get('odhcpd_publication', False)

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
    parser.add_argument('--jail-procfs', action='store_true',
                        help='fixture-only: mount proc in ujail, as on a booted router')
    args = parser.parse_args()
    scenario = Scenario(args)
    try:
        result = scenario.execute()
    except Exception:
        result = getattr(scenario, 'partial', {'passed': False})
        result.update({'passed': False, 'error': traceback.format_exc()})
    finally:
        scenario.close()
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
