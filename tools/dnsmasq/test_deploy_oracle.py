#!/usr/bin/env python3
"""Verify fail-closed dnsmasq activation in disposable exact-image rootfses.

Run the suite on the AArch64 Oracle build host as root. Each test receives fresh
network/mount/PID namespaces and a private overlay, the image's ubusd/procd/
netifd/init/ujail, and a separate veth client. Never invoke this on OpenWrt.
Raw rootfses/logs stay below --output (which must contain a private component).
The derived summary contains only synthetic identities and pass/fail evidence.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback

from m2_lifecycle import Scenario
from m2_rootfs import STOCK_SHA256, command, process_identity, sha256

CASES = ('crash', 'hang', 'startup-failure', 'dns-loss', 'dhcp-loss',
         'overlay-full', 'overlay-readonly', 'tmp-full', 'unconfirmed',
         'confirmed-fault', 'ubusd-candidate', 'ubusd-fallback', 'guard-killed',
         'manual-rollback', 'guard-restart-after-fallback', 'failed-handback',
         'lease-before-start', 'hosts-reload')

# Executes outside the router chroot, but within the real client's netns. It
# validates DHCP offer + ACK and assigned DNS/router options, then queries both
# DNS transports from the address allocated by dnsmasq. No host DHCP utility or
# local health-probe success is used as a substitute for this client.
CLIENT = r'''
import json, os, socket, struct, subprocess, time
from dns_service_probe import query, semantics
IFACE = 'client0'
xid = 0x4d320027
mac = bytes.fromhex(os.environ.get('DNSMASQ_CLIENT_MAC', '020000000027'))
def packet(kind, address=None, server=None):
    p = bytearray(240)
    p[:3] = bytes((1,1,6)); p[4:8] = struct.pack('!I', xid)
    p[10:12] = b'\x80\0'; p[28:34] = mac
    p[236:240] = bytes((99,130,83,99))
    p += bytes((53,1,kind,55,3,1,3,6))
    if address: p += bytes((50,4)) + socket.inet_aton(address)
    if server: p += bytes((54,4)) + socket.inet_aton(server)
    p += b'\xff'
    return p

def options(packet):
    result, pos = {}, 240
    while pos < len(packet):
        code = packet[pos]; pos += 1
        if code == 255: break
        if code == 0: continue
        if pos >= len(packet): raise AssertionError('truncated DHCP length')
        length = packet[pos]; pos += 1
        if pos + length > len(packet): raise AssertionError('truncated DHCP option')
        result[code] = packet[pos:pos+length]; pos += length
    return result

def exchange(s, raw, request, message):
    for attempt in range(4):
        s.sendto(request, ('255.255.255.255', 67))
        deadline = time.monotonic()+1
        while time.monotonic() < deadline:
            try: frame = raw.recv(65535)
            except socket.timeout: continue
            if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17: continue
            header = (frame[14] & 15) * 4; udp = 14 + header
            if header < 20 or len(frame) < udp + 8: continue
            source, destination, length = struct.unpack_from('!HHH', frame, udp)
            if (source, destination) != (67,68) or length < 248 or len(frame) < udp + length: continue
            reply = frame[udp+8:udp+length]; peer = (socket.inet_ntoa(frame[26:30]),source)
            if len(reply) < 240 or reply[4:8] != struct.pack('!I',xid): continue
            opts=options(reply)
            if opts.get(53) == bytes((message,)):
                assert reply[0] == 2 and reply[28:34] == mac
                assert peer[1] == 67
                return reply, opts
    raise AssertionError('DHCP message %d unavailable' % message)

subprocess.run(['ip','link','set',IFACE,'address',':'.join('%02x' % value for value in mac)],check=True)
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as raw, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    raw.bind((IFACE,0)); raw.settimeout(.5)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,IFACE.encode()+b'\0')
    s.settimeout(.5); s.bind(('0.0.0.0',68))
    offer, opts=exchange(s,raw,packet(1),2)
    address=socket.inet_ntoa(offer[16:20])
    server=socket.inet_ntoa(opts[54])
    ack, opts=exchange(s,raw,packet(3,address,server),5)
    assert socket.inet_ntoa(ack[16:20]) == address
    assert server == '192.168.1.1'
    assert opts[6][:4] == socket.inet_aton(server)
    assert opts[3][:4] == socket.inet_aton(server)
subprocess.run(['ip','addr','replace',address+'/24','dev',IFACE],check=True)
result={'dhcp_offer':True,'dhcp_ack':True,'address':address,'server':server,
        'dns_option':server,'router_option':server,'dns':{}}
request=query('lifecycle.lan')
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.bind((address,0));s.settimeout(2);s.sendto(request,(server,53));reply=s.recv(4096)
    value=semantics(reply)
    assert [r['data'] for r in value['records'] if r['section']=='answer']==['192.0.2.51']
    result['dns']['udp']=True
with socket.create_connection((server,53),2,source_address=(address,0)) as s:
    s.sendall(struct.pack('!H',len(request))+request)
    def exact(n):
        b=b''
        while len(b)<n:
            chunk=s.recv(n-len(b))
            if not chunk: raise AssertionError('DNS TCP EOF')
            b+=chunk
        return b
    reply=exact(struct.unpack('!H',exact(2))[0]);value=semantics(reply)
    assert [r['data'] for r in value['records'] if r['section']=='answer']==['192.0.2.51']
    result['dns']['tcp']=True
print(json.dumps(result))
'''


def host(*args, check=True, timeout=20):
    return subprocess.run(list(map(str, args)), check=check, text=True,
                          capture_output=True, timeout=timeout)


def wait(predicate, label, seconds=40):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, AssertionError) as error:
            last = str(error)
        time.sleep(.2)
    raise AssertionError(f'{label} not ready in {seconds}s: {last}')


def fill(path):
    """Fill only a verified tmpfs until the kernel actually returns ENOSPC."""
    fs = host('stat', '-f', '-c', '%T', path.parent).stdout.strip()
    assert fs == 'tmpfs', fs
    count = 0
    try:
        with path.open('wb', buffering=0) as stream:
            block = bytes(65536)
            while True:
                count += stream.write(block)
    except OSError as error:
        assert error.errno == errno.ENOSPC, error
    with path.open('ab', buffering=0) as stream:
        try:
            stream.write(b'x')
        except OSError as error:
            assert error.errno == errno.ENOSPC
        else:
            raise AssertionError('filled filesystem still accepts writes')
    return {'errno': 'ENOSPC', 'bytes_written': count,
            'available_bytes': os.statvfs(path.parent).f_bavail * os.statvfs(path.parent).f_frsize}


class Deployment:
    def __init__(self, args):
        self.args, self.out = args, args.output
        self.out.mkdir(parents=True, exist_ok=False)
        fixture_out = self.out / 'fixture'
        if args.case == 'overlay-full':
            storage = self.out / 'limited-overlay'
            storage.mkdir()
            host('mount', '-t', 'tmpfs', '-o', 'size=32m,mode=0700', 'deploy-overlay', storage)
            fixture_out = storage / 'fixture'
        fixture_args = argparse.Namespace(image_root=args.image_root,
            rust_binary=args.rust_binary, implementation='c', output=fixture_out,
            jail_procfs=False, skip_odhcpd=True)
        self.fixture = Scenario(fixture_args)
        self.root = self.fixture.root
        self.fixture.out = self.out  # Keep evidence outside the ENOSPC mount.
        shutil.copy2(fixture_out / 'rootfs-identity.json', self.out / 'rootfs-identity.json')
        identity = json.loads((fixture_out / 'rootfs-identity.json').read_text())
        self.lower = Path(identity['filesystem']['lower'])
        (self.root / 'rom').mkdir(exist_ok=True)
        host('mount', '--bind', self.lower, self.root / 'rom')
        host('mount', '-o', 'remount,bind,ro', self.root / 'rom')
        assert sha256(self.root / 'rom/usr/sbin/dnsmasq') == STOCK_SHA256
        destinations = {'dnsmasq-deploy': 'usr/sbin/dnsmasq-deploy',
                        'dnsmasq-deploy-lock-init': 'usr/libexec/dnsmasq-deploy-lock-init'}
        for source, relative in destinations.items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.deploy_dir / source, target)
            target.chmod(0o755)
        target = self.root / 'usr/libexec/dnsmasq-deploy-probe'
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(args.probe_binary, target)
        target.chmod(0o755)
        self.hashes = {STOCK_SHA256, sha256(args.rust_binary)}
        self.row = {'case': args.case, 'passed': False, 'support': {}, 'steps': {},
                    'candidate_sha256': sha256(args.rust_binary), 'stock_sha256': STOCK_SHA256,
                    'rom_read_only': True, 'fixture_init_sha256': sha256(self.root / 'etc/init.d/dnsmasq')}
        self.row['inputs'] = {
            'controller_sha256': sha256(self.root / 'usr/sbin/dnsmasq-deploy'),
            'init_lock_sha256': sha256(self.root / 'usr/libexec/dnsmasq-deploy-lock-init'),
            'probe_sha256': sha256(args.probe_binary),
            'harness_sha256': sha256(Path(__file__)),
            'image_root': str(args.image_root),
            'package_database_sha256': sha256(self.root / 'lib/apk/db/installed'),
            'image_base_manifest_sha256': identity['filesystem']['base_manifest_sha256'],
        }
        self.ubusd = None

    def run(self, *args, check=True):
        result = subprocess.run(command(self.root, *args), capture_output=True, text=True, timeout=35)
        self.fixture.rows.append({'command': list(args), 'rc': result.returncode,
                                  'stdout': result.stdout, 'stderr': result.stderr})
        (self.out / 'commands.json').write_text(json.dumps(self.fixture.rows, indent=2) + '\n')
        if check and result.returncode:
            raise AssertionError(self.fixture.rows[-1])
        return result

    def control(self, verb, *args, check=True):
        return self.run('/usr/sbin/dnsmasq-deploy', verb, *args, check=check)

    def daemons(self, digest=None):
        result = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                exe = os.readlink(proc / 'exe')
                if not (exe.endswith(('/dnsmasq', '/candidate')) or 'dnsmasq-rs' in exe):
                    continue
                actual = sha256(proc / 'exe')
                if actual not in self.hashes or (digest and actual != digest):
                    continue
                result.append({'pid': int(proc.name), 'sha256': actual, 'exe': exe,
                    'start_ticks': (proc / 'stat').read_text().split()[21],
                    'cmdline': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(),
                    'root': os.readlink(proc / 'root')})
            except (FileNotFoundError, ProcessLookupError):
                continue
        return result

    def one(self, digest):
        rows = self.daemons()
        return rows[0] if len(rows) == 1 and rows[0]['sha256'] == digest else None

    def client(self, hardware=None):
        client_pid = os.environ['DNSMASQ_CLIENT_PID']
        environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent))
        if hardware:
            environment['DNSMASQ_CLIENT_MAC'] = hardware
        result = subprocess.run(['nsenter', '-t', client_pid, '-n', sys.executable, '-c', CLIENT],
                                env=environment, capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, {'stdout': result.stdout, 'stderr': result.stderr}
        return json.loads(result.stdout)

    def objects(self):
        result = self.run('/bin/ubus', '-t', '2', 'list', check=False)
        rows = set(result.stdout.splitlines())
        return {'dnsmasq', 'dnsmasq.dns'}.issubset(rows)

    def boot(self):
        f = self.fixture
        self.ubusd = f.start('/sbin/ubusd')
        wait(lambda: self.run('/bin/ubus', 'list', check=False).returncode == 0, 'ubusd')
        self.row['support']['ubusd'] = process_identity(self.root, self.ubusd.pid)
        for binary, obj in [('/sbin/logd', 'log'), ('/sbin/procd', 'service'),
                            ('/sbin/netifd', 'network')]:
            process = f.start(binary)
            wait(lambda: self.run('/bin/ubus', 'list', obj, check=False).returncode == 0, obj)
            self.row['support'][binary] = process_identity(self.root, process.pid)
        wait(lambda: f.bus('network.interface.lan', 'status').get('up'), 'netifd lan')
        self.run('/etc/init.d/dnsmasq', 'start')
        self.row['stock_initial'] = wait(lambda: self.one(STOCK_SHA256), 'stock process')
        service = self.fixture.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True})
        instances = list(service['dnsmasq']['instances'].values())
        assert len(instances) == 1
        self.row['stock_wrapper_argv'] = Path(f"/proc/{instances[0]['pid']}/cmdline").read_bytes().split(b'\0')[:-1]
        self.row['stock_wrapper_argv'] = [v.decode() for v in self.row['stock_wrapper_argv']]
        self.row['stock_client'] = wait(self.client, 'stock client')
        assert self.objects(), 'stock ubus objects absent'

    def prepare(self):
        candidate = '/usr/sbin/dnsmasq-rs'
        digest = self.row['candidate_sha256']
        if self.args.case == 'startup-failure':
            # A static ELF with an approved explicit identity, whose actual
            # service launch exits nonzero. This is a distinct test artifact.
            candidate = '/m2/dnsmasq-startup-failure'
            source = self.out / 'startup-failure.c'
            source.write_text('int main(void) { return 42; }\n')
            host('cc', '-static', '-Os', '-s', source, '-o', self.root / candidate.lstrip('/'))
            digest = sha256(self.root / candidate.lstrip('/'))
            self.row['fault_candidate_sha256'] = digest
        self.control('prepare', candidate, digest, '192.168.1.1',
                     'lifecycle.lan', '192.0.2.51', 'br-lan', '192.168.1.1')
        self.row['after_prepare'] = self.one(STOCK_SHA256)
        assert self.row['after_prepare'], 'prepare disrupted C'

    def block_port(self, port):
        host('nft', 'add', 'table', 'inet', 'deploy_fault')
        host('nft', 'add', 'chain', 'inet', 'deploy_fault', 'input',
             '{ type filter hook input priority -50; policy accept; }')
        host('nft', 'add', 'rule', 'inet', 'deploy_fault', 'input', 'udp', 'dport', str(port), 'drop')
        if port == 53:
            host('nft', 'add', 'rule', 'inet', 'deploy_fault', 'input', 'tcp', 'dport', str(port), 'drop')

    def clear_fault(self):
        host('nft', 'delete', 'table', 'inet', 'deploy_fault', check=False)

    def restart_bus(self):
        self.ubusd.terminate()
        self.ubusd.wait(3)
        self.ubusd = self.fixture.start('/sbin/ubusd')
        wait(lambda: self.run('/bin/ubus', 'list', check=False).returncode == 0, 'new ubusd')

    def guard_pid(self):
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                argv = (proc / 'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError, ProcessLookupError):
                continue
            if any(arg.endswith(b'/dnsmasq-deploy') for arg in argv) and any(
                    arg in (b'guard', b'_guard', b'watch', b'_watch', b'monitor', b'supervise') for arg in argv):
                return int(proc.name)
        return None

    def execute(self):
        self.boot()
        self.prepare()
        if self.args.case == 'lease-before-start':
            self.row['prepared_new_client'] = self.client('020000000028')
            leases = (self.root / 'tmp/dhcp.leases').read_text()
            assert '02:00:00:00:00:28' in leases
            self.row['leases_before_start'] = leases
        started = time.monotonic()
        case = self.args.case
        activation = self.control('start', check=case != 'startup-failure')
        self.row['start_returncode'] = activation.returncode
        if case != 'startup-failure':
            candidate = wait(lambda: self.one(self.row['candidate_sha256']), 'candidate identity')
            self.row['candidate_running'] = candidate
            self.row['candidate_client'] = wait(self.client, 'candidate client')
            self.row['steps']['candidate_actual_elf'] = True
        else:
            candidate = None
        if case == 'hosts-reload':
            (self.root / 'tmp/hosts/dhcp').write_text('192.0.2.51 lifecycle.lan\n192.0.2.70 callback.lan\n')
            self.run('/usr/sbin/odhcpd-update')
            self.row['candidate_callback_dns'] = self.fixture.expect_dns('callback.lan', '192.0.2.70')
            assert self.one(self.row['candidate_sha256'])['pid'] == candidate['pid']
        if case == 'confirmed-fault':
            status = dict(line.split('=', 1) for line in self.control('status').stdout.splitlines() if '=' in line)
            assert self.control('confirm', status['token'], check=False).returncode != 0, 'confirmation allowed before observation window'
            while float(Path('/proc/uptime').read_text().split()[0]) < int(status['started']) + 154:
                assert self.one(self.row['candidate_sha256']), 'candidate failed during observation'
                time.sleep(1)
            self.row['observation_client'] = self.client()
            self.control('confirm', status['token'])
            self.row['confirmation_status'] = self.control('status').stdout
            while float(Path('/proc/uptime').read_text().split()[0]) < int(status['started']) + 185:
                assert self.one(self.row['candidate_sha256']), 'confirmed candidate reverted at old deadline'
                time.sleep(1)
            self.row['confirmed_past_deadline_client'] = self.client()
            self.row['steps']['confirmation_cancels_deadline'] = True
        fault_started = time.monotonic()
        if case in ('crash', 'confirmed-fault'):
            os.kill(candidate['pid'], signal.SIGKILL)
        elif case == 'hang':
            os.kill(candidate['pid'], signal.SIGSTOP)
        elif case in ('dns-loss', 'dhcp-loss'):
            self.block_port(53 if case == 'dns-loss' else 67)
        elif case == 'overlay-full':
            self.row['space_fault'] = fill(self.out / 'limited-overlay' / 'filler')
            os.kill(candidate['pid'], signal.SIGKILL)
        elif case == 'overlay-readonly':
            host('mount', '-o', 'remount,ro', self.root)
            try:
                (self.root / 'etc/deploy-readonly-check').write_text('must fail')
            except OSError as error:
                assert error.errno == errno.EROFS
                self.row['space_fault'] = {'errno': 'EROFS'}
            else:
                raise AssertionError('overlay is writable')
            os.kill(candidate['pid'], signal.SIGKILL)
        elif case == 'tmp-full':
            used = (os.statvfs(self.root / 'tmp').f_blocks - os.statvfs(self.root / 'tmp').f_bfree) * os.statvfs(self.root / 'tmp').f_frsize
            host('mount', '-o', f'remount,size={used + 65536}', self.root / 'tmp')
            self.row['space_fault'] = fill(self.root / 'tmp/filler')
            os.kill(candidate['pid'], signal.SIGKILL)
        elif case in ('ubusd-candidate', 'ubusd-fallback'):
            if case == 'ubusd-fallback':
                self.control('rollback')
                before_bus = wait(lambda: self.one(STOCK_SHA256), 'manual ROM fallback')
            else:
                before_bus = candidate
            self.restart_bus()
            self.row['before_bus_restart'] = before_bus
            if case == 'ubusd-fallback':
                wait(lambda: self.one(STOCK_SHA256) and self.one(STOCK_SHA256)['pid'] != before_bus['pid'] and self.objects(),
                     'ROM C restarted and ubus objects restored', 40)
        elif case == 'guard-killed':
            guard = wait(self.guard_pid, 'independently supervised guard')
            self.row['killed_guard_pid'] = guard
            os.kill(guard, signal.SIGKILL)
        elif case in ('manual-rollback', 'guard-restart-after-fallback', 'failed-handback', 'lease-before-start', 'hosts-reload'):
            self.control('rollback')
        # No confirmation must use the production deadline; it is intentionally
        # not shortened by an environment variable or fixture-only code path.
        if case == 'ubusd-candidate':
            actual = wait(lambda: self.one(self.row['candidate_sha256']) and self.objects(),
                          'candidate ubus objects recovered', 40)
            self.row['after_bus_restart'] = self.one(self.row['candidate_sha256'])
            assert self.row['after_bus_restart']['pid'] != candidate['pid']
            self.row['steps']['ubus_objects_restored'] = bool(actual)
            self.row['client_after_bus'] = wait(self.client, 'client after ubusd restart')
            self.control('rollback')
        fallback = wait(lambda: self.one(STOCK_SHA256), 'ROM fallback actual ELF',
                        220 if case == 'unconfirmed' else 50)
        self.row['fallback_seconds'] = round(time.monotonic() - fault_started, 3)
        self.row['activation_to_fallback_seconds'] = round(time.monotonic() - started, 3)
        self.row['fallback_running'] = fallback
        self.row['initial_fallback_status'] = self.control('status').stdout
        if case == 'unconfirmed':
            assert 175 <= self.row['activation_to_fallback_seconds'] <= 220
        self.clear_fault()  # External packet blackholes also affect the C server.
        self.row['fallback_client'] = wait(self.client, 'ROM fallback client')
        wait(self.objects, 'fallback ubus objects')
        wait(lambda: (self.root / 'run/dnsmasq-deploy/phase').read_text().strip() == 'fallback',
             'fallback health acceptance', 25)
        self.row['fallback_status'] = self.control('status').stdout
        self.row['service_recovered_seconds'] = round(time.monotonic() - fault_started, 3)
        assert 'actual_sha256=' + STOCK_SHA256 in self.row['fallback_status']
        if case == 'ubusd-fallback':
            self.row['steps']['ubus_objects_restored'] = True
        if case == 'hosts-reload':
            (self.root / 'tmp/hosts/dhcp').write_text('192.0.2.51 lifecycle.lan\n192.0.2.71 callback.lan\n')
            self.run('/usr/sbin/odhcpd-update')
            self.row['fallback_callback_dns'] = self.fixture.expect_dns('callback.lan', '192.0.2.71')
            assert self.one(STOCK_SHA256)['pid'] == fallback['pid']
            self.row['steps']['odhcpd_callback_reloads_both_sides'] = True
        # Leave the fault marker latched, and check that C is not repeatedly
        # restarted by the same stale health failure/deadline.
        stable_started = time.monotonic()
        for _ in range(15):
            time.sleep(1)
            stable = self.one(STOCK_SHA256)
            assert stable and stable['pid'] == fallback['pid'] and stable['start_ticks'] == fallback['start_ticks'], self.daemons()
        self.row['fallback_stability_seconds'] = round(time.monotonic() - stable_started, 3)
        if case == 'tmp-full':
            # Refill pages released by the emergency reserve before testing
            # planned handback's independent write preflight.
            self.row['handback_space_fault'] = fill(self.root / 'tmp/filler2')
            release = self.control('release', check=False)
            assert release.returncode != 0
            assert self.one(STOCK_SHA256)['pid'] == fallback['pid']
            self.row['steps']['full_tmp_handback_preserves_c'] = True
        if case == 'lease-before-start':
            leases = (self.root / 'tmp/dhcp.leases').read_text()
            assert '02:00:00:00:00:28' in leases
            assert self.row['prepared_new_client']['address'] in leases
            self.row['steps']['lease_since_prepare_preserved'] = True
        if case == 'guard-restart-after-fallback':
            guard = self.guard_pid()
            assert guard
            os.kill(guard, signal.SIGKILL)
            wait(lambda: self.guard_pid() and self.guard_pid() != guard, 'guard respawn adopting C')
            for _ in range(15):
                time.sleep(1)
                assert self.one(STOCK_SHA256)['pid'] == fallback['pid']
            self.row['steps']['guard_respawn_keeps_c_pid'] = True
        if case == 'failed-handback':
            # An open FD pins this real bind mount, forcing the kernel to
            # return EBUSY at the last handback unmount. No command shim or
            # controller test hook substitutes for the failing syscall.
            pinned = os.open(self.root / 'etc/init.d/dnsmasq', os.O_RDONLY)
            try:
                release = self.control('release', check=False)
            finally:
                os.close(pinned)
            self.row['failed_release'] = {'rc': release.returncode, 'stdout': release.stdout, 'stderr': release.stderr}
            assert release.returncode != 0
            recovered = wait(lambda: self.one(STOCK_SHA256), 'failed handback restores ROM')
            wait(lambda: (self.root / 'run/dnsmasq-deploy/phase').read_text().strip() == 'fallback', 'failed handback guardian')
            self.row['failed_handback_client'] = self.client()
            self.row['failed_handback_process'] = recovered
            self.row['steps']['failed_handback_restores_c'] = True
        if case == 'manual-rollback':
            self.row['release_status'] = self.control('release').stdout
            self.row['released_process'] = wait(lambda: self.one(STOCK_SHA256), 'stock handback')
            self.row['released_client'] = self.client()
            assert sha256(self.root / 'usr/sbin/dnsmasq') == STOCK_SHA256
            assert sha256(self.root / 'etc/init.d/dnsmasq') == self.row['fixture_init_sha256']
            self.row['steps']['stock_management_restored'] = True
        self.row['steps'].update(actual_rom_elf=True, real_client_dns_dhcp=True,
                                 no_fallback_restart_loop=True)
        self.row['package_database_after_sha256'] = sha256(self.root / 'lib/apk/db/installed')
        assert self.row['package_database_after_sha256'] == self.row['inputs']['package_database_sha256']
        self.row['steps']['package_database_unchanged'] = True
        self.row['passed'] = True
        return self.row

    def close(self):
        self.clear_fault()
        # Fault mounts remain private until namespace exit. Cleanup does not
        # reinstall any package or mutate the extracted image.
        try:
            self.control('rollback', check=False)
        finally:
            self.fixture.close()


def single(args):
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or not os.environ.get('DNSMASQ_CLIENT_PID'):
        raise RuntimeError('--case must run through run_isolated.sh and actual_config_network.py')
    deployment = None
    try:
        deployment = Deployment(args)
        result = deployment.execute()
    except Exception:
        result = deployment.row if deployment else {'case': args.case}
        result.update(passed=False, error=traceback.format_exc())
    finally:
        if deployment:
            try:
                deployment.close()
            except Exception:
                result['cleanup_error'] = traceback.format_exc()
                result['passed'] = False
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'case': args.case, 'passed': result['passed'], 'error': result.get('error')}), flush=True)
    return 0 if result['passed'] else 1


def suite(args):
    if os.geteuid() != 0 or os.uname().sysname != 'Linux' or Path('/etc/openwrt_release').exists():
        raise RuntimeError('suite requires root on the Linux build host, never OpenWrt')
    args.output.mkdir(parents=True, exist_ok=False)
    tools = Path(__file__).resolve().parent
    # actual_config_network consumes only this synthetic resolver fixture.
    source = args.output / 'network-source'
    (source / 'tmp/resolv.conf.d').mkdir(parents=True)
    (source / 'tmp/resolv.conf.d/resolv.conf.auto').write_text('')
    results = []
    for case in args.cases or CASES:
        argv = ['sh', str(tools / 'run_isolated.sh'), sys.executable,
                str(tools / 'actual_config_network.py'), '--source-root', str(source),
                '--router-cidr', '192.168.1.1/24', '--output', str(args.output / (case+'-network')),
                '--', sys.executable, str(Path(__file__).resolve()),
                '--image-root', str(args.image_root), '--rust-binary', str(args.rust_binary),
                '--probe-binary', str(args.probe_binary), '--deploy-dir', str(args.deploy_dir),
                '--output', str(args.output / case), '--case', case]
        print('CASE ' + case, flush=True)
        with (args.output / (case+'.log')).open('w') as log:
            process = subprocess.run(argv, stdout=log, stderr=log, timeout=420)
        path = args.output / case / 'result.json'
        result = json.loads(path.read_text()) if path.exists() else {'case': case, 'passed': False, 'error': 'missing result'}
        result['command'] = argv
        result['returncode'] = process.returncode
        result['passed'] = bool(result['passed'] and process.returncode == 0)
        results.append(result)
        (args.output / 'summary.json').write_text(json.dumps({'passed': all(r['passed'] for r in results),
                    'cases': results}, indent=2)+'\n')
        print(json.dumps({'case': case, 'passed': result['passed']}), flush=True)
    return 0 if all(row['passed'] for row in results) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--probe-binary', type=Path, required=True)
    parser.add_argument('--deploy-dir', type=Path, default=Path(__file__).resolve().parent / 'deploy')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--cases', nargs='+', choices=CASES)
    args = parser.parse_args()
    for field in ('image_root', 'rust_binary', 'probe_binary', 'deploy_dir', 'output'):
        setattr(args, field, getattr(args, field).resolve())
    if 'private' not in args.output.parts:
        parser.error('--output must contain a private path component')
    return single(args) if args.case else suite(args)


if __name__ == '__main__':
    raise SystemExit(main())
