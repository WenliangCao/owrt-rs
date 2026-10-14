#!/usr/bin/env python3
"""FULL-R2: exact-image hosts reload ENOMEM, repeated HUP and shared-service recovery.

Run through run_isolated.sh. The dns profile retains recheck_hosts_limits.py's
original arguments and UDP-only pre-limit warmup. The shared profile adds the
existing synthetic DHCP fixture; it is not a captured household configuration.
Default: initial 2000, 30000 replacement rows, VmSize +1024 KiB, three repeats.
For adjacent boundaries use --initial-rows 1,2000,10000 and
--headroom-kib 256,512,1024,2048,none (none is the unrestricted control).
Raw packets, traces, identities and generated files remain in private output.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import socket
import struct
import subprocess
import threading
import time

from audit_20261011_dhcp import decode, packet
from audit_integration_resources import status
from dns_service_probe import exact_read, query, read_name, rr, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


class ExpiryUpstream:
    """Optional TTL control, outside the daemon's RLIMIT_AS and rootfs."""
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.address = '198.51.100.11'
        self.ttl = 2
        self.requests = 0
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                request, peer = self.socket.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                name, end = read_name(request, 12)
                assert name.endswith('.expiry.test')
                self.requests += 1
                response = (request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
                            + request[12:end + 4] + rr(1, socket.inet_aton(self.address), ttl=self.ttl))
                self.socket.sendto(response, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        assert not self.thread.is_alive(), 'expiry upstream thread did not stop'


def address(index):
    return f'192.0.2.{index % 250 + 1}'


def write_hosts(path, prefix, count):
    # Match the original replacement contents without retaining a large string.
    with path.open('w') as output:
        for index in range(count):
            output.write(f'{address(index)} {prefix}{index:06d}.test\n')


def dns_probe(out, label, name, expected, tcp=False, connection=None):
    request = query(name, ident=0x7412)
    (out / f'{label}.request').write_bytes(request)
    result = {'name': name, 'transport': 'tcp' if tcp else 'udp',
              'ok': False, 'expected_address': expected, 'has_expected_address': False}
    client = connection
    try:
        if client is None:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
            client.settimeout(.3)
            client.connect(('127.0.0.1', 15353))
        client.settimeout(.3)
        if tcp:
            client.sendall(struct.pack('!H', len(request)) + request)
            reply = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        else:
            client.send(request)
            reply = client.recv(65535)
        raw = out / f'{label}.reply'
        raw.write_bytes(reply)
        decoded = semantics(reply)
        assert decoded['id'] == 0x7412 and decoded['flags'] & 0x8000
        assert decoded['questions'] == [[name, 1, 1]], 'DNS question mismatch'
        result.update(ok=True, rcode=decoded['flags'] & 15, reply=decoded,
                      reply_sha256=sha256(raw))
        result['has_expected_address'] = result['rcode'] == 0 and any(
            rr['section'] == 'answer' and rr['type'] == 1 and rr['class'] == 1 and rr['name'] == name
            and rr['data'] == expected for rr in decoded['records'])
    except Exception as error:
        result['error'] = repr(error)
    finally:
        if connection is None and client is not None:
            client.close()
    return result


def dhcp_probe(out, label, xid):
    request = packet(3, xid, name='lease')
    (out / f'{label}.request').write_bytes(request)
    result = {'ok': False, 'xid': xid}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lo\0')
            client.bind(('0.0.0.0', 68))
            deadline = time.monotonic() + 2
            client.sendto(request, ('255.255.255.255', 67))
            while True:
                client.settimeout(max(.001, deadline - time.monotonic()))
                reply, peer = client.recvfrom(4096)
                if len(reply) >= 240 and struct.unpack('!I', reply[4:8])[0] == xid:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('no DHCP reply with matching transaction ID')
        raw = out / f'{label}.reply'
        raw.write_bytes(reply)
        decoded = decode(reply)
        result.update(reply=decoded, reply_sha256=sha256(raw), peer=list(peer))
        result['ok'] = (reply[0] == 2 and reply[28:34] == request[28:34]
                        and decoded['message_type'] == 5 and decoded['yiaddr'] == '127.0.0.30')
    except Exception as error:
        result['error'] = repr(error)
    return result


def wait_ready(proc, out, name, expected, label='startup-udp'):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f'daemon exited during readiness: {proc.returncode}')
        reply = dns_probe(out, label, name, expected)
        if reply['has_expected_address']:
            return reply
        time.sleep(.02)
    raise TimeoutError(f'initial hosts not ready: {name}')


def sample_names(initial, replacement, prefixes):
    names = {'ready.test': '192.0.2.41', 'old000000.test': address(0),
             f'old{initial - 1:06d}.test': address(initial - 1)}
    for prefix in prefixes:
        for index in sorted({0, replacement // 2, replacement - 1}):
            names[f'{prefix}{index:06d}.test'] = address(index)
    return names


def hosts_sample_state(probe, initial, replacement, prefixes, recovered=False):
    groups = {'old': [f'old{index:06d}.test' for index in sorted({0, initial - 1})]}
    groups.update({prefix: [f'{prefix}{index:06d}.test'
                           for index in sorted({0, replacement // 2, replacement - 1})]
                   for prefix in prefixes})
    if recovered:
        groups['recovered'] = ['recovered.test']
    states = {}
    for transport, replies in probe['dns'].items():
        present = {generation: [name for name in names if replies[name]['has_expected_address']]
                   for generation, names in groups.items()}
        complete = [generation for generation, names in groups.items()
                    if len(present[generation]) == len(names) and all(
                        replies[name]['ok'] and not any(rr['section'] == 'answer'
                                                      for rr in replies[name]['reply']['records'])
                        for other, other_names in groups.items() if other != generation
                        for name in other_names)]
        states[transport] = {'present_samples': present,
                             'complete_sample_generation': complete[0] if len(complete) == 1 else None}
    return states


def service_probe(proc, out, phase, names, shared, xid, held=None, old_names=None):
    result = {'exit_before': proc.poll(), 'dns': {}}
    if proc.poll() is None:
        result['memory'] = status(proc.pid)
    for transport in ('udp', 'tcp'):
        result['dns'][transport] = {
            name: dns_probe(out, f'{phase}-{transport}-{name}', name, expected, transport == 'tcp')
            for name, expected in names.items()}
    if shared:
        result['dhcp'] = dhcp_probe(out, f'{phase}-dhcp', xid)
    if held is not None:
        result['held_tcp'] = {
            name: dns_probe(out, f'{phase}-held-{name}', name, expected, True, held)
            for name, expected in (names | old_names).items()}
        result['held_tcp_snapshot_stable'] = all(
            reply['ok'] and (reply['has_expected_address'] if name in old_names or name == 'ready.test'
                             else not any(rr['section'] == 'answer' and rr['name'] == name
                                          for rr in reply['reply']['records']))
            for name, reply in result['held_tcp'].items()
            if name != 'lease.test' and not name.endswith('.expiry.test'))
    result['exit_after'] = proc.poll()
    return result


def healthy(probe, shared, names, transports=('udp',)):
    return (probe['exit_before'] is None and probe['exit_after'] is None
            and all(probe['dns'][transport][name]['has_expected_address']
                    for transport in transports for name in names)
            and (not shared or probe['dhcp']['ok']))


def run(args, side, service, initial, headroom, repeat):
    ceiling = 'none' if headroom is None else str(headroom)
    out = args.output / f'{service}-{side}-initial{initial}-extra{ceiling}-repeat{repeat}'
    out.mkdir()
    probes = out / 'probes'
    probes.mkdir()
    root = prepare(args.image_root, None, out / 'stage', args.rust)
    hosts = root / 'm2/hosts'
    write_hosts(hosts, 'old', initial)
    argv = ['-k', '--conf-file=', '--no-resolv', '--no-hosts', '--user=root',
            '--group=root', '--listen-address=127.0.0.1', '--port=15353',
            '--pid-file=/m2/pid', '--host-record=ready.test,192.0.2.41',
            '--addn-hosts=/m2/hosts', '--log-facility=/dev/null']
    shared = service == 'shared'
    upstream = ExpiryUpstream() if args.cache_expiry else None
    if upstream:
        argv.append(f'--server=/expiry.test/127.0.0.1#{upstream.port}')
    if shared:
        argv += ['--no-ping', '--dhcp-authoritative', '--domain=test',
                 '--dhcp-range=127.0.0.30,127.0.0.30,255.0.0.0,1h',
                 '--dhcp-host=02:00:00:00:00:01,127.0.0.30,lease',
                 '--dhcp-leasefile=/m2/leases']
    result = {'side': side, 'service': service, 'repeat': repeat, 'initial_rows': initial,
              'new_rows': args.new_rows, 'headroom_kib': headroom, 'argv': argv,
              'held_tcp': args.held_tcp, 'cache_expiry': args.cache_expiry,
              'pressure_rounds': [], 'passed': False}
    tracer = None
    held = None
    old_names = {'old000000.test': address(0), f'old{initial - 1:06d}.test': address(initial - 1)}
    with (out / 'stderr').open('wb') as stderr:
        proc = subprocess.Popen(command(root, side, *argv), stdout=stderr, stderr=stderr)
        try:
            result['initial_last_host'] = wait_ready(
                proc, probes, f'old{initial - 1:06d}.test', address(initial - 1))
            identity = process_identity(root, proc.pid)
            write_json(out / 'process-identity.json', identity)
            result['pid'] = proc.pid
            result['binary_sha256'] = identity['sha256']
            assert identity['sha256'] == (STOCK_SHA256 if side == 'c' else args.rust_sha256)
            if shared:
                result['initial_dhcp'] = dhcp_probe(probes, 'startup-dhcp', 0x74131000)
                assert result['initial_dhcp']['ok'], 'initial DHCP ACK failed'
                result['initial_lease_dns'] = dns_probe(
                    probes, 'startup-lease', 'lease.test', '127.0.0.30')
                assert result['initial_lease_dns']['has_expected_address'], 'initial lease DNS failed'
            if upstream:
                first = dns_probe(probes, 'cache-prime', 'dynamic.expiry.test', upstream.address)
                before = upstream.requests
                upstream.address = '198.51.100.12'
                cached = dns_probe(probes, 'cache-unexpired', 'dynamic.expiry.test', '198.51.100.11')
                cached_requests = upstream.requests
                time.sleep(2.2)
                expired = dns_probe(probes, 'cache-expired', 'dynamic.expiry.test', upstream.address)
                result['cache_expiry_control'] = {
                    'prime': first, 'unexpired': cached, 'expired': expired,
                    'prime_requests': before, 'unexpired_requests': cached_requests,
                    'expired_requests': upstream.requests}
                assert all(reply['has_expected_address'] for reply in (first, cached, expired))
                assert before == cached_requests and upstream.requests > cached_requests
            if args.held_tcp:
                held = socket.create_connection(('127.0.0.1', 15353), .3)
                result['initial_held_tcp'] = dns_probe(
                    probes, 'startup-held', f'old{initial - 1:06d}.test', address(initial - 1), True, held)
                assert result['initial_held_tcp']['has_expected_address'], 'initial held TCP failed'
            result['initial_memory'] = status(proc.pid)
            previous = resource.prlimit(proc.pid, resource.RLIMIT_AS)
            result['previous_rlimit_as'] = previous
            limit = None if headroom is None else (result['initial_memory']['VmSize'] + headroom) * 1024
            result['limit_bytes'] = limit
            trace_path = out / 'syscalls'
            tracer = subprocess.Popen(['strace', '-f', '-qq', '-p', str(proc.pid),
                '-e', 'trace=memory,tgkill', '-o', str(trace_path)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(.1)
            assert tracer.poll() is None, 'strace did not attach'
            if limit is not None:
                resource.prlimit(proc.pid, resource.RLIMIT_AS, (limit, previous[1]))
            prefixes = []
            for generation in range(args.pressure_rounds):
                prefix = 'new' if generation == 0 else f'next{generation}'
                prefixes.append(prefix)
                hup_cache = None
                if upstream:
                    upstream.ttl = 60
                    hup_name = f'hup{generation}.expiry.test'
                    cached_address = upstream.address
                    hup_cache = dns_probe(probes, f'pre-hup{generation}', hup_name, cached_address)
                    assert hup_cache['has_expected_address'], 'pre-HUP cache prime failed'
                    upstream.address = ('198.51.100.13' if cached_address != '198.51.100.13'
                                        else '198.51.100.12')
                write_hosts(hosts, prefix, args.new_rows)
                proc.send_signal(signal.SIGHUP)
                time.sleep(args.settle_seconds)
                names = sample_names(initial, args.new_rows, prefixes)
                if shared:
                    names['lease.test'] = '127.0.0.30'
                if upstream:
                    names['dynamic.expiry.test'] = upstream.address
                    names[hup_name] = upstream.address
                observation = service_probe(proc, probes, f'pressure{generation}', names,
                                            shared, 0x74131001 + generation, held, old_names)
                observation.update(generation=generation, prefix=prefix, hosts_sha256=sha256(hosts))
                if hup_cache:
                    observation['unexpired_cache_before_hup'] = hup_cache
                    observation['hup_cache_purged'] = {
                        transport: observation['dns'][transport][hup_name]['has_expected_address']
                        for transport in ('udp', 'tcp')}
                observation['hosts_samples'] = hosts_sample_state(
                    observation, initial, args.new_rows, prefixes)
                result['pressure_rounds'].append(observation)
                if proc.poll() is not None:
                    raise RuntimeError(f'daemon exited under pressure: {proc.returncode}')
            resource.prlimit(proc.pid, resource.RLIMIT_AS, previous)
            result['after_release_no_hup'] = service_probe(
                proc, probes, 'released', names, shared, 0x74131100, held, old_names)
            result['after_release_no_hup']['hosts_samples'] = hosts_sample_state(
                result['after_release_no_hup'], initial, args.new_rows, prefixes)
            hosts.write_text('192.0.2.44 recovered.test\n')
            proc.send_signal(signal.SIGHUP)
            # Readiness requires the replacement name, not the unchanged ready host.
            result['recovery_ready'] = wait_ready(
                proc, probes, 'recovered.test', '192.0.2.44', 'recovery-readiness')
            recovery_names = {'ready.test': '192.0.2.41', 'recovered.test': '192.0.2.44'}
            if shared:
                recovery_names['lease.test'] = '127.0.0.30'
            if upstream:
                recovery_names['dynamic.expiry.test'] = upstream.address
            result['recovered'] = service_probe(proc, probes, 'recovered', names | recovery_names,
                                                shared, 0x74131101, held, old_names)
            result['recovered']['hosts_samples'] = hosts_sample_state(
                result['recovered'], initial, args.new_rows, prefixes, recovered=True)
            required = ['ready.test', 'lease.test'] if shared else ['ready.test']
            if upstream:
                required.append('dynamic.expiry.test')
            result['pressure_udp_dhcp_healthy'] = all(
                healthy(row, shared, required) for row in result['pressure_rounds'])
            # C's TCP child can fail at this ceiling; retain this stricter result
            # separately instead of silently folding TCP failures into success.
            result['pressure_tcp_healthy'] = all(
                healthy(row, shared, required, ('tcp',)) for row in result['pressure_rounds'])
            result['release_udp_tcp_dhcp_healthy'] = healthy(
                result['after_release_no_hup'], shared, required, ('udp', 'tcp'))
            result['recovery_udp_tcp_dhcp_healthy'] = healthy(
                result['recovered'], shared, list(recovery_names), ('udp', 'tcp'))
            result['passed'] = (result['pressure_udp_dhcp_healthy']
                                and result['release_udp_tcp_dhcp_healthy']
                                and result['recovery_udp_tcp_dhcp_healthy'])
            if upstream:
                result['hup_cache_purged'] = all(
                    row['hup_cache_purged']['udp'] for row in result['pressure_rounds'])
                result['passed'] &= result['hup_cache_purged']
            if side == 'rust':
                # Samples detect mixed/partial publication; they do not prove
                # every name in a large generation was present or absent.
                result['rust_atomic_samples'] = all(
                    row['hosts_samples']['udp']['complete_sample_generation'] is not None
                    for row in (*result['pressure_rounds'], result['after_release_no_hup']))
                result['rust_atomic_samples'] &= all(
                    state['complete_sample_generation'] == 'recovered'
                    for state in result['recovered']['hosts_samples'].values())
                result['passed'] &= result['rust_atomic_samples']
            if args.held_tcp:
                result['held_tcp_snapshot_stable'] = all(row['held_tcp_snapshot_stable'] for row in (
                    *result['pressure_rounds'], result['after_release_no_hup'], result['recovered']))
                result['passed'] &= result['held_tcp_snapshot_stable']
        except Exception as error:
            result['error'] = repr(error)
        finally:
            if held is not None:
                held.close()
            result['exit_before_stop'] = proc.poll()
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(3)
                except subprocess.TimeoutExpired:
                    result['forced_stop'] = True
                    proc.kill()
                    proc.wait()
            result['exit'] = proc.returncode
            if tracer:
                try:
                    tracer.wait(3)
                except subprocess.TimeoutExpired:
                    tracer.terminate()
                    tracer.wait(3)
                if trace_path.exists():
                    result['enomem_count'] = trace_path.read_text().count('ENOMEM')
                    result['trace_sha256'] = sha256(trace_path)
            if upstream:
                upstream.close()
                result['upstream_requests'] = upstream.requests
                result['upstream_errors'] = upstream.errors
                result['passed'] &= not upstream.errors
            result['passed'] &= result['exit_before_stop'] is None and result['exit'] == 0
    result['stderr_sha256'] = sha256(out / 'stderr')
    write_json(out / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--rust-sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--initial-rows', default='2000')
    parser.add_argument('--headroom-kib', default='1024')
    parser.add_argument('--new-rows', type=int, default=30000)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--pressure-rounds', type=int, default=2)
    parser.add_argument('--services', default='dns,shared')
    parser.add_argument('--sides', default='c,rust')
    parser.add_argument('--held-tcp', action='store_true',
                        help='separate boundary: retain a pre-limit TCP view across HUPs; changes warmup')
    parser.add_argument('--cache-expiry', action='store_true',
                        help='separate boundary: TTL=2 upstream cache and post-expiry address change')
    parser.add_argument('--settle-seconds', type=float, default=2)
    args = parser.parse_args()
    initial_rows = [int(value) for value in args.initial_rows.split(',')]
    headrooms = [None if value == 'none' else int(value) for value in args.headroom_kib.split(',')]
    services, sides = args.services.split(','), args.sides.split(',')
    assert min(initial_rows) > 0 and args.new_rows > 0
    assert args.repeats > 0 and args.pressure_rounds > 0 and args.settle_seconds >= 0
    assert all(value is None or value >= 0 for value in headrooms)
    assert set(services) <= {'dns', 'shared'} and set(sides) <= {'c', 'rust'}
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert not args.output.exists() and 'private' in args.output.resolve().parts
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    assert sha256(args.rust) == args.rust_sha256
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.mkdir(parents=True)
    result = {'source_commit': args.source_commit, 'driver_sha256': sha256(Path(__file__)),
              'c_sha256': STOCK_SHA256, 'rust_sha256': args.rust_sha256,
              'tool_sha256': {name: sha256(Path(prepare.__code__.co_filename).parent / name) for name in (
                  'run_isolated.sh', 'm2_rootfs.py', 'audit_integration_resources.py',
                  'audit_20261011_dhcp.py', 'dns_service_probe.py')},
              'scope': 'Private namespaces; synthetic legal hosts and optional loopback DHCP client.',
              'cases': []}
    for initial in initial_rows:
        for headroom in headrooms:
            for service in services:
                for repeat in range(1, args.repeats + 1):
                    for side in sides:
                        row = run(args, side, service, initial, headroom, repeat)
                        result['cases'].append(row)
                        write_json(args.output / 'result.json', result)
                        print(json.dumps({key: row.get(key) for key in (
                            'side', 'service', 'initial_rows', 'headroom_kib', 'repeat',
                            'passed', 'pressure_tcp_healthy', 'exit', 'enomem_count', 'error')}), flush=True)
    result['passed'] = all(row['passed'] for row in result['cases'])
    write_json(args.output / 'result.json', result)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
