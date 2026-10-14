#!/usr/bin/env python3
"""Independent guardian fault checks; Oracle namespaces only, never a router.

Uses the unchanged deployment suite fixture and exact-image executables. ptrace
stops only the guardian at a real openat syscall boundary, then injects SIGKILL;
it does not patch the controller, libc, mount, procd, ujail, or candidate.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback

import test_deploy_oracle as base
from m2_rootfs import STOCK_SHA256, command, sha256

CASES = ('c-attempt-crash', 'c-attempt-before-crash', 'binary-journal-crash',
         'guard-stopped', 'c-bus-repeat', 'services', 'c-tcp-connection')


def trace_kill(pid, target, timing, ready, evidence):
    if os.uname().machine != 'aarch64':
        raise RuntimeError('openat syscall number below is AArch64 only')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long

    def ptrace(request, address=0, data=0):
        value = libc.ptrace(request, pid, ctypes.c_void_p(address),
                            ctypes.c_void_p(data))
        if value == -1:
            raise OSError(ctypes.get_errno(), 'ptrace')
        return value

    ptrace(0x4206, 0, 1)  # SEIZE, TRACESYSGOOD
    ptrace(0x4207)  # INTERRUPT
    os.waitpid(pid, 0)
    Path(ready).touch()
    pending = None
    deliver = 0
    with open(f'/proc/{pid}/mem', 'rb', buffering=0) as memory:
        while True:
            ptrace(24, 0, deliver)  # SYSCALL
            _, status = os.waitpid(pid, 0)
            if not os.WIFSTOPPED(status):
                raise RuntimeError(f'tracee exited: {status}')
            sig = os.WSTOPSIG(status)
            deliver = 0 if sig in (signal.SIGTRAP, signal.SIGTRAP | 0x80) else sig
            if sig != signal.SIGTRAP | 0x80:
                continue
            info = ctypes.create_string_buffer(128)
            ptrace(0x420e, len(info), ctypes.addressof(info))
            raw = info.raw
            if raw[0] == 1 and struct.unpack_from('Q', raw, 24)[0] == 56:
                args = struct.unpack_from('6Q', raw, 32)
                memory.seek(args[1])
                path = memory.read(512).split(b'\0', 1)[0].decode()
                if path == target:
                    pending = {'syscall': 'openat', 'path': path,
                               'timing': timing, 'guardian_pid': pid,
                               'flags': args[2]}
                    if timing == 'before':
                        break
            elif raw[0] == 2 and pending:
                pending['open_return'] = struct.unpack_from('q', raw, 24)[0]
                assert pending['open_return'] >= 0
                break
        Path(evidence).write_text(json.dumps(pending, indent=2) + '\n')
        os.kill(pid, signal.SIGKILL)
        # SIGKILL terminates a ptrace-stopped process without PTRACE_CONT.
        os.waitpid(pid, 0)


def trace_process(d, pid, filename, timing):
    ready, evidence = d.out / 'trace-ready', d.out / 'trace.json'
    process = subprocess.Popen([sys.executable, __file__, '--trace', str(pid),
        '/run/dnsmasq-deploy/' + filename, timing, str(ready), str(evidence)])
    base.wait(ready.exists, 'ptrace armed', 10)
    return process, evidence


def state(d):
    return dict(line.split('=', 1) for line in d.control('status').stdout.splitlines()
                if '=' in line)


def run_case(args):
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('run only through the isolated suite')
    d = base.Deployment(args)
    result = d.row
    result['inputs']['recheck_harness_sha256'] = sha256(Path(__file__))
    wan_socket = None
    try:
        d.boot()
        if args.case == 'services':
            base.host('ip', 'link', 'add', 'guard-wan0', 'type', 'dummy')
            base.host('ip', 'link', 'set', 'guard-wan0', 'up')
            wan_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            wan_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'guard-wan0\0')
            wan_socket.bind(('0.0.0.0', 68))
            result['wan_udp68_bound_throughout'] = True
            d.run('/etc/init.d/odhcpd', 'start')
            base.wait(lambda: bool(d.fixture.bus('service', 'list', {'name': 'odhcpd'})), 'odhcpd')
            result['odhcpd_before'] = d.fixture.bus('service', 'list', {'name': 'odhcpd'})
        d.prepare()
        s = d.root / 'run/dnsmasq-deploy'
        if args.case == 'binary-journal-crash':
            launch = subprocess.Popen(command(d.root, '/usr/sbin/dnsmasq-deploy', 'start'),
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            guard = base.wait(d.guard_pid, 'guardian started', 10)
            trace, evidence = trace_process(d, guard, 'binary_mounted', 'before')
            assert trace.wait(30) == 0
            launch.wait(35)
            result['fault'] = json.loads(evidence.read_text())
            base.wait(lambda: state(d)['phase'] == 'fallback', 'C fallback', 40)
            result['fallback'] = state(d)
            result['fallback_client'] = d.client()
            result['mounts_before_release'] = [line for line in Path('/proc/mounts').read_text().splitlines()
                                             if line.split()[1] == str(d.root / 'usr/sbin/dnsmasq')]
            release = d.control('release', check=False)
            result['release'] = {'rc': release.returncode, 'stderr': release.stderr}
            result['after_release'] = state(d)
            result['failure_reproduced'] = release.returncode != 0
        else:
            d.control('start')
            candidate = base.wait(lambda: d.one(d.row['candidate_sha256']), 'candidate')
            result['candidate_client'] = d.client()
            guard = d.guard_pid()
            if args.case in ('c-attempt-crash', 'c-attempt-before-crash'):
                timing = 'after' if args.case == 'c-attempt-crash' else 'before'
                trace, evidence = trace_process(d, guard, 'c_attempted', timing)
                d.control('rollback')
                assert trace.wait(30) == 0
                result['fault'] = json.loads(evidence.read_text())
                terminal = 'recovery-failed' if timing == 'after' else 'fallback'
                base.wait(lambda: state(d)['phase'] == terminal, terminal, 40)
                result['after_fault'] = state(d)
                result['c_attempted_exists'] = (s / 'c_attempted').exists()
                result['c_attempted_size'] = (s / 'c_attempted').stat().st_size
                result['daemons'] = d.daemons()
                time.sleep(15)
                result['after_15_seconds'] = state(d)
                result['failure_reproduced'] = not d.daemons() and state(d)['phase'] == 'recovery-failed'
                probe = d.run('/usr/libexec/dnsmasq-deploy-probe', '192.168.1.1',
                              'lifecycle.lan', '192.0.2.51', 'br-lan', '192.168.1.1', check=False)
                result['fresh_probe_after_fault'] = {'rc': probe.returncode,
                                                     'stdout': probe.stdout, 'stderr': probe.stderr}
                try:
                    result['client_after_fault'] = d.client()
                except AssertionError as error:
                    result['client_after_fault'] = {'failed': True, 'error': str(error)}
            elif args.case == 'c-tcp-connection':
                d.control('rollback')
                base.wait(lambda: state(d)['phase'] == 'fallback', 'fallback', 40)
                from dns_service_probe import query
                with socket.create_connection(('192.168.1.1', 53), timeout=3) as connection:
                    packet = query('lifecycle.lan')
                    connection.sendall(struct.pack('!H', len(packet)) + packet)
                    length = struct.unpack('!H', connection.recv(2))[0]
                    result['tcp_response_bytes'] = len(connection.recv(length))
                    result['daemons_during_tcp'] = d.daemons()
                    base.wait(lambda: state(d)['phase'] == 'recovery-failed', 'TCP identity rejection', 15)
                    result['during_tcp'] = state(d)
                time.sleep(5)
                result['after_tcp_closed'] = state(d)
                result['healthy_client_after_failure'] = d.client()
                result['failure_reproduced'] = state(d)['phase'] == 'recovery-failed'
            elif args.case == 'guard-stopped':
                before = state(d)
                os.kill(guard, signal.SIGSTOP)
                while float(Path('/proc/uptime').read_text().split()[0]) < int(before['deadline']) + 10:
                    time.sleep(1)
                result['past_deadline'] = state(d)
                result['guardian_stat'] = Path(f'/proc/{guard}/stat').read_text().split()[2]
                result['seconds_past_deadline'] = float(Path('/proc/uptime').read_text().split()[0]) - int(before['deadline'])
                result['failure_reproduced'] = bool(d.one(d.row['candidate_sha256']))
                os.kill(guard, signal.SIGCONT)
                base.wait(lambda: state(d)['phase'] == 'fallback', 'C after CONT', 40)
                result['after_cont'] = state(d)
                result['recovered_client'] = d.client()
            elif args.case == 'c-bus-repeat':
                d.control('rollback')
                base.wait(lambda: state(d)['phase'] == 'fallback', 'fallback', 40)
                c = d.one(STOCK_SHA256)
                d.restart_bus()
                base.wait(lambda: d.one(STOCK_SHA256) and d.one(STOCK_SHA256)['pid'] != c['pid'] and d.objects(),
                          'first C B5 repair', 40)
                result['first_repair'] = state(d)
                c = d.one(STOCK_SHA256)
                d.restart_bus()
                base.wait(lambda: state(d)['reason'] == 'bus-repair-exhausted', 'repair exhaustion', 30)
                time.sleep(10)
                result['after_second_restart'] = state(d)
                result['objects'] = d.run('/bin/ubus', '-t', '2', 'list', 'dnsmasq*', check=False).stdout.splitlines()
                result['client_after_second_restart'] = d.client()
                result['same_c_pid'] = d.one(STOCK_SHA256)['pid'] == c['pid']
                result['failure_reproduced'] = not d.objects() and state(d)['phase'] == 'fallback'
            elif args.case == 'services':
                # Add genuine image services, then preserve their identity and
                # use the existing external DHCPv6 client through the handoff.
                def client6():
                    value = d.fixture.dhcp6_exchange()
                    value.pop('packets', None)
                    return value
                result['rust_dhcp6'] = client6()
                result['rust_dhcp6_dns'] = d.fixture.expect_dns('m2-dhcp6.lan', result['rust_dhcp6']['address'], 28)
                d.control('rollback')
                base.wait(lambda: state(d)['phase'] == 'fallback', 'fallback', 40)
                result['c_dhcp6'] = client6()
                result['c_dhcp6_dns'] = d.fixture.expect_dns('m2-dhcp6.lan', result['c_dhcp6']['address'], 28)
                result['odhcpd_after'] = d.fixture.bus('service', 'list', {'name': 'odhcpd'})
                result['other_processes_alive'] = {path: Path(f"/proc/{value['pid']}").exists()
                                                  for path, value in result['support'].items()}
                result['failure_reproduced'] = False
        result['completed'] = True
    except Exception:
        result['completed'] = False
        result['error'] = traceback.format_exc()
    finally:
        if wan_socket:
            wan_socket.close()
        try:
            guard = d.guard_pid()
            if guard:
                os.kill(guard, signal.SIGCONT)
            d.close()
        except Exception:
            result['cleanup_error'] = traceback.format_exc()
    (d.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ('case', 'completed', 'failure_reproduced', 'error')}), flush=True)
    return 0 if result['completed'] else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--trace':
        trace_kill(int(sys.argv[2]), *sys.argv[3:])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image-root', 'rust-binary', 'probe-binary', 'deploy-dir', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--case', choices=CASES, required=True)
    args = parser.parse_args()
    if 'private' not in args.output.parts:
        parser.error('private output path required')
    return run_case(args)


if __name__ == '__main__':
    raise SystemExit(main())
