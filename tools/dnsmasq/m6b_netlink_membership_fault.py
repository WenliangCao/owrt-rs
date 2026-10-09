#!/usr/bin/env python3
"""Exact-image AArch64 startup membership faults, with actual syscall receipts.

Match sockaddr_nl(AF_NETLINK, groups=0x550), never the first bind by count.
Skip only that bind and set its return errno via the existing AArch64 ptrace
mechanism. Group-zero fallback and getsockname execute in the real kernel.
This prepares two small pair cases; it does not build, measure, or touch a router.
"""
from __future__ import annotations
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import query, semantics
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256
import m5_listeners as fixture

CASES = ('membership-eperm', 'membership-einval')


def save(path, value):
    fixture.save(path, value)


def membership_address(data):
    if len(data) < 12:
        return None
    family, pad, port, groups = struct.unpack_from('=HHII', data)
    return {'family': family, 'port': port, 'groups': groups} if family == 16 else None


def check_trace(report, case):
    """Receipts, not a requested fault flag, establish actual target coverage."""
    events = report.get('events', [])
    expected = errno.EPERM if case == 'membership-eperm' else errno.EINVAL
    injected = [row for row in events if row.get('injected')]
    if len(injected) != 1:
        raise ValueError('exactly one membership syscall must be injected')
    first = injected[0]
    if (first['syscall'] != 200 or first['groups'] != 0x550 or first['family'] != 16
            or first.get('entry_syscall') != 200 or first.get('skipped_syscall') != -1
            or first.get('exit_syscall') != -1 or first.get('entry_stop') != 1
            or first.get('exit_stop') != 2 or first.get('syscall_regset_bytes') != 4
            or first['fd'] <= 0 or first.get('entry_x0') != first['fd']
            or first['actual_result'] != first['fd'] or first['result'] != -expected):
        raise ValueError('membership target or skipped-kernel/errno witness differs')
    fd = first['fd']
    fallback = [row for row in events if row['syscall'] == 200 and row['fd'] == fd and row.get('groups') == 0]
    named = [row for row in events if row['syscall'] == 204 and row['fd'] == fd]
    if case == 'membership-eperm':
        if (len(fallback) != 1 or fallback[0]['result'] != 0 or fallback[0]['actual_result'] != 0
                or fallback[0].get('injected') or len(named) != 1 or named[0]['result'] != 0
                or named[0]['actual_result'] != 0 or named[0].get('injected')):
            raise ValueError('EPERM must execute one real group-zero bind and getsockname')
        if not (events.index(first) < events.index(fallback[0]) < events.index(named[0])):
            raise ValueError('membership fallback/name order differs from exact C')
        if named[0]['address'] is None or named[0]['address']['groups'] != 0 or named[0]['address']['port'] <= 0:
            raise ValueError('kernel socket did not actually bind without multicast groups')
    elif fallback or named:
        raise ValueError('EINVAL must not attempt group-zero fallback')
    return True


def traced_start(argv, case, side, stdout, stderr, report_path):
    if platform.machine() != 'aarch64':
        raise RuntimeError('fault ABI pinned to exact-image AArch64')
    libc = ctypes.CDLL(None, use_errno=True); libc.ptrace.restype = ctypes.c_long
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('size', ctypes.c_size_t)]
    def preexec():
        if libc.ptrace(0, 0, None, None):
            raise OSError(ctypes.get_errno(), 'PTRACE_TRACEME')
    process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL,
                               start_new_session=True, preexec_fn=preexec)
    pid = process.pid; registers = (ctypes.c_uint64 * 34)()
    attached, pending, target_fd = True, None, None
    fault = errno.EPERM if case == 'membership-eperm' else errno.EINVAL
    report = {'pid': pid, 'case': case, 'side': side, 'events': [], 'completed': False}
    deadline = time.monotonic() + 8
    def ptrace(request, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(ctypes.c_uint(request), ctypes.c_uint(pid), ctypes.c_void_p(address), ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'ptrace')
        return result
    def regs(write=False):
        vector = Iovec(ctypes.addressof(registers), ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204, 1, ctypes.addressof(vector))
    def syscall_number(value=None):
        number = ctypes.c_int(0 if value is None else value)
        vector = Iovec(ctypes.addressof(number), ctypes.sizeof(number))
        ptrace(0x4204 if value is None else 0x4205, 0x404, ctypes.addressof(vector))
        if vector.size != ctypes.sizeof(number):
            raise ValueError('short NT_ARM_SYSTEM_CALL register witness')
        return number.value
    def memory(address, size):
        # Open at the selected stop: /proc/mem opened before exec retains the old mm.
        with Path(f'/proc/{pid}/mem').open('rb', buffering=0) as stream:
            value = os.pread(stream.fileno(), size, address)
        if len(value) != size: raise ValueError('short live sockaddr witness')
        return value
    def wait_stop():
        while time.monotonic() < deadline:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited: return status
            time.sleep(.001)
        raise TimeoutError('membership startup ptrace deadline')
    try:
        status = wait_stop()
        if not os.WIFSTOPPED(status): raise RuntimeError('initial exec stop missing')
        ptrace(0x4200, 0, 1)  # PTRACE_O_TRACESYSGOOD
        delivered_signal = 0
        while True:
            ptrace(24, 0, delivered_signal); delivered_signal = 0
            status = wait_stop()
            if not os.WIFSTOPPED(status):
                process.returncode = os.waitstatus_to_exitcode(status); attached = False
                raise RuntimeError('daemon exited before selected membership boundary')
            signum = os.WSTOPSIG(status)
            if signum != signal.SIGTRAP | 0x80:
                delivered_signal = 0 if signum == signal.SIGTRAP else signum
                continue
            info = ctypes.create_string_buffer(128); ptrace(0x420e, 128, ctypes.addressof(info)); regs()
            if info.raw[0] == 1:
                pending = None
                executable = os.readlink(f'/proc/{pid}/exe')
                if not executable.endswith('/dnsmasq' + ('-rs' if side == 'rust' else '')): continue
                number, args = int(registers[8]), [int(value) for value in registers[:6]]
                if number == 200 and args[2] >= 12:
                    wire = memory(args[1], 12); address = membership_address(wire)
                    if address and ((target_fd is None and address['groups'] == 0x550)
                                    or target_fd == args[0]):
                        inject = target_fd is None
                        if inject: report['elf_sha256'] = sha256(Path(f'/proc/{pid}/exe'))
                        target_fd = args[0]
                        pending = {'syscall': number, 'fd': args[0], **address, 'sockaddr': wire.hex(),
                                   'entered_monotonic_ns': time.monotonic_ns(), 'injected': inject}
                        if inject:
                            pending.update(entry_syscall=syscall_number(), entry_stop=int(info.raw[0]),
                                           entry_x0=args[0], syscall_regset_bytes=ctypes.sizeof(ctypes.c_int))
                            syscall_number(-1)
                            pending['skipped_syscall'] = syscall_number()
                elif number == 204 and target_fd == args[0]:
                    pending = {'syscall': number, 'fd': args[0], 'pointer': args[1], 'injected': False,
                               'entered_monotonic_ns': time.monotonic_ns()}
            elif info.raw[0] == 2 and pending:
                returned = ctypes.c_int64(registers[0]).value
                pending['actual_result'] = returned
                if pending['injected']:
                    pending.update(exit_syscall=syscall_number(), exit_stop=int(info.raw[0]))
                    registers[0] = (-fault) & ((1 << 64) - 1); regs(True)
                    regs()
                pending['result'] = ctypes.c_int64(registers[0]).value
                pending['exited_monotonic_ns'] = time.monotonic_ns()
                if pending['syscall'] == 204 and returned == 0:
                    pending['address'] = membership_address(memory(pending.pop('pointer'), 12))
                report['events'].append(pending); save(report_path, report)
                done = (case == 'membership-einval' and pending['injected']) or (case == 'membership-eperm' and pending['syscall'] == 204)
                pending = None
                if done:
                    check_trace(report, case); report['completed'] = True
                    ptrace(17); attached = False
                    return process, report
    finally:
        if attached:
            try: ptrace(17, 0, signal.SIGKILL)
            except OSError: pass
            if process.poll() is None: process.kill(); process.wait(2)
        save(report_path, report)


def health(port=15353):
    packet = query('ready.test', 1, 0x5501)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(1); endpoint.sendto(packet, ('127.0.0.1', port)); reply, peer = endpoint.recvfrom(4096)
    parsed = semantics(reply)
    answers = [row for row in parsed['records'] if row['section'] == 'answer']
    if (parsed['id'] != 0x5501 or parsed['flags'] & 0x820f != 0x8000
            or parsed['questions'] != [['ready.test', 1, 1]] or len(answers) != 1
            or not (answers[0]['type'] == 1 and answers[0]['class'] == 1 and answers[0]['name'] == 'ready.test'
                    and answers[0]['data'] == '192.0.2.53')):
        raise ValueError('fallback startup health answer differs')
    return {'query': packet.hex(), 'reply': reply.hex(), 'peer': list(peer)}


def check_cleanup(case, cleanup):
    expected = 5 if case == 'membership-einval' else 0
    if not cleanup or cleanup['forced'] or cleanup['returncode'] != expected:
        raise ValueError('membership lifecycle return differs from expected ' + str(expected))
    return True


def side_run(args):
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        raise RuntimeError('root in run_isolated.sh required')
    args.out.mkdir(parents=True, exist_ok=False)
    if sha256(args.image_root / 'usr/sbin/dnsmasq') != STOCK_SHA256:
        raise ValueError('exact image C identity differs')
    expected_elf = STOCK_SHA256 if args.side == 'c' else sha256(args.rust_binary)
    root = prepare(args.image_root, None, args.out / 'filesystem', args.rust_binary)
    rows, failures = [], []
    config = ('port=15353\nno-hosts\nno-resolv\nuser=root\ngroup=root\nlisten-address=127.0.0.1\n'
              'bind-interfaces\npid-file=/m2/pid\nlog-facility=-\nhost-record=ready.test,192.0.2.53\n')
    (root / 'm2/membership.conf').write_text(config)
    for case in CASES:
        out = args.out / case; out.mkdir(); process = None
        try:
            with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
                process, trace = traced_start(command(root, args.side, '-k', '-C', '/m2/membership.conf'),
                                             case, args.side, stdout, stderr, out / 'trace.json')
                if trace.get('elf_sha256') != expected_elf: raise ValueError('actual syscall subject ELF differs')
                if case == 'membership-einval':
                    process.wait(3)
                    if process.returncode != 5: raise ValueError('netlink EINVAL startup must exit5')
                    outcome = {'case': case, 'exit': 5, 'fallback': False}
                else:
                    deadline = time.monotonic() + 3
                    while not (root / 'm2/pid').exists():
                        if process.poll() is not None or time.monotonic() > deadline: raise TimeoutError('fallback readiness')
                        time.sleep(.01)
                    identity = process_identity(root, process.pid)
                    expected = STOCK_SHA256 if args.side == 'c' else sha256(args.rust_binary)
                    if identity['sha256'] != expected: raise ValueError('actual image/product identity differs')
                    save(out / 'identity.json', identity); save(out / 'health.json', health())
                    outcome = {'case': case, 'exit': 0, 'fallback': True}
                if trace.get('completed') is not True: raise ValueError('membership receipt is incomplete')
                check_trace(trace, case); rows.append(outcome)
        except Exception as error:
            failure = {'case': case, 'error': repr(error)}; failures.append(failure); save(out / 'failure.json', failure)
        finally:
            cleanup = fixture.stop(process) if process else None
            save(out / 'cleanup.json', cleanup)
            if cleanup:
                try: check_cleanup(case, cleanup)
                except ValueError as error: failures.append({'case': case, 'cleanup': cleanup, 'error': str(error)})
            (root / 'm2/pid').unlink(missing_ok=True)
    report = {'side': args.side, 'rows': rows, 'failures': failures,
              'passed': not failures and [row['case'] for row in rows] == list(CASES),
              'runtime_errno_syscall_qualification': 'not executed by this startup-only tool',
              'physical_router': False}
    save(args.out / 'result.json', report); return 0 if report['passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--side', choices=('c', 'rust', 'both'), default='both')
    args = parser.parse_args(); args.out = args.out.resolve()
    if 'private' not in args.out.parts: raise ValueError('fresh private output required')
    if args.side != 'both': return side_run(args)
    args.out.mkdir(parents=True, exist_ok=False); reports, exits = {}, {}
    for name in ('c', 'rust'):
        cmd = ['sh', str(Path(__file__).with_name('run_isolated.sh')), sys.executable, __file__, '--side', name,
               '--image-root', str(args.image_root), '--rust-binary', str(args.rust_binary), '--out', str(args.out / name)]
        with (args.out / (name + '.log')).open('wb') as log:
            exits[name] = subprocess.run(cmd, stdout=log, stderr=log).returncode
        reports[name] = json.loads((args.out / name / 'result.json').read_text())
    passed = not any(exits.values()) and all(report['passed'] for report in reports.values()) and reports['c']['rows'] == reports['rust']['rows']
    save(args.out / 'result.json', {'passed': passed, 'exits': exits, 'reports': reports, 'physical_router': False})
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
