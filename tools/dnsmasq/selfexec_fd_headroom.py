#!/usr/bin/env python3
"""Fixed 2/3/4/8 FD-hole pressure and recovery, Oracle/local Linux only.

Use the SAME command/configuration for exact K and the candidate, changing only
binary/hash/source/output. Default private /proc is visible: K's lookup needs
/proc/self/fd independently of FD pressure. --proc-mode absent separately tests
the candidate's real jail boundary; never compare K's missing-proc failure as
a headroom regression. No third-party packages or product changes are needed.

Run outside target PID namespaces with host /proc, under the private mount/net
wrapper documented by selfexec_jail_boundary.py. This Python entry requires
resource.prlimit and pidfd support on the SAME Linux host as the target. It is
not a remote-SSH controller or a claim that OpenWrt already has Python.

Every helper/resolver x 2/3/4/8 case starts a fresh isolated service. Each case
starts at the observed router's exact soft/hard NOFILE limits 1024/4096.
uses one fixed 2-second pressure operation and one recovery operation, with
20 parallel local DNS health requests and up to 0.5 seconds to drain replies.
Helper stimulus is a real one-block TFTP transfer with a unique callback path;
resolver stimulus is a unique hostname servers-file route followed by HUP.
Unique phase names prevent delayed pressure work from proving recovery.

Lowering/restoring pauses only the pinned, identity-checked owned process while
counting its real descriptor holes; hard limit never changes. Any missing PID,
identity/group mismatch, unexpected limit change or health failure is retained.
A failed operation is NEVER excused by an implementation's extra FDs. Failure
stops that case, restores in finally when identity still matches, and records a
fresh public recovery operation. Later predeclared cases use fresh processes.
This is not device installation authorization; a device wrapper still needs
its existing production guard and owned process-group boundary.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import resource
import select
import signal
import socket
import sys
import time

import selfexec_jail_boundary as jail

LEVELS = (2, 3, 4, 8)
PAYLOAD = b'fd-headroom-fixture'


def identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'starttime_ticks': int(fields[19]), 'pgrp': int(fields[2]), 'state': fields[0]}


def same_identity(actual, expected):
    return all(actual[key] == expected[key] for key in ['pid', 'starttime_ticks', 'pgrp'])


def fd_snapshot(pid):
    before = identity(pid); proc = Path('/proc') / str(pid)
    rows = []
    for path in sorted((proc / 'fd').iterdir(), key=lambda item: int(item.name)):
        info = (proc / 'fdinfo' / path.name).read_text()
        flags = next(line.split()[1] for line in info.splitlines() if line.startswith('flags:'))
        rows.append({'fd': int(path.name), 'target': os.readlink(path), 'flags_octal': flags, 'fdinfo': info})
    limits = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    after = identity(pid)
    if not same_identity(before, after): raise RuntimeError('PID identity changed during FD snapshot')
    return {'identity': after, 'limits': list(limits), 'fds': rows, 'at_ns': time.monotonic_ns()}


def limit_for_holes(open_fds, wanted, old_soft):
    """Exclude the (wanted+1)th free FD; retain exactly wanted holes below soft."""
    if wanted not in LEVELS or len(open_fds) != len(set(open_fds)) or any(type(fd) is not int or fd < 0 for fd in open_fds):
        raise ValueError('invalid FD inventory or headroom')
    used = set(open_fds); free = []
    for fd in range(len(used) + wanted + 1):
        if fd not in used:
            if len(free) == wanted:
                if old_soft != resource.RLIM_INFINITY and fd > old_soft:
                    raise ValueError('original soft limit has insufficient headroom')
                return fd, free
            free.append(fd)
    raise AssertionError('FD-hole bound was insufficient')


class LimitChange:
    """One owned process, one limit, one finally restore; no process discovery."""
    def __init__(self, pid, owned_group, wanted, output):
        self.pid, self.wanted, self.output = pid, wanted, output
        self.expected = identity(pid)
        if self.expected['pgrp'] != owned_group: raise RuntimeError('target is outside owned process group')
        self.pidfd = os.pidfd_open(pid)
        self.changed = False; self.stopped = False
        self.record = {'requested_holes': wanted, 'expected_identity': self.expected, 'owned_group': owned_group}

    def save(self): jail.save(self.output, self.record)

    def checked_identity(self):
        current = identity(self.pid)
        if not same_identity(current, self.expected): raise RuntimeError('PID/starttime/group mismatch')
        if current['state'] == 'Z': raise RuntimeError('target is a zombie')
        return current

    def stop(self):
        if self.checked_identity()['state'] in ['T', 't']:
            raise RuntimeError('target was already stopped by another owner')
        signal.pidfd_send_signal(self.pidfd, signal.SIGSTOP)
        self.stopped = True
        deadline = time.monotonic() + 1
        while self.checked_identity()['state'] not in ['T', 't']:
            if time.monotonic() >= deadline: raise RuntimeError('target did not stop')
            select.select([], [], [], .002)

    def resume(self):
        if self.stopped:
            self.checked_identity()
            signal.pidfd_send_signal(self.pidfd, signal.SIGCONT)
            self.stopped = False

    def apply(self):
        try:
            self.stop()
            before = fd_snapshot(self.pid)
            if before['limits'] != [1024, 4096]:
                raise RuntimeError('baseline NOFILE limits differ from frozen router 1024/4096')
            soft, holes = limit_for_holes([row['fd'] for row in before['fds']], self.wanted, before['limits'][0])
            self.original = tuple(before['limits']); self.limited = (soft, self.original[1])
            self.record.update(before=before, available_fds=holes, planned_limits=list(self.limited))
            self.save()  # Original limits/identity survive an interrupted apply.
            self.checked_identity()
            resource.prlimit(self.pid, resource.RLIMIT_NOFILE, self.limited)
            self.changed = True
            after = fd_snapshot(self.pid)
            actual_holes = [fd for fd in range(soft) if fd not in {row['fd'] for row in after['fds']}]
            self.record['applied'] = after
            if after['limits'] != list(self.limited) or actual_holes != holes or after['fds'] != before['fds']:
                raise RuntimeError('stopped target FD inventory or applied limits changed')
            self.record['applied_exactly'] = True
        finally:
            try: self.save()
            finally: self.resume()

    def restore(self):
        try:
            if not self.changed:
                self.record['restore'] = {'needed': False}
                return
            self.stop()
            self.record['before_restore'] = fd_snapshot(self.pid)
            if tuple(self.record['before_restore']['limits']) != self.limited:
                raise RuntimeError('limit changed outside this fixture; refusing to overwrite it')
            self.checked_identity()
            resource.prlimit(self.pid, resource.RLIMIT_NOFILE, self.original)
            self.changed = False
            after = fd_snapshot(self.pid)
            if tuple(after['limits']) != self.original: raise RuntimeError('original limit was not restored')
            self.record['restore'] = {'needed': True, 'restored': True, 'snapshot': after}
        except Exception as error:
            self.record['restore'] = {'needed': self.changed, 'restored': False, 'error': f'{type(error).__name__}: {error}'}
        finally:
            try: self.resume()
            except Exception as error: self.record['resume_error'] = f'{type(error).__name__}: {error}'
            self.save()

    def close(self): os.close(self.pidfd)


def prepare_pressure(root, mode):
    if mode != 'helper': return
    config = root / 'fixture/config'
    config.write_text(config.read_text() + 'enable-tftp\ntftp-root=/fixture/tftp\n')
    folder = root / 'fixture/tftp'; folder.mkdir(mode=0o755); folder.chmod(0o755)
    for holes in LEVELS:
        for phase in ['pressure', 'recovery']:
            payload = folder / f'fd-{phase}-{holes}.bin'
            payload.write_bytes(PAYLOAD); payload.chmod(0o644)
    # Preserve the initial old-callback contract and add exact public TFTP IDs.
    script = root / 'fixture/script'
    old = script.read_text()
    extra = ('if [ "$1" = tftp ]; then\n'
             f'  [ "$#" -eq 4 ] && [ "$2" = {len(PAYLOAD)} ] && [ "$3" = 127.0.0.1 ] || exit 66\n'
             '  case "$4" in /fixture/tftp/fd-pressure-[2348].bin|/fixture/tftp/fd-recovery-[2348].bin) ;; *) exit 67;; esac\n'
             '  printf "%s %s %s %s\\n" "$1" "$2" "$3" "$4" >> /fixture/callback\n  exit 0\nfi\n')
    script.write_text('#!/bin/sh\n' + extra + old.removeprefix('#!/bin/sh\n'))


def callback_count(text, label):
    expected = f'tftp {len(PAYLOAD)} 127.0.0.1 /fixture/tftp/{label}.bin'
    return text.splitlines().count(expected)


def stage(args, mode, root, phase, process, owner, owner_fd, upstream, resolver):
    result = {'phase': phase, 'operation_ok': False, 'health': [], 'operation': [], 'resolver_child': None}
    try:
        return run_stage(args, mode, root, phase, process, owner, owner_fd, upstream, resolver, result)
    except Exception as error:
        result.update(passed=False, error=f'{type(error).__name__}: {error}')
        return result
    finally:
        jail.save(root.parent / f'{phase}-stage.json', result)


def run_stage(args, mode, root, phase, process, owner, owner_fd, upstream, resolver, result):
    label = f'fd-{phase}-{args.headroom}'
    start = time.monotonic(); deadline = start + 2.5; health_sent = {}; health_done = set(); sent = 0
    name = f'probe.{label}.jail.test'; operation_wire = jail.query(name, ident=0x7111)
    lookup_name = f'{label}.lookup.jail.test'
    if mode == 'resolver':
        (root / 'fixture/servers').write_text(f'server=/{label}.jail.test/{lookup_name}#15354\n')
        signal.pidfd_send_signal(owner_fd, signal.SIGHUP)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as health, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        health.setblocking(False); client.setblocking(False)
        if mode == 'helper':
            client.sendto(b'\0\1' + (label + '.bin').encode() + b'\0octet\0', ('127.0.0.1', 69))
        next_operation = start
        while time.monotonic() < deadline:
            now = time.monotonic()
            if process.poll() is not None: result['stopped'] = 'owner exited'; break
            while sent < 20 and now >= start + sent * .1:
                ident = 0x9000 + sent
                health.sendto(jail.query('ready.jail.test', ident=ident), ('127.0.0.1', 53))
                health_sent[ident] = time.monotonic(); sent += 1
            if any(now - when > .5 for ident, when in health_sent.items() if ident not in health_done):
                result['stopped'] = 'local DNS health exceeded 500 ms'; break
            if mode == 'resolver' and not result['operation_ok'] and now >= next_operation and now < start + 2:
                client.sendto(operation_wire, ('127.0.0.1', 53)); next_operation = now + .1
            ready, _, _ = select.select([health, client, upstream, resolver], [], [], min(.05, max(0, deadline - now)))
            if upstream in ready:
                packet, peer = upstream.recvfrom(65535); upstream.sendto(jail.answer(packet), peer)
                result.setdefault('upstream', []).append(packet.hex())
            if resolver in ready:
                packet, peer = resolver.recvfrom(65535)
                if jail.read_name(packet, 12)[0].lower() != lookup_name:
                    result.setdefault('unrelated_resolver_requests', []).append(packet.hex())
                else:
                    if result['resolver_child'] is None:
                        try: result['resolver_child'] = jail.worker_observation(owner, root, args.sha256, 'lookup', args.proc_visible)
                        except OSError as error: result['resolver_child'] = {'captured': False, 'error': str(error)}
                    result.setdefault('resolver_requests', []).append(packet.hex())
                    resolver.sendto(jail.resolver_answer(packet, lookup_name), peer)
            if health in ready:
                packet, peer = health.recvfrom(65535); value = jail.semantics(packet); ident = int.from_bytes(packet[:2], 'big')
                valid = (ident in health_sent and ident not in health_done and peer == ('127.0.0.1', 53)
                         and value['flags'] & 15 == 0 and value['questions'] == [['ready.jail.test', 1, 1]]
                         and [row['data'] for row in value['records'] if row['section'] == 'answer'] == ['192.0.2.7'])
                result['health'].append({'id': ident, 'ok': valid, 'wire': packet.hex(), 'received_ns': time.monotonic_ns()})
                if not valid: result['stopped'] = 'wrong or duplicate DNS health response'; break
                health_done.add(ident)
            if client in ready:
                packet, peer = client.recvfrom(65535); result['operation'].append({'wire': packet.hex(), 'peer': list(peer)})
                if mode == 'helper':
                    if packet != b'\0\3\0\1' + PAYLOAD: result['stopped'] = 'wrong TFTP data'; break
                    client.sendto(b'\0\4\0\1', peer)
                else:
                    value = jail.semantics(packet)
                    if (packet[:2] == operation_wire[:2] and value['flags'] & 15 == 0 and value['questions'] == [[name, 1, 1]]
                            and [row['data'] for row in value['records'] if row['section'] == 'answer'] == ['192.0.2.7']):
                        result['operation_ok'] = True
            if mode == 'helper':
                result['callbacks_raw'] = (root / 'fixture/callback').read_text()
                result['callback_count'] = callback_count(result['callbacks_raw'], label)
                result['operation_ok'] = result['callback_count'] == 1
                if result['callback_count'] > 1: result['stopped'] = 'duplicate script callback'; break
    result['health_sent'] = sent; result['health_received'] = len(health_done)
    result['health_ok'] = sent == 20 and len(health_done) == 20 and 'stopped' not in result
    result['passed'] = result['operation_ok'] and result['health_ok'] and (
        mode == 'helper' or (result['resolver_child'] or {}).get('valid') is True)
    result['finished_ns'] = time.monotonic_ns()
    return result


def trial(args, mode, root, baseline, process, owner, owner_fd, upstream, resolver):
    result = {'headroom': args.headroom, 'passed': False}
    if (not baseline.get('runtime_boundary') or
            (mode == 'helper' and (not jail.startup_callback_work(baseline.get('callback'))['valid'] or
                                   not baseline['helper_child'].get('valid'))) or
            (mode == 'resolver' and (not baseline['after']['ok'] or not baseline['resolver_child'].get('valid')))):
        raise RuntimeError('baseline did not qualify for pressure')
    pid = baseline['helper_child']['pid'] if mode == 'helper' else owner
    group = os.getpgid(process.pid)
    deadline = time.monotonic() + 1
    while Path(f'/proc/{pid}/task/{pid}/children').read_text().strip():
        if time.monotonic() >= deadline: raise RuntimeError('pressure target was not idle')
        select.select([], [], [], .002)
    if mode == 'helper':
        baseline['callback'] = (root / 'fixture/callback').read_text()
        baseline['callback_work'] = jail.startup_callback_work(baseline['callback'])
        if not baseline['callback_work']['valid']:
            raise RuntimeError('complete startup callback work did not qualify for pressure')
    change = LimitChange(pid, group, args.headroom, root.parent / 'limit-change.json')
    try:
        try:
            change.apply()
            result['pressure'] = stage(args, mode, root, 'pressure', process, owner, owner_fd, upstream, resolver)
        except Exception as error:
            result['pressure_error'] = f'{type(error).__name__}: {error}'
        finally:
            change.restore()
            result['limit_change'] = change.record
        try:
            result['recovery'] = stage(args, mode, root, 'recovery', process, owner, owner_fd, upstream, resolver)
        except Exception as error:
            result['recovery_error'] = f'{type(error).__name__}: {error}'
        result['passed'] = (change.record.get('applied_exactly') is True
                            and change.record.get('restore', {}).get('restored') is True
                            and result.get('pressure', {}).get('passed') is True
                            and result.get('recovery', {}).get('passed') is True)
    finally:
        change.close()
        jail.save(root.parent / 'pressure-result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--proc-mode', choices=['visible', 'absent'], default='visible')
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.geteuid() != 0 or not hasattr(resource, 'prlimit')
            or not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal')):
        parser.error('Linux root, resource.prlimit and pidfd support required')
    observer = jail.namespaces('self')
    if any(observer[name] == jail.namespaces(1)[name] for name in ['mnt', 'net']):
        parser.error('private mount/net namespaces with host /proc required')
    if {name for _, name in socket.if_nameindex()} != {'lo'}: parser.error('loopback-only network required')
    state = jail.status('self')
    if state['Seccomp'] or state['NoNewPrivs'] or state['CapPrm'] & (jail.CAPS | 1 << 24) != (jail.CAPS | 1 << 24):
        parser.error('seccomp=0/Nnp=0, network capabilities and CAP_SYS_RESOURCE required')
    args.binary = args.binary.resolve(); args.image_root = args.image_root.resolve(); args.output = args.output.resolve()
    if jail.sha256(args.binary) != args.sha256 or 'private' not in args.output.parts or args.output.exists():
        parser.error('exact binary hash and fresh private output required')
    args.proc_visible = args.proc_mode == 'visible'; args.expect = 'success'
    args.initial_nofile = (1024, 4096)
    def terminated(number, frame):
        raise InterruptedError(f'pressure fixture interrupted by signal {number}')
    signal.signal(signal.SIGTERM, terminated)
    output = args.output; output.mkdir(parents=True)
    report = {'source_commit': args.source_commit, 'binary_sha256': args.sha256, 'tool_sha256': jail.sha256(__file__),
              'jail_tool_sha256': jail.sha256(jail.__file__), 'proc_mode': args.proc_mode,
              'baseline_nofile': [1024, 4096],
              'schedule': [{'holes': holes, 'mode': mode} for holes in LEVELS for mode in ['helper', 'resolver']], 'cases': []}
    for holes in LEVELS:
        args.headroom = holes; args.output = output / f'holes-{holes}'; args.output.mkdir()
        for mode in ['helper', 'resolver']:
            report['cases'].append(jail.run_case(args, mode, observer, prepare_pressure, trial))
            jail.save(output / 'result.json', report)
    report['passed'] = all(row['passed'] for row in report['cases'])
    jail.save(output / 'result.json', report)
    print(jail.json.dumps({'passed': report['passed'], 'cases': len(report['cases']), 'output': str(output)}))
    return int(not report['passed'])


if __name__ == '__main__':
    raise SystemExit(main())
