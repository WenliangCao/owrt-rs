#!/usr/bin/env python3
"""Oracle-only C/eight-variant registration syscall counts, including epoll.

Run only after timing collection has stopped. Traced timing is never evidence.
Usage: sudo python3 syscalls.py --oracle-host-only --out NEW_DIRECTORY
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time


BASE = Path('/home/ubuntu')
ROOTFS = BASE / 'owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files'
ROOT = BASE / 'r135'
CONTROL_SHA = '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0'
C_SHA = 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'
LABELS = tuple(f's{s}b{b}k{k}' for s in (0, 1) for b in (0, 1) for k in (0, 1))
BENCHMARK = BASE / 'r134/out/owrt-benchmark'
BENCHMARK_SHA = '0ca42fbafe08b7ace0aaa90f78c08c9c0f69022a64f6d5073ab6ceb77a88e693'
LIBRARIES = {
    'lib/libc.so': '8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b',
    'lib/libubox.so.20260213': 'a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063',
    'lib/libgcc_s.so.1': '33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c',
    'lib/libblobmsg_json.so.20260213': 'e6a2a2cdf07f453c28f703537c636516e92d17b63ad732ec606b5cd99bd5ef97',
    'usr/lib/libjson-c.so.5.4.0': '830799c5682eff7f75800482dabd65a1fe2e925374a19da2a25a2da708d8a153',
}
EPOLL_CALLS = ('epoll_wait', 'epoll_pwait')
CALLS = ('recvmsg', 'read', 'sendmsg', 'getrandom', *EPOLL_CALLS)
PHASES = ('startup', 'connection_setup', 'preflight', 'warmup', 'measured', 'validation_lookup', 'teardown')
N, WARMUP = 100, 20
ATTRIBUTION = (
    'A successful recvmsg request prefix starts its phase. EAGAIN probes and epoll waits '
    'are assigned to the previously received request until the next successful request recvmsg. '
    'Startup precedes successful accept; connection setup, preflight, warmup, validation LOOKUPs '
    'and EOF teardown are separate from measured cycles. This is a prior-request convention, '
    'not a synchronized timed interval: the wait leading into the first measured request belongs '
    'to the prior warmup request, and the wait leading into the final LOOKUP belongs to the last '
    'measured request. epoll_wait and epoll_pwait are counted separately as printed by strace. '
    'Totals cover selected syscall families only, not every daemon syscall.'
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def subjects():
    manifest = ROOT / 'variants-01/variants.json'
    variants = json.loads(manifest.read_text())
    labels = [v['label'] for v in variants['variants']]
    require(len(labels) == 8 and set(labels) == set(LABELS), 'expected all eight variants exactly once')
    require(variants['base_binary_sha256'] == CONTROL_SHA, 'variant base differs from frozen R134')
    binaries = {'c': (ROOTFS / 'sbin/ubusd', C_SHA)}
    manifests = {str(manifest): sha(manifest)}
    for label in LABELS:
        directory = ROOT / 'build-01' / label
        identity = directory / 'binary.sha256'
        expected = identity.read_text().split()[0]
        require(re.fullmatch(r'[0-9a-f]{64}', expected), f'invalid identity: {label}')
        binaries[label] = (directory / 'ubusd-rs', expected)
        manifests[str(identity)] = sha(identity)
    require(binaries['s1b1k1'][1] == CONTROL_SHA, 'R134 control differs')
    return binaries, manifests


def summarize(trace):
    """Requests are serial; successful recvmsg prefixes identify each request."""
    counts = defaultdict(Counter)
    returns = defaultdict(Counter)
    requests = []
    epoll = []
    epoll_ready = defaultdict(Counter)
    expected_types = [6, 4, 7, 4] + [6, 7] * (WARMUP + N) + [4]
    phase = 'startup'
    added = removed = 0
    peer_fd = None
    current = None
    for number, line in enumerate(trace.splitlines(), 1):
        if line.startswith(('--- ', '+++ ')):
            continue
        match = re.match(r'([a-z0-9_]+)\((.*)\) += (-?\d+)(.*)$', line)
        require(match is not None, f'unparsed trace line {number}: {line}')
        name, arguments, result, suffix = match.groups()
        result = int(result)
        if name in ('accept', 'accept4'):
            if result >= 0:
                require(peer_fd is None, 'unexpected second benchmark connection')
                peer_fd = result
                phase = 'connection_setup'
                current = None
            continue
        require(name in CALLS, f'unexpected syscall {name}')
        if name == 'recvmsg' and result > 0:
            parts = re.findall(r'iov_base="((?:\\x[0-9a-f]{2})*)", iov_len=(\d+)', arguments)
            require(parts, f'missing recvmsg payload at {number}')
            data = b''.join(bytes.fromhex(encoded.replace('\\x', '')) for encoded, _ in parts)
            require(len(data) == result and len(data) >= 12, 'short or truncated request prefix')
            require(int(arguments.split(',', 1)[0]) == peer_fd, 'unexpected receive fd')
            kind = data[1]
            seq = int.from_bytes(data[2:4], 'big')
            require(len(requests) < len(expected_types) and kind == expected_types[len(requests)],
                    f'request ordering differs at request {len(requests) + 1}')
            require(seq == len(requests) + 1, 'request sequence differs from frozen caller')
            if kind == 6:  # ADD_OBJECT
                added += 1
                phase = 'preflight' if added == 1 else 'warmup' if added <= WARMUP + 1 else 'measured'
            elif kind == 7:  # REMOVE_OBJECT
                removed += 1
                require(removed == added, 'ADD/REMOVE request ordering')
                phase = 'preflight' if added == 1 else 'warmup' if added <= WARMUP + 1 else 'measured'
            elif kind == 4:  # LOOKUP, outside cycle measurement
                phase = 'validation_lookup'
            else:
                raise RuntimeError(f'unexpected request type {kind}')
            current = {'type': kind, 'seq': seq, 'phase': phase, 'trace_line': number,
                       'cycle_ordinal': added, 'measured_cycle': added - WARMUP - 1 if phase == 'measured' else None,
                       'bytes_in_recvmsg': result, 'frame_bytes': 8 + (int.from_bytes(data[8:12], 'big') & 0xffffff)}
            require(result <= current['frame_bytes'], 'multiple requests in one recvmsg need explicit attribution')
            requests.append(current)
        if name in ('read', 'recvmsg') and result == 0 and peer_fd is not None:
            if int(arguments.split(',', 1)[0]) == peer_fd:
                phase = 'teardown'
                current = None
        counts[phase][name] += 1
        if result == -1:
            status = 'eagain' if 'EAGAIN' in suffix else 'eintr' if 'EINTR' in suffix else 'error'
        elif result == 0:
            status = 'timeout' if name in EPOLL_CALLS else 'eof'
        else:
            status = 'positive'
        returns[phase][f'{name}:{status}'] += 1
        require(status != 'error', f'unexpected syscall failure at line {number}: {line}')
        if name in EPOLL_CALLS:
            epoll.append({'call': name, 'phase': phase, 'trace_line': number, 'result': result,
                          'status': status, 'prior_request': current})
            if result > 0:
                epoll_ready[phase][name] += result
        if name == 'sendmsg':
            require(result > 0, f'failed sendmsg at {number}')
        if name == 'getrandom':
            require(result > 0, f'failed getrandom at {number}')
    require(added == removed == N + WARMUP + 1, f'cycle counts {added}/{removed}')
    require(len(requests) == len(expected_types), 'incomplete frozen request transcript')
    totals = Counter()
    for values in counts.values():
        totals.update(values)
    phases = {phase: {call: counts[phase][call] for call in CALLS} for phase in PHASES}
    receive = {phase: {'successful': returns[phase]['recvmsg:positive'],
                       'eagain': returns[phase]['recvmsg:eagain'], 'eof': returns[phase]['recvmsg:eof'],
                       'eintr': returns[phase]['recvmsg:eintr']} for phase in PHASES}
    return {'counts': {call: totals[call] for call in CALLS}, 'phases': phases,
            'returns_by_phase': dict(returns), 'recvmsg_by_phase': receive,
            'requests': requests, 'epoll_calls': epoll,
            'epoll_ready_events_by_phase': {phase: {call: epoll_ready[phase][call] for call in EPOLL_CALLS}
                                            for phase in PHASES},
            'cycles': {'preflight': 1, 'warmup': WARMUP, 'measured': N},
            'measured_calls_per_cycle': {call: counts['measured'][call] / N for call in CALLS},
            'measured_recvmsg_successful_per_cycle': receive['measured']['successful'] / N,
            'measured_recvmsg_eagain_per_cycle': receive['measured']['eagain'] / N,
            'attribution': ATTRIBUTION}


def run_case(out, label, binary, expected, methods):
    out.mkdir()
    acl = out / 'empty-acl'
    acl.mkdir()
    socket = str(out / 'bus.sock')
    require(len(socket.encode()) < 108, 'socket path too long')
    loader = ROOTFS / 'lib/libc.so'
    daemon_args = [str(binary), '-s', socket, '-A', str(acl)]
    if label == 'c':
        daemon_args = [str(loader), '--library-path', f'{ROOTFS}/lib:{ROOTFS}/usr/lib',
                       '--argv0', '/sbin/ubusd', *daemon_args]
    command = ['strace', '-qq', '-xx', '-v', '-s', '65535', '-e',
               'trace=' + ','.join((*CALLS, 'accept', 'accept4')), '-o', str(out / 'trace.txt'), *daemon_args]
    write_json(out / 'daemon-command.json', command)
    tracer = None
    daemon_pid = None
    try:
        with (out / 'daemon.log').open('wb') as log:
            tracer = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=True, preexec_fn=lambda: os.sched_setaffinity(0, {1}))
            deadline = time.monotonic() + 10
            while not Path(socket).exists():
                require(tracer.poll() is None and time.monotonic() < deadline, 'daemon startup failed')
                time.sleep(.01)
            children = Path(f'/proc/{tracer.pid}/task/{tracer.pid}/children').read_text().split()
            require(len(children) == 1, f'unexpected strace children {children}')
            daemon_pid = int(children[0])
            require(os.sched_getaffinity(daemon_pid) == {1}, 'daemon affinity')
            exe = loader if label == 'c' else binary
            require(sha(f'/proc/{daemon_pid}/exe') == sha(exe), 'live executable changed')
            before_maps = Path(f'/proc/{daemon_pid}/maps').read_text()
            (out / 'daemon-maps.txt').write_text(before_maps)
            require(str(binary) in before_maps, 'subject absent from process mappings')
            if label == 'c':
                for relative in LIBRARIES:
                    require(str(ROOTFS / relative) in before_maps, f'exact library not mapped: {relative}')
            caller_command = [str(BENCHMARK), 'exec-cpu', '0', str(BENCHMARK), 'register-cycle',
                              socket, str(methods), '8', str(N), str(WARMUP), str(daemon_pid)]
            write_json(out / 'caller-command.json', caller_command)
            with (out / 'caller.json').open('wb') as caller, (out / 'caller.log').open('wb') as err:
                subprocess.run(caller_command, stdout=caller, stderr=err, timeout=60, check=True)
            require(not (out / 'caller.log').read_bytes(), 'benchmark stderr')
            require(sha(f'/proc/{daemon_pid}/exe') == sha(exe), 'live executable changed after caller')
            require(sha(binary) == expected and sha(BENCHMARK) == BENCHMARK_SHA, 'artifact changed')
            os.kill(daemon_pid, signal.SIGTERM)
            require(tracer.wait(timeout=10) in (0, 128 + signal.SIGTERM, -signal.SIGTERM), 'unexpected daemon exit')
        result = summarize((out / 'trace.txt').read_text())
        result.update(subject=label, methods=methods, subject_sha256=expected,
                      benchmark_sha256=BENCHMARK_SHA, trace_sha256=sha(out / 'trace.txt'),
                      caller_sha256=sha(out / 'caller.json'))
        write_json(out / 'result.json', result)
        (out / 'COMPLETE').touch()
        return {key: value for key, value in result.items() if key not in ('requests', 'epoll_calls')}
    finally:
        if tracer is not None and tracer.poll() is None:
            os.killpg(tracer.pid, signal.SIGKILL)
            tracer.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-host-only', action='store_true', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64'
            and not Path('/etc/openwrt_release').exists(), 'Oracle Linux host required')
    require(os.geteuid() == 0, 'run through sudo for ptrace')
    require({0, 1} <= os.sched_getaffinity(0), 'CPU 0/1 unavailable')
    require(sha(BENCHMARK) == BENCHMARK_SHA, 'benchmark identity')
    binaries, manifests = subjects()
    for binary, expected in binaries.values():
        require(sha(binary) == expected, f'subject identity: {binary}')
    for relative, expected in LIBRARIES.items():
        require(sha(ROOTFS / relative) == expected, f'library identity: {relative}')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'Oracle structural syscall diagnostic only; all traced latency and CPU are excluded from performance claims.',
              'runner_sha256': sha(__file__), 'benchmark_sha256': BENCHMARK_SHA,
              'benchmark_path': str(BENCHMARK), 'invocation': sys.argv, 'kernel': platform.release(),
              'subjects': {label: {'path': str(path), 'sha256': expected} for label, (path, expected) in binaries.items()},
              'input_manifests_sha256': manifests, 'counted_syscalls': list(CALLS),
              'attribution': ATTRIBUTION, 'subject_cpu': 1, 'caller_cpu': 0,
              'strace_version': subprocess.check_output(['strace', '-V'], text=True).splitlines()[0],
              'library_sha256': LIBRARIES, 'samples': []}
    try:
        for methods in (1, 16):
            for label, (binary, expected) in binaries.items():
                print(f'START {label} methods={methods}', flush=True)
                report['samples'].append(run_case(out / f'{label}-{methods}', label, binary, expected, methods))
                write_json(out / 'result.json', report)
                print(f'COMPLETE {label} methods={methods}', flush=True)
        for path, expected in manifests.items():
            require(sha(path) == expected, f'input manifest changed: {path}')
        report['passed'] = True
        write_json(out / 'result.json', report)
        (out / 'COMPLETE').touch()
    except Exception as error:
        report.update(passed=False, error=str(error))
        write_json(out / 'result.json', report)
        (out / 'FAILED').touch()
        raise


if __name__ == '__main__':
    main()
