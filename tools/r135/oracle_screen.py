#!/usr/bin/env python3
"""Exploratory two-pair Oracle screen; never a router performance verdict."""
import argparse
import concurrent.futures
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import threading
import time

ROOT = Path('/home/ubuntu/r135')
ROOTFS = Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
LIBRARIES = {
    'lib/libc.so': '8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b',
    'lib/libubox.so.20260213': 'a808d6aeff85a7ba31c8a87dda9496692b0b1b349a6012404f4a76d1fbbe4063',
    'lib/libgcc_s.so.1': '33a47a54f9d8d901055aa0812dfcb4b1b4630061c9c0052f9b8e267c7279c16c',
    'lib/libblobmsg_json.so.20260213': 'e6a2a2cdf07f453c28f703537c636516e92d17b63ad732ec606b5cd99bd5ef97',
    'usr/lib/libjson-c.so.5.4.0': '830799c5682eff7f75800482dabd65a1fe2e925374a19da2a25a2da708d8a153',
}
LANES = [('register_1', 'register-cycle', '1', '8'),
         ('register_16', 'register-cycle', '16', '8'),
         ('event_1', 'register-watch', '1', '1')]
STOP = threading.Event()
STOP_SIGNAL = None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def request_stop(signum, _frame):
    # Do not raise in the main thread while workers own isolated sessions.
    # They finish the current caller (at most its 60s timeout), then clean up.
    global STOP_SIGNAL
    STOP_SIGNAL = signum
    STOP.set()


def stop_reason():
    return f'stop requested by signal {STOP_SIGNAL}' if STOP_SIGNAL is not None else 'another worker failed'


def stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def validate_measurement(data, daemon_pid, daemon_start, caller_pid, pair, affinity, n, warmup):
    require(data['schema'] == 1 and type(data['successful']) is int and data['successful'] == n
            and data['warmup'] == warmup and data['errors'] == 0, 'invalid measurement counts')
    samples = data['latency_ns']
    require(len(samples) == n and all(type(v) is int and v > 0 for v in samples), 'invalid latency samples')
    require(math.isfinite(data['wall_s']) and data['wall_s'] > 0, 'invalid wall time')
    metrics = {'mean_us': sum(samples) / n / 1000, 'ops_per_s': n / data['wall_s']}
    ordered = sorted(samples)
    for key, quantile in (('p50_us', .50), ('p95_us', .95), ('p99_us', .99)):
        metrics[key] = ordered[math.floor((n - 1) * quantile + .5)] / 1000
    for key, expected in metrics.items():
        require(math.isfinite(data[key]) and math.isclose(data[key], expected, rel_tol=1e-8, abs_tol=1e-6),
                f'{key} differs from raw measurements')
    require(len(data['daemon_cpu']) == 1, 'one daemon required')
    cpu = data['daemon_cpu'][0]
    require(cpu['pid'] == daemon_pid, 'wrong monitored daemon PID')
    caller_mask = str(pair[0]) if affinity == 'split' else f'{pair[0]}-{pair[1]}'
    for name, pid, before, after, mask, elapsed in (
            ('daemon', daemon_pid, cpu['before'], cpu['after'], str(pair[1]), cpu['cpu_clock_ns']),
            ('caller', caller_pid, data['client_before'], data['client_after'], caller_mask, data['client_cpu_clock_ns'])):
        require(before['pid'] == after['pid'] == pid and before['start_ticks'] == after['start_ticks'],
                f'{name} process identity changed')
        if name == 'daemon':
            require(before['start_ticks'] == daemon_start, 'daemon start time differs from live process')
        for sample in (before, after):
            require(sample['Cpus_allowed_list'] == mask, f'{name} affinity mismatch')
            require(type(sample['process_cpu_ns']) is int and sample['process_cpu_ns'] >= 0,
                    f'{name} CPU clock sample invalid')
        require(before['process_cpu_resolution_ns'] == after['process_cpu_resolution_ns'] > 0,
                f'{name} CPU clock resolution changed')
        require(type(elapsed) is int and elapsed > 0 and elapsed == after['process_cpu_ns'] - before['process_cpu_ns'],
                f'{name} CPU clock delta differs')
        for field in ('voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches'):
            require(type(before[field]) is int and type(after[field]) is int
                    and 0 <= before[field] <= after[field], f'{name} {field} regressed')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def proc_record():
    return {name: Path('/proc', name).read_text() for name in ('stat', 'loadavg', 'meminfo')}


def run_subject(out, label, subject, bench, bench_sha, pair, block, n, warmup):
    out.mkdir(parents=True)
    binary, expected = subject
    socket = str(out / 'bus.sock')
    require(len(socket.encode()) < 108, 'socket path too long')
    acl = out / 'acl'
    acl.mkdir()
    daemon_cpu, caller_cpu = pair[1], pair[0]
    subject_args = ['-s', socket, '-A', str(acl)]
    if label == 'c':
        args = ['taskset', '-c', str(daemon_cpu), str(ROOTFS / 'lib/libc.so'),
                '--library-path', f'{ROOTFS}/lib:{ROOTFS}/usr/lib',
                '--argv0', '/sbin/ubusd', str(binary), *subject_args]
    else:
        args = [str(bench), 'exec-cpu-as', str(daemon_cpu), str(binary), '/sbin/ubusd', *subject_args]
    write(out / 'daemon-command.json', args)
    write(out / 'system-before.json', proc_record())
    daemon = caller = None
    results = []
    try:
        with (out / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 10
            while not Path(socket).exists():
                require(not STOP.is_set(), stop_reason())
                require(daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed')
                time.sleep(.005)
            require(os.sched_getaffinity(daemon.pid) == {daemon_cpu}, 'daemon affinity mismatch')
            live_stat = Path(f'/proc/{daemon.pid}/stat').read_text()
            daemon_start = int(live_stat.rsplit(') ', 1)[1].split()[19])
            (out / 'daemon-stat.txt').write_text(live_stat)
            cmdline = Path(f'/proc/{daemon.pid}/cmdline').read_bytes()
            (out / 'daemon-cmdline.bin').write_bytes(cmdline)
            if label != 'c':
                require(cmdline == b'\0'.join(x.encode() for x in ['/sbin/ubusd', *subject_args]) + b'\0',
                        'Rust argv0 or arguments differ')
            exe = ROOTFS / 'lib/libc.so' if label == 'c' else binary
            require(sha(f'/proc/{daemon.pid}/exe') == sha(exe), 'live executable mismatch')
            maps = Path(f'/proc/{daemon.pid}/maps').read_text()
            (out / 'daemon-maps.txt').write_text(maps)
            require(str(binary) in maps, 'subject not mapped')
            if label == 'c':
                require(all(str(ROOTFS / name) in maps for name in LIBRARIES), 'C libraries not mapped')
            conditions = list(itertools.product(('split', 'pair_allowed'), LANES))
            if (block + caller_cpu // 2) % 2:
                conditions.reverse()
            for affinity, (lane, command, a, b) in conditions:
                require(not STOP.is_set(), stop_reason())
                mask = str(caller_cpu) if affinity == 'split' else ','.join(map(str, pair))
                cmd = ['taskset', '-c', mask, str(bench), command, socket, a, b,
                       str(n), str(warmup), str(daemon.pid)]
                name = f'{affinity}-{lane}'
                write(out / f'{name}-command.json', cmd)
                with (out / f'{name}.json').open('wb') as stdout, (out / f'{name}.log').open('wb') as stderr:
                    caller = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, start_new_session=True)
                    require(caller.wait(timeout=60) == 0, f'caller failed: {name}')
                require(not (out / f'{name}.log').read_bytes(), f'caller stderr: {name}')
                data = json.loads((out / f'{name}.json').read_text())
                validate_measurement(data, daemon.pid, daemon_start, caller.pid, pair, affinity, n, warmup)
                results.append(dict(label=label, block=block, pair=list(pair), affinity=affinity, lane=lane,
                                    file=str(out / f'{name}.json'), subject_sha256=expected,
                                    benchmark_sha256=bench_sha))
            require(daemon.poll() is None and sha(binary) == expected and sha(bench) == bench_sha, 'artifact changed or daemon died')
            write(out / 'system-after.json', proc_record())
            write(out / 'results.json', results)
    finally:
        # These workloads do not fork; retain and reap both owned session
        # leaders even when a caller times out or a stop signal is pending.
        try:
            stop_process(caller)
        finally:
            stop_process(daemon)
            Path(socket).unlink(missing_ok=True)
            write(out / 'cleanup.json', dict(daemon_exited=daemon is None or daemon.poll() is not None,
                                           returncode=None if daemon is None else daemon.returncode,
                                           caller_exited=caller is None or caller.poll() is not None,
                                           caller_returncode=None if caller is None else caller.returncode,
                                           socket_absent=not Path(socket).exists()))
    require(not STOP.is_set(), stop_reason())
    (out / 'COMPLETE').touch()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=4)
    parser.add_argument('--iterations', type=int, default=10000)
    parser.add_argument('--subjects', nargs='+')
    parser.add_argument('--serial', action='store_true')
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64'
            and not Path('/etc/openwrt_release').exists() and os.geteuid() == 0, 'Oracle sudo required')
    require(args.repeats > 0 and args.iterations > 0, 'invalid loop counts')
    bench = ROOT / 'benchmark-01/owrt-benchmark'
    bench_sha = (ROOT / 'benchmark-01/binary.sha256').read_text().split()[0]
    require(sha(bench) == bench_sha, 'benchmark identity')
    subjects = {
        'c': (ROOTFS / 'sbin/ubusd', 'cfb83044bbe82052fe063adaf4580e721dc85a03fb174217b5ea8fb801193a88'),
        'r131': (Path('/home/ubuntu/r131-event-batch/maps/r131'), 'c5bcf6e7c6f2ed565140e183ba3aa97c1ef60274bbde8398771ac13680da839a'),
    }
    for variant in json.loads((ROOT / 'variants-01/variants.json').read_text())['variants']:
        label = variant['label']
        directory = ROOT / 'build-01' / label
        subjects[label] = (directory / 'ubusd-rs', (directory / 'binary.sha256').read_text().split()[0])
    require(subjects['s1b1k1'][1] == '98d7ff9ddd04db45d9d71b8f7a4f317f193c3539752532c30f01075e0e7197c0', 'R134 control differs')
    if args.subjects:
        subjects = {label: subjects[label] for label in args.subjects}
    for binary, expected in subjects.values():
        require(sha(binary) == expected, f'subject identity: {binary}')
    for name, expected in LIBRARIES.items():
        require(sha(ROOTFS / name) == expected, f'library identity: {name}')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    pairs = [(0, 1)] if args.serial else [(0, 1), (2, 3)]
    require(all(set(pair) <= os.sched_getaffinity(0) for pair in pairs), 'CPU pair unavailable')
    schedules = []
    labels = list(subjects)
    label_width = max(map(len, labels))
    block_width = len(str(args.repeats - 1))
    for pair in pairs:
        jobs = []
        for block in range(args.repeats):
            order = labels if (block + pair[0] // 2) % 2 == 0 else list(reversed(labels))
            jobs.extend((block, label) for label in order)
        schedules.append(jobs)
    plan = dict(scope='Oracle exploratory screen, no router verdict', runner_sha256=sha(__file__),
                benchmark_sha256=bench_sha, subjects={k: dict(path=str(v[0]), sha256=v[1]) for k, v in subjects.items()},
                library_sha256=LIBRARIES, pairs=pairs, schedules=schedules, iterations=args.iterations,
                warmup=20, kernel=platform.release(),
                launcher='All subjects receive argv0 /sbin/ubusd; subject directory names padded to equal byte length',
                output_label_width=label_width, output_block_width=block_width,
                stop_policy='SIGTERM/SIGINT sets STOP; wait current caller or its 60s timeout, then reap owned sessions',
                interpretation='Separate conditions by CPU pair/block/affinity; parallel shared-cache effects and lane history remain exploratory')
    write(out / 'plan.json', plan)

    def worker(pair, jobs):
        records = []
        try:
            for block, label in jobs:
                require(not STOP.is_set(), stop_reason())
                padded_label = label.ljust(label_width, '_')
                dest = out / f'p{pair[0]}-{block:0{block_width}d}-{padded_label}'
                records += run_subject(dest, label, subjects[label], bench, bench_sha, pair,
                                       block, args.iterations, 20)
                print(f'COMPLETE pair={pair} block={block} {label}', flush=True)
            return records
        except Exception:
            STOP.set()
            raise

    previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous_handlers:
        signal.signal(sig, request_stop)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(pairs)) as pool:
            futures = [pool.submit(worker, pair, jobs) for pair, jobs in zip(pairs, schedules)]
            records = [record for future in futures for record in future.result()]
        require(not STOP.is_set(), stop_reason())
        write(out / 'results.json', dict(passed=True, records=records))
        write(out / 'hashes.json', {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
        require(not STOP.is_set(), stop_reason())
        (out / 'COMPLETE').touch()
    except Exception as error:
        write(out / 'failure.json', dict(error=str(error), stop_signal=STOP_SIGNAL))
        (out / 'FAILED').touch()
        raise
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    main()
