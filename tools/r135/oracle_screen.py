#!/usr/bin/env python3
"""Exploratory two-pair Oracle screen; never a router performance verdict."""
import argparse
import concurrent.futures
import hashlib
import itertools
import json
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


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


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
    args = [str(binary), '-s', socket, '-A', str(acl)]
    if label == 'c':
        args = [str(ROOTFS / 'lib/libc.so'), '--library-path', f'{ROOTFS}/lib:{ROOTFS}/usr/lib',
                '--argv0', '/sbin/ubusd', *args]
    args = ['taskset', '-c', str(daemon_cpu), *args]
    write(out / 'daemon-command.json', args)
    write(out / 'system-before.json', proc_record())
    daemon = None
    results = []
    try:
        with (out / 'daemon.log').open('wb') as log:
            daemon = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + 10
            while not Path(socket).exists():
                require(daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed')
                time.sleep(.005)
            require(os.sched_getaffinity(daemon.pid) == {daemon_cpu}, 'daemon affinity mismatch')
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
                require(not STOP.is_set(), 'another worker failed')
                mask = str(caller_cpu) if affinity == 'split' else ','.join(map(str, pair))
                cmd = ['taskset', '-c', mask, str(bench), command, socket, a, b,
                       str(n), str(warmup), str(daemon.pid)]
                name = f'{affinity}-{lane}'
                write(out / f'{name}-command.json', cmd)
                with (out / f'{name}.json').open('wb') as stdout, (out / f'{name}.log').open('wb') as stderr:
                    subprocess.run(cmd, stdout=stdout, stderr=stderr, timeout=60, check=True,
                                   start_new_session=True)
                require(not (out / f'{name}.log').read_bytes(), f'caller stderr: {name}')
                data = json.loads((out / f'{name}.json').read_text())
                require(data['successful'] == n and data['errors'] == 0 and len(data['latency_ns']) == n,
                        'invalid measurements')
                require(len(data['daemon_cpu']) == 1, 'one daemon required')
                cpu = data['daemon_cpu'][0]
                expected_mask = {caller_cpu} if affinity == 'split' else set(pair)
                # CPU pairs are consecutive; status represents them as a range.
                mask_text = str(caller_cpu) if len(expected_mask) == 1 else f'{pair[0]}-{pair[1]}'
                for side in ('before', 'after'):
                    require(data[f'client_{side}']['Cpus_allowed_list'] == mask_text, 'caller affinity mismatch')
                    require(cpu[side]['Cpus_allowed_list'] == str(daemon_cpu), 'daemon mask changed')
                    require(cpu[side]['process_cpu_resolution_ns'] > 0, 'missing CPU clock resolution')
                require(cpu['cpu_clock_ns'] > 0, 'missing process CPU time')
                results.append(dict(label=label, block=block, pair=list(pair), affinity=affinity, lane=lane,
                                    file=str(out / f'{name}.json'), subject_sha256=expected,
                                    benchmark_sha256=bench_sha))
            require(daemon.poll() is None and sha(binary) == expected and sha(bench) == bench_sha, 'artifact changed or daemon died')
            write(out / 'system-after.json', proc_record())
            write(out / 'results.json', results)
    finally:
        if daemon is not None:
            if daemon.poll() is None:
                os.killpg(daemon.pid, signal.SIGTERM)
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(daemon.pid, signal.SIGKILL)
                    daemon.wait(timeout=5)
            Path(socket).unlink(missing_ok=True)
            write(out / 'cleanup.json', dict(daemon_exited=daemon.poll() is not None,
                                           returncode=daemon.returncode, socket_absent=not Path(socket).exists()))
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
    for pair in pairs:
        jobs = []
        for block in range(args.repeats):
            order = labels if (block + pair[0] // 2) % 2 == 0 else list(reversed(labels))
            jobs.extend((block, label) for label in order)
        schedules.append(jobs)
    plan = dict(scope='Oracle exploratory screen, no router verdict', runner_sha256=sha(__file__),
                benchmark_sha256=bench_sha, subjects={k: dict(path=str(v[0]), sha256=v[1]) for k, v in subjects.items()},
                library_sha256=LIBRARIES, pairs=pairs, schedules=schedules, iterations=args.iterations,
                warmup=20, kernel=platform.release())
    write(out / 'plan.json', plan)

    def worker(pair, jobs):
        records = []
        try:
            for block, label in jobs:
                require(not STOP.is_set(), 'another worker failed')
                dest = out / f'p{pair[0]}-{block}-{label}'
                records += run_subject(dest, label, subjects[label], bench, bench_sha, pair,
                                       block, args.iterations, 20)
                print(f'COMPLETE pair={pair} block={block} {label}', flush=True)
            return records
        except Exception:
            STOP.set()
            raise

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(pairs)) as pool:
            futures = [pool.submit(worker, pair, jobs) for pair, jobs in zip(pairs, schedules)]
            records = [record for future in futures for record in future.result()]
        write(out / 'results.json', dict(passed=True, records=records))
        write(out / 'hashes.json', {str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
        (out / 'COMPLETE').touch()
    except Exception as error:
        write(out / 'failure.json', dict(error=str(error)))
        (out / 'FAILED').touch()
        raise


if __name__ == '__main__':
    main()
