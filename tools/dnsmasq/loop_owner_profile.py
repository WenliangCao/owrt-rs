#!/usr/bin/env python3
"""Oracle-only excluded perf diagnostic of exact SDK ELF owner hot paths.

Runs inside a fresh loopback-only netns. Defaults preserve the original DNS
workload. Explicit rate=0 is a separate saturation diagnostic. Instrumented
elapsed time is never an acceptance measurement.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import re
import resource
import shutil
import signal
import socket
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def validate_load_counts(full, warm, duration, rate):
    assert not full['interrupted'] and not full['output_failed']
    for phase, seconds in (('warmup', warm), ('measurement', duration)):
        part = full[phase]
        assert part['scheduled'] == part['sent'] == part['correct']
        if rate or seconds == 0:
            assert part['correct'] == seconds * rate
        else:
            assert part['correct'] > 0, 'unpaced workload completed no queries'
        assert not any(part[key] for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))


def verify_mapped_files(mapping, expected_images):
    elf_files, data_files = {}, {}
    for line in mapping.splitlines():
        fields = line.split(maxsplit=5)
        permissions = fields[1]
        path = fields[5] if len(fields) == 6 else ''
        if not path.startswith('/'):
            assert 'x' not in permissions or path == '[vdso]', ('unexpected executable mapping', line)
            continue
        data = Path(path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if data.startswith(b'\x7fELF'):
            elf_files[path] = digest
        else:
            assert 'x' not in permissions, ('unexpected executable data mapping', path)
            row = data_files.setdefault(path, {'sha256': digest, 'bytes': len(data), 'mappings': []})
            row['mappings'].append({'permissions': permissions, 'offset': fields[2]})
    assert elf_files == expected_images, (elf_files, expected_images)
    return {'elf_files': elf_files, 'non_executable_data_files': data_files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--stock-image-root', type=Path)
    parser.add_argument('--c-symbol-receipt', type=Path)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=('udp', 'tcp'), required=True)
    parser.add_argument('--profile', choices=('hit', 'miss', 'mixed'), required=True)
    parser.add_argument('--observer', choices=('stat', 'sample', 'none'), default='sample',
                        help='stat-only totals or separate self-sampling; never concurrent')
    parser.add_argument('--rate', type=int, default=200,
                        help='queries/second; zero is a separately planned unpaced UDP diagnostic')
    parser.add_argument('--loadgen-sha256', default='b5ac83a15590818079bb22d59be663265a38bc41452e7ae29a85624adda293bd')
    parser.add_argument('--sample-event', choices=('instructions:u', 'cycles:u'), default='instructions:u')
    parser.add_argument('--strace', action='store_true', help='syscall counts instead of PMU capture')
    args = parser.parse_args()
    assert args.rate >= 0 and (args.rate != 0 or args.mode == 'udp')
    assert re.fullmatch('[0-9a-f]{64}', args.loadgen_sha256)
    observer = 'strace' if args.strace else args.observer
    assert bool(args.build) != bool(args.stock_image_root), 'select one exact implementation'
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    image_files = {}
    if args.stock_image_root:
        from dns_udp_refusal_diff import TARGET_FILES, C_HASH
        image_root = args.stock_image_root.resolve()
        for name, digest in TARGET_FILES.items():
            assert sha(image_root / name) == digest, name
        artifact = out / 'dnsmasq-c'
        shutil.copy2(image_root / 'usr/sbin/dnsmasq', artifact)
        expected = C_HASH
        assert args.c_symbol_receipt is not None
        receipt = json.loads(args.c_symbol_receipt.read_text())
        assert receipt['stripped_sha256'] == expected and receipt['strip_reproduces_exact_image']
        companion = Path(receipt['companion_path'])
        assert sha(companion) == receipt['companion_sha256']
        shutil.copy2(companion, out / 'dnsmasq-c-symbols')
        shutil.copy2(args.c_symbol_receipt, out / 'c-symbol-receipt.json')
        build = {'source_commit': None, 'reference': 'exact image C dnsmasq 2.93',
                 'artifacts': [{'path': artifact.name, 'sha256': expected, 'bytes': artifact.stat().st_size}],
                 'symbol_receipt_sha256': sha(args.c_symbol_receipt)}
        save(out / 'build.json', build)
        launch = [image_root / 'lib/libc.so', '--library-path',
                  f'{image_root}/lib:{image_root}/usr/lib', artifact]
        image_files = {str(image_root / name): digest for name, digest in TARGET_FILES.items()
                       if name.startswith('lib/')}
        process_expected = TARGET_FILES['lib/libc.so']
    else:
        for name in ('dnsmasq-rs', 'link.map', 'build.json'):
            shutil.copy2(args.build / name, out / name)
        artifact = out / 'dnsmasq-rs'
        build = json.loads((out / 'build.json').read_text())
        expected = next(item['sha256'] for item in build['artifacts'] if item['path'] == artifact.name)
        assert sha(out / 'link.map') == build['link_map']['sha256']
        launch = [artifact]
        process_expected = expected
    artifact.chmod(0o755)
    assert sha(artifact) == expected
    image_files[str(artifact)] = expected
    # Alternative diagnostic tools must be explicitly bound before a run.
    assert sha(args.tools / 'm6a_loadgen') == args.loadgen_sha256
    assert sha(args.tools / 'm6a_upstream') == '01c25e6a2f48a5c933555334c4d1f58489c083d19fd5f1ca8542b1a93b597b68'
    save(out / 'profile-scope.json', {'scope': __doc__, 'mode': args.mode,
         'profile': args.profile, 'elf_sha256': expected,
         'observer': observer, 'rate': args.rate, 'loadgen_sha256': args.loadgen_sha256,
         'clock_ticks_per_second': os.sysconf('SC_CLK_TCK'),
         'source_commit': build.get('source_commit'),
         'artifact_file': artifact.name, 'mapped_images': image_files,
         'process_tree': 'root and every inherited fork; no --no-inherit',
         'counter_window': '5s warmup + 20s measurement at the recorded rate, then fixed 1s drain; prewarm excluded',
         'sample_event': args.sample_event, 'sample_period': 10000,
         'deployed_baseline': expected == '8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7'})
    (out / 'config').write_text(
        'no-hosts\nno-resolv\nno-poll\nuser=root\ngroup=root\ninterface=lo\n'
        'bind-interfaces\nlisten-address=127.0.0.1\nport=15353\ncache-size=1000\n'
        'edns-packet-max=1232\ndns-forward-max=150\nserver=127.0.0.1#15354\n'
        'host-record=ready.device-perf.test,192.0.2.1\n'
        f'pid-file={out}/pid\nlog-facility={out}/daemon.log\n')
    children = []
    channels = []
    controls = []

    def start(argv, label):
        with (out / f'{label}.stdout').open('wb') as stdout, (out / f'{label}.stderr').open('wb') as stderr:
            environment = dict(os.environ)
            environment.pop('LD_PRELOAD', None)
            environment.pop('LD_LIBRARY_PATH', None)
            child = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr, env=environment)
        children.append(child)
        save(out / f'{label}.command.json', list(map(str, argv)))
        return child

    def finish(child, sig=None):
        if child.poll() is None and sig is not None:
            child.send_signal(sig)
        status = child.wait(timeout=10)
        children.remove(child)
        return status

    def instrument(argv, label):
        control, ack = out / f'{label}.control', out / f'{label}.ack'
        os.mkfifo(control)
        os.mkfifo(ack)
        write_fd = os.open(control, os.O_RDWR)
        read_fd = os.open(ack, os.O_RDWR | os.O_NONBLOCK)
        channels.append((write_fd, read_fd))
        child = start([*argv, '--delay=-1', '--control', f'fifo:{control},{ack}'], label)
        return child, write_fd, read_fd

    def control(channel, command):
        child, write_fd, read_fd = channel
        sent = time.monotonic_ns()
        os.write(write_fd, (command + '\n').encode())
        assert select.select([read_fd], [], [], 5)[0], 'missing perf control ACK'
        ack = os.read(read_fd, 64)
        assert ack.rstrip(b'\n\0') == b'ack', ack
        assert child.poll() is None
        controls.append({'perf_pid': child.pid, 'command': command,
                         'sent_ns': sent, 'acknowledged_ns': time.monotonic_ns(),
                         'ack_hex': ack.hex()})

    def load(mode, profile, duration, warm, label, rate=200):
        usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        started = time.monotonic_ns()
        child = start(['taskset', '-c', '3', args.tools / 'm6a_loadgen', '--mode', mode,
            '--host', '127.0.0.1', '--port', '15353', '--clients', '8' if mode == 'tcp' else '32',
            '--duration-seconds', duration, '--warmup-seconds', warm, '--rate', rate,
            '--seed', '0x293001', '--name-prefix', 'm6a.test', '--profile', profile,
            '--qtype', 'aaaa30', '--cache-names', '800', '--timeout-ms', '1000',
            '--output', out / label], label)
        status = child.wait(timeout=duration + warm + 10)
        children.remove(child)
        # This synchronous wait is the only child reaped during load(). Other
        # owned processes remain alive. Retain sender cost to expose a client
        # CPU ceiling in an unpaced throughput comparison.
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        save(out / f'{label}-cpu.json', {
            'scope': 'whole loadgen process including startup/warmup/drain',
            'elapsed_ns': time.monotonic_ns() - started,
            'user_seconds': usage_after.ru_utime - usage_before.ru_utime,
            'system_seconds': usage_after.ru_stime - usage_before.ru_stime,
            'returncode': status})
        assert status == 0
        full = json.loads((out / f'{label}.json').read_text())
        validate_load_counts(full, warm, duration, rate)
        return full

    try:
        upstream = start(['taskset', '-c', '1', args.tools / 'm6a_upstream', '--port', '15354',
            '--delay-us', '1000', '--ttl', '120', '--output', out / 'upstream.json',
            '--ready-file', out / 'upstream.ready'], 'upstream')
        deadline = time.monotonic() + 5
        while not (out / 'upstream.ready').exists():
            assert upstream.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        daemon = start(['nice', '-n', '10', 'taskset', '-c', '2', *launch, '--keep-in-foreground',
                        '--conf-file=' + str(out / 'config')], 'daemon')
        query = struct.pack('!6H', 0x2930, 0x100, 1, 0, 0, 0) + b'\x05ready\x0bdevice-perf\x04test\0' + struct.pack('!HH', 1, 1)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(.1)
                    client.sendto(query, ('127.0.0.1', 15353))
                    answer = client.recv(1232)
                assert answer[-4:] == bytes([192, 0, 2, 1])
                break
            except TimeoutError:
                assert daemon.poll() is None and time.monotonic() < deadline
        proc = Path('/proc') / str(daemon.pid)
        identity = {'pid': daemon.pid, 'exe': os.readlink(proc / 'exe'),
                    'sha256': sha(proc / 'exe'), 'maps': (proc / 'maps').read_text(),
                    'stat': (proc / 'stat').read_text()}
        save(out / 'process-identity.json', identity)
        assert identity['sha256'] == process_expected and os.sched_getaffinity(daemon.pid) == {2}
        identity['mapped_file_identity'] = verify_mapped_files(identity['maps'], image_files)
        identity['mapped_images'] = image_files
        save(out / 'process-identity.json', identity)
        if args.profile != 'miss':
            load('udp', 'hit', 5, 0, 'prewarm')
        child_path = proc / 'task' / str(daemon.pid) / 'children'
        assert not child_path.read_text().strip(), 'prewarm must leave no unobserved children'
        instruments = []
        if observer == 'strace':
            tracer = start(['strace', '-f', '-v', '-I2', '-yy', '-ttt', '-s', '0', '-e',
                'trace=all', '-p', daemon.pid,
                '-o', out / 'syscalls.txt'], 'strace')
            deadline = time.monotonic() + 5
            while not re.search(r'TracerPid:\s+[1-9]', (proc / 'status').read_text()):
                assert tracer.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
        elif observer != 'none':
            if observer == 'sample':
                instruments.append(instrument(['perf', 'record', '-e', args.sample_event, '-c', '10000', '-p', daemon.pid,
                                   '-o', out / 'perf.data'], 'perf-record'))
            else:
                instruments.append(instrument(['perf', 'stat', '-vv', '-x,', '-e',
                                   '{instructions:u,instructions:k,cycles:u,cycles:k}', '-p', daemon.pid,
                                   '-o', out / 'perf-stat.csv'], 'perf-stat'))
            for channel in instruments:
                control(channel, 'enable')
        (out / 'cpu-before.stat').write_text((proc / 'stat').read_text())
        load_start = time.monotonic_ns()
        full_counts = load(args.mode, args.profile, 20, 5, 'client', args.rate)
        load_end = time.monotonic_ns()
        drain_started = time.monotonic_ns()
        time.sleep(1)
        drain_ended = time.monotonic_ns()
        remaining_children = child_path.read_text().strip().split()
        save(out / 'tree-tail.json', {'root_pid': daemon.pid,
             'root_starttime_ticks': identity['stat'].rsplit(')', 1)[1].split()[19],
             'drain_started_ns': drain_started, 'drain_ended_ns': drain_ended,
             'remaining_children': remaining_children, 'complete': not remaining_children})
        assert not remaining_children, 'fixed post-load drain ended with live children; retain incomplete attempt'
        # Waited-child ticks must already be incorporated in this endpoint.
        (out / 'cpu-after.stat').write_text((proc / 'stat').read_text())
        if observer != 'strace':
            for channel in instruments:
                control(channel, 'disable')
            save(out / 'perf-controls.json', {'controls': controls,
                 'load_start_ns': load_start, 'load_end_ns': load_end})
        # Stop observing at the shared grace boundary, before artifact hashing
        # or map verification adds implementation-size-dependent work.
        statuses = ([finish(tracer, signal.SIGINT)] if observer == 'strace' else
                    [finish(channel[0], signal.SIGINT) for channel in instruments])
        assert all(status in (0, 130, -signal.SIGINT) for status in statuses)
        maps_after = (proc / 'maps').read_text()
        (out / 'maps-after').write_text(maps_after)
        mapped_after = verify_mapped_files(maps_after, image_files)
        save(out / 'mapped-files-after.json', mapped_after)
        assert mapped_after == identity['mapped_file_identity'], 'mapped file identities changed during capture'
        assert sha(proc / 'exe') == process_expected
        assert all(sha(path) == digest for path, digest in image_files.items())
        assert re.search(r'TracerPid:\s+0\b', (proc / 'status').read_text())
        assert finish(daemon, signal.SIGTERM) == 0
        assert finish(upstream, signal.SIGTERM) == 0
        exports = [] if observer != 'sample' else [(['perf', 'script', '-i', out / 'perf.data', '--hide-call-graph',
                            '-F', 'pid,tid,misc,period,event,ip,sym,dso'], 'samples.txt'),
                           (['perf', 'report', '-i', out / 'perf.data', '--stdio', '--no-children',
                            '--sort', 'dso,symbol', '--show-nr-samples', '--show-total-period',
                            '--percent-limit', '0', '-g', 'none', '--field-separator', ';',
                            '--no-demangle'], 'self.txt'),
                           (['perf', 'script', '-i', out / 'perf.data', '--show-task-events',
                             '--show-mmap-events', '--show-lost-events', '--ns',
                             '-F', 'pid,tid,misc,time,event,ip,sym,dso'], 'task-events.txt')]
        for argv, name in exports:
            with (out / name).open('wb') as stdout:
                subprocess.run(list(map(str, argv)), stdout=stdout, check=True)
        save(out / 'complete.json', {'valid_count_profile': True, 'measurement': full_counts['measurement'],
             'completed_operations': full_counts['warmup']['correct'] + full_counts['measurement']['correct'],
             'rate': args.rate, 'observer': observer, 'tree_tail_complete': True,
             'perf_statuses': statuses, 'timing_eligible': False})
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for write_fd, read_fd in channels:
            os.close(write_fd)
            os.close(read_fd)


if __name__ == '__main__':
    main()
