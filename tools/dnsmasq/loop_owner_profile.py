#!/usr/bin/env python3
"""Oracle-only excluded perf diagnostic of exact SDK ELF owner hot paths.

Runs inside a fresh loopback-only netns. It preserves frozen DNS workloads,
but perf-instrumented elapsed time is never an acceptance measurement.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import re
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=('udp', 'tcp'), required=True)
    parser.add_argument('--profile', choices=('hit', 'miss', 'mixed'), required=True)
    parser.add_argument('--strace', action='store_true', help='syscall counts instead of PMU capture')
    args = parser.parse_args()
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    out = args.out.resolve()
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    for name in ('dnsmasq-rs', 'link.map', 'build.json'):
        shutil.copy2(args.build / name, out / name)
    (out / 'dnsmasq-rs').chmod(0o755)
    build = json.loads((out / 'build.json').read_text())
    expected = next(item['sha256'] for item in build['artifacts'] if item['path'] == 'dnsmasq-rs')
    assert sha(out / 'dnsmasq-rs') == expected
    assert sha(out / 'link.map') == build['link_map']['sha256']
    save(out / 'profile-scope.json', {'scope': __doc__, 'mode': args.mode,
         'profile': args.profile, 'elf_sha256': expected,
         'observer': 'strace' if args.strace else 'perf',
         'source_commit': build.get('source_commit'),
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
            child = subprocess.Popen(list(map(str, argv)), stdout=stdout, stderr=stderr)
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

    def load(mode, profile, duration, warm, label):
        child = start(['taskset', '-c', '3', args.tools / 'm6a_loadgen', '--mode', mode,
            '--host', '127.0.0.1', '--port', '15353', '--clients', '8' if mode == 'tcp' else '32',
            '--duration-seconds', duration, '--warmup-seconds', warm, '--rate', '200',
            '--seed', '0x293001', '--name-prefix', 'm6a.test', '--profile', profile,
            '--qtype', 'aaaa30', '--cache-names', '800', '--timeout-ms', '1000',
            '--output', out / label], label)
        status = child.wait(timeout=duration + warm + 10)
        children.remove(child)
        assert status == 0
        counts = json.loads((out / f'{label}.json').read_text())['measurement']
        assert counts['correct'] == duration * 200 and counts['sent'] == duration * 200
        assert not any(counts[key] for key in ('timeout', 'wrong', 'transport_error', 'scheduled_skipped'))
        return counts

    try:
        upstream = start(['taskset', '-c', '1', args.tools / 'm6a_upstream', '--port', '15354',
            '--delay-us', '1000', '--ttl', '120', '--output', out / 'upstream.json',
            '--ready-file', out / 'upstream.ready'], 'upstream')
        deadline = time.monotonic() + 5
        while not (out / 'upstream.ready').exists():
            assert upstream.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        daemon = start(['taskset', '-c', '2', out / 'dnsmasq-rs', '--keep-in-foreground',
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
        assert identity['sha256'] == expected and os.sched_getaffinity(daemon.pid) == {2}
        save(out / 'process-identity.json', identity)
        if args.profile != 'miss':
            load('udp', 'hit', 5, 0, 'prewarm')
        if args.strace:
            tracer = start(['strace', '-I2', '-yy', '-ttt', '-s', '0', '-e',
                'trace=network,ppoll,close,fcntl,ioctl', '-p', daemon.pid,
                '-o', out / 'syscalls.txt'], 'strace')
            deadline = time.monotonic() + 5
            while not re.search(r'TracerPid:\s+[1-9]', (proc / 'status').read_text()):
                assert tracer.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
        else:
            record = instrument(['perf', 'record', '-e', 'instructions', '-c', '10000', '-p', daemon.pid,
                                 '-o', out / 'perf.data'], 'perf-record')
            stat = instrument(['perf', 'stat', '-x,', '-e', 'instructions,cycles', '-p', daemon.pid,
                               '-o', out / 'perf-stat.csv'], 'perf-stat')
            for channel in (record, stat):
                control(channel, 'enable')
        load_start = time.monotonic_ns()
        counts = load(args.mode, args.profile, 20, 5, 'client')
        load_end = time.monotonic_ns()
        if not args.strace:
            for channel in (record, stat):
                control(channel, 'disable')
            save(out / 'perf-controls.json', {'controls': controls,
                 'load_start_ns': load_start, 'load_end_ns': load_end})
        (out / 'maps-after').write_text((proc / 'maps').read_text())
        assert sha(proc / 'exe') == expected
        statuses = ([finish(tracer, signal.SIGINT)] if args.strace else
                    [finish(channel[0], signal.SIGINT) for channel in (record, stat)])
        assert all(status in (0, 130, -signal.SIGINT) for status in statuses)
        assert re.search(r'TracerPid:\s+0\b', (proc / 'status').read_text())
        assert finish(daemon, signal.SIGTERM) == 0
        assert finish(upstream, signal.SIGTERM) == 0
        exports = [] if args.strace else [(['perf', 'script', '-i', out / 'perf.data', '--hide-call-graph',
                            '-F', 'pid,tid,misc,period,event,ip,sym,dso'], 'samples.txt'),
                           (['perf', 'report', '-i', out / 'perf.data', '--stdio', '--no-children',
                            '--sort', 'dso,symbol', '--show-nr-samples', '--show-total-period',
                            '--percent-limit', '0', '-g', 'none', '--field-separator', ';',
                            '--no-demangle'], 'self.txt')]
        for argv, name in exports:
            with (out / name).open('wb') as stdout:
                subprocess.run(list(map(str, argv)), stdout=stdout, check=True)
        save(out / 'complete.json', {'valid_count_profile': True, 'measurement': counts,
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
