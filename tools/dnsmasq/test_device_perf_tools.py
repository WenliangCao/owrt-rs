#!/usr/bin/env python3
"""Calibrate measurement binaries without a dnsmasq or a router.

Run on Linux: test_device_perf_tools.py BIN_DIR OUTPUT_DIR
The fixed upstream, scheduler and semantic checks are tested over loopback.
These are tool calibration results, not dnsmasq performance observations.
"""
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    bins, output = map(Path, sys.argv[1:])
    output.mkdir()
    reports = []
    for mode, delay, disabled in [('udp', 1000, False), ('tcp', 1000, False),
                                  ('udp', 0, False), ('udp', 1000, True)]:
        label = f'{mode}-{delay}-{disabled}'
        folder = output / label
        folder.mkdir()
        port = free_port()
        server = subprocess.Popen([str(bins / 'm6a_upstream'), '--port', str(port),
            '--output', str(folder / 'upstream.json'), '--ready-file', str(folder / 'ready'),
            '--delay-us', str(delay), '--ttl', '120'] + (['--disabled'] if disabled else []))
        try:
            deadline = time.monotonic() + 3
            while not (folder / 'ready').exists():
                assert server.poll() is None and time.monotonic() < deadline
                time.sleep(.01)
            subprocess.run([str(bins / 'm6a_loadgen'), '--mode', mode,
                '--host', '127.0.0.1', '--port', str(port), '--clients', '8',
                '--duration-seconds', '3', '--warmup-seconds', '1', '--rate', '200',
                '--seed', '0x293001', '--name-prefix', 'tool.test', '--profile', 'miss',
                '--qtype', 'aaaa30', '--cache-names', '800', '--timeout-ms', '20',
                '--output', str(folder / 'load')], check=True)
        finally:
            server.send_signal(signal.SIGTERM)
            assert server.wait(timeout=3) == 0
        load = json.loads((folder / 'load.json').read_text())
        upstream = json.loads((folder / 'upstream.json').read_text())
        count = load['measurement']
        assert count['sent'] == count['scheduled'] == 600
        assert count['scheduled_skipped'] == count['wrong'] == count['transport_error'] == 0
        assert upstream['delay_queue_dropped'] == 0
        rows = list(struct.iter_unpack('<QQQHHBBBB', (folder / 'load.latencies.bin').read_bytes()))
        assert len(rows) == 600
        assert sum(row[4] == 1 for row in rows) == 420
        assert sum(row[4] == 28 for row in rows) == 180
        lag = dict(struct.iter_unpack('<QQ', (folder / 'load.send-lag.bin').read_bytes()))
        assert set(lag) == {row[0] for row in rows}
        if disabled:
            assert count['correct'] == 0 and count['timeout'] == 600
            assert all(row[5] == 1 for row in rows)
        else:
            assert count['correct'] == 600 and count['timeout'] == 0
            assert all(row[5] == 0 for row in rows)
            if delay:
                assert min(row[1] for row in rows) >= delay * 1000
            assert upstream['total']['requests'] == upstream['total']['replies'] == 800
        reports.append({'label': label, 'measurement': count,
                        'upstream': upstream, 'minimum_latency_ns': min(row[1] for row in rows)})
    # A delayed upstream must not serialize N queries into N * delay.
    folder = output / 'concurrent-delay'
    folder.mkdir()
    port = free_port()
    server = subprocess.Popen([str(bins / 'm6a_upstream'), '--port', str(port),
        '--output', str(folder / 'upstream.json'), '--ready-file', str(folder / 'ready'),
        '--delay-us', '10000', '--ttl', '120'])
    try:
        deadline = time.monotonic() + 3
        while not (folder / 'ready').exists():
            assert server.poll() is None and time.monotonic() < deadline
            time.sleep(.01)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            begin = time.monotonic_ns()
            for i in range(32):
                packet = struct.pack('!6H', i, 0x100, 1, 0, 0, 0) + b'\x01x\x04test\0' + struct.pack('!HH', 1, 1)
                sock.sendto(packet, ('127.0.0.1', port))
            ids = {struct.unpack('!H', sock.recv(4096)[:2])[0] for _ in range(32)}
            elapsed = time.monotonic_ns() - begin
            assert ids == set(range(32)) and 10_000_000 <= elapsed < 100_000_000
    finally:
        server.send_signal(signal.SIGTERM)
        assert server.wait(timeout=3) == 0
    reports.append({'label': 'concurrent-delay', 'replies': len(ids), 'elapsed_ns': elapsed})
    (output / 'summary.json').write_text(json.dumps({'passed': True, 'cases': reports}, indent=2) + '\n')
    print(json.dumps({'passed': True, 'cases': len(reports)}))


if __name__ == '__main__':
    main()
