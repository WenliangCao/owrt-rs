#!/usr/bin/env python3
"""Compare exact C and Rust SIGHUP hosts/cache behavior in a Linux netns.

Run via run_isolated.sh. All fixtures, packets and binaries stay in private/.
Configuration is identical; -d keeps both servers foreground without a host
pid file. This gate covers hosts and forward-cache reload, not DHCP scripts,
resolver polling, ubus or procd. The C daemon generates expected results.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, name, query, read_name, rr, semantics


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(.05)
        self.port = self.socket.getsockname()[1]
        self.counts = {}
        self.errors = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                host, end = read_name(packet, 12)
                kind, cls = struct.unpack_from('!HH', packet, end)
                if kind != 1 or cls != 1:
                    raise AssertionError('fixture only accepts IN A upstream queries')
                self.counts[host] = self.counts.get(host, 0) + 1
                negative = host == 'negative.test'
                response = packet[:2] + struct.pack('!5H', 0x8183 if negative else 0x8180,
                                                    1, 0 if negative else 1, 0, 0)
                response += packet[12:end + 4]
                if not negative:
                    response += rr(1, bytes([192, 0, 2, 7]), 120)
                self.socket.sendto(response, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        if self.thread.is_alive():
            raise AssertionError('upstream thread survived shutdown')
        if self.errors:
            raise AssertionError(self.errors)


def exchange(port, host, kind=1, tcp=False, ident=0x2950):
    packet = query(host, kind, ident)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect(('127.0.0.1', port))
        if tcp:
            client.sendall(struct.pack('!H', len(packet)) + packet)
            answer = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        else:
            client.send(packet)
            answer = client.recv(65535)
    parsed = semantics(answer)
    if parsed['id'] != ident:
        raise AssertionError('client transaction ID changed')
    return answer.hex(), parsed


def await_address(process, port, host, address):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('daemon exited during readiness/reload')
        try:
            _, result = exchange(port, host)
            if any(record['data'] == address for record in result['records']):
                return
        except (OSError, ConnectionError):
            pass
        time.sleep(.025)
    raise AssertionError(f'reload did not publish {host} within bounded wait')


def run(binary, output, config_file, hosts_file, port, upstream, restart_missing=False):
    rows = []
    trace = {'rows': rows, 'status': 'failed'}
    start_counts = dict(upstream.counts)
    with (output / 'stderr.log').open('w') as log:
        process = subprocess.Popen([str(binary), '-C', str(config_file), '-d'],
                                   stdout=log, stderr=log)
        try:
            await_address(process, port, 'fixed.test', '192.0.2.90')
            def record(label, host, kind=1, tcp=False, cache_age=None):
                wire, parsed = exchange(port, host, kind, tcp, 0x2960 + len(rows))
                counts = {key: value - start_counts.get(key, 0)
                          for key, value in upstream.counts.items()
                          if value != start_counts.get(key, 0)}
                row = {'case': label, 'wire': wire, 'reply': parsed,
                       'upstream': counts, 'transport': 'tcp' if tcp else 'udp'}
                if cache_age is not None:
                    row['cache_age'] = time.monotonic() - cache_age
                rows.append(row)
            if restart_missing:
                record('missing-at-start-fixed', 'fixed.test', tcp=True)
                record('missing-at-start-absent', 'live.test')
            else:
                record('hosts-before-udp', 'live.test')
                record('hosts-before-tcp', 'live.test', tcp=True)
                record('hosts-before-aaaa', 'live.test', kind=28)
                first = time.monotonic()
                record('cache-fill', 'cached.test')
                record('cache-hit', 'cached.test', cache_age=first)
                record('negative-fill', 'negative.test')
                record('negative-hit', 'negative.test')
                hosts_file.write_text('192.0.2.12 live.test\n2001:db8::12 live.test\n')
                original = config_file.read_text()
                config_file.write_text(original.replace('192.0.2.90', '192.0.2.99'))
                process.send_signal(signal.SIGHUP)
                await_address(process, port, 'live.test', '192.0.2.12')
                record('hosts-after-udp', 'live.test')
                record('hosts-after-tcp', 'live.test', tcp=True)
                record('hosts-after-aaaa', 'live.test', kind=28)
                record('configuration-not-reread', 'fixed.test', tcp=True)
                first = time.monotonic()
                record('cache-flushed', 'cached.test')
                record('cache-hit-after-reload', 'cached.test', cache_age=first)
                record('negative-flushed', 'negative.test')
                record('negative-hit-after-reload', 'negative.test')
                hosts_file.unlink()
                process.send_signal(signal.SIGHUP)
                await_address(process, port, 'live.test', '192.0.2.7')
                record('missing-file-old-name-removed', 'live.test')
                record('missing-file-fixed-record-kept', 'fixed.test', tcp=True)
                hosts_file.write_text('192.0.2.14 live.test\n')
                for _ in range(20):
                    process.send_signal(signal.SIGHUP)
                await_address(process, port, 'live.test', '192.0.2.14')
                record('recreated-file', 'live.test')
                record('recreated-file-tcp', 'live.test', tcp=True)
                config_file.write_text(original)
            # -d makes C handle TCP synchronously. Partial-frame signal cleanup
            # belongs to the separate dns_signal_smoke gate; compare reload
            # and normal shutdown here with identical foreground arguments.
            process.send_signal(signal.SIGTERM)
            trace['exit'] = process.wait(5)
            if trace['exit'] != 0:
                raise AssertionError('daemon did not shut down successfully')
            trace['status'] = 'passed'
        except Exception as error:
            trace['error'] = repr(error)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(5)
            (output / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
    return trace


def canonical(trace):
    result = copy.deepcopy(trace)
    for row in result['rows']:
        row.pop('wire')
        if 'cache_age' in row:
            # Both daemons use whole-second expiry. Preserve and verify actual
            # TTL; allow only elapsed time rounded up to the next second.
            age = row.pop('cache_age')
            if age > 2:
                raise AssertionError('cache-hit timing window exceeded; retain failed run')
            for record in row['reply']['records']:
                if not 120 - math.ceil(age) <= record['ttl'] <= 120:
                    raise AssertionError('cache TTL outside measured elapsed window')
                record['ttl'] = {'initial': 120, 'elapsed_window_seconds': 2}
    return result


def compare(expected, actual):
    if expected['status'] != 'passed' or actual['status'] != 'passed':
        return False
    return canonical(expected) == canonical(actual)


def calibrate(expected):
    if not compare(expected, copy.deepcopy(expected)):
        raise AssertionError('equal reference rejected')
    mutations = []
    for key, value in [('id', 0), ('flags', 0)]:
        changed = copy.deepcopy(expected)
        changed['rows'][0]['reply'][key] = value
        mutations.append(changed)
    for key, value in [('data', '192.0.2.222'), ('ttl', 0)]:
        changed = copy.deepcopy(expected)
        changed['rows'][0]['reply']['records'][0][key] = value
        mutations.append(changed)
    changed = copy.deepcopy(expected)
    changed['rows'].pop()
    mutations.append(changed)
    changed = copy.deepcopy(expected)
    changed['rows'][0]['upstream']['unexpected.test'] = 1
    mutations.append(changed)
    if any(compare(expected, changed) for changed in mutations):
        raise AssertionError('controlled behavioral mismatch was not counted')
    return {'equal_passed': 1, 'injected_failures_detected': len(mutations)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('run via run_isolated.sh in a private Linux network namespace')
    output = args.output.resolve()
    if 'private' not in output.parts:
        parser.error('evidence must be below ignored private/')
    output.mkdir(parents=True, exist_ok=False)
    config_file, hosts_file = output / 'dnsmasq.conf', output / 'hosts'
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    upstream = Upstream()
    config = f'''no-resolv
no-hosts
listen-address=127.0.0.1
port={port}
local-ttl=37
cache-size=16
neg-ttl=30
addn-hosts={hosts_file}
host-record=fixed.test,192.0.2.90
server=127.0.0.1#{upstream.port}
'''
    summary = {'status': 'failed', 'checks_passed': 0, 'checks_failed': 0,
               'identity': {key: digest(getattr(args, key).resolve()) for key in ('reference', 'rust')},
               'calibration': None}
    traces = {}
    try:
        for label in ('reference', 'rust'):
            config_file.write_text(config)
            hosts_file.write_text('192.0.2.11 live.test\n2001:db8::11 live.test\n')
            run_dir = output / label
            run_dir.mkdir()
            traces[label] = run(getattr(args, label).resolve(), run_dir, config_file,
                                hosts_file, port, upstream)
            hosts_file.unlink()
            missing_dir = output / (label + '-missing')
            missing_dir.mkdir()
            traces[label + '-missing'] = run(getattr(args, label).resolve(), missing_dir,
                                              config_file, hosts_file, port, upstream, True)
            if label == 'reference':
                summary['calibration'] = calibrate(traces[label])
        for suffix in ('', '-missing'):
            expected, actual = traces['reference' + suffix], traces['rust' + suffix]
            if not compare(expected, actual):
                summary['checks_failed'] += 1
                raise AssertionError('C/Rust trace mismatch: ' + (suffix or 'reload'))
            summary['checks_passed'] += len(expected['rows']) + 1  # checked shutdown
        summary['status'] = 'passed'
    except Exception as error:
        summary['error'] = repr(error)
        summary['checks_failed'] = max(1, summary['checks_failed'])
    finally:
        try:
            upstream.close()
        except Exception as error:
            summary['status'] = 'failed'
            summary['error'] = repr(error)
            summary['checks_failed'] += 1
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
