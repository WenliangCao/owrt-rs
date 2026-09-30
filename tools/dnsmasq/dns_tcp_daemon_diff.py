#!/usr/bin/env python3
"""Exact C/Rust TCP daemon framing, refusal and forwarding differential.

Requires run_isolated.sh. A fixed corpus exercises frame event order, the 100
query limit and real TCP upstream reuse. Cache is disabled equally; this is not
full cache, resolver-reload or OpenWrt service equivalence. All raw evidence is
written below private/ and C supplies the expected output.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_service_probe import exact_read, query, read_name, rr, semantics


def frame(packet):
    return struct.pack('!H', len(packet)) + packet


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.listen()
        self.socket.settimeout(.05)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.events = []
        self.failures = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            self.events.append('open')
            try:
                with client:
                    client.settimeout(.1)
                    while not self.stop.is_set():
                        try:
                            size = exact_read(client, 2)
                        except socket.timeout:
                            continue
                        except ConnectionError:
                            break
                        packet = exact_read(client, struct.unpack('!H', size)[0])
                        self.events.append(packet.hex())
                        _, end = read_name(packet, 12)
                        body = packet[12:end + 4]
                        answer = packet[:2] + struct.pack('!5H', 0x81a0, 1, 1, 0, 0)
                        answer += body + rr(1, bytes([198, 51, 100, 7]), 120)
                        client.sendall(frame(answer))
            except Exception as error:
                self.failures.append(repr(error))
            self.events.append('close')

    def close(self):
        self.stop.set()
        self.thread.join(2)
        self.socket.close()
        assert not self.thread.is_alive() and not self.failures, self.failures


def cases():
    good = query('local.test', ident=0x2940)
    ignored_reply = bytearray(good)
    ignored_reply[2] |= 0x80
    values = [
        ('local', [frame(good)], True),
        ('fragmented', [frame(good)[:1], frame(good)[1:7], frame(good)[7:]], True),
        ('ignore-short-and-qr', [frame(b'bad') + frame(ignored_reply) + frame(good)], True),
        ('answer-before-zero', [frame(good) + b'\0\0'], False),
        ('answer-before-oversize', [frame(good) + b'\x10\0'], False),
        ('answer-before-truncated-prefix', [frame(good) + b'\0'], True),
        ('hundred-query-close', [b''.join(frame(query('local.test', ident=0x3000+i)) for i in range(100))], False),
        ('ignored-frames-not-counted', [frame(b'bad')*105 + frame(good)*2], True),
        ('unowned-refused', [frame(query('unowned.test', ident=0x2950))], True),
    ]
    opt = b'\0\0\x29\x10\0\0\0\x80\0\0\0'
    packet = bytearray(query('unowned.test', ident=0x2951))
    packet[11] = 1
    values.append(('unowned-refused-edns', [frame(packet + opt)], True))
    for opcode in (1, 2, 5):
        packet = bytearray(good)
        packet[2] |= opcode << 3
        values.append((f'opcode-{opcode}', [frame(packet)], True))
    packet = bytearray(good)
    packet[5] = 2
    packet += good[12:]
    values.append(('two-questions', [frame(packet)], True))
    values.append(('tcp-upstream-reuse', [frame(query('forward.test', ident=0x2960)) +
                                        frame(query('forward.test', ident=0x2961))], True))
    return values


def run(binary, config, port, output, upstream):
    result = {'status': 'failed', 'rows': []}
    with (output / 'stderr.log').open('w') as log:
        process = subprocess.Popen([str(binary), '-C', str(config), '-d'], stdout=log, stderr=log)
        try:
            until = time.monotonic() + 5
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                try:
                    with socket.create_connection(('127.0.0.1', port), .1):
                        break
                except OSError:
                    if time.monotonic() >= until:
                        raise AssertionError('readiness timeout')
                    time.sleep(.02)
            for label, chunks, half_close in cases():
                first = len(upstream.events)
                packets = []
                with socket.create_connection(('127.0.0.1', port), 2) as client:
                    client.settimeout(2)
                    for chunk in chunks:
                        client.sendall(chunk)
                        if len(chunks) > 1:
                            time.sleep(.01)
                    if half_close:
                        client.shutdown(socket.SHUT_WR)
                    while True:
                        prefix = client.recv(2)
                        if not prefix:
                            break
                        prefix += exact_read(client, 2-len(prefix))
                        packets.append(exact_read(client, struct.unpack('!H', prefix)[0]))
                if label == 'tcp-upstream-reuse':
                    until = time.monotonic() + 2
                    while upstream.events[first:].count('close') < 1 and time.monotonic() < until:
                        time.sleep(.01)
                    assert upstream.events[first:].count('close') == 1, 'upstream connection leaked'
                result['rows'].append({'case': label, 'requests': [bytes(chunk).hex() for chunk in chunks],
                                       'packets': [packet.hex() for packet in packets],
                                       'replies': [semantics(packet) for packet in packets],
                                       'upstream': upstream.events[first:]})
            process.send_signal(signal.SIGTERM)
            result['exit'] = process.wait(5)
            assert result['exit'] == 0
            result['status'] = 'passed'
        except Exception as error:
            result['error'] = repr(error)
            raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(5)
            (output / 'trace.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def comparable(trace):
    value = copy.deepcopy(trace)
    for row in value['rows']:
        row.pop('packets')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('private Linux network namespace required')
    output = args.output.resolve()
    if 'private' not in output.parts:
        parser.error('output must be under private/')
    output.mkdir(parents=True, exist_ok=False)
    upstream = Upstream()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config = output / 'dnsmasq.conf'
    config.write_text(f'''no-hosts
no-resolv
listen-address=127.0.0.1
port={port}
cache-size=0
host-record=local.test,192.0.2.1
server=/forward.test/127.0.0.1#{upstream.port}
''')
    summary = {'status': 'failed', 'checks_passed': 0, 'checks_failed': 0,
               'identity': {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest()
                            for name in ('reference', 'rust')}}
    try:
        traces = {}
        for name in ('reference', 'rust'):
            work = output / name
            work.mkdir()
            traces[name] = run(getattr(args, name).resolve(), config, port, work, upstream)
        expected, actual = comparable(traces['reference']), comparable(traces['rust'])
        assert comparable(traces['reference']) == expected
        mutations = []
        for key, value in [('flags', 0), ('id', 0)]:
            mutation = copy.deepcopy(expected)
            mutation['rows'][0]['replies'][0][key] = value
            mutations.append(mutation)
        mutation = copy.deepcopy(expected)
        mutation['rows'][0]['replies'].clear()
        mutations.append(mutation)
        mutation = copy.deepcopy(expected)
        mutation['rows'][-1]['upstream'].append('open')
        mutations.append(mutation)
        assert all(changed != expected for changed in mutations)
        summary['calibration'] = {'equal_passed': 1, 'injected_failures_detected': len(mutations)}
        failures = [left['case'] for left, right in zip(expected['rows'], actual['rows']) if left != right]
        assert len(expected['rows']) == len(actual['rows']) == 15
        summary['mismatches'] = failures
        summary['checks_failed'] = len(failures)
        summary['checks_passed'] = 15 - len(failures)
        summary['reply_count'] = sum(len(row['replies']) for row in actual['rows'])
        summary['status'] = 'passed' if not failures else 'failed'
    except Exception as error:
        summary['error'] = repr(error)
        summary['checks_failed'] = max(1, summary['checks_failed'])
    finally:
        upstream.close()
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return int(summary['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
