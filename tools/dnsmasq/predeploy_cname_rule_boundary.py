#!/usr/bin/env python3
"""Exact-image cached CNAME -> literal TCP envelope boundary; isolated only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

from m2_rootfs import image_elf_command
from predeploy_audit_dns import exact_read, name, semantics


def digest(data):
    return hashlib.sha256(data).hexdigest()


def request(host, kind, ident):
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + name(host) + struct.pack('!HH', kind, 1)


def exchange(stream, packet):
    stream.sendall(struct.pack('!H', len(packet)) + packet)
    return exact_read(stream, struct.unpack('!H', exact_read(stream, 2))[0])


def run(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert 'private' in args.out.resolve().parts
    args.out.mkdir(parents=True, exist_ok=False)
    host = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'example'])
    query = request(host, 28, 0x7311)
    fit_count = (65535 - len(query)) // 28
    if args.direct_only:
        query = request('t', 28, 0x7311)
    rows = []
    for count in (fit_count, fit_count + 1):
        folder = args.out / str(count)
        folder.mkdir()
        configuration = ('no-hosts\nno-resolv\nuser=root\ngroup=root\n'
                         'bind-interfaces\nlisten-address=127.0.0.1\nport=15353\n'
                         'cache-size=150\nserver=127.0.0.1#15354\n'
                         'pid-file=\nlog-facility=-\n' +
                         ''.join(f'address=/t/2001:db8::{i:x}\n' for i in range(1, count + 1)))
        config = folder / 'dnsmasq.conf'
        config.write_text(configuration)
        upstream_queries = []
        stop = threading.Event()
        ready = threading.Event()
        def serve():
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('127.0.0.1', 15354))
                listener.listen()
                listener.settimeout(.1)
                ready.set()
                while not stop.is_set():
                    try:
                        stream, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with stream:
                        stream.settimeout(.1)
                        while not stop.is_set():
                            try:
                                packet = exact_read(stream, struct.unpack('!H', exact_read(stream, 2))[0])
                            except socket.timeout:
                                continue
                            except (ConnectionError, OSError):
                                break
                            q = semantics(packet)['questions'][0]
                            upstream_queries.append(q)
                            target = name('t')
                            body = (b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 120, len(target)) + target +
                                    target + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([8, 8, 4, 4]))
                            reply = struct.pack('!6H', int.from_bytes(packet[:2], 'big'), 0x8180, 1, 2, 0, 0) + packet[12:] + body
                            stream.sendall(struct.pack('!H', len(reply)) + reply)
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        assert ready.wait(3)
        command = image_elf_command(args.image_root, args.binary) if args.image_elf else [str(args.binary)]
        with (folder / 'daemon.log').open('wb') as log:
            process = subprocess.Popen(command + ['-k', '-C', str(config)], stdout=log, stderr=log)
            row = {'literal_count': count, 'query_bytes': len(query)}
            try:
                deadline = time.monotonic() + 5
                while True:
                    assert process.poll() is None and time.monotonic() < deadline
                    try:
                        stream = socket.create_connection(('127.0.0.1', 15353), .1)
                        break
                    except OSError:
                        time.sleep(.02)
                with stream:
                    stream.settimeout(3)
                    warm = exchange(stream, request(host, 1, 0x7310))
                    answer = exchange(stream, query)
                    (folder / 'warm.reply').write_bytes(warm)
                    (folder / 'answer.reply').write_bytes(answer)
                    decoded = semantics(answer)
                    row.update({'response_bytes': len(answer), 'flags': decoded['flags'],
                                 'answer_count': len(decoded['records']),
                                 'question': decoded['questions'], 'reply_sha256': digest(answer),
                                 'warm_sha256': digest(warm), 'upstream_queries': upstream_queries,
                                 'daemon_alive': process.poll() is None})
            except (OSError, ConnectionError) as error:
                row.update(error=type(error).__name__ + ': ' + str(error),
                           daemon_alive=process.poll() is None, upstream_queries=upstream_queries)
            finally:
                process.terminate()
                process.wait(5)
                stop.set()
                thread.join(2)
            row['process_exit'] = process.returncode
            rows.append(row)
    result = {'binary_sha256': digest(args.binary.read_bytes()),
              'tool_sha256': digest(Path(__file__).read_bytes()),
              'scope': 'Synthetic config; exact TCP literal envelope; isolated loopback namespace',
              'direct_only': args.direct_only, 'cases': rows}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--image-elf', action='store_true')
    parser.add_argument('--direct-only', action='store_true', help='query literal owner directly to isolate pre-existing record ordering')
    parser.add_argument('--out', type=Path, required=True)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
