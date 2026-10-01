#!/usr/bin/env python3
"""One ordinary C/Rust comparison for actual-config DNS policies and hosts dirs."""
import argparse
import collections
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import threading
import time
from dns_service_probe import query, read_name, rr, name, semantics, exchange, exact_read


class Upstream:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(('127.0.0.1', self.port))
        self.tcp.listen()
        self.stop = False
        self.counts = collections.Counter()
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def reply(self, packet):
        host, end = read_name(packet, 12)
        kind = struct.unpack_from('!H', packet, end)[0]
        self.counts[(host, kind)] += 1
        value = (ipaddress.ip_address('8.8.4.4').packed if kind == 1 else
                 ipaddress.ip_address('2606:4700:4700::1111').packed if kind == 28 else
                 name('upstream.example') if kind == 12 else b'\x02ok')
        return packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + packet[12:end + 4] + rr(kind, value)

    def run(self):
        while not self.stop:
            ready, _, _ = select.select([self.udp, self.tcp], [], [], .05)
            for endpoint in ready:
                try:
                    if endpoint is self.udp:
                        packet, peer = endpoint.recvfrom(65535)
                        endpoint.sendto(self.reply(packet), peer)
                    else:
                        conn, _ = endpoint.accept()
                        with conn:
                            conn.settimeout(1)
                            while True:
                                try:
                                    size = struct.unpack('!H', exact_read(conn, 2))[0]
                                except ConnectionError:
                                    break
                                response = self.reply(exact_read(conn, size))
                                conn.sendall(struct.pack('!H', len(response)) + response)
                except Exception as error:
                    self.errors.append(repr(error))

    def close(self):
        self.stop = True
        self.thread.join(2)
        self.udp.close()
        self.tcp.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('requires run_isolated.sh')
    args.out.mkdir(parents=True, exist_ok=False)
    directory = args.out / 'hosts'
    directory.mkdir()
    for file, text in [('a', '127.0.0.7 directory.test first.test\n'),
                       ('b', '127.0.0.7 second.test\n'),
                       ('.hidden', '127.0.0.8 hidden.test\n'),
                       ('backup~', '127.0.0.9 backup.test\n')]:
        (directory / file).write_text(text)
    upstream = Upstream()
    config = args.out / 'dnsmasq.conf'
    config.write_text(f'''port=15353
no-resolv
no-hosts
listen-address=127.0.0.1
pid-file={args.out}/pid
server=127.0.0.1#{upstream.port}
server=/168.192.in-addr.arpa/127.0.0.1#{upstream.port}
cache-size=0
no-round-robin
domain-needed
bogus-priv
localise-queries
local=/lan/
addn-hosts={directory}
host-record=multi.test,127.2.0.3,2001:db8::3
host-record=multi.test,192.0.2.3
host-record=known,127.0.0.4
cname=alias.test,multi.test
''')
    rows, errors = [], []
    log = (args.out / 'stderr.log').open('wb')
    process = subprocess.Popen([str(args.binary.resolve()), '-k', '-C', str(config)], stdout=log, stderr=log)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(f'daemon exited {process.returncode}')
            try:
                exchange(15353, query('ready.example'))
                break
            except OSError:
                time.sleep(.02)
        else:
            raise RuntimeError('listener not ready')
        schedule = [('directory.test', 1), ('7.0.0.127.in-addr.arpa', 12),
                    ('hidden.test', 1), ('backup.test', 1),
                    ('missing', 1), ('missing', 28), ('missing', 255), ('missing', 16),
                    ('known', 28), ('ready.example', 1), ('absent.lan', 1),
                    ('1.0.0.10.in-addr.arpa', 12), ('1.1.168.192.in-addr.arpa', 12),
                    ('8.8.8.8.in-addr.arpa', 12), (ipaddress.ip_address('fc00::1').reverse_pointer, 12),
                    ('multi.test', 1), ('multi.test', 28), ('multi.test', 255), ('alias.test', 1)]
        for tcp in (False, True):
            for host, kind in schedule:
                before = upstream.counts[(host, kind)]
                try:
                    request = query(host, kind)
                    response = exchange(15353, request, tcp=tcp)
                    rows.append({'name': host, 'type': kind, 'tcp': tcp,
                                 'reply': semantics(response), 'upstream': upstream.counts[(host, kind)] - before})
                    (args.out / f'{len(rows):02}.request').write_bytes(request)
                    (args.out / f'{len(rows):02}.reply').write_bytes(response)
                except Exception as error:
                    errors.append({'name': host, 'type': kind, 'tcp': tcp, 'error': repr(error)})
    except Exception as error:
        errors.append({'startup': repr(error)})
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            errors.append({'shutdown': 'required SIGKILL'})
        upstream.close()
        log.close()
    differences = []
    if args.reference:
        reference = json.loads(args.reference.read_text())
        for index, (expected, actual) in enumerate(zip(reference['rows'], rows)):
            if expected != actual:
                differences.append({'index': index, 'expected': expected, 'actual': actual})
        if len(reference['rows']) != len(rows):
            errors.append({'length': [len(reference['rows']), len(rows)]})
    result = {'planned': 38, 'executed': len(rows), 'rows': rows, 'differences': differences,
              'errors': errors + upstream.errors, 'exit': process.returncode}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: len(value) if isinstance(value, list) else value for key, value in result.items() if key != 'rows'}))
    raise SystemExit(bool(errors or upstream.errors or differences or len(rows) != 38))


if __name__ == '__main__':
    main()
