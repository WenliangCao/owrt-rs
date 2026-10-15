#!/usr/bin/env python3
"""Supplementary actual-daemon CNAME/NX retention-boundary observations.

Requires the existing real isolated Linux namespaces. No clock is changed.
Seed a CNAME TTL20 + negative TTL5 response at an aligned second, then query at
+10.2 seconds with stale retention5. A TXT-terminal variant checks whether the
internal stale flag can also affect a returned packet/EDE. Raw C and Rust data
remain separate; this probe never replaces the frozen 1,100-command corpus.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import threading
import time


def name(value):
    return b''.join(bytes([len(label)]) + label.encode() for label in value.split('.')) + b'\0'


def rr(owner, kind, ttl, data):
    return name(owner) + struct.pack('!HHIH', kind, 1, ttl, len(data)) + data


def response(packet, read_name):
    host, end = read_name(packet, 12)
    if isinstance(host, bytes):
        host = host.decode()
    question = packet[12:end + 4]
    alias = host.lower() == 'alias.test'
    soa = name('ns.test') + name('hostmaster.test') + struct.pack('!5I', 1, 2, 3, 4, 5)
    return (packet[:2] + struct.pack('!5H', 0x8183, 1, int(alias), 1, 0) + question
            + (rr('alias.test', 5, 20, name('target.test')) if alias else b'')
            + rr('test', 6, 20, soa))


class Upstream:
    def __init__(self, read_name):
        self.read_name = read_name
        self.stop = threading.Event()
        self.rows, self.workers, self.sockets = [], [], []
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = socket.socket(socket.AF_INET, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', 15354))
            sock.settimeout(.2)
            if kind == socket.SOCK_STREAM:
                sock.listen(8)
            self.sockets.append(sock)
            worker = threading.Thread(target=self.run, args=(sock, kind), daemon=True)
            self.workers.append(worker)
            worker.start()

    def reply(self, packet, transport):
        host, _ = self.read_name(packet, 12)
        reply = response(packet, self.read_name)
        self.rows.append({'epoch': time.time(), 'transport': transport, 'name': host,
                          'request_wire': packet.hex(), 'response_wire': reply.hex()})
        return reply

    def run(self, sock, kind):
        while not self.stop.is_set():
            try:
                if kind == socket.SOCK_DGRAM:
                    packet, peer = sock.recvfrom(65535)
                    sock.sendto(self.reply(packet, 'udp'), peer)
                else:
                    client, _ = sock.accept()
                    client.settimeout(2)
                    with client:
                        head = exact(client, 2)
                        packet = exact(client, struct.unpack('!H', head)[0])
                        reply = self.reply(packet, 'tcp')
                        client.sendall(struct.pack('!H', len(reply)) + reply)
            except socket.timeout:
                continue
            except (OSError, EOFError):
                if self.stop.is_set():
                    break

    def close(self):
        self.stop.set()
        for sock in self.sockets:
            sock.close()
        for worker in self.workers:
            worker.join(3)
        assert all(not worker.is_alive() for worker in self.workers)


def exact(client, count):
    output = b''
    while len(output) < count:
        part = client.recv(count - len(output))
        if not part:
            raise EOFError()
        output += part
    return output


def exchange(query, tcp=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect(('127.0.0.1', 15353))
        if tcp:
            client.sendall(struct.pack('!H', len(query)) + query)
            return exact(client, struct.unpack('!H', exact(client, 2))[0])
        client.send(query)
        return client.recv(65535)


def request(host, qtype=1, edns=False):
    return (struct.pack('!6H', 0x1234, 0x100, 1, 0, 0, int(edns)) + name(host)
            + struct.pack('!HH', qtype, 1)
            + (b'\0' + struct.pack('!HHIH', 41, 1232, 0, 0) if edns else b''))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('tools', 'image-root', 'rust', 'output'):
        parser.add_argument('--' + arg, type=Path, required=True)
    parser.add_argument('--implementation', choices=['c', 'rust'], required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--profile', choices=['finite', 'min-max'], action='append')
    parser.add_argument('--transport', choices=['udp', 'tcp'], action='append')
    args = parser.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
    assert sorted(n for _, n in socket.if_nameindex()) == ['lo']
    assert 'private' in args.output.resolve().parts
    sys.path.insert(0, str(args.tools.resolve()))
    from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256
    from dns_service_probe import read_name, semantics
    import subprocess
    assert sha256(args.image_root / 'usr/sbin/dnsmasq') == STOCK_SHA256
    binary = args.image_root / 'usr/sbin/dnsmasq' if args.implementation == 'c' else args.rust
    assert sha256(binary) == args.expected_sha256
    args.output.mkdir(parents=True, exist_ok=False)
    root = prepare(args.image_root, None, args.output / 'stage', args.rust)
    report = {'implementation': args.implementation, 'elf_sha256': args.expected_sha256,
              'scope': 'supplementary live-clock boundary; not replacement of frozen corpus', 'cases': []}
    for profile in args.profile or ['finite', 'min-max']:
        for transport in args.transport or ['udp', 'tcp']:
            for terminal in [False, True]:
                label = f'{profile}-{transport}-' + ('txt-terminal' if terminal else 'ordinary')
                folder = args.output / label
                folder.mkdir()
                runtime = root / 'm2' / label
                runtime.mkdir()
                config = ('no-hosts\nno-resolv\nno-poll\nuser=root\ngroup=root\nbind-interfaces\n'
                    'listen-address=127.0.0.1\nport=15353\ncache-size=32\nneg-ttl=5\n'
                    'use-stale-cache=5\nno-0x20-encode\nserver=127.0.0.1#15354\n'
                    'host-record=ready.test,192.0.2.41\nlocal-ttl=37\nlog-queries\n'
                    f'log-facility=/m2/{label}/daemon.log\npid-file=/m2/{label}/pid\n')
                if profile == 'min-max':
                    config += 'min-cache-ttl=4\nmax-cache-ttl=12\n'
                if terminal:
                    config += 'txt-record=target.test,local-terminal\n'
                (runtime / 'config').write_text(config)
                row = {'case': label, 'config': config, 'queries': [], 'passed_runtime': False}
                upstream = Upstream(read_name)
                with (folder / 'stderr.log').open('w') as log:
                    process = subprocess.Popen(command(root, args.implementation, '-k', '-C', f'/m2/{label}/config'),
                                               stdout=log, stderr=log, start_new_session=True)
                    try:
                        for _ in range(100):
                            assert process.poll() is None
                            try:
                                if semantics(exchange(request('ready.test')))['records']:
                                    break
                            except OSError:
                                pass
                            time.sleep(.02)
                        else:
                            raise RuntimeError('readiness failed')
                        row['identity'] = process_identity(root, process.pid)
                        assert row['identity']['sha256'] == args.expected_sha256
                        epoch = int(time.time()) + 1 + .1
                        time.sleep(max(0, epoch - time.time()))
                        for phase, qtype, edns, tcp in [('seed', 1, False, False),
                              ('cutoff', 16 if terminal else 1, terminal, transport == 'tcp')]:
                            if phase == 'cutoff':
                                time.sleep(max(0, epoch + 10.2 - time.time()))
                            before = len(upstream.rows)
                            query = request('alias.test', qtype, edns)
                            sent = time.time()
                            reply = exchange(query, tcp)
                            row['queries'].append({'phase': phase, 'sent_epoch': sent, 'epoch_delta': sent - epoch,
                                'request_wire': query.hex(), 'response_wire': reply.hex(), 'semantics': semantics(reply),
                                'upstream_before': before, 'upstream_after': len(upstream.rows)})
                        assert process.poll() is None
                        os.kill(process.pid, signal.SIGUSR1)
                        time.sleep(.1)
                        row['passed_runtime'] = True
                    except Exception as error:
                        row['error'] = repr(error)
                    finally:
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(3)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                        row['exit'] = process.returncode
                        upstream.close()
                row['upstream'] = upstream.rows
                if (runtime / 'daemon.log').exists():
                    (folder / 'daemon.log').write_bytes((runtime / 'daemon.log').read_bytes())
                (folder / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
                report['cases'].append(row)
                (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
                print(label, row['passed_runtime'], row.get('error'), flush=True)
    return int(any(not r['passed_runtime'] or r['exit'] != 0 for r in report['cases']))


if __name__ == '__main__':
    raise SystemExit(main())
