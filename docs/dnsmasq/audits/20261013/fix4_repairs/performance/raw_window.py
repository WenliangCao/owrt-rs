#!/usr/bin/env python3
"""Cached A bank plus N unrelated-name raw records (A or type-absent).

Before filling the normal bank, prove the configured raw A is usable over
both UDP and TCP. This startup proof runs outside the measured epoch.
"""
from pathlib import Path
import socket
import struct
import sys

source = Path(sys.argv.pop(1))
count = int(sys.argv.pop(1))
rrtype = int(sys.argv.pop(1))
sys.path.insert(0, str(source / 'tools/dnsmasq'))
import m6a_window as window

original_config = window.config_for
original_fill = window.fill_and_prove


def config_for(scenario, tcp_profile='hit'):
    return original_config(scenario, tcp_profile) + ''.join(
        f'dns-rr=unused{i}.audit.test,{rrtype},c0000201\n' for i in range(count))


def recv_exact(endpoint, count):
    result = bytearray()
    while len(result) < count:
        block = endpoint.recv(count - len(result))
        if not block:
            raise RuntimeError('early TCP EOF during raw A proof')
        result += block
    return bytes(result)


def fill_and_prove(out, names, disable, upstream_pid, daemon_pid, mixed=False):
    if count == 0:
        return original_fill(out, names, disable, upstream_pid, daemon_pid, mixed)
    host = f'unused{count // 2}.audit.test'
    packet = window.query(host, rrtype, 0x51a1)
    evidence = dict(declarations=count, rrtype=rrtype, host=host, query_hex=packet.hex(), replies={})
    for transport in ('udp', 'tcp'):
        endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM)
        with endpoint:
            endpoint.settimeout(2)
            endpoint.connect(('127.0.0.1', window.PORT))
            if transport == 'udp':
                endpoint.send(packet)
                answer = endpoint.recv(65535)
            else:
                endpoint.sendall(struct.pack('!H', len(packet)) + packet)
                answer = recv_exact(endpoint, struct.unpack('!H', recv_exact(endpoint, 2))[0])
        parsed = window.semantics(answer)
        valid = (parsed['id'] == 0x51a1 and parsed['flags'] & 0x820f == 0x8000
                 and parsed['questions'] == [[host, rrtype, 1]] and len(parsed['records']) == 1
                 and parsed['records'][0]['section'] == 'answer'
                 and parsed['records'][0]['name'] == host and parsed['records'][0]['type'] == rrtype
                 and parsed['records'][0]['class'] == 1
                 and parsed['records'][0]['data'] == ('192.0.2.1' if rrtype == 1 else 'c0000201')
                 and window.complete_dns_wire(answer))
        evidence['replies'][transport] = dict(correct=valid, hex=answer.hex(), decoded=parsed)
        window.save(out / 'same-type-proof.json', evidence)
        if not valid:
            raise AssertionError(f'{transport} configured TYPE A proof failed')
    return original_fill(out, names, disable, upstream_pid, daemon_pid, mixed)


window.config_for = config_for
window.fill_and_prove = fill_and_prove
raise SystemExit(window.main())
