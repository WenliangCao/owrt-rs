#!/usr/bin/env python3
"""Minimal real-kernel interrupted IPv6 dump, in a private network namespace."""
import json
import os
import socket
import struct
import subprocess

assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
subprocess.run(['ip', 'link', 'add', 'audit0', 'type', 'dummy'], check=True)
subprocess.run(['ip', 'link', 'set', 'audit0', 'up'], check=True)
idx = socket.if_nametoindex('audit0')
cmd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
cmd.bind((0, 0))
seq = 0


def message(ty, flags, seq, body):
    return struct.pack('IHHII', len(body) + 16, ty, flags, seq, 0) + body


def address(index):
    return socket.inet_pton(socket.AF_INET6, f'2001:db8:{index:x}::1')


def change(ty, addr):
    global seq
    seq += 1
    body = struct.pack('BBBBI', 10, 64, 2, 0, idx) + struct.pack('HH', 20, 1) + addr
    cmd.send(message(ty, 1 | 4 | (0x400 | 0x200 if ty == 20 else 0), seq, body))
    ack = cmd.recv(65536)
    error = struct.unpack_from('i', ack, 16)[0]
    assert error == 0, error


for i in range(1, 1001):
    change(20, address(i))

dump = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
dump.bind((0, 0))
dump.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
dump.send(message(22, 1 | 0x300, 1, struct.pack('BBBBI', 10, 0, 0, 0, idx)))
seen = set()
chunks = []
removed = None
done = False
while not done:
    data = dump.recv(1 << 17)
    flags_seen = set()
    count = 0
    offset = 0
    while offset + 16 <= len(data):
        length, ty, flags, _, _ = struct.unpack_from('IHHII', data, offset)
        body = data[offset + 16:offset + length]
        flags_seen.add(flags)
        if ty == 3:
            done = True
        elif ty == 20 and struct.unpack_from('I', body, 4)[0] == idx:
            off = 8
            while off + 4 <= len(body):
                size, attr = struct.unpack_from('HH', body, off)
                if attr == 1:
                    seen.add(body[off + 4:off + 20])
                    count += 1
                off += (size + 3) & ~3
        offset += (length + 3) & ~3
    chunks.append({'bytes': len(data), 'addresses': count, 'flags': sorted(flags_seen)})
    if removed is None:
        removed = sorted(seen)[0]
        change(21, removed)
expected = {address(i) for i in range(1, 1001)} - {removed}
print(json.dumps({'expected_after_change': len(expected), 'received': len(seen),
    'missing_current': sorted(socket.inet_ntop(socket.AF_INET6, a) for a in expected - seen),
    'removed_still_in_snapshot': removed in seen, 'chunks': chunks}))
