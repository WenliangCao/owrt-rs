#!/usr/bin/env python3
"""AArch64 ptrace netlink fixtures for the EDNS family driver.

The immutable image ELF stays unchanged. After attaching to an already started
daemon, observe RTM_GETNEIGH and replace one actual kernel receive. All injected
bytes and syscall observations are retained as raw private evidence.
"""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import time


def fixture(sequence, pid, length, interface=2, done=True):
    payload = struct.pack('=BBHiHBB', 2, 0, 0, interface, 0x80, 0, 0)
    for kind, value in [(1, socket.inet_aton('192.0.2.17')), (2, bytes(range(1, length + 1)))]:
        payload += struct.pack('=HH', len(value) + 4, kind) + value
        payload += b'\0' * (-len(payload) % 4)
    packet = struct.pack('=IHHII', len(payload) + 16, 28, 2, sequence, pid) + payload
    if done:
        packet += struct.pack('=IHHIIi', 20, 3, 2, sequence, pid, 0)
    return packet


def trace(pid, output, mode, length, interface):
    if platform.machine() != 'aarch64':
        raise RuntimeError('netlink ptrace ABI pinned to AArch64 image')
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    def ptrace(request, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(ctypes.c_uint(request), ctypes.c_uint(pid),
                             ctypes.c_void_p(address), ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'ptrace')
        return result
    registers = (ctypes.c_ulonglong * 34)()
    def regs(write=False):
        value = Iovec(ctypes.addressof(registers), ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204, 1, ctypes.addressof(value))
    report = {'pid': pid, 'mode': mode, 'mac_length': length, 'interface': interface, 'requests': [], 'receives': [], 'injected': False}
    attached = False
    memory = None
    request = None
    active = None
    def read(address, size):
        data = os.pread(memory, size, address)
        if len(data) != size:
            raise AssertionError('short tracee memory read')
        return data
    def write(address, data):
        for offset in range(0, len(data), 8):
            value = data[offset:offset + 8]
            if len(value) < 8:
                value += read(address + offset + len(value), 8 - len(value))
            ptrace(5, address + offset, int.from_bytes(value, 'little'))
    try:
        ptrace(16)
        os.waitpid(pid, 0)
        attached = True
        ptrace(0x4200, 0, 1)  # TRACESYSGOOD
        memory = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        output.with_suffix('.ready').write_text('attached\n')
        while True:
            ptrace(24)
            _, status = os.waitpid(pid, 0)
            if not os.WIFSTOPPED(status):
                raise AssertionError('tracee ended before neighbor fixture')
            if os.WSTOPSIG(status) not in (signal.SIGTRAP | 0x80, signal.SIGTRAP):
                ptrace(24, 0, os.WSTOPSIG(status))
                _, status = os.waitpid(pid, 0)
                continue
            info = (ctypes.c_ubyte * 128)()
            ptrace(0x420e, ctypes.sizeof(info), ctypes.addressof(info))
            regs()
            if info[0] == 1:
                active = None
                if registers[8] == 206 and registers[2] >= 16:
                    sent = read(registers[1], min(registers[2], 28))
                    if struct.unpack_from('=H', sent, 4)[0] == 30:
                        request = (int(registers[0]), struct.unpack_from('=I', sent, 8)[0])
                        report['requests'].append({'descriptor': request[0], 'sequence': request[1], 'wire': sent.hex()})
                elif request and registers[0] == request[0] and registers[8] in (207, 212):
                    if registers[8] == 207:
                        active = (int(registers[1]), int(registers[2]), int(registers[3]))
                    else:
                        msg = read(registers[1], 32)
                        iov = read(struct.unpack_from('=Q', msg, 16)[0], 16)
                        active = (*struct.unpack('=QQ', iov), int(registers[2]))
            elif info[0] == 2 and active:
                returned = ctypes.c_longlong(registers[0]).value
                buffer, capacity, flags = active
                report['receives'].append({'result': returned, 'flags': flags, 'capacity': capacity})
                if returned > 0 and not flags & 2:  # C first peeks; replace only consumed datagram.
                    original = read(buffer, min(returned, capacity))
                    report['original_wire'] = original.hex()
                    original_pid = struct.unpack_from('=I', original, 12)[0]
                    packet = fixture(request[1], original_pid, length, interface)
                    if mode == 'error':
                        packet = struct.pack('=IHHIIi', 20, 2, 2, request[1], original_pid, -errno.EIO)
                    elif mode == 'partial-error':
                        packet = fixture(request[1], original_pid, length, interface, done=False)
                        packet += struct.pack('=IHHIIi', 20, 2, 2, request[1], original_pid, -errno.EIO)
                    elif mode == 'hold':
                        packet = fixture(request[1], original_pid, length, interface, done=False)
                    if mode in ('error', 'partial-error'):
                        packet += struct.pack('=IHHIIi', 20, 3, 2, request[1], original_pid, 0)
                    if len(packet) > capacity:
                        raise AssertionError('fixture exceeds actual receive buffer')
                    write(buffer, packet)
                    registers[0] = len(packet)
                    regs(write=True)
                    report['injected'] = True
                    report['wire'] = packet.hex()
                    ptrace(17)
                    attached = False
                    break
                active = None
    finally:
        if memory is not None:
            os.close(memory)
        if attached:
            try:
                ptrace(17)
            except OSError:
                pass
        output.write_text(json.dumps(report, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=['complete', 'error', 'partial-error', 'hold'], default='complete')
    parser.add_argument('--length', type=int, default=6)
    parser.add_argument('--interface', type=int, default=2)
    args = parser.parse_args()
    raise SystemExit(trace(args.pid, args.out, args.mode, args.length, args.interface))
