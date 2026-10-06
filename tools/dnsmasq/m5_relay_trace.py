#!/usr/bin/env python3
"""Observe actual AArch64 DHCP recv/send/ARP syscalls without changing them."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import struct
import time


def trace(pid, output):
    assert platform.machine() == 'aarch64', 'witness ABI is the exact image AArch64 ABI'
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
    libc = ctypes.CDLL(None, use_errno=True); libc.ptrace.restype = ctypes.c_long
    registers = (ctypes.c_ulonglong * 34)()
    attached = False; memory = None; stopping = False; active = None
    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    def ptrace(operation, address=0, data=0):
        ctypes.set_errno(0)
        value = libc.ptrace(operation, pid, ctypes.c_void_p(address), ctypes.c_void_p(data))
        if value == -1 and ctypes.get_errno(): raise OSError(ctypes.get_errno(), 'ptrace')
        return value
    def read(address, length):
        if not address or not length: return b''
        value = os.pread(memory, min(length, 65535), address)
        assert len(value) == min(length, 65535), 'exact live tracee memory witness'
        return value
    def message(address, returned=None):
        header = read(address, 56)
        name, namelen = struct.unpack_from('=QI', header)
        vectors, count, control, controllen = struct.unpack_from('=QQQQ', header, 16)
        assert count <= 1024, 'bounded live iovec witness'
        sizes = list(struct.iter_unpack('=QQ', read(vectors, count * 16)))
        remaining = sum(length for _, length in sizes) if returned is None else returned
        payload = bytearray()
        for pointer, length in sizes:
            size = min(length, remaining); payload.extend(read(pointer, size)); remaining -= size
            if not remaining: break
        return dict(payload=payload.hex(), address=read(name, namelen).hex(), control=read(control, controllen).hex(), flags=struct.unpack_from('=I', header, 48)[0])
    output = Path(output)
    with output.open('w') as log:
        def record(value):
            log.write(json.dumps(value, sort_keys=True)+'\n'); log.flush()
        try:
            ptrace(16); os.waitpid(pid, 0); attached = True; ptrace(0x4200, 0, 1)
            memory = os.open('/proc/'+str(pid)+'/mem', os.O_RDONLY)
            output.with_suffix('.ready').write_text('observing actual syscalls; no injection\n')
            while not stopping:
                ptrace(24)
                while True:
                    waited, status = os.waitpid(pid, os.WNOHANG)
                    if waited: break
                    if stopping:
                        os.kill(pid, signal.SIGSTOP)
                        _, status = os.waitpid(pid, 0); break
                    time.sleep(.001)
                if not os.WIFSTOPPED(status):
                    attached = False; record(dict(tracee_status=status)); break
                if stopping: break
                signum = os.WSTOPSIG(status)
                if signum not in [signal.SIGTRAP | 0x80, signal.SIGTRAP]:
                    ptrace(24, 0, signum); _, status = os.waitpid(pid, 0); continue
                info = (ctypes.c_ubyte * 128)(); ptrace(0x420e, ctypes.sizeof(info), ctypes.addressof(info))
                iov = Iovec(ctypes.addressof(registers), ctypes.sizeof(registers)); ptrace(0x4204, 1, ctypes.addressof(iov))
                if info[0] == 1:
                    number = int(registers[8]); active = None
                    if number in [206, 207, 211, 212] or number == 29 and registers[1] == 0x8955:
                        active = dict(number=number, fd=int(registers[0]), arguments=[int(x) for x in registers[:6]], entered_ns=time.monotonic_ns())
                        try:
                            if number == 29: active['arp_request'] = read(registers[2], 68).hex()
                            elif number == 211: active.update(message(registers[1]))
                            elif number == 206: active.update(payload=read(registers[1], registers[2]).hex(), address=read(registers[4], registers[5]).hex())
                        except Exception as error: active['entry_memory_error'] = repr(error)
                elif info[0] == 2 and active is not None:
                    active['returned'] = ctypes.c_longlong(registers[0]).value; active['exited_ns'] = time.monotonic_ns()
                    args = active['arguments']
                    try:
                        if active['returned'] >= 0:
                            if active['number'] == 212: active.update(message(args[1], active['returned']))
                            elif active['number'] == 207: active.update(payload=read(args[1], min(args[2], active['returned'])).hex(), address=read(args[4], struct.unpack('=I', read(args[5], 4))[0] if args[5] else 0).hex())
                    except Exception as error: active['exit_memory_error'] = repr(error)
                    record(active); active = None
        finally:
            if memory is not None: os.close(memory)
            if attached:
                try: ptrace(17)
                except OSError as error:
                    if error.errno != errno.ESRCH: raise
                try: os.kill(pid, signal.SIGCONT)
                except ProcessLookupError: pass
            record(dict(detached=True, stopped_by_controller=stopping))
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True); parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); raise SystemExit(trace(args.pid, args.out))
