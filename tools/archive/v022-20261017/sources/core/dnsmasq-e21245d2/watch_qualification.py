#!/usr/bin/env python3
"""Read terminal/failure events only; no status polling or experiment mutation."""
import ctypes
import json
import os
from pathlib import Path
import selectors

root = Path('/srv/owrt-archive/unified-work/private/dnsmasq-final')
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
assert fd >= 0
assert libc.inotify_add_watch(fd, os.fsencode(root / 'families'), 0x80 | 0x8) >= 0
assert libc.inotify_add_watch(fd, os.fsencode(root), 0x80 | 0x8) >= 0
selector = selectors.DefaultSelector()
selector.register(fd, selectors.EVENT_READ)
try:
    pidfd = os.pidfd_open(2104032)
    selector.register(pidfd, selectors.EVENT_READ)
except ProcessLookupError:
    pidfd = None


def inspect():
    qualification = json.loads((root / 'qualification.json').read_text())
    families = json.loads((root / 'families/result.json').read_text())
    failed = [r for r in families['families'] if not r['passed']]
    if qualification['status'] != 'running' or failed:
        print(json.dumps({'qualification': qualification, 'failed_families': failed,
                          'completed_families': len(families['families'])}, indent=2), flush=True)
        return True
    return False


while not inspect():
    if pidfd is None:
        raise RuntimeError('controller exited without terminal qualification')
    for key, _ in selector.select():
        if key.fd == fd:
            os.read(fd, 65536)
        elif key.fd == pidfd:
            selector.unregister(pidfd)
            os.close(pidfd)
            pidfd = None
