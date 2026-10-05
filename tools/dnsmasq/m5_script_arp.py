#!/usr/bin/env python3
"""Exact-image script-ARP family evidence in disposable namespaces.

Reference-only and selected calibrations explicitly retain missing cases and
cannot qualify the option. Callback order and payload come from the image C.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import query, exact_read
from m2_rootfs import command, prepare, process_identity, sha256
from m5_edns_netlink import trace as trace_neighbor
from m5_edns import Upstream, fixture_stream, options as edns_options, query as edns_query
from m5_tftp_allocation import trace_allocation

HERE = Path(__file__).resolve().parent
PORT = 15353
MAC = '02:00:00:91:00:17'
V4 = '192.0.2.17'
V6 = 'fd42:91::17'
SCRIPT = '''#!/bin/sh
printf '%s|%s|%s|%s|%s|%s|%s|%s\\n' "$#" "$1" "$2" "$3" "$(id -u)" "$(id -g)" "$DNSMASQ_INTERFACE" "$DNSMASQ_CLIENT_ID" >> /m2/arp-events
if [ "$M5_ARP_FDS" = 1 ]; then
  for fd in /proc/$$/fd/*; do
    printf '%s|' "${fd##*/}" >> /m2/arp-fds
    readlink "$fd" >> /m2/arp-fds
  done
fi
if [ "$M5_ARP_DELAY" = 1 ] && [ ! -f /m2/arp-delay-started ]; then
  : > /m2/arp-delay-started
  sleep 2
fi
case "$M5_ARP_FAILURE" in
  exit) exit 7 ;;
  signal) kill -TERM "$$" ;;
esac
printf '%s|%s|%s\\n' "$1" "$2" "$3" >> /m2/arp-finished
'''


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def ip(*args):
    return subprocess.run(['ip', *map(str, args)], check=True, capture_output=True, text=True)


def network():
    for name, address in [('arps0', '192.0.2.1/24'), ('arpw0', '198.51.100.1/24')]:
        ip('link', 'add', name, 'type', 'dummy')
        ip('link', 'set', name, 'up')
        ip('addr', 'add', address, 'dev', name)
    ip('addr', 'add', 'fd42:91::1/64', 'dev', 'arps0', 'nodad')
    ip('addr', 'add', 'fe80::1/64', 'dev', 'arps0', 'nodad')
    for address in ['192.0.2.18/24', '192.0.2.19/24']:
        ip('addr', 'add', address, 'dev', 'arps0')


def neighbor(address, mac=MAC, state='permanent', interface='arps0'):
    if mac is None:
        ip('neigh', 'del', address, 'dev', interface)
    else:
        ip('neigh', 'replace', address, 'lladdr', mac, 'nud', state, 'dev', interface)


def profiles():
    rows = [
        dict(case='disabled-only-script', enabled=False, no_dns=True, no_events=True, no_helper=True),
        dict(case='enabled-no-script', script=False, no_events=True, no_helper=True),
        dict(case='port-zero-only', no_dns=True),
        dict(case='dns-only'),
        dict(case='foreground-user', user='nobody'),
        dict(case='debug-user', user='nobody', debug=True),
        dict(case='daemon-user', user='nobody', daemon=True),
        dict(case='ignored-scriptuser-unknown', extra='dhcp-scriptuser=unknown_arp_user\n'),
        dict(case='ignored-scriptuser-nobody', extra='dhcp-scriptuser=nobody\n'),
        dict(case='dhcp-scriptuser-applied', extra='dhcp-range=192.0.2.10,192.0.2.20,10m\ndhcp-scriptuser=nobody\n', helper_uid=65534),
        dict(case='readonly-no-dhcp-init', extra='leasefile-ro\n'),
        dict(case='initial-v4'),
        dict(case='initial-v6', neighbors=[(V6, MAC, 'arps0')]),
        dict(case='initial-dual', neighbors=[(V4, MAC, 'arps0'), (V6, MAC, 'arps0')]),
        dict(case='excluded-interface-visible', extra='except-interface=arpw0\n', neighbors=[('198.51.100.17', MAC, 'arpw0')]),
        dict(case='link-local-unscoped', neighbors=[('fe80::17', MAC, 'arps0')]),
        dict(case='argv-and-inherited-env'),
        dict(case='helper-descriptor-roles', descriptors=True),
        dict(case='idle-91-no-wake', no_dns=True, clock=True),
        dict(case='wake-tftp-timer', no_dns=True, tftp_clock=True,
             extra='enable-tftp\ntftp-root=/m2/arp-tftp\n'),
        dict(case='tftp-lookup-refresh', tftp_lookup=True,
             extra='enable-tftp\ntftp-root=/m2/arp-tftp\ntftp-unique-root=mac\n'),
        dict(case='netlink-missing-done', pending_dump=True, extra='add-mac\n'),
        dict(case='stop-pending-dump', pending_dump=True, stop_pending=True, extra='add-mac\n'),
        dict(case='positive-record-enomem', allocation='positive', extra='add-mac\n'),
        dict(case='negative-record-enomem', allocation='negative', extra='add-mac\n'),
        dict(case='stop-buffered-script-finishes', delay=True, stop_buffered=True),
        dict(case='stop-helper-failure-cleanup', helper_failure=True, extra='add-mac\n'),
    ]
    for state in ['reachable', 'stale', 'delay', 'probe', 'permanent', 'none', 'noarp', 'incomplete', 'failed']:
        # The real kernel removes LLADDR when NUD_NONE is requested. The
        # separate raw state-none-with-hardware case covers that C predicate.
        rows.append(dict(case='state-' + state, state=state, no_events=state in ['none', 'noarp', 'incomplete', 'failed']))
    return rows + raw_profiles()


def raw_profiles():
    base = dict(address=V4, mac=MAC)
    alternate = '02:00:00:91:00:18'
    fresh = '192.0.2.18'
    def callback(added, address, mac):
        return ['3', 'arp-add' if added else 'arp-del', mac or '01-', address, '0', '0', 'inherited-iface', 'inherited-id']
    rows = []
    def add(label, entries, expected):
        rows.append(dict(case=label, extra='add-mac\n', raw=entries, expected=expected))
    add('unchanged-no-duplicate', [base], [])
    add('mac-replace-delete-add', [dict(address=V4, mac=alternate)],
        [callback(False, V4, MAC), callback(True, V4, alternate)])
    add('removed-delete', [], [callback(False, V4, MAC)])
    add('same-mac-distinct-ip', [base, dict(address=fresh, mac=MAC)], [callback(True, fresh, MAC)])
    add('same-ip-distinct-interface', [base, dict(address=V4, mac=alternate, interface=3)], [callback(True, V4, alternate)])
    add('duplicate-dump-identity', [dict(address=fresh, mac=alternate)] * 2,
        [callback(False, V4, MAC), callback(True, fresh, alternate), callback(True, fresh, alternate)])
    add('delete-before-add', [dict(address=fresh, mac=alternate)],
        [callback(False, V4, MAC), callback(True, fresh, alternate)])
    for label, length in [('zero', 0), ('one', 1), ('six', 6), ('sixteen', 16), ('seventeen', 17)]:
        mac = ':'.join(f'{value:02x}' for value in range(1, length + 1))
        add('mac-length-' + label, [base, dict(address=fresh, mac=mac)],
            [] if length > 16 else [callback(True, fresh, mac)])
    add('missing-destination', [base, dict(address=None, mac=MAC)], [])
    add('missing-hardware', [base, dict(address=fresh, mac=None)], [])
    add('state-none-with-hardware', [base, dict(address=fresh, mac=MAC, state=0)], [callback(True, fresh, MAC)])
    many = [base, dict(address=fresh, mac=alternate), dict(address='192.0.2.19', mac='02:00:00:91:00:19')]
    added = [callback(True, '192.0.2.19', '02:00:00:91:00:19'), callback(True, fresh, alternate)]
    add('addition-list-order', many, added)
    add('deletion-stack-order', [], [callback(False, V4, MAC), callback(False, fresh, alternate), callback(False, '192.0.2.19', '02:00:00:91:00:19')])
    rows[-1]['warmup'] = many
    rows[-1]['warmup_expected'] = added
    add('confirmed-position', [base, many[2], dict(address='192.0.2.20', mac='02:00:00:91:00:20')],
        [callback(False, fresh, alternate), callback(True, '192.0.2.20', '02:00:00:91:00:20')])
    rows[-1]['warmup'] = many
    rows[-1]['warmup_expected'] = added
    rows[-1]['finish'] = []
    rows[-1]['finish_expected'] = [callback(False, V4, MAC), callback(False, '192.0.2.19', '02:00:00:91:00:19'), callback(False, '192.0.2.20', '02:00:00:91:00:20')]
    add('positive-zero-udp-lazy', [base, dict(address='127.0.0.1', mac=''), dict(address=fresh, mac='')],
        [callback(True, fresh, ''), callback(True, '127.0.0.1', '')])
    rows[-1]['zero_positive'] = True
    for label, failure in [('script-exit-recovery', 'exit'), ('script-signal-recovery', 'signal')]:
        add(label, [base, dict(address=fresh, mac=alternate)], [callback(True, fresh, alternate)])
        rows[-1]['script_failure'] = failure
    add('script-exec-error', [base, dict(address=fresh, mac=alternate)], [])
    rows[-1]['exec_failure'] = True
    rows.append(dict(case='slow-helper-dns-progress', delay=True))
    add('netlink-error', [base], [callback(False, V4, MAC)])
    rows[-1]['netlink_mode'] = 'error'
    rows[-1]['reference_difference'] = 'c-error-dump-retires-complete-cache'
    add('netlink-partial-error', [base, dict(address=fresh, mac=alternate)], [callback(True, fresh, alternate)])
    rows[-1]['netlink_mode'] = 'partial-error'
    rows[-1]['reference_difference'] = 'c-partial-dump-publishes-arp-record'
    return rows


def neighbor_packet(entries, sequence, pid, length, interface, done=True):
    packet = bytearray()
    for entry in entries:
        address = entry.get('address')
        family = socket.AF_INET6 if address and ':' in address else socket.AF_INET
        payload = struct.pack('=BBHiHBB', family, 0, 0, entry.get('interface', interface), entry.get('state', 0x80), 0, 0)
        attributes = []
        if address is not None:
            attributes.append((1, socket.inet_pton(family, address)))
        if entry.get('mac') is not None:
            attributes.append((2, bytes.fromhex(entry['mac'].replace(':', ''))))
        for kind, value in attributes:
            payload += struct.pack('=HH', len(value) + 4, kind) + value
            payload += b'\0' * (-len(payload) % 4)
        packet.extend(struct.pack('=IHHII', len(payload) + 16, 28, 2, sequence, pid) + payload)
    if done:
        packet.extend(struct.pack('=IHHIIi', 20, 3, 2, sequence, pid, 0))
    return bytes(packet)


def refresh_with_fixture(pid, entries, folder, target='127.0.0.1', mode='complete'):
    output = folder / 'netlink-fault.json'
    tracer = subprocess.Popen([sys.executable, __file__, '--trace-neighbor', str(pid), str(output), json.dumps(entries), mode])
    try:
        deadline = time.monotonic() + 3
        while not output.with_suffix('.ready').exists() and tracer.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert output.with_suffix('.ready').exists(), 'neighbor tracer attach'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.settimeout(3)
            endpoint.bind(('127.0.0.20', 0))
            endpoint.connect((target, PORT))
            wire = query('arp-health.test', 0x7102)
            endpoint.sendall(struct.pack('!H', len(wire)) + wire)
            reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
        assert tracer.wait(3) == 0, 'neighbor tracer exit'
        receipt = json.loads(output.read_text())
        assert receipt['injected'], 'actual neighbor syscall receipt'
        return reply.hex()
    finally:
        if tracer.poll() is None:
            tracer.kill()
            tracer.wait()


def clock_contract(root, pid, folder):
    initial = callbacks(root)
    neighbor('192.0.2.18', '02:00:00:91:00:18')
    os.kill(pid, signal.SIGHUP)
    time.sleep(.3)
    assert callbacks(root) == initial, 'fresh cache changed before90seconds'
    start = time.monotonic()
    next_notice = start
    progress = []
    while time.monotonic() - start < 91:
        if time.monotonic() >= next_notice:
            os.kill(pid, 0)
            progress.append(dict(elapsed=time.monotonic() - start, callbacks=len(callbacks(root))))
            save(folder / 'clock-progress.json', progress)
            print(json.dumps(dict(case='idle-91-no-wake', elapsed=round(time.monotonic() - start, 1))), flush=True)
            next_notice += 15
        time.sleep(.05)
    idle = callbacks(root)
    save(folder / 'idle-callbacks.json', idle)
    assert idle == initial, 'idle ARP-only acquired a wake source'
    os.kill(pid, signal.SIGHUP)
    deadline = time.monotonic() + 3
    while len(callbacks(root)) < len(initial) + 1 and time.monotonic() < deadline:
        time.sleep(.02)
    after = callbacks(root)
    save(folder / 'refreshed-callbacks.json', after)
    assert after[len(initial):] == [['3', 'arp-add', '02:00:00:91:00:18', '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id']], 'real91second refresh/wake control'
    return [dict(case='before-90-retains', unchanged=True),
            dict(case='idle-91-no-wake', unchanged=True, real_wait_seconds=time.monotonic() - start),
            dict(case='real-91-active-refresh', callbacks=after[len(initial):])]


def zero_positive_contract(root, pid, folder, upstream):
    def exchange(label, tcp):
        before = len(upstream.events)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(3)
            endpoint.bind(('192.0.2.18', 0))
            endpoint.connect(('127.0.0.1', PORT))
            packet = edns_query(label + '.arp.test', 0x7120 + before, opts=b'')
            endpoint.sendall(struct.pack('!H', len(packet)) + packet if tcp else packet)
            reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0]) if tcp else endpoint.recv(4096)
        assert len(upstream.events) == before + 1, 'actual forwarded identity query'
        observation = upstream.events[-1]
        (folder / (label + '.request')).write_bytes(bytes.fromhex(observation['wire']))
        (folder / (label + '.reply')).write_bytes(reply)
        found = edns_options(bytes.fromhex(observation['wire']))
        values = []
        data = found[4] if found else b''
        while data:
            code, size = struct.unpack_from('!HH', data)
            value, data = data[4:4 + size], data[4 + size:]
            if code == 65001:
                values.append(value.hex())
        return values
    (root / 'm2/arp-events').write_bytes(b'')
    replacement = '02:00:00:91:00:18'
    neighbor('192.0.2.18', replacement)
    rows = []
    for label, tcp in [('positive-zero-udp-lazy', False), ('positive-zero-tcp-nonlazy', True)]:
        values = exchange(label, tcp)
        time.sleep(.1)
        save(folder / (label + '.callbacks.json'), callbacks(root))
        assert values == [] and callbacks(root) == [], 'positive-zero became a negative cache record'
        rows.append(dict(case=label, mac_options=values, callbacks=[]))
    control = folder / 'refresh-control'
    control.mkdir()
    refresh_with_fixture(pid, [dict(address=V4, mac=MAC), dict(address='127.0.0.1', mac=''),
                              dict(address='192.0.2.18', mac=replacement)], control, target='127.0.0.2')
    deadline = time.monotonic() + 2
    while len(callbacks(root)) < 2 and time.monotonic() < deadline:
        time.sleep(.02)
    observed = callbacks(root)
    save(control / 'callbacks.json', observed)
    assert observed == [['3', 'arp-del', '01-', '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id'],
                        ['3', 'arp-add', replacement, '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id']], 'zero-positive refresh transition control'
    values = exchange('positive-zero-refresh-control', False)
    assert values == [replacement.replace(':', '')], 'post-refresh MAC lookup control'
    rows.append(dict(case='positive-zero-refresh-control', mac_options=values, callbacks=observed))
    return rows


def tftp_clock_contract(root, pid, folder):
    initial = callbacks(root)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(2)
        endpoint.bind(('127.0.0.3', 0))
        packet = b'\0\1public\0octet\0timeout\x00255\0'
        endpoint.sendto(packet, ('127.0.0.1', 69))
        reply, peer = endpoint.recvfrom(4096)
        assert reply == b'\0\6timeout\x00255\0', 'actual held TFTP transfer'
        (folder / 'tftp-hold.request').write_bytes(packet)
        (folder / 'tftp-hold.reply').write_bytes(reply)
        neighbor('192.0.2.18', '02:00:00:91:00:18')
        start = time.monotonic()
        progress = []
        next_notice = start
        while time.monotonic() - start < 91:
            if time.monotonic() >= next_notice:
                os.kill(pid, 0)
                progress.append(dict(elapsed=time.monotonic() - start, callbacks=len(callbacks(root))))
                save(folder / 'clock-progress.json', progress)
                print(json.dumps(dict(case='wake-tftp-timer', elapsed=round(time.monotonic() - start, 1))), flush=True)
                next_notice += 15
            time.sleep(.05)
        observed = callbacks(root)
        save(folder / 'refreshed-callbacks.json', observed)
        endpoint.sendto(b'\0\5\0\0fixture complete\0', peer)
    assert observed[len(initial):] == [['3', 'arp-add', '02:00:00:91:00:18', '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id']], 'existing TFTP poll timer did not refresh ARP'
    return dict(case='wake-tftp-timer', callbacks=observed[len(initial):], real_wait_seconds=time.monotonic() - start)


def tftp_refresh_contract(root, folder):
    initial = callbacks(root)
    neighbor('192.0.2.18', '02:00:00:91:00:18')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(3)
        endpoint.bind(('127.0.0.4', 0))
        request = b'\0\1public\0octet\0'
        endpoint.sendto(request, ('127.0.0.1', 69))
        reply, peer = endpoint.recvfrom(4096)
        (folder / 'tftp.request').write_bytes(request)
        (folder / 'tftp.reply').write_bytes(reply)
        assert reply == b'\0\3\0\1public' and peer[1] != 69, 'TFTP MAC-miss fallback and data'
        endpoint.sendto(b'\0\4\0\1', peer)
    deadline = time.monotonic() + 2
    while len(callbacks(root)) < len(initial) + 2 and time.monotonic() < deadline:
        time.sleep(.02)
    observed = callbacks(root)
    save(folder / 'lookup-callbacks.json', observed)
    arp = [call for call in observed[len(initial):] if call[1].startswith('arp-')]
    assert arp == [['3', 'arp-add', '02:00:00:91:00:18', '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id']], 'TFTP refresh did not share the ARP producer'
    return dict(case='tftp-lookup-refresh', callbacks=arp, packet=reply.hex())


def pending_dump_contract(root, pid, folder, side, stop_pending):
    entries = [dict(address=V4, mac=MAC), dict(address='192.0.2.18', mac='02:00:00:91:00:18')]
    output = folder / 'netlink-fault.json'
    tracer = subprocess.Popen([sys.executable, __file__, '--trace-neighbor', str(pid), str(output), json.dumps(entries), 'hold'])
    try:
        deadline = time.monotonic() + 3
        while not output.with_suffix('.ready').exists() and tracer.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert output.with_suffix('.ready').exists(), 'pending tracer readiness'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.settimeout(3)
            endpoint.bind(('127.0.0.20', 0))
            endpoint.connect(('127.0.0.1', PORT))
            wire = query('arp-health.test', 0x7130)
            endpoint.sendall(struct.pack('!H', len(wire)) + wire)
            assert tracer.wait(3) == 0, 'pending fixture injection'
            receipt = json.loads(output.read_text())
            stream = fixture_stream(receipt['wire'])
            assert receipt['injected'] and stream is not None, 'raw pending receipt'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as active:
                active.settimeout(.3)
                active.sendto(query('arp-health.test', 0x7131), ('127.0.0.1', PORT))
                try:
                    active.recv(4096)
                    healthy = True
                except socket.timeout:
                    healthy = False
            assert healthy == (side == 'rust'), 'guarded C owner stall or Rust progress'
            reply = None
            if stop_pending:
                os.kill(pid, signal.SIGTERM)
            else:
                try:
                    reply = exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
                except socket.timeout:
                    pass
                assert bool(reply) == (side == 'rust'), 'guarded pending timeout fallback'
            return dict(health_while_pending=healthy, timeout_reply=bool(reply),
                        fault=dict(injected=True, mode='hold', wire=stream[0].hex()))
    finally:
        if tracer.poll() is None:
            tracer.kill()
            tracer.wait()


def allocation_contract(args, root, pid, folder, upstream, record):
    if args.side == 'c':
        symbols = subprocess.run(['readelf', '-Ds', str(args.image_root / 'lib/libc.so')], capture_output=True, text=True, check=True).stdout
        offset = int(re.search(r'^\s*\d+:\s+([0-9a-f]+).*\bcalloc\s*$', symbols, re.M)[1], 16)
        kind, size = 'calloc', 48
    else:
        assert args.allocator_map is not None, 'production allocator map required'
        symbols = args.allocator_map.read_text()
        offset = int(re.search(r'^\s*0x([0-9a-f]+)\s+realloc\s*$', symbols, re.M)[1], 16)
        kind, size = 'realloc', 112
    (folder / 'allocator-symbols').write_text(symbols)
    (root / 'm2/arp-events').write_bytes(b'')
    if record == 'positive':
        neighbor('192.0.2.18', '02:00:00:91:00:18')
    output = folder / 'allocation.json'
    tracer = subprocess.Popen([sys.executable, __file__, '--trace-allocation', str(pid), str(size), kind, str(offset), str(output)])
    def tcp_health():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as endpoint:
            endpoint.settimeout(4)
            endpoint.bind(('127.0.0.1', 0))
            endpoint.connect(('127.0.0.1', PORT))
            wire = query('arp-health.test', 0x7140)
            endpoint.sendall(struct.pack('!H', len(wire)) + wire)
            return exact_read(endpoint, struct.unpack('!H', exact_read(endpoint, 2))[0])
    try:
        deadline = time.monotonic() + 3
        while not Path(str(output) + '.ready').exists() and tracer.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        assert Path(str(output) + '.ready').exists(), 'allocator breakpoint readiness'
        (folder / 'first-health.reply').write_bytes(tcp_health())
        assert tracer.wait(3) == 0, 'allocator trace exit'
        receipt = json.loads(output.read_text())
        assert receipt['injected'], 'actual record allocation did not fail'
        time.sleep(.1)
        before = callbacks(root)
        save(folder / 'failed-allocation-callbacks.json', before)
        assert before == [], 'allocation failure created an ARP record'
        if record == 'negative':
            neighbor('192.0.2.18', '02:00:00:91:00:18')
            count = len(upstream.events)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(3)
                endpoint.bind(('127.0.0.1', 0))
                endpoint.sendto(edns_query('negative-allocation.arp.test', 0x7141, opts=b''), ('127.0.0.1', PORT))
                (folder / 'lazy-health.reply').write_bytes(endpoint.recv(4096))
            assert len(upstream.events) == count + 1, 'actual lazy lookup'
            (folder / 'lazy-health.request').write_bytes(bytes.fromhex(upstream.events[-1]['wire']))
        else:
            (folder / 'second-health.reply').write_bytes(tcp_health())
        deadline = time.monotonic() + 2
        while not callbacks(root) and time.monotonic() < deadline:
            time.sleep(.02)
        observed = callbacks(root)
        save(folder / 'recovery-callbacks.json', observed)
        assert observed == [['3', 'arp-add', '02:00:00:91:00:18', '192.0.2.18', '0', '0', 'inherited-iface', 'inherited-id']], 'uncached allocation failure did not recover on the next lookup'
        return dict(callbacks=observed, fault=dict(injected=True, operation=record + '-record-allocation'))
    finally:
        if tracer.poll() is None:
            tracer.kill()
            tracer.wait()


def buffered_stop_contract(root, process, pid, folder, owned):
    assert (root / 'm2/arp-delay-started').exists() and not (root / 'm2/arp-finished').read_bytes(), 'actual running callback before TERM'
    start = time.monotonic()
    cleanup = stop_daemon(process, pid)
    elapsed = time.monotonic() - start
    save(folder / 'parent-term.json', dict(cleanup=cleanup, elapsed=elapsed))
    assert cleanup['exit'] == 0 and not cleanup['forced'] and elapsed < 1, 'parent waited for its running ARP script'
    assert not (root / 'm2/arp-finished').read_bytes(), 'script finished before parent exit'
    deadline = time.monotonic() + 3
    while not (root / 'm2/arp-finished').read_bytes() and time.monotonic() < deadline:
        time.sleep(.02)
    finished = (root / 'm2/arp-finished').read_bytes()
    (folder / 'finished-after-parent.raw').write_bytes(finished)
    assert finished.startswith(b'arp-add|'), 'already delivered script was lost on TERM'
    helper_statuses = []
    for child in owned:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            ended, status = os.waitpid(child['pid'], os.WNOHANG)
            if ended:
                helper_statuses.append(os.waitstatus_to_exitcode(status))
                break
            time.sleep(.02)
        else:
            raise AssertionError('helper survived its command EOF')
    assert helper_statuses == [0], 'helper EOF exit'
    return dict(case='stop-buffered-script-finishes', parent_exited_before_script=True, helper_statuses=helper_statuses)


def helper_failure_contract(root, pid, folder, owned):
    assert len(owned) == 1, 'actual helper identity'
    os.kill(owned[0]['pid'], signal.SIGKILL)
    time.sleep(.15)
    (root / 'm2/arp-events').write_bytes(b'')
    refresh_with_fixture(pid, [dict(address=V4, mac=MAC), dict(address='192.0.2.18', mac='02:00:00:91:00:18')], folder)
    time.sleep(.15)
    observed = callbacks(root)
    save(folder / 'after-helper-failure.json', observed)
    assert observed == [], 'dead helper received or retained a callback'
    (folder / 'health-after-helper-failure.reply').write_bytes(bytes.fromhex(health()))
    os.kill(pid, 0)
    return dict(case='stop-helper-failure-cleanup', callbacks=observed, dns_health=True)


def callbacks(root):
    return [line.decode('utf-8', 'surrogateescape').split('|')
            for line in (root / 'm2/arp-events').read_bytes().splitlines()]


def health():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(1)
        endpoint.sendto(query('arp-health.test', 0x7101), ('127.0.0.1', PORT))
        return endpoint.recv(4096).hex()


def helpers(pid):
    result = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            values = dict(line.split(':', 1) for line in (entry / 'status').read_text().splitlines() if ':' in line)
        except (OSError, ValueError):
            continue
        if int(values.get('PPid', '0')) == pid:
            result.append(dict(pid=int(entry.name), uid=list(map(int, values['Uid'].split())),
                               gid=list(map(int, values['Gid'].split()))))
    return result


def stop_daemon(process, pid):
    if pid is None:
        if process is None or process.poll() is not None:
            return dict(started=False)
        pid = process.pid
    if process.pid == pid and process.poll() is not None:
        return dict(started=True, forced=False, exit=process.returncode)
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    status = None
    while time.monotonic() < deadline:
        if process.pid == pid:
            status = process.poll()
            if status is not None:
                break
        else:
            ended, raw = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = os.waitstatus_to_exitcode(raw)
                break
        time.sleep(.02)
    forced = status is None
    if forced:
        os.kill(pid, signal.SIGKILL)
        status = process.wait(2) if process.pid == pid else os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    return dict(started=True, forced=forced, exit=status)


def run_side(args):
    assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1', 'use run_isolated.sh'
    args.out.mkdir(parents=True, exist_ok=False)
    plan = json.loads((HERE / 'm5_script_arp.json').read_text())
    save(args.out / 'plan.json', plan)
    root = prepare(args.image_root, None, args.out / 'filesystem', args.rust_binary)
    network()
    script = root / 'm2/arp-script'
    script.write_text(SCRIPT)
    script.chmod(0o755)
    tftp = root / 'm2/arp-tftp'
    tftp.mkdir()
    (tftp / 'public').write_bytes(b'public')
    (tftp / 'public').chmod(0o644)
    selected = re.compile(args.select or '.')
    rows, failures = [], []
    syntax = [
        ('syntax-config', 'script-arp\n', []),
        ('syntax-config-empty', 'script-arp=\n', []),
        ('syntax-config-argument', 'script-arp=1\n', []),
        ('syntax-cli', '', ['--script-arp']),
        ('syntax-cli-argument', '', ['--script-arp=1']),
        ('syntax-repeat', 'script-arp\nscript-arp\n', ['--script-arp', '--script-arp']),
    ]
    for label, config, flags in syntax:
        if not selected.search(label):
            continue
        folder = args.out / label
        folder.mkdir()
        script.write_text(SCRIPT)
        script.chmod(0o755)
        (root / 'm2/arp.conf').write_text(config)
        (folder / 'config').write_text(config)
        result = subprocess.run(command(root, args.side, '--test', '-C', '/m2/arp.conf', *flags), capture_output=True, timeout=4)
        (folder / 'stdout').write_bytes(result.stdout)
        (folder / 'stderr').write_bytes(result.stderr)
        rows.append(dict(case=label, exit=result.returncode, stdout=result.stdout.hex(), stderr=result.stderr.hex()))
    for spec in profiles():
        label = spec['case']
        if not selected.search(label):
            continue
        folder = args.out / label
        folder.mkdir()
        script.write_text(SCRIPT)
        script.chmod(0o755)
        for interface in ['arps0', 'arpw0']:
            # iproute's default flush excludes PERMANENT and NOARP entries.
            ip('neigh', 'flush', 'dev', interface, 'nud', 'all')
        for address, mac, interface in spec.get('neighbors', [(V4, MAC, 'arps0')]):
            neighbor(address, mac, spec.get('state', 'permanent'), interface)
        if 'raw' in spec:
            # C grows its receive workspace from the actual kernel datagram.
            # An ignored NOARP record gives the real buffer room for the
            # controlled multi-record fixture without inventing a capacity.
            for index in range(max(1, len(spec.get('warmup', spec['raw'])) - 1)):
                neighbor('192.0.2.' + str(250 - index), MAC, 'noarp')
        current = subprocess.run(['ip', '-j', 'neigh', 'show'], capture_output=True, check=True)
        (folder / 'kernel-neighbors.json').write_bytes(current.stdout)
        (root / 'm2/arp-events').write_bytes(b'')
        (root / 'm2/arp-events').chmod(0o666)
        (root / 'm2/arp-finished').write_bytes(b'')
        (root / 'm2/arp-finished').chmod(0o666)
        (root / 'm2/arp-delay-started').unlink(missing_ok=True)
        (root / 'm2/arp-fds').write_bytes(b'')
        (root / 'm2/arp-fds').chmod(0o666)
        (root / 'm2/arp.pid').unlink(missing_ok=True)
        config = ('port=' + str(0 if spec.get('no_dns') else PORT) + '\nno-hosts\nno-resolv\n'
                  'bind-interfaces\nlisten-address=127.0.0.1\nuser=' + spec.get('user', 'root') + '\n'
                  'group=' + ('nogroup' if spec.get('user') else 'root') + '\n'
                  'pid-file=/m2/arp.pid\nlog-facility=/m2/arp.log\n'
                  'dhcp-leasefile=/m2/arp.leases\nhost-record=arp-health.test,192.0.2.44\n')
        if spec.get('enabled', True):
            config += 'script-arp\n'
        if spec.get('script', True):
            config += 'dhcp-script=/m2/arp-script\n'
        config += spec.get('extra', '')
        (root / 'm2/arp.conf').write_text(config)
        (folder / 'config').write_text(config)
        env = dict(os.environ, DNSMASQ_INTERFACE='inherited-iface', DNSMASQ_CLIENT_ID='inherited-id')
        env['M5_ARP_FAILURE'] = spec.get('script_failure', '')
        env['M5_ARP_DELAY'] = '1' if spec.get('delay') else '0'
        env['M5_ARP_FDS'] = '1' if spec.get('descriptors') else '0'
        process = None
        pid = None
        upstream = Upstream() if spec.get('zero_positive') or spec.get('allocation') else None
        held = (root / 'm2/arp-held-fd').open('wb') if spec.get('descriptors') else None
        if upstream:
            config += 'cache-size=0\nserver=127.0.0.2#' + str(upstream.port) + '\n'
            config = config.replace('listen-address=127.0.0.1\n', 'listen-address=127.0.0.1,127.0.0.2\n')
            (root / 'm2/arp.conf').write_text(config)
            (folder / 'config').write_text(config)
        try:
            with (folder / 'stderr').open('wb') as output:
                flags = [] if spec.get('daemon') else ['-d' if spec.get('debug') else '-k']
                process = subprocess.Popen(command(root, args.side, *flags, '-C', '/m2/arp.conf'),
                                           stdout=output, stderr=output, env=env, start_new_session=True,
                                           pass_fds=(held.fileno(),) if held else ())
                if spec.get('debug'):
                    # C debug deliberately omits the PID file.
                    pid = process.pid
                    time.sleep(.15)
                    assert process.poll() is None, 'debug startup'
                else:
                    deadline = time.monotonic() + 4
                    while not (root / 'm2/arp.pid').exists() and time.monotonic() < deadline:
                        if process.poll() not in [None, 0]:
                            raise AssertionError('startup failed')
                        time.sleep(.01)
                    assert (root / 'm2/arp.pid').exists(), 'pid readiness'
                    pid = int((root / 'm2/arp.pid').read_text())
                save(folder / 'identity.json', process_identity(root, pid))
                wanted_count = 0 if spec.get('no_events') else len(spec.get('neighbors', [(V4, MAC, 'arps0')]))
                deadline = time.monotonic() + 3
                while len(callbacks(root)) < wanted_count and time.monotonic() < deadline:
                    time.sleep(.02)
                time.sleep(.15)
                observed = callbacks(root)
                save(folder / 'callbacks.json', observed)
                assert len(observed) == wanted_count, 'initial callback inventory'
                for call in observed:
                    assert call[0] == '3' and call[1] == 'arp-add', 'ARP argv/action'
                    assert call[4] == str(spec.get('helper_uid', 0)), 'actual helper UID'
                    assert call[6:] == ['inherited-iface', 'inherited-id'], 'inherited environment'
                if spec.get('delay') and not spec.get('stop_buffered'):
                    assert (root / 'm2/arp-delay-started').exists() and not (root / 'm2/arp-finished').read_bytes(), 'slow script is actually active'
                    replies = [health() for _ in range(10)]
                    save(folder / 'health-during-script.json', replies)
                    assert not (root / 'm2/arp-finished').read_bytes(), 'health happened after the script'
                    deadline = time.monotonic() + 3
                    while not (root / 'm2/arp-finished').read_bytes() and time.monotonic() < deadline:
                        time.sleep(.02)
                    assert (root / 'm2/arp-finished').read_bytes(), 'script recovery'
                if 'raw' in spec:
                    if spec.get('exec_failure'):
                        script.unlink()
                    if 'warmup' in spec:
                        warmup = folder / 'warmup'
                        warmup.mkdir()
                        (root / 'm2/arp-events').write_bytes(b'')
                        refresh_with_fixture(pid, spec['warmup'], warmup)
                        deadline = time.monotonic() + 2
                        while len(callbacks(root)) < len(spec['warmup_expected']) and time.monotonic() < deadline:
                            time.sleep(.02)
                        time.sleep(.15)
                        save(warmup / 'callbacks.json', callbacks(root))
                        assert callbacks(root) == spec['warmup_expected'], 'C-derived warmup order'
                    (root / 'm2/arp-events').write_bytes(b'')
                    refresh_with_fixture(pid, spec['raw'], folder, mode=spec.get('netlink_mode', 'complete'))
                    deadline = time.monotonic() + 2
                    while len(callbacks(root)) < len(spec['expected']) and time.monotonic() < deadline:
                        time.sleep(.02)
                    time.sleep(.15)
                    observed = callbacks(root)
                    save(folder / 'raw-callbacks.json', observed)
                    expected = [] if args.side == 'rust' and spec.get('reference_difference') else spec['expected']
                    assert observed == expected, 'C-derived raw callback order/payload or guarded complete-snapshot policy'
                    if 'finish' in spec:
                        finish = folder / 'finish'
                        finish.mkdir()
                        (root / 'm2/arp-events').write_bytes(b'')
                        refresh_with_fixture(pid, spec['finish'], finish)
                        deadline = time.monotonic() + 2
                        while len(callbacks(root)) < len(spec['finish_expected']) and time.monotonic() < deadline:
                            time.sleep(.02)
                        time.sleep(.1)
                        observed = callbacks(root)
                        save(finish / 'callbacks.json', observed)
                        assert observed == spec['finish_expected'], 'confirmed record position changed across snapshots'
                    if spec.get('exec_failure'):
                        logged = (root / 'm2/arp.log').read_bytes()
                        assert b'failed to execute /m2/arp-script: No such file or directory' in logged, 'actual ARP script exec error notice'
                        (folder / 'exec-error.log').write_bytes(logged)
                        script.write_text(SCRIPT)
                        script.chmod(0o755)
                        recovery = folder / 'exec-recovery'
                        recovery.mkdir()
                        replacement = '02:00:00:91:00:19'
                        refresh_with_fixture(pid, spec['raw'] + [dict(address='192.0.2.19', mac=replacement)], recovery)
                        deadline = time.monotonic() + 2
                        while not callbacks(root) and time.monotonic() < deadline:
                            time.sleep(.02)
                        observed = callbacks(root)
                        save(recovery / 'callbacks.json', observed)
                        assert observed == [['3', 'arp-add', replacement, '192.0.2.19', '0', '0', 'inherited-iface', 'inherited-id']], 'ARP helper did not recover after exec error'
                owned = helpers(pid)
                assert len(owned) == (0 if spec.get('no_helper') else 1), 'helper qualification'
                baseline = len(list(Path('/proc/' + str(pid) + '/fd').iterdir()))
                reply = None if spec.get('no_dns') else health()
                save(folder / 'helper-identities.json', owned)
                remaining = len(list(Path('/proc/' + str(pid) + '/fd').iterdir()))
                save(folder / 'descriptor-health.json', dict(before=baseline, after=remaining))
                assert baseline == remaining, 'descriptor recovery'
                if spec.get('descriptors'):
                    descriptors = (root / 'm2/arp-fds').read_bytes()
                    (folder / 'script-descriptors.raw').write_bytes(descriptors)
                    assert b'arp-held-fd' not in descriptors, 'startup descriptor leaked into ARP script'
                    assert not any(kind in descriptors for kind in [b'socket:[', b'arp.leases', b'arp.log']), 'service descriptor leaked into script'
                if spec.get('clock'):
                    rows.extend(clock_contract(root, pid, folder))
                elif spec.get('tftp_clock'):
                    rows.append(tftp_clock_contract(root, pid, folder))
                elif spec.get('tftp_lookup'):
                    rows.append(tftp_refresh_contract(root, folder))
                elif spec.get('zero_positive'):
                    rows.extend(zero_positive_contract(root, pid, folder, upstream))
                elif spec.get('pending_dump'):
                    (root / 'm2/arp-events').write_bytes(b'')
                    pending = pending_dump_contract(root, pid, folder, args.side, spec.get('stop_pending', False))
                    observed = callbacks(root)
                    save(folder / 'pending-callbacks.json', observed)
                    assert observed == [], 'partial dump emitted a script callback'
                    rows.append(dict(case=label, callbacks=[], reference_difference='c-no-done-owner-stall', **pending))
                elif spec.get('allocation'):
                    rows.append(dict(case=label, **allocation_contract(args, root, pid, folder, upstream, spec['allocation'])))
                elif spec.get('stop_buffered'):
                    rows.append(buffered_stop_contract(root, process, pid, folder, owned))
                elif spec.get('helper_failure'):
                    rows.append(helper_failure_contract(root, pid, folder, owned))
                else:
                    row = dict(case=label, callbacks=observed, helper_count=len(owned), dns_health=reply is not None)
                    if spec.get('reference_difference'):
                        receipt = json.loads((folder / 'netlink-fault.json').read_text())
                        row['reference_difference'] = spec['reference_difference']
                        stream = fixture_stream(receipt['wire'])
                        assert stream is not None, 'complete raw fault stream identity'
                        row['fault'] = dict(injected=receipt['injected'], mode=receipt['mode'], wire=stream[0].hex())
                    rows.append(row)
        except Exception as error:
            failed = dict(case=label, error=repr(error))
            failures.append(failed)
            save(folder / 'failure.json', failed)
        finally:
            cleanup = stop_daemon(process, pid)
            if upstream:
                upstream.close()
            if held:
                held.close()
            save(folder / 'cleanup.json', cleanup)
            if spec.get('pending_dump'):
                expected = args.side == 'c'
                if cleanup.get('forced', False) != expected:
                    failures.append(dict(case=label, error='pending stop reference guard', cleanup=cleanup))
                next((row for row in rows if row['case'] == label), {})['stop_forced'] = cleanup.get('forced', False)
            (folder / 'arp-events.raw').write_bytes((root / 'm2/arp-events').read_bytes())
            if (root / 'm2/arp.log').exists():
                (folder / 'daemon.log').write_bytes((root / 'm2/arp.log').read_bytes())
                (root / 'm2/arp.log').unlink()
            if (cleanup.get('forced') or cleanup.get('exit', 0)) and not (spec.get('pending_dump') and args.side == 'c' and cleanup.get('forced') and cleanup.get('exit') == -9):
                failures.append(dict(case=label, cleanup=cleanup))
    required = {case for boundary in plan['boundaries'] for case in boundary['required_cases']}
    executed = {row['case'] for row in rows}
    report = dict(side=args.side, rows=rows, failures=failures, required_count=len(required),
                  missing_required_cases=sorted(required - executed), qualified=False,
                  reference_only=args.side == 'c', selected=args.select,
                  binary_sha256=sha256(args.image_root / 'usr/sbin/dnsmasq' if args.side == 'c' else args.rust_binary),
                  driver_sha256=sha256(Path(__file__)), manifest_sha256=sha256(HERE / 'm5_script_arp.json'))
    save(args.out / 'result.json', report)
    print(json.dumps(dict(side=args.side, executed=len(rows), missing=len(required - executed), failures=failures)))
    return bool(failures)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--trace-neighbor':
        pid, output, entries = int(sys.argv[2]), Path(sys.argv[3]), json.loads(sys.argv[4])
        return trace_neighbor(pid, output, sys.argv[5] if len(sys.argv) > 5 else 'complete', 6, 2,
                              packet_builder=lambda *args, **kwargs: neighbor_packet(entries, *args, **kwargs))
    if len(sys.argv) > 1 and sys.argv[1] == '--trace-allocation':
        return trace_allocation(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6], file_record=False)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--side', choices=['c', 'rust', 'both'], default='both')
    parser.add_argument('--select')
    parser.add_argument('--allocator-map', type=Path)
    args = parser.parse_args()
    if args.side != 'both':
        return run_side(args)
    args.out.mkdir(parents=True, exist_ok=False)
    exits = {}
    for side in ['c', 'rust']:
        with (args.out / (side + '.launch.log')).open('wb') as log:
            argv = ['sh', str(HERE / 'run_isolated.sh'), sys.executable, __file__, '--side', side,
                    '--image-root', str(args.image_root), '--rust-binary', str(args.rust_binary), '--out', str(args.out / side)]
            if args.select:
                argv += ['--select', args.select]
            if args.allocator_map:
                argv += ['--allocator-map', str(args.allocator_map)]
            exits[side] = subprocess.run(argv, stdout=log, stderr=log).returncode
    reports = [json.loads((args.out / side / 'result.json').read_text()) for side in ['c', 'rust']]
    def observations(report):
        rows = copy.deepcopy(report['rows'])
        for row in rows:
            if 'real_wait_seconds' in row:
                assert row['real_wait_seconds'] >= 91, 'actual refresh time witness'
                row.pop('real_wait_seconds')
            for stream in ['stdout', 'stderr']:
                if stream in row:
                    row[stream] = bytes.fromhex(row[stream]).replace(b'dnsmasq-rs', b'dnsmasq').hex()
        return rows
    def differences(candidate):
        result = []
        if candidate['failures']:
            result.append(dict(side='rust', failures=candidate['failures']))
        left, right = observations(reports[0]), observations(candidate)
        reference_specs = {spec['case']: spec for spec in profiles() if spec.get('reference_difference')}
        for row in right:
            if row['case'] in reference_specs and row.get('callbacks') != []:
                result.append(dict(case=row['case'], error='candidate published an incomplete snapshot'))
            if row['case'] in ['netlink-missing-done', 'stop-pending-dump']:
                if (row.get('health_while_pending') is not True or row.get('stop_forced') is not False
                        or (row['case'] == 'netlink-missing-done' and row.get('timeout_reply') is not True)):
                    result.append(dict(case=row['case'], error='candidate pending owner contract'))
        if [row['case'] for row in left] != [row['case'] for row in right]:
            result.append(dict(error='case inventory mismatch'))
        else:
            for c_row, r_row in zip(left, right):
                if c_row == r_row:
                    continue
                spec = reference_specs.get(c_row['case'])
                if (c_row['case'] in ['netlink-missing-done', 'stop-pending-dump']
                        and c_row.get('reference_difference') == r_row.get('reference_difference') == 'c-no-done-owner-stall'
                        and c_row.get('fault') == r_row.get('fault') and c_row.get('fault', {}).get('injected')
                        and c_row.get('fault', {}).get('mode') == 'hold' and c_row.get('fault', {}).get('wire')
                        and c_row.get('callbacks') == r_row.get('callbacks') == []
                        and c_row.get('health_while_pending') is False and r_row.get('health_while_pending') is True
                        and c_row.get('stop_forced') is True and r_row.get('stop_forced') is False
                        and (c_row['case'] == 'stop-pending-dump' or (c_row.get('timeout_reply') is False and r_row.get('timeout_reply') is True))):
                    continue
                if spec:
                    wanted = spec['reference_difference']
                    c_other, r_other = c_row.copy(), r_row.copy()
                    c_other.pop('callbacks')
                    r_other.pop('callbacks')
                    c_fault, r_fault = c_row.get('fault', {}), r_row.get('fault', {})
                    if (c_row.get('callbacks') == spec['expected'] and r_row.get('callbacks') == []
                            and c_row.get('reference_difference') == r_row.get('reference_difference') == wanted
                            and c_other == r_other and c_fault == r_fault
                            and c_fault.get('injected') and c_fault.get('mode') == spec['netlink_mode']
                            and c_fault.get('wire')
                            and c_row.get('dns_health') and r_row.get('dns_health')):
                        continue
                result.append(dict(c=c_row, rust=r_row))
        return result
    mismatches = differences(reports[1])
    if reports[0]['failures']:
        mismatches.append(dict(side='c', failures=reports[0]['failures']))
    if any(exits.values()):
        mismatches.append(dict(error='side exit', exits=exits))
    controls = []
    if not mismatches:
        for label in ['missing-case', 'wrong-uid', 'wrong-action', 'wrong-hardware', 'wrong-order', 'fixture-failure']:
            mutant = copy.deepcopy(reports[1])
            callbacks_row = next(row for row in mutant['rows'] if row.get('callbacks'))
            if label == 'missing-case':
                mutant['rows'].pop()
            elif label == 'wrong-uid':
                callbacks_row['callbacks'][0][4] = '123'
            elif label == 'wrong-action':
                callbacks_row['callbacks'][0][1] = 'arp-del'
            elif label == 'wrong-hardware':
                callbacks_row['callbacks'][0][2] = '00:00:00:00:00:00'
            elif label == 'wrong-order':
                next(row for row in mutant['rows'] if len(row.get('callbacks', [])) > 1)['callbacks'].reverse()
            else:
                mutant['failures'].append(dict(injected=True))
            controls.append(dict(case=label, rejected=bool(differences(mutant))))
        for label in ['missing-fault', 'wrong-fault-stream', 'candidate-owner-stall']:
            mutant = copy.deepcopy(reports[1])
            targets = [row for row in mutant['rows'] if row.get('fault')]
            if not targets:
                continue
            if label == 'missing-fault':
                targets[0].pop('fault')
            elif label == 'wrong-fault-stream':
                targets[0]['fault']['wire'] = '00'
            else:
                held = next((row for row in targets if row['case'] == 'netlink-missing-done'), None)
                if held is None:
                    continue
                held['health_while_pending'] = False
                held['stop_forced'] = True
                held['timeout_reply'] = False
            controls.append(dict(case=label, rejected=bool(differences(mutant))))
    missing = {side: report['missing_required_cases'] for side, report in zip(['c', 'rust'], reports)}
    qualified = not mismatches and not args.select and not any(missing.values()) and len(controls) == 9 and all(row['rejected'] for row in controls)
    result = dict(exits=exits, failures=mismatches, missing_required_cases=missing, negative_controls=controls,
                  paired_observations_passed=not mismatches, qualified=qualified,
                  binary_sha256=sha256(args.rust_binary), bytes=args.rust_binary.stat().st_size)
    save(args.out / 'result.json', result)
    print(json.dumps(dict(paired=len(reports[0]['rows']), failures=len(mismatches), missing=len(missing['c']), qualified=qualified)))
    return bool(mismatches)


if __name__ == '__main__':
    raise SystemExit(main())
