#!/usr/bin/env python3
"""IPv4 dhcp-range family against exact-image C in disposable namespaces.

The first phase freezes parser and ordinary range observations. Packet transport
and namespaces reuse the existing DHCP matrix helpers; expected packets always
come from image C. Raw output and failed runs remain in private evidence.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
import platform
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import m5_option_matrix_dhcp as dhcp
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256
from m5_dhcp_tags_options import options, primary_options, request, comparable_reply
from m2_dhcp_scenarios import Capture, make_client
from test_single_poll_service import stop

SERVER = '10.77.0.1'

# Keep the executable scenarios tied to the source-derived family checklist.
# The plan is written beside each run so a partial Oracle run cannot be read as
# coverage of a boundary that was never scheduled.  Probe-fault rows are
# explicitly identified, and planned-only rows never count as a pass.
BOUNDARY_IDS = [
    'CFG-01', 'CFG-02', 'CFG-03', 'CFG-04', 'CFG-05', 'CFG-06', 'CFG-07', 'CFG-08', 'CFG-09',
    'CTX-01', 'CTX-02', 'CTX-03', 'CTX-04', 'CTX-05', 'CTX-06',
    'SELECT-01', 'SELECT-02', 'SELECT-03', 'SELECT-04', 'SELECT-05', 'SELECT-06',
    'SELECT-07', 'SELECT-08', 'SELECT-09', 'SELECT-10',
    'LEASE-01', 'LEASE-02', 'LEASE-03',
    'PROBE-01', 'PROBE-02', 'PROBE-03', 'PROBE-04', 'PROBE-05', 'PROBE-06',
    'PROBE-07', 'PROBE-08', 'LIFE-01', 'LIFE-02', 'LIFE-03',
]


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def fd_snapshot(pid):
    files = {}
    for entry in Path(f'/proc/{pid}/fd').iterdir():
        try:
            files[entry.name] = os.readlink(entry)
        except FileNotFoundError:
            pass
    return {'files': files, 'sockets': {name: Path(f'/proc/{pid}/net/{name}').read_text()
            for name in ['udp', 'udp6', 'tcp', 'tcp6', 'unix']}}


def settled_fds(pid, path, expected=None):
    """Require actual return to the baseline, allowing an active OS borrow."""
    samples, repeated, last = [], 0, None
    deadline = time.monotonic()+1
    while time.monotonic() < deadline:
        snapshot = fd_snapshot(pid)
        count = len(snapshot['files'])
        samples.append({'at': time.time(), **snapshot})
        if count == (count if expected is None else expected):
            repeated = repeated+1 if last == count else 1
        else:
            repeated = 0
        if repeated == 3:
            break
        last = count
        time.sleep(.02)
    save(path, {'expected': expected, 'stable': repeated == 3, 'samples': samples})
    return count, repeated == 3


class RangeCapture(Capture):
    def __init__(self, out):
        self.out, self.rows, self.stop = out, [], threading.Event()
        self.sockets = []
        for interface in ['br-lan', 'lan-port']:
            # ETH_P_ALL also observes locally transmitted frames.  A socket
            # bound to ETH_P_IP alone misses outgoing ICMP on this kernel.
            endpoint = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            endpoint.bind((interface, 0))
            endpoint.settimeout(.05)
            self.sockets.append((interface, endpoint))
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()


def fault_program(kind, machine=None):
    """Narrow child-only seccomp filter; unrelated DNS/DHCP syscalls survive."""
    machine = machine or platform.machine()
    numbers = {'aarch64': {'socket': 198, 'setsockopt': 208, 'sendto': 206, 'recvfrom': 207},
               'x86_64': {'socket': 41, 'setsockopt': 54, 'sendto': 44, 'recvfrom': 45}}
    if machine not in numbers:
        raise ValueError('unsupported fault-injector architecture: '+machine)
    # seccomp_data stores 64-bit syscall arguments starting at offset 16.
    # A socket's CLOEXEC/NONBLOCK bits are masked before checking SOCK_RAW.
    matchers = {
        'socket': ('socket', [(0, 2, None), (1, 3, 15), (2, 1, None)]),
        'setup': ('setsockopt', [(1, 1, None), (2, 5, None)]),
        'send': ('sendto', [(2, 28, None), (5, 16, None)]),
        'send-eagain': ('sendto', [(2, 28, None), (5, 16, None)]),
        'receive': ('recvfrom', [(2, 48, None)]),
    }
    syscall, arguments = matchers[kind]
    program = [[0x20, 0, 0, 0], [0x15, 0, 0, numbers[machine][syscall]]]
    jumps = [1]
    for index, wanted, mask in arguments:
        program.append([0x20, 0, 0, 16+index*8])
        if mask is not None:
            program.append([0x54, 0, 0, mask])
        jumps.append(len(program))
        program.append([0x15, 0, 0, wanted])
    error = 11 if kind == 'send-eagain' else 1
    program.extend([[0x06, 0, 0, 0x00050000 | error], [0x06, 0, 0, 0x7fff0000]])
    for index in jumps:
        program[index][2] = len(program)-index-2
    return program


def fault_exec(kind, argv):
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filters', ctypes.POINTER(Filter))]
    rows = fault_program(kind)
    filters = (Filter*len(rows))(*(Filter(*row) for row in rows))
    program = Program(len(rows), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot install ICMP fault filter')
    os.execvp(argv[0], argv)


def client_worker(spec):
    """Raw response capture includes the 67->67 relay path and BOOTP."""
    event, xid = spec['event'], spec['xid']
    if event.get('loopback'):
        interface = 'lo'
    elif event.get('relay'):
        interface = 'client0'
    elif event.get('guest'):
        interface = 'client1'
    else:
        interface = make_client({'id': event.get('client', 1), 'mac': dhcp.mac(event.get('client', 1))})
    local = event['packet'].get('giaddr', '0.0.0.0') if event.get('relay') else event['packet'].get('ciaddr', '0.0.0.0')
    if local != '0.0.0.0':
        subprocess.run(['ip', 'addr', 'replace', local+'/24', 'dev', interface], check=True)
    packet = request(event['packet'], xid)
    destination = event.get('destination', SERVER if event.get('relay') or event.get('action') in ('renew', 'release') else '255.255.255.255')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        raw.bind((interface, 0))
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode()+b'\0')
        source_port = event.get('source_port', 67 if event.get('relay') else 68)
        listener_port = event.get('listener_port', 67)
        endpoint.bind((local, source_port))
        sent = time.time()
        endpoint.sendto(packet, (destination, listener_port))
        if spec.get('sent_marker'):
            save(spec['sent_marker'], {'sent': sent, 'packet': packet.hex()})
        deadline = time.monotonic()+event.get('timeout', .6)
        while time.monotonic() < deadline:
            raw.settimeout(deadline-time.monotonic())
            try:
                frame = raw.recv(65535)
            except socket.timeout:
                break
            if len(frame) < 42 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
                continue
            offset = 14+(frame[14] & 15)*4
            if len(frame) < offset+8:
                continue
            sport, dport, size = struct.unpack_from('!HHH', frame, offset)
            response = frame[offset+8:offset+size]
            if (sport, dport) != (listener_port, source_port) or len(response) < 240:
                continue
            if response[4:8] != struct.pack('!I', xid):
                continue
            return {'request': packet.hex(), 'reply': response.hex(), 'ethernet': frame.hex(),
                    'sent': sent, 'received': time.time(), 'destination': {
                        'ethernet': frame[:6].hex(), 'source_ip': socket.inet_ntoa(frame[26:30]),
                        'address': socket.inet_ntoa(frame[30:34]), 'source_port': sport, 'port': dport}}
    return {'request': packet.hex(), 'reply': None, 'sent': sent, 'received': time.time()}


def syntax_cases():
    values = [
        ('range-basic', 'normal', '10.77.0.10,10.77.0.14'),
        ('range-reverse', 'reverse', '10.77.0.14,10.77.0.10'),
        ('range-one-address', 'single', '10.77.0.10,10.77.0.10'),
        ('range-repeat', 'first', '10.77.0.10,10.77.0.14'),
        ('range-repeat', 'second', '10.77.0.20,10.77.0.24'),
    ]
    for prefix in ['lan', 'red', 'dead', '1234', '1.2.3', '2001:db8::1', '',
                   'set:dead', 'set:pool', 'tag:match', 'net:match', 'tag:!blocked',
                   'set:,red', 'tag:,net:,set:', 'set:a,set:b', 'red,blue',
                   '"set:red"', '"tag:known"', '"192.0.2.1"', '"dead"', '"red,blue"']:
        values.append(('range-prefix-grammar', 'prefix-'+str(len(values)), prefix+',10.77.0.10,10.77.0.14'))
    for name, value in [
        ('range-tags', 'tag:known,net:br-lan,tag:!blocked,10.77.0.10,10.77.0.14'),
        ('range-filter-conjunction', 'tag:known,tag:!blocked,net:lan,10.77.0.10,10.77.0.14'),
        ('range-empty-selectors', 'tag:,net:,set:,10.77.0.10,10.77.0.14'),
    ]:
        values.append((name, name, value))
    for value in ['', '0', '119S', '121s', '1m', '2M', '1H', '1D', '1W', 'h',
                  'infinite', 'deprecated', 'DEPRECATED', 'word', '-1', '1 h',
                  '2147483647', '2147483648', '4294967295', '4294967296',
                  '4294967297', '2147483647w', '18446744073709551616']:
        group = ('range-wide-lease' if any(c.isdigit() for c in value) and len(value)>8
                 else 'range-infinite-deprecated' if value in ('infinite','deprecated','DEPRECATED')
                 else 'range-lease-grammar')
        values.append((group, 'lease-'+str(len(values)), '10.77.0.10,10.77.0.14,'+value))
    for value in [
        '10.77.0.10,10.77.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.200',
        '10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0,600',
        '10.77.0.10,10.77.0.14,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.0.255.0',
        '10.77.0.10,10.78.0.14,255.255.255.0',
        '10.77.0.10,10.77.0.14,10.77.0.255',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600,extra',
        '10.77.0.10,static', '10.77.0.10,proxy',
    ]:
        values.append(('range-mask-grammar', 'mask-'+str(len(values)), value))
    for value in [
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255',
        '10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600',
    ]:
        values.append(('range-broadcast-grammar', 'broadcast-'+str(len(values)), value))
    for value in ['10.77.0.10', 'bad', '10.77.0.10,broken', '10.77.0.10,10.77.0.14,1.2.3',
                  '::,constructor:br-lan,ra-stateless', '2001:db8::10,2001:db8::20',
                  '0.0.0.0,255.255.255.255', '0.0.0.0,255.255.255.255,0.0.0.0']:
        values.append(('range-invalid','invalid-'+str(len(values)),value))
    for value in [
        '2001:db8::10,2001:db8::20',
        '::,constructor:br-lan,ra-stateless',
        '::,ra-only',
    ]:
        values.append(('range-ipv6', 'ipv6-'+str(len(values)), value))
    for value in [
        '0.0.0.0,255.255.255.255',
        '0.0.0.0,255.255.255.255,0.0.0.0',
        '10.77.0.10,10.77.0.14,255.255.255.0,10.77.0.255,600,extra',
    ]:
        values.append(('range-full-address-space', 'full-'+str(len(values)), value))
    cases = []
    for group, name, value in values:
        case = {'name': group+'--'+name, 'group': group, 'ranges': [value], 'events': []}
        cases.append(case)
    # A repeated declaration must remain one configuration so C's prepend
    # order is observable by the parser driver.
    repeat = next(case for case in cases if case['name'] == 'range-repeat--first')
    repeat['ranges'] = ['10.77.0.10,10.77.0.14', '10.77.0.20,10.77.0.24']
    cases.remove(next(case for case in cases if case['name'] == 'range-repeat--second'))
    groups = {
        'range-basic': ['CFG-01', 'SELECT-03', 'LIFE-01'],
        'range-reverse': ['CFG-01'],
        'range-one-address': ['CFG-01', 'SELECT-03', 'SELECT-09'],
        'range-repeat': ['CFG-01'],
        'range-prefix-grammar': ['CFG-02', 'CFG-03', 'CFG-04', 'CFG-09'],
        'range-tags': ['CFG-03'],
        'range-filter-conjunction': ['CFG-03', 'SELECT-01'],
        'range-empty-selectors': ['CFG-04'],
        'range-lease-grammar': ['CFG-06'],
        'range-lease-wire': ['CFG-06', 'LEASE-01'],
        'range-infinite-deprecated': ['CFG-06', 'CFG-07'],
        'range-wide-lease': ['CFG-08'],
        'range-mask-grammar': ['CFG-05', 'CFG-09'],
        'range-broadcast-grammar': ['CFG-05', 'LEASE-02'],
        'range-invalid': ['CFG-09'],
        'range-ipv6': ['CFG-09'],
        'range-full-address-space': ['CFG-08', 'CFG-09'],
    }
    for case in cases:
        case['boundaries'] = groups.get(case['group'], [])
    return cases


def service_cases():
    def event(name, action='discover', **fields):
        defaults = {'discover': 2, 'select': 5, 'renew': 5, 'rebind': 5, 'bootp': 0,
                    'decline': None, 'release': None}
        fields.setdefault('expect_status', defaults.get(action))
        return dict(id=name, action=action, flags=0x8000, **fields)
    def row(name, ranges, events, extra='', boundaries=(), **fields):
        value = dict(name=name, group=name.split('--')[0], ranges=ranges, events=events,
                     extra=extra, boundaries=list(boundaries))
        value.update(fields)
        return value

    yield row('range-basic--dora', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'), event('ack', 'select', address='assigned'),
               event('release', 'release', address='assigned')],
              boundaries=['CTX-01', 'CTX-02', 'SELECT-03', 'SELECT-09', 'LIFE-01', 'LIFE-02', 'LIFE-03'])
    yield row('range-reverse--offer', ['10.77.0.14,10.77.0.10,255.255.255.0,600'],
              [event('offer')], boundaries=['CFG-01'])
    yield row('range-one-address--exhaust', ['10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('first'), event('ack', 'select', address='assigned'), event('exhausted', client=2, expect_status=None)],
              boundaries=['CFG-01', 'SELECT-03', 'SELECT-08', 'SELECT-09'])
    for name, tail in [('absent',''),('empty',','),('deprecated',',deprecated'),('infinite',',infinite'),
                       ('minimum',',0'),('wide',',4294967297'),
                       ('signed-boundary', ',2147483648'), ('maximum-finite', ',4294967294')]:
        yield row('range-lease-wire--'+name, ['10.77.0.10,10.77.0.14'+tail],
                  [event('offer'), event('commit', 'select', address='assigned')],
                  boundaries=['CFG-06', 'CFG-07', 'CFG-08', 'LEASE-01'])
    yield row('range-static--known-unknown', ['10.77.0.0,static,255.255.255.0,600'],
              [event('known'), event('ack', 'select', address='10.77.0.40'), event('unknown', client=2, expect_status=None)],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n',
              boundaries=['SELECT-04', 'SELECT-05', 'SELECT-08'])
    yield row('range-proxy--ordinary-pxe', ['10.77.0.0,proxy,255.255.255.0,600'],
              [event('ordinary', expect_status=None), event('pxe', packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]}, prl=[43, 60, 224])],
              'pxe-service=0,Range fixture,boot.bin\n', boundaries=['SELECT-06', 'SELECT-07'])
    yield row('range-tag-priority--matched', ['10.77.0.10,10.77.0.10,255.255.255.0,600',
                                           'tag:selected,set:chosen,10.77.0.20,10.77.0.20,255.255.255.0,600'],
              [event('without-tag'), event('with-tag', packet={'extra': [[60, b'Matrix'.hex()]]}, prl=[224])],
              'dhcp-vendorclass=set:selected,Matrix\ndhcp-option=tag:chosen,224,2\n',
              boundaries=['SELECT-01', 'SELECT-02', 'LEASE-02'])
    yield row('range-filter-conjunction--negative',
              ['tag:known,net:br-lan,tag:!blocked,10.77.0.10,10.77.0.11,255.255.255.0,600',
               '10.77.0.20,10.77.0.21,255.255.255.0,600'],
              [event('untagged'), event('known', packet={'extra': [[60, b'Matrix'.hex()]]})],
              'dhcp-vendorclass=set:known,Matrix\n', boundaries=['CFG-03', 'SELECT-01'])
    yield row('range-set-tag-stage--options',
              ['tag:selected,set:chosen,10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('matched', packet={'extra': [[60, b'Matrix'.hex()]]}, prl=[224])],
              'dhcp-vendorclass=set:selected,Matrix\ndhcp-option=tag:chosen,224,2\n',
              boundaries=['SELECT-02', 'LEASE-02'])
    for prefix in ['red', 'set:red']:
        yield row('range-legacy-tag--'+prefix.replace(':', '-'),
                  [prefix+',10.77.0.10,10.77.0.10,255.255.255.0,600'],
                  [event('selected', prl=[224, 225])],
                  'dhcp-option=tag:red,224,2\ntag-if=tag:red,set:ready\ndhcp-option=tag:ready,225,3\n',
                  boundaries=['CFG-03', 'SELECT-02'])
    yield row('range-legacy-tag--quoted-set-prefix',
              ['"set:red",10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('literal-tag', prl=[224])], 'dhcp-option=tag:set:red,224,2\n',
              boundaries=['CFG-02', 'CFG-03', 'SELECT-02'])
    yield row('range-set-tag-stage--cannot-match-self',
              ['tag:chosen,set:chosen,10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('unmatched', expect_status=None)], boundaries=['SELECT-01', 'SELECT-02'])
    for negative in ['!', '#']:
        yield row('range-filter-conjunction--negate-'+str(ord(negative)),
                  ['tag:known,tag:'+negative+'blocked,net:br-lan,10.77.0.10,10.77.0.10,255.255.255.0,600'],
                  [event('unmatched', expect_status=None),
                   event('matching', packet={'extra': [[60, b'Known'.hex()]]}),
                   event('blocked', expect_status=None, packet={'extra': [[60, b'KnownBlocked'.hex()]]})],
                  'dhcp-vendorclass=set:known,Known\ndhcp-vendorclass=set:blocked,Blocked\n',
                  boundaries=['CFG-03', 'SELECT-01'])
    yield row('range-derived-mask--offer', ['10.77.0.10,10.77.0.14'], [event('offer')],
              boundaries=['CTX-01', 'CTX-02'])
    yield row('range-inconsistent-derived--none', ['10.77.0.10,10.78.0.14'], [event('offer', expect_status=None)],
              boundaries=['CTX-01', 'CTX-06'])
    yield row('range-mask-broadcast--explicit-zero', ['10.77.0.10,10.77.0.14,255.255.255.0,0.0.0.0,600'],
              [event('offer', prl=[1, 3, 28, 51, 58, 59])], boundaries=['CTX-02', 'LEASE-02'])
    yield row('range-mask-broadcast--fallback-and-no-prl', ['10.77.0.10,10.77.0.14,255.255.255.128,600'],
              [event('offer', prl=[1, 3, 28, 51, 58, 59]), event('no-prl', omit_prl=True)],
              boundaries=['CTX-02', 'LEASE-02'])
    yield row('range-no-context--excluded-ingress', ['10.77.0.10,10.77.0.14'],
              [event('ignored', expect_status=None)], extra='no-dhcp-interface=br-lan\n', boundaries=['CTX-06'])
    for suffix in ['', ',0.0.0.0']:
        yield row('range-full-address-space--'+('derived' if not suffix else 'zero-mask'),
                  ['0.0.0.0,255.255.255.255'+suffix], [event('no-context', expect_status=None)],
                  boundaries=['CFG-09', 'CTX-06'])
    yield row('range-interface-aliases--first-local', ['10.77.0.10,10.77.0.14'], [event('offer')],
              server_aliases=['10.77.0.3'], boundaries=['CTX-03', 'CTX-04'])
    yield row('range-interface-aliases--explicit-secondary', ['10.77.0.10,10.77.0.14'],
              [event('offer', expect_server='10.77.0.3')], server_aliases=['10.77.0.3'],
              secondary_only=True, boundaries=['CTX-03'])
    yield row('range-address-update--mask-and-restore', ['10.77.0.130,10.77.0.131'],
              [event('full-mask'),
               event('smaller-mask', 'network', commands=[['addr', 'del', '10.77.0.1/24', 'dev', 'br-lan'],
                                                        ['addr', 'add', '10.77.0.1/25', 'dev', 'br-lan']]),
               event('retained-guessed-mask'),
               event('restore-mask', 'network', commands=[['addr', 'del', '10.77.0.1/25', 'dev', 'br-lan'],
                                                        ['addr', 'add', '10.77.0.1/24', 'dev', 'br-lan']]),
               event('restored')], boundaries=['CTX-01', 'CTX-04'])
    yield row('range-context-order--two-pools',
              ['10.77.0.20,10.77.0.21,255.255.255.0,600', '10.77.0.10,10.77.0.11,255.255.255.0,600'],
              [event('first'), event('second', client=2)], boundaries=['CTX-03', 'SELECT-10'])
    yield row('range-multi-interface--guest', ['10.77.0.10,10.77.0.14'],
              [event('lan'), event('guest', client=2, guest=True)], two_interfaces=True,
              boundaries=['CTX-04', 'CTX-06'])
    yield row('range-remote-selectors--link-selection',
              ['10.77.0.10,10.77.0.14,255.255.255.0,600',
               '10.78.0.10,10.78.0.14,255.255.255.0,600',
               '10.79.0.10,10.79.0.14,255.255.255.0,600'],
              [event('option118', relay=True, packet={'giaddr': '10.77.0.2',
                      'extra': [[118, socket.inet_aton('10.78.0.0').hex()]]}),
               event('link-precedes118', relay=True, packet={'giaddr': '10.77.0.2',
                      'extra': [[118, socket.inet_aton('10.78.0.0').hex()], [82, '05040a4f0000']]}),
               event('forced-unknown', relay=True, expect_status=None, packet={'giaddr': '10.77.0.2',
                      'extra': [[118, socket.inet_aton('10.80.0.0').hex()]]})],
              boundaries=['CTX-05', 'SELECT-10'])
    yield row('range-remote-classful--fallback', ['10.78.0.10,10.78.0.14'],
              [event('relay', relay=True, packet={'giaddr': '10.77.0.2',
                       'extra': [[118, socket.inet_aton('10.78.0.0').hex()]]})], boundaries=['CTX-05'])
    yield row('range-requested-address--eligible', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('discover'), event('requested', 'select', address='10.77.0.12')], boundaries=['SELECT-04'])
    yield row('range-reserved-and-leases--skip', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('first'), event('ack', 'select', address='assigned'), event('second', client=2), event('decline', 'decline', address='assigned'),
               event('after-decline'), event('commit-new', 'select', address='assigned'),
               event('release', 'release', address='assigned'), event('after-release', client=2)],
              'dhcp-host='+dhcp.mac(3)+',10.77.0.11\n', boundaries=['SELECT-04', 'SELECT-08', 'SELECT-09'])
    yield row('range-narrow-priority--static',
              ['10.77.0.10,10.77.0.14,255.255.255.0,600', '10.77.0.0,static,255.255.255.0,600'],
              [event('known', client=1, address='10.77.0.40')],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n', boundaries=['SELECT-05', 'LEASE-03'])
    yield row('range-bootp-static--known', ['10.77.0.0,static,255.255.255.0,600'],
              [event('bootp', 'bootp')], 'dhcp-host='+dhcp.mac(1)+',10.77.0.40\n',
              boundaries=['SELECT-06'])
    yield row('range-bootp-dynamic--permission', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('bootp', 'bootp')], 'bootp-dynamic\n', boundaries=['SELECT-06'])
    for mode in ['static', 'proxy']:
        yield row('range-bootp-dynamic--'+mode+'-does-not-allocate',
                  ['10.77.0.0,'+mode+',255.255.255.0,600'],
                  [event('unknown', 'bootp', expect_status=None)], 'bootp-dynamic\n', boundaries=['SELECT-06'])
    yield row('range-mixed-proxy--head', ['10.77.0.0,proxy,255.255.255.0,600',
                                          '10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('ordinary', expect_status=None), event('pxe', packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]})],
              'pxe-service=0,Range fixture,boot.bin\n', boundaries=['SELECT-07', 'SELECT-10'])
    for proxy_first in [False, True]:
        ranges = ['tag:allowed,10.77.0.0,proxy,255.255.255.0,600',
                  '10.77.0.10,10.77.0.14,255.255.255.0,600']
        if not proxy_first:
            ranges.reverse()
        yield row('range-mixed-proxy--tagged-'+('head' if proxy_first else 'tail'), ranges,
                  [event('allowed-pxe', packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]}),
                   event('unmatched-pxe', client=2, expect_status=None if proxy_first else 2,
                         packet={'extra': [[60, b'PXEClient'.hex()], [93, '0000']]})],
                  'dhcp-mac=set:allowed,'+dhcp.mac(1)+'\npxe-service=0,Range fixture,boot.bin\n',
                  boundaries=['SELECT-07'])
    for prefix, expected in [('192.0.2', None), ('10.77.0', 2), ('172.16.0', 2)]:
        for last in [0, 255]:
            address = prefix+'.'+str(last)
            yield row('range-class-c-ends--'+address,
                      [address+','+address+',255.255.255.0,600'],
                      [event('offer', expect_status=expected)],
                      server_aliases=[] if prefix == '10.77.0' else [prefix+'.1'], boundaries=['SELECT-08'])
    yield row('range-selecting-context-chain--server-id',
              ['10.77.0.10,10.77.0.11,255.255.255.0,600', '10.77.0.20,10.77.0.21,255.255.255.0,600'],
              [event('selected', 'select', address='10.77.0.20', server_id='10.77.0.1')],
              boundaries=['SELECT-10'])
    yield row('range-selecting-context-chain--consumed-prefix',
              ['10.77.0.10,10.77.0.11,255.255.255.0,600',
               '10.78.0.10,10.78.0.11,255.255.255.0,600',
               '10.79.0.10,10.79.0.11,255.255.255.0,600'],
              [event('previous-pool', 'select', address='10.79.0.10', server_id='10.78.0.1', expect_status=6),
               event('later-pool', 'select', address='10.78.0.10', server_id='10.79.0.1'),
               event('selected-pool', 'select', address='10.79.0.10', server_id='10.79.0.1'),
               event('tftp-alias', 'select', client=2, address='10.77.0.10', server_id='10.80.0.1', expect_status=6)],
              server_aliases=['10.78.0.1', '10.79.0.1', '10.80.0.1'],
              extra='enable-tftp\ntftp-root=/m2\n', boundaries=['SELECT-10'])
    yield row('range-identity-seed--extended-client', ['10.77.0.10,10.77.0.24,255.255.255.0,600'],
              [event('hardware'),
               event('zero-hardware', packet={'htype': 0, 'hlen': 0, 'chaddr': '', 'extra': [[61, '001122334455']]}),
               event('alternate-client-id', packet={'htype': 0, 'hlen': 0, 'chaddr': '', 'extra': [[61, '0066778899aa']]})],
              boundaries=['SELECT-03'])
    yield row('range-host-and-client-lease--floor', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('host', packet={'extra': [[50, socket.inet_aton('10.77.0.10').hex()]]})],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.10,60\n', boundaries=['LEASE-01'])
    yield row('range-host-and-client-lease--client-floor', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('shortened', expect_lease=120, packet={'extra': [[51, (60).to_bytes(4, 'big').hex()]]}),
               event('host-override', expect_lease=900)],
              'dhcp-host='+dhcp.mac(1)+',10.77.0.10,900\n', boundaries=['LEASE-01'])
    yield row('range-restart-renew--existing', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'), event('ack', 'select', address='assigned'), event('restart', 'restart'),
               event('renew', 'renew', address='assigned')], boundaries=['LEASE-03'])
    yield row('range-restart-renew--static-outside-pool',
              ['10.77.0.10,10.77.0.14,255.255.255.0,600', '10.77.0.0,static,255.255.255.0,600'],
              [event('offer'), event('ack', 'select', address='assigned'), event('restart', 'restart'),
               event('renew', 'renew', address='assigned'), event('rebind', 'rebind', address='assigned')],
              extra='dhcp-host='+dhcp.mac(1)+',10.77.0.40\n', boundaries=['LEASE-03', 'SELECT-05'])
    yield row('range-restart-renew--wrong-network-rebind', ['10.77.0.10,10.77.0.14,255.255.255.0,600'],
              [event('offer'), event('ack', 'select', address='assigned'),
               event('new-pool', 'restart', replace_config=[
                   ['dhcp-range=10.77.0.10,10.77.0.14', 'dhcp-range=10.78.0.10,10.78.0.14']]),
               event('old-network', 'rebind', address='assigned', expect_status=6, timeout=4)],
              server_aliases=['10.78.0.1'], boundaries=['LEASE-03'])
    probe_range = ['10.77.0.10,10.77.0.10,255.255.255.0,600']
    yield row('range-probe-free--icmp', probe_range,
              [event('offer', timing='wait', icmp='request')], no_ping=False, boundaries=['PROBE-01'])
    yield row('range-probe-conflict--occupied', ['10.77.0.10,10.77.0.11,255.255.255.0,600'],
              [event('offer', packet={'extra': [[50, socket.inet_aton('10.77.0.10').hex()]]},
                     expect_address='10.77.0.11', icmp='conflict')],
              conflict_address='10.77.0.10', no_ping=False, boundaries=['PROBE-01', 'PROBE-08'])
    yield row('range-probe-bypass--no-ping', probe_range,
              [event('offer', timing='cached', icmp='none')], boundaries=['PROBE-01'])
    yield row('range-probe-bypass--loopback', ['127.0.0.10,127.0.0.10,255.0.0.0,600'],
              [event('offer', loopback=True, destination='127.0.0.1', timing='cached', icmp='none')],
              loopback_only=True, no_ping=False, boundaries=['PROBE-01'])
    yield row('range-probe-cache--same-client', probe_range,
              [event('discover', timing='wait', icmp='request'), event('repeat', timing='cached', icmp='none')],
              no_ping=False, boundaries=['PROBE-02', 'PROBE-08'])
    yield row('range-probe-cache--six-live-entry-bypass', ['10.77.0.10,10.77.0.20,255.255.255.0,600'],
              [event('client-'+str(index), client=index+1, timing='wait' if index < 6 else 'cached',
                     icmp='request' if index < 6 else 'none', expect_address='10.77.0.'+str(10+index),
                     packet={'extra': [[50, socket.inet_aton('10.77.0.'+str(10+index)).hex()]]})
               for index in range(7)], no_ping=False, boundaries=['PROBE-02'])
    yield row('range-probe-cache--sequential-owner-hash', probe_range,
              [event('first', timing='wait', icmp='request'),
               event('different-owner', client=2, expect_status=None, timeout=.6, icmp='none'),
               event('same-owner', timing='cached', icmp='none')],
              no_ping=False, extra='dhcp-sequential-ip\n', boundaries=['PROBE-02', 'PROBE-08'])
    for fault in ['socket', 'setup', 'send', 'receive']:
        yield row('range-probe-'+fault+'-failure--cache', probe_range,
                  [event('first', timing='cached' if fault in ('socket', 'setup') else 'wait',
                         icmp='conflict' if fault == 'receive' else 'none'),
                   event('cached', timing='cached', icmp='none')],
                  no_ping=False, fault_injection=fault,
                  conflict_address='10.77.0.10' if fault == 'receive' else None,
                  boundaries=['PROBE-03' if fault in ('socket', 'setup') else 'PROBE-04' if fault == 'send'
                              else 'PROBE-05'])
    yield row('range-probe-cancel--pending', probe_range,
              [event('signal-during-probe', cancel=True, timeout=5)], no_ping=False,
              boundaries=['PROBE-07'])
    yield row('range-probe-retry--eagain-exhaustion', probe_range,
              [event('exhausted-retry', timing='wait', icmp='none', coexistence=True),
               event('cached', timing='cached', icmp='none')], no_ping=False,
              fault_injection='send-eagain', extra='enable-tftp\ntftp-root=/m2/tftp\n',
              boundaries=['PROBE-04', 'PROBE-06', 'PROBE-07'])
    yield row('range-probe-progress--dns-tftp', probe_range,
              [event('offer', timing='wait', icmp='request', coexistence=True)], no_ping=False,
              extra='enable-tftp\ntftp-root=/m2/tftp\n', boundaries=['PROBE-06'])
    yield row('range-probe-progress--send-failure-dns-tftp', probe_range,
              [event('offer', timing='wait', icmp='none', coexistence=True)], no_ping=False,
              fault_injection='send', extra='enable-tftp\ntftp-root=/m2/tftp\n',
              boundaries=['PROBE-04', 'PROBE-06'])
    yield row('range-address-update--queued-pxe-after-probe',
              ['10.78.0.0,proxy,255.255.255.0,600',
               '10.77.0.10,10.77.0.10,255.255.255.0,600'],
              [event('ordinary-before-pxe', timing='wait', icmp='request', dual_listener=True)],
              no_ping=False, server_aliases=['10.78.0.1'],
              extra='pxe-service=0,Range fixture,boot.bin\nenable-tftp\ntftp-root=/m2\n',
              boundaries=['CTX-04', 'PROBE-06'])


def configuration(case):
    lines=['no-hosts','no-resolv','user=root','group=root','port=15353',
           'interface=br-lan','host-record=matrix.ready,8.8.8.8',
           'dhcp-authoritative','dhcp-leasefile=/m2/range.leases','pid-file=/m2/range.pid']
    if case.get('no_ping', True):
        lines.insert(5, 'no-ping')
    if case.get('secondary_only'):
        lines.remove('interface=br-lan')
        lines.append('listen-address=127.0.0.1,10.77.0.3')
    if case.get('loopback_only'):
        lines[lines.index('interface=br-lan')] = 'interface=lo'
    lines.extend('dhcp-range='+value for value in case['ranges'])
    if case.get('two_interfaces'):
        lines.extend(['interface=br-guest',
                      'dhcp-range=10.78.0.10,10.78.0.14,255.255.255.0,600'])
    return '\n'.join(lines)+'\n'+case.get('extra','')


def lease_snapshot(root, durations):
    file = root/'m2/range.leases'
    text = file.read_text() if file.exists() else ''
    return text, normalize_leases(text, durations)


def normalize_leases(text, durations):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0].isdigit():
            expires, address = int(fields[0]), fields[2]
            if expires:
                duration, sent, received = durations[address]
                assert int(sent)-1+duration <= expires <= int(received)+1+duration, (fields, durations[address])
                fields[0] = 'finite-'+str(duration)
            else:
                fields[0] = 'infinite'
        rows.append(fields)
    return sorted(rows)


def decode(raw, event):
    if raw['reply'] is None:
        return None
    original = bytes.fromhex(raw['reply'])
    assert original[0] == 2
    original_values = {code: bytes.fromhex(value) for code, value in options(original)}
    normalized_event = copy.deepcopy(event['packet'])
    if original_values.get(53) != b'\x05':
        normalized_event.pop('renew', None)
    normalized = comparable_reply(original, normalized_event)
    wire = bytes.fromhex(normalized)
    opts = options(wire)
    values = {code: bytes.fromhex(value) for code, value in opts}
    return {'wire': normalized, 'options': opts, 'status': values.get(53, b'\0')[0],
            'address': socket.inet_ntoa(wire[16:20]),
            'server': socket.inet_ntoa(values[54]) if 54 in values else None,
            'lease_time': int.from_bytes(values[51], 'big') if 51 in values else None,
            'destination': raw['destination']}


def guard_row(row, event, raw=None, icmp=None):
    errors = []
    response = row.get('response')
    if 'expect_status' in event:
        actual = response.get('status') if response else None
        if actual != event['expect_status']:
            errors.append('status')
    for source, target in [('expect_address', 'address'), ('expect_lease', 'lease_time'), ('expect_server', 'server')]:
        if source in event and (response is None or response[target] != event[source]):
            errors.append(target)
    if raw is not None and event.get('timing'):
        elapsed = raw['received']-raw['sent']
        if event['timing'] == 'wait' and not 1.5 <= elapsed <= 6:
            errors.append('probe-wait')
        if event['timing'] == 'cached' and not 0 <= elapsed < 1:
            errors.append('probe-cache')
    if icmp is not None and event.get('icmp'):
        requests = [packet for packet in icmp if packet['type'] == 8]
        replies = [packet for packet in icmp if packet['type'] == 0]
        if event['icmp'] == 'none' and requests:
            errors.append('unexpected-icmp')
        if event['icmp'] in ('request', 'conflict') and not requests:
            errors.append('missing-icmp')
        if event['icmp'] == 'conflict' and not any(packet['source'] == '10.77.0.10' for packet in replies):
            errors.append('missing-conflict-reply')
    if event.get('coexistence') and row.get('coexistence') != {'dns': True, 'tftp': True, 'before_dhcp': True}:
        errors.append('coexistence')
    return errors


def controls():
    """Mutate independent observations; each must trip a specific guard."""
    event = {'expect_status': 2, 'expect_address': '10.77.0.10', 'expect_lease': 600,
             'timing': 'wait', 'icmp': 'conflict', 'coexistence': True}
    row = {'response': {'status': 2, 'address': '10.77.0.10', 'lease_time': 600},
           'coexistence': {'dns': True, 'tftp': True, 'before_dhcp': True}}
    raw = {'sent': 100, 'received': 103}
    icmp = [{'type': 8}, {'type': 0, 'source': '10.77.0.10'}]
    assert not guard_row(row, event, raw, icmp)
    result = {}
    for key, bad_value in [('status', None), ('address', '10.77.0.11'), ('lease_time', 601)]:
        changed = copy.deepcopy(row)
        changed['response'][key] = bad_value
        assert guard_row(changed, event, raw, icmp), key
        result[key] = 'detected'
    for field in ['dns', 'tftp', 'before_dhcp']:
        changed = copy.deepcopy(row)
        changed['coexistence'][field] = False
        assert 'coexistence' in guard_row(changed, event, raw, icmp)
        result['coexistence-'+field] = 'detected'
    assert 'probe-wait' in guard_row(row, event, {'sent': 100, 'received': 100.01}, icmp)
    result['skipped-wait'] = 'detected'
    assert 'probe-cache' in guard_row(row, dict(event, timing='cached'), raw, icmp)
    result['missed-cache'] = 'detected'
    assert 'missing-icmp' in guard_row(row, event, raw, [])
    result['missing-icmp'] = 'detected'
    assert 'missing-conflict-reply' in guard_row(row, event, raw, [{'type': 8}])
    result['missing-conflict-reply'] = 'detected'
    assert 'unexpected-icmp' in guard_row(row, dict(event, icmp='none'), raw, icmp)
    result['unexpected-icmp'] = 'detected'
    baseline = {'status': 'ok', 'syntax': {'stdout': '', 'stderr': ''}, 'rows': [row], 'planned': 1}
    for kind in ['missing-row', 'wrong-diagnostic', 'leftover-pid', 'descriptor-leak']:
        changed = copy.deepcopy(baseline)
        if kind == 'missing-row':
            changed['rows'] = []
        elif kind == 'wrong-diagnostic':
            changed['syntax']['stderr'] = 'wrong'
        elif kind == 'leftover-pid':
            changed['pid_removed'] = False
        else:
            changed['fd_stable'] = False
        assert comparable(changed) != comparable(baseline)
        result[kind] = 'detected'
    return result


def start_daemon(root, side, case, stdout, stderr):
    argv = command(root, side, '-k', '-C', '/m2/range.conf')
    if case.get('fault_injection'):
        argv = [sys.executable, str(Path(__file__).resolve()), '--fault-exec', case['fault_injection'], *argv]
    process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
    deadline = time.monotonic()+4
    ready = False
    while process.poll() is None and time.monotonic() < deadline:
        try:
            ready = dhcp.dns_health()['records'][0]['data'] == '8.8.8.8'
            if ready:
                break
        except (socket.timeout, OSError):
            time.sleep(.01)
    return process, {'ready': ready, 'exit': process.poll()}


def exchange(network, event, xid, folder, daemon=None):
    spec = {'event': event, 'xid': xid}
    argv = [sys.executable, str(Path(__file__).resolve()), '--client']
    if not event.get('coexistence') and not event.get('cancel') and not event.get('dual_listener'):
        command_line = [*argv, json.dumps(spec)]
        if not event.get('loopback'):
            command_line = network.argv(*command_line)
        completed = subprocess.run(command_line, check=True, text=True,
                                   capture_output=True, timeout=event['timeout']+3)
        return json.loads(completed.stdout), None
    marker = folder/'sent.json'
    spec['sent_marker'] = str(marker)
    process = subprocess.Popen(network.argv(*argv, json.dumps(spec)), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        deadline = time.monotonic()+2
        while not marker.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError('DHCP client never reached send')
            time.sleep(.01)
        time.sleep(.15)
        assert process.poll() is None, 'DHCP completed before coexistence observations'
        if event.get('dual_listener'):
            for args in [['addr', 'del', '10.78.0.1/24', 'dev', 'br-lan'],
                         ['addr', 'add', '10.78.0.3/24', 'dev', 'br-lan']]:
                subprocess.run(['ip', *args], check=True, capture_output=True, timeout=3)
            changed_at = time.time()
            secondary = dhcp.wire_event({'id': 'queued-pxe', 'action': 'discover', 'client': 2,
                        'listener_port': 4011, 'source_port': 4011, 'timeout': 6, 'flags': 0x8000,
                        'packet': {'extra': [[60, b'PXEClient'.hex()], [93, '0000']]}}, {})
            secondary_spec = {'event': secondary, 'xid': xid+0x1000}
            queued = subprocess.Popen(network.argv(*argv, json.dumps(secondary_spec)),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      start_new_session=True)
            try:
                out, err = process.communicate(timeout=event['timeout']+3)
                assert process.returncode == 0, err
                raw = json.loads(out)
                out, err = queued.communicate(timeout=8)
                assert queued.returncode == 0, err
                pxe_raw = json.loads(out)
            finally:
                if queued.poll() is None:
                    stop(queued)
            pxe = decode(pxe_raw, secondary)
            save(folder/'dual-listener.json', {'address_changed_at': changed_at, 'pxe_event': secondary,
                                               'pxe_raw': pxe_raw, 'pxe': pxe})
            assert raw['sent'] < changed_at < pxe_raw['sent'] < raw['received'] <= pxe_raw['received']
            assert pxe and pxe['status'] == 2 and pxe['server'] == '10.78.0.3'
            return raw, {'queued_before_first_reply': True, 'reply_after_first': True, 'pxe': pxe}
        if event.get('cancel'):
            signalled = time.monotonic()
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(5)
            elapsed = time.monotonic()-signalled
            out, err = process.communicate(timeout=event['timeout']+2)
            assert process.returncode == 0, err
            raw = json.loads(out)
            save(folder/'cancellation.json', {'signal': 'SIGTERM', 'exit': daemon.returncode,
                                            'exit_after_signal_seconds': elapsed})
            return raw, {'exit_after_signal_seconds': elapsed, 'exit': daemon.returncode}
        dns = dhcp.dns_health()
        dns_at = time.time()
        output = network.exec(sys.executable, str(Path(dhcp.__file__).resolve()), '--client',
                              json.dumps({'event': {'action': 'tftp'}, 'xid': xid}))
        tftp = json.loads(output.stdout)
        tftp_at = time.time()
        out, err = process.communicate(timeout=event['timeout']+3)
        if process.returncode:
            raise AssertionError(('client failed', process.returncode, err))
        raw = json.loads(out)
        witness = {'dns': dns, 'dns_at': dns_at, 'tftp': tftp, 'tftp_at': tftp_at,
                   'sent': raw['sent'], 'received': raw['received']}
        save(folder/'coexistence.json', witness)
        verified = {'dns': dns['records'][0]['data'] == '8.8.8.8',
                    'tftp': tftp.get('reply') == (b'\0\3\0\1matrix-tftp').hex(),
                    'before_dhcp': raw['sent'] < dns_at <= tftp_at < raw['received']}
        return raw, verified
    finally:
        if process.poll() is None:
            stop(process)


def run(root, side, case, folder, syntax_only):
    folder.mkdir()
    text = configuration(case)
    (root/'m2/range.conf').write_text(text)
    (folder/'config').write_text(text)
    for name in ['range.leases', 'range.pid']:
        (root/'m2'/name).unlink(missing_ok=True)
    syntax = subprocess.run(command(root, side, '--test', '-C', '/m2/range.conf'), capture_output=True, timeout=5)
    result = {'status': 'failed', 'syntax': {'exit': syntax.returncode,
              'stdout': syntax.stdout.decode(errors='replace'), 'stderr': syntax.stderr.decode(errors='replace')},
              'rows': [], 'planned': len(case['events']), 'startup': None, 'guards': []}
    (folder/'syntax.stdout').write_bytes(syntax.stdout)
    (folder/'syntax.stderr').write_bytes(syntax.stderr)
    if syntax_only or case.get('planned_only'):
        result['status'] = 'ok' if syntax.returncode in (0, 1) else 'failed'
        if case.get('planned_only'):
            result.update(status='not-executed', execution='planned-only',
                          reason=case.get('incomplete_reason', 'injection unavailable'))
        save(folder/'observed.json', result)
        return result
    network = process = capture = None
    try:
        network = dhcp.setup_network(case)
        if not case.get('no_ping', True):
            network.exec(sys.executable, '-c',
                         'import sys;sys.path.insert(0,sys.argv[1]);from m2_dhcp_scenarios import make_client;'
                         'print(make_client({"id":200,"mac":"02:00:4d:35:44:c8"}))',
                         str(Path(__file__).resolve().parent))
            # Free targets need an L2 neighbour too: otherwise Linux only
            # broadcasts ARP and the intended ICMP packet never reaches the
            # capture.  The peer has no IP except the explicit conflict row.
            for last in range(10, 21):
                subprocess.run(['ip', 'neigh', 'replace', f'10.77.0.{last}', 'lladdr',
                                '02:00:4d:35:44:c8', 'nud', 'permanent', 'dev', 'br-lan'], check=True)
        if case.get('conflict_address'):
            network.exec('ip', 'addr', 'add', case['conflict_address']+'/24', 'dev', 'm2c200')
        if any(event.get('coexistence') for event in case['events']):
            (root/'m2/tftp').mkdir(exist_ok=True)
            (root/'m2/tftp/probe.bin').write_bytes(b'matrix-tftp')
        if case.get('fault_injection'):
            save(folder/'fault-filter.json', {'kind': case['fault_injection'], 'machine': platform.machine(),
                                             'program': fault_program(case['fault_injection'])})
        capture = RangeCapture(folder)
        save(folder/'network.json', {'server': json.loads(subprocess.check_output(['ip', '-j', 'addr'])),
                                    'client': json.loads(network.exec('ip', '-j', 'addr').stdout)})
        with (folder/'stdout').open('wb') as stdout, (folder/'stderr').open('wb') as stderr:
            process, result['startup'] = start_daemon(root, side, case, stdout, stderr)
            if not result['startup']['ready']:
                raise AssertionError('service configuration did not start')
            result['identity'] = process_identity(root, process.pid)
            expected_sha = sha256(root/('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))
            assert result['identity']['sha256'] == expected_sha
            assigned, durations = {}, {}
            baseline, stable = settled_fds(process.pid, folder/'startup-fds.json')
            assert stable, 'startup descriptors did not settle'
            result['fd_samples'] = [baseline]
            for index, source_event in enumerate(case['events']):
                event_folder = folder/f'{index:03}'
                event_folder.mkdir()
                if source_event['action'] == 'restart':
                    ended = stop(process)
                    assert not ended['forced'] and ended['returncode'] == 0
                    for old, new in source_event.get('replace_config', []):
                        assert old in text
                        text = text.replace(old, new)
                    (root/'m2/range.conf').write_text(text)
                    (event_folder/'config').write_text(text)
                    process, ready = start_daemon(root, side, case, stdout, stderr)
                    assert ready['ready']
                    observed, event = {'restart': True}, source_event
                elif source_event['action'] == 'network':
                    for args in source_event['commands']:
                        subprocess.run(['ip', *args], check=True, capture_output=True, timeout=3)
                    save(event_folder/'network.json', json.loads(subprocess.check_output(['ip', '-j', 'addr'])))
                    time.sleep(.05)
                    observed, event = {'network_updated': True}, source_event
                else:
                    wire_source = copy.deepcopy(source_event)
                    if wire_source['action'] == 'bootp':
                        wire_source['action'] = 'discover'
                    event = dhcp.wire_event(wire_source, assigned)
                    if source_event.get('omit_prl'):
                        event['packet'].pop('prl', None)
                    if source_event['action'] == 'bootp':
                        event['packet']['kind'] = 0
                    event.setdefault('timeout', 8 if not case.get('no_ping', True) else 2)
                    before_health = dhcp.dns_health()
                    raw, coexistence = exchange(network, event, 0xb500+index, event_folder, process)
                    observed = decode(raw, event)
                    save(event_folder/'raw.json', raw)
                    time.sleep(.12)  # let the capture thread drain this packet's ICMP rows
                    packet_icmp = [item for item in capture.rows if raw['sent'] <= item['time'] <= raw['received']+.12]
                    save(event_folder/'icmp.json', packet_icmp)
                    if observed and observed['status'] in (0, 2, 5) and observed['address'] != '0.0.0.0':
                        assigned[str(event.get('client', 1))] = observed['address']
                        if observed['status'] == 5 and observed['lease_time'] is not None:
                            durations[observed['address']] = (observed['lease_time'], raw['sent'], raw['received'])
                lease_text, leases = lease_snapshot(root, durations)
                (event_folder/'leases').write_text(lease_text)
                row = {'id': event['id'], 'response': observed, 'leases': leases,
                       'health': before_health if source_event.get('cancel') else dhcp.dns_health()}
                if source_event.get('coexistence'):
                    row['coexistence'] = coexistence
                if source_event.get('dual_listener'):
                    row['dual_listener'] = coexistence
                if source_event.get('cancel'):
                    elapsed = coexistence['exit_after_signal_seconds']
                    assert coexistence['exit'] == 0
                    assert 1.5 < elapsed < 5 and observed and observed['status'] == 2
                    assert not leases
                    row['cancellation_verified'] = True
                elif source_event['action'] not in ('restart', 'network'):
                    errors = guard_row(row, source_event, raw, packet_icmp)
                    if errors:
                        result['guards'].append({'event': event['id'], 'errors': errors})
                result['rows'].append(row)
                if not source_event.get('cancel'):
                    count, stable = settled_fds(process.pid, event_folder/'fds.json', baseline)
                    result['fd_samples'].append(count)
                    if not stable:
                        result['guards'].append({'event': event['id'], 'errors': ['descriptor-leak']})
                save(folder/'observed.json', result)
            result['fd_stable'] = result['fd_samples'][-1] == result['fd_samples'][0]
            if not result['fd_stable']:
                result['guards'].append({'errors': ['descriptor-leak']})
            result['status'] = 'ok' if not result['guards'] else 'failed'
    except Exception as error:
        result['error'] = repr(error)
    finally:
        if capture is not None:
            capture.close()
        if process is not None:
            ended = stop(process)
            result.update(exit=process.returncode, forced=ended['forced'],
                          reaped=not Path(f'/proc/{process.pid}').exists())
        if network is not None:
            result['network_cleanup'] = network.close()
            if result['network_cleanup']['forced'] or result['network_cleanup']['returncode'] != -signal.SIGTERM:
                result['status'] = 'failed'
        result['interfaces_clean'] = [name for _, name in socket.if_nameindex()] == ['lo']
        result['pid_removed'] = not (root/'m2/range.pid').exists()
        if not result['interfaces_clean'] or not result['pid_removed'] or result.get('forced'):
            result['status'] = 'failed'
        if result.get('exit') != 0 or len(result['rows']) != result['planned']:
            result['status'] = 'failed'
        save(folder/'observed.json', result)
    return result


def comparable(observed):
    value=copy.deepcopy(observed)
    for stream in ['stdout','stderr']:
        value['syntax'][stream]=value['syntax'][stream].replace('dnsmasq-rs:','dnsmasq:')
    return {key:value.get(key) for key in ['status','syntax','startup','rows','exit','forced','reaped','interfaces_clean','pid_removed','fd_stable']}


def boundary_plan(cases):
    """Describe scheduled, planned-only and missing family boundaries."""
    rows = {}
    for boundary in BOUNDARY_IDS:
        selected = [case for case in cases if boundary in case.get('boundaries', [])]
        rows[boundary] = {
            'cases': [case['name'] for case in selected],
            'planned_only': [case['name'] for case in selected if case.get('planned_only')],
            'scheduled': bool(selected),
            'unexecuted': any(case.get('planned_only') for case in selected),
        }
    return {
        'schema': 'm5-dhcp-range-boundary-plan-v1',
        'boundaries': rows,
        'missing': [boundary for boundary, row in rows.items() if not row['scheduled']],
        'unexecuted': [boundary for boundary, row in rows.items() if row['unexecuted']],
        'planned_only': sorted({name for row in rows.values() for name in row['planned_only']}),
    }


def qualify_runs(runs, manifests, probe_tests, out):
    """Replay every frozen requirement from locally verified immutable runs."""
    from m5_option_matrix_archive import verify
    required = {}
    driver_sha = sha256(runs[0]/'driver.py')
    archives = {}
    for manifest in manifests:
        report = json.loads(manifest.read_text())
        archive = manifest.with_name(report['archive_name'])
        verified = verify(archive, manifest, None)
        archives[report['prefix']] = (report, verified)
    identities, completed, source_commits = set(), {}, set()
    for run_dir in runs:
        report, verified = archives[run_dir.name]
        # The plain review copy must still match the independently verified
        # tar, including driver/config/raw packet and terminal observations.
        for name, entry in report['entries'].items():
            if entry['kind'] == 'file' and 'rootfs-overlay' not in Path(name).parts:
                assert sha256(run_dir/name) == entry['sha256'], (run_dir, name)
        result = json.loads((run_dir/'result.json').read_text())
        plan = json.loads((run_dir/'plan.json').read_text())
        assert result['passed'] and result['comparison_executed'] and not result['failures']
        assert not result.get('unexecuted')
        assert result['c_sha256'] == STOCK_SHA256
        assert result['tool_sha256'] == driver_sha == sha256(run_dir/'driver.py')
        for name, expected in result['dependencies'].items():
            assert sha256(run_dir/'driver-dependencies'/name) == expected, name
        assert json.loads((run_dir/'negative-controls.json').read_text()) == controls()
        identities.add(result['rust_sha256'])
        source_commits.add(result['source_commit'])
        assert [row['name'] for row in result['cases']] == [case['name'] for case in plan]
        for case in plan:
            required.setdefault(case['name'], case)
            observed = {}
            for side in ['c', 'rust']:
                folder = run_dir/case['name']/side
                assert (folder/'config').read_text() == configuration(case)
                observed[side] = json.loads((folder/'observed.json').read_text())
                value = observed[side]
                assert value['status'] == 'ok' and len(value['rows']) == len(case['events'])
                if not case['events']:
                    continue
                assert value['identity']['sha256'] == (STOCK_SHA256 if side == 'c' else result['rust_sha256'])
                assert not value['guards'] and value['fd_stable']
                assert value['reaped'] and value['interfaces_clean'] and value['pid_removed']
                assert not value['forced'] and value['exit'] == 0
                assert not value['network_cleanup']['forced'] and value['network_cleanup']['returncode'] == -15
                assigned, durations = {}, {}
                for index, (source_event, row) in enumerate(zip(case['events'], value['rows'])):
                    event_folder = folder/f'{index:03}'
                    assert row['id'] == source_event['id']
                    action = source_event['action']
                    if action not in ('network', 'restart'):
                        wire_source = copy.deepcopy(source_event)
                        if action == 'bootp':
                            wire_source['action'] = 'discover'
                        event = dhcp.wire_event(wire_source, assigned)
                        if source_event.get('omit_prl'):
                            event['packet'].pop('prl', None)
                        if action == 'bootp':
                            event['packet']['kind'] = 0
                        raw = json.loads((event_folder/'raw.json').read_text())
                        assert request(event['packet'], 0xb500+index).hex() == raw['request']
                        decoded = decode(raw, event)
                        assert decoded == row['response']
                        icmp = json.loads((event_folder/'icmp.json').read_text())
                        if source_event.get('cancel'):
                            cancelled = json.loads((event_folder/'cancellation.json').read_text())
                            assert cancelled['exit'] == 0 and 1.5 < cancelled['exit_after_signal_seconds'] < 5
                            assert decoded and decoded['status'] == 2 and row['cancellation_verified']
                        else:
                            assert not guard_row(row, source_event, raw, icmp)
                        if source_event.get('coexistence'):
                            witness = json.loads((event_folder/'coexistence.json').read_text())
                            assert witness['sent'] == raw['sent'] and witness['received'] == raw['received']
                            assert raw['sent'] < witness['dns_at'] <= witness['tftp_at'] < raw['received']
                            assert witness['dns']['records'][0]['data'] == '8.8.8.8'
                            assert witness['tftp']['reply'] == (b'\0\3\0\1matrix-tftp').hex()
                        if decoded and decoded['status'] in (0, 2, 5) and decoded['address'] != '0.0.0.0':
                            assigned[str(event.get('client', 1))] = decoded['address']
                            if decoded['status'] == 5 and decoded['lease_time'] is not None:
                                durations[decoded['address']] = (decoded['lease_time'], raw['sent'], raw['received'])
                    assert row['leases'] == normalize_leases((event_folder/'leases').read_text(), durations)
            assert comparable(observed['c']) == comparable(observed['rust'])
            completed[case['name']] = {'run': str(run_dir), 'events': len(case['events']),
                                       'archive_sha256': verified['archive_sha256']}
    assert len(identities) == len(source_commits) == 1
    checklist = json.loads(Path(__file__).with_name('m5_dhcp_range_checklist.json').read_text())
    tests = probe_tests.read_text()
    for boundary in checklist['boundaries']:
        for name in boundary.get('unit_guards', []):
            assert 'dhcp::probe::tests::'+name+' ... ok' in tests, name
        required_cases = boundary['case_catalogue']
        missing = [name for name in required_cases if name not in completed]
        boundary.update(status='passed' if not missing else 'blocked',
                        missing_cases=missing,
                        evidence=[completed[name] | {'case': name} for name in required_cases if name in completed])
    blocked = [boundary['id'] for boundary in checklist['boundaries'] if boundary['status'] == 'blocked']
    checklist.update(status='qualified' if not blocked else 'partial', checked=len(checklist['boundaries'])-len(blocked),
                     blocked=blocked,
                     source_commit=next(iter(source_commits)), rust_sha256=next(iter(identities)),
                     tool_sha256=driver_sha, cases=len(completed),
                     events_per_side=sum(case['events'] for case in completed.values()),
                     unit_evidence={'path': str(probe_tests), 'sha256': sha256(probe_tests)})
    save(out, checklist)
    return {'qualified': checklist['status'] == 'qualified', 'status': checklist['status'],
            'blocked': blocked, 'boundaries': checklist['checked'], 'cases': len(completed),
            'events_per_side': checklist['events_per_side'], 'source_commit': checklist['source_commit']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path);parser.add_argument('--rust',type=Path)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--side',choices=['c','rust','both'],default='both')
    parser.add_argument('--syntax',action='store_true');parser.add_argument('--case',action='append');parser.add_argument('--source-commit')
    parser.add_argument('--qualify-runs', nargs='+', type=Path)
    parser.add_argument('--archive-manifest', action='append', type=Path, default=[])
    parser.add_argument('--probe-tests', type=Path)
    args=parser.parse_args()
    if args.qualify_runs:
        print(json.dumps(qualify_runs(args.qualify_runs, args.archive_manifest, args.probe_tests, args.out)))
        return 0
    assert args.image_root is not None and args.rust is not None
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert [name for _,name in socket.if_nameindex()]==['lo'];assert 'private' in args.out.resolve().parts and not args.out.exists()
    root=prepare(args.image_root,None,args.out/'image',args.rust);(root/'m2').chmod(0o777)
    (args.out/'driver.py').write_bytes(Path(__file__).read_bytes())
    save(args.out/'negative-controls.json', controls())
    checklist_path = Path(__file__).with_name('m5_dhcp_range_checklist.json')
    if checklist_path.exists():
        (args.out/'checklist.json').write_bytes(checklist_path.read_bytes())
    cases=syntax_cases() if args.syntax else list(service_cases())
    if args.case:cases=[case for case in cases if case['name'] in args.case or case['group'] in args.case]
    assert cases;save(args.out/'plan.json',cases)
    selected_plan = boundary_plan(cases)
    # Keep the complete CFG+runtime catalogue alongside a filtered run.  A
    # syntax-only invocation therefore records which service rows were not
    # selected without pretending that parser checks covered them.
    catalog = boundary_plan(syntax_cases() + list(service_cases()))
    selected_plan['catalog'] = catalog
    save(args.out/'boundary-plan.json', selected_plan)
    result={'c_sha256':STOCK_SHA256,'rust_sha256':sha256(args.rust),'source_commit':args.source_commit,
            'tool_sha256':sha256(__file__),'comparison_executed':args.side=='both','cases':[],'failures':[],
            'unexecuted': [], 'dependencies': {
                name: sha256(Path(__file__).with_name(name)) for name in
                ['m5_option_matrix_dhcp.py', 'm5_dhcp_tags_options.py', 'm2_dhcp_scenarios.py',
                 'test_single_poll_service.py', 'dns_service_probe.py', 'm2_rootfs.py',
                 'dhcp_boot_service_diff.py', 'run_isolated.sh']}}
    (args.out/'driver-dependencies').mkdir()
    for name in result['dependencies']:
        (args.out/'driver-dependencies'/name).write_bytes(Path(__file__).with_name(name).read_bytes())
    for case in cases:
        folder=args.out/case['name'];folder.mkdir();observations={}
        for side in ['c','rust'] if args.side=='both' else [args.side]:observations[side]=run(root,side,case,folder/side,args.syntax)
        errors=[]
        if any(row['status'] == 'not-executed' for row in observations.values()):
            result['unexecuted'].append(case['name'])
        if any(row['status']!='ok' for row in observations.values()):errors.append('failed-side')
        if args.side == 'both' and comparable(observations['c']) != comparable(observations['rust']):
            errors.append('difference')
        result['cases'].append({'name': case['name'], 'group': case['group'], 'errors': errors})
        if errors:result['failures'].append(case['name'])
        save(args.out/'result.json',result)
    result['passed']=not result['failures'];save(args.out/'result.json',result)
    print(json.dumps({'passed':result['passed'],'cases':len(cases),'failures':result['failures']}));return int(not result['passed'])


if __name__ == '__main__':
    if len(sys.argv) >= 4 and sys.argv[1] == '--fault-exec':
        fault_exec(sys.argv[2], sys.argv[3:])
    elif len(sys.argv) == 3 and sys.argv[1] == '--client':
        print(json.dumps(client_worker(json.loads(sys.argv[2]))))
    elif sys.argv[1:] == ['--controls']:
        print(json.dumps(controls()))
    else:
        raise SystemExit(main())
