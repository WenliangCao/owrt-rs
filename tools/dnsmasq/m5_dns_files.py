#!/usr/bin/env python3
"""Exact-image resolver/server file lifecycle differential. Run in run_isolated.sh.

Each side uses the shared read-only image plus a disposable overlay. Config,
file mutations, replies, upstream packets and cleanup state are retained under
private evidence. C supplies runtime expectations; unexercised checklist rows
remain explicitly open. This driver never operates a physical router.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import json
import os
import platform
import re
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import exact_read, read_name, semantics
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, process_identity, sha256
from m5_option_matrix import Upstream, descendants, normalized_text, query


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def probe(label, host=None, **extra):
    return dict(op='query', id=label, name=host or label + '.files.test', **extra)


def write(path, text, **extra):
    return dict(op='write', path=path, text=text, **extra)


def signal_reload():
    return {'op': 'signal'}


def scenarios():
    cases = []
    def add(ident, checks, files, actions, config='', **extra):
        cases.append(dict(id=ident, checks=checks.split(','), files=files, actions=actions, config=config, **extra))
    r1, r2 = 'nameserver 127.0.0.2\n', 'nameserver 127.0.0.3\n'
    initial = {'resolv': r1}
    add('inplace-rename-delete-empty', 'WATCH-04,RSLV-05,RSLV-06,STATE-05', initial,
        [probe('initial'), write('resolv', r2), probe('inplace'), write('resolv', r1, atomic=True),
         probe('renamed'), {'op': 'unlink', 'path': 'resolv'}, probe('deleted'), write('resolv', ''),
         probe('empty'), write('resolv', 'invalid row\n'), probe('invalid'), write('resolv', r2), probe('recovered')])
    add('missing-leaf', 'WATCH-01,RSLV-02', {}, [probe('missing'), write('resolv', r1), probe('created')])
    add('missing-parent', 'WATCH-01,FAIL-01', {}, [], 'resolv-file=/m2/files/missing/resolv\n', expected_start=False)
    add('missing-parent-no-poll', 'WATCH-01,FAIL-01', {}, [], 'resolv-file=/m2/files/missing/resolv\nno-poll\n', default_resolv=False, expected_start=False)
    add('ignored-missing-parent', 'CFG-02,WATCH-01', {}, [probe('inline')],
        'no-resolv\nresolv-file=/m2/files/missing/resolv\nserver=127.0.0.2\n')
    for mode in ('no-poll', 'poll'):
        add(mode + '-signal', 'NPOLL-01,NPOLL-02', initial,
            [probe('before'), write('resolv', r2, hold_open=True), signal_reload(), probe('after-hup'),
             {'op': 'close-file', 'path': 'resolv'}, probe('after-close'), signal_reload(), probe('second-hup')],
            'no-poll\n' if mode == 'no-poll' else '')
    add('no-poll-multiple', 'CFG-02', initial, [],
        'resolv-file=/m2/files/second\nno-poll\n', expected_test=1, expected_start=False)
    add('no-poll-multiple-no-resolv', 'CFG-02', initial, [probe('explicit')],
        'resolv-file=/m2/files/second\nno-poll\nno-resolv\nserver=127.0.0.2\n')
    add('newest-file-and-ties', 'CFG-01,RSLV-01',
        {'resolv': {'text': r1, 'mtime': 1700000010}, 'second': {'text': r2, 'mtime': 1700000020}},
        [probe('newest'), write('resolv', r1, mtime=1700000015), probe('older-write'),
         write('resolv', r1, mtime=1700000020), probe('equal-newest-option'),
         write('resolv', r1, atomic=True, mtime=1700000030), probe('replaced-inode')],
        'resolv-file=/m2/files/second\n')
    for leaf in ('.hidden', 'backup~', '#backup#'):
        add('filtered-' + leaf.replace('#', 'hash').replace('.', 'dot').replace('~', 'tilde'),
            'WATCH-05', {leaf: r1}, [probe('initial'), write(leaf, r2), probe('ignored-write')],
            f'resolv-file=/m2/files/{leaf}\n', default_resolv=False)
    add('relative-name', 'WATCH-03', {'resolv': r1}, [], 'resolv-file=resolv\n', default_resolv=False, expected_start=False)
    add('relative-dot-name', 'WATCH-03', {'resolv': r1}, [probe('relative-missing')],
        'resolv-file=./missing\n', default_resolv=False)
    add('symlink-relative', 'WATCH-02,WATCH-06', {'target': r1, 'resolv': {'symlink': 'target'}},
        [probe('initial'), write('target', r2), probe('target-write'), write('other', r1),
         {'op': 'symlink', 'path': 'resolv', 'target': 'other'}, probe('retarget-no-event'),
         write('other', 'nameserver 127.0.0.4\n'), probe('new-target-no-watch'), write('target', r1), probe('old-target-trigger')])
    add('symlink-absolute', 'WATCH-02', {'target': r1, 'resolv': {'symlink': '/m2/files/target'}},
        [probe('initial'), write('target', r2), probe('target-write')])
    add('resolver-token-matrix', 'RSLV-03,RSLV-04', {'resolv': ''},
        [action for i, text in enumerate(['server 127.0.0.2\r\n', 'nameserver 127.0.0.2#bad\n',
          ' nameserver\t127.0.0.3 # good\n', 'Nameserver 127.0.0.2\n', 'nameserver ::1%lo\n',
          'nameserver ::1%unknown\n', 'nameserver 127.0.0.2%lo\n']) for action in
         (write('resolv', text), probe('token-' + str(i)))])
    add('servers-file-life', 'SFILE-01,SFILE-02,SFILE-03,SFILE-04,SFILE-06',
        {'resolv': r1, 'servers': 'server=/file.test/127.0.0.3\nserver=/local.test/\n'},
        [probe('file-initial', 'initial.file.test'), probe('local-initial', 'initial.local.test'),
         write('servers', 'server=/file.test/127.0.0.4\naddress=/bad/1.2.3.4\nserver=/new.test/\n'),
         probe('file-before-hup', 'before.file.test'), signal_reload(), probe('file-after-hup', 'after.file.test'),
         probe('local-removed', 'removed.local.test'), probe('new-local', 'new.test'),
         {'op': 'unlink', 'path': 'servers'}, signal_reload(), probe('missing-keeps-file', 'missing.file.test'),
         write('servers', ''), signal_reload(), probe('empty-removes-file', 'empty.file.test')],
        'servers-file=/m2/files/servers\n')
    add('servers-file-missing-start', 'CFG-03,SFILE-03', initial,
        [probe('missing'), write('servers', 'server=/file.test/127.0.0.3\n'), probe('no-auto', 'before.file.test'),
         signal_reload(), probe('hup-load', 'after.file.test')], 'servers-file=/m2/files/servers\n')
    add('inline-file-resolv-banks', 'RSLV-07,RSLV-08,STATE-03',
        {'resolv': r1, 'servers': 'server=/file.test/127.0.0.3\n'},
        [probe('inline-initial', 'a.inline.test'), probe('file-initial', 'a.file.test'), probe('default-initial'),
         write('resolv', r2), probe('inline-after', 'b.inline.test'), probe('file-after', 'b.file.test'), probe('default-after'),
         write('servers', ''), signal_reload(), probe('file-fallback', 'c.file.test')],
        'server=/inline.test/127.0.0.4\nservers-file=/m2/files/servers\n')
    for clear in (False, True):
        add('cache-clear-' + str(int(clear)), 'CLEAR-01,CLEAR-02,CLEAR-03,STATE-05',
            {'resolv': r1, 'hosts': '192.0.2.31 host.files.test\n'},
            [probe('seed', 'cache.files.test', cache=True), write('hosts', '192.0.2.32 host.files.test\n'),
             write('resolv', r2), probe('cache-after', 'cache.files.test', cache=True), probe('hosts-after', 'host.files.test'),
             write('resolv', ''), probe('cache-empty', 'cache.files.test', cache=True), signal_reload(),
             probe('cache-hup', 'cache.files.test', cache=True), probe('hosts-hup', 'host.files.test')],
            'addn-hosts=/m2/files/hosts\n' + ('clear-on-reload\n' if clear else ''), cache_size=64)
    add('tcp-parent-snapshot', 'STATE-04', initial,
        [{'op': 'connect', 'id': 'held'}, probe('held-before', transports=['held']), write('resolv', r2),
         probe('parent-new'), probe('held-after', transports=['held']), {'op': 'disconnect', 'id': 'held'}, probe('fresh-tcp')])
    add('zero-and-own-server', 'RSLV-09', {'resolv': 'nameserver 0.0.0.0\n'},
        [probe('zero'), write('resolv', r1), probe('valid')])
    for mode in ('poll', 'no-poll'):
        add('route-event-' + mode, 'RSLV-02,NPOLL-02', {'resolv': {'text': r1, 'mtime': 1700000010}},
            [probe('initial'), write('resolv', r2, hold_open=True, mtime=1700000020), {'op': 'route', 'prefix': '198.18.1.0/24'},
             probe('after-manual-route'), {'op': 'address-route', 'address': '198.18.2.1/24'},
             probe('after-route'), {'op': 'close-file', 'path': 'resolv'}],
            'no-poll\n' if mode == 'no-poll' else '')
    add('pending-reused-slot', 'STATE-01,STATE-02', initial,
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'}, write('resolv', r2),
         {'op': 'inject', 'id': 'held', 'server': 0}, {'op': 'receive-udp', 'id': 'old-reply', 'pending': 'held'},
         {'op': 'inject', 'id': 'held', 'server': 1}, {'op': 'receive-udp', 'id': 'new-reply', 'pending': 'held'}])
    add('pending-retired-slot', 'STATE-02', initial,
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'}, write('resolv', ''),
         {'op': 'inject', 'id': 'held', 'server': 0}, {'op': 'receive-udp', 'id': 'retired-reply', 'pending': 'held'}, probe('fresh-refused')])
    add('pending-all-servers-retired-last-slot', 'STATE-02', {'resolv': r1 + r2},
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test', 'upstream_count': 2}, write('resolv', r2),
         {'op': 'inject', 'id': 'held', 'server': 1, 'capture_server': 1},
         {'op': 'receive-udp', 'id': 'retired-last-reply', 'pending': 'held'}, probe('fresh-survivor')], 'all-servers\n')
    add('own-v4-same-port', 'RSLV-09', {}, [probe('own-v4')], 'no-resolv\nserver=127.0.0.1#{listen_port}\n')
    add('own-v6-same-port', 'RSLV-09', {}, [probe('own-v6')], 'no-resolv\nserver=::1#{listen_port}\n', listen='127.0.0.1,::1')
    add('own-address-other-port', 'RSLV-09', {'resolv': 'nameserver 127.0.0.1\n'}, [probe('other-port')], local_upstream=True)
    add('default-system-resolver', 'CFG-01', {}, [probe('system-default')], default_resolv=False, sys_files={'/etc/resolv.conf': r1})
    for label, config, files in [
        ('empty-resolv', 'resolv-file=\n', {}),
        ('empty-then-file', 'resolv-file=\nresolv-file=/m2/files/resolv\n', initial),
        ('file-then-empty', 'resolv-file=/m2/files/resolv\nresolv-file=\n', initial),
        ('duplicate-file', 'resolv-file=/m2/files/resolv\nresolv-file=/m2/files/resolv\n', initial),
    ]:
        add(label, 'CFG-01', files, [probe('grammar')], config, default_resolv=False, sys_files={'/etc/resolv.conf': 'nameserver 127.0.0.4\n'})
    for flag in ['no-poll', 'clear-on-reload']:
        add('parameter-' + flag, 'CFG-03', initial, [], flag + '=bad\n', expected_test=1, expected_start=False)
    for count in [20, 21]:
        files = {'target': r1}
        target = 'target'
        for index in range(count):
            leaf = 'link' + str(index); files[leaf] = {'symlink': target}; target = leaf
        add('symlink-limit-' + str(count), 'WATCH-02', files, [probe('limit')] if count == 20 else [],
            'resolv-file=/m2/files/' + target + '\n', default_resolv=False, expected_start=count == 20)
    add('symlink-loop', 'WATCH-02', {'resolv': {'symlink': 'resolv'}}, [], expected_start=False)
    add('absolute-root-leaf', 'WATCH-03', {}, [], 'resolv-file=/leaf\n', default_resolv=False, expected_start=False)
    add('parent-replacement', 'WATCH-06', {'watch/resolv': r1, 'next/resolv': r2},
        [probe('parent-initial'), {'op': 'rename', 'path': 'watch', 'to': 'old'},
         {'op': 'rename', 'path': 'next', 'to': 'watch'}, probe('parent-replaced'),
         write('watch/resolv', 'nameserver 127.0.0.4\n'), probe('new-parent-unwatched'),
         write('old/resolv', r1), probe('old-parent-trigger')],
        'resolv-file=/m2/files/watch/resolv\n', default_resolv=False)
    add('mtime-zero-negative', 'RSLV-01', {'resolv': {'text': r1, 'mtime': 0}},
        [probe('zero-time'), write('resolv', r2, mtime=-1), probe('negative-time'),
         write('resolv', r2, mtime=1), probe('positive-time')])
    add('removed-winner-route-fallback', 'RSLV-02',
        {'resolv': {'text': r1, 'mtime': 1700000010}, 'second': {'text': r2, 'mtime': 1700000020}},
        [probe('winner'), {'op': 'unlink', 'path': 'second'}, probe('delete-ignored'),
         {'op': 'address-route', 'address': '198.18.2.1/24'}, probe('fallback'),
         {'op': 'unlink', 'path': 'resolv'}, {'op': 'address-route', 'address': '198.18.3.1/24'}, probe('all-missing-retains')],
        'resolv-file=/m2/files/second\n')
    add('resolver-open-permission', 'RSLV-05', initial,
        [probe('permission-initial'), write('resolv', r2, mode=0), probe('denied-retains'),
         write('resolv', r2, mode=0o644), probe('permission-recovered')], user='dnsmasq', group='dnsmasq')
    add('resolver-directory', 'RSLV-05', initial,
        [probe('file-initial'), {'op': 'directory-replace', 'path': 'resolv'}, probe('directory-empty'),
         {'op': 'rmdir', 'path': 'resolv'}, write('resolv', r2), probe('file-recovered')])
    add('diagnostics-debug', 'SFILE-02,SFILE-03,NPOLL-01', {},
        [write('resolv', r1), write('servers', 'server=/file.test/127.0.0.3\naddress=/bad/1.2.3.4\nserver=/other.test/127.0.0.4\n'),
         signal_reload(), probe('valid-prefix', 'a.file.test'), probe('valid-after-error', 'a.other.test')],
        'no-daemon\nno-poll\nservers-file=/m2/files/servers\n', diagnostics=True)
    add('watch-emfile', 'FAIL-01', initial, [], expected_start=False, inotify_fault=True)
    dhcp_files = dict(initial, **{'leases': '4102444800 02:11:22:33:44:55 198.18.5.10 leased *\n',
        'helper.sh': '#!/bin/sh\nprintf "%s|%s|%s|%s\\n" "$1" "$2" "$3" "$4" >> /m2/files/helper.log\n', 'dhcp.hosts': ''})
    dhcp_config = ('clear-on-reload\ninterface=m5filelan\nno-ping\ndomain=files.test\n'
                   'dhcp-range=198.18.5.10,198.18.5.20,255.255.255.0,1h\n'
                   'dhcp-leasefile=/m2/files/leases\ndhcp-script=/m2/files/helper.sh\n')
    add('clear-helper-unchanged', 'CLEAR-02,CLEAR-03', dhcp_files,
        [{'op': 'helper-events', 'id': 'initial-helper', 'expect_events': 2}, probe('lease-initial', 'leased.files.test'),
         write('resolv', r2), {'op': 'helper-events', 'id': 'auto-helper', 'expect_events': 0},
         signal_reload(), {'op': 'helper-events', 'id': 'hup-helper', 'expect_events': 1}],
        dhcp_config, dhcp_witness=True)
    add('clear-dhcp-hosts-bank', 'CLEAR-02', dhcp_files,
        [{'op': 'helper-events', 'id': 'initial-helper', 'expect_events': 2}, probe('lease-initial', 'leased.files.test'),
         write('dhcp.hosts', '02:11:22:33:44:55,newname,198.18.5.10\n'), write('resolv', r2),
         probe('new-lease-name', 'newname.files.test'), probe('old-name-forwarded', 'leased.files.test'),
         {'op': 'helper-events', 'id': 'changed-helper'}],
        dhcp_config + 'dhcp-hostsfile=/m2/files/dhcp.hosts\n', dhcp_witness=True)
    add('no-poll-missing-atomic', 'CFG-02,NPOLL-01', {},
        [probe('missing'), write('resolv', r1), probe('created-no-hup'), signal_reload(), probe('created-hup'),
         write('resolv', r2, atomic=True), probe('renamed-no-hup'), signal_reload(), probe('renamed-hup')], 'no-poll\n')
    add('empty-no-poll', 'CFG-02', {}, [probe('empty-initial'), signal_reload(), probe('empty-hup')],
        'resolv-file=\nno-poll\n', default_resolv=False, sys_files={'/etc/resolv.conf': r1})
    for no_poll in (False, True):
        add('clear-helper-signal-' + str(int(no_poll)), 'CLEAR-02,CLEAR-03,NPOLL-01', dhcp_files,
            [{'op': 'helper-events', 'id': 'initial'}, probe('seed', 'cached.files.test', cache=True),
             {'op': 'metrics', 'id': 'seed-counts'}, write('resolv', r2),
             probe('after-write', 'cached.files.test', cache=True), {'op': 'metrics', 'id': 'write-counts'},
             signal_reload(), {'op': 'helper-events', 'id': 'one-hup'}, probe('after-hup', 'cached.files.test', cache=True),
             {'op': 'metrics', 'id': 'hup-counts'}, {'op': 'signal-burst', 'count': 8},
             {'op': 'helper-events', 'id': 'coalesced'}, {'op': 'metrics', 'id': 'burst-counts'}],
            dhcp_config + ('no-poll\n' if no_poll else ''), dhcp_witness=True, cache_size=64, metrics=True)
    add('clear-servers-file-signal', 'SFILE-01,CLEAR-03',
        dict(dhcp_files, servers='server=/file.test/127.0.0.3\n'),
        [{'op': 'helper-events', 'id': 'initial'}, probe('seed', 'cached.file.test', cache=True),
         write('servers', 'server=/file.test/127.0.0.4\n'), write('resolv', r2),
         probe('resolver-does-not-read-server-file', 'fresh.file.test'), {'op': 'helper-events', 'id': 'auto'},
         signal_reload(), {'op': 'helper-events', 'id': 'hup'}, probe('server-file-after-hup', 'cached.file.test', cache=True)],
        dhcp_config + 'servers-file=/m2/files/servers\n', dhcp_witness=True, cache_size=64)
    for clear in (False, True):
        add('cache-rewrite-neg-' + str(int(clear)), 'CLEAR-01,CLEAR-03,STATE-05', initial,
            [probe('seed-positive', 'positive.files.test', cache=True), probe('seed-negative', 'negative.files.test', cache=True),
             {'op': 'metrics', 'id': 'seed-counts'}, write('resolv', r1),
             probe('rewrite-positive', 'positive.files.test', cache=True), probe('rewrite-negative', 'negative.files.test', cache=True),
             {'op': 'metrics', 'id': 'rewrite-counts'}, write('resolv', ''),
             probe('empty-positive', 'positive.files.test', cache=True), probe('empty-negative', 'negative.files.test', cache=True),
             {'op': 'metrics', 'id': 'empty-counts'}, write('resolv', 'nameserver 0.0.0.0\n'),
             probe('filtered-positive', 'positive.files.test', cache=True), probe('filtered-negative', 'negative.files.test', cache=True),
             {'op': 'metrics', 'id': 'filtered-counts'}],
            'neg-ttl=120\n' + ('clear-on-reload\n' if clear else ''), cache_size=64, metrics=True,
            negative_names=['negative.files.test'])
    add('clear-open-failure', 'CLEAR-01,RSLV-05', initial,
        [probe('seed', 'cached.files.test', cache=True), write('resolv', r2, mode=0),
         probe('denied-cache', 'cached.files.test', cache=True), probe('denied-source', 'fresh.files.test'),
         write('resolv', r2, mode=0o644), probe('recovered-cache', 'cached.files.test', cache=True)],
        'clear-on-reload\n', user='dnsmasq', group='dnsmasq', cache_size=64)
    add('clear-ethers-lease', 'CLEAR-02', dhcp_files,
        [{'op': 'helper-events', 'id': 'initial'}, probe('lease', 'leased.files.test'),
         {'op': 'write-system', 'path': '/etc/ethers', 'text': '02:11:22:33:44:55 ethername\n'}, write('resolv', r2),
         probe('new-name', 'ethername.files.test'), probe('old-name', 'leased.files.test'),
         {'op': 'helper-events', 'id': 'ethers-events'}],
        dhcp_config + 'read-ethers\n', dhcp_witness=True, sys_files={'/etc/ethers': ''})
    expected = {
        'inplace-rename-delete-empty': {'initial': 11, 'inplace': 12, 'renamed': 11, 'deleted': 11, 'empty': 5, 'invalid': 5, 'recovered': 12},
        'missing-leaf': {'missing': 5, 'created': 11},
        'no-poll-signal': {'before': 11, 'after-hup': 12, 'after-close': 12, 'second-hup': 12},
        'poll-signal': {'before': 11, 'after-hup': 11, 'after-close': 12, 'second-hup': 12},
        'newest-file-and-ties': {'newest': 12, 'older-write': 12, 'equal-newest-option': 12, 'replaced-inode': 11},
        'symlink-relative': {'initial': 11, 'target-write': 12, 'retarget-no-event': 12, 'new-target-no-watch': 12, 'old-target-trigger': 13},
        'symlink-absolute': {'initial': 11, 'target-write': 12},
        'resolver-token-matrix': {'token-0': 11, 'token-1': 5, 'token-2': 12, 'token-3': 5, 'token-4': 14, 'token-5': 14, 'token-6': 5},
        'route-event-poll': {'initial': 11, 'after-manual-route': 11, 'after-route': 12},
        'route-event-no-poll': {'initial': 11, 'after-manual-route': 11, 'after-route': 11},
        'pending-reused-slot': {'old-reply': None, 'new-reply': 12},
        'pending-retired-slot': {'retired-reply': None, 'fresh-refused': 5},
        'pending-all-servers-retired-last-slot': {'retired-last-reply': None, 'fresh-survivor': 12},
        'own-v4-same-port': {'own-v4': 5}, 'own-v6-same-port': {'own-v6': 5}, 'own-address-other-port': {'other-port': 15},
    }
    for case in cases:
        if case['id'].startswith('filtered-'): expected[case['id']] = {'initial': 11, 'ignored-write': 11}
        for action in case['actions']:
            wanted = expected.get(case['id'], {})
            if action.get('id') in wanted:
                value = wanted[action['id']]
                action['c_expect'] = {'timeout': True} if value is None else ({'rcode': 5} if value == 5 else {'addresses': ['192.0.2.' + str(value)], 'rcode': 0})
    for case in cases:
        if case['id'] == 'resolver-token-matrix':
            next(a for a in case['actions'] if a.get('id') == 'token-4')['c_expect'] = {
                'udp': {'timeout': True}, 'tcp': {'addresses': ['192.0.2.14'], 'rcode': 0}}
    return cases


def put(root, relative, value, opened):
    path = image_path(root, '/m2/files/' + relative, follow_leaf=False)
    value = {'text': value} if isinstance(value, str) else value
    path.parent.mkdir(parents=True, exist_ok=True)
    if 'symlink' in value:
        path.unlink(missing_ok=True)
        path.symlink_to(value['symlink'])
        return
    if path.is_symlink():
        path = image_path(root, '/m2/files/' + relative)
    target = path.with_name('temp-' + path.name) if value.get('atomic') else path
    handle = target.open('wb')
    handle.write(value.get('text', '').encode())
    handle.flush()
    if 'mtime' in value:
        os.utime(handle.fileno(), (value['mtime'], value['mtime']))
    if 'mode' in value: os.fchmod(handle.fileno(), value['mode'])
    if value.get('hold_open'):
        opened[relative] = handle
    else:
        handle.close()
    if value.get('atomic'):
        target.replace(path)


def exchange(port, action, ident, transport, upstreams, connections):
    packet = query(action, ident)
    before = [len(upstream.events) for upstream in upstreams]
    started = time.monotonic()
    response, error = None, None
    owned = transport in ('udp', 'tcp')
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == 'udp' else socket.SOCK_STREAM) if owned else connections[transport]
    try:
        client.settimeout(.5)
        if owned:
            client.connect(('127.0.0.1', port))
        client.sendall(packet if transport == 'udp' else struct.pack('!H', len(packet)) + packet)
        response = client.recv(65535) if transport == 'udp' else exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
    except (OSError, EOFError) as problem:
        error = {'kind': type(problem).__name__, 'errno': getattr(problem, 'errno', None)}
    finally:
        if owned:
            client.close()
    parsed = semantics(response) if response else None
    if parsed and parsed['id'] != ident:
        raise AssertionError('client transaction identity mismatch')
    return {'id': action['id'] + ':' + transport, 'response': parsed, 'error': error,
            'request': packet.hex(), 'reply': response.hex() if response else None,
            'elapsed': time.monotonic() - started, 'cache': action.get('cache', False),
            'upstreams': [{'server': upstream.host, 'events': copy.deepcopy(upstream.events[start:])}
                          for upstream, start in zip(upstreams, before)]}


def run_side(root, side, case, folder):
    folder.mkdir()
    data = root / 'm2/files'
    if data.exists(): shutil.rmtree(data)
    data.mkdir()
    # Nonroot daemon fixtures need write access to the PID parent at shutdown.
    # The resolver data stays root-owned so chmod(0) still witnesses EACCES.
    (root / 'm2').chmod(0o777 if case.get('user', 'root') != 'root' else 0o755)
    opened, connections, pending = {}, {}, {}
    routes, addresses, links = [], [], []
    if case.get('dhcp_witness'):
        subprocess.run(['ip', 'link', 'add', 'm5filelan', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'link', 'set', 'm5filelan', 'up'], check=True)
        subprocess.run(['ip', 'addr', 'add', '198.18.5.1/24', 'dev', 'm5filelan'], check=True)
        links.append('m5filelan')
    route_socket = None
    if any(a['op'] in ('route', 'address-route') for a in case['actions']):
        route_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        route_socket.bind((0, 0x40 | 0x400)); route_socket.settimeout(.02)
    for path, value in case['files'].items(): put(root, path, value, opened)
    for path, value in case.get('sys_files', {}).items():
        target = image_path(root, path); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(value)
    if case.get('dhcp_witness'):
        (data / 'helper.sh').chmod(0o755)
    helper_offset = 0
    names = {(a['name'], a.get('type', 1)) for a in case['actions'] if a['op'] in ('query', 'start-udp')}
    upstreams = []
    for index, address in enumerate(['127.0.0.2', '127.0.0.3', '127.0.0.4', '::1'] + (['127.0.0.1'] if case.get('local_upstream') else [])):
        fixtures = [{'name': host, 'type': kind, 'reply': f'192.0.2.{11 + index}' if kind == 1 else f'2001:db8::{11 + index}'} for host, kind in names]
        delayed = {a['name'] for a in case['actions'] if a['op'] == 'start-udp'}
        for fixture in fixtures:
            if fixture['name'] in delayed: fixture['drop_all'] = True
            if fixture['name'] in case.get('negative_names', []): fixture.update(rcode=3, records=[])
        upstreams.append(Upstream(fixtures, address, 53))
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    config = ('no-hosts\nno-0x20-encode\nno-round-robin\nstrict-order\n'
              + f'user={case.get("user", "root")}\ngroup={case.get("group", "root")}\n'
              + f'listen-address={case.get("listen", "127.0.0.1")}\nhost-record=ready.files.test,192.0.2.250\n'
              'pid-file=/m2/files.pid\n' + f'port={port}\ncache-size={case.get("cache_size", 0)}\n'
              + ('resolv-file=/m2/files/resolv\n' if case.get('default_resolv', True) else '') + case['config'].replace('{listen_port}', str(port)))
    if case.get('metrics'): config += 'enable-ubus=file-metrics\n'
    (root / 'm2/files.conf').write_text(config)
    (folder / 'config').write_text(config)
    test = subprocess.run(command(root, side, '--test', '-C', '/m2/files.conf'), capture_output=True, timeout=5)
    result = {'syntax': {'exit': test.returncode, 'stdout': test.stdout.decode(errors='replace'), 'stderr': test.stderr.decode(errors='replace')}, 'rows': [], 'actions': []}
    process, bus, bus_log = None, None, None
    try:
        if case.get('metrics'):
            bus_log = (folder / 'ubusd.log').open('wb')
            bus = subprocess.Popen(command(root, '/sbin/ubusd'), stdout=bus_log, stderr=bus_log, start_new_session=True)
            deadline = time.monotonic() + 2
            while subprocess.run(command(root, '/bin/ubus', 'list'), capture_output=True, timeout=1).returncode:
                if bus.poll() is not None or time.monotonic() >= deadline: raise AssertionError('ubusd startup')
                time.sleep(.02)
        with (folder / 'stdout').open('wb') as stdout, (folder / 'stderr').open('wb') as stderr:
            argv = command(root, side, '-k', '-C', '/m2/files.conf')
            if case.get('inotify_fault'): argv = [sys.executable, str(Path(__file__).resolve()), '--exec-inotify-fault', *argv]
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
            deadline = time.monotonic() + 3
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    ready = exchange(port, probe('ready', 'ready.files.test'), 0x3000, 'udp', upstreams, connections)
                    if ready['response']:
                        result['startup'] = {'ready': True}; break
                except OSError:
                    pass
                time.sleep(.01)
            else:
                result['startup'] = {'ready': False, 'exit': process.poll()}
            if result['startup']['ready']:
                result['identity'] = process_identity(root, process.pid)
                expected = sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))
                if result['identity']['sha256'] != expected: raise AssertionError('running ELF identity mismatch')
                for index, action in enumerate(case['actions']):
                    op = action['op']
                    if op == 'query':
                        for number, transport in enumerate(action.get('transports', ['udp', 'tcp'])):
                            result['rows'].append(exchange(port, action, 0x4000 + index * 4 + number, transport, upstreams, connections))
                    elif op == 'start-udp':
                        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); client.settimeout(.2)
                        packet = query(action, 0x4000 + index * 4)
                        before = [len(u.events) for u in upstreams]
                        client.sendto(packet, ('127.0.0.1', port))
                        pending[action['id']] = {'client': client, 'packet': packet, 'before': before, 'name': action['name']}
                        deadline = time.monotonic() + 1
                        while sum(len(u.events) - n for u, n in zip(upstreams, before)) < action.get('upstream_count', 1):
                            if time.monotonic() > deadline: raise AssertionError('pending query did not reach expected upstreams')
                            time.sleep(.005)
                    elif op == 'inject':
                        held = pending[action['id']]
                        captured = upstreams[action.get('capture_server', 0)]
                        original, peer, _ = next(row for row in captured.captured if read_name(row[0], 12)[0] == held['name'])
                        end = read_name(original, 12)[1]
                        answer = original[:2] + struct.pack('!5H', 0x8580, 1, 1, 0, 0) + original[12:end + 4]
                        answer += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 120, 4) + bytes([192, 0, 2, 11 + action['server']])
                        upstreams[action['server']].udp.sendto(answer, peer)
                        result['actions'].append({'op': 'injected-wire', 'wire': answer.hex(), 'server': action['server'], 'peer': list(peer)})
                    elif op == 'receive-udp':
                        held = pending[action['pending']]
                        response, error = None, None
                        try: response = held['client'].recv(65535)
                        except OSError as problem: error = {'kind': type(problem).__name__, 'errno': getattr(problem, 'errno', None)}
                        result['rows'].append({'id': action['id'] + ':udp-async', 'response': semantics(response) if response else None,
                            'error': error, 'request': held['packet'].hex(), 'reply': response.hex() if response else None, 'elapsed': 0, 'cache': False,
                            'upstreams': [{'server': u.host, 'events': copy.deepcopy(u.events[n:])} for u, n in zip(upstreams, held['before'])]})
                        held['before'] = [len(u.events) for u in upstreams]
                    elif op in ('route', 'address-route'):
                        if op == 'route':
                            subprocess.run(['ip', 'route', 'add', action['prefix'], 'dev', 'lo', 'scope', 'link'], check=True)
                            routes.append(action['prefix'])
                        else:
                            device = 'm5route' + str(len(links))
                            subprocess.run(['ip', 'link', 'add', device, 'type', 'dummy'], check=True)
                            subprocess.run(['ip', 'link', 'set', device, 'up'], check=True)
                            links.append(device)
                            subprocess.run(['ip', 'addr', 'add', action['address'], 'dev', device], check=True)
                            addresses.append((action['address'], device))
                        packets = []
                        for _ in range(16):
                            try: wire, peer = route_socket.recvfrom(65535)
                            except socket.timeout: break
                            records, at = [], 0
                            while at + 16 <= len(wire):
                                length, kind, flags, seq, pid = struct.unpack_from('=IHHII', wire, at)
                                if length < 16 or at + length > len(wire): break
                                row = {'kind': kind, 'flags': flags, 'sequence': seq, 'pid': pid}
                                if length >= 28: row['route'] = list(wire[at + 16:at + 28])
                                records.append(row); at += (length + 3) & ~3
                            packets.append({'peer': list(peer), 'wire': wire.hex(), 'records': records})
                        result['actions'].append({'op': 'netlink-witness', 'trigger': op, 'packets': packets})
                    elif op == 'rename':
                        (data / action['path']).rename(data / action['to'])
                    elif op == 'directory-replace':
                        path = data / action['path']; temporary = path.with_name('new-directory')
                        temporary.mkdir(); path.unlink(); temporary.rename(path)
                    elif op == 'rmdir': (data / action['path']).rmdir()
                    elif op == 'helper-events':
                        time.sleep(.25)
                        path = data / 'helper.log'
                        lines = path.read_text().splitlines() if path.exists() else []
                        result['rows'].append({'id': action['id'] + ':helper', 'helper_events': lines[helper_offset:], 'response': None, 'error': None, 'cache': False, 'upstreams': []})
                        helper_offset = len(lines)
                    elif op == 'metrics':
                        response = subprocess.run(command(root, '/bin/ubus', 'call', 'file-metrics', 'metrics', '{}'), capture_output=True, text=True, timeout=2)
                        if response.returncode: raise AssertionError('ubus metrics failed: ' + response.stderr)
                        value = json.loads(response.stdout)
                        result['rows'].append({'id': action['id'] + ':metrics', 'metrics': value, 'response': None,
                                               'error': None, 'cache': False, 'upstreams': []})
                    elif op == 'write-system': image_path(root, action['path']).write_text(action['text'])
                    elif op == 'write': put(root, action['path'], action, opened)
                    elif op == 'unlink': image_path(root, '/m2/files/' + action['path'], follow_leaf=False).unlink()
                    elif op == 'symlink': put(root, action['path'], {'symlink': action['target']}, opened)
                    elif op == 'close-file': opened.pop(action['path']).close()
                    elif op == 'signal': process.send_signal(signal.SIGHUP)
                    elif op == 'signal-burst':
                        # Freeze the owner so standard signals deterministically coalesce.
                        process.send_signal(signal.SIGSTOP)
                        deadline = time.monotonic() + 1
                        while '\nState:\tT' not in Path(f'/proc/{process.pid}/status').read_text():
                            if time.monotonic() > deadline: raise AssertionError('SIGSTOP not observed')
                            time.sleep(.001)
                        for _ in range(action['count']): process.send_signal(signal.SIGHUP)
                        process.send_signal(signal.SIGCONT)
                    elif op == 'connect': connections[action['id']] = socket.create_connection(('127.0.0.1', port), .5)
                    elif op == 'disconnect': connections.pop(action['id']).close()
                    else: raise ValueError(op)
                    result['actions'].append(dict(action, daemon_alive=process.poll() is None))
                    if op != 'query': time.sleep(.08)
    finally:
        for handle in opened.values(): handle.close()
        for client in connections.values(): client.close()
        for held in pending.values(): held['client'].close()
        for prefix in routes: subprocess.run(['ip', 'route', 'del', prefix, 'dev', 'lo'], check=True)
        for address, device in addresses: subprocess.run(['ip', 'addr', 'del', address, 'dev', device], check=True)
        for device in reversed(links): subprocess.run(['ip', 'link', 'del', device], check=True)
        if route_socket: route_socket.close()
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=3); result['forced_kill'] = True
        result['exit'] = process.returncode if process else None
        if bus is not None:
            bus.terminate()
            try: bus.wait(timeout=2)
            except subprocess.TimeoutExpired: bus.kill(); bus.wait(); result['forced_bus_kill'] = True
        if bus_log: bus_log.close()
        for upstream in upstreams: upstream.close()
        deadline = time.monotonic() + 2
        while descendants(root) and time.monotonic() < deadline: time.sleep(.02)
        result['cleanup'] = {'live_pids': descendants(root), 'pid_file': (root / 'm2/files.pid').exists()}
        result['stdout'] = (folder / 'stdout').read_text()
        result['stderr'] = (folder / 'stderr').read_text()
        result['file_diagnostics'] = [line.removeprefix('dnsmasq: ').removeprefix('dnsmasq-rs: ') for line in result['stderr'].splitlines()
            if re.search(r'(?:failed to read|cannot read|no servers found) /m2/files/| at line [0-9]+ of /m2/files/', line)]
        if not result.get('startup', {}).get('ready'):
            result.setdefault('startup', {'ready': False}).update(stdout=result['stdout'], stderr=result['stderr'])
        dump(folder / 'observed.json', result)
    return result


def projection(row):
    row = copy.deepcopy(row)
    for key in ['request', 'reply', 'elapsed']: row.pop(key, None)
    for upstream in row['upstreams']:
        for event in upstream['events']:
            event.pop('wire', None); event.pop('reply_wire', None)
    return row


def compare(left, right, case):
    failures = []
    if case.get('diagnostics') and left['file_diagnostics'] != right['file_diagnostics']:
        failures.append({'phase': 'file-diagnostics', 'c': left['file_diagnostics'], 'rust': right['file_diagnostics']})
    for phase in ('syntax', 'startup'):
        a, b = copy.deepcopy(left[phase]), copy.deepcopy(right[phase])
        for value in (a, b):
            for stream in ('stdout', 'stderr'):
                if stream in value: value[stream] = normalized_text(value[stream])
        if a != b: failures.append({'phase': phase, 'c': a, 'rust': b})
    suffixes = {'helper-events': ['helper'], 'receive-udp': ['udp-async'], 'metrics': ['metrics']}
    wanted = [action['id'] + ':' + transport for action in case['actions'] if action['op'] in ('query', *suffixes)
              for transport in suffixes.get(action['op'], action.get('transports', ['udp', 'tcp']))] if left['startup']['ready'] else []
    for side, observed in [('c', left), ('rust', right)]:
        if [row['id'] for row in observed['rows']] != wanted: failures.append({'phase': 'coverage', 'side': side})
        if observed.get('forced_kill') or observed.get('forced_bus_kill') or observed['cleanup']['live_pids']: failures.append({'phase': 'cleanup', 'side': side})
        if observed['startup']['ready'] and (observed['exit'] != 0 or observed['cleanup']['pid_file']): failures.append({'phase': 'shutdown', 'side': side})
    if left['cleanup'] != right['cleanup']: failures.append({'phase': 'cleanup-state', 'c': left['cleanup'], 'rust': right['cleanup']})
    for a, b in zip(left['rows'], right['rows']):
        a, b = projection(a), projection(b)
        if a.get('cache') and a.get('response') and b.get('response'):
            ar, br = a['response'].get('records', []), b['response'].get('records', [])
            for x, y in zip(ar, br):
                if abs(x.get('ttl', 0) - y.get('ttl', 0)) <= 1: y['ttl'] = x['ttl']
        if a != b: failures.append({'phase': 'runtime', 'id': a['id'], 'c': a, 'rust': b})
    return failures


def controls():
    case = {'actions': [probe('one')]}
    base = {'syntax': {'exit': 0, 'stdout': '', 'stderr': 'dnsmasq: syntax check OK.\n'}, 'startup': {'ready': True},
            'exit': 0, 'cleanup': {'live_pids': [], 'pid_file': False}, 'rows': [
                {'id': 'one:' + transport, 'response': {'id': 1, 'flags': 0x8180, 'records': []}, 'error': None, 'cache': False,
                 'upstreams': [{'server': '127.0.0.2', 'events': [{'name': 'one.files.test', 'type': 1, 'transport': transport}]}]}
                for transport in ('udp', 'tcp')]}
    assert not compare(base, copy.deepcopy(base), case)
    found = []
    for change in ['missing-row', 'wrong-diagnostic', 'wrong-exit', 'startup', 'wrong-answer', 'missing-forward', 'wrong-server', 'leaked-child', 'leaked-pid']:
        mutated = copy.deepcopy(base)
        if change == 'missing-row': mutated['rows'].pop()
        elif change == 'wrong-diagnostic': mutated['syntax']['stderr'] = 'dnsmasq: wrong\n'
        elif change == 'wrong-exit': mutated['syntax']['exit'] = 1
        elif change == 'startup': mutated['startup']['ready'] = False
        elif change == 'wrong-answer': mutated['rows'][0]['response']['flags'] = 0x8183
        elif change == 'missing-forward': mutated['rows'][0]['upstreams'][0]['events'].clear()
        elif change == 'wrong-server': mutated['rows'][0]['upstreams'][0]['server'] = '127.0.0.3'
        elif change == 'leaked-child': mutated['cleanup']['live_pids'] = [123]
        elif change == 'leaked-pid': mutated['cleanup']['pid_file'] = True
        assert compare(base, mutated, case), change
        found.append(change)
    return found


def exec_inotify_fault(argv):
    if platform.machine() != 'aarch64': raise RuntimeError('fault syscall ABI is pinned AArch64')
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    # asm-generic __NR_inotify_init1=26; deny only this syscall with EMFILE.
    filters = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, 26), Filter(0x06, 0, 0, 0x50000 | errno.EMFILE), Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(4, filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), 'seccomp setup')
    os.execvp(argv[0], argv)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scenarios')
    parser.add_argument('--sides', choices=['both', 'c'], default='both')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    negative = controls()
    if args.self_test:
        print(json.dumps({'negative_controls': negative, 'scenarios': len(scenarios())})); return 0
    if not all([args.image_root, args.rust, args.rust_sha256, args.source_commit, args.output]): parser.error('image, candidate identity and output required')
    if sha256(args.rust) != args.rust_sha256: raise ValueError('candidate SHA mismatch')
    out = args.output.resolve()
    if 'private' not in out.parts or out.exists(): raise ValueError('fresh private output required')
    out.mkdir(parents=True)
    selected = [case for case in scenarios() if not args.scenarios or case['id'] in args.scenarios.split(',')]
    sides = ['c', 'rust'] if args.sides == 'both' else ['c']
    report = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256, 'stock_sha256': STOCK_SHA256,
              'tool_sha256': sha256(Path(__file__)), 'negative_controls': negative, 'scenarios': [], 'failures': [],
              'normalization': ['executable error prefix only in --test', 'upstream transaction IDs retained raw, semantic traces compare exactly',
                                'cache-marked probe TTL differences of at most one elapsed second permitted; upstream/cache causality remains exact'],
              'incomplete_boundaries': ['INI-01', 'WATCH-06 parent replacement', 'STATE-01/02 live delayed packet', 'FAIL-01 injected syscall failures', 'CLEAR-02 DHCP hooks', 'SFILE-05 endpoint dependency'], 'closed_options': []}
    driver = out / 'driver'; driver.mkdir()
    dependencies = ['m5_dns_files.py', 'm5_option_matrix.py', 'm5_option_matrix_probes.py', 'm2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh']
    report['driver_sha256'] = {}
    for filename in dependencies:
        source = Path(__file__).with_name(filename)
        shutil.copy2(source, driver / filename)
        report['driver_sha256'][filename] = sha256(source)
    dump(out / 'schedule.json', selected)
    roots = {side: prepare(args.image_root, None, out / side, args.rust) for side in sides}
    for case in selected:
        folder = out / case['id']; folder.mkdir()
        row = {'id': case['id'], 'checks': case['checks'], 'failures': []}
        try:
            observed = {side: run_side(roots[side], side, case, folder / side) for side in sides}
            c = observed['c']
            if c['syntax']['exit'] != case.get('expected_test', 0) or c['startup']['ready'] != case.get('expected_start', True):
                row['failures'].append({'phase': 'c-calibration', 'syntax': c['syntax'], 'startup': c['startup']})
            row['rows'] = len(c['rows'])
            for action in case['actions']:
                if 'expect_events' in action:
                    actual = next((entry for entry in c['rows'] if entry['id'] == action['id'] + ':helper'), {})
                    if len(actual.get('helper_events', [])) != action['expect_events']:
                        row['failures'].append({'phase': 'c-helper-calibration', 'id': action['id'], 'expected': action['expect_events'], 'actual': actual})
                if 'c_expect' not in action: continue
                matched = [entry for entry in c['rows'] if entry['id'].rsplit(':', 1)[0] == action['id']]
                if not matched: row['failures'].append({'phase': 'c-runtime-calibration', 'id': action['id'], 'missing': True})
                for entry in matched:
                    wanted = action['c_expect'].get(entry['id'].rsplit(':', 1)[1], action['c_expect']); response = entry['response']
                    valid = response is None if wanted.get('timeout') else response is not None and response['flags'] & 15 == wanted['rcode']
                    if valid and 'addresses' in wanted:
                        valid = sorted(r['data'] for r in response.get('records', []) if r['type'] in (1, 28) and r['section'] == 'answer') == sorted(wanted['addresses'])
                    if not valid: row['failures'].append({'phase': 'c-runtime-calibration', 'id': entry['id'], 'expected': wanted, 'actual': entry})
            if args.sides == 'both': row['failures'].extend(compare(c, observed['rust'], case))
        except Exception as problem:
            row['failures'].append({'phase': 'infrastructure', 'error': repr(problem)})
        report['scenarios'].append(row)
        dump(out / 'progress.json', report)
    report['failures'] = [dict(scenario=row['id'], **failure) for row in report['scenarios'] for failure in row['failures']]
    dump(out / 'result.json', report)
    print(json.dumps({'scenarios': len(selected), 'rows': sum(row.get('rows', 0) for row in report['scenarios']), 'failures': len(report['failures']), 'closed_options': []}))
    return int(bool(report['failures']))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--exec-inotify-fault': exec_inotify_fault(sys.argv[2:])
    raise SystemExit(main())
