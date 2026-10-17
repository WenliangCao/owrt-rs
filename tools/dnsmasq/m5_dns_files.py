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
import hashlib
import tarfile
import json
import os
import platform
import re
import resource
import threading
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
import m5_dhcp_tags_options as dhcp_wire


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
    add('init-generated-file-paths', 'INI-01', {},
        [probe('touched-empty'), {'op': 'write-system', 'path': '/tmp/resolv.conf.d/resolv.conf.auto', 'text': r1},
         probe('netifd-populated'), probe('server-before', 'a.file.test'),
         {'op': 'write-system', 'path': '/tmp/file-servers.conf', 'text': 'server=/file.test/127.0.0.4\n'},
         signal_reload(), probe('server-after', 'b.file.test')],
        'resolv-file=/tmp/resolv.conf.d/resolv.conf.auto\nservers-file=/tmp/file-servers.conf\n',
        default_resolv=False, sys_files={'/tmp/resolv.conf.d/resolv.conf.auto': '', '/tmp/file-servers.conf': 'server=/file.test/127.0.0.3\n'})
    add('resolver-link-local-scope', 'RSLV-04', {'resolv': 'nameserver fe80::53%m5scope\n'},
        [probe('scope-valid'), write('resolv', 'nameserver fe80::53%missing\n'), probe('scope-missing'),
         write('resolv', 'nameserver fe80::53%m5scope\n'), probe('scope-restored')], scoped_upstream=True)
    add('file-event-burst', 'FAIL-02,CLEAR-01,CLEAR-03', initial,
        [{'op': 'reading-count', 'id': 'startup-read', 'minimum': 1, 'expect_reading': 1},
         {'op': 'file-burst', 'count': 512, 'text': r2},
         {'op': 'reading-count', 'id': 'burst-read', 'minimum': 2, 'expect_reading': 2},
         probe('burst-source', transports=['udp'])], 'no-daemon\nclear-on-reload\n')
    add('reading-no-poll', 'NPOLL-01', initial,
        [{'op': 'reading-count', 'id': 'startup-no-message', 'minimum': 0, 'expect_reading': 0},
         write('resolv', r2), signal_reload(), probe('after-hup', transports=['udp']),
         {'op': 'reading-count', 'id': 'hup-no-message', 'minimum': 0, 'expect_reading': 0}],
        'no-daemon\nno-poll\n')
    # Frozen required_cases are expanded explicitly; boundary IDs alone never
    # authorize closing an option. These fixtures cover non-endpoint edges.
    add('grammar-empty-two-and-duplicate', 'CFG-01,RSLV-01',
        {'resolv': {'text': r1, 'mtime': 1700000010}, 'second': {'text': r2, 'mtime': 1700000010}},
        [probe('last-declared')], 'resolv-file=\nresolv-file=/m2/files/resolv\nresolv-file=/m2/files/second\n', default_resolv=False)
    add('servers-empty', 'CFG-03', initial, [probe('ordinary')], 'servers-file=\n')
    add('servers-repeated-option', 'CFG-03', initial, [],
        'servers-file=/m2/files/a\nservers-file=/m2/files/b\n', expected_test=1, expected_start=False)
    add('port-zero-suppresses-watch', 'WATCH-01', {}, [],
        'resolv-file=/m2/files/missing/resolv\n', default_resolv=False, dns_disabled=True)
    add('watch-parent-eacces', 'WATCH-01,WATCH-03,FAIL-01', initial, [],
        expected_start=False, inotify_fault='watch-eacces')
    add('symlink-dangling-target', 'WATCH-02', {'resolv': {'symlink': 'target'}},
        [probe('absent'), write('target', r1), probe('created')])
    add('symlink-two-hop', 'WATCH-02', {'resolv': {'symlink': 'middle'}, 'middle': {'symlink': 'target'}, 'target': r1},
        [probe('initial'), write('target', r2), probe('changed')])
    add('watch-neighbor-and-deleted-event', 'WATCH-04,WATCH-05', initial,
        [probe('initial'), write('neighbor', r2), probe('neighbor-ignored'),
         {'op': 'write-delete-paused', 'path': 'resolv', 'text': r2}, probe('deleted-before-drain'),
         write('resolv', r2), probe('created')])
    add('inode-same-mtime', 'RSLV-01', {'resolv': {'text': r1, 'mtime': 1700000010}},
        [probe('initial'), write('resolv', r2, atomic=True, mtime=1700000010), probe('same-time-new-inode')])
    add('resolver-lexical-complete', 'RSLV-03,RSLV-04', initial,
        [action for i, text in enumerate(['search ignored.test\ndomain ignored.test\nnameserver 127.0.0.2 trailing words\n',
          'nameserver host.invalid\nnameserver 127.0.0.3#53\n', 'nameserver ::1%123456\n',
          'nameserver ::1%lo\n', 'nameserver 127.0.0.3\r\n']) for action in
         (write('resolv', text), probe('lexical-' + str(i)))])
    add('resolver-empty-repeated-route', 'RSLV-06', {'resolv': ''},
        [probe('initial'), write('resolv', ''), probe('repeated'), {'op': 'pause', 'seconds': .15},
         probe('steady'), {'op': 'address-route', 'address': '198.18.2.1/24'}, probe('route-empty'),
         write('resolv', r1), probe('populated')])
    add('runtime-resolver-emfile', 'FAIL-01,RSLV-05,CLEAR-01', initial,
        [probe('initial', transports=['udp']), {'op': 'fd-limit', 'limit': 'first-free'}, write('resolv', r2),
         probe('local-during-emfile', 'ready.files.test', transports=['udp']), {'op': 'fd-limit', 'restore': True},
         probe('old-source-retained', transports=['udp']), write('resolv', r2), probe('recovered')],
        'no-daemon\nclear-on-reload\n', diagnostics=True)
    add('resolver-partial-stream-eio', 'RSLV-05,FAIL-02', initial,
        [probe('initial'), {'op': 'stream-read-error', 'text': 'nameserver 127.0.0.3\nnameserver 127.0.0.4'},
         probe('partial-final-line')], 'no-poll\n')
    for kind, length in [('large', 16 * 1024 * 1024), ('long-line', 256 * 1024)]:
        add('resolver-' + kind, 'FAIL-02', initial,
            [probe('initial'), {'op': 'large-file', 'id': kind, 'bytes': length, 'single_line': kind == 'long-line', 'tail': r2},
             probe('after-large')])
    add('tcp-pending-publication', 'STATE-04,STATE-05', initial,
        [{'op': 'start-tcp', 'id': 'held', 'name': 'delayed.files.test'}, write('resolv', r2), probe('new-parent'),
         {'op': 'release-tcp', 'server': 0}, {'op': 'receive-tcp', 'id': 'old-pending', 'pending': 'held'},
         probe('published-cache', 'delayed.files.test', cache=True, transports=['udp']),
         probe('old-connection', transports=['held']), {'op': 'disconnect', 'id': 'held'},
         probe('fresh', transports=['udp']), probe('fresh', cache=True, transports=['tcp'])], cache_size=64)
    add('tftp-across-resolver-reload', 'STATE-05', dict(initial, **{'payload': 'T' * 1400}),
        [{'op': 'tftp-start', 'id': 'transfer'}, write('resolv', r2), probe('changed'),
         {'op': 'tftp-finish', 'id': 'transfer'}], 'enable-tftp\ntftp-root=/m2/files\n')
    for phase in ['startup', 'runtime']:
        add('fifo-' + phase, 'FAIL-02,FAIL-01', initial,
            [{'op': 'fifo-reload', 'id': phase, 'phase': phase, 'text': r2}, probe('fifo-published')],
            'no-poll\n', fifo_startup=phase == 'startup')
    add('pending-file-shutdown', 'FAIL-01', initial,
        [{'op': 'fifo-reload', 'id': 'shutdown', 'text': r2, 'shutdown': True}], 'no-poll\n')
    add('symlink-readlink-eacces', 'WATCH-02,FAIL-01', {'resolv': {'symlink': 'target'}, 'target': r1}, [],
        expected_start=False, inotify_fault='readlink-eacces')
    add('servers-lexical-and-forbidden-includes', 'CFG-03,SFILE-02,SFILE-03,SFILE-04,SFILE-06',
        dict(initial, servers='server=/before.test/127.0.0.3\nconf-file=/m2/files/injected\nconf-dir=/m2/files/include\nunknown-option=x\nserver\nserver="/quoted.test/127.0.0.4" # comment\nrev-server=192.0.2.0/24,127.0.0.3\n',
             injected='server=/forbidden.test/127.0.0.4\n'),
        [probe('before', 'a.before.test'), probe('quoted', 'a.quoted.test'),
         probe('forbidden', 'a.forbidden.test'), probe('reverse', '10.2.0.192.in-addr.arpa', type=12),
         write('servers', 'invalid-only\n'), signal_reload(), probe('invalid-removes-old', 'a.before.test'),
         {'op': 'write-system', 'path': '/m2/files.conf', 'text': 'bad-main-config\n'}, signal_reload(), probe('main-not-reread')],
        'no-daemon\nservers-file=/m2/files/servers\n', diagnostics=True)
    add('servers-permission-and-literal-dash', 'SFILE-03', dict(initial, **{'servers': 'server=/file.test/127.0.0.3\n', '-': 'server=/dash.test/127.0.0.4\n'}),
        [probe('file', 'a.file.test'), write('servers', 'server=/file.test/127.0.0.4\n', mode=0), signal_reload(),
         probe('kept', 'b.file.test'), write('servers', '', mode=0o644), signal_reload(), probe('removed', 'c.file.test')],
        'no-daemon\nservers-file=/m2/files/servers\n', user='dnsmasq', group='dnsmasq', diagnostics=True)
    add('servers-relative-dash', 'SFILE-03', {}, [probe('dash', 'a.dash.test')],
        'no-resolv\nservers-file=-\n', default_resolv=False, sys_files={'/-': 'server=/dash.test/127.0.0.3\n'})
    for bank in ['inline', 'resolver', 'both']:
        add('default-marker-' + bank, 'RSLV-07,RSLV-08,STATE-03', initial,
            [probe('default-marked', 'a.marker.test'), probe('ordinary')],
            'server=/marker.test/#\n' + ('server=127.0.0.3\n' if bank in ('inline', 'both') else '')
            + ('no-resolv\n' if bank == 'inline' else ''))
    add('default-address-marker-precedence', 'RSLV-08,STATE-03', initial,
        [probe('marked', 'a.marker.test'), probe('default-literal', 'any.test'), probe('wildcard', 'a.wild.test')],
        'server=/marker.test/#\naddress=/#/192.0.2.60\naddress=/*.wild.test/192.0.2.61\n')
    add('resolver-default-marker-empty', 'RSLV-08', {'resolv': ''},
        [probe('no-server', 'a.marker.test')], 'server=/marker.test/#\n')
    add('no-resolv-retains-file-and-inline', 'RSLV-07', {'servers': 'server=/file.test/127.0.0.3\n'},
        [probe('inline'), probe('file', 'a.file.test')],
        'no-resolv\nserver=127.0.0.4\nservers-file=/m2/files/servers\n')
    add('resolver-reorder-and-duplicates', 'RSLV-07,STATE-01,STATE-03', {'resolv': r1 + r2 + r1},
        [probe('initial'), write('resolv', r2 + r1 + r2), probe('reordered'), write('resolv', r2 + r1 + r2), probe('identical')])
    add('file-route-collision-wildcard-order', 'SFILE-04,STATE-01,STATE-03',
        dict(initial, servers='server=/zone.test/127.0.0.3\nserver=/*.wild.test/127.0.0.3\n'),
        [probe('collision', 'a.zone.test'), probe('wild-before', 'a.wild.test'),
         write('servers', 'server=/zone.test/127.0.0.4\nserver=/*.wild.test/127.0.0.4\n'), signal_reload(),
         probe('collision-after', 'b.zone.test'), probe('wild-after', 'b.wild.test'),
         write('resolv', r2), probe('after-interleave'), write('servers', ''), signal_reload(), probe('collision-removed', 'c.zone.test')],
        'servers-file=/m2/files/servers\nserver=/zone.test/127.0.0.2\n')
    add('dhcp-during-repeated-reloads', 'STATE-05,CLEAR-02', initial,
        [a for i in range(4) for a in ({'op': 'dhcp-inform', 'id': 'before-' + str(i)},
         write('resolv', r2 if i % 2 else r1), {'op': 'dhcp-inform', 'id': 'after-' + str(i)}, probe('dns-' + str(i)))],
        'interface=lo\nno-ping\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,600\n'
        'dhcp-option=224,file-witness\ndhcp-leasefile=/m2/files/leases\nclear-on-reload\n')
    add('pending-file-bank-reuse', 'STATE-01,STATE-02', dict(initial, servers='server=/files.test/127.0.0.2\n'),
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'},
         write('servers', 'server=/files.test/127.0.0.3\n'), signal_reload(),
         {'op': 'inject', 'id': 'held', 'server': 0}, {'op': 'receive-udp', 'id': 'old-reply', 'pending': 'held'},
         {'op': 'inject', 'id': 'held', 'server': 1}, {'op': 'receive-udp', 'id': 'new-reply', 'pending': 'held'}],
        'servers-file=/m2/files/servers\n')
    add('pending-kept-server', 'STATE-02', initial,
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'}, write('resolv', r1),
         {'op': 'inject', 'id': 'held', 'server': 0}, {'op': 'receive-udp', 'id': 'kept-reply', 'pending': 'held'}])
    add('servers-partial-stream-eio', 'SFILE-02,SFILE-03,SFILE-06,FAIL-02',
        dict(initial, servers='server=/file.test/127.0.0.2\n'),
        [probe('initial', 'a.file.test'), {'op': 'stream-read-error', 'path': 'servers',
         'text': 'server=/file.test/127.0.0.3\nserver=/second.test/127.0.0.4'},
         probe('first-complete', 'b.file.test'), probe('partial-final', 'a.second.test')],
        'servers-file=/m2/files/servers\n')
    add('pending-reused-fast-retry', 'STATE-02', initial,
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'}, write('resolv', r2),
         {'op': 'await-upstream', 'id': 'held', 'server': 1},
         {'op': 'inject', 'id': 'held', 'server': 1, 'capture_server': 1},
         {'op': 'receive-udp', 'id': 'retry-reply', 'pending': 'held'}], 'fast-dns-retry=500,2000\n')
    add('pending-cancel-fd-recovery', 'STATE-02,STATE-05', initial,
        [{'op': 'start-udp', 'id': 'held', 'name': 'pending.files.test'}, write('resolv', ''),
         {'op': 'inject', 'id': 'held', 'server': 0}, {'op': 'receive-udp', 'id': 'cancelled', 'pending': 'held'}], fd_cancel=True)
    add('servers-ipv6-reverse-and-marker', 'SFILE-04,STATE-03',
        dict(initial, servers='server=/marker.test/#\nrev-server=192.0.2.128/25,::1\nserver=/*.wild.test/::1\n'),
        [probe('marker', 'a.marker.test'), probe('reverse-selected', '130.2.0.192.in-addr.arpa', type=12),
         probe('reverse-fallback', '1.2.0.192.in-addr.arpa', type=12), probe('wild', 'a.wild.test')],
        'servers-file=/m2/files/servers\n')
    add('file-global-source-interleave', 'STATE-03,RSLV-07,RSLV-08',
        dict(initial, servers='server=127.0.0.3\n'),
        [probe('initial', 'a.marker.test'), write('resolv', r2), probe('resolver-replaced', 'b.marker.test'),
         write('servers', 'server=127.0.0.2\n'), signal_reload(), probe('file-replaced', 'c.marker.test'),
         write('resolv', r2), probe('resolver-last', 'd.marker.test')],
        'servers-file=/m2/files/servers\nserver=127.0.0.4\nserver=/marker.test/#\n')
    add('global-source-eligibility', 'RSLV-07,RSLV-08', dict(initial, servers='server=127.0.0.3\n'),
        [probe('all-three', 'a.marker.test', transports=['udp'], upstream_expected=3), write('resolv', ''),
         probe('remaining-two', 'b.marker.test', transports=['udp'], upstream_expected=2)],
        'servers-file=/m2/files/servers\nserver=127.0.0.4\nserver=/marker.test/#\nall-servers\n',
        strict_order=False, common_upstream_reply=True)
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
    if action.get('upstream_expected'):
        await_predicate(lambda: sum(len(u.events) - n for u, n in zip(upstreams, before)) >= action['upstream_expected'], 'not every eligible source received the query')
    parsed = semantics(response) if response else None
    if parsed and parsed['id'] != ident:
        raise AssertionError('client transaction identity mismatch')
    return {'id': action['id'] + ':' + transport, 'response': parsed, 'error': error,
            'request': packet.hex(), 'reply': response.hex() if response else None,
            'elapsed': time.monotonic() - started, 'cache': action.get('cache', False),
            'upstreams': [{'server': upstream.host, 'events': copy.deepcopy(upstream.events[start:])}
                          for upstream, start in zip(upstreams, before)]}



class FileUpstream(Upstream):
    """Only test peers use threads; delayed TCP response is driver-controlled."""
    def __init__(self, *args):
        self.release_tcp = threading.Event()
        super().__init__(*args)

    def connection(self, client):
        try:
            with client:
                client.settimeout(2)
                while not self.stop.is_set():
                    packet = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
                    response = self.answer(packet, 'tcp')
                    host, end = read_name(packet, 12)
                    fixture = self.probes.get((host, struct.unpack_from('!H', packet, end)[0]), {})
                    if fixture.get('hold_tcp'):
                        while not self.release_tcp.wait(.01):
                            if self.stop.is_set(): return
                    client.sendall(struct.pack('!H', len(response)) + response)
        except (ConnectionError, OSError, EOFError):
            pass
        except Exception as problem:
            self.errors.append(repr(problem))

    def close(self):
        self.release_tcp.set()
        super().close()


def local_health(port, ident=0x3100, timeout=.15):
    packet = query(probe('health', 'ready.files.test'), ident)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(packet, ('127.0.0.1', port))
        try: response = client.recv(4096)
        except socket.timeout: response = None
    parsed = semantics(response) if response else None
    return {'elapsed': time.monotonic() - started, 'request': packet.hex(),
            'reply': response.hex() if response else None,
            'healthy': bool(parsed and parsed['id'] == ident and parsed['records'][0]['data'] == '192.0.2.250')}


def open_file_fds(pid, suffix):
    found = []
    for path in Path(f'/proc/{pid}/fd').iterdir():
        try:
            target = os.readlink(path)
            if target.endswith(suffix): found.append({'fd': int(path.name), 'target': target,
                'fdinfo': Path(f'/proc/{pid}/fdinfo/{path.name}').read_text()})
        except (FileNotFoundError, PermissionError): pass
    return found


def await_predicate(test, label, seconds=2):
    deadline = time.monotonic() + seconds
    while True:
        value = test()
        if value: return value
        if time.monotonic() >= deadline: raise AssertionError(label)
        time.sleep(.002)


def pending_fifo(root, process, port, text, shutdown=False):
    """Open a real FIFO with a held writer; release it after progress witness."""
    path = root / 'm2/files/resolv'
    path.unlink(); os.mkfifo(path)
    process.send_signal(signal.SIGHUP)
    writer = None
    def attach_writer():
        nonlocal writer
        try: writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK); return True
        except OSError as problem:
            if problem.errno != errno.ENXIO: raise
            return False
    await_predicate(attach_writer, 'FIFO reader never opened')
    fds = await_predicate(lambda: open_file_fds(process.pid, '/m2/files/resolv'), 'FIFO read FD not witnessed')
    health = local_health(port)
    exit_before_release = None
    if shutdown:
        process.send_signal(signal.SIGTERM)
        time.sleep(.1)
        exit_before_release = process.poll()
    # Closing the writer is the explicit release gate for blocking C. Keep
    # pending data/no-data observations distinct from forced fixture cleanup.
    if not shutdown: os.write(writer, text.encode())
    os.close(writer)
    return {'pending_fds': fds, 'health_while_pending': health, 'shutdown': shutdown, 'exit_before_release': exit_before_release}


def trace_read_error(pid, descriptor, output):
    """One child-owned AArch64 read/readv EIO after a successful partial read."""
    if platform.machine() != 'aarch64': raise RuntimeError('ptrace ABI is pinned AArch64')
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    def ptrace(request, address=0, data=0):
        ctypes.set_errno(0)
        value = libc.ptrace(ctypes.c_uint(request), ctypes.c_uint(pid), ctypes.c_void_p(address), ctypes.c_void_p(data))
        if value == -1 and ctypes.get_errno(): raise OSError(ctypes.get_errno(), 'ptrace')
        return value
    registers = (ctypes.c_ulonglong * 34)()
    def regs(write=False):
        value = Iovec(ctypes.addressof(registers), ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204, 1, ctypes.addressof(value))
    report = {'pid': pid, 'descriptor': descriptor, 'reads': [], 'injected': False}
    attached = False
    try:
        ptrace(16); os.waitpid(pid, 0); attached = True
        ptrace(0x4200, 0, 1)  # PTRACE_O_TRACESYSGOOD
        Path(str(output) + '.ready').write_text('attached\n')
        read_active, fault_active, consumed = False, False, False
        while True:
            ptrace(24)
            _, status = os.waitpid(pid, 0)
            if not os.WIFSTOPPED(status): raise AssertionError('tracee ended before injected read')
            stop = os.WSTOPSIG(status)
            if stop != signal.SIGTRAP | 0x80:
                if stop in (signal.SIGTERM, signal.SIGINT): raise AssertionError('tracee interrupted')
                continue
            info = (ctypes.c_ubyte * 128)()
            ptrace(0x420e, ctypes.sizeof(info), ctypes.addressof(info))
            regs()
            if info[0] == 1:
                read_active = registers[8] in (63, 65) and registers[0] == descriptor
                fault_active = read_active and consumed
                if fault_active:
                    syscall = ctypes.c_int(-1)
                    value = Iovec(ctypes.addressof(syscall), ctypes.sizeof(syscall))
                    ptrace(0x4205, 0x404, ctypes.addressof(value))
            elif info[0] == 2 and read_active:
                returned = ctypes.c_longlong(registers[0]).value
                if fault_active:
                    registers[0] = (1 << 64) - errno.EIO; regs(write=True)
                    report['reads'].append({'result': -errno.EIO, 'injected': True})
                    report['injected'] = True
                    ptrace(17); attached = False; break
                report['reads'].append({'result': returned, 'injected': False})
                dump(Path(output), report)
                consumed |= returned > 0
                read_active = False
    finally:
        if attached:
            try: ptrace(17)
            except OSError: pass
        dump(Path(output), report)
    return 0


def partial_stream_error(root, process, text, folder, relative='resolv'):
    path = root / 'm2/files' / relative; path.unlink(); os.mkfifo(path)
    process.send_signal(signal.SIGHUP)
    writer = None
    def attach_writer():
        nonlocal writer
        try: writer = os.open(path, os.O_WRONLY | os.O_NONBLOCK); return True
        except OSError as problem:
            if problem.errno != errno.ENXIO: raise
            return False
    await_predicate(attach_writer, 'partial stream reader never opened')
    fds = await_predicate(lambda: open_file_fds(process.pid, '/m2/files/' + relative), 'partial stream FD not witnessed')
    report_path = folder / 'read-error.json'
    tracer = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--trace-read-error',
        str(process.pid), str(fds[0]['fd']), str(report_path)])
    try:
        await_predicate(lambda: Path(str(report_path) + '.ready').exists() or tracer.poll() is not None, 'ptrace attach deadline')
        if tracer.poll() is not None: raise AssertionError('ptrace attach failed')
        os.write(writer, text.encode())
        await_predicate(lambda: report_path.exists() or tracer.poll() is not None, 'successful read not witnessed')
        # The nonblocking owner waits for FIFO readiness before its next read.
        # Extra bytes make that attempted read ready; ptrace returns EIO before
        # they are consumed, leaving the already-read final line partial.
        if tracer.poll() is None: os.write(writer, b'never-consumed')
        if tracer.wait(5) != 0: raise AssertionError('read fault injector failed')
        report = json.loads(report_path.read_text())
        if not report['injected'] or not any(r['result'] > 0 for r in report['reads']): raise AssertionError('partial read EIO was not reached')
        return dict(report, input=text.encode().hex())
    finally:
        os.close(writer)
        if tracer.poll() is None: tracer.kill(); tracer.wait()


def large_reload(root, process, port, action):
    path = root / 'm2/files/resolv'
    length = action['bytes']
    body = (b'#' + b'x' * (length - 2) + b'\n' if action['single_line']
            else (b'#' + b'x' * 126 + b'\n') * (length // 128))
    samples, stop = [], threading.Event()
    def reader():
        while not stop.is_set():
            active = bool(open_file_fds(process.pid, '/m2/files/resolv'))
            sample = local_health(port, 0x3200 + len(samples) % 1024)
            samples.append(dict(sample, file_active=active, file_still_active=bool(open_file_fds(process.pid, '/m2/files/resolv'))))
            time.sleep(.001)
    worker = threading.Thread(target=reader); worker.start()
    try:
        path.write_bytes(body + action['tail'].encode())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if len(samples) >= 30 and not open_file_fds(process.pid, '/m2/files/resolv'): break
            time.sleep(.002)
        else: raise AssertionError('large resolver job did not drain')
    finally:
        stop.set(); worker.join(1)
    if worker.is_alive() or not samples: raise AssertionError('health sampler missing or leaked')
    latency = sorted(x['elapsed'] for x in samples)
    active_latency = sorted(x['elapsed'] for x in samples if x['file_active'])
    return {'bytes': len(body) + len(action['tail']), 'sha256': sha256(path), 'samples': samples,
            'p95_seconds': latency[min(len(latency) - 1, int(len(latency) * .95))],
            'pending_p95_seconds': active_latency[min(len(active_latency) - 1, int(len(active_latency) * .95))] if active_latency else None,
            'all_healthy': all(x['healthy'] for x in samples),
            'healthy_while_file_open': sum(x['healthy'] and x['file_active'] and x['file_still_active'] for x in samples)}


def run_side(root, side, case, folder):
    folder.mkdir()
    data = root / 'm2/files'
    if data.exists(): shutil.rmtree(data)
    data.mkdir()
    # Nonroot daemon fixtures need write access to the PID parent at shutdown.
    # The resolver data stays root-owned so chmod(0) still witnesses EACCES.
    (root / 'm2').chmod(0o777 if case.get('user', 'root') != 'root' else 0o755)
    opened, connections, pending = {}, {}, {}
    transfers, limit_before = {}, None
    startup_writer = None
    routes, addresses, links = [], [], []
    if case.get('dhcp_witness'):
        subprocess.run(['ip', 'link', 'add', 'm5filelan', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'link', 'set', 'm5filelan', 'up'], check=True)
        subprocess.run(['ip', 'addr', 'add', '198.18.5.1/24', 'dev', 'm5filelan'], check=True)
        links.append('m5filelan')
    if case.get('scoped_upstream'):
        subprocess.run(['ip', 'link', 'add', 'm5scope', 'type', 'dummy'], check=True)
        subprocess.run(['ip', 'link', 'set', 'm5scope', 'up'], check=True)
        subprocess.run(['ip', '-6', 'addr', 'add', 'fe80::53/64', 'dev', 'm5scope', 'nodad'], check=True)
        links.append('m5scope')
    route_socket = None
    if any(a['op'] in ('route', 'address-route') for a in case['actions']):
        route_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        route_socket.bind((0, 0x40 | 0x400)); route_socket.settimeout(.02)
    for path, value in case['files'].items(): put(root, path, value, opened)
    for path, value in case.get('sys_files', {}).items():
        target = image_path(root, path); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(value)
    if case.get('dhcp_witness'):
        (data / 'helper.sh').chmod(0o755)
    if case.get('fifo_startup'):
        (data / 'resolv').unlink(); os.mkfifo(data / 'resolv')
    helper_offset = 0
    names = {(a['name'], a.get('type', 1)) for a in case['actions'] if a['op'] in ('query', 'start-udp', 'start-tcp')}
    upstreams = []
    for index, address in enumerate(['127.0.0.2', '127.0.0.3', '127.0.0.4', '::1'] + (['127.0.0.1'] if case.get('local_upstream') else []) + (['fe80::53%m5scope'] if case.get('scoped_upstream') else [])):
        fixtures = [{'name': host, 'type': kind, 'reply': f'192.0.2.{11 if case.get("common_upstream_reply") else 11 + index}' if kind == 1 else f'2001:db8::{11 + index}'} for host, kind in names]
        delayed = {a['name'] for a in case['actions'] if a['op'] == 'start-udp'}
        for fixture in fixtures:
            if fixture['name'] in delayed: fixture['drop_all'] = True
            if any(a['op'] == 'start-tcp' and a['name'] == fixture['name'] for a in case['actions']): fixture['hold_tcp'] = True
            if fixture['name'] in case.get('negative_names', []): fixture.update(rcode=3, records=[])
        upstreams.append(FileUpstream(fixtures, address, 53))
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0)); port = reserve.getsockname()[1]
    config = ('no-hosts\nno-0x20-encode\nno-round-robin\n' + ('strict-order\n' if case.get('strict_order', True) else '')
              + f'user={case.get("user", "root")}\ngroup={case.get("group", "root")}\n'
              + (f'listen-address={case.get("listen", "127.0.0.1")}\n' if case.get('listen', '127.0.0.1') is not None else '')
              + 'host-record=ready.files.test,192.0.2.250\n'
              'pid-file=/m2/files.pid\n' + f'port={0 if case.get("dns_disabled") else port}\ncache-size={case.get("cache_size", 0)}\n'
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
            if case.get('inotify_fault'): argv = [sys.executable, str(Path(__file__).resolve()), '--exec-inotify-fault', str(case['inotify_fault']), *argv]
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
            if case.get('fifo_startup'):
                result['fifo_startup_before_writer'] = local_health(port)
                def initial_writer():
                    with (data / 'resolv').open('wb') as writer: writer.write(b'nameserver 127.0.0.2\n')
                startup_writer = threading.Thread(target=initial_writer); startup_writer.start()
            deadline = time.monotonic() + 3
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    ready = exchange(port, probe('ready', 'ready.files.test'), 0x3000, 'udp', upstreams, connections)
                    if ready['response'] or (case.get('dns_disabled') and (root / 'm2/files.pid').exists()):
                        result['startup'] = {'ready': True}; break
                except OSError:
                    pass
                time.sleep(.01)
            else:
                result['startup'] = {'ready': False, 'exit': process.poll()}
            if result['startup']['ready']:
                result['identity'] = process_identity(root, process.pid)
                result['inotify_fds'] = open_file_fds(process.pid, 'anon_inode:inotify')
                if case.get('fd_cancel'): result['fd_before'] = sorted(os.readlink(path) for path in Path(f'/proc/{process.pid}/fd').iterdir())
                expected = sha256(root / ('usr/sbin/dnsmasq' if side == 'c' else 'usr/sbin/dnsmasq-rs'))
                if result['identity']['sha256'] != expected: raise AssertionError('running ELF identity mismatch')
                for index, action in enumerate(case['actions']):
                    op = action['op']
                    if op == 'query':
                        for number, transport in enumerate(action.get('transports', ['udp', 'tcp'])):
                            result['rows'].append(exchange(port, action, 0x4000 + index * 4 + number, transport, upstreams, connections))
                    elif op == 'start-tcp':
                        client = socket.create_connection(('127.0.0.1', port), 1); client.settimeout(2)
                        packet = query(action, 0x4000 + index * 4)
                        before = [len(u.events) for u in upstreams]
                        client.sendall(struct.pack('!H', len(packet)) + packet)
                        connections[action['id']] = client
                        pending[action['id']] = {'client': client, 'packet': packet, 'before': before, 'name': action['name']}
                        await_predicate(lambda: sum(len(u.events) - n for u, n in zip(upstreams, before)), 'pending TCP did not reach upstream')
                    elif op == 'await-upstream':
                        held = pending[action['id']]
                        await_predicate(lambda: any(read_name(row[0], 12)[0] == held['name'] for row in upstreams[action['server']].captured), 'retry never reached changed upstream')
                    elif op == 'release-tcp': upstreams[action['server']].release_tcp.set()
                    elif op == 'receive-tcp':
                        held = pending[action['pending']]
                        response = exact_read(held['client'], struct.unpack('!H', exact_read(held['client'], 2))[0])
                        result['rows'].append({'id': action['id'] + ':tcp-async', 'response': semantics(response),
                            'error': None, 'request': held['packet'].hex(), 'reply': response.hex(), 'elapsed': 0, 'cache': False,
                            'upstreams': [{'server': u.host, 'events': copy.deepcopy(u.events[n:])} for u, n in zip(upstreams, held['before'])]})
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
                    elif op == 'dhcp-inform':
                        request = dhcp_wire.request({'kind': 8, 'ciaddr': '127.0.0.10', 'prl': [224]}, 0xd5800000 + index)
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                            endpoint.bind(('0.0.0.0', 68)); endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); endpoint.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')
                            response, peer, _, _ = dhcp_wire.receive(endpoint, request, ('255.255.255.255', 67), timeout=.5)
                        if response is None: raise AssertionError('DHCP INFORM reply missing across reload')
                        result['rows'].append({'id': action['id'] + ':dhcp', 'packet': response.hex(), 'request': request.hex(),
                            'response': None, 'error': None, 'cache': False, 'upstreams': []})
                    elif op == 'pause': time.sleep(action['seconds'])
                    elif op == 'fd-limit':
                        if action.get('restore'):
                            resource.prlimit(process.pid, resource.RLIMIT_NOFILE, limit_before); limit_before = None
                        else:
                            limit_before = resource.prlimit(process.pid, resource.RLIMIT_NOFILE)
                            descriptors = {int(p.name) for p in Path(f'/proc/{process.pid}/fd').iterdir()}
                            ceiling = action['limit']
                            if ceiling == 'first-free':
                                ceiling = next(n for n in range(max(descriptors) + 2) if n not in descriptors)
                            resource.prlimit(process.pid, resource.RLIMIT_NOFILE, (ceiling, limit_before[1]))
                        result['actions'].append({'op': 'actual-fd-limit', 'limits': resource.prlimit(process.pid, resource.RLIMIT_NOFILE)})
                    elif op == 'stream-read-error':
                        result['actions'].append({'op': 'partial-read-eio', **partial_stream_error(root, process, action['text'], folder, action.get('path', 'resolv'))})
                    elif op == 'large-file':
                        evidence = large_reload(root, process, port, action)
                        result['actions'].append({'op': 'large-file-health', 'id': action['id'], **evidence})
                        result['rows'].append({'id': action['id'] + ':large', 'all_healthy': evidence['all_healthy'],
                            'response': None, 'error': None, 'cache': False, 'upstreams': []})
                    elif op == 'fifo-reload':
                        evidence = pending_fifo(root, process, port, action['text'], action.get('shutdown', False))
                        result['actions'].append({'op': 'fifo-progress', 'id': action['id'], **evidence})
                    elif op == 'write-delete-paused':
                        process.send_signal(signal.SIGSTOP)
                        try:
                            await_predicate(lambda: '\nState:\tT' in Path(f'/proc/{process.pid}/status').read_text(), 'paused owner missing')
                            put(root, action['path'], action['text'], opened); (data / action['path']).unlink()
                        finally: process.send_signal(signal.SIGCONT)
                    elif op == 'tftp-start':
                        endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); endpoint.settimeout(1)
                        endpoint.sendto(b'\x00\x01payload\x00octet\x00', ('127.0.0.1', 69))
                        packet, peer = endpoint.recvfrom(4096)
                        if packet[:4] != b'\x00\x03\x00\x01': raise AssertionError('TFTP DATA1 missing')
                        transfers[action['id']] = {'socket': endpoint, 'peer': peer, 'packets': [packet], 'body': packet[4:]}
                    elif op == 'tftp-finish':
                        transfer = transfers[action['id']]; endpoint = transfer['socket']
                        block = 1
                        while len(transfer['packets'][-1]) == 516:
                            endpoint.sendto(struct.pack('!HH', 4, block), transfer['peer'])
                            packet, peer = endpoint.recvfrom(4096)
                            block += 1
                            if peer != transfer['peer'] or packet[:4] != struct.pack('!HH', 3, block): raise AssertionError('TFTP transfer discontinuity')
                            transfer['packets'].append(packet); transfer['body'] += packet[4:]
                        endpoint.sendto(struct.pack('!HH', 4, block), transfer['peer'])
                        result['rows'].append({'id': action['id'] + ':tftp', 'body': transfer['body'].hex(),
                            'packets': [packet.hex() for packet in transfer['packets']], 'response': None, 'error': None, 'cache': False, 'upstreams': []})
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
                    elif op == 'reading-count':
                        deadline = time.monotonic() + 2
                        while True:
                            lines = (folder / 'stderr').read_text().splitlines()
                            count = sum('reading /m2/files/resolv' in line for line in lines)
                            if count >= action['minimum']: break
                            if time.monotonic() >= deadline: raise AssertionError('missing successful resolver reading message')
                            time.sleep(.005)
                        time.sleep(.05)
                        count = sum('reading /m2/files/resolv' in line for line in (folder / 'stderr').read_text().splitlines())
                        result['rows'].append({'id': action['id'] + ':reading', 'reading_count': count,
                                               'response': None, 'error': None, 'cache': False, 'upstreams': []})
                    elif op == 'file-burst':
                        process.send_signal(signal.SIGSTOP)
                        try:
                            deadline = time.monotonic() + 1
                            while '\nState:\tT' not in Path(f'/proc/{process.pid}/status').read_text():
                                if time.monotonic() > deadline: raise AssertionError('SIGSTOP not observed')
                                time.sleep(.001)
                            for _ in range(action['count']):
                                put(root, 'resolv', action['text'], opened)
                                # Alternate a different name so the kernel cannot
                                # coalesce identical consecutive close-write events.
                                put(root, 'noise-' + 'x' * 200, 'irrelevant', opened)
                        finally:
                            process.send_signal(signal.SIGCONT)
                    elif op == 'metrics':
                        samples, deadline = [], time.monotonic() + 1
                        while True:
                            response = subprocess.run(command(root, '/bin/ubus', 'call', 'file-metrics', 'metrics', '{}'), capture_output=True, text=True, timeout=2)
                            if response.returncode: raise AssertionError('ubus metrics failed: ' + response.stderr)
                            value = json.loads(response.stdout)
                            samples.append(value)
                            if value['tcp_connections'] == len(connections): break
                            if time.monotonic() >= deadline: raise AssertionError('closed TCP connection gauge did not drain')
                            time.sleep(.01)
                        result['actions'].append({'op': 'metrics-drain', 'id': action['id'], 'samples': samples})
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
                if case.get('fd_cancel'):
                    time.sleep(.1)
                    result['fd_after'] = sorted(os.readlink(path) for path in Path(f'/proc/{process.pid}/fd').iterdir())
    finally:
        if limit_before is not None and process is not None and process.poll() is None:
            resource.prlimit(process.pid, resource.RLIMIT_NOFILE, limit_before)
        if startup_writer is not None:
            startup_writer.join(1)
            if startup_writer.is_alive(): result['startup_writer_leaked'] = True
        for transfer in transfers.values(): transfer['socket'].close()
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



def witness_errors(observed, side, case):
    """Reject empty/missing fault evidence and preserve the C FIFO limitation."""
    errors = []
    actions = observed.get('actions', [])
    def witness(op, ident=None):
        return next((x for x in actions if x.get('op') == op and (ident is None or x.get('id') == ident)), None)
    for action in case['actions']:
        op = action['op']
        if op == 'large-file':
            found = witness('large-file-health', action['id'])
            if not found or not found.get('samples') or found.get('bytes', 0) < action['bytes'] or not found.get('all_healthy'):
                errors.append('large-file health data absent or failed')
            elif not action['single_line'] and side == 'rust' and not found.get('healthy_while_file_open'):
                errors.append('Rust did not answer while the large file was still open')
        elif op == 'stream-read-error':
            found = witness('partial-read-eio')
            if not found or not found.get('injected') or not any(x.get('result', 0) > 0 for x in found.get('reads', [])) or not any(x.get('injected') and x.get('result') == -errno.EIO for x in found.get('reads', [])):
                errors.append('partial read plus injected EIO not witnessed')
        elif op == 'fifo-reload':
            found = witness('fifo-progress', action['id'])
            if not found or not found.get('pending_fds') or found.get('health_while_pending', {}).get('healthy') != (side == 'rust'):
                errors.append('FIFO blocking C/nonblocking Rust classification failed')
            if action.get('shutdown') and found and found.get('exit_before_release') != 0:
                errors.append('pending FIFO shutdown classification failed')
        elif op == 'tftp-finish':
            found = next((row for row in observed['rows'] if row['id'] == action['id'] + ':tftp'), {})
            if found.get('body') != ('T' * 1400).encode().hex() or len(found.get('packets', [])) != 3:
                errors.append('TFTP transfer payload or blocks missing')
        elif op == 'fd-limit' and not action.get('restore'):
            if not any('No file descriptors available' in line for line in observed.get('file_diagnostics', [])):
                errors.append('runtime resolver EMFILE not reached')
    if case.get('fifo_startup') and observed.get('fifo_startup_before_writer', {}).get('healthy') is not False:
        errors.append('FIFO startup replied before initial source completed')
    if observed.get('startup_writer_leaked'): errors.append('FIFO startup writer leaked')
    if case.get('fd_cancel') and (not observed.get('fd_before') or len(observed.get('fd_after', [])) != len(observed['fd_before'])):
        errors.append('cancelled upstream descriptor did not return to baseline')
    return errors


def compare(left, right, case):
    failures = [dict(phase='fault-witness', side=side, error=error)
                for side, observed in [('c', left), ('rust', right)] for error in witness_errors(observed, side, case)]
    if case.get('diagnostics') and left['file_diagnostics'] != right['file_diagnostics']:
        failures.append({'phase': 'file-diagnostics', 'c': left['file_diagnostics'], 'rust': right['file_diagnostics']})
    for phase in ('syntax', 'startup'):
        a, b = copy.deepcopy(left[phase]), copy.deepcopy(right[phase])
        for value in (a, b):
            for stream in ('stdout', 'stderr'):
                if stream in value: value[stream] = normalized_text(value[stream])
        if a != b: failures.append({'phase': phase, 'c': a, 'rust': b})
    suffixes = {'helper-events': ['helper'], 'receive-udp': ['udp-async'], 'metrics': ['metrics'], 'reading-count': ['reading'], 'receive-tcp': ['tcp-async'], 'large-file': ['large'], 'tftp-finish': ['tftp'], 'dhcp-inform': ['dhcp']}
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
    for kind, op, payload in [('helper', 'helper-events', {'helper_events': ['old|mac|ip|name']}),
                              ('metrics', 'metrics', {'metrics': {'dns_cache_inserted': 1, 'dns_queries_forwarded': 2}}),
                              ('reading', 'reading-count', {'reading_count': 1})]:
        observed = copy.deepcopy(base)
        observed['rows'] = [dict(id='one:' + kind, response=None, error=None, cache=False, upstreams=[], **payload)]
        config = {'actions': [{'op': op, 'id': 'one'}]}
        assert not compare(observed, copy.deepcopy(observed), config)
        changed = copy.deepcopy(observed)
        key = next(iter(payload))
        changed['rows'][0][key] = [] if kind == 'helper' else {} if kind == 'metrics' else 0
        assert compare(observed, changed, config)
        found.append('wrong-' + kind)
    # Every new side channel must be falsifiable independently of the DNS rows.
    for label, op, action, recorded in [
        ('partial-read', 'stream-read-error', {}, {'op': 'partial-read-eio', 'injected': True, 'reads': [{'result': 41}, {'result': -5, 'injected': True}]}),
        ('fifo-progress', 'fifo-reload', {'id': 'fifo'}, {'op': 'fifo-progress', 'id': 'fifo', 'pending_fds': [{'fd': 10}], 'health_while_pending': {'healthy': True}}),
        ('large-progress', 'large-file', {'id': 'large', 'bytes': 1024, 'single_line': False}, {'op': 'large-file-health', 'id': 'large', 'bytes': 1024, 'samples': [{}], 'all_healthy': True, 'healthy_while_file_open': 1}),
    ]:
        case = {'actions': [dict(op=op, **action)]}
        sample = {'actions': [recorded], 'rows': []}
        assert not witness_errors(sample, 'rust', case), label
        assert witness_errors({'actions': [], 'rows': []}, 'rust', case), label
        found.append('missing-' + label)
    return found


def exec_inotify_fault(argv):
    kind, argv = argv[0], argv[1:]
    number, error = {'watch-eacces': (27, errno.EACCES), 'readlink-eacces': (78, errno.EACCES)}.get(kind, (26, errno.EMFILE))
    if platform.machine() != 'aarch64': raise RuntimeError('fault syscall ABI is pinned AArch64')
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
    # asm-generic __NR_inotify_init1=26; deny only this syscall with EMFILE.
    filters = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x50000 | error), Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(4, filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), 'seccomp setup')
    os.execvp(argv[0], argv)



def qualify(args):
    """Audit immutable raw runs against every frozen required case."""
    from m5_option_matrix_archive import verify as verify_archive
    manifest = json.loads(args.requirements.read_text())
    frozen = json.loads(args.frozen_checklist.read_text())
    if manifest['source_identity'] != frozen['source_identity']: raise AssertionError('C source identities changed')
    if [b['id'] for b in manifest['boundaries']] != [b['id'] for b in frozen['boundaries']]: raise AssertionError('frozen boundary inventory changed')
    for mapped, original in zip(manifest['boundaries'], frozen['boundaries']):
        if [x['requirement'] for x in mapped['required_cases']] != original['required_cases']:
            raise AssertionError('required cases were removed or renamed: ' + mapped['id'])
    candidate_sha = sha256(args.rust)
    build = json.loads(args.build_json.read_text())
    artifact = next(x for x in build['artifacts'] if x['path'] == 'dnsmasq-rs')
    if artifact['sha256'] != candidate_sha or artifact['bytes'] != args.rust.stat().st_size: raise AssertionError('candidate build artifact mismatch')
    if args.source_commit not in build['source']: raise AssertionError('candidate source path mismatch')
    # Git blob hashes bind every compiled crate source/manifest/config to the
    # original immutable build archive without trusting today's worktree.
    tree = subprocess.check_output(['git', 'ls-tree', '-rz', args.source_commit, '--',
        'components/dnsmasq', 'components/ubus', 'components/platform', '.cargo', 'rust-toolchain.toml'])
    expected = {}
    for row in tree.split(b'\0'):
        if not row: continue
        mode, kind, rest = row.split(b' ', 2); blob, path = rest.split(b'\t', 1)
        if kind == b'blob': expected[path.decode()] = blob.decode()
    checked = {}
    with tarfile.open(args.source_archive) as archive:
        for entry in archive:
            if entry.name not in expected: continue
            data = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if blob != expected[entry.name]: raise AssertionError('build input differs from commit: ' + entry.name)
            checked[entry.name] = hashlib.sha256(data).hexdigest()
    if set(checked) != set(expected): raise AssertionError('source archive lacks compiled inputs')
    catalog = {case['id']: case for case in scenarios()}
    by_case, archives, raw_results = {}, [], []
    for run in args.qualify_runs:
        report = json.loads((run / 'result.json').read_text())
        schedule = json.loads((run / 'schedule.json').read_text())
        if report['source_commit'] != args.source_commit or report['rust_sha256'] != candidate_sha or report['stock_sha256'] != STOCK_SHA256 or report['failures']:
            raise AssertionError('run is failed or belongs to a different candidate: ' + str(run))
        if [x['id'] for x in report['scenarios']] != [x['id'] for x in schedule]: raise AssertionError('schedule incomplete')
        if set(controls()) - set(report['negative_controls']): raise AssertionError('run lacks required negative controls')
        for name, digest in report['driver_sha256'].items():
            if sha256(run / 'driver' / name) != digest: raise AssertionError('executed driver changed')
        for case, row in zip(schedule, report['scenarios']):
            if case['id'] not in catalog or row['failures']: raise AssertionError('unknown or failed scenario')
            observed = {side: json.loads((run / case['id'] / side / 'observed.json').read_text()) for side in ['c', 'rust']}
            errors = compare(observed['c'], observed['rust'], case)
            if errors: raise AssertionError({'case': case['id'], 'recheck': errors})
            for side, value in observed.items():
                wanted = STOCK_SHA256 if side == 'c' else candidate_sha
                if value['startup']['ready'] and value.get('identity', {}).get('sha256') != wanted: raise AssertionError('runtime ELF identity missing')
            if row['rows'] != len(observed['c']['rows']): raise AssertionError('observation count changed')
            by_case[case['id']] = {'result': str(run / 'result.json'), 'result_sha256': sha256(run / 'result.json'),
                'observed': {side: {'path': str(run / case['id'] / side / 'observed.json'), 'sha256': sha256(run / case['id'] / side / 'observed.json')} for side in observed},
                'rows': row['rows']}
        archived = run.parent / 'archives' / run.name
        archive, metadata = Path(str(archived) + '.tar.gz'), Path(str(archived) + '.json')
        verified = verify_archive(archive, metadata, None)
        prune = json.loads(Path(str(archived) + '.pruned.json').read_text())
        if prune['archive_sha256'] != verified['archive_sha256']: raise AssertionError('remote prune receipt mismatch')
        archives.append(dict(path=str(archive), manifest=str(metadata), **verified, remote_removed=prune['removed']))
        raw_results.append({'path': str(run / 'result.json'), 'sha256': sha256(run / 'result.json')})
    if set(catalog) != set(by_case): raise AssertionError({'unscheduled_or_missing': sorted(set(catalog) - set(by_case))})
    enospc = json.loads(args.enospc_audit.read_text())
    if not enospc['cases'] or any(x['errno'] != errno.ENOSPC or x['product_observations'] != 0 or not x['rerun_passed'] for x in enospc['cases']):
        raise AssertionError('ENOSPC infrastructure classification missing')
    # Actual descriptor flags, including inotify NONBLOCK/CLOEXEC, are observed
    # under both image binaries; they are never inferred from option metadata.
    flag_case = by_case['file-global-source-interleave']
    for side in ['c', 'rust']:
        observed = json.loads(Path(flag_case['observed'][side]['path']).read_text())
        flags = [int(next(line.split()[1] for line in x['fdinfo'].splitlines() if line.startswith('flags:')), 8) for x in observed.get('inotify_fds', [])]
        if not flags or any(value & 0o2004000 != 0o2004000 for value in flags): raise AssertionError('inotify descriptor flags missing')
    audit = []
    external = {'@enospc-audit', '@negative-controls', '@all-cleanup', '@whole-family', '@all-required', '@archive-verified', '@remote-pruned', '@elf-identity'}
    for boundary in manifest['boundaries']:
        cases = []
        for item in boundary['required_cases']:
            if item['deferred']:
                if boundary['id'] != 'SFILE-05': raise AssertionError('unexpected deferred requirement')
                cases.append(dict(item, checked=False, reason='server/local/rev-server endpoint family')); continue
            if not item['scenarios'] or any(name not in by_case and name not in external for name in item['scenarios']): raise AssertionError('required case has no concrete witness')
            cases.append(dict(item, checked=True, evidence=[by_case[name] if name in by_case else {'audit': name} for name in item['scenarios']]))
        audit.append(dict(boundary, required_cases=cases, checked=all(x['checked'] for x in cases)))
    options = {}
    for option in ['resolv-file', 'servers-file', 'no-poll', 'clear-on-reload']:
        relevant = [b for b in audit if option in b['options']]
        options[option] = {'checked': all(b['checked'] for b in relevant), 'boundaries': [b['id'] for b in relevant], 'deferred': [b['id'] for b in relevant if not b['checked']]}
    output = {'schema': 'dns-files-required-case-qualification-v1', 'closed_options': [name for name, value in options.items() if value['checked']],
        'options': options, 'candidate': {'source_commit': args.source_commit, 'sha256': candidate_sha, 'bytes': args.rust.stat().st_size,
            'previous_candidate_bytes': 1474584, 'delta_bytes': args.rust.stat().st_size - 1474584}, 'stock_sha256': STOCK_SHA256,
        'source_archive': {'path': str(args.source_archive), 'sha256': sha256(args.source_archive), 'verified_compiled_inputs': checked},
        'frozen_checklist_sha256': sha256(args.frozen_checklist), 'requirements_sha256': sha256(args.requirements),
        'scenarios': len(by_case), 'observations': sum(x['rows'] for x in by_case.values()), 'negative_controls': controls(),
        'checked_boundaries': sum(b['checked'] for b in audit), 'boundaries': audit, 'raw_results': raw_results, 'archives': archives,
        'enospc_infrastructure_only': {'path': str(args.enospc_audit), 'sha256': sha256(args.enospc_audit)},
        'reference_differences': [{'name': 'blocking FIFO stream input', 'scope': 'C blocks DNS while a resolver FIFO writer stays open; Rust retains single-owner DNS service. Both publish the same stream and terminate cleanly on TERM.',
            'evidence': [by_case[name] for name in ['fifo-startup', 'fifo-runtime', 'pending-file-shutdown']]}]}
    if args.output.exists(): raise ValueError('fresh qualification output required')
    dump(args.output, output)
    print(json.dumps({'closed_options': output['closed_options'], 'scenarios': output['scenarios'], 'observations': output['observations'], 'checked_boundaries': output['checked_boundaries']}))
    return 0


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
    parser.add_argument('--qualify-runs', nargs='+', type=Path)
    parser.add_argument('--requirements', type=Path, default=Path(__file__).with_name('m5_dns_files_requirements.json'))
    parser.add_argument('--frozen-checklist', type=Path)
    parser.add_argument('--enospc-audit', type=Path)
    parser.add_argument('--build-json', type=Path)
    parser.add_argument('--source-archive', type=Path)
    args = parser.parse_args()
    negative = controls()
    if args.qualify_runs: return qualify(args)
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
              'incomplete_boundaries': ['FAIL-01 runtime file/watch/shutdown faults',
                                        'FAIL-02 large/long/nonregular/partial reads',
                                        'STATE-04 pending TCP publication',
                                        'STATE-05 TFTP transfer across reload',
                                        'RSLV-05 partial stream read error',
                                        'SFILE-05 endpoint dependency'], 'closed_options': []}
    driver = out / 'driver'; driver.mkdir()
    dependencies = ['m5_dns_files.py', 'm5_option_matrix.py', 'm5_option_matrix_probes.py', 'm2_rootfs.py', 'dns_service_probe.py', 'run_isolated.sh', 'm5_dhcp_tags_options.py', 'dhcp_boot_service_diff.py']
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
                if 'expect_reading' in action:
                    actual = next((entry for entry in c['rows'] if entry['id'] == action['id'] + ':reading'), {})
                    if actual.get('reading_count') != action['expect_reading']:
                        row['failures'].append({'phase': 'c-reading-calibration', 'id': action['id'], 'expected': action['expect_reading'], 'actual': actual})
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
    # Scenario boundary IDs are an index, not proof that every required case
    # in the source checklist ran. Keep qualification open until those cases
    # have individual evidence, including file faults and live transfers.
    dump(out / 'result.json', report)
    print(json.dumps({'scenarios': len(selected), 'rows': sum(row.get('rows', 0) for row in report['scenarios']), 'failures': len(report['failures']), 'closed_options': report['closed_options']}))
    return int(bool(report['failures']))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--trace-read-error':
        raise SystemExit(trace_read_error(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))
    if len(sys.argv) > 1 and sys.argv[1] == '--exec-inotify-fault': exec_inotify_fault(sys.argv[2:])
    raise SystemExit(main())
