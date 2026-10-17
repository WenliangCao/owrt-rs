#!/usr/bin/env python3
"""One exact-image logging/CLI family differential driver; raw evidence retained."""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import fcntl
import json
import os
import platform
import select
import threading
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import time

from dns_service_probe import answer as ordinary_upstream_answer, exact_read, name as wire_name, query, read_name, rr, semantics
from m2_rootfs import bind_unix_socket, STOCK_SHA256, command, image_path, prepare, process_identity, sha256
from m5_dhcp_tags_options import comparable_reply, inform_clock_witness, primary_options

DEPENDENCIES = ['dns_service_probe.py', 'm2_rootfs.py', 'run_isolated.sh',
                'm5_logging_requirements.json', 'm5_dhcp_tags_options.py',
                'dhcp_boot_service_diff.py']
FACILITIES = {'kern': 0, 'user': 8, 'mail': 16, 'daemon': 24, 'auth': 32,
              'security': 32, 'syslog': 40, 'lpr': 48, 'news': 56, 'uucp': 64,
              'cron': 72, 'authpriv': 80, 'ftp': 88, 'local0': 128, 'local1': 136,
              'local2': 144, 'local3': 152, 'local4': 160, 'local5': 168,
              'local6': 176, 'local7': 184, 'mark': 192}
RUST_VERSION_IDENTITY = '; dnsmasq-rs 0.1.0 (Rust implementation)'
RETRY_BARRIER_SECONDS = 2
BASE = ['--no-hosts', '--no-resolv', '--bind-interfaces', '--no-0x20-encode',
        '--listen-address=127.0.0.1', '--port=15353', '--group=root',
        '--pid-file=', '--host-record=ready.logging,192.0.2.1']


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def cases():
    rows = []
    for name, facility in FACILITIES.items():
        rows.append({'id': 'facility-' + name, 'scope': 'sink', 'kind': 'run',
                     'argv': ['--log-facility=' + name], 'facility': facility,
                     'receiver': 'dgram', 'options': ['log-facility']})
    rows.extend([
        {'id': 'facility-uppercase', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=SeCuRiTy'], 'facility': 32, 'receiver': 'dgram',
         'options': ['log-facility']},
        {'id': 'default-normal', 'scope': 'sink', 'kind': 'run', 'argv': [],
         'facility': 24, 'receiver': 'dgram', 'options': ['log-facility', 'no-daemon']},
        {'id': 'default-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': [], 'facility': 128, 'receiver': 'dgram',
         'options': ['log-facility', 'no-daemon']},
        {'id': 'debug-explicit-daemon', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=daemon'], 'facility': 24, 'receiver': 'dgram',
         'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-foreground', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'stderr-debug-foreground', 'scope': 'sink', 'kind': 'run', 'mode': ['-d', '-k'],
         'argv': ['--log-facility=-'], 'options': ['log-facility', 'no-daemon']},
        {'id': 'file-create', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o640, 0, 0], 'options': ['log-facility']},
        {'id': 'file-append', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'existing': 'preexisting\n', 'file_mode': 0o604, 'expected_metadata': [0o604, 0, 0],
         'options': ['log-facility']},
        {'id': 'file-owner-normal', 'scope': 'sink', 'kind': 'run', 'user': 'nobody',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o660, 65534, 0], 'options': ['log-facility']},
        {'id': 'file-owner-debug', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'], 'user': 'nobody',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'expected_metadata': [0o660, 65534, 0], 'options': ['log-facility', 'no-daemon']},
        {'id': 'file-existing-group-owner', 'scope': 'sink', 'kind': 'run', 'user': 'nobody',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'existing': 'preexisting\n', 'file_mode': 0o640, 'file_gid': 65534,
         'expected_metadata': [0o640, 65534, 65534], 'options': ['log-facility']},
        {'id': 'file-rotate', 'scope': 'sink', 'kind': 'run', 'rotate': True,
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'options': ['log-facility']},
        {'id': 'file-reopen-fails', 'scope': 'sink', 'kind': 'run', 'rotate': True,
         'reopen_directory': True, 'receiver': 'dgram',
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'options': ['log-facility']},
        {'id': 'tcp-accepted-file-rotation', 'scope': 'sink', 'kind': 'run',
         'tcp_rotate': True, 'file': 'daemon.log',
         'argv': ['--log-facility=/m2/logging/daemon.log', '--log-debug', '--strict-order',
                  '--server=127.0.0.2#15955', '--server=127.0.0.3#15956'],
         'options': ['log-facility', 'log-debug']},
        {'id': 'syslog-stream', 'scope': 'sink', 'kind': 'run', 'receiver': 'stream',
         'facility': 24, 'argv': [], 'options': ['log-facility']},
        {'id': 'file-open-missing-parent', 'scope': 'sink', 'kind': 'run', 'exit': 3,
         'receiver': 'dgram', 'argv': ['--log-facility=/m2/logging/missing/daemon.log'],
         'options': ['log-facility']},
        {'id': 'facility-file-origins', 'scope': 'sink', 'kind': 'run',
         'config': 'log-facility=/m2/logging/daemon.log\n', 'file': 'daemon.log',
         'argv': ['--log-facility=local3'], 'options': ['log-facility']},
        {'id': 'stderr-sigusr2-keeps-fd', 'scope': 'sink', 'kind': 'run',
         'argv': ['--log-facility=-'], 'sink_edge': 'preserve', 'options': ['log-facility']},
        {'id': 'syslog-sigusr2-keeps-fd', 'scope': 'sink', 'kind': 'run',
         'argv': [], 'receiver': 'dgram', 'facility': 24,
         'sink_edge': 'preserve', 'options': ['log-facility']},
        {'id': 'debug-stderr-no-extra-fd', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': [], 'receiver': 'dgram', 'facility': 128,
         'sink_edge': 'debug-fd', 'options': ['log-facility', 'no-daemon']},
        {'id': 'file-reopen-recovers-owner', 'scope': 'sink', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log',
         'receiver': 'dgram', 'user': 'nobody', 'sink_edge': 'recover',
         'options': ['log-facility']},
    ])
    for kind in ['fifo-no-reader', 'fifo-full', 'stderr-full', 'debug-echo-full']:
        rows.append({'id': 'blocked-sink-' + kind, 'scope': 'blocked-sink', 'kind': 'run',
                     'argv': [], 'blocked_kind': kind, 'options': ['log-facility'],
                     'policy_source': 'log.c:135-160,301-319,407-471',
                     'policy_difference': 'The single poll owner must not block. C waits for FIFO open or sink writes; Rust keeps serving with bounded queued records and explicit overflow accounting, then drains on reader recovery.'})
        rows.append({'id': 'blocked-sink-' + kind + '-shutdown', 'scope': 'blocked-sink', 'kind': 'run',
                     'argv': [], 'blocked_kind': kind, 'blocked_never_release': True,
                     'options': ['log-facility'], 'policy_source': 'log.c:135-160,301-319,459-475',
                     'policy_difference': 'The reader never recovers. C startup SIGTERM exits5 for FIFO/primary stderr; debug fprintf remains blocked in libc exit and needs external SIGKILL. Rust serves before TERM, then retains queued records while waiting for the reader and needs external SIGKILL.'})
    rows.append({'id': 'fifo-peer-disconnect-fallback', 'scope': 'blocked-sink', 'kind': 'run',
                 'argv': [], 'blocked_kind': 'fifo-peer-disconnect', 'options': ['log-facility'],
                 'policy_source': 'log.c:289-335',
                 'policy_difference': 'C abandons a failed file descriptor without closing it. Rust closes its owned descriptor; both preserve the critical libc-syslog fallback and later producer payloads/tags.'})
    for name in ['', 'local8', 'audit', '24', 'foo']:
        rows.append({'id': 'bad-facility-' + (name or 'empty'), 'scope': 'sink',
                     'kind': 'test', 'exit': 1, 'argv': ['--log-facility=' + name],
                     'options': ['log-facility', 'test']})
    for name, argv in [('version', ['--version']), ('help', ['--help']),
                       ('help-dhcp', ['--help', 'dhcp']), ('help-dhcp6', ['--help', 'dhcp6']),
                       ('help-unknown', ['--help', 'other']),
                       ('help-dhcp-extra', ['--help', 'dhcp', 'extra'])]:
        rows.append({'id': 'cli-' + name, 'scope': 'cli', 'kind': 'cli', 'argv': argv,
                     'options': ['version'] if name == 'version' else ['help']})
    rows.extend([
        {'id': 'cli-version-invalid-default', 'scope': 'cli', 'kind': 'cli',
         'argv': ['--version'], 'invalid_default': True, 'options': ['version']},
        {'id': 'cli-help-invalid-default', 'scope': 'cli', 'kind': 'cli',
         'argv': ['--help'], 'invalid_default': True, 'options': ['help']},
        {'id': 'test-no-runtime-file', 'scope': 'cli', 'kind': 'test',
         'argv': ['--log-facility=/m2/logging/missing/daemon.log'],
         'options': ['log-facility', 'test']},
        {'id': 'test-debug-stderr', 'scope': 'cli', 'kind': 'test',
         'argv': ['-d', '--log-facility=-'], 'options': ['no-daemon', 'test']},
        {'id': 'no-ident-default', 'scope': 'identity', 'kind': 'run',
         'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user'],
         'chaos': True, 'options': ['no-ident']},
        {'id': 'no-ident-enabled', 'scope': 'identity', 'kind': 'run',
         'argv': ['--log-facility=-', '--no-ident', '--txt-record=kept.logging,explicit-user'],
         'chaos': True, 'options': ['no-ident']},
    ])
    query_modes = [([], 'ordinary'), (['extra'], 'extra'), (['proto'], 'proto'),
                   (['auth'], 'auth'), (['only_failed'], 'only_failed'),
                   ([''], 'ordinary'), (['unknown'], 'ordinary'), (['EXTRA'], 'ordinary'),
                   (['extra,proto'], 'ordinary'), (['proto', 'unknown'], 'proto'),
                   (['extra', 'only_failed'], 'only_failed'), (['auth', 'proto'], 'auth')]
    for index, (modes, expected) in enumerate(query_modes):
        rows.append({'id': f'query-mode-{index:02d}', 'scope': 'query-reference', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries'] +
                             ['--log-queries=' + mode for mode in modes] +
                             ['--host-record=v6.logging,2001:db8::1',
                              '--cname=alias.logging,ready.logging',
                              '--txt-record=kept.logging,explicit-user',
                              '--address=/nxdomain.logging/'],
                     'query_probes': True, 'query_mode': expected, 'options': ['log-queries']})
    rows.append({'id': 'query-debug-proto', 'scope': 'query-reference', 'kind': 'run',
                 'mode': ['-d'], 'argv': ['--log-facility=-', '--log-queries=proto',
                                        '--host-record=v6.logging,2001:db8::1',
                                        '--cname=alias.logging,ready.logging',
                                        '--txt-record=kept.logging,explicit-user',
                                        '--address=/nxdomain.logging/'],
                 'query_probes': True, 'query_mode': 'proto', 'options': ['log-queries', 'no-daemon']})
    local_query_args = [
        '--addn-hosts=/m2/logging/hosts.extra',
        '--host-record=cfg.logging,192.0.2.22,2001:db8::22',
        '--cname=alias-file.logging,file.logging',
        '--cname=orphan.logging,missing-target.logging',
        '--ptr-record=ptr.logging,ptr-target.logging',
        '--mx-host=mx.logging,file.logging,10',
        '--srv-host=_demo._tcp.logging,file.logging,1234,1,2',
        '--naptr-record=naptr.logging,10,20,S,SIP+D2U,,file.logging',
        '--dns-rr=raw.logging,65280,010203',
        '--interface-name=interface.logging,lo',
        '--synth-domain=synth.logging,192.0.2.30,192.0.2.31,s',
        '--filterwin2k', '--domain-needed', '--bogus-priv',
        '--address=/zero.logging/#', '--address=/literal.logging/192.0.2.40',
        '--local=/empty.logging/', '--host-record=known.empty.logging,192.0.2.41',
        '--address=/nxdomain.logging/']
    local_query_sequence = [
        ('READY.LOGGING', 1), ('cfg.logging', 1), ('cfg.logging', 28),
        ('file.logging', 1), ('v6-file.logging', 28), ('alias-file.logging', 1),
        ('21.2.0.192.in-addr.arpa', 12), ('ptr.logging', 12),
        ('mx.logging', 15), ('_demo._tcp.logging', 33), ('naptr.logging', 35),
        ('raw.logging', 65280), ('interface.logging', 1), ('interface.logging', 28),
        ('s192-0-2-30.synth.logging', 1), ('30.2.0.192.in-addr.arpa', 12),
        ('windows.logging', 6), ('_unknown._tcp.logging', 33), ('_unknown.logging', 255),
        ('dotless', 1), ('1.0.0.10.in-addr.arpa', 12), ('orphan.logging', 1),
        ('zero.logging', 1), ('zero.logging', 28), ('literal.logging', 1),
        ('empty.logging', 28), ('missing.empty.logging', 1), ('nxdomain.logging', 1), ('', 1)]
    local_query_messages = [
        'config cfg.logging is 192.0.2.22',
        '/m2/logging/hosts.extra file.logging is 192.0.2.21',
        'config alias-file.logging is <CNAME>',
        '/m2/logging/hosts.extra 192.0.2.21 is file.logging',
        'config ptr.logging is <PTR>', 'config mx.logging is <MX>',
        'config _demo._tcp.logging is <SRV>', 'config naptr.logging is <NAPTR>',
        'config raw.logging is <type=65280>',
        'config interface.logging is 127.0.0.1',
        'config s192-0-2-30.synth.logging is 192.0.2.30',
        'config 192.0.2.30 is s192-0-2-30.synth.logging',
        'config windows.logging is NODATA', 'config dotless is NXDOMAIN',
        'config 10.0.0.1 is NXDOMAIN', 'config orphan.logging is <CNAME>',
        'config zero.logging is 0.0.0.0', 'config zero.logging is ::',
        'config literal.logging is 192.0.2.40',
        'config empty.logging is NODATA-IPv6',
        'config missing.empty.logging is NXDOMAIN', 'query[A] . from 127.0.0.1']
    for name, modes, mode in [('ordinary', [], 'ordinary'), ('proto', ['proto'], 'proto'),
                              ('failed', ['only_failed'], 'only_failed')]:
        required = [message for message in local_query_messages if 'NODATA' in message or 'NXDOMAIN' in message] if mode == 'only_failed' else local_query_messages
        rows.append({'id': 'query-local-' + name, 'scope': 'query-local', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries', *['--log-queries=' + value for value in modes], *local_query_args],
                     'setup_files': {'hosts.extra': '192.0.2.21 file.logging\n2001:db8::21 v6-file.logging\n'},
                     'query_probes': True, 'query_mode': mode, 'query_sequence': local_query_sequence,
                     'query_startup_barrier': 'read /m2/logging/hosts.extra - 2 names\n',
                     'query_required_messages': required, 'options': ['log-queries']})
    forward_query_sequence = [
        ('ready.logging', 1),
        ('a.forward.test', 1), ('a.forward.test', 1),
        ('v6.forward.test', 28), ('v6.forward.test', 28),
        ('alias.forward.test', 1), ('alias.forward.test', 1),
        ('7.2.0.192.in-addr.arpa', 12), ('7.2.0.192.in-addr.arpa', 12),
        ('txt.forward.test', 16), ('txt.forward.test', 16),
        ('nx.forward.test', 1), ('nx.forward.test', 1),
        ('nodata.forward.test', 28), ('nodata.forward.test', 28),
        ('error.forward.test', 1), ('truncated.forward.test', 1)]
    forward_query_messages = [
        'forwarded a.forward.test to 127.0.0.2#15957',
        'reply a.forward.test is 192.0.2.7', 'cached a.forward.test is 192.0.2.7',
        'reply v6.forward.test is 2001:db8::7', 'cached v6.forward.test is 2001:db8::7',
        'reply alias.forward.test is <CNAME>', 'cached alias.forward.test is <CNAME>',
        'reply 192.0.2.7 is ptr-target.forward.test', 'cached 192.0.2.7 is ptr-target.forward.test',
        'reply txt.forward.test is hello', 'cached txt.forward.test is hello',
        'reply txt.forward.test is Second', 'cached txt.forward.test is Second',
        'reply nx.forward.test is NXDOMAIN', 'cached nx.forward.test is NXDOMAIN',
        'reply nodata.forward.test is NODATA-IPv6', 'cached nodata.forward.test is NODATA-IPv6',
        'reply error is REFUSED', 'reply is truncated' ]
    for label, modes, mode in [('ordinary', [], 'ordinary'), ('proto', ['proto'], 'proto'),
                               ('failed', ['only_failed'], 'only_failed')]:
        required = [message for message in forward_query_messages if 'NODATA' in message or 'NXDOMAIN' in message or 'REFUSED' in message] if mode == 'only_failed' else forward_query_messages
        rows.append({'id': 'query-forward-' + label, 'scope': 'query-forward', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries', *['--log-queries=' + value for value in modes],
                              '--server=127.0.0.2#15957', '--server=127.0.0.3#15958', '--all-servers', '--cache-rr=TXT'],
                     'query_probes': True, 'query_mode': mode, 'query_sequence': forward_query_sequence,
                     'query_upstream': True, 'query_required_messages': required,
                     'options': ['log-queries']})
    for label, extra, probes, required in [
        ('filter', ['--filter-A', '--filter-AAAA', '--filter-rr=TXT'],
         [('ready.logging', 1), ('a.forward.test', 1), ('a.forward.test', 1), ('v6.forward.test', 28), ('v6.forward.test', 28), ('txt.forward.test', 16), ('txt.forward.test', 16)],
         ['config a.forward.test is NODATA-IPv4', 'config v6.forward.test is NODATA-IPv6', 'config txt.forward.test is NODATA']),
        ('bogus', ['--bogus-nxdomain=192.0.2.7'],
         [('ready.logging', 1), ('a.forward.test', 1), ('a.forward.test', 1), ('alias.forward.test', 1), ('alias.forward.test', 1)],
         ['config a.forward.test is NXDOMAIN', 'cached a.forward.test is NXDOMAIN']),
        ('rebind', ['--stop-dns-rebind'],
         [('ready.logging', 1), ('rebind.forward.test', 1), ('rebind.forward.test', 1), ('rebind-alias.forward.test', 1), ('rebind-alias.forward.test', 1)],
         ['possible DNS-rebind attack detected: rebind.forward.test', 'possible DNS-rebind attack detected: rebind-terminal.forward.test'])]:
        rows.append({'id': 'query-policy-' + label, 'scope': 'query-policy', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries=proto', '--server=127.0.0.2#15957', '--cache-rr=TXT', *extra],
                     'query_probes': True, 'query_mode': 'proto', 'query_sequence': probes,
                     'query_upstream': True, 'query_required_messages': required, 'options': ['log-queries']})
    rows.append({'id': 'query-control-labels', 'scope': 'query-control', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries=proto'], 'query_probes': True,
                 'query_mode': 'proto', 'query_sequence': [('ready.logging', 1)], 'query_control_probe': True,
                 'chaos_notimp_uninitialised_ede': True,
                 'query_required_messages': ['non-query opcode 2 from 127.0.0.1', 'reply opcode is not implemented',
                                            'config version.bind is not implemented', 'query[A] ready.logging from 127.0.0.1'],
                 'options': ['log-queries']})
    rows.append({'id': 'query-stale-producers', 'scope': 'query-control', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries=proto', '--use-stale-cache', '--server=127.0.0.2#15957'],
                 'query_probes': True, 'query_mode': 'proto', 'query_sequence': [('ready.logging', 1)],
                 'query_upstream': True, 'query_stale_probe': True,
                 'query_required_messages': ['cached-stale stale-udp.forward.test is 192.0.2.7',
                                             'cached-stale stale-tcp.forward.test is 192.0.2.7'],
                 'options': ['log-queries']})
    refresh = copy.deepcopy(next(row for row in rows if row['id'] == 'query-stale-producers'))
    refresh['id'] = 'query-stale-refresh-context'
    refresh['query_refresh_reply'] = True
    refresh['query_required_messages'].extend(['UDP 106 reply stale-udp.forward.test is 192.0.2.7',
                                               'TCP 107 reply stale-tcp.forward.test is 192.0.2.7'])
    rows.append(refresh)
    rows.append({'id': 'query-upstream-errors', 'scope': 'query-control', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries=proto', '--all-servers', '--server=127.0.0.2#15957', '--server=127.0.0.3#15958'],
                 'query_probes': True, 'query_mode': 'proto', 'query_sequence': [('ready.logging', 1), ('formerr.forward.test', 1), ('servfail.forward.test', 1), ('numeric.forward.test', 1)],
                 'query_upstream': True, 'query_required_messages': ['reply error is FORMERR', 'reply error is SERVFAIL', 'reply error is 10'],
                 'options': ['log-queries']})
    rows.append({'id': 'query-extreme-name-bytes', 'scope': 'query-extreme', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries=proto'], 'query_probes': True,
                 'query_mode': 'proto', 'query_sequence': [('ready.logging', 1)], 'query_extreme_probe': True,
                 'query_required_messages': ['query[A] <name unprintable> from 127.0.0.1'], 'options': ['log-queries']})
    rows.append({'id': 'query-extreme-counted-TXT', 'scope': 'query-extreme', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries=proto', '--server=127.0.0.2#15957', '--cache-rr=TXT'],
                 'query_probes': True, 'query_mode': 'proto',
                 'query_sequence': [('ready.logging', 1), ('max-txt.forward.test', 16), ('max-txt.forward.test', 16)],
                 'query_upstream': True, 'query_required_messages': ['reply max-txt.forward.test is ' + 'X' * 255,
                    'cached max-txt.forward.test is ' + 'X' * 255, 'reply max-txt.forward.test is Leading'], 'options': ['log-queries']})
    for kind in ['coalesce', 'clientretry', 'fastretry']:
        rows.append({'id': 'query-transaction-' + kind, 'scope': 'query-transactions', 'kind': 'run',
                     'argv': ['--log-facility=-', '--log-queries=proto', '--server=127.0.0.2#15957',
                              *(['--fast-dns-retry=50,1000'] if kind == 'fastretry' else [])],
                     'query_probes': True, 'query_mode': 'proto', 'query_sequence': [('ready.logging', 1)],
                     'query_upstream': True, 'query_transaction_probe': kind, 'options': ['log-queries']})
    rows.append({'id': 'query-dhcp-origin', 'scope': 'query-dhcp', 'kind': 'run',
                 'argv': ['--log-facility=-', '--log-queries', '--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m',
                          '--dhcp-host=02:00:00:00:00:aa,127.0.0.10,m5-client', '--dhcp-host=02:00:00:00:00:bb,ignore',
                          '--dhcp-authoritative', '--dhcp-leasefile=/m2/logging/leases', '--dhcp-broadcast', '--no-ping'],
                 'dhcp_probes': True, 'quiet_dhcp': False, 'detail_dhcp': False, 'dhcp_query_origin': True,
                 'options': ['log-queries']})
    for label, quiet, detail in [('ordinary', False, False), ('quiet', True, False),
                                  ('detail', False, True), ('quiet-detail', True, True)]:
        rows.append({'id': 'dhcp-packets-' + label, 'scope': 'dhcp-packets', 'kind': 'run',
                     'argv': ['--log-facility=-', '--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m',
                              '--dhcp-host=02:00:00:00:00:aa,127.0.0.10,m5-client',
                              '--dhcp-host=02:00:00:00:00:bb,ignore', '--dhcp-authoritative',
                              '--dhcp-leasefile=/m2/logging/leases', '--dhcp-broadcast', '--no-ping',
                              *(['--quiet-dhcp'] if quiet else []), *(['--log-dhcp'] if detail else [])],
                     'dhcp_probes': True, 'quiet_dhcp': quiet, 'detail_dhcp': detail,
                     'options': ['log-dhcp', 'quiet-dhcp']})
    delay_quiet = copy.deepcopy(next(row for row in rows if row['id'] == 'dhcp-packets-quiet-detail'))
    delay_quiet['id'] = 'dhcp-packets-quiet-detail-delay'
    delay_quiet['scope'] = 'dhcp-quiet-delay'
    delay_quiet['argv'].append('--dhcp-reply-delay=0')
    delay_quiet['quiet_delay_probe'] = True
    rows.append(delay_quiet)
    rows.extend([
        {'id': 'daemon-default-stderr', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=-'], 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-default-syslog', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': [], 'receiver': 'dgram', 'facility': 24, 'daemonized': True,
         'pidfile': '/m2/logging/daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=./relative.log'], 'file': '/relative.log', 'daemonized': True,
         'pidfile': './daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'foreground-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': ['-k'],
         'argv': ['--log-facility=./relative.log'], 'file': '/relative.log',
         'pidfile': './daemon.pid', 'options': ['no-daemon', 'log-facility']},
        {'id': 'debug-relative-paths', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=./relative.log'], 'file': '/m2/logging/relative.log',
         'pidfile': './daemon.pid', 'sentinel_pid': True, 'options': ['no-daemon', 'log-facility']},
        {'id': 'debug-foreground-precedence', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d', '-k'],
         'argv': ['--log-facility=./relative.log'], 'file': '/m2/logging/relative.log',
         'pidfile': './daemon.pid', 'sentinel_pid': True, 'options': ['no-daemon']},
        {'id': 'debug-keeps-configured-nobody-identity', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d'],
         'user': 'nobody', 'argv': ['--log-facility=-'], 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon']},
        {'id': 'foreground-drops-nobody-identity', 'scope': 'daemon', 'kind': 'run', 'mode': ['-k'],
         'user': 'nobody', 'expected_uid': 65534, 'argv': ['--log-facility=-'],
         'pidfile': '/m2/logging/daemon.pid', 'options': ['no-daemon']},
        {'id': 'nonroot-pid-open-failure-ignored', 'scope': 'daemon', 'kind': 'run', 'mode': ['-k'],
         'launcher_uid': 65534, 'expected_uid': 65534, 'ignore_pid_failure': True,
         'argv': ['--log-facility=-'], 'pidfile': '/m2/logging/missing/daemon.pid',
         'options': ['no-daemon']},
        {'id': 'pid-symlink-target-preserved', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'daemonized': True, 'pid_symlink': True, 'argv': ['--log-facility=-'],
         'pidfile': '/m2/logging/daemon.pid', 'options': ['no-daemon']},
        {'id': 'debug-sigint-pid', 'scope': 'daemon', 'kind': 'run', 'mode': ['-d'],
         'argv': ['--log-facility=-'], 'pidfile': './daemon.pid', 'sentinel_pid': True,
         'signal': 'int', 'exit': 5, 'expect_ready': True, 'options': ['no-daemon']},
        {'id': 'daemon-log-open-failure', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': [], 'config': 'log-facility=/m2/logging/missing/daemon.log\n',
         'exit': 3, 'receiver': 'dgram', 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-log-failure-parent-facility', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=local3'], 'config': 'log-facility=/m2/logging/missing/daemon.log\n',
         'exit': 3, 'receiver': 'dgram', 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
         'options': ['no-daemon', 'log-facility']},
        {'id': 'daemon-pid-open-failure', 'scope': 'daemon', 'kind': 'run', 'mode': [],
         'argv': ['--log-facility=-'], 'exit': 3, 'receiver': 'dgram', 'daemonized': True,
         'pidfile': '/m2/logging/missing/daemon.pid', 'options': ['no-daemon']},
    ])
    for mode, label in [([], 'default'), (['-k'], 'foreground'), (['-d'], 'debug')]:
        for service in ['tftp', 'dhcp']:
            extra = ['--enable-tftp', '--tftp-root=/m2/logging'] if service == 'tftp' else [
                '--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', '--no-ping',
                '--dhcp-broadcast', '--dhcp-leasefile=/m2/logging/leases']
            rows.append({'id': 'helper-startup-' + service + '-' + label, 'scope': 'daemon', 'kind': 'run',
                         'mode': mode, 'daemonized': not mode, 'pidfile': '/m2/logging/daemon.pid',
                         'helper_script': True, 'helper_fds': True,
                         'expected_helper_uid': 65534 if service == 'dhcp' and label != 'debug' else 0,
                         'argv': ['--log-facility=-', '--dhcp-script=/m2/logging/script',
                                  '--dhcp-scriptuser=nobody', *extra], 'options': ['no-daemon']})
        rows.append({'id': 'log-path-opaque-failure-' + label, 'scope': 'daemon', 'kind': 'run',
                     'mode': mode, 'daemonized': not mode, 'exit': 3,
                     'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram', 'argv': [],
                     'config_bytes': b'log-facility=/m2/logging/missing-\xff/daemon.log\n'.hex(),
                     'options': ['log-facility', 'no-daemon']})
        for identity in ['user', 'group']:
            rows.append({'id': 'startup-unknown-' + identity + '-' + label, 'scope': 'daemon',
                         'kind': 'run', 'mode': mode, 'daemonized': not mode, 'exit': 1,
                         'pidfile': '/m2/logging/daemon.pid', identity: 'm5-unknown-identity',
                         'argv': ['--log-facility=-'], 'options': ['no-daemon']})
        rows.append({'id': 'startup-tftp-root-missing-' + label, 'scope': 'daemon',
                     'kind': 'run', 'mode': mode, 'daemonized': not mode, 'exit': 3,
                     'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram',
                     'argv': ['--log-facility=-', '--enable-tftp', '--tftp-root=/m2/logging/missing'],
                     'options': ['no-daemon', 'log-facility']})
        rows.append({'id': 'tftp-scriptuser-unknown-' + label, 'scope': 'scriptuser-boundary',
                     'kind': 'run', 'mode': mode, 'daemonized': not mode,
                     'pidfile': '/m2/logging/daemon.pid', 'helper_script': True,
                     'argv': ['--log-facility=-', '--enable-tftp', '--tftp-root=/m2/logging',
                              '--dhcp-script=/m2/logging/script', '--dhcp-scriptuser=m5-missing-script-user'],
                     'options': ['no-daemon', 'dhcp-scriptuser']})
    for name, extra, helper_uid in [
        ('tftp-nobody', ['--enable-tftp', '--tftp-root=/m2/logging'], 0),
        ('no-service', [], None),
        ('dhcp-nobody', ['--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', '--no-ping',
                         '--dhcp-broadcast', '--dhcp-leasefile=/m2/logging/leases'], 65534),
    ]:
        rows.append({'id': 'scriptuser-' + name, 'scope': 'scriptuser-boundary', 'kind': 'run',
                     'mode': ['-k'], 'pidfile': '/m2/logging/daemon.pid', 'helper_script': True,
                     'expected_helper_uid': helper_uid,
                     'argv': ['--log-facility=-', '--dhcp-script=/m2/logging/script',
                              '--dhcp-scriptuser=nobody', *extra], 'options': ['dhcp-scriptuser']})
    for name, number, error in [('fork-one', 220, errno.EAGAIN), ('fork-two', 220, errno.EAGAIN), ('error-pipe', 59, errno.EMFILE),
                                ('error-pipe-flags', 25, errno.EIO),
                                ('pid-write', 64, errno.EIO), ('pid-close', 57, errno.EIO),
                                ('log-chown', 55, errno.EPERM), ('pid-chown', 55, errno.EPERM),
                                ('pid-short-write', 64, 0), ('log-space', 64, errno.ENOSPC),
                                ('log-interrupt', 64, errno.EINTR)]:
        failed = name not in ['log-chown', 'pid-chown', 'pid-short-write', 'log-space', 'log-interrupt']
        rows.append({'id': 'startup-fault-' + name, 'scope': 'startup-fault', 'kind': 'run',
                     'mode': [] if name in ['fork-one', 'fork-two', 'error-pipe', 'error-pipe-flags'] else ['-k'],
                     'daemonized': name in ['fork-one', 'fork-two', 'error-pipe', 'error-pipe-flags'], 'fault': name,
                     'fault_number': number, 'fault_errno': error,
                     'exit': (5 if name in ['fork-one', 'fork-two', 'error-pipe', 'error-pipe-flags'] else 3) if failed else 0,
                     'pidfile': '/m2/logging/daemon.pid',
                     'user': 'nobody' if name in ['log-chown', 'pid-chown'] else 'root',
                     'file': '/m2/logging/daemon.log' if name.startswith('log-') else None,
                     'argv': ['--log-facility=/m2/logging/daemon.log'] if name.startswith('log-') else ['--log-facility=-'],
                     'receiver': 'dgram', 'options': ['no-daemon', 'log-facility']})
    opaque_log = b'/m2/logging/daemon-\xff.log'
    rows.append({'id': 'file-owner-warning-opaque-path', 'scope': 'startup-fault', 'kind': 'run',
                 'mode': ['-k'], 'daemonized': False, 'fault': 'log-chown', 'fault_number': 55,
                 'fault_errno': errno.EPERM, 'pidfile': '/m2/logging/daemon.pid', 'user': 'nobody',
                 'file': os.fsdecode(opaque_log), 'argv': [], 'receiver': 'dgram',
                 'config_bytes': (b'log-facility=' + opaque_log + b'\n').hex(),
                 'options': ['log-facility']})
    for name, number in [('setgroups', 159), ('setgid', 144), ('setuid', 146), ('capset', 91), ('keepcaps', 167)]:
        rows.append({'id': 'credential-fault-' + name, 'scope': 'credential-fault', 'kind': 'run',
                     'mode': ['-k'], 'fault': name, 'fault_number': number, 'fault_errno': errno.EPERM,
                     'exit': 5, 'pidfile': '/m2/logging/daemon.pid', 'user': 'nobody',
                     'receiver': 'dgram', 'argv': [], 'options': ['no-daemon']})
    rows.append({'id': 'helper-credential-fault-foreground', 'scope': 'startup-fault', 'kind': 'run',
                 'mode': ['-k'], 'fault': 'helper-setuid', 'fault_number': 146, 'fault_errno': errno.EPERM,
                 'fault_follow_child': True, 'exit': 5, 'pidfile': '/m2/logging/daemon.pid',
                 'helper_script': True, 'receiver': 'dgram',
                 'argv': ['--log-facility=-', '--dhcp-script=/m2/logging/script', '--dhcp-scriptuser=nobody',
                          '--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', '--no-ping',
                          '--dhcp-broadcast', '--dhcp-leasefile=/m2/logging/leases'],
                 'options': ['no-daemon']})
    rows.append({'id': 'helper-credential-fault-default', 'scope': 'startup-fault', 'kind': 'run',
                 'mode': [], 'daemonized': True, 'fault': 'helper-setuid', 'fault_number': 146,
                 'fault_errno': errno.EPERM, 'fault_follow_child': True, 'fault_follow_depth': 3,
                 'exit': 5, 'pidfile': '/m2/logging/daemon.pid', 'helper_script': True, 'receiver': 'dgram',
                 'argv': ['--log-facility=-', '--dhcp-script=/m2/logging/script', '--dhcp-scriptuser=nobody',
                          '--dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,10m', '--no-ping',
                          '--dhcp-broadcast', '--dhcp-leasefile=/m2/logging/leases'], 'options': ['no-daemon']})
    rows.append({'id': 'startup-error-frame-interrupt', 'scope': 'startup-fault', 'kind': 'run',
                 'mode': [], 'daemonized': True, 'fault': 'error-frame-interrupt', 'fault_number': 66,
                 'fault_errno': errno.EINTR, 'fault_follow_child': True, 'fault_follow_depth': 2,
                 'exit': 3, 'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram',
                 'argv': ['--log-facility=/m2/logging/missing/daemon.log'], 'options': ['no-daemon']})
    rows.append({'id': 'pid-chown-capability-missing', 'scope': 'ownership-warning', 'kind': 'run',
                 'mode': ['-k'], 'pidfile': '/m2/logging/daemon.pid', 'user': 'nobody',
                 'drop_chown': True, 'receiver': 'dgram', 'argv': [], 'options': ['no-daemon']})
    for name, number, error, target in [
        ('syslog-socket', 198, errno.EMFILE, 'socket-open'),
        ('stderr-dup', 23, errno.EMFILE, 'stderr-dup'),
        *[('syslog-' + label, 64, error, 'socket-write') for label, error in [
            ('interrupt', errno.EINTR), ('again', errno.EAGAIN), ('buffers', errno.ENOBUFS),
            ('not-connected', errno.ENOTCONN), ('refused', errno.ECONNREFUSED),
            ('destination', errno.EDESTADDRREQ), ('reset', errno.ECONNRESET), ('pipe', errno.EPIPE),
            ('fatal', errno.EIO)]],
        *[('connect-' + label, 203, error, 'socket-connect') for label, error in [
            ('missing', errno.ENOENT), ('already', errno.EALREADY), ('refused', errno.ECONNREFUSED),
            ('connected', errno.EISCONN), ('interrupt', errno.EINTR), ('again', errno.EAGAIN)]],
    ]:
        rows.append({'id': 'sink-fault-' + name, 'scope': 'sink-fault', 'kind': 'run',
                     'mode': ['-k'], 'fault': name, 'fault_number': number, 'fault_errno': error,
                     'fault_target': target, 'exit': 3 if target in ['socket-open', 'stderr-dup'] else 0,
                     'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram',
                     'argv': ['--log-facility=-'] if target == 'stderr-dup' else [],
                     'options': ['log-facility']})
    for index, value in enumerate([None, '', '0', '1', '5', '100', '101', '2147483648',
                                   '4294967295', '4294967296', '4294967301', '9' * 80]):
        argument = '--log-async' + ('' if value is None else '=' + value)
        integer = 5 if value is None else int(value or '0') & 0xffffffff
        integer = integer if integer < 0x80000000 else integer - 0x100000000
        limit = min(integer, 100)
        rows.append({'id': f'async-value-{index:02d}', 'scope': 'async', 'kind': 'run',
                     'argv': [argument], 'receiver': 'dgram', 'facility': 24,
                     'allow_no_syslog': limit < 0, 'async_notice': limit,
                     'options': ['log-async']})
    for destination, extra in [('stderr', {'argv': ['--log-facility=-']}),
                                ('file', {'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log'})]:
        rows.append({'id': 'async-overridden-' + destination, 'scope': 'async', 'kind': 'run',
                     **extra, 'argv': [*extra['argv'], '--log-async=7'], 'async_notice': 0,
                     'options': ['log-async', 'log-facility']})
    for index, value in enumerate(['-1', '+1', '1x', ' 1']):
        rows.append({'id': f'async-invalid-{index:02d}', 'scope': 'async', 'kind': 'test',
                     'exit': 1, 'argv': ['--log-async=' + value], 'options': ['log-async', 'test']})
    rows.append({'id': 'async-origin-precedence', 'scope': 'async', 'kind': 'run',
                 'config': 'log-async=3\n', 'argv': ['--log-async=7'], 'receiver': 'dgram',
                 'facility': 24, 'async_notice': 3, 'options': ['log-async']})
    rows.append({'id': 'async-repeat-cli', 'scope': 'async', 'kind': 'test', 'exit': 1,
                 'argv': ['--log-async=3', '--log-async=7'], 'options': ['log-async', 'test']})
    rows.extend([
        {'id': 'async-repeat-file', 'scope': 'async', 'kind': 'test', 'exit': 1,
         'argv': [], 'config': 'log-async=3\nlog-async=7\n', 'options': ['log-async', 'test']},
        {'id': 'async-invalid-file', 'scope': 'async', 'kind': 'test', 'exit': 1,
         'argv': [], 'config': 'log-async=-1\n', 'options': ['log-async', 'test']},
    ])
    rows.append({'id': 'async-overflow-startup', 'scope': 'async-overflow', 'kind': 'run',
                 'pause_receiver': True, 'receiver': 'dgram', 'facility': 24,
                 'argv': ['--log-async=2', '--dhcp-leasefile=/m2/logging/leases', '--no-ping',
                          '--dhcp-broadcast', *[f'--dhcp-range=127.0.{index}.10,127.0.{index}.20,255.0.0.0,10m'
                                              for index in range(20)]],
                 'options': ['log-async', 'log-facility']})
    rows.append({'id': 'async-stream-short-write', 'scope': 'async-transport', 'kind': 'run',
                 'mode': ['-k'], 'receiver': 'stream', 'fault': 'syslog-short-write', 'fault_target': 'stream-write',
                 'fault_number': 64, 'fault_errno': 0, 'pidfile': '/m2/logging/daemon.pid',
                 'argv': ['--log-async=5'], 'options': ['log-async', 'log-facility']})
    rows.append({'id': 'async-real-reconnect-two-cycles', 'scope': 'async-recovery', 'kind': 'run',
                 'receiver': 'dgram', 'late_receiver': True, 'argv': ['--log-async=2'],
                 'options': ['log-async', 'log-facility']})
    rows.append({'id': 'async-tcp-inherited-queue', 'scope': 'async-tcp-queue', 'kind': 'run',
                 'receiver': 'dgram', 'late_receiver': True, 'queued_tcp': True,
                 'argv': ['--log-async=2', '--log-debug', '--server=127.0.0.2#15955'],
                 'options': ['log-async', 'log-facility']})
    for enabled in [False, True]:
        for family, server in [('v4', '127.0.0.2'), ('v6', '::1')]:
            rows.append({'id': 'debug-tcp-' + family + ('-enabled' if enabled else '-disabled'),
                         'scope': 'debug', 'kind': 'run', 'debug_probes': 'tcp', 'debug_enabled': enabled,
                         'debug_server': server, 'argv': ['--log-facility=-', '--server=' + server + '#15955',
                                                        *(['--log-debug'] if enabled else [])],
                         'options': ['log-debug']})
        for kind in ['interface', 'explicit']:
            rows.append({'id': 'debug-dynamic-' + kind + ('-enabled' if enabled else '-disabled'),
                         'scope': 'debug', 'kind': 'run', 'debug_probes': kind, 'debug_enabled': enabled,
                         'base_skip': ['--bind-interfaces'],
                         'argv': ['--log-facility=-', '--bind-dynamic',
                                  *(['--interface=m5log'] if kind == 'interface' else ['--listen-address=192.0.2.101']),
                                  *(['--log-debug'] if enabled else [])], 'options': ['log-debug']})
    server = '--server=192.0.2.53#15555'
    for name, argv, files, skip, actions in [
        ('resolv-inline', [server, '--resolv-file=/m2/logging/resolv'], {'resolv': 'nameserver 192.0.2.54\n'}, True, []),
        ('resolv-empty', [server, '--resolv-file=/m2/logging/resolv'], {'resolv': ''}, True, []),
        ('resolv-missing', [server, '--resolv-file=/m2/logging/resolv'], {}, True, []),
        ('server-good', [server, '--servers-file=/m2/logging/servers'], {'servers': 'server=192.0.2.55#15556\n'}, False, []),
        ('server-empty', [server, '--servers-file=/m2/logging/servers'], {'servers': ''}, False, []),
        ('server-missing', [server, '--servers-file=/m2/logging/servers'], {}, False, []),
        ('no-poll-both', [server, '--no-poll', '--resolv-file=/m2/logging/resolv', '--servers-file=/m2/logging/servers'],
         {'resolv': 'nameserver 192.0.2.54\n', 'servers': 'server=192.0.2.55#15556\n'}, True, []),
        ('no-poll-missing', [server, '--no-poll', '--resolv-file=/m2/logging/resolv'], {}, True, []),
        ('resolv-server-missing', [server, '--resolv-file=/m2/logging/resolv', '--servers-file=/m2/logging/servers'],
         {'resolv': 'nameserver 192.0.2.54\n'}, True, []),
        ('server-replace', [server, '--servers-file=/m2/logging/servers'], {'servers': 'server=192.0.2.55#15556\n'}, False,
         [('servers', 'server=192.0.2.56#15557\n', 'hup'), ('servers', '', 'hup')]),
        ('resolv-replace', [server, '--resolv-file=/m2/logging/resolv'], {'resolv': 'nameserver 192.0.2.54\n'}, True,
         [('resolv', 'nameserver 192.0.2.56\n', 'close')]),
        ('no-poll-replace', [server, '--no-poll', '--resolv-file=/m2/logging/resolv', '--servers-file=/m2/logging/servers'],
         {'resolv': 'nameserver 192.0.2.54\n', 'servers': 'server=192.0.2.55#15556\n'}, True,
         [('resolv', 'nameserver 192.0.2.56\n', 'hup')]),
    ]:
        rows.append({'id': 'server-logs-' + name, 'scope': 'server-logs', 'kind': 'run',
                     'argv': ['--log-facility=-', *argv], 'setup_files': files, 'file_actions': actions,
                     'base_skip': ['--no-resolv'] if skip else [], 'options': ['log-facility', 'no-daemon']})
    rows.append({'id': 'server-logs-upstream-limit', 'scope': 'server-logs', 'kind': 'run',
                 'argv': ['--log-facility=-', *[f'--server=192.0.2.{index}#15555' for index in range(1, 36)]],
                 'options': ['log-facility', 'no-daemon']})
    rows.append({'id': 'server-logs-local-limit', 'scope': 'server-logs', 'kind': 'run',
                 'argv': ['--log-facility=-', *[f'--server=/local{index}.logging/' for index in range(10)],
                          '--server=/standard.logging/#', '--server=/domain.logging/192.0.2.53#15555',
                          '--server=//192.0.2.54#15556'], 'options': ['log-facility', 'no-daemon']})
    for quiet in [False, True]:
        for variant in ['requests', 'port-exhausted', 'timeout']:
            rows.append({'id': 'tftp-logs-' + variant + ('-quiet' if quiet else '-ordinary'),
                         'scope': 'tftp-logs', 'kind': 'run', 'tftp_probes': variant,
                         'quiet': quiet, 'argv': ['--log-facility=-', '--enable-tftp',
                            '--tftp-root=/m2/logging',
                            *(['--quiet-tftp'] if quiet else []),
                            *(['--tftp-port-range=35000,35000'] if variant == 'port-exhausted' else [])],
                         'options': ['quiet-tftp', 'log-facility']})
    for destination, extra in [('stderr', {'argv': ['--log-facility=-']}),
                                ('file', {'argv': ['--log-facility=/m2/logging/daemon.log'], 'file': 'daemon.log'}),
                                ('syslog', {'argv': [], 'receiver': 'dgram', 'facility': 24}),
                                ('stream', {'argv': [], 'receiver': 'stream', 'facility': 24})]:
        for enabled in [False, True]:
            rows.append({'id': 'script-logs-' + destination + ('-debug-enabled' if enabled else '-debug-disabled'),
                         'scope': 'script-logs', 'kind': 'run', **extra,
                         'tftp_probes': 'script', 'script_probes': 'output',
                         'argv': [*extra['argv'], '--enable-tftp', '--tftp-root=/m2/logging',
                                  '--dhcp-script=/m2/logging/script', *(['--log-debug'] if enabled else [])],
                         'options': ['log-facility', 'log-debug']})
    for outcome in ['signal', 'exec']:
        rows.append({'id': 'script-logs-' + outcome, 'scope': 'script-logs', 'kind': 'run',
                     'tftp_probes': 'script', 'script_probes': outcome,
                     'argv': ['--log-facility=-', '--enable-tftp', '--tftp-root=/m2/logging',
                              '--dhcp-script=/m2/logging/script'], 'options': ['log-facility', 'log-debug']})
    for mode, label in [(['-k'], 'foreground'), (['-d'], 'debug')]:
        rows.append({'id': 'helper-exec-inheritance-' + label, 'scope': 'helper-inheritance', 'kind': 'run',
                     'mode': mode, 'inherited_umask': 0o077, 'tftp_probes': 'script',
                     'script_probes': 'inheritance', 'argv': ['--log-facility=-', '--enable-tftp',
                         '--tftp-root=/m2/logging', '--dhcp-script=/m2/logging/script'],
                     'options': ['no-daemon']})
    dhcp_base = ['--log-facility=-', '--dhcp-leasefile=/m2/logging/leases', '--no-ping', '--dhcp-broadcast']
    for name, arguments, extra in [
        ('cache-disabled', ['--cache-size=0'], {}),
        ('cache-large', ['--cache-size=10001'], {}),
        ('dns-disabled', ['--port=0', '--enable-tftp', '--tftp-root=/m2/logging'], {'no_dns': True, 'base_skip': ['--port=15353']}),
        ('ignored-resolv', ['--resolv-file=/m2/logging/resolv'], {}),
        ('ubus-pending', ['--enable-ubus=logging'], {}),
        ('interface-warning', ['--interface=m5-missing-iface'], {'base_skip': ['--bind-interfaces']}),
        ('local-service-net', ['--local-service=net'], {'base_skip': ['--listen-address=127.0.0.1']}),
        ('local-service-host', ['--local-service=host'], {'base_skip': ['--listen-address=127.0.0.1']}),
        ('nameserver', ['--server=192.0.2.53#15555'], {}),
        ('local-domain', ['--server=/only.logging/'], {}),
    ]:
        rows.append({'id': 'startup-output-' + name, 'scope': 'startup-output', 'kind': 'run',
                     'argv': ['--log-facility=-', *arguments], **extra,
                     'options': ['log-facility', 'no-daemon']})
    for mode, label in [([], 'default'), (['-k'], 'foreground'), (['-d'], 'debug')]:
        path = b'/m2/logging/missing-\xff/daemon.pid'
        rows.append({'id': 'pid-path-opaque-failure-' + label, 'scope': 'error-frame', 'kind': 'run',
                     'mode': mode, 'daemonized': not mode, 'exit': 0 if label == 'debug' else 3,
                     'pidfile': os.fsdecode(path), 'receiver': 'dgram', 'argv': [],
                     'config_bytes': (b'pid-file=' + path + b'\n').hex(), 'options': ['no-daemon']})
    rows.append({'id': 'daemon-runtime-servers-file-failure', 'scope': 'daemon', 'kind': 'run',
                 'mode': [], 'daemonized': True, 'pidfile': '/m2/logging/daemon.pid',
                 'argv': ['--log-facility=-', '--servers-file=/m2/logging/missing-servers'],
                 'options': ['no-daemon']})
    for target in ['pid', 'log']:
        path = '/m2/logging/' + 'x' * 65536
        rows.append({'id': 'daemon-overlong-' + target + '-error-frame', 'scope': 'error-frame',
                     'kind': 'run', 'mode': [], 'daemonized': True, 'exit': 3,
                     'pidfile': path if target == 'pid' else '/m2/logging/daemon.pid',
                     'overlong_pid': target == 'pid', 'receiver': 'dgram',
                     'argv': ['--log-facility=' + (path if target == 'log' else '-')],
                     'options': ['no-daemon', 'log-facility']})
    prefix = b'/m2/logging/' + b'x' * 5000
    rows.append({'id': 'debug-echo-overlong-tftp-root', 'scope': 'root-access', 'kind': 'run',
                 'mode': ['-d'], 'daemonized': False, 'pidfile': '/m2/logging/daemon.pid',
                 'file': '/m2/logging/daemon.log', 'argv': ['--log-facility=/m2/logging/daemon.log'],
                 'config_bytes': (b'enable-tftp\ntftp-no-fail\ntftp-root=' + prefix + b'\n').hex(),
                 'root_prefix': prefix.hex(), 'root_variant': 'global-no-fail', 'root_no_fail': True,
                 'options': ['no-daemon', 'log-facility', 'tftp-root', 'tftp-no-fail']})
    for mode, label in [([], 'default'), (['-k'], 'foreground'), (['-d'], 'debug')]:
        for variant, prefix, no_fail, enabled in [
            ('global-fatal', b'/m2/logging/missing-global', False, True),
            ('interface-fatal', b'/m2/logging/missing-interface', False, True),
            ('both-fatal', b'/m2/logging/missing-global', False, True),
            ('global-no-fail', b'/m2/logging/missing-global', True, True),
            ('interface-no-fail', b'/m2/logging/missing-interface', True, True),
            ('both-no-fail', b'/m2/logging/missing-global', True, True),
            ('unused-root', b'/m2/logging/missing-unused', False, False),
            ('utf8-fatal', '/m2/logging/missing-ä'.encode(), False, True),
            ('opaque-fatal', b'/m2/logging/missing-\xff', False, True),
            ('utf8-no-fail', '/m2/logging/missing-ä'.encode(), True, True),
            ('opaque-no-fail', b'/m2/logging/missing-\xff', True, True),
            ('empty-interface-fatal', b'', False, True),
            ('empty-interface-no-fail', b'', True, True),
            ('empty-global', b'', False, True),
        ]:
            config = b'enable-tftp\n' if enabled else b''
            interface = variant.startswith('interface-') or variant.startswith('empty-interface-')
            config += b'tftp-root=' + prefix + (b',lo' if interface else b'') + b'\n'
            if variant.startswith('both-'):
                config += b'tftp-root=/m2/logging/missing-interface,lo\n'
            if no_fail:
                config += b'tftp-no-fail\n'
            rows.append({'id': 'tftp-root-' + variant + '-' + label, 'scope': 'root-access',
                         'kind': 'run', 'mode': mode, 'daemonized': not mode,
                         'exit': 0 if no_fail or not enabled or variant == 'empty-global' else 3,
                         'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram', 'argv': ['--log-facility=-'],
                         'config_bytes': config.hex(), 'root_prefix': prefix.hex(),
                         'root_variant': variant, 'root_no_fail': no_fail,
                         'options': ['tftp-root', 'tftp-no-fail'] if no_fail else ['tftp-root']})
        for no_fail in [False, True] if label != 'debug' else [False]:
                rows.append({'id': 'tftp-root-permission-' + ('no-fail-' if no_fail else 'fatal-') + label,
                             'scope': 'root-access', 'kind': 'run', 'mode': mode, 'daemonized': not mode,
                             'exit': 0 if no_fail or label == 'debug' else 3, 'user': 'nobody', 'root_permissions': True,
                             'pidfile': '/m2/logging/daemon.pid', 'receiver': 'dgram', 'argv': ['--log-facility=-'],
                             'config_bytes': (b'enable-tftp\ntftp-root=/m2/logging/private-root\n' +
                                              (b'tftp-no-fail\n' if no_fail else b'')).hex(),
                             'root_prefix': b'/m2/logging/private-root'.hex(), 'root_variant': 'permission-debug' if label == 'debug' else 'permission',
                             'root_no_fail': no_fail, 'options': ['tftp-root', 'tftp-no-fail']})
    for name, ranges in [
        ('dynamic', ['127.0.0.10,127.0.0.20,255.0.0.0,10m']),
        ('static', ['127.0.0.0,static,255.0.0.0,3723']),
        ('proxy', ['127.0.0.0,proxy']),
        ('infinite', ['127.0.0.10,127.0.0.20,255.0.0.0,infinite']),
        ('multi', ['127.0.0.10,127.0.0.20,255.0.0.0,93784',
                   '127.0.0.0,static,255.0.0.0,2m', '127.0.0.0,proxy']),
    ]:
        rows.append({'id': 'startup-dhcp-' + name, 'scope': 'startup-output', 'kind': 'run',
                     'argv': [*dhcp_base, *['--dhcp-range=' + value for value in ranges]],
                     'options': ['log-facility', 'log-dhcp']})
    for name, flags in [('plain', []), ('secure', ['--tftp-secure']),
                         ('single', ['--tftp-single-port']),
                         ('both', ['--tftp-secure', '--tftp-single-port']),
                         ('no-global-root', ['--tftp-root=/m2/logging,lo'])]:
        rows.append({'id': 'startup-tftp-' + name, 'scope': 'startup-output', 'kind': 'run',
                     'argv': ['--log-facility=-', '--enable-tftp',
                              *([] if name == 'no-global-root' else ['--tftp-root=/m2/logging']), *flags],
                     'options': ['log-facility']})
    for enabled in [False, True]:
        rows.append({'id': 'no-ident-full-' + ('enabled' if enabled else 'default'),
                     'scope': 'identity-full', 'kind': 'run', 'identity_matrix': True,
                     'reference_defect': 'C TCP have_pseudoheader persists across local/no-server queries',
                     'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user',
                              '--txt-record=version.bind,explicit-user',
                              '--txt-record=explicit.server,server-user'] + (['--no-ident'] if enabled else []),
                     'options': ['no-ident']})
    for name, cls in [('local', 1), ('refused', 255)]:
        rows.append({'id': 'tcp-edns-sticky-' + name, 'scope': 'identity-full', 'kind': 'run',
                     'identity_matrix': True, 'identity_sticky_probe': cls,
                     'reference_defect': 'C TCP have_pseudoheader persists across local/no-server queries',
                     'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user'],
                     'options': ['no-ident']})
        rows.append({'id': 'tcp-edns-fresh-' + name, 'scope': 'identity-full', 'kind': 'run',
                     'identity_matrix': True, 'identity_sticky_probe': cls, 'identity_fresh': True,
                     'argv': ['--log-facility=-', '--txt-record=kept.logging,explicit-user'],
                     'options': ['no-ident']})
    return rows


def normalized(value):
    value = value.replace('dnsmasq-rs:', 'dnsmasq:')
    value = re.sub(r'(?m)^(<\d+>)?[A-Z][a-z]{2} [ 0-9][0-9] \d\d:\d\d:\d\d ',
                   lambda match: (match[1] or '') + '<TIME> ', value)
    return re.sub(r'(dnsmasq(?:-(?:dhcp|tftp|script|debug))?)\[\d+\]:', r'\1[<PID>]:', value)


class Receiver:
    def __init__(self, root, kind):
        self.listener = self.client = None
        self.raw, self.pending = [], b''
        self.kind = kind
        if kind:
            path = image_path(root, '/dev/log', follow_leaf=False)
            path.unlink(missing_ok=True)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM if kind == 'stream' else socket.SOCK_DGRAM)
            bind_unix_socket(self.listener, path)
            path.chmod(0o777)
            if kind == 'stream':
                self.listener.listen(1)
            self.listener.setblocking(False)

    def drain(self):
        if not self.listener:
            return
        if self.kind == 'stream' and not self.client:
            try:
                self.client, _ = self.listener.accept()
                self.client.setblocking(False)
            except BlockingIOError:
                return
        endpoint = self.client or self.listener
        while True:
            try:
                data = endpoint.recv(65535)
            except BlockingIOError:
                break
            if not data:
                break
            if self.kind == 'stream':
                self.pending += data
                while b'\0' in self.pending:
                    row, self.pending = self.pending.split(b'\0', 1)
                    self.raw.append(row)
            else:
                if b'\0' in data:
                    raise AssertionError('NUL inside syslog datagram')
                self.raw.append(data)

    def close(self):
        if self.client:
            self.client.close()
        if self.listener:
            self.listener.close()


def query_packet(name, kind=1, ident=0x7100):
    if not name:
        return struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + b'\0' + struct.pack('!HH', kind, 1)
    return query(name, kind, ident)


def exchange(name, kind=1, chaos=False, port=None, timeout=.03):
    wire = query_packet(name, kind, 0x7100)
    if chaos:
        wire = wire[:-2] + b'\0\3'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        if port is not None:
            client.bind(('127.0.0.1', port))
        client.settimeout(timeout)
        client.sendto(wire, ('127.0.0.1', 15353))
        reply = client.recv(65535)
    if reply[:2] != wire[:2]:
        raise AssertionError('wrong client DNS transaction')
    return semantics(reply), {'request': wire.hex(), 'reply': reply.hex()}


def query_sequence(case=None):
    if case and "query_sequence" in case:
        return case["query_sequence"]
    return [('ready.logging', 1), ('ready.logging', 28), ('v6.logging', 28),
            ('alias.logging', 1), ('1.2.0.192.in-addr.arpa', 12),
            ('kept.logging', 16), ('nxdomain.logging', 1), ('ready.logging', 65400)]


def query_clock():
    return {'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns()}


def align_query_phase():
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        clock = query_clock()
        fraction = clock['wall_ns'] % 1_000_000_000
        if 190_000_000 <= fraction <= 210_000_000:
            return {'epoch': clock['wall_ns'] // 1_000_000_000, 'aligned_at': clock, 'intervals': []}
        time.sleep(.001)
    raise AssertionError('real wall-clock query phase alignment timed out')


def tcp_sequence(probes, intervals=None):
    rows, raw = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.settimeout(.5)
        client.bind(('127.0.0.1', 16502))
        client.connect(('127.0.0.1', 15353))
        for name, kind in probes:
            wire = query_packet(name, kind, 0x7200)
            started = query_clock() if intervals is not None else None
            client.sendall(len(wire).to_bytes(2, 'big') + wire)
            reply = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
            if intervals is not None:
                intervals.append({'name': name, 'type': kind, 'transport': 'tcp', 'started': started, 'finished': query_clock()})
            rows.append({'name': name, 'type': kind, 'transport': 'tcp', 'response': semantics(reply)})
            raw.append({'request': wire.hex(), 'reply': reply.hex(), 'transport': 'tcp'})
    return rows, raw


def tftp_sequence(variant, out, receiver):
    rows, raw = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('127.0.0.1', 16504))
        client.settimeout(.2)
        def request(label, wire, expected, finish=False, remote_error=None):
            client.sendto(wire, ('127.0.0.1', 69))
            try:
                reply, peer = client.recvfrom(65535)
            except socket.timeout:
                if expected is not None:
                    raise
                rows.append({'label': label, 'response': None})
                raw.append({'label': label, 'request': wire.hex(), 'reply': None})
                return
            if expected is None or reply != expected:
                raise AssertionError(('TFTP source response', label, expected, reply))
            rows.append({'label': label, 'response': reply.hex(), 'dedicated': peer[1] != 69})
            raw.append({'label': label, 'request': wire.hex(), 'reply': reply.hex(), 'peer': list(peer)})
            if remote_error:
                client.sendto(remote_error, peer)
                raw.append({'label': label + '-client-error', 'request': remote_error.hex(), 'peer': list(peer)})
            if finish:
                client.sendto(b'\0\4\0\1', peer)
                last, origin = client.recvfrom(65535)
                if last != b'\0\3\0\2' + b'x' * 188 or origin != peer:
                    raise AssertionError('TFTP final block')
                client.sendto(b'\0\4\0\2', peer)
                rows.append({'label': label + '-last', 'response': last.hex()})
                raw.append({'label': label + '-last', 'reply': last.hex(), 'peer': list(peer)})
            time.sleep(.02)
            receiver.drain()
        rrq = b'\0\1public\0octet\0'
        if variant == 'script':
            request('completed', rrq, b'\0\3\0\1' + b'x' * 512, finish=True)
        elif variant == 'port-exhausted':
            request('port-exhausted', rrq, None)
        elif variant == 'timeout':
            request('timeout', rrq, b'\0\3\0\1' + b'x' * 512)
            deadline = time.monotonic() + 125
            while time.monotonic() < deadline:
                receiver.drain()
                if b'timeout sending /m2/logging/public to 127.0.0.1' in (out / 'stderr').read_bytes():
                    break
                time.sleep(.03)
            else:
                raise AssertionError('source 120-second transfer timeout did not log')
        else:
            request('completed', rrq, b'\0\3\0\1' + b'x' * 512, finish=True)
            for label, wire, reply in [
                ('missing', b'\0\1missing\0octet\0', b'\0\5\0\1file /m2/logging/missing not found for 127.0.0.1\0'),
                ('permissions', b'\0\1private\0octet\0', b'\0\5\0\2cannot access /m2/logging/private: Permission denied\0'),
                ('read', b'\0\1directory\0octet\0', b'\0\5\0\0cannot read /m2/logging/directory: Is a directory\0'),
                ('mode', b'\0\1public\0bad\0', b'\0\5\0\4unsupported request from 127.0.0.1\0'),
                ('write', b'\0\2', b'\0\5\0\4unsupported write request from 127.0.0.1\0'),
                ('unknown', b'\0\x09', None),
            ]:
                request(label, wire, reply)
            for label, filename in [('sanitise', b'missing-\1\t\n\x7f\x80\xff-name')]:
                clean = bytes(byte for byte in filename if 0x20 <= byte <= 0x7e)
                request(label, b'\0\1' + filename + b'\0octet\0',
                        b'\0\5\0\1file /m2/logging/' + clean + b' not found for 127.0.0.1\0')
            stem = b'a' * 200 + b'/' + b'b' * 200 + b'/'
            for size in [498, 499, 520]:
                overhead = len(b'file /m2/logging/' + stem + b' not found for 127.0.0.1')
                filename = stem + b'x' * (size - overhead)
                message = b'file /m2/logging/' + filename + b' not found for 127.0.0.1'
                request('bounded-' + str(size), b'\0\1' + filename + b'\0octet\0',
                        b'\0\5\0\1' + message[:499] + b'\0')
            request('client-error', rrq, b'\0\3\0\1' + b'x' * 512,
                    remote_error=b'\0\5\0\3client\1failed\0')
    return rows, raw


def debug_sequence(case, out, receiver):
    if case['debug_probes'] == 'tcp':
        wire = query('debug-forward.logging', 1, 0x7450)
        with socket.create_connection(('127.0.0.1', 15353), timeout=2) as client:
            client.sendall(len(wire).to_bytes(2, 'big') + wire)
            reply = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
        save(out / 'debug-tcp-wire.json', {'request': wire.hex(), 'reply': reply.hex(), 'semantics': semantics(reply)})
        # With no connection made, C make_local_answer(flags0) uses REFUSED.
        if reply[:2] != wire[:2] or semantics(reply)['flags'] & 15 != 5:
            raise AssertionError('source TCP all-connections-failed REFUSED')
        time.sleep(.03)
        receiver.drain()
        return [{'request': wire.hex(), 'reply': reply.hex()}], None
    explicit = case['debug_probes'] == 'explicit'
    old_nonlocal = Path('/proc/sys/net/ipv4/ip_nonlocal_bind').read_text()
    subprocess.run(['ip', 'link', 'add', 'm5log', 'type', 'dummy'], check=True)
    index = socket.if_nametoindex('m5log')
    rows = []
    try:
        subprocess.run(['ip', 'link', 'set', 'm5log', 'addrgenmode', 'none'], check=True)
        if explicit:
            Path('/proc/sys/net/ipv4/ip_nonlocal_bind').write_text('1\n')
        subprocess.run(['ip', 'link', 'set', 'm5log', 'up'], check=True)
        address = '192.0.2.102' if explicit else '192.0.2.100'
        subprocess.run(['ip', 'address', 'add', address + '/24', 'dev', 'm5log'], check=True)
        if explicit:
            subprocess.run(['ip', 'route', 'add', 'local', '192.0.2.101/32', 'dev', 'lo'], check=True)
        target = '192.0.2.101' if explicit else address
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            receiver.drain()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(.03)
                wire = query('ready.logging', 1, 0x7451)
                client.sendto(wire, (target, 15353))
                try:
                    reply = client.recv(65535)
                    if [value['data'] for value in semantics(reply)['records']] != ['192.0.2.1']:
                        raise AssertionError('dynamic listener health')
                    rows.append({'request': wire.hex(), 'reply': reply.hex(), 'target': target})
                    break
                except socket.timeout:
                    pass
            time.sleep(.01)
        else:
            raise AssertionError('dynamic listener did not activate')
        subprocess.run(['ip', 'link', 'delete', 'm5log'], check=True)
        time.sleep(.2)
        receiver.drain()
    finally:
        subprocess.run(['ip', 'link', 'delete', 'm5log'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if explicit:
            subprocess.run(['ip', 'route', 'delete', 'local', '192.0.2.101/32', 'dev', 'lo'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path('/proc/sys/net/ipv4/ip_nonlocal_bind').write_text(old_nonlocal)
    return rows, index


def identity_probes():
    probes = []
    def add(labels, kind=16, cls=3, rd=True, edns=False, do=False, rcode=None, txt=None):
        probes.append({'labels': labels, 'type': kind, 'class': cls, 'rd': rd,
                       'edns': edns, 'do': do, 'rcode': rcode, 'txt': txt})
    for labels in [[b'bind'], [b'server'], [b'version', b'bind'], [b'explicit', b'server'],
                   [b'VeRsIoN', b'BiNd'], [b'foo', b'bar', b'SeRvEr']]:
        for kind in [1, 16, 28, 255]:
            add(labels, kind, rcode=4)
    for labels in [[b'badbind'], [b'badserver'], [b'foo', b'badbind'], [b'foo', b'badserver'],
                   [b'foo.bind'], [b'foo.server']]:
        add(labels, rcode=5)
    for labels in [[b'x.y', b'bind'], [b'x\0y', b'bind'], [b'x\1y', b'server']]:
        add(labels, rcode=4)
    for rd, do in [(False, False), (True, False), (False, True), (True, True)]:
        add([b'binary.dot', b'bind'], rd=rd, edns=True, do=do, rcode=4)
    for labels, value in [([b'kept', b'logging'], 'explicit-user'),
                          ([b'version', b'bind'], 'explicit-user'),
                          ([b'explicit', b'server'], 'server-user')]:
        for kind in [16, 255]:
            add(labels, kind, 1, rcode=0, txt=value)
            # QCLASS ANY does not match an explicit IN TXT: exact C uses
            # t->class==qclass; QTYPE ANY is the independent positive control.
            add(labels, kind, 255)
    return probes


def identity_sequence(transport, calibrate, sticky_probe=None, fresh=False):
    observed, raw = [], []
    endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM)
    endpoint.settimeout(.5)
    if transport == 'tcp':
        endpoint.connect(('127.0.0.1', 15353))
    try:
        probes = identity_probes()
        if sticky_probe is not None:
            base = {'labels': [b'kept', b'logging'], 'type': 16, 'class': sticky_probe,
                    'rd': True, 'edns': False, 'do': False, 'rcode': 0 if sticky_probe == 1 else None,
                    'txt': 'explicit-user' if sticky_probe == 1 else None}
            probes = [base] if fresh else [dict(base, edns=True), base]
        for index, probe in enumerate(probes):
            qname = b''.join(bytes([len(label)]) + label for label in probe['labels']) + b'\0'
            wire = struct.pack('!6H', 0x7300 + index, 0x100 if probe['rd'] else 0,
                               1, 0, 0, int(probe['edns']))
            wire += qname + struct.pack('!HH', probe['type'], probe['class'])
            if probe['edns']:
                wire += b'\0' + struct.pack('!HHIH', 41, 1232, 0x8000 if probe['do'] else 0, 0)
            if transport == 'tcp':
                endpoint.sendall(len(wire).to_bytes(2, 'big') + wire)
                reply = exact_read(endpoint, int.from_bytes(exact_read(endpoint, 2), 'big'))
            else:
                endpoint.sendto(wire, ('127.0.0.1', 15353))
                reply = endpoint.recv(65535)
            answer = semantics(reply)
            if reply[:2] != wire[:2]:
                raise AssertionError('identity query transaction changed')
            if calibrate and probe['rcode'] is not None and answer['flags'] & 15 != probe['rcode']:
                raise AssertionError(('identity RCODE calibration', probe, answer))
            answers = [record for record in answer['records'] if record['section'] == 'answer']
            if calibrate and probe['txt'] is not None:
                expected = (bytes([len(probe['txt'])]) + probe['txt'].encode()).hex()
                if [record['data'] for record in answers] != [expected] or any(record['class'] != 1 for record in answers):
                    raise AssertionError(('explicit IN TXT control', probe, answer))
            elif calibrate and probe['txt'] is None and answers:
                raise AssertionError(('unexpected identity/class255 record', probe, answer))
            row = {'probe': dict(probe, labels=[label.hex() for label in probe['labels']]),
                   'transport': transport, 'response': answer, 'reply_wire': reply.hex()}
            observed.append(row)
            raw.append({'request': wire.hex(), 'reply': reply.hex(), 'transport': transport})
    finally:
        endpoint.close()
    return observed, raw


class QueryUpstream:
    """Fixed-address UDP/TCP fixture; retain each actual request and response."""
    def __init__(self, refresh_reply=False, retry_barrier=False):
        self.refresh_reply = refresh_reply
        self.retry_barrier = retry_barrier
        self.held_retry = None
        self.retry_requests = 0
        self.released_on_request = None
        self.retry_released = threading.Event()
        self.sockets, self.clients, self.wire, self.errors = [], {}, [], []
        self.pending = []
        self.stale_seen = set()
        self.stopped = threading.Event()
        for address, port in [('127.0.0.2', 15957), ('127.0.0.3', 15958)]:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((address, port))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((address, port))
            tcp.listen()
            self.sockets.extend([udp, tcp])
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def response(self, request):
        name, end = read_name(request, 12)
        kind = struct.unpack_from('!H', request, end)[0]
        question = request[12:end + 4]
        if name == 'rebind.forward.test':
            body = rr(1, bytes([10, 1, 2, 3]))
            return request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + body
        if name == 'rebind-alias.forward.test':
            body = rr(5, wire_name('rebind-terminal.forward.test')) + rr(1, bytes([10, 1, 2, 3]), owner=wire_name('rebind-terminal.forward.test'))
            return request[:2] + struct.pack('!5H', 0x8180, 1, 2, 0, 0) + question + body
        if name.startswith('stale-'):
            seen = name in self.stale_seen
            if seen and not self.refresh_reply: return None
            self.stale_seen.add(name)
            return request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + rr(1, bytes([192, 0, 2, 7]), ttl=120 if seen else 1)
        if name == 'alias.forward.test':
            body = rr(5, wire_name('terminal.forward.test')) + rr(1, bytes([192, 0, 2, 7]), owner=wire_name('terminal.forward.test'))
            return request[:2] + struct.pack('!5H', 0x8180, 1, 2, 0, 0) + question + body
        if name == 'max-txt.forward.test':
            text = b''.join(b'\xff' + bytes([ord('X') + index]) * 255 for index in range(4)) + b'\0\x0fLeading\x01ignored'
            return request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + rr(16, text)
        if kind == 16:
            body = rr(16, b'\x05hello\x06Second\x00')
            return request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + body
        if kind == 12:
            body = rr(12, wire_name('ptr-target.forward.test'))
            return request[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0) + question + body
        for prefix, rcode in [('formerr.', 1), ('servfail.', 2), ('numeric.', 10)]:
            if name.startswith(prefix): return request[:2] + struct.pack('!5H', 0x8180 | rcode, 1, 0, 0, 0) + question
        if name.startswith('error.'):
            return request[:2] + struct.pack('!5H', 0x8185, 1, 0, 0, 0) + question
        if name.startswith('truncated.'):
            return request[:2] + struct.pack('!5H', 0x8380, 1, 0, 0, 0) + question
        return ordinary_upstream_answer(request)

    def run(self):
        while not self.stopped.is_set():
            ready, _, _ = select.select(self.sockets + list(self.clients), [], [], .005)
            due = [item for item in self.pending if item[0] <= time.monotonic()]
            self.pending = [item for item in self.pending if item not in due]
            for _, endpoint, peer, response, record in due:
                endpoint.sendto(response, peer)
                record['response_sent_monotonic_ns'] = time.monotonic_ns()
            if self.held_retry and self.released_on_request is None:
                if time.monotonic_ns() - self.held_retry[3]['received_monotonic_ns'] > RETRY_BARRIER_SECONDS * 1_000_000_000:
                    self.errors.append('fast retry upstream witness timed out')
                    self.stopped.set()
                    continue
            for endpoint in ready:
                try:
                    if endpoint in self.clients:
                        received = endpoint.recv(65535)
                        if not received:
                            endpoint.close(); del self.clients[endpoint]; continue
                        self.clients[endpoint].extend(received)
                        pending = self.clients[endpoint]
                        while len(pending) >= 2 and len(pending) >= 2 + int.from_bytes(pending[:2], 'big'):
                            length = int.from_bytes(pending[:2], 'big')
                            request = bytes(pending[2:2 + length]); del pending[:2 + length]
                            response = self.response(request)
                            self.wire.append({'transport': 'tcp', 'request': request.hex(), 'reply': None if response is None else response.hex(), 'server': list(endpoint.getsockname())})
                            if response is not None: endpoint.sendall(len(response).to_bytes(2, 'big') + response)
                    elif endpoint.type == socket.SOCK_STREAM:
                        client, _ = endpoint.accept(); client.settimeout(.5); self.clients[client] = bytearray()
                    else:
                        request, peer = endpoint.recvfrom(65535)
                        received = time.monotonic_ns()
                        response = self.response(request)
                        record = {'transport': 'udp', 'request': request.hex(), 'reply': None if response is None else response.hex(),
                                  'server': list(endpoint.getsockname()), 'peer': list(peer),
                                  'received_monotonic_ns': received, 'response_sent_monotonic_ns': None}
                        self.wire.append(record)
                        if response is None: continue
                        if read_name(request, 12)[0] == 'delay.forward.test':
                            if self.retry_barrier:
                                record['reply'] = None
                                self.retry_requests += 1
                                if self.retry_requests == 1:
                                    self.held_retry = (endpoint, peer, response, record)
                                elif self.retry_requests == 2:
                                    first_endpoint, first_peer, first_response, first = self.held_retry
                                    if record['request'] != first['request'] or peer != first_peer or endpoint is not first_endpoint:
                                        raise AssertionError('fast retry wire/peer changed')
                                    first['response_send_started_monotonic_ns'] = time.monotonic_ns()
                                    first_endpoint.sendto(first_response, first_peer)
                                    first['reply'] = first_response.hex()
                                    first['response_sent_monotonic_ns'] = time.monotonic_ns()
                                    self.released_on_request = self.retry_requests
                                    self.retry_released.set()
                            else:
                                self.pending.append((time.monotonic() + .12, endpoint, peer, response, record))
                        else:
                            endpoint.sendto(response, peer)
                            record['response_sent_monotonic_ns'] = time.monotonic_ns()
                except Exception as error:
                    self.errors.append(repr(error))
                    self.stopped.set()

    def close(self):
        self.stopped.set(); self.thread.join(1)
        if self.thread.is_alive(): raise AssertionError('query fixture thread leaked')
        for endpoint in self.sockets + list(self.clients): endpoint.close()
        if self.held_retry and self.released_on_request is None:
            self.errors.append('fast retry reply was never released by an actual retry')
        if self.errors: raise AssertionError(('query fixture failure', self.errors))


def query_transaction_probe(kind):
    trace, rows = [], []
    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
    clients[0].bind(('127.0.0.1', 16505)); clients[0].settimeout(1)
    if kind == 'fastretry': clients[0].settimeout(RETRY_BARRIER_SECONDS + .5)
    if kind == 'coalesce':
        clients.append(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        clients[1].bind(('127.0.0.1', 16506)); clients[1].settimeout(1)
    try:
        first = query_packet('delay.forward.test', 1, 0x7601)
        sent = time.monotonic_ns()
        clients[0].sendto(first, ('127.0.0.1', 15353))
        if kind == 'coalesce':
            second = query_packet('delay.forward.test', 1, 0x7602)
            clients[1].sendto(second, ('127.0.0.1', 15353))
        elif kind == 'clientretry':
            time.sleep(.015)
            clients[0].sendto(first, ('127.0.0.1', 15353))
        for index, client in enumerate(clients):
            response = client.recv(65535)
            received = time.monotonic_ns()
            request = first if index == 0 else second
            if response[:2] != request[:2]: raise AssertionError('transaction recipient ID changed')
            rows.append({'transport': 'udp', 'response': semantics(response)})
            trace.append({'transport': 'udp', 'request': request.hex(), 'reply': response.hex(), 'client': list(client.getsockname())})
            if kind == 'fastretry': trace[-1].update(send_count=1, sent_monotonic_ns=sent, received_monotonic_ns=received)
        cached_sent = time.monotonic_ns()
        answer, raw = exchange('delay.forward.test', 1, port=16507, timeout=1)
        rows.append({'transport': 'udp-cached', 'response': answer});trace.append(dict(raw, transport='udp-cached'))
        if kind == 'fastretry': trace[-1].update(send_count=1, client=['127.0.0.1', 16507],
            sent_monotonic_ns=cached_sent, received_monotonic_ns=time.monotonic_ns())
    finally:
        for client in clients: client.close()
    return rows, trace


def query_extreme_probe():
    labels = [[b'x\x01y', b'logging'], [b'bin\x7f\xff', b'logging'],
              [b'a' * 63, b'b' * 63, b'c' * 63, b'd' * 61]]
    rows, trace = [], []
    for transport in ['udp', 'tcp']:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client.bind(('127.0.0.1', 16511));client.settimeout(1)
            if transport == 'tcp':client.connect(('127.0.0.1', 15353))
            for index, parts in enumerate(labels):
                wire = struct.pack('!6H', 0x7800 + index, 0x0100, 1, 0, 0, 0)
                wire += b''.join(bytes([len(label)]) + label for label in parts) + b'\0\0\x01\0\x01'
                if transport == 'tcp':
                    client.sendall(len(wire).to_bytes(2, 'big') + wire)
                    reply = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
                else:client.sendto(wire, ('127.0.0.1', 15353));reply = client.recv(65535)
                if reply[:2] != wire[:2]:raise AssertionError('extreme query transaction changed')
                rows.append({'labels': [label.hex() for label in parts], 'transport': transport, 'reply_wire': reply.hex()})
                trace.append({'request': wire.hex(), 'reply': reply.hex(), 'transport': transport})
    return rows, trace


def query_stale_probe():
    rows, trace = [], []
    for name in ['stale-udp.forward.test', 'stale-tcp.forward.test']:
        answer, raw = exchange(name, 1, port=16509, timeout=1)
        rows.append({'name': name, 'transport': 'udp-warm', 'response': answer}); trace.append(dict(raw, transport='udp-warm'))
    time.sleep(2.2)
    answer, raw = exchange('stale-udp.forward.test', 1, port=16509, timeout=1)
    rows.append({'name': 'stale-udp.forward.test', 'transport': 'udp-stale', 'response': answer}); trace.append(dict(raw, transport='udp-stale'))
    tcp_rows, tcp_raw = tcp_sequence([('stale-tcp.forward.test', 1)])
    rows.extend(tcp_rows); trace.extend(tcp_raw)
    for row in rows[2:]:
        addresses = [record for record in row['response']['records'] if record['type'] == 1]
        if len(addresses) != 1 or addresses[0]['ttl'] != 0:
            raise AssertionError(('actual stale answer missing', row))
    return rows, trace


def query_control_probe():
    rows, trace = [], []
    probes = [('ready.logging', 1, 1, 2), ('version.bind', 16, 3, 0), ('ready.logging', 1, 255, 0)]
    for transport in ['udp', 'tcp']:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if transport == 'tcp' else socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client.bind(('127.0.0.1', 16510)); client.settimeout(1)
            if transport == 'tcp': client.connect(('127.0.0.1', 15353))
            for index, (name, kind, cls, opcode) in enumerate(probes):
                wire = struct.pack('!6H', 0x7700 + index, 0x0100 | opcode << 11, 1, 0, 0, 0) + wire_name(name) + struct.pack('!HH', kind, cls)
                if transport == 'tcp':
                    client.sendall(len(wire).to_bytes(2, 'big') + wire); response = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
                else: client.sendto(wire, ('127.0.0.1', 15353)); response = client.recv(65535)
                if response[:2] != wire[:2]: raise AssertionError('query control transaction changed')
                rows.append({'name': name, 'class': cls, 'opcode': opcode, 'transport': transport, 'response': semantics(response)})
                trace.append({'request': wire.hex(), 'reply': response.hex(), 'transport': transport})
    return rows, trace


def dhcp_packet(kind, xid, *, mac='0200000000aa', address=None, ciaddr='0.0.0.0', server=None, message=None):
    data = bytearray(240)
    data[:3] = bytes([1, 1, 6]); data[4:8] = struct.pack('!I', xid)
    data[10:12] = b'\x80\0'; data[12:16] = socket.inet_aton(ciaddr)
    data[28:34] = bytes.fromhex(mac); data[236:240] = bytes.fromhex('63825363')
    def option(code, value): data.extend(bytes([code, len(value)]) + value)
    if kind: option(53, bytes([kind]))
    if message is not None: option(56, message.encode())
    if address is not None: option(50, socket.inet_aton(address))
    if server is not None: option(54, socket.inet_aton(server))
    option(12, b'm5-client'); option(60, b'm5-fixture'); option(77, b'\x04test')
    option(55, bytes([1, 3, 6, 12, 15, 51, 58, 59]))
    data.append(255)
    return bytes(data)


def dhcp_sequence(leasefile, query_origin=False):
    rows, trace = [], []
    steps = [
        ('bootp', 0, {}, 0),
        ('discover', 1, {}, 2),
        ('request', 3, {'address': '127.0.0.10', 'server': '127.0.0.1'}, 5),
        ('inform', 8, {'ciaddr': '127.0.0.10'}, 5),
        ('nak', 3, {'address': '127.0.0.99', 'server': '127.0.0.1'}, 6),
        ('request-again', 3, {'address': '127.0.0.10', 'server': '127.0.0.1'}, 5),
        ('release', 7, {'ciaddr': '127.0.0.10', 'server': '127.0.0.1'}, None),
        ('release-unknown', 7, {'ciaddr': '127.0.0.10', 'server': '127.0.0.1'}, None),
        ('decline', 4, {'address': '127.0.0.10', 'server': '127.0.0.1', 'message': 'client declines'}, None),
        ('decline-empty', 4, {'address': '127.0.0.10', 'server': '127.0.0.1'}, None),
        ('discover-ignored', 1, {'mac': '0200000000bb'}, None),
        ('inform-ignored', 8, {'mac': '0200000000bb', 'ciaddr': '127.0.0.10'}, None)]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0'); client.bind(('0.0.0.0', 68))
        for index, (label, kind, fields, expected) in enumerate(steps):
            xid = 0x1200 + index
            request = dhcp_packet(kind, xid, **fields)
            client.settimeout(.15 if expected is None else 1)
            lease_before = leasefile.read_text() if kind == 8 and leasefile.exists() else ''
            before_ns = time.time_ns()
            client.sendto(request, ('255.255.255.255', 67))
            response = None
            while True:
                try: received = client.recv(65535)
                except socket.timeout: break
                if len(received) >= 240 and received[4:8] == request[4:8]: response = received; break
            after_ns = time.time_ns()
            if expected is None and response is not None: raise AssertionError(('ignored DHCP replied', label))
            if expected is not None:
                if response is None: raise AssertionError(('missing DHCP reply', label))
                at, actual = 240, None
                while at < len(response):
                    code = response[at]; at += 1
                    if code == 255: break
                    if code == 0: continue
                    length = response[at]; at += 1
                    if code == 53: actual = response[at]
                    at += length
                if actual != (None if expected == 0 else expected): raise AssertionError(('DHCP response type', label, actual, expected))
            if query_origin and label == 'request':
                for name, kind in [('m5-client', 1), ('10.0.0.127.in-addr.arpa', 12)]:
                    answer, raw = exchange(name, kind, port=16509)
                    rows.append({'label': 'dns-' + name, 'response': answer})
                    trace.append(dict(raw, label='dns-' + name))
            observed = {'label': label, 'reply': response.hex() if response is not None else None}
            raw = dict(observed, request=request.hex())
            if kind == 8 and response is not None:
                clock = inform_clock_witness(lease_before, {'kind': kind, **fields}, before_ns, after_ns)
                observed['inform_clock'] = clock
                raw['inform_clock'] = clock
            rows.append(observed)
            trace.append(raw)
    return rows, trace


def normalize_dhcp_inform(row, detail):
    """Validate the actual expiry/clock, then omit only elapsed INFORM time."""
    for exchange in row.get('dhcp', []):
        if exchange.get('label') != 'inform':
            continue
        response = bytes.fromhex(exchange['reply'])
        event = {'kind': 8, 'ciaddr': '127.0.0.10'}
        clock = exchange.pop('inform_clock')
        exchange['reply'] = comparable_reply(response, event, clock)
        options = [option for option in primary_options(response)['rows'] if option['code'] == 51]
        assert len(options) == 1, 'fixture INFORM must report its existing lease'
        remaining = int(options[0]['value'], 16)
        # util.c::prettyprint_time, applied only after the wire time was
        # validated against this side's pre-request lease and clock interval.
        duration = 'infinite' if remaining == 0xffffffff else ''.join(
            str(value) + suffix for value, suffix in [
                (remaining // 86400, 'd'), (remaining // 3600 % 24, 'h'),
                (remaining // 60 % 60, 'm'), (remaining % 60, 's')] if value)
        xid = int.from_bytes(response[4:8], 'big')
        pattern = re.compile(r'(?m)^([^\n]*dnsmasq-dhcp(?:\[[^\]\n]+\])?: ' + str(xid)
            + r' sent size:  4 option: 51 lease-time  )([^\n]*)(?=\n|$)')
        messages = list(pattern.finditer(row['stderr']))
        assert len(messages) == int(detail), 'INFORM lease-time log count differs'
        assert all(match[2] == duration for match in messages), 'INFORM lease-time log differs from its wire value'
        row['stderr'] = pattern.sub(lambda match: match[1] + '<INFORM-remaining>', row['stderr'])


def run(root, side, case, out):
    if case.get('blocked_kind'):
        return run_blocked_sink(root, side, case, out)
    if case.get('scope') in ['daemon', 'scriptuser-boundary', 'startup-fault', 'credential-fault', 'ownership-warning', 'sink-fault', 'error-frame', 'root-access', 'async-transport']:
        return run_daemon(root, side, case, out)
    out.mkdir()
    folder = image_path(root, '/m2/logging')
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    (folder / 'config').write_bytes(bytes.fromhex(case['config_bytes']) if 'config_bytes' in case else case.get('config', '').encode())
    for name, text in case.get('setup_files', {}).items():
        (folder / name).write_text(text)
    query_upstream = QueryUpstream(case.get('query_refresh_reply', False),
        retry_barrier=case.get('query_transaction_probe') == 'fastretry') if case.get('query_upstream') else None
    blocker = None
    tcp_upstream = None
    if case.get('tcp_rotate'):
        tcp_upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_upstream.bind(('127.0.0.2', 15955))
        tcp_upstream.listen()
        tcp_upstream.settimeout(2)
    if case.get('tftp_probes') or case.get('no_dns'):
        (folder / 'public').write_bytes(b'x' * 700)
        (folder / 'public').chmod(0o644)
        (folder / 'private').write_bytes(b'private')
        (folder / 'private').chmod(0o600)
        (folder / 'directory').mkdir()
        if case.get('tftp_probes') == 'port-exhausted':
            blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            blocker.bind(('127.0.0.1', 35000))
    if case.get('script_probes'):
        outcome = case['script_probes']
        if outcome != 'exec':
            script = folder / 'script'
            script.write_text('#!/bin/sh\n' + ("printf 'inherited umask %s\\n' \"$(umask)\"\n"
                "while read name value rest; do case \"$name\" in SigIgn:) printf 'inherited ignored %s\\n' \"$value\";; esac; done < /proc/self/status\n"
                if outcome == 'inheritance' else 'kill -USR1 $$\n' if outcome == 'signal' else
                "printf 'one\\n\\n'; printf 'nul\\000hidden\\n'; head -c 4096 /dev/zero | tr '\\000' x; printf '\\ntail'; exit 7\n"))
            script.chmod(0o755)
    image_path(root, '/etc/dnsmasq.conf', follow_leaf=False).write_text(
        'unrecognised-directive=fail\n' if case.get('invalid_default') else '')
    if 'existing' in case:
        (folder / case['file']).write_text(case['existing'])
        (folder / case['file']).chmod(case['file_mode'])
        if 'file_gid' in case:
            os.chown(folder / case['file'], 0, case['file_gid'])
    receiver = Receiver(root, None if case.get('late_receiver') else case.get('receiver'))
    # C selects the DHCP help list only with exactly argc3 and argv[2]=dhcp.
    argv = [] if case['kind'] == 'cli' else ['-C', '/m2/logging/config']
    if case['kind'] != 'cli':
        argv += [arg for arg in BASE if arg not in case.get('base_skip', [])] + ['--user=' + case.get('user', 'root')]
        argv += ['--test'] if case['kind'] == 'test' else case.get('mode', ['-k'])
    argv += case['argv']
    full = command(root, side, *argv)
    observed = {'ready': False, 'exit': None, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': ''}
    save(out / 'fixture.json', case)
    save(out / 'command.json', full)
    start = time.monotonic()
    trace = {'dns': [], 'command': full}
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True,
                                   preexec_fn=(lambda: os.umask(case['inherited_umask'])) if 'inherited_umask' in case else None)
        try:
            deadline = start + 3
            while time.monotonic() < deadline:
                if not case.get('pause_receiver'):
                    receiver.drain()
                if process.poll() is not None:
                    break
                if case['kind'] == 'run':
                    try:
                        if case.get('query_probes') and case.get('query_startup_barrier', 'cleared cache\n').encode() not in (out / 'stderr').read_bytes():
                            time.sleep(.005)
                            continue
                        if case.get('no_dns'):
                            rows, raw = tftp_sequence('script', out, receiver)
                            observed['tftp'] = rows
                            trace['tftp'] = raw
                        else:
                            answer, raw = exchange('ready.logging', port=16500 if case.get('query_probes') else None)
                            if [row['data'] for row in answer['records']] != ['192.0.2.1']:
                                raise AssertionError('wrong readiness answer')
                            trace['dns'].append(raw)
                        observed['ready'] = True
                        trace['identity'] = process_identity(root, process.pid)
                        wanted = sha256(image_path(root, '/usr/sbin/dnsmasq' + ('-rs' if side == 'rust' else '')))
                        if trace['identity']['sha256'] != wanted:
                            raise AssertionError('wrong daemon identity')
                        break
                    except (socket.timeout, ConnectionRefusedError):
                        pass
                time.sleep(.005)
            if observed['ready']:
                if case.get('tcp_rotate'):
                    wire = query('rotation-forward.logging', 1, 0x7520)
                    with socket.create_connection(('127.0.0.1', 15353), timeout=2) as client:
                        client.sendall(len(wire).to_bytes(2, 'big') + wire)
                        peer, _ = tcp_upstream.accept()
                        peer.settimeout(2)
                        upstream_wire = exact_read(peer, int.from_bytes(exact_read(peer, 2), 'big'))
                        path = folder / case['file']
                        path.rename(path.with_suffix('.old'))
                        process.send_signal(signal.SIGUSR2)
                        deadline = time.monotonic() + 1
                        while not path.exists() and time.monotonic() < deadline:
                            time.sleep(.005)
                        if not path.exists():
                            raise AssertionError('parent file reopen did not complete')
                        peer.close()
                        tcp_upstream.close()
                        reply = exact_read(client, int.from_bytes(exact_read(client, 2), 'big'))
                        observed['tcp_rotate_reply'] = reply.hex()
                        trace['tcp_rotate'] = {'request': wire.hex(), 'upstream_request': upstream_wire.hex(),
                                               'reply': reply.hex()}
                    time.sleep(.03)
                if case.get('sink_edge'):
                    def snapshot():
                        return {entry.name: os.readlink(entry) for entry in Path(f'/proc/{process.pid}/fd').iterdir()}
                    def health():
                        answer, raw = exchange('ready.logging')
                        if [value['data'] for value in answer['records']] != ['192.0.2.1']:
                            raise AssertionError('reopen harmed client health')
                        trace['dns'].append(raw)
                    before = snapshot()
                    if case['sink_edge'] in ['preserve', 'debug-fd']:
                        process.send_signal(signal.SIGUSR2)
                        time.sleep(.08)
                        after = snapshot()
                        observed['sink_edge'] = {'same_fds': before == after}
                        if case['sink_edge'] == 'debug-fd':
                            observed['sink_edge']['stderr_copies'] = sum(value == before['2'] for value in before.values())
                        health()
                    else:
                        path = folder / case['file']
                        path.rename(path.with_suffix('.old'))
                        path.mkdir()
                        process.send_signal(signal.SIGUSR2)
                        time.sleep(.08)
                        failed = snapshot()
                        process.send_signal(signal.SIGHUP)
                        time.sleep(.08)
                        receiver.drain()
                        health()
                        path.rmdir()
                        path.write_text('replacement\n')
                        path.chmod(0o604)
                        process.send_signal(signal.SIGUSR2)
                        time.sleep(.08)
                        process.send_signal(signal.SIGHUP)
                        time.sleep(.08)
                        receiver.drain()
                        health()
                        meta = path.stat()
                        observed['sink_edge'] = {'old_fd_closed': not any(value.endswith('/daemon.old') for value in failed.values()),
                            'replacement_metadata': [meta.st_mode & 0o777, meta.st_uid, meta.st_gid]}
                    trace['sink_fds'] = {'before': before, 'after': snapshot()}
                if case.get('late_receiver'):
                    receiver.close()
                    receiver = Receiver(root, 'dgram')
                    if case.get('queued_tcp'):
                        rows, _ = debug_sequence({'debug_probes': 'tcp'}, out, receiver)
                        observed['debug_wire'] = rows
                        trace['debug_wire'] = rows
                    else:
                        process.send_signal(signal.SIGHUP)
                        time.sleep(.08)
                        receiver.drain()
                        first = list(receiver.raw)
                        receiver.close()
                        image_path(root, '/dev/log', follow_leaf=False).unlink()
                        for _ in range(2):
                            process.send_signal(signal.SIGHUP)
                            time.sleep(.04)
                        receiver = Receiver(root, 'dgram')
                        receiver.raw = first
                        process.send_signal(signal.SIGHUP)
                        time.sleep(.08)
                        receiver.drain()
                for name, text, trigger in case.get('file_actions', []):
                    (folder / name).write_text(text)
                    if trigger == 'hup':
                        process.send_signal(signal.SIGHUP)
                    time.sleep(.08)
                    receiver.drain()
                    answer, raw = exchange('ready.logging')
                    if [value['data'] for value in answer['records']] != ['192.0.2.1']:
                        raise AssertionError('file replacement harmed client health')
                    trace['dns'].append(raw)
                if case.get('debug_probes'):
                    rows, index = debug_sequence(case, out, receiver)
                    observed['debug_wire'] = rows
                    if index is not None:
                        observed['interface_index'] = index
                    trace['debug_wire'] = rows
                    trace['interface_index'] = index
                if case.get('pause_receiver'):
                    deadline = time.monotonic() + .2
                    while time.monotonic() < deadline:
                        receiver.drain()
                        time.sleep(.005)
                if case.get('dhcp_probes'):
                    rows, raw = dhcp_sequence(folder / 'leases', case.get('dhcp_query_origin', False))
                    observed['dhcp'] = rows; trace['dhcp'] = raw
                if case.get('tftp_probes'):
                    rows, raw = tftp_sequence(case['tftp_probes'], out, receiver)
                    observed['tftp'] = rows
                    trace['tftp'] = raw
                if case.get('script_probes'):
                    deadline = time.monotonic() + 1
                    while time.monotonic() < deadline:
                        receiver.drain()
                        captured = (out / 'stderr').read_bytes() + (out / 'stdout').read_bytes() + b''.join(receiver.raw)
                        if case.get('file') and (folder / case['file']).exists():
                            captured += (folder / case['file']).read_bytes()
                        if any(text in captured for text in [b'script process exited with status 7',
                                                            b'script process killed by signal 10',
                                                            b'failed to execute /m2/logging/script', b'inherited ignored ']):
                            break
                        time.sleep(.005)
                if case.get('identity_matrix'):
                    for transport in ['udp', 'tcp']:
                        rows, raw = identity_sequence(transport, side == 'c', case.get('identity_sticky_probe'), case.get('identity_fresh', False))
                        observed['dns'].extend(rows)
                        trace['dns'].extend(raw)
                if case.get('query_probes'):
                    phase = align_query_phase() if case['id'] == 'query-forward-ordinary' else None
                    intervals = phase['intervals'] if phase else None
                    for name, kind in query_sequence(case):
                        started = query_clock() if phase else None
                        answer, raw = exchange(name, kind, port=16501, timeout=1 if case.get('query_upstream') else .03)
                        if phase:
                            intervals.append({'name': name, 'type': kind, 'transport': 'udp', 'started': started, 'finished': query_clock()})
                        observed['dns'].append({'name': name, 'type': kind, 'transport': 'udp', 'response': answer})
                        trace['dns'].append(dict(raw, transport='udp'))
                    rows, raw = tcp_sequence(query_sequence(case), intervals)
                    observed['dns'].extend(rows)
                    trace['dns'].extend(raw)
                    started = query_clock() if phase else None
                    answer, raw = exchange('ready.logging', port=16503)
                    if phase:
                        intervals.append({'name': 'ready.logging', 'type': 1, 'transport': 'udp-after-tcp',
                                          'started': started, 'finished': query_clock()})
                        observed['query_phase'] = phase
                        save(out / 'query-phase.json', phase)
                    observed['dns'].append({'name': 'ready.logging', 'type': 1, 'transport': 'udp-after-tcp', 'response': answer})
                    trace['dns'].append(dict(raw, transport='udp-after-tcp'))
                    if case.get('query_extreme_probe'):
                        rows, raw = query_extreme_probe(); observed['dns'].extend(rows); trace['dns'].extend(raw)
                    if case.get('query_stale_probe'):
                        rows, raw = query_stale_probe(); observed['dns'].extend(rows); trace['dns'].extend(raw)
                        if case.get('query_refresh_reply'): time.sleep(.1)
                    if case.get('query_control_probe'):
                        rows, raw = query_control_probe(); observed['dns'].extend(rows); trace['dns'].extend(raw)
                    if case.get('query_transaction_probe'):
                        rows, raw = query_transaction_probe(case['query_transaction_probe'])
                        observed['dns'].extend(rows); trace['dns'].extend(raw)
                        if case['query_transaction_probe'] == 'fastretry':
                            if not query_upstream.retry_released.wait(.5):
                                raise AssertionError('fast retry release witness missing')
                            observed['fast_retry_witness'] = {'client_queries': raw,
                                'upstream': [packet for packet in query_upstream.wire
                                             if read_name(bytes.fromhex(packet['request']), 12)[0] == 'delay.forward.test'],
                                'released_on_request': query_upstream.released_on_request,
                                'upstream_requests': query_upstream.retry_requests,
                                'deadline_seconds': RETRY_BARRIER_SECONDS + .5}
                if case.get('chaos'):
                    for name in ['version.bind', 'authors.bind', 'copyright.bind', 'cachesize.bind',
                                 'insertions.bind', 'evictions.bind', 'hits.bind', 'misses.bind', 'servers.bind']:
                        answer, raw = exchange(name, 16, True)
                        observed['dns'].append({'name': name, 'response': answer})
                        trace['dns'].append(raw)
                    answer, raw = exchange('kept.logging', 16)
                    if [record['data'] for record in answer['records']] != ['0d6578706c696369742d75736572']:
                        raise AssertionError('no-ident changed explicit IN TXT record')
                    observed['dns'].append({'name': 'kept.logging', 'response': answer})
                    trace['dns'].append(raw)
                if case.get('rotate'):
                    path = folder / case['file']
                    path.rename(path.with_suffix('.old'))
                    if case.get('reopen_directory'):
                        path.mkdir()
                    process.send_signal(signal.SIGUSR2)
                    time.sleep(.03)
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(.8)
            except subprocess.TimeoutExpired:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            receiver.drain()
            observed['exit'] = process.returncode
        finally:
            if process.poll() is None:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            receiver.drain()
            receiver.close()
            if blocker:
                blocker.close()
            if tcp_upstream:
                tcp_upstream.close()
            if query_upstream:
                try:
                    query_upstream.close()
                finally:
                    save(out / 'upstream-wire.json', query_upstream.wire)
                    if case.get('query_transaction_probe') == 'fastretry':
                        witness = observed.setdefault('fast_retry_witness', {})
                        witness.update(upstream=[packet for packet in query_upstream.wire
                            if read_name(bytes.fromhex(packet['request']), 12)[0] == 'delay.forward.test'],
                            upstream_requests=query_upstream.retry_requests,
                            released_on_request=query_upstream.released_on_request)
                        save(out / 'fast-retry-witness.json', witness)
            trace['duration'] = time.monotonic() - start
            trace['stream_tail'] = receiver.pending.hex()
            save(out / 'trace.json', trace)
    for path in sorted(folder.iterdir()):
        if path.name in ['daemon.log', 'daemon.old'] and path.is_file():
            observed['files'][path.name] = path.read_bytes().hex()
            info = path.stat()
            observed['file_metadata'][path.name] = [info.st_mode & 0o777, info.st_uid, info.st_gid]
            (out / path.name).write_bytes(path.read_bytes())
    observed['syslog'] = [row.hex() for row in receiver.raw]
    observed['stdout'] = (out / 'stdout').read_bytes().decode(errors='backslashreplace')
    observed['stderr'] = (out / 'stderr').read_bytes().decode(errors='backslashreplace')
    save(out / 'syslog.json', [row.hex() for row in receiver.raw])
    save(out / 'observed.json', observed)
    return observed


def run_blocked_sink(root, side, case, out):
    out.mkdir()
    folder = image_path(root, '/m2/logging')
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    (folder / 'config').write_text('')
    kind = case['blocked_kind']
    receiver = Receiver(root, 'dgram' if kind == 'fifo-peer-disconnect' else None)
    pipe_reader = pipe_writer = fifo_reader = None
    filler_bytes = 0
    log_path = folder / 'daemon.log'
    if kind.startswith('fifo-'):
        os.mkfifo(log_path, 0o640)
        if kind in ['fifo-full', 'fifo-peer-disconnect']:
            fifo_reader = os.open(log_path, os.O_RDONLY | os.O_NONBLOCK)
            fill = os.open(log_path, os.O_WRONLY | os.O_NONBLOCK) if kind == 'fifo-full' else None
        else:
            fill = None
    else:
        pipe_reader, pipe_writer = os.pipe()
        os.set_blocking(pipe_reader, False)
        # Use a separate open-file description for the filler. The logger's
        # inherited write flags stay unchanged by our nonblocking writes.
        fill = os.open(f'/proc/self/fd/{pipe_writer}', os.O_WRONLY | os.O_NONBLOCK)
    if fill is not None:
        capacity = fcntl.fcntl(fill, 1032)  # Linux F_GETPIPE_SZ.
        while True:
            try:
                filler_bytes += os.write(fill, b'B' * 4096)
            except BlockingIOError:
                break
        os.close(fill)
        if filler_bytes != capacity:
            raise AssertionError('sink was not filled to its actual kernel capacity')
    mode = ['-d'] if kind == 'debug-echo-full' else ['-k']
    sink = '/m2/logging/daemon.log' if kind != 'stderr-full' else '-'
    user = 'nobody' if kind.startswith('fifo-') else 'root'
    full = command(root, side, '-C', '/m2/logging/config', *BASE,
                   '--user=' + user, *mode, '--log-facility=' + sink,
                   *(['--enable-tftp', '--tftp-root=/m2/logging'] if kind == 'fifo-peer-disconnect' else []))
    if kind == 'fifo-peer-disconnect':
        (folder / 'public').write_bytes(b'x' * 700)
        (folder / 'public').chmod(0o644)
    save(out / 'fixture.json', case)
    save(out / 'command.json', full)
    captured = bytearray()
    observed = {'ready': False, 'exit': None, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': ''}
    trace = {'command': full, 'filler_bytes': filler_bytes, 'dns': []}
    reader = fifo_reader if fifo_reader is not None else pipe_reader
    def drain(fd):
        while True:
            try:
                value = os.read(fd, 65536)
                if not value:
                    break
                captured.extend(value)
            except BlockingIOError:
                break
    def probe():
        try:
            answer, wire = exchange('ready.logging')
        except (socket.timeout, ConnectionRefusedError):
            return False
        if [r['data'] for r in answer['records']] != ['192.0.2.1']:
            raise AssertionError('blocked sink corrupted DNS response')
        trace['dns'].append(wire)
        return True
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=stdout,
            stderr=pipe_writer if pipe_writer is not None else stderr,
            env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True)
        try:
            time.sleep(.3)
            observed['pre_release_ready'] = probe()
            trace['blocked_process_alive'] = process.poll() is None
            if kind == 'fifo-peer-disconnect':
                drain(reader)
                os.close(fifo_reader)
                fifo_reader = reader = None
                process.send_signal(signal.SIGHUP)
                time.sleep(.15)
                receiver.drain()
                rows, raw = tftp_sequence('script', out, receiver)
                observed['tftp'] = rows
                trace['tftp'] = raw
                observed['fifo_fds_after_failure'] = sum(
                    os.readlink(entry).endswith('/m2/logging/daemon.log')
                    for entry in Path(f'/proc/{process.pid}/fd').iterdir())
                observed['ready'] = probe()
                process.send_signal(signal.SIGTERM)
                process.wait(.8)
                observed['exit'] = process.returncode
            elif case.get('blocked_never_release'):
                observed['ready'] = observed['pre_release_ready']
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(.4)
                except subprocess.TimeoutExpired:
                    observed['forced'] = True
                    process.kill()
                    process.wait(1)
                observed['exit'] = process.returncode
            else:
                if kind == 'fifo-no-reader':
                    fifo_reader = os.open(log_path, os.O_RDONLY | os.O_NONBLOCK)
                reader = fifo_reader if fifo_reader is not None else pipe_reader
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    drain(reader)
                    observed['ready'] = probe()
                    if observed['ready'] and (b'cleared cache\n' in captured or b'overflow: ' in captured
                                             or kind == 'debug-echo-full'):
                        break
                    time.sleep(.01)
                process.send_signal(signal.SIGHUP)
                time.sleep(.15)
                drain(reader)
                if not probe():
                    raise AssertionError('blocked sink recovery harmed DNS')
                process.send_signal(signal.SIGTERM)
                process.wait(.8)
                observed['exit'] = process.returncode
        finally:
            if process.poll() is None:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            if pipe_writer is not None:
                os.close(pipe_writer)
            if reader is not None:
                drain(reader)
            if fifo_reader is not None:
                os.close(fifo_reader)
            if pipe_reader is not None:
                os.close(pipe_reader)
            receiver.drain()
            receiver.close()
            save(out / 'trace.json', trace)
    if filler_bytes:
        if captured[:filler_bytes] != b'B' * filler_bytes:
            raise AssertionError('full sink filler bytes changed')
        del captured[:filler_bytes]
    (out / 'sink.raw').write_bytes(captured)
    if kind.startswith('fifo-'):
        observed['files']['daemon.log'] = captured.hex()
        observed['stderr'] = (out / 'stderr').read_text()
        meta = log_path.stat()
        observed['file_metadata']['daemon.log'] = [meta.st_mode & 0o777, meta.st_uid, meta.st_gid]
    elif kind == 'debug-echo-full':
        observed['files']['daemon.log'] = log_path.read_bytes().hex()
        observed['stderr'] = captured.decode(errors='backslashreplace')
    else:
        observed['stderr'] = captured.decode(errors='backslashreplace')
    observed['stdout'] = (out / 'stdout').read_text()
    observed['syslog'] = [row.hex() for row in receiver.raw]
    save(out / 'syslog.json', observed['syslog'])
    save(out / 'observed.json', observed)
    return observed


def proc_state(pid, root):
    try:
        data = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        if data[0] == 'Z':
            return {'pid': pid, 'state': 'Z', 'ppid': int(data[1]),
                    'pgrp': int(data[2]), 'sid': int(data[3])}
        cwd = os.readlink(f'/proc/{pid}/cwd')
        if cwd.startswith(str(root)):
            cwd = '/' + cwd[len(str(root)):].lstrip('/')
        status = Path(f'/proc/{pid}/status').read_text()
        stdio = []
        for fd in [0, 1, 2]:
            target = os.readlink(f'/proc/{pid}/fd/{fd}')
            stdio.append('null' if target.endswith('/dev/null') else
                         'capture' if target.endswith('/stdout') or target.endswith('/stderr') else target)
        return {'pid': pid, 'state': data[0], 'ppid': int(data[1]), 'pgrp': int(data[2]),
                'sid': int(data[3]), 'cwd': cwd, 'stdio': stdio,
                'uid': [int(value) for value in re.search(r'^Uid:\s+(.*)$', status, re.M)[1].split()],
                'gid': [int(value) for value in re.search(r'^Gid:\s+(.*)$', status, re.M)[1].split()]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def helper_fd_observation(fd, target, fdinfo):
    """Decode Linux /proc evidence without using the observer host's O_CLOEXEC."""
    flags_line = re.search(r'^flags:\s+([0-7]+)\s*$', fdinfo, re.M)
    if flags_line is None:
        raise ValueError(f'missing Linux fdinfo flags for helper FD {fd}')
    flags = int(flags_line[1], 8)
    pipe = re.fullmatch(r'pipe:\[(\d+)\]', target)
    return {'fd': fd, 'target': target, 'flags_octal': flags_line[1],
            'pipe_inode': int(pipe[1]) if pipe else None,
            'direction': {0: 'read', 1: 'write', 2: 'read-write', 3: 'invalid'}[flags & 3],
            'cloexec': bool(flags & 0o2000000)}


def observe_helper_fds(pid, proc_root=Path('/proc')):
    folder = proc_root / str(pid)
    descriptors = []
    for entry in sorted((folder / 'fd').iterdir(), key=lambda path: int(path.name)):
        fd = int(entry.name)
        if fd > 2:
            descriptors.append(helper_fd_observation(
                fd, os.readlink(entry), (folder / 'fdinfo' / entry.name).read_text()))
    return {'pid': pid, 'descriptors': descriptors}


def helper_pipe_errors(observations, copies):
    """Require exactly two pipe endpoints, one read and one write, with N copies."""
    if (not isinstance(observations, list) or len(observations) != 1
            or not isinstance(observations[0], dict)):
        return ['expected exactly one observed helper']
    descriptors = observations[0].get('descriptors')
    if not isinstance(descriptors, list) or len(descriptors) != 2 * copies:
        return [f'expected exactly {2 * copies} nonstdio helper FDs']
    groups, seen = {}, set()
    for descriptor in descriptors:
        try:
            if not isinstance(descriptor, dict):
                return ['incomplete helper FD observation']
            fd = descriptor['fd']
            if type(fd) is not int or fd <= 2 or fd in seen:
                return ['invalid or repeated helper FD number']
            seen.add(fd)
            actual = helper_fd_observation(fd, descriptor['target'],
                                           'flags:\t' + descriptor['flags_octal'] + '\n')
            if any(descriptor.get(key) != actual[key] for key in ['pipe_inode', 'direction', 'cloexec']):
                return ['helper FD metadata disagrees with raw target/flags']
            if actual['pipe_inode'] is None or actual['pipe_inode'] <= 0:
                return ['helper inherited a non-pipe FD']
            if copies == 2 and not actual['cloexec']:
                return ['self-exec helper FD is missing CLOEXEC']
            groups.setdefault(actual['pipe_inode'], []).append(actual['direction'])
        except (KeyError, TypeError, ValueError):
            return ['incomplete helper FD observation']
    if len(groups) != 2 or sorted(groups.values()) != [['read'] * copies, ['write'] * copies]:
        return [f'expected two distinct pipes with {copies} read copies and {copies} write copies']
    return []


def reap_children():
    reaped = {}
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if not pid:
            break
        reaped[pid] = os.waitstatus_to_exitcode(status)
    return reaped



class StartupPipeSelector:
    """Identify the startup channel by its caller, never by pipe ordinal.

    C dnsmasq.c:597-611 and Rust StartupChannel::begin both chdir("/")
    successfully, create the private error pipe, then fork. Signal/helper pipes
    outside that interval must never receive an error-channel fault.
    """
    def __init__(self):
        self.root_chdir_complete = False
        self.fork_seen = False
        self.pointer = None
        self.writer = None
        self.pending = None
        self.events = []

    def enter(self, number, args, root_path=False):
        self.pending = None
        if number == 49 and root_path:  # AArch64 chdir.
            self.pending = 'root-chdir'
            self.events.append({'kind': 'root-chdir-entry'})
        elif number == 220:  # AArch64 clone (libc fork).
            self.fork_seen = True
        elif number == 59 and self.root_chdir_complete and not self.fork_seen and self.pointer is None:
            self.pointer = args[0]
            self.pending = 'startup-pipe'
            self.events.append({'kind': 'startup-pipe-entry', 'pointer': args[0], 'flags': args[1]})
            return True
        return False

    def exit(self, result):
        pending, self.pending = self.pending, None
        if pending == 'root-chdir':
            self.root_chdir_complete = result == 0
            self.events.append({'kind': 'root-chdir-exit', 'result': result})
        elif pending == 'startup-pipe':
            self.events.append({'kind': 'startup-pipe-exit', 'result': result})
            return result == 0
        return False

    def bind_fds(self, reader, writer):
        self.writer = writer
        self.events.append({'kind': 'startup-pipe-fds', 'reader': reader, 'writer': writer})


def keepcaps_enable(args):
    """Select only PR_SET_KEEPCAPS(1), not an earlier unrelated prctl."""
    return args[0] == 8 and args[1] == 1


def traced_startup(argv, case, side, stdout, stderr, report_path):
    if platform.machine() != 'aarch64':
        raise RuntimeError('startup syscall ABI is pinned AArch64')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    class Iovec(ctypes.Structure):
        _fields_ = [('base', ctypes.c_void_p), ('size', ctypes.c_size_t)]
    class Registers(ctypes.Structure):
        _fields_ = [('x', ctypes.c_uint64 * 31), ('sp', ctypes.c_uint64),
                    ('pc', ctypes.c_uint64), ('pstate', ctypes.c_uint64)]
    def preexec():
        if libc.ptrace(0, 0, None, None) != 0:
            raise OSError(ctypes.get_errno(), 'PTRACE_TRACEME')
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True, preexec_fn=preexec)
    pid = process.pid
    def ptrace(request, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(ctypes.c_uint(request), ctypes.c_uint(pid),
                             ctypes.c_void_p(address), ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'ptrace')
        return result
    def regs(write=False, value=None):
        value = value or Registers()
        vec = Iovec(ctypes.addressof(value), ctypes.sizeof(value))
        ptrace(0x4205 if write else 0x4204, 1, ctypes.addressof(vec))
        return value
    report = {'pid': pid, 'fault': case['fault'], 'injected': False, 'events': []}
    attached, pending = True, None
    startup_pipe = StartupPipeSelector()
    report['startup_pipe'] = startup_pipe.events
    followed_children = 0
    socket_pending, logging_socket, logging_socket_type = 0, None, 0
    deadline = time.monotonic() + 5
    def wait_stop():
        while time.monotonic() < deadline:
            returned, status = os.waitpid(pid, os.WNOHANG)
            if returned:
                return status
            time.sleep(.001)
        raise TimeoutError('startup trace syscall deadline')
    try:
        status = wait_stop()
        if not os.WIFSTOPPED(status):
            raise AssertionError('tracee did not stop at initial exec')
        ptrace(0x4200, 0, 1 | (2 if case['fault'] == 'fork-two' or case.get('fault_follow_child') else 0))
        for _ in range(50000):
            ptrace(24)
            status = wait_stop()
            if not os.WIFSTOPPED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                attached = False
                raise AssertionError('tracee exited before selected startup syscall')
            if status >> 16 == 1 and (case['fault'] == 'fork-two' or case.get('fault_follow_child')):
                child = ctypes.c_ulong()
                ptrace(0x4201, 0, ctypes.addressof(child))
                ptrace(17 if case.get('fault_follow_child') else 7)
                pid = child.value
                followed_children += 1
                status = wait_stop()
                if not os.WIFSTOPPED(status):
                    raise AssertionError('fork child did not stop')
                continue
            if os.WSTOPSIG(status) != signal.SIGTRAP | 0x80:
                continue
            info = ctypes.create_string_buffer(128)
            ptrace(0x420e, ctypes.sizeof(info), ctypes.addressof(info))
            operation = info.raw[0]
            if operation == 1:
                number = struct.unpack_from('=Q', info.raw, 24)[0]
                args = struct.unpack_from('=6Q', info.raw, 32)
                try:
                    executable = os.readlink(f'/proc/{pid}/exe')
                except FileNotFoundError:
                    continue
                if not executable.endswith('/dnsmasq' + ('-rs' if side == 'rust' else '')):
                    continue
                root_path = False
                if number == 49:
                    # Both exact callers pass the literal "/". The low two
                    # bytes distinguish it from any other chdir target.
                    root_path = ptrace(2, args[0]) & 0xffff == ord('/')
                selected_pipe = startup_pipe.enter(number, args, root_path)
                if number == 198 and args[0] == 1:
                    socket_pending = args[1] & 0xf
                target = ''
                if number in [57, 55, 64, 66]:
                    try:
                        target = os.readlink(f'/proc/{pid}/fd/{args[0]}')
                    except FileNotFoundError:
                        pass
                match = number == case['fault_number'] or (number == 66 and case['fault_number'] == 64)
                if case['fault'] == 'fork-two':
                    match &= pid != process.pid
                if case.get('fault_follow_child'):
                    match &= followed_children == case.get('fault_follow_depth', 1)
                if case['fault'] == 'keepcaps':
                    match &= keepcaps_enable(args)
                elif case['fault'] == 'error-pipe':
                    match &= selected_pipe
                elif case['fault'] == 'error-pipe-flags':
                    match &= args[0] == startup_pipe.writer and args[1] == 4
                elif case['fault'] == 'error-frame-interrupt':
                    match &= args[0] == startup_pipe.writer
                elif case['fault'] in ['pid-write', 'pid-close', 'pid-chown', 'pid-short-write']:
                    match &= target.endswith('/m2/logging/daemon.pid')
                elif case.get('fault_target') == 'socket-open':
                    # Rust's optional UBus probe also opens AF_UNIX datagram
                    # sockets. Only the logger uses its explicit nonblocking
                    # owner socket; C log_start uses the plain datagram type.
                    match &= args[0] == 1 and args[1] == (2 if side == 'c' else 2 | 0x800 | 0x80000)
                elif case.get('fault_target') == 'stderr-dup':
                    match &= args[0] == 2
                elif case.get('fault_target') in ['socket-write', 'socket-connect']:
                    match &= args[0] == logging_socket
                elif case.get('fault_target') == 'stream-write':
                    match &= args[0] == logging_socket and logging_socket_type == 1
                elif case['fault'].startswith('log-'):
                    match &= target.endswith(case.get('file') or '/m2/logging/daemon.log')
                if not match:
                    continue
                pending = {'number': number, 'args': list(args), 'target': target}
                if case['fault'] == 'syslog-short-write':
                    value = regs()
                    value.x[2] = 3
                    regs(True, value)
                elif case['fault'] == 'pid-short-write':
                    if number == 66:
                        pending['iov_length'] = ptrace(2, args[1] + 8) & ((1 << 64) - 1)
                        ptrace(5, args[1] + 8, 1)
                    else:
                        value = regs()
                        value.x[2] = 1
                        regs(True, value)
                elif case['fault'] != 'pid-close':
                    skipped = ctypes.c_int(-1)
                    vec = Iovec(ctypes.addressof(skipped), ctypes.sizeof(skipped))
                    ptrace(0x4205, 0x404, ctypes.addressof(vec))
            elif operation == 2:
                result = struct.unpack_from('=q', info.raw, 24)[0]
                if startup_pipe.exit(result) and pending is None:
                    word = ptrace(2, startup_pipe.pointer) & ((1 << 64) - 1)
                    startup_pipe.bind_fds(word & 0xffffffff, word >> 32)
                if socket_pending and pending is None:
                    logging_socket = result
                    logging_socket_type = socket_pending
                    socket_pending = 0
                if pending is None:
                    continue
                if 'iov_length' in pending:
                    ptrace(5, pending['args'][1] + 8, pending['iov_length'])
                if case['fault_errno']:
                    value = regs()
                    value.x[0] = (-case['fault_errno']) & ((1 << 64) - 1)
                    regs(True, value)
                report['events'].append(dict(pending, actual_result=result,
                    injected_result=-case['fault_errno'] if case['fault_errno'] else result, injected_pid=pid))
                report['injected'] = True
                ptrace(17)
                if case['fault'] == 'fork-two':
                    # The original parent remains traced while reading its
                    # startup channel. Reap/detach its SIGCHLD delivery stop
                    # before Popen sees it as a terminal process status.
                    pid = process.pid
                    status = wait_stop()
                    if os.WIFSTOPPED(status):
                        ptrace(17)
                    else:
                        process.returncode = os.waitstatus_to_exitcode(status)
                attached = False
                return process
        raise AssertionError('startup syscall budget exceeded')
    finally:
        if attached:
            try:
                os.kill(pid, signal.SIGSTOP)
                os.waitpid(pid, 0)
                ptrace(17, 0, signal.SIGKILL)
                process.wait(1)
            except (OSError, ChildProcessError):
                pass
        save(report_path, report)


def run_daemon(root, side, case, out):
    out.mkdir()
    folder = image_path(root, '/m2/logging')
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(mode=0o777)
    folder.chmod(0o777)
    (folder / 'config').write_bytes(bytes.fromhex(case['config_bytes']) if 'config_bytes' in case else case.get('config', '').encode())
    if case.get('root_permissions'):
        (folder / 'private-root').mkdir(mode=0o700)
    if case.get('helper_script'):
        script = folder / 'script'
        script.write_text('#!/bin/sh\nexit 0\n')
        script.chmod(0o755)
    debug = '-d' in case['mode']
    pid_path = root / case['pidfile'].lstrip('/') if case.get('overlong_pid') else image_path(
        root, case['pidfile'] if case['pidfile'].startswith('/') else
        ('/m2/logging/' if debug else '/') + case['pidfile'].removeprefix('./'))
    if not case.get('overlong_pid'):
        pid_path.unlink(missing_ok=True)
    if case.get('sentinel_pid'):
        pid_path.write_text('sentinel\n')
    if case.get('pid_symlink'):
        (folder / 'pid-target').write_text('must survive\n')
        pid_path.symlink_to('/m2/logging/pid-target')
    log_path = image_path(root, case['file']) if case.get('file') else None
    if log_path:
        log_path.unlink(missing_ok=True)
    receiver = Receiver(root, case.get('receiver'))
    executable = '/usr/sbin/dnsmasq' + ('-rs' if side == 'rust' else '')
    argv = ['-C', '/m2/logging/config', *[arg for arg in BASE if arg not in ['--pid-file=', '--group=root']],
            '--group=' + case.get('group', 'root'),
            '--user=' + case.get('user', 'root'), '--pid-file=' + case['pidfile'], *case['mode'], *case['argv']]
    full = command(root, '/bin/sh', '-c', 'cd /m2/logging && exec "$@"', 'logging', executable, *argv)
    if case.get('launcher_uid') is not None:
        if full[0] != 'chroot':
            raise AssertionError('nonroot launcher requires exact chroot command')
        full.insert(1, '--userspec=' + str(case['launcher_uid']) + ':0')
    save(out / 'fixture.json', case)
    save(out / 'command.json', full)
    observed = {'ready': False, 'exit': None, 'forced': False, 'syslog': [], 'files': {},
                'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': '', 'process': {},
                'pid_written': False, 'pid_after_exit': False, 'live_processes': []}
    trace = {'command': full, 'samples': [], 'reaped': {}}
    service_pid = None
    start = time.monotonic()
    def drop_chown():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(24, 0, 0, 0, 0) != 0:  # PR_CAPBSET_DROP, CAP_CHOWN
            raise OSError(ctypes.get_errno(), 'drop CAP_CHOWN in tracee bounding set')
    with (out / 'stdout').open('wb') as stdout, (out / 'stderr').open('wb') as stderr:
        process = traced_startup(full, case, side, stdout, stderr, out / 'fault.json') if case.get('fault') else subprocess.Popen(
            full, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            env={**os.environ, 'LC_ALL': 'C', 'TZ': 'UTC'}, start_new_session=True,
            preexec_fn=drop_chown if case.get('drop_chown') else None)
        try:
            deadline = start + 3
            while time.monotonic() < deadline:
                receiver.drain()
                parent_exit = process.poll()
                if case.get('daemonized'):
                    try:
                        service_pid = int(pid_path.read_text().strip())
                    except (OSError, ValueError):
                        pass
                else:
                    service_pid = process.pid
                if service_pid:
                    state = proc_state(service_pid, root)
                    if state and state['state'] != 'Z':
                        try:
                            answer, raw = exchange('ready.logging')
                            if [row['data'] for row in answer['records']] != ['192.0.2.1']:
                                raise AssertionError('wrong daemon readiness answer')
                            trace['dns'] = [raw]
                            trace['identity'] = process_identity(root, service_pid)
                            if trace['identity']['sha256'] != sha256(image_path(root, executable)):
                                raise AssertionError('wrong detached daemon ELF')
                            # The readiness request may wait while startup
                            # changes cwd/stdio. Record the state after its
                            # response, rather than the earlier liveness probe.
                            state = proc_state(service_pid, root)
                            if not state or state['state'] == 'Z':
                                raise ProcessLookupError(service_pid)
                            observed['ready'] = True
                            trace['samples'].append(state)
                            observed['process'] = {'is_original': service_pid == process.pid,
                                'session_leader': state['sid'] == service_pid,
                                'group_leader': state['pgrp'] == service_pid,
                                'cwd': state['cwd'], 'stdio': state['stdio'],
                                'uid': state['uid'], 'gid': state['gid']}
                            if 'expected_helper_uid' in case:
                                helpers = []
                                helper_states = []
                                helper_fd_observations = []
                                for item in Path('/proc').iterdir():
                                    if item.name.isdigit() and int(item.name) != service_pid:
                                        child = proc_state(int(item.name), root)
                                        if child and child['state'] != 'Z' and child['ppid'] == service_pid:
                                            helpers.append(child['uid'][1])
                                            if case.get('helper_fds'):
                                                fd_observation = observe_helper_fds(child['pid'])
                                                helper_fd_observations.append(fd_observation)
                                                descriptors = fd_observation['descriptors']
                                                helper_states.append({'same_session': child['sid'] == state['sid'],
                                                    'same_group': child['pgrp'] == state['pgrp'],
                                                    'cwd': child['cwd'], 'stdio': child['stdio'],
                                                    'fd_count': len(descriptors),
                                                    'only_command_event_pipes': all(fd['target'].startswith('pipe:[') for fd in descriptors)})
                                observed['helper_uids'] = sorted(helpers)
                                if case.get('helper_fds'):
                                    observed['helper_states'] = helper_states
                                    observed['helper_fd_observations'] = helper_fd_observations
                            observed['pid_written'] = pid_path.exists() and pid_path.read_text() != 'sentinel\n'
                            if not case.get('daemonized') or parent_exit == 0:
                                break
                        except (socket.timeout, ConnectionRefusedError, FileNotFoundError, ProcessLookupError):
                            pass
                if parent_exit is not None and (not case.get('daemonized') or parent_exit != 0):
                    break
                time.sleep(.005)
            if observed['ready']:
                os.kill(service_pid, signal.SIGINT if case.get('signal') == 'int' else signal.SIGTERM)
            if process.poll() is None:
                process.wait(.8)
            observed['exit'] = process.returncode
            deadline = time.monotonic() + .8
            while time.monotonic() < deadline:
                receiver.drain()
                trace['reaped'].update(reap_children())
                # All PID>1 in this private PID namespace are test descendants.
                live = []
                for path in Path('/proc').iterdir():
                    if path.name.isdigit() and int(path.name) > 1:
                        state = proc_state(int(path.name), root)
                        if state:
                            live.append(state)
                if not live:
                    break
                time.sleep(.005)
            observed['live_processes'] = [row['pid'] for row in live]
        finally:
            if process.poll() is None:
                observed['forced'] = True
                process.kill()
                process.wait(1)
            for path in Path('/proc').iterdir():
                if path.name.isdigit() and int(path.name) > 1:
                    try:
                        state = proc_state(int(path.name), root)
                        if state and state['state'] != 'Z':
                            os.kill(int(path.name), signal.SIGKILL)
                            observed['forced'] = True
                    except ProcessLookupError:
                        pass
            trace['reaped'].update(reap_children())
            receiver.drain()
            receiver.close()
            trace['duration'] = time.monotonic() - start
            trace['stream_tail'] = receiver.pending.hex()
            save(out / 'trace.json', trace)
    observed['pid_after_exit'] = False if case.get('overlong_pid') else pid_path.exists()
    if case.get('pid_symlink'):
        observed['pid_symlink_target_preserved'] = (folder / 'pid-target').read_text() == 'must survive\n'
    if log_path and log_path.is_file():
        observed['files']['relative.log'] = log_path.read_bytes().hex()
        meta = log_path.stat()
        observed['file_metadata']['relative.log'] = [meta.st_mode & 0o777, meta.st_uid, meta.st_gid]
        (out / 'relative.log').write_bytes(log_path.read_bytes())
    observed['syslog'] = [row.hex() for row in receiver.raw]
    observed['stdout'] = (out / 'stdout').read_bytes().decode(errors='backslashreplace')
    observed['stderr'] = (out / 'stderr').read_bytes().decode(errors='backslashreplace')
    save(out / 'observed.json', observed)
    return observed


def fast_retry_witness_errors(row):
    witness = row.get('fast_retry_witness') or {}
    clients, upstream = witness.get('client_queries', []), witness.get('upstream', [])
    if len(clients) != 2 or len(upstream) != 2 or witness.get('upstream_requests') != 2 or witness.get('released_on_request') != 2:
        return ['missing exact client/initial-forward/first-retry inventory']
    first, cached = clients; initial, retry = upstream
    if (first.get('send_count') != 1 or cached.get('send_count') != 1
            or first.get('transport') != 'udp' or cached.get('transport') != 'udp-cached'
            or witness.get('deadline_seconds') != RETRY_BARRIER_SECONDS + .5
            or first.get('client') != ['127.0.0.1', 16505] or cached.get('client') != ['127.0.0.1', 16507]
            or bytes.fromhex(first['request'])[:2] != bytes.fromhex(first['reply'])[:2]
            or bytes.fromhex(cached['request'])[:2] != bytes.fromhex(cached['reply'])[:2]
            or initial['request'] != retry['request'] or initial['server'] != retry['server']
            or initial['peer'] != retry['peer'] or initial['transport'] != 'udp' or retry['transport'] != 'udp'
            or initial.get('reply') is None or retry.get('reply') is not None
            or retry.get('response_sent_monotonic_ns') is not None):
        return ['client resent or upstream retry wire/endpoint/response count changed']
    times = [first.get('sent_monotonic_ns'), initial.get('received_monotonic_ns'),
             retry.get('received_monotonic_ns'), initial.get('response_send_started_monotonic_ns'),
             initial.get('response_sent_monotonic_ns'), first.get('received_monotonic_ns'),
             cached.get('sent_monotonic_ns'), cached.get('received_monotonic_ns')]
    if any(type(value) is not int or value <= 0 for value in times): return ['missing actual monotonic timestamps']
    sent, received, retried, reply_started, reply_completed, answered, cache_sent, cache_answered = times
    if (not sent <= received <= retried <= reply_started <= reply_completed
            or not reply_started <= answered <= cache_sent <= cache_answered
            or retried - received > RETRY_BARRIER_SECONDS * 1_000_000_000
            or cache_answered - sent > (RETRY_BARRIER_SECONDS + .5) * 1_000_000_000):
        return ['reply preceded actual retry or transaction exceeded its bounded deadline']
    return []


def query_phase_errors(row, case):
    phase = row.get('query_phase') or {}
    intervals = phase.get('intervals', [])
    expected = [(name, kind, transport) for transport in ['udp', 'tcp'] for name, kind in query_sequence(case)]
    expected.append(('ready.logging', 1, 'udp-after-tcp'))
    if [(item.get('name'), item.get('type'), item.get('transport')) for item in intervals] != expected:
        return ['missing exact UDP seed/read and TCP read interval inventory']
    aligned = phase.get('aligned_at', {})
    clocks = [aligned] + [item[edge] for item in intervals for edge in ['started', 'finished']]
    if any(type(clock.get(key)) is not int or clock[key] <= 0 for clock in clocks for key in ['wall_ns', 'monotonic_ns']):
        return ['missing actual wall/monotonic observation clocks']
    epoch = phase.get('epoch')
    if (not 190_000_000 <= aligned['wall_ns'] % 1_000_000_000 <= 210_000_000
            or any(clock['wall_ns'] // 1_000_000_000 != epoch for clock in clocks)
            or [clock['monotonic_ns'] for clock in clocks] != sorted(clock['monotonic_ns'] for clock in clocks)
            or [clock['wall_ns'] for clock in clocks] != sorted(clock['wall_ns'] for clock in clocks)):
        return ['cache seed/read sequence crossed its real integer-second phase']
    return []


def compare(reference, candidate, case, reference_only=False):
    failures = []
    expected_ready = case.get('expect_ready', case['kind'] == 'run' and case.get('exit', 0) == 0)
    for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
        expectations = [('exit', case.get('exit', 0)), ('ready', expected_ready), ('forced', False)]
        if case.get('blocked_never_release'):
            waiting_for_reader = side == 'rust' or case['blocked_kind'] == 'debug-echo-full'
            expectations = [('exit', -9 if waiting_for_reader else 5),
                            ('ready', side == 'rust'), ('forced', waiting_for_reader)]
        for field, expected in expectations:
            if row[field] != expected:
                failures.append({'side': side, 'field': field, 'expected': expected, 'actual': row[field]})
    if 'expected_metadata' in case and reference['file_metadata'].get(case['file']) != case['expected_metadata']:
        failures.append({'kind': 'C-file-metadata', 'actual': reference['file_metadata']})
    if case.get('tcp_rotate'):
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            old = bytes.fromhex(row['files'].get('daemon.old', '')).decode(errors='backslashreplace')
            current = bytes.fromhex(row['files'].get('daemon.log', '')).decode(errors='backslashreplace')
            for endpoint in ['127.0.0.2#15955', '127.0.0.3#15956']:
                message = 'TCP connection failed to ' + endpoint
                if old.count(message) != 1 or message in current:
                    failures.append({'kind': 'accepted-TCP-pins-log-destination', 'side': side,
                                     'endpoint': endpoint, 'old_count': old.count(message),
                                     'new_count': current.count(message)})
    if case.get('sink_edge'):
        wanted = {'same_fds': True} if case['sink_edge'] in ['preserve', 'debug-fd'] else {
            'old_fd_closed': True, 'replacement_metadata': [0o604, 0, 0]}
        if case['sink_edge'] == 'debug-fd':
            wanted['stderr_copies'] = 1
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            if row.get('sink_edge') != wanted:
                failures.append({'kind': 'sink-reopen-source-control', 'side': side,
                                 'expected': wanted, 'actual': row.get('sink_edge')})
    if case.get('scope') == 'daemon':
        if reference['live_processes']:
            failures.append({'kind': 'C-daemon-descendants', 'actual': reference['live_processes']})
        if reference['ready']:
            daemonized = case.get('daemonized', False)
            expected = {'is_original': not daemonized, 'session_leader': not daemonized,
                        'group_leader': not daemonized, 'cwd': '/m2/logging' if '-d' in case['mode'] else '/',
                        'stdio': ['null', 'capture', 'capture'] if '-d' in case['mode'] else ['null'] * 3,
                        'uid': [case.get('expected_uid', 0)] * 4, 'gid': [0] * 4}
            if reference['process'] != expected:
                failures.append({'kind': 'C-daemon-process-state', 'expected': expected, 'actual': reference['process']})
            if reference['pid_written'] != ('-d' not in case['mode'] and not case.get('ignore_pid_failure')):
                failures.append({'kind': 'C-daemon-PID-write', 'actual': reference['pid_written']})
            if reference['pid_after_exit'] != (case.get('signal') == 'int'):
                failures.append({'kind': 'C-daemon-PID-cleanup', 'actual': reference['pid_after_exit']})
    if 'expected_helper_uid' in case:
        expected = [] if case['expected_helper_uid'] is None else [case['expected_helper_uid']]
        if reference.get('helper_uids') != expected:
            failures.append({'kind': 'C-helper-identity-control', 'expected': expected,
                             'actual': reference.get('helper_uids')})
    if case.get('pid_symlink'):
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            if row.get('pid_symlink_target_preserved') is not True:
                failures.append({'kind': 'PID-symlink-target-control', 'side': side})
    if case.get('helper_fds'):
        debug = '-d' in case['mode']
        contract = case.get('helper_fd_contract', 'legacy')
        if contract not in ['legacy', 'fork', 'selfexec']:
            raise ValueError('unknown helper FD contract')
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            copies = 2 if contract == 'selfexec' and side == 'rust' else 1
            wanted = [{'same_session': True, 'same_group': True, 'cwd': '/m2/logging' if debug else '/',
                       'stdio': ['null', 'capture', 'capture'] if debug else ['null'] * 3,
                       'fd_count': 2 * copies, 'only_command_event_pipes': True}]
            if row.get('helper_states') != wanted:
                failures.append({'kind': 'helper-startup-owned-FD-control', 'side': side,
                                 'expected': wanted, 'actual': row.get('helper_states')})
            if contract != 'legacy':
                failures.extend({'kind': 'helper-startup-FD-structure', 'side': side,
                                 'contract': contract, 'error': error}
                                for error in helper_pipe_errors(row.get('helper_fd_observations'), copies))
    if 'facility' in case and expected_ready:
        if not reference['syslog'] and not case.get('allow_no_syslog'):
            failures.append({'kind': 'C-no-syslog-records'})
        for record in reference['syslog']:
            text = bytes.fromhex(record).decode()
            match = re.match(r'<(\d+)>', text)
            if not match or (int(match[1]) & ~7) != case['facility']:
                failures.append({'kind': 'C-PRI-facility', 'actual': text})
    if 'async_notice' in case:
        text = reference['stderr'] + ''.join(bytes.fromhex(value).decode() for value in reference['syslog'])
        text += ''.join(bytes.fromhex(value).decode() for value in reference['files'].values())
        limit = case['async_notice']
        notice = f'asynchronous logging enabled, queue limit is {limit} messages'
        if (limit > 0 and notice not in text) or (limit <= 0 and 'asynchronous logging enabled' in text):
            failures.append({'kind': 'C-async-notice', 'expected': limit, 'actual': text})
    if case.get('pause_receiver'):
        messages = [bytes.fromhex(value).decode() for value in reference['syslog']]
        overflow = [text for text in messages if 'overflow: ' in text]
        if len(overflow) != 1 or not re.search(r'overflow: [1-9][0-9]* log entries lost$', overflow[0]):
            failures.append({'kind': 'C-async-overflow', 'actual': messages})
    if case.get('late_receiver'):
        messages = [bytes.fromhex(value).decode() for value in reference['syslog']]
        counts = [int(match[1]) for text in messages if (match := re.search(r'overflow: ([0-9]+) log entries lost$', text))]
        if case.get('queued_tcp'):
            if (counts != [3, 4]
                or sum('TCP connection failed' in text for text in messages) != 1
                or sum('started, version' in text for text in messages) != 1
                or sum('compile time options' in text for text in messages) != 1
                or any('exiting on receipt' in text for text in messages)
                or not messages or 'TCP connection failed' not in messages[0]):
                failures.append({'kind': 'C-TCP-inherited-queue-PID-guard', 'counts': counts, 'actual': messages})
        elif len(counts) != 2 or not all(value > 0 for value in counts):
            failures.append({'kind': 'C-async-repeated-overflow-reset', 'counts': counts, 'actual': messages})
    if case.get('tftp_probes'):
        text = reference['stderr'] + ''.join(bytes.fromhex(value).decode() for value in reference['syslog'])
        text += ''.join(bytes.fromhex(value).decode() for value in reference['files'].values())
        variant = case['tftp_probes']
        required = ['sent /m2/logging/public to 127.0.0.1'] if variant == 'script' else [
            'unable to get free port for TFTP'] if variant == 'port-exhausted' else [
            'timeout sending /m2/logging/public to 127.0.0.1'] if variant == 'timeout' else [
            'sent /m2/logging/public to 127.0.0.1',
            'cannot access /m2/logging/private: Permission denied',
            'cannot read /m2/logging/directory: Is a directory',
            'unsupported request from 127.0.0.1', 'unsupported write request from 127.0.0.1',
            'error 3 clientfailed received from 127.0.0.1',
            'failed sending /m2/logging/public to 127.0.0.1']
        if variant == 'requests':
            missing = 'file /m2/logging/missing not found for 127.0.0.1'
            if case['quiet'] and missing in text:
                failures.append({'kind': 'C-quiet-TFTP-not-found', 'actual': text})
            if not case['quiet']:
                required.append(missing)
        for message in required:
            if message not in text:
                failures.append({'kind': 'C-TFTP-log-producer', 'missing': message, 'actual': text})
    if case.get('script_probes'):
        text = reference['stderr'] + ''.join(bytes.fromhex(value).decode() + '\n' for value in reference['syslog'])
        text += ''.join(bytes.fromhex(value).decode() for value in reference['files'].values())
        if case['script_probes'] == 'inheritance':
            for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
                inherited = row['stdout'] + row['stderr']
                mask = re.search(r'inherited ignored ([0-9a-fA-F]+)', inherited)
                if 'inherited umask 0022\n' not in inherited or not mask or int(mask[1], 16) & 0x7002 != 0x7002:
                    failures.append({'kind': 'helper-exec-signal-umask-control', 'side': side, 'actual': inherited})
            required = []
        else:
            required = ['script process killed by signal 10'] if case['script_probes'] == 'signal' else [
            'failed to execute /m2/logging/script: No such file or directory'] if case['script_probes'] == 'exec' else [
            'dnsmasq-script[', ': one\n', ': \n', ': nul\n', ': tail\n', 'script process exited with status 7']
        for message in required:
            if message not in text:
                failures.append({'kind': 'C-script-log-producer', 'missing': message, 'actual': text})
        if case['script_probes'] == 'output':
            records = [bytes.fromhex(value) for value in reference['syslog']]
            records += [line + b'\n' for value in reference['files'].values()
                        for line in bytes.fromhex(value).splitlines()]
            if not records:
                records = [line + b'\n' for line in reference['stderr'].encode().splitlines()]
            long = [record for record in records if b': xxxxxxxxxxxxxxxx' in record]
            if len(long) != 1 or len(long[0]) != (1023 if reference['syslog'] else 1024):
                failures.append({'kind': 'C-script-max-message', 'lengths': [len(value) for value in long]})
            if not reference_only:
                actual = [bytes.fromhex(value) for value in candidate['syslog']]
                actual += [line + b'\n' for value in candidate['files'].values()
                           for line in bytes.fromhex(value).splitlines()]
                if not actual:
                    actual = [line + b'\n' for line in candidate['stderr'].encode().splitlines()]
                long = [record for record in actual if b': xxxxxxxxxxxxxxxx' in record]
                if len(long) != 1 or len(long[0]) != (1023 if candidate['syslog'] else 1024):
                    failures.append({'kind': 'Rust-script-max-message', 'lengths': [len(value) for value in long]})
    if case.get('scope') == 'root-access':
        prefix = bytes.fromhex(case['root_prefix']).decode(errors='backslashreplace')
        text = reference['stderr']
        variant = case['root_variant']
        if case['id'] == 'debug-echo-overlong-tftp-root':
            for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
                warning = 'dnsmasq-tftp: warning: ' + prefix + ' inaccessible\n'
                signon = 'dnsmasq-tftp: TFTP root is ' + prefix + '  \n'
                if warning not in row['stderr'] or signon not in row['stderr']:
                    failures.append({'kind': 'uncapped-debug-echo-required', 'side': side})
                primary = [line + b'\n' for value in row['files'].values()
                           for line in bytes.fromhex(value).splitlines()
                           if b'TFTP root is ' in line or b': warning: /m2/logging/' in line]
                if len(primary) != 2 or any(len(record) != 1024 for record in primary):
                    failures.append({'kind': 'primary-record-cap-required', 'side': side,
                                     'lengths': [len(record) for record in primary]})
        if variant == 'unused-root':
            if any(message in text for message in ['-tftp[', 'TFTP root is ', 'TFTP enabled', 'inaccessible']):
                failures.append({'kind': 'C-unused-TFTP-root', 'actual': text})
        elif variant in ['empty-global', 'permission-debug']:
            if 'inaccessible' in text or 'FAILED to start up' in text:
                failures.append({'kind': 'C-null-global-or-debug-access', 'actual': text})
            if variant == 'empty-global' and 'TFTP enabled' not in text:
                failures.append({'kind': 'C-null-global-sign-on', 'actual': text})
        elif case['root_no_fail']:
            interface = variant.startswith('interface-') or variant.startswith('empty-interface-')
            warning = ('warning: TFTP directory ' if interface else 'warning: ') + ('(null)' if not prefix else prefix) + ' inaccessible'
            if warning not in text:
                failures.append({'kind': 'C-TFTP-root-warning', 'missing': warning, 'actual': text})
            if variant.startswith('both-') and 'warning: TFTP directory /m2/logging/missing-interface inaccessible' not in text:
                failures.append({'kind': 'C-TFTP-interface-root-warning', 'actual': text})
            signon = 'TFTP enabled' if interface else 'TFTP root is '
            if text.find(signon) < 0 or text.find(signon) >= text.find(warning):
                failures.append({'kind': 'C-TFTP-root-warning-order', 'actual': text})
        else:
            error = 'Bad address' if variant.startswith('empty-interface-') else 'Permission denied' if case.get('root_permissions') else 'No such file or directory'
            message = 'TFTP directory ' + (prefix or error) + ' inaccessible: ' + error
            # Default parent records its second critical line in syslog;
            # foreground/debug '-' retain both records on inherited stderr.
            combined = text + ''.join(bytes.fromhex(value).decode(errors='backslashreplace') for value in reference['syslog'])
            if message not in text or 'FAILED to start up' not in combined:
                failures.append({'kind': 'C-TFTP-root-fatal', 'missing': message, 'actual': combined})
    if case.get('debug_probes'):
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            text = row['stderr']
            if not case['debug_enabled']:
                if 'dnsmasq-debug[' in text:
                    failures.append({'kind': 'debug-disabled-producer', 'side': side, 'actual': text})
                continue
            variant = case['debug_probes']
            required = ['TCP connection failed to ' + case['debug_server'] + '#15955'] if variant == 'tcp' else [
                'listening on 192.0.2.101 port 15353'] if variant == 'explicit' else [
                f'listening on m5log(#{row["interface_index"]}): 192.0.2.100 port 15353',
                f'stopped listening on m5log(#{row["interface_index"]}): 192.0.2.100 port 15353']
            for message in required:
                if message not in text:
                    failures.append({'kind': 'debug-source-producer', 'side': side, 'missing': message, 'actual': text})
    if case['kind'] == 'cli':
        expected = ('Known DHCP options:\n' if case['argv'] == ['--help', 'dhcp'] else
                    'Dnsmasq version 2.93  ' if case['argv'] == ['--version'] else
                    'Usage: dnsmasq [options]\n')
        if not reference['stdout'].startswith(expected):
            failures.append({'kind': 'C-CLI-dispatch', 'expected_prefix': expected,
                             'actual': reference['stdout']})
    if case.get('chaos') and any(record.get('section') == 'answer'
                                for answer in reference['dns'] if answer['name'] != 'kept.logging'
                                for record in answer['response']['records']):
        failures.append({'kind': 'C-no-ID-generated-answer', 'actual': reference['dns']})
    if case.get('dhcp_probes'):
        messages = [line.split(': ', 1)[-1] for line in reference['stderr'].splitlines() if 'DHCP' in line and 'range' not in line]
        quiet, detail = case['quiet_dhcp'], case['detail_dhcp']
        required = ['DHCPREQUEST(lo) 127.0.0.99 02:00:00:00:00:aa ',
                    'DHCPRELEASE(lo) 127.0.0.10 02:00:00:00:00:aa unknown lease'] if quiet and not detail else [
                    'DHCPDISCOVER(lo) 02:00:00:00:00:aa ',
                    'DHCPOFFER(lo) 127.0.0.10 02:00:00:00:00:aa ',
                    'DHCPACK(lo) 127.0.0.10 02:00:00:00:00:aa m5-client',
                    'DHCPINFORM(lo) 127.0.0.10 02:00:00:00:00:aa ',
                    'DHCPRELEASE(lo) 127.0.0.10 02:00:00:00:00:aa unknown lease']
        if quiet and not detail: required = required[1:]  # only error-pointer notices survive.
        for item in required:
            if not any(item in message for message in messages): failures.append({'kind': 'C-DHCP-packet-producer', 'missing': item, 'actual': messages})
        for item in ['DHCPDECLINE(lo) 127.0.0.10 02:00:00:00:00:aa client declines', 'disabling DHCP static address 127.0.0.10 for 10m']:
            if item not in reference['stderr']: failures.append({'kind': 'C-DHCP-decline-producer', 'missing': item})
        ignored = 'DHCPDISCOVER(lo) 02:00:00:00:00:bb ignored'
        if quiet and any(ignored in message for message in messages): failures.append({'kind': 'C-DHCP-quiet-ignored-discover', 'actual': messages})
        if detail and not all(re.match(r'^[0-9]+ DHCP', message) for message in messages if re.match(r'^([0-9]+ )?DHCP(?:DISCOVER|OFFER|REQUEST|ACK|NAK|INFORM|RELEASE)\(', message)):
            failures.append({'kind': 'C-DHCP-detail-xid', 'actual': messages})
    if case.get('quiet_delay_probe') and 'reply delay:' in reference['stderr']:
        failures.append({'kind': 'C-quiet-DHCP-detail-independent-delay', 'actual': reference['stderr']})
    if case.get('dhcp_query_origin'):
        for message in ['DHCP m5-client is 127.0.0.10', 'DHCP 127.0.0.10 is m5-client']:
            if message not in reference['stderr']: failures.append({'kind': 'C-query-DHCP-origin', 'missing': message})
    if case.get('query_probes'):
        mode, text = case['query_mode'], reference['stderr']
        if mode in ['auth', 'only_failed']:
            if 'query[' in text:
                failures.append({'kind': 'C-query-log-filter', 'mode': mode, 'actual': text})
        elif 'query[A] ready.logging from 127.0.0.1' not in text:
            failures.append({'kind': 'C-query-log-missing', 'mode': mode, 'actual': text})
        if mode == 'proto' and not all(word in text for word in ['UDP ', 'TCP ']):
            failures.append({'kind': 'C-query-protocol-prefix', 'actual': text})
        if mode == 'only_failed' and 'is NXDOMAIN' not in text:
            failures.append({'kind': 'C-query-only-failed-negative', 'actual': text})
        transaction = case.get('query_transaction_probe')
        if transaction:
            messages = [line.split(': ', 1)[-1] for line in text.splitlines() if 'delay.forward.test' in line or 'query is duplicate' in line]
            if transaction == 'coalesce':
                required = ['UDP 104 127.0.0.1/16505 query[A] delay.forward.test',
                            'UDP 105 127.0.0.1/16506 query[A] delay.forward.test',
                            'UDP 104 127.0.0.1/16505 reply delay.forward.test is 192.0.2.7',
                            'UDP 105 127.0.0.1/16506 reply query is duplicate']
            elif transaction == 'clientretry':
                required = ['UDP 104 127.0.0.1/16505 query[A] delay.forward.test',
                            'UDP 105 127.0.0.1/16505 query[A] delay.forward.test',
                            'UDP 105 127.0.0.1/16505 reply delay.forward.test is 192.0.2.7']
            else:
                required = ['UDP 104 forwarded delay.forward.test to 127.0.0.2#15957',
                            'UDP 104 127.0.0.1/16505 reply delay.forward.test is 192.0.2.7']
            for item in required:
                if not any(message.startswith(item) for message in messages):
                    failures.append({'kind': 'C-query-transaction-producer', 'missing': item, 'actual': messages})
        for message in case.get('query_required_messages', []):
            if message not in text:
                failures.append({'kind': 'C-query-source-producer', 'missing': message})
    if case.get('blocked_kind') == 'fifo-peer-disconnect':
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            if row.get('pre_release_ready') is not True or row.get('fifo_fds_after_failure') != (1 if side == 'c' else 0):
                failures.append({'kind': 'FIFO-disconnect-FD-source-control', 'side': side,
                                 'ready': row.get('pre_release_ready'), 'fifo_fds': row.get('fifo_fds_after_failure')})
            messages = [normalized(bytes.fromhex(value).decode(errors='backslashreplace')) for value in row['syslog']]
            endings = ['log failed: Broken pipe\n', 'sent /m2/logging/public to 127.0.0.1\n',
                       'exiting on receipt of SIGTERM\n']
            if len(messages) != len(endings) or any(not msg.endswith(': ' + end) or 'dnsmasq[<PID>]: ' not in msg
                                                    for msg, end in zip(messages, endings)):
                failures.append({'kind': 'FIFO-disconnect-fallback-producer', 'side': side, 'actual': messages})
    elif case.get('blocked_kind'):
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            if row.get('pre_release_ready') != (side == 'rust'):
                failures.append({'kind': 'blocked-sink-single-owner-health', 'side': side,
                                 'actual': row.get('pre_release_ready')})
        # This is the explicit nonblocking policy boundary, not an exact log
        # equivalence claim: validate each side's records before classifying.
        def messages(row):
            text = row['stderr'] if case['blocked_kind'] == 'stderr-full' else bytes.fromhex(row['files'].get('daemon.log', '')).decode(errors='backslashreplace')
            return [line.split(': ', 1)[1] for line in normalized(text).splitlines() if ': ' in line]
        original, replacement = messages(reference), messages(candidate)
        wanted_c = ['started, version 2.93 cachesize 150', 'compile time options: ',
                    'warning: no upstream servers configured', 'cleared cache', 'cleared cache',
                    'exiting on receipt of SIGTERM']
        if case.get('blocked_never_release'):
            wanted_c = []
        def matches(actual, wanted):
            return len(actual) == len(wanted) and all(a.startswith(b) if b.endswith(': ') else a == b
                                                     for a, b in zip(actual, wanted))
        if not matches(original, wanted_c):
            failures.append({'kind': 'C-blocked-sink-record-contract', 'actual': original})
        if case.get('blocked_never_release'):
            wanted_rust = ['started, version 2.93 cachesize 150', 'compile time options: ',
                          'warning: no upstream servers configured', 'cleared cache',
                          'exiting on receipt of SIGTERM'] if case['blocked_kind'] == 'debug-echo-full' else []
        else:
            wanted_rust = wanted_c if case['blocked_kind'] == 'debug-echo-full' else [
                wanted_c[0], 'overflow: 3 log entries lost', 'cleared cache', 'exiting on receipt of SIGTERM']
        if case['blocked_kind'].startswith('fifo-'):
            for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
                ownership_blocked = side == 'c' and case.get('blocked_never_release') and case['blocked_kind'] == 'fifo-no-reader'
                metadata = [0o640, 0, 0] if ownership_blocked else [0o660, 65534, 0]
                if row['file_metadata'].get('daemon.log') != metadata:
                    failures.append({'kind': 'blocked-fifo-owner-control', 'side': side,
                                     'expected': metadata, 'actual': row['file_metadata']})
        if not reference_only and not matches(replacement, wanted_rust):
            failures.append({'kind': 'Rust-blocked-sink-record-contract', 'actual': replacement})
        if case['blocked_kind'] == 'debug-echo-full':
            for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
                echo = [line.split(': ', 1)[1] for line in row['stderr'].splitlines() if ': ' in line]
                if not matches(echo, wanted_c):
                    failures.append({'kind': 'blocked-debug-echo-record-contract', 'side': side, 'actual': echo})
    if reference_only:
        return failures
    left, right = copy.deepcopy(reference), copy.deepcopy(candidate)
    if case.get('helper_fds'):
        for row in [left, right]:
            # Absolute FD numbers/inodes stay in raw evidence. The default
            # comparison still requires the original exact two-FD state.
            row.pop('helper_fd_observations', None)
            if case.get('helper_fd_contract', 'legacy') != 'legacy':
                # Each side's complete state and explicit pipe topology were
                # checked above; only selfexec permits the disclosed 2 -> 4.
                row.pop('helper_states', None)
    if case.get('dhcp_probes'):
        for side, row in [('c', left), ('rust', right)]:
            try:
                normalize_dhcp_inform(row, case.get('detail_dhcp', False))
            except (AssertionError, KeyError, ValueError) as error:
                failures.append({'kind': 'INFORM-expiry-clock-or-log', 'side': side, 'error': str(error)})
        if failures:
            return failures
    if case['id'] == 'query-forward-ordinary':
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            failures.extend({'kind': 'actual-cache-seed-read-phase', 'side': side, 'error': error}
                            for error in query_phase_errors(row, case))
        left.pop('query_phase', None); right.pop('query_phase', None)
    if case.get('query_transaction_probe') == 'fastretry':
        for side, row in [('c', reference)] + ([] if reference_only else [('rust', candidate)]):
            failures.extend({'kind': 'actual-fast-retry-witness', 'side': side, 'error': error}
                            for error in fast_retry_witness_errors(row))
        # Each side's real events were checked above; absolute clock values
        # and the independently allocated upstream DNS IDs are retained raw.
        left.pop('fast_retry_witness', None); right.pop('fast_retry_witness', None)
    if case.get('blocked_kind') == 'fifo-peer-disconnect':
        for row in [left, right]:
            row.pop('fifo_fds_after_failure', None)
    elif case.get('blocked_kind'):
        for row in [left, right]:
            row.pop('pre_release_ready', None)
            row['files'] = {}
            row['stderr'] = ''
            if case.get('blocked_never_release'):
                for field in ['ready', 'exit', 'forced', 'file_metadata']:
                    row.pop(field, None)
    for row in [left, right]:
        if 'interface_index' in row:
            index = row['interface_index']
            # Indices increase between sequential namespace fixture creations.
            # The raw producer guard above verifies each implementation's own
            # actual index before this identity-only comparison normalization.
            row['stderr'] = row['stderr'].replace(f'm5log(#{index})', 'm5log(#<INDEX>)')
            row['interface_index'] = '<INDEX>'
        for stream in ['stdout', 'stderr']:
            row[stream] = normalized(row[stream])
        row['syslog'] = [normalized(bytes.fromhex(value).decode(errors='backslashreplace'))
                         for value in row['syslog']]
        row['files'] = {name: normalized(bytes.fromhex(value).decode(errors='backslashreplace'))
                        for name, value in row['files'].items()}
        if case.get('script_probes') == 'output':
            # Both raw record caps were checked above. Actual namespace PIDs
            # can have different decimal widths, leaving different counts of
            # this known 4096-byte x prefix after C's 1024-byte serialization.
            # Normalize only that uniform body; all other bytes stay compared.
            def clipped_identity(value):
                return re.sub(r'(dnsmasq-script\[<PID>\]: )x{900,}(?=\n|$)', r'\1<4096-x-prefix-truncated-at-record-cap>', value)
            row['stderr'] = clipped_identity(row['stderr'])
            row['syslog'] = [clipped_identity(value) for value in row['syslog']]
            row['files'] = {name: clipped_identity(value) for name, value in row['files'].items()}
    if case.get('chaos_notimp_uninitialised_ede'):
        # rfc1035.c:1838-1854 sets NOTIMP but leaves addr.log.ede unset.
        # Keep only the observed unknown suffix exception, with exact matching
        # CHAOS TXT question/response on both sides; every other byte compares.
        for transport in ['UDP', 'TCP']:
            def valid_chaos(row):
                return any(item.get('transport') == transport.lower()
                           and item.get('name') == 'version.bind'
                           and item.get('class') == 3 and item.get('opcode') == 0
                           and item['response']['questions'] == [['version.bind', 16, 3]]
                           and item['response']['flags'] & 15 == 4
                           and not item['response']['records'] for item in row['dns'])
            if valid_chaos(left) and valid_chaos(right):
                pattern = (r'(?m)^(dnsmasq\[<PID>\]: ' + transport +
                           r' [0-9]+ 127\.0\.0\.1/16510 config version\.bind is not implemented)'
                           r' \(EDE: unknown\)(?=\n|$)')
                left['stderr'] = re.sub(pattern, r'\1', left['stderr'])
    if case.get('argv') == ['--version']:
        first, separator, rest = left['stdout'].partition('\n')
        expected = first + RUST_VERSION_IDENTITY + separator + rest
        if right['stdout'] != expected:
            failures.append({'kind': 'Rust-version-identity-and-license', 'expected': expected,
                             'actual': right['stdout']})
        else:
            # This one disclosed first-line difference preserves the exact
            # compile-options/init interface and every GPL/warranty line.
            right['stdout'] = left['stdout']
    if case.get('identity_matrix') and len(left['dns']) == len(right['dns']):
        previous_edns = False
        for index, (expected, actual) in enumerate(zip(left['dns'], right['dns'])):
            if expected['transport'] == 'udp':
                previous_edns = False
            if expected != actual and case.get('reference_defect') and previous_edns:
                corrected = without_leaked_tcp_opt(expected)
                if corrected is not None and actual == corrected:
                    right['dns'][index] = expected
            previous_edns |= expected['transport'] == 'tcp' and expected['probe']['edns']
    for field in left:
        if left[field] != right[field]:
            failures.append({'field': field, 'expected': left[field], 'actual': right[field]})
    return failures


def without_leaked_tcp_opt(row):
    if row['transport'] != 'tcp' or row['probe']['edns']:
        return None
    additions = [record for record in row['response']['records'] if record['section'] == 'additional']
    if len(additions) != 1 or additions[0]['type'] != 41:
        return None
    wire = bytes.fromhex(row['reply_wire'])
    if int.from_bytes(wire[10:12], 'big') != 1:
        return None
    length = 11 + len(bytes.fromhex(additions[0]['data']))
    if wire[-length] != 0:
        return None
    corrected = copy.deepcopy(row)
    corrected_wire = wire[:10] + b'\0\0' + wire[12:-length]
    corrected['reply_wire'] = corrected_wire.hex()
    corrected['response'] = semantics(corrected_wire)
    return corrected


def controls():
    case = {'id': 'control', 'kind': 'run', 'exit': 0}
    row = {'ready': True, 'exit': 0, 'forced': False, 'syslog': [], 'files': {},
           'file_metadata': {}, 'dns': [], 'stdout': '', 'stderr': 'dnsmasq: value\n'}
    result = {}
    def inform_row(remaining, second, name=b'client'):
        packet = bytearray(240); packet[0] = 2
        packet[4:8] = (4611).to_bytes(4, 'big'); packet[236:240] = bytes.fromhex('63825363')
        packet += bytes([53, 1, 5, 51, 4]) + remaining.to_bytes(4, 'big')
        packet += bytes([12, len(name)]) + name + b'\xff'
        clock = inform_clock_witness('1600 aa 127.0.0.10 client *\n',
            {'kind': 8, 'ciaddr': '127.0.0.10'}, second * 10**9 + 100, second * 10**9 + 200)
        duration = '10m' if remaining == 600 else '9m59s'
        return {'dhcp': [{'label': 'inform', 'reply': packet.hex(), 'inform_clock': clock}],
            'stderr': 'dnsmasq-dhcp[1]: 4610 sent size:  4 option: 51 lease-time  10m\n'
                + 'dnsmasq-dhcp[1]: 4611 sent size:  4 option: 51 lease-time  ' + duration + '\n'}
    def normalized_inform(row):
        row = copy.deepcopy(row); normalize_dhcp_inform(row, True); return row
    c_inform, r_inform = inform_row(600, 1000), inform_row(599, 1001)
    result['INFORM-independent-clock-phases'] = normalized_inform(c_inform) == normalized_inform(r_inform)
    for label, bad in [('wrong-wire-time', inform_row(599, 1000)),
                       ('wrong-log-time', dict(r_inform, stderr=r_inform['stderr'].replace('9m59s', '10m')))]:
        try: normalized_inform(bad)
        except (AssertionError, KeyError, ValueError): result['INFORM-' + label] = True
        else: result['INFORM-' + label] = False
    result['INFORM-other-option-kept'] = normalized_inform(c_inform) != normalized_inform(inform_row(599, 1001, b'changed'))
    result['INFORM-fresh-ACK-time-kept'] = normalized_inform(c_inform) != normalized_inform(
        dict(r_inform, stderr=r_inform['stderr'].replace('4610 sent size:  4 option: 51 lease-time  10m',
            '4610 sent size:  4 option: 51 lease-time  9m59s')))
    assert all(value for key, value in result.items() if key.startswith('INFORM-'))
    quiet_case = {'id': 'quiet-control', 'kind': 'run', 'dhcp_probes': True, 'quiet_dhcp': True, 'detail_dhcp': False}
    quiet = dict(row, stderr='dnsmasq-dhcp[1]: DHCPRELEASE(lo) 127.0.0.10 02:00:00:00:00:aa unknown lease\n'
                              'dnsmasq-dhcp[1]: DHCPDECLINE(lo) 127.0.0.10 02:00:00:00:00:aa client declines\n'
                              'dnsmasq-dhcp[1]: disabling DHCP static address 127.0.0.10 for 10m\n')
    assert not compare(quiet, quiet, quiet_case)
    result['quiet-DHCP-success-leak'] = bool(compare(quiet, dict(quiet, stderr=quiet['stderr'] + 'dnsmasq-dhcp[1]: DHCPACK(lo) 127.0.0.10 02:00:00:00:00:aa client\n'), quiet_case))
    result['quiet-DHCP-error-hidden'] = bool(compare(quiet, dict(quiet, stderr=quiet['stderr'].replace('unknown lease', '')), quiet_case))
    result['quiet-DHCP-warning-hidden'] = bool(compare(quiet, dict(quiet, stderr=quiet['stderr'].replace('disabling DHCP static address 127.0.0.10 for 10m', '')), quiet_case))
    result['quiet-DHCP-ignored-discover-leak'] = bool(compare(quiet, dict(quiet, stderr=quiet['stderr'] + 'dnsmasq-dhcp[1]: DHCPDISCOVER(lo) 02:00:00:00:00:bb ignored\n'), quiet_case))
    assert all(value for key, value in result.items() if key.startswith('quiet-DHCP-'))
    chaos_case = {'id': 'chaos-control', 'kind': 'run', 'chaos_notimp_uninitialised_ede': True}
    chaos_dns = [{'transport': 'udp', 'name': 'version.bind', 'class': 3, 'opcode': 0,
                  'response': {'questions': [['version.bind', 16, 3]], 'flags': 0x8184, 'records': []}}]
    chaos_line = 'dnsmasq[1]: UDP 105 127.0.0.1/16510 config version.bind is not implemented'
    chaos = dict(row, dns=chaos_dns, stderr=chaos_line + ' (EDE: unknown)\n')
    clean_chaos = dict(chaos, stderr=chaos_line + '\n')
    assert not compare(chaos, clean_chaos, chaos_case)
    for name, old, new in [('ID', 'UDP 105', 'UDP 106'), ('name', 'version.bind', 'other.bind'),
                           ('RCODE', 'not implemented', 'REFUSED'), ('client', '/16510', '/16511')]:
        result['chaos-EDE-defect-' + name] = bool(compare(chaos, dict(clean_chaos, stderr=clean_chaos['stderr'].replace(old, new)), chaos_case))
    result['chaos-EDE-defect-other-EDE'] = bool(compare(dict(chaos, stderr=chaos['stderr'].replace('unknown', 'not ready')), clean_chaos, chaos_case))
    result['chaos-EDE-defect-order'] = bool(compare(dict(chaos, stderr=chaos['stderr'] + 'dnsmasq[1]: kept\n'), dict(clean_chaos, stderr='dnsmasq[1]: kept\n' + clean_chaos['stderr']), chaos_case))
    wrong_class = copy.deepcopy(chaos_dns); wrong_class[0]['class'] = 1
    result['chaos-EDE-defect-question-required'] = bool(compare(dict(chaos, dns=wrong_class), dict(clean_chaos, dns=wrong_class), chaos_case))
    wrong_rcode = copy.deepcopy(chaos_dns); wrong_rcode[0]['response']['flags'] = 0x8185
    result['chaos-EDE-defect-wire-RCODE-required'] = bool(compare(dict(chaos, dns=wrong_rcode), dict(clean_chaos, dns=wrong_rcode), chaos_case))
    result['chaos-EDE-defect-scenario-required'] = bool(compare(chaos, clean_chaos, case))
    assert all(value for key, value in result.items() if key.startswith('chaos-EDE-defect-'))
    for field, corrupt in [('exit', 3), ('ready', False), ('forced', True), ('stderr', 'dnsmasq: wrong\n'),
                           ('syslog', ['3c33303e77726f6e67']), ('files', {'daemon.log': '77726f6e67'}),
                           ('file_metadata', {'daemon.log': [0o600, 0, 0]}), ('dns', [{'name': 'wrong'}])]:
        changed = copy.deepcopy(row)
        changed[field] = corrupt
        result[field] = bool(compare(row, changed, case))
    if not all(result.values()):
        raise AssertionError('negative control bypass')
    wrong_help = dict(row, stdout='Usage: dnsmasq [options]\n', ready=False)
    result['help-argc-dispatch'] = bool(compare(wrong_help, wrong_help,
        {'id': 'help-control', 'kind': 'cli', 'argv': ['--help', 'dhcp']}, True))
    if not result['help-argc-dispatch']:
        raise AssertionError('help dispatch calibration bypass')
    version = dict(row, ready=False, stderr='', stdout='Dnsmasq version 2.93  Copyright (c) 2000-2026 Simon Kelley\nCompile time options: fixture\n\nThis software comes with ABSOLUTELY NO WARRANTY.\n')
    candidate = dict(version, stdout=version['stdout'].replace('Simon Kelley\n', 'Simon Kelley' + RUST_VERSION_IDENTITY + '\n'))
    version_case = {'id': 'version-control', 'kind': 'cli', 'argv': ['--version']}
    assert not compare(version, candidate, version_case)
    result['version-identity'] = bool(compare(version, version, version_case))
    corrupt = dict(candidate, stdout=candidate['stdout'].replace('NO WARRANTY', 'SOME WARRANTY'))
    result['version-license'] = bool(compare(version, corrupt, version_case))
    assert result['version-identity'] and result['version-license']
    frozen = {'options': {'example': {'qualification_ready': True,
              'required': [{'id': 'missing-map', 'required_scenarios': []}]}}}
    result['empty-required-map'] = not qualification(frozen, [], False)['example']['closed']
    frozen['options']['example']['required'][0]['required_scenarios'] = ['unexecuted']
    result['unexecuted-required-case'] = not qualification(frozen, [], False)['example']['closed']
    assert result['empty-required-map'] and result['unexecuted-required-case']
    debug_case = {'id': 'debug-control', 'kind': 'run', 'debug_probes': 'interface', 'debug_enabled': True}
    debug_row = dict(row, interface_index=2,
        stderr='dnsmasq-debug[1]: listening on m5log(#2): 192.0.2.100 port 15353\n'
               'dnsmasq-debug[1]: stopped listening on m5log(#2): 192.0.2.100 port 15353\n')
    assert not compare(debug_row, debug_row, debug_case)
    result['debug-actual-interface-index'] = bool(compare(debug_row, dict(debug_row, interface_index=3), debug_case))
    result['debug-unlisten-required'] = bool(compare(dict(debug_row, stderr=debug_row['stderr'].splitlines()[0]), debug_row, debug_case, True))
    result['debug-disabled-no-output'] = bool(compare(debug_row, debug_row, dict(debug_case, debug_enabled=False), True))
    assert all(result[name] for name in ['debug-actual-interface-index', 'debug-unlisten-required', 'debug-disabled-no-output'])
    def capped_script(pid, length=1024, poison=False):
        prefix = f'dnsmasq-script[{pid}]: '
        body = 'x' * (length - len(prefix) - 1)
        if poison:
            body = body[:-1] + 'y'
        return ('dnsmasq-script[1]: one\ndnsmasq-script[1]: \ndnsmasq-script[1]: nul\n'
                + prefix + body + '\n' + 'dnsmasq-script[1]: tail\ndnsmasq[1]: script process exited with status 7\n')
    capped_case = {'id': 'cap-control', 'kind': 'run', 'script_probes': 'output'}
    capped = dict(row, stderr=capped_script(99))
    assert not compare(capped, dict(capped, stderr=capped_script(100)), capped_case)
    for name, bad in [('record-cap-short', capped_script(100, 1023)),
                      ('record-cap-long', capped_script(100, 1025)),
                      ('record-cap-payload', capped_script(100, poison=True))]:
        result[name] = bool(compare(capped, dict(capped, stderr=bad), capped_case))
        assert result[name]
    copied_case = {'id': 'copied-control', 'kind': 'run', 'queued_tcp': True, 'late_receiver': True}
    copied_lines = ['TCP connection failed to 127.0.0.2#15955', 'overflow: 3 log entries lost',
                    'started, version 2.93 cachesize 150', 'compile time options: fixture', 'overflow: 4 log entries lost']
    copied = dict(row, stderr='', syslog=[('<31>Jan  1 00:00:00 dnsmasq[1]: ' + line).encode().hex() for line in copied_lines])
    assert not compare(copied, copied, copied_case)
    for name, corrupt in [('copied-parent-discard', [*copied_lines, copied_lines[2]]),
                          ('copied-overflow-missing', [line for line in copied_lines if 'overflow: 3' not in line]),
                          ('copied-overflow-duplicated', [*copied_lines, copied_lines[1]]),
                          ('copied-record-order', copied_lines[2:] + copied_lines[:2])]:
        changed = dict(copied, syslog=[('<31>Jan  1 00:00:00 dnsmasq[1]: ' + line).encode().hex() for line in corrupt])
        result[name] = bool(compare(changed, changed, copied_case, True))
        assert result[name]
    c_wire = bytes.fromhex('732585800001000100000001046b657074076c6f6767696e670000100001c00c0010000100000000000e0d6578706c696369742d7573657200002904d0000000000000')
    leaked = {'transport': 'tcp', 'probe': {'edns': False}, 'reply_wire': c_wire.hex(), 'response': semantics(c_wire)}
    corrected = without_leaked_tcp_opt(leaked)
    preceding = dict(leaked, probe={'edns': True})
    c = dict(row, dns=[preceding, leaked])
    rust = dict(row, dns=[preceding, corrected])
    defect_case = dict(case, identity_matrix=True, reference_defect='C TCP stale OPT')
    assert not compare(c, rust, defect_case)
    corrupt = copy.deepcopy(rust)
    changed_wire = bytes.fromhex(corrected['reply_wire'])
    changed_wire = changed_wire[:3] + bytes([changed_wire[3] | 5]) + changed_wire[4:]
    corrupt['dns'][1] = dict(corrected, reply_wire=changed_wire.hex(), response=semantics(changed_wire))
    result['reference-defect-RCODE-guard'] = bool(compare(c, corrupt, defect_case))
    result['reference-defect-needs-prior-EDNS'] = bool(compare(dict(row, dns=[leaked]), dict(row, dns=[corrected]), defect_case))
    result['reference-defect-never-removes-requested-OPT'] = bool(compare(dict(row, dns=[preceding]), dict(row, dns=[dict(corrected, probe={'edns': True})]), defect_case))
    assert all(result[key] for key in result if key.startswith('reference-defect-'))
    blocked_case = dict(case, blocked_kind='stderr-full')
    prefix = 'dnsmasq[1]: '
    c_messages = ['started, version 2.93 cachesize 150', 'compile time options: fixture',
                  'warning: no upstream servers configured', 'cleared cache', 'cleared cache',
                  'exiting on receipt of SIGTERM']
    rust_messages = [c_messages[0], 'overflow: 3 log entries lost', *c_messages[-2:]]
    blocked_c = dict(row, pre_release_ready=False, stderr=''.join(prefix + x + '\n' for x in c_messages))
    blocked_rust = dict(row, pre_release_ready=True, stderr=''.join(prefix + x + '\n' for x in rust_messages))
    assert not compare(blocked_c, blocked_rust, blocked_case)
    result['blocked-sink-health-required'] = bool(compare(blocked_c,
        dict(blocked_rust, pre_release_ready=False), blocked_case))
    result['blocked-sink-overflow-required'] = bool(compare(blocked_c,
        dict(blocked_rust, stderr=blocked_rust['stderr'].replace('overflow: 3', 'overflow: 2')), blocked_case))
    result['blocked-sink-record-order'] = bool(compare(
        dict(blocked_c, stderr=''.join(prefix + x + '\n' for x in reversed(c_messages))),
        blocked_rust, blocked_case))
    assert all(result[key] for key in result if key.startswith('blocked-sink-'))
    long_prefix = '/m2/logging/' + 'x' * 5000
    echo_case = dict(case, id='debug-echo-overlong-tftp-root', scope='root-access',
                     root_prefix=long_prefix.encode().hex(), root_variant='global-no-fail', root_no_fail=True)
    echo_text = 'dnsmasq-tftp: TFTP root is ' + long_prefix + '  \n'
    echo_text += 'dnsmasq-tftp: warning: ' + long_prefix + ' inaccessible\n'
    primary_lines = []
    for text in ['dnsmasq-tftp[1]: TFTP root is ' + long_prefix,
                 'dnsmasq-tftp[1]: warning: ' + long_prefix]:
        primary_lines.append(text[:1023] + '\n')
    echo_row = dict(row, stderr=echo_text, files={'daemon.log': ''.join(primary_lines).encode().hex()})
    assert not compare(echo_row, echo_row, echo_case)
    result['full-debug-echo-required'] = bool(compare(echo_row, dict(echo_row, stderr=echo_text[:1024]), echo_case))
    result['separate-primary-cap-required'] = bool(compare(echo_row,
        dict(echo_row, files={'daemon.log': echo_text.encode().hex()}), echo_case))
    assert result['full-debug-echo-required'] and result['separate-primary-cap-required']
    return result


def qualification(required, rows, reference_only):
    executed = {row['id']: row for row in rows}
    result = {}
    for option, definition in required['options'].items():
        checked = []
        for boundary in definition['required']:
            mapping = boundary['required_scenarios']
            checked.append(dict(boundary, checked=not reference_only and bool(mapping)
                                and all(key in executed and not executed[key]['failures'] for key in mapping)))
        result[option] = {'closed': bool(checked) and definition.get('qualification_ready', False)
                          and all(row['checked'] for row in checked), 'required': checked}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--rust-sha256')
    parser.add_argument('--source-commit')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--scopes', default='sink,cli,identity')
    parser.add_argument('--scenarios')
    parser.add_argument('--helper-fd-contract', choices=['legacy', 'fork', 'selfexec'], default='legacy',
                        help='supplemental helper-only gate: fork=two FDs, selfexec=candidate four CLOEXEC FDs; default keeps original gate')
    parser.add_argument('--reference-only', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    calibration = controls()
    if args.self_test:
        print(json.dumps(calibration, sort_keys=True))
        return 0
    if not all([args.image_root, args.rust, args.rust_sha256, args.source_commit, args.output]):
        parser.error('image-root/rust/rust-sha256/source-commit/output required')
    if os.geteuid() != 0 or os.environ.get('DNSMASQ_TEST_ISOLATED') != '1':
        parser.error('isolated root namespace required')
    if sha256(args.rust) != args.rust_sha256:
        parser.error('candidate identity mismatch')
    out = args.output.resolve()
    if 'private' not in out.parts or out.exists():
        parser.error('fresh private output required')
    scenarios = [case for case in cases() if case['scope'] in args.scopes.split(',')]
    if args.scenarios:
        wanted = set(args.scenarios.split(','))
        if wanted - {case['id'] for case in scenarios}:
            parser.error('unknown scenario')
        scenarios = [case for case in scenarios if case['id'] in wanted]
    if args.helper_fd_contract != 'legacy':
        if not args.scenarios or not scenarios or any(not case.get('helper_fds') for case in scenarios):
            parser.error('supplemental helper FD contract requires explicit helper-startup scenarios only')
        for case in scenarios:
            case['helper_fd_contract'] = args.helper_fd_contract
    out.mkdir(parents=True)
    driver = out / 'driver'
    driver.mkdir()
    for name in [Path(__file__).name, *DEPENDENCIES]:
        shutil.copy2(Path(__file__).with_name(name), driver / name)
    sides = ['c'] if args.reference_only else ['c', 'rust']
    roots = {side: prepare(args.image_root, None, out / side, args.rust) for side in sides}
    result = {'source_commit': args.source_commit, 'rust_sha256': args.rust_sha256,
              'c_sha256': STOCK_SHA256, 'reference_only': args.reference_only,
              'helper_fd_contract': args.helper_fd_contract,
              'required_sha256': sha256(Path(__file__).with_name('m5_logging_requirements.json')),
              'driver_sha256': sha256(Path(__file__)), 'negative_controls': calibration,
              'scenarios': [], 'failures': [], 'closed': []}
    for case in scenarios:
        case_out = out / case['id']
        case_out.mkdir()
        row = {'id': case['id'], 'options': case['options'], 'failures': []}
        if case.get('policy_difference'):
            row['declared_policy_difference'] = {'source': case['policy_source'],
                                                  'description': case['policy_difference']}
        if case['argv'] == ['--version']:
            row['declared_identity_difference'] = RUST_VERSION_IDENTITY
        try:
            values = {side: run(roots[side], side, case, case_out / side) for side in sides}
            row['failures'] = compare(values['c'], values.get('rust', values['c']), case, args.reference_only)
            if case.get('reference_defect') and not args.reference_only:
                defects = []
                previous_edns = False
                for index, (c_row, rust_row) in enumerate(zip(values['c']['dns'], values['rust']['dns'])):
                    if c_row['transport'] == 'udp':
                        previous_edns = False
                    if previous_edns and c_row != rust_row and without_leaked_tcp_opt(c_row) == rust_row:
                        defects.append({'index': index, 'probe': c_row['probe'],
                                        'c_wire': c_row['reply_wire'], 'rust_wire': rust_row['reply_wire']})
                    previous_edns |= c_row['transport'] == 'tcp' and c_row['probe']['edns']
                row['reference_defect'] = {'source': 'forward.c:2378,2513,2721,2745-2755',
                                           'description': case['reference_defect'], 'affected': defects}
        except Exception as error:
            row['failures'].append({'kind': 'infrastructure', 'error': repr(error)})
        result['scenarios'].append(row)
        save(out / 'progress.json', result)
    result['failures'] = [dict(case=row['id'], **failure)
                          for row in result['scenarios'] for failure in row['failures']]
    required = json.loads(Path(__file__).with_name('m5_logging_requirements.json').read_text())
    result['options'] = qualification(required, result['scenarios'], args.reference_only)
    result['closed'] = [name for name, detail in result['options'].items() if detail['closed']]
    save(out / 'result.json', result)
    print(json.dumps({'cases': len(scenarios), 'failures': len(result['failures']), 'closed': result['closed'],
                      'reference_defect_packets': sum(len(row.get('reference_defect', {}).get('affected', [])) for row in result['scenarios'])}))
    return int(bool(result['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
