#!/usr/bin/env python3
"""Family-level DHCP tags/options comparison against the exact image ELF.

Run under run_isolated.sh; no host listeners or router state are used. Expected
packets always come from the image C daemon. Full wire bytes, lease names and
exit/cleanup are retained; only lease epoch fields are normalized.
"""
import argparse
import copy
import json
import os
import re
from pathlib import Path
import signal
import socket
import struct
import sys
import subprocess
import time

from dhcp_boot_service_diff import packet as base_packet, options
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256


# Names and types from exact C dhcp-common.c::opttab, not the Rust parser.
NAMED_OPTIONS = [('netmask', 1, '192.0.2.10'), ('time-offset', 2, '7'), ('router', 3, '192.0.2.10'), ('dns-server', 6, '192.0.2.10'), ('log-server', 7, '192.0.2.10'), ('lpr-server', 9, '192.0.2.10'), ('boot-file-size', 13, '7'), ('domain-name', 15, 'example.test'), ('swap-server', 16, '192.0.2.10'), ('root-path', 17, 'example.test'), ('extension-path', 18, 'example.test'), ('ip-forward-enable', 19, '7'), ('non-local-source-routing', 20, '7'), ('policy-filter', 21, '192.0.2.10'), ('max-datagram-reassembly', 22, '7'), ('default-ttl', 23, '7'), ('mtu', 26, '7'), ('all-subnets-local', 27, '7'), ('router-discovery', 31, '7'), ('router-solicitation', 32, '192.0.2.10'), ('static-route', 33, '192.0.2.10'), ('trailer-encapsulation', 34, '7'), ('arp-timeout', 35, '7'), ('ethernet-encap', 36, '7'), ('tcp-ttl', 37, '7'), ('tcp-keepalive', 38, '7'), ('nis-domain', 40, 'example.test'), ('nis-server', 41, '192.0.2.10'), ('ntp-server', 42, '192.0.2.10'), ('netbios-ns', 44, '192.0.2.10'), ('netbios-dd', 45, '192.0.2.10'), ('netbios-nodetype', 46, '7'), ('netbios-scope', 47, '7'), ('x-windows-fs', 48, '192.0.2.10'), ('x-windows-dm', 49, '192.0.2.10'), ('T1', 58, '180s'), ('T2', 59, '180s'), ('vendor-class', 60, '7'), ('nis+-domain', 64, 'example.test'), ('nis+-server', 65, '192.0.2.10'), ('tftp-server', 66, 'example.test'), ('bootfile-name', 67, 'example.test'), ('mobile-ip-home', 68, '192.0.2.10'), ('smtp-server', 69, '192.0.2.10'), ('pop3-server', 70, '192.0.2.10'), ('nntp-server', 71, '192.0.2.10'), ('irc-server', 74, '192.0.2.10'), ('user-class', 77, '7'), ('rapid-commit', 80, '7'), ('last-transaction', 91, '180s'), ('associated-ip', 92, '192.0.2.10'), ('client-arch', 93, '7'), ('client-interface-id', 94, '7'), ('client-machine-id', 97, '7'), ('posix-timezone', 100, 'example.test'), ('tzdb-timezone', 101, 'example.test'), ('ipv6-only', 108, '7'), ('captive-portal', 114, 'example.test'), ('domain-search', 119, 'example.test'), ('sip-server', 120, 'example.test'), ('classless-static-route', 121, '192.0.2.0/24,127.0.0.1'), ('vendor-id-encap', 125, '7'), ('tftp-server-address', 150, '192.0.2.10'), ('server-ip-address', 255, '192.0.2.10')]

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def option(code, value):
    assert 0 < code < 255 and len(value) <= 255
    return bytes([code, len(value)]) + value


def request(item, xid):
    # Keep the legacy boot header and defaults; optional keys only extend it.
    wire = bytearray(base_packet(item, xid)[:240])
    if 'htype' in item:
        wire[1] = item['htype']
    if 'mac' in item or 'chaddr' in item or 'hlen' in item:
        address = bytes.fromhex(item.get('chaddr', item.get('mac', '020000000001')))
        length = item.get('hlen', len(address))
        assert 0 <= length <= 16 and len(address) <= 16
        wire[2] = length
        wire[28:44] = address.ljust(16, b'\0')
    for field, offset in [('ciaddr', 12), ('giaddr', 24)]:
        if field in item:
            wire[offset:offset+4] = socket.inet_aton(item[field])
    if 'flags' in item:
        wire[10:12] = struct.pack('!H', item['flags'])
    for field, offset, size in [('sname', 44, 64), ('file', 108, 128)]:
        if field in item:
            value = bytes.fromhex(item[field])
            assert len(value) <= size
            wire[offset:offset+size] = value.ljust(size, b'\0')
    if item['kind']:
        wire.extend(option(53, bytes([item['kind']])))
    if item['kind'] == 3:
        if item.get('requested_address', True):
            wire.extend(option(50, socket.inet_aton(item.get('address', '127.0.0.40'))))
        if item.get('server_id', '127.0.0.1') is not None:
            wire.extend(option(54, socket.inet_aton(item.get('server_id', '127.0.0.1'))))
    if 'prl' in item:
        wire.extend(option(55, bytes(item['prl'])))
    if 'maximum' in item:
        wire.extend(option(57, struct.pack('!H', item['maximum'])))
    for code, value in item.get('extra', []):
        wire.extend(option(code, bytes.fromhex(value)))
    wire.extend(bytes.fromhex(item.get('raw_tail', '')))
    if 'end_offset' in item:
        assert item['end_offset'] >= len(wire), (item['label'], len(wire))
        wire.extend(b'\0' * (item['end_offset'] - len(wire)))
    if item.get('end', True):
        wire.append(255)
    wire.extend(bytes.fromhex(item.get('after_end', '')))
    return bytes(wire)


def fixtures():
    def offer(label='offer', **kwargs):
        return dict(label=label, kind=1, maximum=1500, prl=[1,3,6,12,15,26,43,58,59,60,66,67,119,120,121,125,224,225], **kwargs)
    def tlv(code, value):
        return [code, value.hex()]
    for start in range(0, len(NAMED_OPTIONS), 5):
        group = NAMED_OPTIONS[start:start + 5]
        text = ''.join(f'dhcp-option=option:{name},{value}\n' for name, _, value in group)
        event = offer('named-options')
        event['prl'] = sorted(set(event['prl'] + [code for _, code, _ in group if code != 255]))
        yield (f'named-table-{start // 5:02}', text, [event])
    # Arbitrary option numbers outside the named table use type inference.
    named_codes = {code for _, code, _ in NAMED_OPTIONS}
    internal = {0, 12, 28, 43, 50, 51, 52, 53, 54, 55, 56, 57, 61, 81, 82, 118, 255}
    generic = [code for code in range(1, 255) if code not in named_codes | internal]
    for start in range(0, len(generic), 8):
        codes = generic[start:start + 8]
        text = ''.join(f'dhcp-option={code},01:02:03\n' for code in codes)
        event = offer('arbitrary-options'); event['prl'] = codes
        yield (f'numeric-table-{start // 8:02}', text, [event])
    yield ('ordinary-types', 'dhcp-option=option:mtu,1500\ndhcp-option=224,1025s\ndhcp-option=225,01:02:03\n', [offer(),dict(offer('ack'),kind=3)])
    yield ('address-descriptors', 'dhcp-option=121,192.0.2.0/24,127.0.0.1\ndhcp-option=120,192.0.2.10,192.0.2.11\n', [offer()])
    yield ('compressed-names', 'dhcp-option=119,a.example,b.example,example,.\ndhcp-option=120,sip.example\n', [offer()])
    yield ('vendor-encapsulation', 'dhcp-option=vendor:Widget,1,01:02\ndhcp-option=vendor:Widget,2,"hello"\n', [offer('matched',extra=[tlv(60,b'WidgetClient')]),offer('unmatched',extra=[tlv(60,b'Other')])])
    yield ('vendor-override', 'dhcp-option=60,WidgetOverride\ndhcp-option=vendor:Widget,1,7\n', [offer('override',extra=[tlv(60,b'Other')])])
    yield ('encapsulation', 'dhcp-option=encap:224,1,1b\ndhcp-option=encap:224,2,"text"\ndhcp-option=vi-encap:1234,1,02:03\n', [offer(),dict(offer('empty-prl'),prl=[]),dict(offer('bootp'),kind=0)])
    yield ('forced-encapsulation', 'dhcp-option-force=encap:224,1,1\ndhcp-option-force=vi-encap:1234,2,2\n', [dict(offer('empty-prl'),prl=[])])
    yield ('request-vs-context-priority', 'dhcp-mac=set:client,02:00:*:00:00:01\ndhcp-option=224,1\ndhcp-option=tag:client,224,2\ndhcp-option=tag:range,224,3\n', [offer()])
    yield ('context-negation', 'dhcp-option=tag:!range,224,1\ndhcp-option=tag:range,224,2\n', [offer()])
    yield ('tag-if-order', 'dhcp-mac=set:client,02:00:00:*:*:*\ntag-if=tag:cli*,set:first\ntag-if=tag:first,set:ready\ndhcp-option=tag:ready,224,2\n', [offer()])
    yield ('hostname-prefix', 'dhcp-name-match=set:prefix,work*\ndhcp-option=tag:prefix,224,2\n', [offer('prefix',extra=[tlv(12,b'WORKstation')]),offer('not-prefix',extra=[tlv(12,b'other')])])
    yield ('vendor-and-user-tags', 'dhcp-vendorclass=set:vendor,Widget\ndhcp-userclass=set:user,desk\ndhcp-option=tag:vendor,224,1\ndhcp-option=tag:user,225,2\n', [offer('both',extra=[tlv(60,b'WidgetClient'),tlv(77,b'\x04desk\x06mobile')]),offer('legacy',extra=[tlv(77,b'legacy-desktop')]),offer('boundary',extra=[tlv(77,b'\x03des\x01k')])])
    yield ('option-match', 'dhcp-match=set:present,225\ndhcp-match=set:arch,option:client-arch,7\ndhcp-match=set:masked,224,01:*:03\ndhcp-option=tag:present,225,1\ndhcp-option=tag:arch,224,2\ndhcp-option=tag:masked,26,1492\n', [offer('all',extra=[tlv(225,b'x'),tlv(93,b'\x00\x00\x00\x07'),tlv(224,b'\x01\x09\x03')]),offer('offset-miss',extra=[tlv(93,b'\x01\x00\x07\x00'),tlv(224,b'\x00\x01\x09\x03')])])
    yield ('ignore-tag', 'dhcp-vendorclass=set:blocked,Blocked\ndhcp-ignore=tag:blocked\n', [offer('accepted'),offer('ignored',extra=[tlv(60,b'BlockedClient')],no_reply=True)])
    yield ('host-filter-and-set', 'dhcp-vendorclass=set:client,Widget\ndhcp-host=tag:client,02:00:00:00:00:01,127.0.0.41,tagged,set:chosen,600s\ndhcp-option=tag:chosen,224,1\n', [offer('fallback'),offer('tagged',extra=[tlv(60,b'Widget')])])
    yield ('host-wildcard', 'dhcp-host=02:00:*:*:*:01,127.0.0.41,masked,600s\n', [offer('masked',mac='020002000001')])
    yield ('host-name-only', 'dhcp-host=named,127.0.0.42,600s\n', [offer('name',mac='020002000002',extra=[tlv(12,b'named')])])
    yield ('ignored-and-generated-names', 'dhcp-host=02:00:00:00:00:02,127.0.0.41,600s\ndhcp-name-match=set:bad,bad*\ndhcp-ignore-names=tag:bad\ndhcp-generate-names=tag:bad\n', [dict(offer('name',mac='020000000002',extra=[tlv(12,b'bad-name')]),kind=3,address='127.0.0.41')])
    yield ('client-update', 'dhcp-client-update\n', [dict(offer('fqdn',extra=[tlv(81,b'\x00\x00\x00client.pool.test')]),kind=3)])
    yield ('rapid-commit', 'dhcp-rapid-commit\n', [offer('ordinary'),offer('rapid',extra=[tlv(80,b'')])])


def identity_fixtures():
    """Frozen identity case groups; every variant has its own daemon state."""
    def event(label='ack', kind=3, **kw):
        return dict(label=label, kind=kind, maximum=1500,
                    prl=[1, 3, 6, 12, 15, 51, 54, 58, 59, 60, 81, 82, 91, 224, 225, 226, 227], **kw)
    def opts(*pairs):
        return [[code, value.hex()] for code, value in pairs]
    def case(group, variant, text='', events=None, **settings):
        return (group+'--'+variant, dict(text=text, fixed_host=False, **settings), events or [event()])
    def marked(text):
        return text+'dhcp-option=224,1\ndhcp-option=tag:hit,224,2\n'
    def vi(enterprise, *classes):
        data = b''.join(bytes([len(value)])+value for value in classes)
        return struct.pack('!I', enterprise)+bytes([len(data)])+data
    def host(label, value, **kw):
        return event(label, extra=opts((12, value)), **kw)
    def marker_events(payloads, code=124):
        return [event(label, kind=1, extra=opts((code, value))) for label, value in payloads]
    def ack_with_dns(label='ack', name='client', **kw):
        return event(label, dns=[(name+'.pool.test', 1), ('40.0.0.127.in-addr.arpa', 12)], **kw)

    yield case('identity-host-bare-colon', 'hardware',
               'dhcp-host=2001:db8::1,127.0.0.40,colon,600s\n',
               [event(chaddr='2001db0801', hlen=5)])

    common = marked('dhcp-match=set:hit,vi-encap:1234,needle\n')
    for code in (256, 65535):
        yield case('identity-match-grammar', f'non-wire-{code}',
                   marked(f'dhcp-match=set:hit,{code},needle\n'),
                   [event('no-option', kind=1), event('ordinary-option', kind=1, extra=opts((224, b'needle')))])
    yield case('identity-match-enterprise', 'identification', common,
               marker_events([('same', vi(1234, b'needle')), ('other', vi(1235, b'needle')),
                              ('short', b'\0\0\x04\xd2'), ('absent', b'')]) +
               [event('option125', kind=1, extra=opts((125, vi(1234, b'needle'))))])
    yield case('identity-match-block-order', 'classes-and-enterprises', common,
               marker_events([('first-block', vi(1234, b'needle')+vi(1, b'else')),
                              ('later-block', vi(1, b'else')+vi(1234, b'needle')),
                              ('later-class', vi(1234, b'else', b'needle')),
                              ('first-class', vi(1234, b'needle', b'else')),
                              ('first-matching-enterprise-miss', vi(1234, b'else')+vi(1234, b'needle'))]))
    yield case('identity-match-empty', 'no-value', marked('dhcp-match=set:hit,vi-encap:1234\n'),
               marker_events([('empty-class', vi(1234, b'')), ('nonempty', vi(1234, b'any')),
                              ('no-data', vi(1234)), ('no-data-before-other', vi(1234)+vi(1, b'x'))]))
    for variant, value, enterprise, payloads in [
        ('substring', 'needle', 1234, [('substring', b'xxneedlexx'), ('case', b'NEEDLE'), ('short', b'need')]),
        ('numeric-stride', '258s', 1234, [('aligned', b'\0\0\1\2'), ('unaligned', b'\0\1\2\0'), ('short', b'\1')]),
        # Exact C's u.encap/u.wildcard_mask union makes the mask the enterprise.
        ('hex-union', '01:02', 0, [('exact', b'\1\2'), ('offset', b'\0\1\2'), ('short', b'\1')]),
        ('wildcard-union', '01:*:03', 2, [('masked', b'\1\x99\3'), ('offset', b'\0\1\x99\3'), ('short', b'\1\x99')]),
    ]:
        samples = [(label, vi(enterprise, payload)) for label, payload in payloads]
        if enterprise != 1234: samples.append(('configured-enterprise-union-overwritten', vi(1234, payloads[0][1])))
        yield case('identity-match-values', variant, marked(f'dhcp-match=set:hit,vi-encap:1234,{value}\n'), marker_events(samples))
    yield case('identity-match-malformed', 'bounded', common,
               marker_events([('outer-too-long', struct.pack('!I',1234)+b'\x20\x06needle'),
                              ('class-too-long', struct.pack('!I',1234)+b'\x07\x20needle'),
                              ('match-before-short-tail', vi(1234,b'needle')+b'\x01'),
                              ('class-match-before-malformed', struct.pack('!I',1234)+b'\x09\x06needle\x08x'),
                              ('wrong-enterprise-before-valid', vi(42,b'other')+vi(1234,b'needle'))]))
    crossing = struct.pack('!I',1234)+b'\x01\x04'+b'ABCD\x00'
    yield case('identity-match-cross-block', 'within-option', marked('dhcp-match=set:hit,vi-encap:1234,ABCD\n'),
               marker_events([('spans-next-enterprise',crossing), ('same-outer-without-tail',crossing[:6])]))
    match = option(124, vi(1234,b'needle'))
    wrong = option(124, vi(42,b'other'))
    yield case('identity-match-scan', 'scanner', common, [
        event('short-earlier',kind=1,raw_tail=(option(124,b'\0')+match).hex()),
        event('first-sufficient',kind=1,raw_tail=(wrong+match).hex()),
        event('pad',kind=1,raw_tail=(b'\0'+match).hex()),
        event('end-before',kind=1,raw_tail=(b'\xff'+match).hex()),
        event('malformed-before',kind=1,raw_tail=(b'\xfe\xff'+match).hex()),
        event('file',kind=1,extra=opts((52,b'\1')),file=(match+b'\xff').hex()),
        event('sname',kind=1,extra=opts((52,b'\2')),sname=(match+b'\xff').hex()),
        event('file-before-sname',kind=1,extra=opts((52,b'\3')),file=(wrong+b'\xff').hex(),sname=(match+b'\xff').hex()),
    ])
    yield case('identity-match-tag-if', 'derived',
               'dhcp-match=set:source,vi-encap:1234,needle\ntag-if=tag:source,set:hit\n'+marked(''),
               marker_events([('match',vi(1234,b'needle')),('miss',vi(1234,b'other'))]))

    for variant, pattern, values in [
        ('short','wpad',[b'wpad',b'WPAD',b'wpad.pool.test',b'other']),
        ('full','wpad.pool.test',[b'wpad',b'WPAD.pool.TEST',b'wpad.other.test']),
    ]:
        yield case('identity-name-exact',variant,marked(f'dhcp-name-match=set:hit,{pattern}\n'),
                   [host(f'name-{i}',value,kind=1) for i,value in enumerate(values)])
    for variant, pattern, values in [
        ('terminal','work*',[b'work',b'WORKstation',b'work.pool.test',b'wor',b'other']),
        ('internal','wo*rk',[b'wo*rk',b'work',b'woXXXrk']),
        ('one-star-stripped','work**',[b'work*',b'work*station',b'workstation']),
    ]:
        yield case('identity-name-prefix',variant,marked(f'dhcp-name-match=set:hit,{pattern}\n'),
                   [host(f'name-{i}',value,kind=1) for i,value in enumerate(values)])
    names = [
        ('option12',opts((12,b'work.pool.test'))),
        ('fqdn-clear',opts((81,b'\0\0\0work.pool.test'))),
        ('fqdn-wire',opts((81,b'\4\0\0\4work\4pool\4test\0'))),
        ('fqdn-precedence',opts((12,b'other'),(81,b'\0\0\0work.pool.test'))),
        ('fqdn-invalid-precedence',opts((12,b'work'),(81,b'\0\0\0.bad'))),
        ('trailing-dot',opts((12,b'work.pool.test.'))),
        ('trailing-nul',opts((12,b'work\0'))),
        ('empty-first-label',opts((12,b'.work'))),
        ('control',opts((12,b'work\x01'))),
        ('nonascii',opts((12,b'work\xff'))),
        ('label64',opts((12,b'work'+b'w'*60))),
    ]
    yield case('identity-name-source','inputs',marked('dhcp-name-match=set:hit,work*\n'),
               [event(label,kind=1,extra=extra) for label,extra in names])
    # C retains offer_hostname even after strip_hostname leaves an empty
    # client label. Observe OFFER and ACK separately for both FQDN encodings.
    for variant, value in [('leading-dot', b'\0\0\0.bad'), ('root-clear', b'\0\0\0.'),
                           ('root-encoded', b'\4\0\0\0'), ('valid-full', b'\0\0\0work.pool.test')]:
        yield case('identity-name-source', variant, marked('dhcp-name-match=set:hit,work*\n'), [
            event('offer', kind=1, extra=opts((81, value))), event('ack', extra=opts((81, value)))])
    yield case('identity-name-tag-if','derived',
               'dhcp-name-match=set:source,work*\ntag-if=tag:source,set:hit\n'+marked(''),
               [host('match',b'work',kind=1),host('miss',b'other',kind=1),event('absent',kind=1)])
    yield case('identity-name-host-selection','tagged-name-only',
               'dhcp-name-match=set:hit,work*\ndhcp-host=tag:hit,work,127.0.0.40,set:chosen,600s\n'+
               'dhcp-option=tag:chosen,225,9\n'+marked(''),
               [host('tagged-name',b'work',kind=1),host('miss-name',b'other',kind=1)])
    yield case('identity-name-host-selection','configured-name-not-packet',
               'dhcp-host=02:00:00:00:00:01,127.0.0.40,work,600s\n'+marked('dhcp-name-match=set:hit,work*\n'),
               [host('different-client-name',b'other',kind=1),event('no-client-name',kind=1)])

    yield case('identity-ignore-unconditional','ordinary','dhcp-ignore-names\n',[
        ack_with_dns('option12',extra=opts((12,b'client'))),
        ack_with_dns('option81',extra=opts((81,b'\0\0\0client.pool.test')))])
    selector_variants = [
        ('tag','tag:hit','dhcp-match=set:hit,224\n'),
        ('net','net:hit','dhcp-match=set:hit,224\n'),
        ('bare','hit','dhcp-match=set:hit,224\n'),
        ('conjunction','tag:hit,tag:other','dhcp-match=set:hit,224\ndhcp-match=set:other,225\n'),
        ('negated','tag:!hit','dhcp-match=set:hit,224\n'),
        ('hash-negation','tag:#hit','dhcp-match=set:hit,224\n'),
        ('case-sensitive','tag:HIT','dhcp-match=set:hit,224\n'),
        ('lone-bang','!',''), ('lone-hash','#',''),
    ]
    for variant, selector, setup in selector_variants:
        for group,directive in [('identity-ignore-selectors','dhcp-ignore-names'),('identity-generate-selectors','dhcp-generate-names')]:
            name = [(12,b'client')] if directive == 'dhcp-ignore-names' else []
            yield case(group,variant,setup+directive+'='+selector+'\n',[
                event('none',extra=opts(*name)),
                event('first',extra=opts(*name,(224,b'x'))),
                event('both',extra=opts(*name,(224,b'x'),(225,b'x')))])
    for group,directive in [('identity-ignore-selectors','dhcp-ignore-names'),('identity-generate-selectors','dhcp-generate-names')]:
        name = [(12,b'client')] if directive == 'dhcp-ignore-names' else []
        yield case(group,'alternative-rules','dhcp-match=set:a,224\ndhcp-match=set:b,225\n'+directive+'=tag:a\n'+directive+'=tag:b\n',[
            event('first',extra=opts(*name,(224,b'x'))),event('second',extra=opts(*name,(225,b'x'))),event('neither',extra=opts(*name))])
    for group,text in [('identity-generate-selectors',''),('identity-generate-selectors','dhcp-generate-names\n')]:
        yield case(group,'enabled' if text else 'disabled',text,[event()])
    for variant, policy in [('unconditional','dhcp-ignore-names\n'),('tagged','dhcp-ignore-names=tag:range\n')]:
        yield case('identity-ignore-config-name',variant,'dhcp-host=02:00:00:00:00:01,127.0.0.40,authority,600s\n'+policy,
                   [ack_with_dns(name='authority',extra=opts((12,b'client')))])
    yield case('identity-ignore-name-only','non-authority','dhcp-host=client,127.0.0.40,600s\ndhcp-ignore-names\n',
               [ack_with_dns(extra=opts((12,b'client')))])
    for variant, name, port in [('correct','authority.pool.test',15353),('wrong-domain','authority.wrong.test',15353),('dns-disabled','authority.pool.test',0)]:
        queries = [] if port == 0 else [(name,1),('40.0.0.127.in-addr.arpa',12)]
        yield case('identity-ignore-dns-name',variant,f'host-record={name},127.0.0.40\ndhcp-ignore-names\n',
                   [event(extra=opts((12,b'client')),dns=queries)],dns_port=port)
    yield case('identity-ignore-range-tag','derived','tag-if=tag:range,set:derived\ndhcp-ignore-names=tag:derived\n',
               [host('discover',b'client',kind=1),ack_with_dns(extra=opts((12,b'client')))])
    yield case('identity-ignore-phases','offer-ack-inform','dhcp-ignore-names\n',[
        host('offer',b'client',kind=1),host('ack',b'client'),
        host('inform',b'client',kind=8,ciaddr='127.0.0.40')])
    yield case('identity-ignore-existing-name','retention','dhcp-match=set:ignore,224\ndhcp-ignore-names=tag:ignore\n',[
        ack_with_dns('initial',extra=opts((12,b'client'))),
        ack_with_dns('ignored-new',extra=opts((12,b'changed'),(224,b'yes')))])

    for variant,text,pairs in [
        ('client','',[(12,b'client')]),
        ('configured','dhcp-host=02:00:00:00:00:01,127.0.0.40,authority,600s\n',[]),
        ('dns','host-record=authority.pool.test,127.0.0.40\n',[]),
        ('ignored-client','dhcp-ignore-names\n',[(12,b'client')]),
    ]:
        yield case('identity-generate-priority',variant,text+'dhcp-generate-names\n',[event(extra=opts(*pairs))])
    yield case('identity-generate-phases','ordinary','dhcp-generate-names\n',[
        event('offer',kind=1),event('inform',kind=8,ciaddr='127.0.0.40'),event('ack')])
    yield case('identity-generate-phases','rapid','dhcp-generate-names\ndhcp-rapid-commit\n',[
        event('rapid',kind=1,extra=opts((80,b'')))])
    for variant,htype,address in [('ethernet',1,'02aabbccdd01'),('arbitrary',6,'02aabbccdd02')]:
        yield case('identity-generate-hardware',variant,'dhcp-generate-names\n',[
            event(htype=htype,chaddr=address,extra=opts((61,b'\x09competing-client')))])
    for size in range(5):
        pairs=[] if size == 0 else [(61,bytes(range(1,size+1)))]
        yield case('identity-generate-clid-short',str(size),'dhcp-generate-names\ndhcp-rapid-commit\n',[
            event('request',hlen=0,chaddr='',htype=0,extra=opts(*pairs)),
            event('rapid',kind=1,hlen=0,chaddr='',htype=0,extra=opts(*pairs,(80,b'')),no_reply=size<=3)])
    for variant,htype,clid in [('equal',1,b'\1\xaa\xbb\xcc'),('unequal',1,b'\2\xaa\xbb\xcc'),
                                ('eui64',24,b'\x1b\xaa\xbb\xcc'),('reverse',27,b'\x18\xaa\xbb\xcc')]:
        yield case('identity-generate-clid-type',variant,'dhcp-generate-names\n',[
            event(htype=htype,hlen=0,chaddr='',extra=opts((61,clid)))])
    for size in [79,80,81,255]:
        clid = bytes([2])+bytes((i%254)+1 for i in range(size-1))
        yield case('identity-generate-clid-limit',str(size),'dhcp-generate-names\n',[
            event(htype=1,hlen=0,chaddr='',extra=opts((61,clid)))])
    yield case('identity-generate-clid-policy','global-ignore','dhcp-generate-names\ndhcp-ignore-clid\n',[
        event(hlen=0,chaddr='',htype=0,extra=opts((61,b'\x02abcd')))])
    yield case('identity-generate-clid-policy','per-host-ignore','dhcp-generate-names\ndhcp-host=id:*,127.0.0.40,600s\n',[
        event(hlen=0,chaddr='',htype=0,extra=opts((61,b'\x02abcd')))])
    yield case('identity-generate-clid-policy','recovered','dhcp-generate-names\n',[
        event('initial',extra=opts((61,b'\x02abcd'))),event('renew-without-clid')])
    generated='02-00-00-00-00-01'
    yield case('identity-generate-publication','lease-dns-renew','dhcp-generate-names\n',[
        ack_with_dns('generated',name=generated),
        ack_with_dns('client-renamed',extra=opts((12,b'client'))),
        ack_with_dns('generated-again',name=generated)])
    yield case('identity-generate-publication','duplicate-name','dhcp-generate-names\n',[
        event('first',hlen=0,chaddr='',htype=1,extra=opts((61,b'\1\xaa\xbb\xcc'))),
        event('second',hlen=0,chaddr='',htype=2,address='127.0.0.41',extra=opts((61,b'\2\xaa\xbb\xcc')))])

    for subcode,name in [(1,'circuitid'),(2,'remoteid'),(6,'subscrid')]:
        selector=marked(f'dhcp-{name}=set:hit,match\n')
        def agent(label,payload,**kw):
            return event(label,kind=1,extra=opts((82,payload)),**kw)
        good=option(subcode,b'match')
        yield case(f'identity-agent-{subcode}-exact','values',selector,[
            agent('same',good),agent('short',option(subcode,b'mat')),agent('long',option(subcode,b'matches')),
            agent('case',option(subcode,b'MATCH')),agent('absent',option(99,b'match'))])
        yield case(f'identity-agent-{subcode}-scan','first-sufficient',selector,[
            agent('short-earlier',option(subcode,b'')+good),
            agent('wrong-earlier',option(subcode,b'wrong')+good),
            agent('pad',b'\0'+good),agent('end',b'\xff'+good),
            agent('malformed-before',b'\x63\xff'+good),agent('match-before-malformed',good+b'\x63\xff')])
        yield case(f'identity-agent-{subcode}-grammar', 'bare-tag', marked(f'dhcp-{name}=hit,match\n'), [
            agent('bare-selector', good)])
        for variant,value,payload in [('text','match',b'match'),('quoted','"a:b"',b'a:b'),('hex','6d:61:74:63:68',b'match'),
                                      ('odd','a:b:c',b'\x0a\x0b\x0c'),('compact','aabb:cc',b'\xaa\xbb\xcc'),('text-star','0*',b'0*'),('empty','',b'')]:
            yield case(f'identity-agent-{subcode}-grammar',variant,marked(f'dhcp-{name}=set:hit,{value}\n'),[
                agent('value',option(subcode,payload))])
    good=option(1,b'match'); wrong=option(1,b'wrong'); outer=option(82,good)
    agent_setup=marked('dhcp-circuitid=set:hit,match\n')
    yield case('identity-agent-outer-scan','duplicates',agent_setup,[
        event('short-first',kind=1,raw_tail=(option(82,b'')+outer).hex()),
        event('sufficient-first',kind=1,raw_tail=(option(82,wrong)+outer).hex()),
        event('no-agent',kind=1),
        event('file',kind=1,extra=opts((52,b'\1')),file=(outer+b'\xff').hex()),
        event('sname',kind=1,extra=opts((52,b'\2')),sname=(outer+b'\xff').hex()),
    ])
    yield case('identity-agent-phases','bootp-and-query',agent_setup+'leasequery\ninterface=br-lan\n'+
               'dhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,600s\n'+
               'dhcp-host=02:00:00:00:00:01,127.0.0.40,600s\n',[
        event('bootp',kind=0,extra=opts((82,good))),
        event('query-no-agent-tag',kind=10,giaddr='10.77.0.2',transport='relay',extra=opts((82,good)))])
    yield case('identity-agent-combined','independent-tags',
               'dhcp-circuitid=set:c,match\ndhcp-circuitid=set:again,match\ndhcp-remoteid=set:r,remote\n'+
               'dhcp-subscrid=set:s,subscriber\ntag-if=tag:c,tag:r,tag:s,set:hit\n'+
               'dhcp-option=tag:c,225,3\ndhcp-option=tag:r,226,4\ndhcp-option=tag:s,227,5\ndhcp-option-force=tag:again,228,6\n'+marked(''),[
        event('all',kind=1,extra=opts((82,good+option(2,b'remote')+option(6,b'subscriber')))),
        event('circuit-only',kind=1,extra=opts((82,good)))])
    for variant,payload in [('ordinary',good),('unknown',good+option(99,b'unknown')),('malformed',good+b'\x63\xff'),('pad-end',b'\0'+good+b'\xff\x63\xff')]:
        yield case('identity-agent-echo',variant,'',[
            event('requested',kind=1,extra=opts((82,payload))),
            dict(event('empty-prl',kind=1,extra=opts((82,payload))),prl=[])])
    yield case('identity-agent-echo-phases','ordinary',agent_setup+'dhcp-rapid-commit\n'+
               'dhcp-host=02:00:00:00:00:01,127.0.0.40,600s\ndhcp-match=set:blocked,224\ndhcp-ignore=tag:blocked\n',[
        event('offer',kind=1,extra=opts((82,good))),event('ack',extra=opts((82,good))),
        event('nak',address='127.0.0.99',extra=opts((82,good))),
        event('inform',kind=8,ciaddr='127.0.0.40',extra=opts((82,good))),
        event('rapid',kind=1,extra=opts((82,good),(80,b''))),
        event('bootp',kind=0,extra=opts((82,good))),
        event('ignored',kind=1,extra=opts((82,good),(224,b'x')),no_reply=True)])
    # 548-byte default capacity: END must be strictly before 548-(7+2).
    for label,offset,end in [('before',538,True),('equal',539,True),('after',540,True),('missing',548,False),('oversize',700,True)]:
        item=event(label,kind=1,extra=opts((82,good)),end_offset=offset,end=end)
        item.pop('maximum')
        yield case('identity-agent-echo-reservation',label,agent_setup,[item])
    large=option(1,b'match')+option(99,b'x'*246)
    assert len(large)==255
    for variant,extra,maximum,prl,payload in [
        ('default','','absent',list(range(224,231)),good),
        ('no-prl','','absent',None,good),
        ('advertised-548','',548,list(range(224,231)),good),
        ('advertised-1500','',1500,list(range(224,231)),good),
        ('empty-prl','','absent',[],good),
        ('no-override','dhcp-no-override\n','absent',list(range(224,231)),good),
        ('large-agent-no-reservation','','absent',[224,225,226],large),
        ('large-agent-reserved','',1500,[224,225,226],large),
        ('occupied-boot','dhcp-boot=boot.bin,boot.pool.test,127.0.0.1\n','absent',list(range(224,231)),good),
    ]:
        item=event(kind=1,extra=opts((82,payload)))
        if prl is None: item.pop('prl')
        else: item['prl']=prl
        if maximum=='absent': item.pop('maximum')
        else: item['maximum']=maximum
        text=extra+''.join(f'dhcp-option={code},"'+chr(65+code-224)*80+'"\n' for code in range(224,231))
        yield case('identity-agent-echo-capacity',variant,text,[item])
    yield case('identity-agent-echo-overload','input-regions',agent_setup,[
        event('file',kind=1,extra=opts((52,b'\1')),file=(outer+b'\xff').hex()),
        event('sname',kind=1,extra=opts((52,b'\2')),sname=(outer+b'\xff').hex()),
        event('file-before-sname',kind=1,extra=opts((52,b'\3')),file=(outer+b'\xff').hex(),sname=(option(82,wrong)+b'\xff').hex()),
        event('duplicate',kind=1,raw_tail=(outer+option(82,wrong)).hex()),
        event('overloaded-without-primary-end',kind=1,extra=opts((52,b'\1')),file=(outer+b'\xff').hex(),end=False),
    ])
    relay_config='interface=br-lan\nleasequery\ndhcp-range=10.77.0.10,10.77.0.30,255.255.255.0,600s\n'
    def query(label):
        return event(label,kind=10,ciaddr='127.0.0.40',giaddr='10.77.0.2',transport='relay')
    rejected=event('reserve-failure',extra=opts((82,wrong)),end_offset=539);rejected.pop('maximum')
    yield case('identity-agent-leasequery-retention','enabled',relay_config,[
        event('initial',extra=opts((82,good),(60,b'VendorOriginal'))),query('query-initial'),
        event('no-metadata'),query('query-retained'),rejected,query('query-after-no-reservation'),
        event('update',extra=opts((82,wrong),(60,b'VendorUpdated'))),query('query-updated')])
    yield case('identity-agent-leasequery-retention','disabled','',[
        event('metadata-disabled',extra=opts((82,good),(60,b'VendorOriginal')),
            seed_leases='{expiry} 02:00:00:00:00:01 127.0.0.40 * *\n'+
                'agent-info 127.0.0.40 '+':'.join(f'{value:02x}' for value in good)+'\n'+
                'vendorclass 127.0.0.40 56:65:6e:64:6f:72:53:65:65:64\n'),event('without-metadata')])
    for variant,prefix in [('ordinary',b''),('padded',b'\0'),('short-before-valid',option(5,b'x')+option(11,b'x'))]:
        payload=prefix+option(5,socket.inet_aton('127.0.0.1'))+prefix+option(11,socket.inet_aton('127.0.0.9'))+good
        yield case('identity-agent-context-regression',variant,relay_config+agent_setup,[
            event('direct',kind=1,extra=opts((82,payload))),
            event('relay-offer',kind=1,giaddr='10.77.0.2',transport='relay',extra=opts((82,payload))),
            event('relay-ack',giaddr='10.77.0.2',transport='relay',server_id='127.0.0.9',extra=opts((82,payload)))])


def identity_parser_cases():
    # (group, variant, config, explicit safe reference defect or None).
    for value in ['[2001:db8::1]','[::1]','[::1/64]','02:00:00:00:00:01,[2001:db8::1],127.0.0.40']:
        yield 'identity-host-ipv6',value,'dhcp-host='+value+'\n',None
    for i,value in enumerate(['set:hit,vi-encap:1234','hit,vi-encap:1234,text','set:hit,vi-encap:1234,01:*:03',
                              'set:hit,vi-encap:1234,258s','vi-encap:1234','set:a,set:b,vi-encap:1234',
                              'set:a,vendor:foo,1','set:a,encap:1,1','set:a,option6:1,1',
                              'set:hit,256,needle','set:hit,65535,needle']):
        yield 'identity-match-grammar',str(i),'dhcp-match='+value+'\n',None
    for i,value in enumerate(['set:hit,work','hit,work*','set:hit,"work"','set:hit,wo*rk','set:hit,work**','set:hit','set:hit,','set:a,set:b,work']):
        yield 'identity-name-grammar',str(i),'dhcp-name-match='+value+'\n',None
    for i,value in enumerate(['set:hit,*','set:,work']):
        reason = ('C opt_string_alloc returns NULL for the stripped star-only pattern; rfc2131.c strlen would dereference it; Rust retains safe match-all behavior'
                  if i == 0 else 'NULL tag in C name matcher; Rust explicitly rejects the empty tag')
        yield 'identity-name-reference-defects',str(i),'dhcp-name-match='+value+'\n',reason
    for directive,group in [('dhcp-ignore-names','identity-ignore-selector-grammar'),('dhcp-generate-names','identity-generate-selector-grammar')]:
        for i,value in enumerate([None,'!','#','tag:!','tag:#','net:hit','hit']):
            yield group,str(i),directive+('' if value is None else '='+value)+'\n',None
        for i,value in enumerate(['','tag:','net:']):
            yield group,'unsafe-'+str(i),directive+'='+value+'\n','NULL C tag predicate; syntax only, retain explicit safe rejection'
    for subcode,name in [(1,'circuitid'),(2,'remoteid'),(6,'subscrid')]:
        for i,value in enumerate(['set:hit','set:hit,','hit,"a:b"','set:hit,a:b:c','set:hit,aabb:cc','set:hit,0*']):
            yield f'identity-agent-{subcode}-grammar',str(i),f'dhcp-{name}='+value+'\n',None
        for i,value in enumerate(['set:,match']):
            yield 'identity-agent-reference-defects',f'{subcode}-{i}',f'dhcp-{name}='+value+'\n','NULL C class tag; syntax only, retain bounded rejection'


IDENTITY_LEGACY = {'host-filter-and-set','host-name-only','host-wildcard','hostname-prefix','option-match','ignored-and-generated-names'}
IDENTITY_META = {'identity-lifecycle','identity-accounting','identity-negative-controls'}


def parser_cases():
    return [
        ('bad-name','dhcp-option=option:unknown,1\n'),
        ('internal-name','dhcp-option=option:hostname,name\n'),
        ('bad-address','dhcp-option=3,broken\n'),
        ('oversize','dhcp-option=224,"'+'x'*256+'"\n'),
        ('bad-tag-if','tag-if=tag:client\n'),
        ('bad-match','dhcp-match=set:a,set:b,224,1\n'),
        ('bad-masked-mac','dhcp-mac=set:client,02:0*:00:00:00:01\n'),
        ('good-match-internal','dhcp-match=set:host,option:hostname,host\n'),
        ('good-hostname','dhcp-host=named,127.0.0.42\n'),
        ('good-star','dhcp-name-match=set:all,*\n'),
    ]


def config(extra):
    # Dict is an optional extension. Existing boot callers still pass a string.
    settings = extra if isinstance(extra, dict) else {'text': extra}
    lines = ['no-hosts', 'no-resolv', 'interface=lo', 'listen-address=127.0.0.1',
             'port=15353', 'no-ping', 'dhcp-authoritative']
    if settings.get('domain', True):
        lines.append('domain=pool.test')
    if settings.get('range', True):
        lines.append('dhcp-range=set:range,127.0.0.10,127.0.0.50,255.0.0.0,600s')
    if settings.get('fixed_host', True):
        lines.append('dhcp-host=02:00:00:00:00:01,127.0.0.40,fixed,600s')
    lines.extend(['dhcp-leasefile=/m2/family.leases', 'pid-file=/m2/family.pid'])
    if settings.get('dns_port') is not None:
        lines[4] = 'port=' + str(settings['dns_port'])
    return '\n'.join(lines) + '\n' + settings.get('text', '')


def syntax(root, side, text, folder, *, startup=False):
    folder.mkdir(parents=True, exist_ok=True)
    (root/'m2/parser.conf').write_text(text)
    def invoke(arguments, prefix=''):
        try:
            result = subprocess.run(command(root, side, *arguments, '-C', '/m2/parser.conf'),
                                    capture_output=True, timeout=5)
            code, stdout, stderr, timed_out = result.returncode, result.stdout, result.stderr, False
        except subprocess.TimeoutExpired as error:
            # subprocess.run kills and reaps its child before raising.
            code, stdout, stderr, timed_out = None, error.stdout or b'', error.stderr or b'', True
        (folder/(prefix+'stdout')).write_bytes(stdout)
        (folder/(prefix+'stderr')).write_bytes(stderr)
        row = {'exit': code, 'stdout': stdout.decode(errors='backslashreplace'),
               'stderr': stderr.decode(errors='backslashreplace')}
        if timed_out: row['timeout'] = True
        return row
    row = invoke(['--test'])
    if startup and row['exit'] not in (0, None):
        # Rejected safe configurations must reject at the real entry point too.
        row['startup'] = invoke(['-k'], 'startup-')
    save(folder/'result.json', row)
    return row


def receive(client, wire, target, timeout=.8):
    client.setblocking(False)
    drained = 0
    while True:
        try: client.recvfrom(65535); drained += 1
        except BlockingIOError: break
    client.sendto(wire, target)
    deadline = time.monotonic() + timeout
    foreign = []
    while time.monotonic() < deadline:
        client.settimeout(max(.001, deadline-time.monotonic()))
        try: response, peer = client.recvfrom(65535)
        except socket.timeout: break
        if len(response) >= 8 and response[4:8] == wire[4:8]:
            return response, peer, foreign, drained
        foreign.append({'wire': response.hex(), 'peer': list(peer)})
    return None, None, foreign, drained


def relay_client(args):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('10.77.0.2', 67))
        response, peer, foreign, drained = receive(client, bytes.fromhex(args.packet), ('10.77.0.1', 67))
    save(args.client_out, {'reply': response.hex() if response is not None else None,
                           'peer': list(peer) if peer else None, 'foreign': foreign, 'drained': drained})


def lease_rows(root):
    path = root/'m2/family.leases'
    leases = path.read_text() if path.exists() else ''
    normalized = []
    for line in leases.splitlines():
        fields = line.split()
        if not fields: continue
        if fields[0].isdigit():
            expiry = int(fields[0])
            assert expiry == 0 or int(time.time())+580 <= expiry <= int(time.time())+601, fields
            fields[0] = 'finite-600' if expiry else 'infinite'
        normalized.append(fields)
    return leases, sorted(normalized)


def dns_observe(name, kind, ident):
    labels = name.rstrip('.').encode().split(b'.')
    assert all(0 < len(label) <= 63 for label in labels)
    qname = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    wire = struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + qname + struct.pack('!HH', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(wire, ('127.0.0.1', 15353))
        response, peer = client.recvfrom(65535)
    assert response[:2] == wire[:2]
    return {'name': name, 'kind': kind, 'query': wire.hex(), 'reply': response.hex(), 'peer': list(peer)}


def primary_options(wire):
    cursor = 240; rows = []
    while cursor < len(wire):
        code = wire[cursor]
        if code == 255: return {'rows': rows, 'end': cursor}
        if code == 0: cursor += 1; continue
        assert cursor+2 <= len(wire)
        size = wire[cursor+1]
        assert cursor+2+size <= len(wire)
        rows.append({'offset': cursor, 'code': code, 'value': wire[cursor+2:cursor+2+size].hex()})
        cursor += 2+size
    raise AssertionError('response has no primary END')


def comparable_reply(response, event):
    # Leasequery is deliberately sent more than one second after ACK. Verify
    # the exact 600-second lease relationships before normalizing clock phase.
    if event['kind'] != 10: return response.hex()
    normalized = bytearray(response)
    rows = primary_options(response)['rows']
    timers = {row['code']: int(row['value'], 16) for row in rows if row['code'] in (51, 58, 59, 91)}
    if 51 in timers:
        remaining = timers[51]
        assert 580 <= remaining < 600, timers
        assert timers == {51: remaining, 58: remaining-300, 59: remaining-75, 91: 600-remaining}, timers
    else:
        assert not timers, timers
    for row in rows:
        if row['code'] in (51, 58, 59, 91):
            start = row['offset']+2
            assert len(bytes.fromhex(row['value'])) == 4
            normalized[start:start+4] = b'\0'*4
    return normalized.hex()


def comparable_syntax(row):
    row = copy.deepcopy(row)
    for stream in ('stdout', 'stderr'):
        if stream in row:
            row[stream] = re.sub(r'(?m)^dnsmasq-rs:', 'dnsmasq:', row[stream])
    if 'startup' in row:
        row['startup'] = comparable_syntax(row['startup'])
    return row


def run(root, side, folder, text, events):
    folder.mkdir()
    (folder/'config').write_text(text)
    (root/'m2/family.conf').write_text(text)
    for path in ('family.leases', 'family.pid'):
        (root/'m2'/path).unlink(missing_ok=True)
    if events and 'seed_leases' in events[0]:
        seeded = events[0]['seed_leases'].replace('{expiry}', str(int(time.time())+600))
        (root/'m2/family.leases').write_text(seeded)
        (folder/'seed.leases').write_text(seeded)
    trace = {'status': 'failed', 'rows': [], 'planned': len(events), 'ready': False}
    process = None; network = None
    with (folder/'daemon.log').open('w') as log, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(('0.0.0.0', 68)); client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.setsockopt(socket.SOL_SOCKET, 25, b'lo\0')
        try:
            if any(event.get('transport') == 'relay' for event in events):
                from test_single_poll_service import Network
                network = Network(); network.start()
            trace['syntax'] = syntax(root, side, text, folder/'syntax')
            assert trace['syntax']['exit'] == 0, 'safe daemon config rejected by --test'
            process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/family.conf'), stdout=log, stderr=log, start_new_session=True)
            deadline = time.monotonic()+5
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                if 'port=0\n' in text:
                    if (root/'m2/family.pid').exists(): break
                else:
                    try:
                        with socket.create_connection(('127.0.0.1', 15353), .05): break
                    except OSError: pass
                assert time.monotonic()<deadline, 'readiness timeout'
                time.sleep(.01)
            trace['ready'] = True
            trace['identity'] = process_identity(root, process.pid)
            for index, event in enumerate(events):
                if event['kind'] == 10:
                    time.sleep(1.05)  # make option91 presence deterministic after the preceding ACK
                wire = request(event, 0xa100+index)
                (folder/f'{index:03}.request').write_bytes(wire)
                if event.get('transport') == 'relay':
                    result_path = folder/f'{index:03}.transport.json'
                    result = subprocess.run(network.argv(sys.executable, Path(__file__).resolve(), '--relay-client',
                        '--packet', wire.hex(), '--client-out', result_path), capture_output=True, timeout=4)
                    assert result.returncode == 0, result.stderr.decode(errors='replace')
                    transport = json.loads(result_path.read_text())
                    response = bytes.fromhex(transport['reply']) if transport['reply'] is not None else None
                    peer = transport['peer']; foreign = transport['foreign']; drained = transport['drained']
                else:
                    response, peer, foreign, drained = receive(client, wire, ('255.255.255.255', 67))
                save(folder/f'{index:03}.transport.json', {'foreign': foreign, 'drained': drained})
                row = {'label': event['label']}
                if response is None:
                    assert event.get('no_reply'), 'unexpected DHCP timeout'
                    row['no_reply'] = True
                else:
                    assert not event.get('no_reply'), 'ignored client received matching xid reply'
                    assert response[0] == 2 and response[4:8] == wire[4:8], 'invalid response header'
                    (folder/f'{index:03}.response').write_bytes(response)
                    comparable = bytes.fromhex(comparable_reply(response, event))
                    row.update(reply=comparable.hex(), peer=list(peer), options=options(comparable), primary=primary_options(comparable))
                leases, normalized = lease_rows(root)
                (folder/f'{index:03}.leases').write_text(leases)
                row['leases'] = normalized
                row['dns'] = [dns_observe(name, kind, 0xb100+index*8+i) for i, (name, kind) in enumerate(event.get('dns', []))]
                trace['rows'].append(row)
            trace['status'] = 'ok'
        except Exception as error:
            trace['error'] = repr(error)
        finally:
            if process is not None:
                if process.poll() is None: os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait(3); trace['forced_cleanup'] = True
                trace['exit'] = process.returncode
                trace['reaped'] = not Path(f'/proc/{process.pid}').exists()
                trace['pid_removed'] = not (root/'m2/family.pid').exists()
                if trace['exit'] != 0 or not trace['reaped'] or not trace['pid_removed'] or trace.get('forced_cleanup'):
                    trace['status'] = 'failed'
            if network is not None:
                try:
                    trace['namespace_cleanup'] = network.close()
                    cleanup = trace['namespace_cleanup']
                    trace['namespace_reaped'] = cleanup is not None and not Path(f"/proc/{cleanup['pid']}").exists()
                    if not trace['namespace_reaped'] or cleanup['returncode'] != -signal.SIGTERM or cleanup['forced']:
                        trace['status'] = 'failed'
                except Exception as error:
                    trace['namespace_error'] = repr(error)
                    trace['status'] = 'failed'
            trace['interfaces_clean'] = sorted(name for _, name in socket.if_nameindex()) == ['lo']
            if not trace['interfaces_clean']: trace['status'] = 'failed'
            save(folder/'trace.json', trace)
    return trace


def compare(expected, actual):
    errors = []
    for side in (expected, actual):
        if side.get('status') != 'ok': errors.append('failed-side')
        if any(side.get(key) != value for key, value in [('ready', True), ('exit', 0), ('reaped', True), ('pid_removed', True), ('interfaces_clean', True)]):
            errors.append('cleanup-or-startup')
        if side.get('forced_cleanup'): errors.append('forced-cleanup')
        if side.get('namespace_error') or ('namespace_cleanup' in side and (not side.get('namespace_reaped') or side['namespace_cleanup']['forced'] or side['namespace_cleanup']['returncode'] != -signal.SIGTERM)):
            errors.append('namespace-cleanup')
        if len(side['rows']) != side.get('planned', len(side['rows'])): errors.append('unexecuted-row')
    if comparable_syntax(expected.get('syntax', {})) != comparable_syntax(actual.get('syntax', {})): errors.append('syntax')
    if len(expected['rows']) != len(actual['rows']): errors.append('row-count')
    for index, (left, right) in enumerate(zip(expected['rows'], actual['rows'])):
        if left != right: errors.append(f'row-{index}')
    return sorted(set(errors))


def all_cases(identity=False):
    legacy = list(fixtures())
    return [case for case in legacy if case[0] in IDENTITY_LEGACY] + list(identity_fixtures()) if identity else legacy


def corpus(path, identity=False):
    path.mkdir(parents=True, exist_ok=True)
    config_dir = path/'config_line'; config_dir.mkdir(exist_ok=True)
    packet_dir = path/'dhcp_packet'; packet_dir.mkdir(exist_ok=True)
    for label, text, events in all_cases(identity):
        text = text.get('text', '') if isinstance(text, dict) else text
        for index, line in enumerate(text.splitlines()):
            (config_dir/f'{label}-{index}').write_bytes(line.encode())
        for index, event in enumerate(events):
            (packet_dir/f'{label}-{index}').write_bytes(request(event, 0xa100+index))
    for label, text in parser_cases():
        (config_dir/label).write_bytes(text.rstrip().encode())
    if identity:
        for group, variant, text, _ in identity_parser_cases():
            safe_variant = ''.join(char if char.isalnum() or char in '-_' else '_' for char in variant)
            (config_dir/(group+'--'+safe_variant)).write_text(text)


def negative_controls(trace):
    assert trace['status'] == 'ok' and trace['rows']
    checks = []
    mutations = [('row', lambda changed: changed['rows'][0].update(reply='mutated')),
                 ('missing-row', lambda changed: changed['rows'].pop()),
                 ('lease', lambda changed: changed['rows'][0].update(leases=[['mutated-name']])),
                 ('echo-missing', lambda changed: changed['rows'][0].update(options=[])),
                 ('echo-placement', lambda changed: changed['rows'][0].update(primary={'end': -1, 'rows': []})),
                 ('cleanup', lambda changed: changed.update(pid_removed=False)),
                 ('diagnostic', lambda changed: changed['syntax'].update(stderr='wrong diagnostic, same exit'))]
    for name, mutate in mutations:
        changed = copy.deepcopy(trace); mutate(changed)
        assert compare(trace, changed), 'negative control missed: '+name
        checks.append(name)
    return checks


def required_case_map(cases, parsers):
    groups = {}
    for name, _, _ in cases:
        groups.setdefault(name.split('--')[0], []).append(name)
    for group, variant, _, _ in parsers:
        groups.setdefault(group, []).append('syntax:'+group+'--'+variant)
    return groups


def check_plan(checklist, cases, parsers):
    groups = {name.split('--')[0] for name, _, _ in cases}
    groups.update(group for group, _, _, _ in parsers)
    groups.update(IDENTITY_META)
    required = set(checklist['cases'])
    assert required <= groups, 'unmapped checklist groups: '+repr(sorted(required-groups))
    for _, _, events in cases:
        for index, item in enumerate(events): request(item, 0xa100+index)
    return {'groups': len(groups), 'required_groups': len(required), 'configurations': len(cases),
            'events': sum(len(events) for _, _, events in cases), 'syntax_cases': len(parsers)}


def checklist_result(checklist, report):
    # Synthetic accounting groups are earned only by complete successful runs.
    evidence = {}
    for row in report['cases']:
        evidence.setdefault(row['name'].split('--')[0], []).append({
            'path': row['name'], 'case': row['name'], 'passed': not row['errors'] and row['c_rows']==row['planned'] and row.get('rust_rows')==row['planned']})
    for row in report['parser']:
        evidence.setdefault(row['group'], []).append({'path': row['path'], 'case': 'syntax:'+row['group']+'--'+row['variant'], 'passed': not row['errors']})
    executed = {row['case'] for rows in evidence.values() for row in rows}
    required = {case for cases in report['required_case_map'].values() for case in cases}
    complete_run = executed == required
    meta_pass = complete_run and not report['failures'] and not report.get('c_only') and bool(report['cases'])
    for group in IDENTITY_META:
        evidence[group] = [{'path': 'result.json', 'passed': meta_pass}]
    result = copy.deepcopy(checklist)
    for boundary in result['boundaries']:
        records = [record for case in boundary['cases'] for record in evidence.get(case, [])]
        complete = all(evidence.get(case) and (case in IDENTITY_META or
            {row['case'] for row in evidence[case]} == set(report['required_case_map'].get(case, [])))
            for case in boundary['cases'])
        boundary['evidence'] = records
        boundary['status'] = 'passed' if not report.get('c_only') and complete and all(row['passed'] for row in records) else 'pending'
    result['checked'] = sum(row['status']=='passed' for row in result['boundaries'])
    result['total'] = len(result['boundaries'])
    result['passed'] = not report.get('c_only') and result['checked'] == result['total']
    result['status'] = 'image-evidence-passed' if result['passed'] else 'image-evidence-incomplete'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path)
    parser.add_argument('--rust-binary', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--case', action='append')
    parser.add_argument('--c-only', action='store_true')
    parser.add_argument('--identity', action='store_true', help='Run the frozen DHCP identity family, including reused legacy cases')
    parser.add_argument('--checklist', type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--emit-corpus', type=Path)
    parser.add_argument('--validate-plan', action='store_true')
    parser.add_argument('--relay-client', action='store_true')
    parser.add_argument('--packet')
    parser.add_argument('--client-out', type=Path)
    args = parser.parse_args()
    if args.relay_client:
        relay_client(args); return 0
    cases = all_cases(args.identity)
    parsers = list(identity_parser_cases()) if args.identity else [('legacy', label, text, None) for label, text in parser_cases()]
    checklist = json.loads(args.checklist.read_text()) if args.checklist else None
    required_map = required_case_map(cases, parsers)
    if args.validate_plan:
        assert checklist and args.identity
        print(json.dumps(check_plan(checklist, cases, parsers))); return 0
    if args.emit_corpus:
        corpus(args.emit_corpus, args.identity); return 0
    if checklist: check_plan(checklist, cases, parsers)
    if args.case:
        cases = [case for case in cases if case[0] in args.case or case[0].split('--')[0] in args.case]
        parsers = [case for case in parsers if case[0] in args.case or case[0]+'--'+case[1] in args.case]
    assert cases or parsers, 'no selected family cases'
    assert os.environ.get('DNSMASQ_TEST_ISOLATED') == '1' and os.geteuid() == 0
    assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
    assert args.out and 'private' in args.out.resolve().parts and not args.out.exists()
    args.out.mkdir(parents=True)
    root = prepare(args.image_root, None, args.out/'image', args.rust_binary)
    (root/'m2').chmod(0o777)
    save(args.out/'plan.json', {'service': cases, 'parser': parsers})
    report = {'c_sha256': sha256(root/'usr/sbin/dnsmasq'), 'rust_sha256': sha256(root/'usr/sbin/dnsmasq-rs'),
              'tool_sha256': sha256(Path(__file__)), 'source_commit': args.source_commit,
              'normalizations': ['diagnostics: only line-leading executable prefix dnsmasq-rs: becomes dnsmasq:; raw streams retained',
                'leasequery: wait 1.05 seconds before each query; validate 600-second lease T1/T2/elapsed relationships then zero only option51/58/59/91 values; raw .response retained',
                'leasefile: finite expiry epochs become finite-600 after checking remaining lifetime; lease identities/names/extensions unchanged'],
              'c_only': args.c_only, 'required_case_map': required_map, 'cases': [], 'parser': [], 'failures': [], 'negative_controls': [], 'reference_differences': []}
    assert report['c_sha256'] == STOCK_SHA256
    for label, extra, events in cases:
        folder = args.out/label; folder.mkdir()
        left = run(root, 'c', folder/'c', config(extra), events)
        row = {'name': label, 'planned': len(events), 'c_rows': len(left['rows'])}
        if args.c_only:
            errors = [] if left['status'] == 'ok' else ['c-failed']
        else:
            right = run(root, 'rust', folder/'rust', config(extra), events)
            row['rust_rows'] = len(right['rows'])
            errors = compare(left, right)
            if left['status'] == 'ok' and left['rows']:
                report['negative_controls'].append({'case': label, 'checks': negative_controls(left)})
        row['errors'] = errors; report['cases'].append(row)
        if errors: report['failures'].append(label)
        save(args.out/'summary.json', report)
    for index, (group, variant, text, defect) in enumerate(parsers):
        label = f'parser-{index:03}'
        row = {'group': group, 'variant': variant, 'path': label, 'errors': []}
        for side in ('c',) if args.c_only else ('c', 'rust'):
            row[side] = syntax(root, side, config(dict(text=text, fixed_host=False)), args.out/label/side, startup=defect is None)
        for side in ('c',) if args.c_only else ('c', 'rust'):
            if row[side]['exit'] not in (0, 1) or row[side].get('startup', {}).get('exit', 1) not in (0, 1):
                row['errors'].append(side+'-abnormal-exit'); report['failures'].append(group+'--'+variant)
        if row['c'].get('timeout') or row['c'].get('startup', {}).get('timeout'):
            row['errors'].append('c-timeout'); report['failures'].append(group+'--'+variant)
        if defect and not args.c_only:
            rust_expected = 0 if group == 'identity-name-reference-defects' and variant == '0' else 1
            if (row['c']['exit'], row['rust']['exit']) != (0, rust_expected):
                row['errors'].append('reference-disposition-changed'); report['failures'].append(group+'--'+variant)
        if not args.c_only and comparable_syntax(row['c']) != comparable_syntax(row['rust']):
            if defect and row['c']['exit'] == 0 and row['rust']['exit'] == 1:
                report['reference_differences'].append({'case': group+'--'+variant, 'scope': 'syntax only', 'reason': defect,
                    'c': row['c'], 'rust': row['rust'], 'path': label})
            else:
                row['errors'].append('syntax-or-startup'); report['failures'].append(group+'--'+variant)
        if defect and not any(item['case'] == group+'--'+variant for item in report['reference_differences']):
            report['reference_differences'].append({'case': group+'--'+variant, 'scope': 'syntax only',
                'reason': defect, 'path': label, 'disposition': 'runtime deliberately not executed; outputs retained'})
        if defect is None and row['c']['exit'] == 0:
            left = run(root, 'c', args.out/label/'startup-c', config(dict(text=text, fixed_host=False)), [])
            row['startup_c'] = {key: left.get(key) for key in ['status', 'ready', 'exit', 'reaped', 'pid_removed', 'interfaces_clean']}
            if not args.c_only:
                right = run(root, 'rust', args.out/label/'startup-rust', config(dict(text=text, fixed_host=False)), [])
                row['startup_rust'] = {key: right.get(key) for key in ['status', 'ready', 'exit', 'reaped', 'pid_removed', 'interfaces_clean']}
                row['errors'].extend(compare(left, right))
            elif left['status'] != 'ok': row['errors'].append('c-startup')
            if row['errors'] and group+'--'+variant not in report['failures']:
                report['failures'].append(group+'--'+variant)
        report['parser'].append(row)
        save(args.out/'summary.json', report)
    report['passed'] = not report['failures'] and not args.c_only
    save(args.out/'summary.json', report); save(args.out/'result.json', report)
    if checklist:
        checked = checklist_result(checklist, report)
        save(args.out/'checklist.json', checked)
        report['boundaries_passed'] = sum(row['status']=='passed' for row in checked['boundaries'])
        report['boundaries_total'] = len(checked['boundaries'])
        report['passed'] = report['passed'] and checked['passed']
        save(args.out/'result.json', report)
    print(json.dumps({key: report[key] for key in ['passed', 'failures']}))
    return int(not report['passed'] if not args.c_only else bool(report['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
