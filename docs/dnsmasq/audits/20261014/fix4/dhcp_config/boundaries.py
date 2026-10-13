#!/usr/bin/env python3
"""Independent three-way config/DHCP boundary checks in a private namespace.

Reuses packet transport only. Cases and comparison are independent of old audits.
Raw fixture configs, packets and daemon logs remain in --out under private/.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

p = argparse.ArgumentParser(description=__doc__)
for name in ('source', 'image', 'main', 'fix', 'out'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
assert os.geteuid() == 0 and os.environ.get('DNSMASQ_TEST_ISOLATED') == '1'
assert 'private' in a.out.resolve().parts
a.out.mkdir(parents=True, exist_ok=False)
sys.path.insert(0, str(a.source / 'tools/dnsmasq'))
import audit_20261011_dhcp as dhcp
from m2_rootfs import image_elf_command

paths = dict(c=a.image / 'usr/sbin/dnsmasq', main=a.main, fix=a.fix)
assert dhcp.sha(paths['c']) == dhcp.STOCK_SHA256
commands = {side: image_elf_command(a.image, path) for side, path in paths.items()}
report = dict(controller_sha256=dhcp.sha(__file__), binary_sha256={s: dhcp.sha(p) for s, p in paths.items()},
              source_sha256={f: dhcp.sha(a.source / f) for f in ['components/dnsmasq/src/config/auth.rs',
              'components/dnsmasq/src/dhcp/daemon.rs', 'components/dnsmasq/src/dhcp/runtime.rs',
              'components/dnsmasq/src/dhcp/state.rs']}, config=[], dhcp=[])

def save():
    (a.out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

directives = []
for name, values in {
    'auth-server': ['', 'ns.test', ',lo', 'ns.test,', 'ns.test,lo/', 'ns.test,lo/4',
                    'ns.test,lo/6', 'ns.test,lo/04', 'ns.test,lo/4/6', 'ns.test,127.0.0.1',
                    'ns.test,::1', 'ns.test,lo,::1', 'ns.test,"lo/4"', 'ns.test,"lo,lo"'],
    'auth-ttl': ['', '0', '4294967296', '99999999999999999999', '-1', '+1', '1x', '"1"'],
    'auth-peer': ['', '127.0.0.1,::1', '127.000.0.1', '::ffff:127.0.0.1', '::1%lo', '127.0.0.1,'],
    'auth-soa': ['', 'x,y,z', '1,,2,3,4', '1,foo,bar,baz'],
    'auth-sec-servers': ['', 'x,,y', '"x,y"'],
    'no-dhcpv6-interface': ['', 'lo,', 'lo*', '"lo,none"'],
}.items():
    directives.extend(name + '=' + value for value in values)
for index, directive in enumerate(directives):
    config = a.out / f'config-{index}.conf'
    config.write_text('port=0\nno-hosts\nno-resolv\n' + directive + '\n')
    observed = {}
    for side, command in commands.items():
        result = subprocess.run(command + ['-C', str(config), '--test'], capture_output=True, timeout=3)
        observed[side] = dict(exit=result.returncode, stderr=result.stderr.decode(errors='backslashreplace').replace(str(config), '<config>'))
    report['config'].append(dict(directive=directive, observed=observed,
        fix_matches_c=observed['fix']['exit'] == observed['c']['exit'],
        main_matches_c=observed['main']['exit'] == observed['c']['exit']))
save()

original_packet = dhcp.packet
def packet(kind, xid, mac=1, rapid=False, wanted=True, name=None, ciaddr=None, server='127.0.0.1', fqdn=None):
    original = bytearray(original_packet(kind, xid, mac, rapid, False, None))
    if ciaddr:
        original[12:16] = socket.inet_aton(ciaddr)
    wire, pos = original[:240], 240
    while pos < len(original):
        code = original[pos]
        pos += 1
        if code == 255:
            break
        size = original[pos]
        value = original[pos + 1:pos + 1 + size]
        pos += 1 + size
        if code != 54:
            wire += dhcp.option(code, value)
    if wanted:
        wire += dhcp.option(50, socket.inet_aton('127.0.0.30' if wanted is True else wanted))
    if kind == 3 and server:
        wire += dhcp.option(54, socket.inet_aton(server))
    if name is not None:
        wire += dhcp.option(12, name.encode())
    if fqdn is not None:
        wire += dhcp.option(81, bytes.fromhex(fqdn))
    return bytes(wire) + b'\xff'
dhcp.packet = packet

cases = list(dhcp.cases())
for policy, config in {
    'hosts': 'addn-hosts={hosts}\ndomain=test\n',
    'ignore': 'dhcp-ignore-names=tag:pool\n',
    'generate': 'dhcp-ignore-names=tag:pool\ndhcp-generate-names=tag:pool\n',
    'tag-if': 'tag-if=set:names,tag:pool\ndhcp-ignore-names=tag:names\ndhcp-generate-names=tag:names\n',
}.items():
    for wanted in ['127.0.0.31', '192.0.2.30']:
        cases.append(dict(name=f'rapid-fallback-{policy}-{wanted}', config=config,
            hosts='127.0.0.30 authoritative.test\n',
            events=[dict(kind=1, rapid=True, wanted=wanted, name='claimed.test')]))
for name in ['', '.test', 'claimed.other', 'claimed..test']:
    for rapid in [False, True]:
        cases.append(dict(name='name-edge-' + name.replace('.', '_') + '-' + str(rapid),
            config='dhcp-generate-names=tag:pool\ndomain=test\n',
            events=[dict(kind=1 if rapid else 3, rapid=rapid, name=name)]))
for rapid in [False, True]:
    cases.append(dict(name='host-domain-mismatch-' + str(rapid),
        config='addn-hosts={hosts}\ndomain=test\n', hosts='127.0.0.30 authoritative.other\n',
        events=[dict(kind=1 if rapid else 3, rapid=rapid, name='claimed')]))
for case in cases:
    rows = {side: dhcp.execute(command, case, a.out / f'{case["name"]}-{side}')
            for side, command in commands.items()}
    report['dhcp'].append(dict(name=case['name'], config=case['config'], observed=rows,
        fix_matches_c=rows['fix'] == rows['c'], main_matches_c=rows['main'] == rows['c']))
    save()
    print(case['name'], rows['fix'] == rows['c'], flush=True)
print(json.dumps({kind: {'count': len(report[kind]), 'fix_c': sum(r['fix_matches_c'] for r in report[kind]),
    'main_c': sum(r['main_matches_c'] for r in report[kind])} for kind in ['config', 'dhcp']}))
