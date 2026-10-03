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
from pathlib import Path
import signal
import socket
import subprocess
import time

from dhcp_boot_service_diff import packet as base_packet, options
from m2_rootfs import command, prepare, process_identity, sha256, STOCK_SHA256


# Names and types from exact C dhcp-common.c::opttab, not the Rust parser.
NAMED_OPTIONS = [('netmask', 1, '192.0.2.10'), ('time-offset', 2, '7'), ('router', 3, '192.0.2.10'), ('dns-server', 6, '192.0.2.10'), ('log-server', 7, '192.0.2.10'), ('lpr-server', 9, '192.0.2.10'), ('boot-file-size', 13, '7'), ('domain-name', 15, 'example.test'), ('swap-server', 16, '192.0.2.10'), ('root-path', 17, 'example.test'), ('extension-path', 18, 'example.test'), ('ip-forward-enable', 19, '7'), ('non-local-source-routing', 20, '7'), ('policy-filter', 21, '192.0.2.10'), ('max-datagram-reassembly', 22, '7'), ('default-ttl', 23, '7'), ('mtu', 26, '7'), ('all-subnets-local', 27, '7'), ('router-discovery', 31, '7'), ('router-solicitation', 32, '192.0.2.10'), ('static-route', 33, '192.0.2.10'), ('trailer-encapsulation', 34, '7'), ('arp-timeout', 35, '7'), ('ethernet-encap', 36, '7'), ('tcp-ttl', 37, '7'), ('tcp-keepalive', 38, '7'), ('nis-domain', 40, 'example.test'), ('nis-server', 41, '192.0.2.10'), ('ntp-server', 42, '192.0.2.10'), ('netbios-ns', 44, '192.0.2.10'), ('netbios-dd', 45, '192.0.2.10'), ('netbios-nodetype', 46, '7'), ('netbios-scope', 47, '7'), ('x-windows-fs', 48, '192.0.2.10'), ('x-windows-dm', 49, '192.0.2.10'), ('T1', 58, '180s'), ('T2', 59, '180s'), ('vendor-class', 60, '7'), ('nis+-domain', 64, 'example.test'), ('nis+-server', 65, '192.0.2.10'), ('tftp-server', 66, 'example.test'), ('bootfile-name', 67, 'example.test'), ('mobile-ip-home', 68, '192.0.2.10'), ('smtp-server', 69, '192.0.2.10'), ('pop3-server', 70, '192.0.2.10'), ('nntp-server', 71, '192.0.2.10'), ('irc-server', 74, '192.0.2.10'), ('user-class', 77, '7'), ('rapid-commit', 80, '7'), ('last-transaction', 91, '180s'), ('associated-ip', 92, '192.0.2.10'), ('client-arch', 93, '7'), ('client-interface-id', 94, '7'), ('client-machine-id', 97, '7'), ('posix-timezone', 100, 'example.test'), ('tzdb-timezone', 101, 'example.test'), ('ipv6-only', 108, '7'), ('captive-portal', 114, 'example.test'), ('domain-search', 119, 'example.test'), ('sip-server', 120, 'example.test'), ('classless-static-route', 121, '192.0.2.0/24,127.0.0.1'), ('vendor-id-encap', 125, '7'), ('tftp-server-address', 150, '192.0.2.10'), ('server-ip-address', 255, '192.0.2.10')]

def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def request(item, xid):
    wire = bytearray(base_packet(item, xid)[:-1])
    if 'mac' in item:
        wire[28:34] = bytes.fromhex(item['mac'])
    for code, value in item.get('extra', []):
        value = bytes.fromhex(value)
        assert len(value) <= 255
        wire.extend(bytes([code, len(value)]) + value)
    wire.append(255)
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
    return ('no-hosts\nno-resolv\ninterface=lo\nlisten-address=127.0.0.1\nport=15353\nno-ping\n'
            'dhcp-authoritative\ndomain=pool.test\n'
            'dhcp-range=set:range,127.0.0.10,127.0.0.50,255.0.0.0,600s\n'
            'dhcp-host=02:00:00:00:00:01,127.0.0.40,fixed,600s\n'
            'dhcp-leasefile=/m2/family.leases\npid-file=/m2/family.pid\n' + extra)


def run(root, side, folder, text, events):
    folder.mkdir()
    (folder/'config').write_text(text)
    (root/'m2/family.conf').write_text(text)
    for path in ('family.leases','family.pid'):
        (root/'m2'/path).unlink(missing_ok=True)
    trace={'status':'failed','rows':[]}; process=None
    with (folder/'daemon.log').open('w') as log, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.bind(('0.0.0.0',68)); client.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        client.setsockopt(socket.SOL_SOCKET,25,b'lo\0'); client.settimeout(.8)
        try:
            process=subprocess.Popen(command(root,side,'-k','-C','/m2/family.conf'),stdout=log,stderr=log,start_new_session=True)
            deadline=time.monotonic()+5
            while True:
                assert process.poll() is None, 'daemon exited before readiness'
                try:
                    with socket.create_connection(('127.0.0.1',15353),.05): break
                except OSError:
                    assert time.monotonic()<deadline, 'readiness timeout'
                    time.sleep(.01)
            trace['identity']=process_identity(root,process.pid)
            for index,event in enumerate(events):
                wire=request(event,0xa100+index)
                (folder/f'{index:03}.request').write_bytes(wire)
                client.sendto(wire,('255.255.255.255',67))
                try: response,peer=client.recvfrom(65535)
                except socket.timeout:
                    assert event.get('no_reply'), 'unexpected DHCP timeout'
                    trace['rows'].append({'label':event['label'],'no_reply':True})
                    continue
                assert not event.get('no_reply'), 'ignored client received reply'
                assert response[0]==2 and response[4:8]==wire[4:8], 'invalid response header'
                (folder/f'{index:03}.response').write_bytes(response)
                leases=(root/'m2/family.leases').read_text()
                (folder/f'{index:03}.leases').write_text(leases)
                normalized=[]
                for line in leases.splitlines():
                    fields=line.split(); expiry=int(fields[0])
                    assert expiry==0 or int(time.time())+597 <= expiry <= int(time.time())+601
                    fields[0]='finite-600' if expiry else 'infinite'; normalized.append(fields)
                trace['rows'].append({'label':event['label'],'reply':response.hex(),'peer':list(peer),'options':options(response),'leases':sorted(normalized)})
            trace['status']='ok'
        except Exception as error:
            trace['error']=repr(error)
        finally:
            if process is not None:
                if process.poll() is None: os.killpg(process.pid,signal.SIGTERM)
                try: process.wait(3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL); process.wait(3); trace['forced_cleanup']=True
                trace['exit']=process.returncode
                trace['reaped']=not Path(f'/proc/{process.pid}').exists()
                trace['pid_removed']=not (root/'m2/family.pid').exists()
                if trace['exit']!=0 or not trace['reaped'] or not trace['pid_removed']:
                    trace['status']='failed'
            save(folder/'trace.json',trace)
    return trace


def compare(expected,actual):
    errors=[]
    if expected.get('status')!='ok' or actual.get('status')!='ok': errors.append('failed-side')
    if len(expected['rows'])!=len(actual['rows']): errors.append('row-count')
    for index,(left,right) in enumerate(zip(expected['rows'],actual['rows'])):
        if left!=right: errors.append(f'row-{index}')
    return errors


def corpus(path):
    path.mkdir(parents=True,exist_ok=True)
    for label,text,events in fixtures():
        config_dir=path/'config_line'; config_dir.mkdir(exist_ok=True)
        for index,line in enumerate(text.splitlines()):
            (config_dir/f'{label}-{index}').write_bytes(line.encode())
        packet_dir=path/'dhcp_packet'; packet_dir.mkdir(exist_ok=True)
        for index,event in enumerate(events):
            wire=request(event,0xa100+index)
            (packet_dir/f'{label}-{index}').write_bytes(wire)
    for label,text in parser_cases():
        (path/'config_line'/label).write_bytes(text.rstrip().encode())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path)
    parser.add_argument('--rust-binary',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--case',action='append')
    parser.add_argument('--c-only',action='store_true')
    parser.add_argument('--emit-corpus',type=Path)
    args=parser.parse_args()
    if args.emit_corpus:
        corpus(args.emit_corpus); return 0
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1' and os.geteuid()==0
    assert sorted(name for _,name in socket.if_nameindex())==['lo']
    assert args.out and 'private' in args.out.resolve().parts and not args.out.exists()
    args.out.mkdir(parents=True)
    root=prepare(args.image_root,None,args.out/'image',args.rust_binary)
    # Both daemons drop privileges after creating the PID file. Its parent
    # must permit removal by the daemon, as the real runtime directory does.
    (root/'m2').chmod(0o777)
    cases=[case for case in fixtures() if not args.case or case[0] in args.case]
    assert cases, 'no selected family cases'
    save(args.out/'plan.json',{'service':cases,'parser':parser_cases()})
    report={'c_sha256':sha256(root/'usr/sbin/dnsmasq'),'rust_sha256':sha256(root/'usr/sbin/dnsmasq-rs'),
            'cases':[],'parser':[],'failures':[],'negative_controls':[]}
    assert report['c_sha256']==STOCK_SHA256
    for label,extra,events in cases:
        folder=args.out/label; folder.mkdir()
        left=run(root,'c',folder/'c',config(extra),events)
        if args.c_only:
            errors=[] if left['status']=='ok' else ['c-failed']
        else:
            right=run(root,'rust',folder/'rust',config(extra),events)
            errors=compare(left,right)
            if left['status']=='ok' and left['rows']:
                changed=copy.deepcopy(left); changed['rows'][0]['reply']='mutated'
                assert compare(left,changed), 'changed reply negative control missed'
                omitted=copy.deepcopy(left); omitted['rows'].pop()
                assert 'row-count' in compare(left,omitted), 'missing row negative control missed'
                report['negative_controls'].append(label)
        report['cases'].append({'name':label,'errors':errors})
        if errors: report['failures'].append(label)
        save(args.out/'summary.json',report)
    for label,text in parser_cases():
        row={'name':label}
        (root/'m2/parser.conf').write_text(text)
        for side in ('c',) if args.c_only else ('c','rust'):
            result=subprocess.run(command(root,side,'--test','-C','/m2/parser.conf'),capture_output=True,timeout=5)
            row[side]=result.returncode
            (args.out/f'parser-{label}-{side}.stdout').write_bytes(result.stdout)
            (args.out/f'parser-{label}-{side}.stderr').write_bytes(result.stderr)
        if not args.c_only and row['c']!=row['rust']: report['failures'].append('parser-'+label)
        report['parser'].append(row)
    save(args.out/'summary.json',report)
    print(json.dumps({'cases':len(report['cases']),'failures':report['failures']}))
    return bool(report['failures'])


if __name__=='__main__':
    raise SystemExit(main())
