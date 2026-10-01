#!/usr/bin/env python3
"""Exact C/Rust DHCP-file-DNS publication and removal integration gate.

Run only via run_isolated.sh. Uses a private lease file, hosts file and loopback
DNS/DHCP/upstream sockets. Expected DNS packets and ordered side effects come
from C. A reply received from DHCP is immediately followed by a DNS query; the
tester does not wait for delayed publication to conceal ACK/DNS ordering bugs.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import time

from dhcp_lease_lifecycle import Daemon, rows
from dns_service_probe import query, read_name, rr, semantics, exact_read

PORT = 15353


class Upstream:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0)); self.socket.settimeout(.025)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event(); self.events = []; self.errors = []
        self.thread = threading.Thread(target=self.run); self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: packet, peer = self.socket.recvfrom(65535)
            except socket.timeout: continue
            try:
                host, end = read_name(packet, 12)
                kind, cls = struct.unpack_from('!HH', packet, end)
                self.events.append([host, kind, cls])
                positive = host == 'client1' and kind == 1
                response = packet[:2] + struct.pack('!5H', 0x8180 if positive else 0x8183, 1, int(positive), 0, 0)
                response += packet[12:end+4]
                if positive: response += rr(1, bytes([198, 51, 100, 7]), 120)
                self.socket.sendto(response, peer)
            except Exception as error: self.errors.append(repr(error))

    def close(self):
        self.stop.set(); self.thread.join(2); self.socket.close()
        assert not self.thread.is_alive() and not self.errors, self.errors


def ask(host, kind, ident, tcp=False):
    request = query(host, kind, ident)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(2); client.connect(('127.0.0.1', PORT))
        if tcp:
            client.sendall(struct.pack('!H', len(request))+request)
            packet = exact_read(client, struct.unpack('!H', exact_read(client, 2))[0])
        else:
            client.send(request); packet = client.recv(65535)
    reply = semantics(packet)
    assert reply['id'] == ident
    return packet, reply


def run(binary, scenario, config, leasefile, hostsfile, output, upstream):
    checks = []; events = []; first = len(upstream.events)
    daemon = Daemon(binary, config, leasefile, output, checks, scenario)
    def dns(label, host, kind=1, tcp=False):
        packet, reply = ask(host, kind, 0x4100+len(events), tcp)
        events.append({'case':label, 'packet':packet.hex(), 'reply':reply,
                       'upstream':upstream.events[first:].copy()})
    def file(label):
        raw = leasefile.read_bytes(); value = rows(leasefile)
        (output/(label+'.leases')).write_bytes(raw)
        # Retain/check actual expiry against the ACK's wall-clock interval;
        # compare its meaning, not unrelated C/Rust run start timestamps.
        observed = []
        for row in value:
            row = dict(row)
            if row['expiry'] and daemon.responses:
                last = next(reply for reply in reversed(daemon.responses)
                            if reply['address'] == socket.inet_aton(row['address']).hex())
                assert int(last['sent'])+599 <= row['expiry'] <= int(last['received'])+601
                row['expiry'] = 'ack+600s'
            observed.append(row)
        events.append({'case':label, 'rows':observed})
    def hup(contents, marker):
        hostsfile.write_text(contents)
        daemon.process.send_signal(signal.SIGHUP)
        until = time.monotonic()+3
        while time.monotonic()<until:
            _, reply = ask('ready.test',1,0x4000)
            if any(item['data']==marker for item in reply['records']): return
            time.sleep(.01)
        raise AssertionError('hosts SIGHUP failed')
    try:
        daemon.start()
        if scenario == 'idle-expiry':
            # The first request after socket readiness must already observe
            # restored names. Do not wait for a late publication to catch up.
            _, reply=ask('restored9.leases.test',1,0x4001)
            assert any(item['data']=='127.0.0.19' for item in reply['records']), 'restored DNS name was not published before serving'
            dns('restored-short','restored9'); dns('restored-fqdn','restored9.leases.test',tcp=True)
            dns('restored-ptr','19.0.0.127.in-addr.arpa',12)
            daemon.wait_rows(lambda value:not value,12)
            events.append({'case':'expired-file','rows':rows(leasefile)})
            dns('expired-short','restored9'); dns('expired-fqdn','restored9.leases.test')
            dns('expired-ptr','19.0.0.127.in-addr.arpa',12)
            assert daemon.xid==0
        else:
            dns('forward-before-lease','client1')
            daemon.exchange(1,address='127.0.0.10')
            dns('offer-not-published','client1.leases.test')
            daemon.exchange(3,address='127.0.0.10',selecting=True)
            dns('ack-visible-short','client1'); dns('ack-visible-fqdn','client1.leases.test')
            dns('ack-visible-ptr','10.0.0.127.in-addr.arpa',12)
            dns('ack-cname-target','alias.test')
            dns('ack-fqdn-tcp','client1.leases.test',tcp=True)
            dns('live-aaaa','client1',28); dns('known-parent-nodata','leases.test',16)
            dns('old-nxdomain-before-lease','client2',28)
            daemon.exchange(1,client=2,address='127.0.0.11')
            daemon.exchange(3,client=2,address='127.0.0.11',selecting=True)
            dns('second-ack-visible','client2')
            dns('old-nxdomain-retained','client2',28)
            daemon.exchange(7,client=2,address='127.0.0.11')
            dns('second-release-visible','client2.leases.test')
            file('ack-file')
            hup('192.0.2.2 ready.test\n192.0.2.88 client1\n','192.0.2.2')
            dns('hosts-conflict-wins','client1'); dns('fqdn-survives-conflict','client1.leases.test')
            hup('192.0.2.3 ready.test\n','192.0.2.3')
            dns('lease-reappears-after-hup','client1')
            daemon.exchange(3,address='127.0.0.10')
            dns('renewal-visible','client1.leases.test'); file('renewal-file')
            daemon.stop(); daemon.start()
            dns('restart-short','client1'); dns('restart-fqdn','client1.leases.test')
            dns('restart-ptr','10.0.0.127.in-addr.arpa',12); file('restart-file')
            daemon.exchange(7,address='127.0.0.10')
            dns('release-short','client1'); dns('release-fqdn','client1.leases.test')
            dns('release-ptr','10.0.0.127.in-addr.arpa',12); file('release-file')
        daemon.stop()
        assert all(item['pass'] for item in checks), checks
        return events
    finally:
        daemon.stop()
        (output/'events.json').write_text(json.dumps(events,indent=2)+'\n')
        (output/'dhcp-checks.json').write_text(json.dumps(checks,indent=2)+'\n')
        (output/'dhcp-replies.json').write_text(json.dumps(daemon.responses,indent=2)+'\n')


def canonical(events):
    return [{key:value for key,value in row.items() if key!='packet'} for row in events]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c',type=Path,required=True);parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--inject-error',action='store_true')
    args=parser.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert not Path('/etc/openwrt_release').exists()
    out=args.out.resolve();assert 'private' in out.parts;out.mkdir(parents=True,exist_ok=False)
    upstream=Upstream()
    summary={'status':'failed','matched':0,'mismatches':[], 'identity':{name:hashlib.sha256(getattr(args,name).read_bytes()).hexdigest() for name in ('c','rust')}}
    try:
        for scenario in ('dora','idle-expiry'):
            work=out/scenario;work.mkdir()
            config=work/'dnsmasq.conf';leasefile=work/'leases';hostsfile=work/'hosts'
            config.write_text(f'''no-resolv
no-hosts
listen-address=127.0.0.1
port={PORT}
no-ping
dhcp-authoritative
dhcp-lease-max=150
dhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,127.255.255.255,600s
dhcp-leasefile={leasefile}
addn-hosts={hostsfile}
domain=leases.test
local-ttl=17
dhcp-ttl={0 if scenario=='idle-expiry' else 5}
cache-size=32
neg-ttl=30
server=127.0.0.1#{upstream.port}
cname=alias.test,client1.leases.test
''')
            results={}
            for implementation in ('c','rust'):
                directory=work/implementation;directory.mkdir()
                hostsfile.write_text('192.0.2.1 ready.test\n')
                leasefile.write_text('' if scenario=='dora' else f'{int(time.time())+8} 02:00:00:00:00:09 127.0.0.19 restored9 *\n')
                results[implementation]=run(getattr(args,implementation).resolve(),scenario,config,leasefile,hostsfile,directory,upstream)
            expected,actual=canonical(results['c']),canonical(results['rust'])
            assert len(expected)==len(actual)==(27 if scenario=='dora' else 7)
            reference = {event['case']:event for event in expected}
            if scenario=='dora':
                assert reference['offer-not-published']['reply']['flags'] & 15 == 3
                assert reference['ack-visible-short']['reply']['records'][0]['data'] == '127.0.0.10'
                assert reference['ack-visible-short']['reply']['records'][0]['ttl'] == 5
                assert reference['ack-visible-ptr']['reply']['records'][0]['data'] == 'client1.leases.test'
                assert reference['old-nxdomain-retained']['reply']['flags'] & 15 == 3
                assert reference['release-file']['rows'] == []
            else:
                assert reference['restored-ptr']['reply']['records'][0]['data'] == 'restored9.leases.test'
                assert reference['expired-file']['rows'] == []
            if args.inject_error and scenario=='dora': actual[2]['reply']['flags']^=1
            mutation=copy.deepcopy(expected);mutation[0]['reply']['flags']^=1
            assert canonical(results['c'])==expected and mutation!=expected
            for left,right in zip(expected,actual):
                if left==right:summary['matched']+=1
                else:summary['mismatches'].append({'scenario':scenario,'case':left['case'],'c':left,'rust':right})
        summary['status']='failed' if summary['mismatches'] else 'passed'
    except Exception as error:summary['error']=repr(error)
    finally:
        upstream.close()
        (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({key:value for key,value in summary.items() if key!='mismatches'}|{'mismatches':len(summary['mismatches'])}))
    return int(summary['status']!='passed')


if __name__=='__main__':raise SystemExit(main())
