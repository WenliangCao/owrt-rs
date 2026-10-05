#!/usr/bin/env python3
"""Exact-image listener contracts. Only disposable namespaces are accepted.

The normal entry runs both sides in separate sibling namespaces. Raw config,
wire packets, address flags, socket inventories, process identities and failed
runs remain in private evidence. --select is exploratory and cannot qualify.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import stop

HERE = Path(__file__).resolve().parent
DNS_PORT = 15353
V4 = {'lan': '10.77.0.1', 'wan': '10.78.0.1'}
V6 = {'lan': 'fd42:77::1', 'wan': 'fd42:78::1'}
PEER = {'lan': 'lpeer', 'wan': 'wpeer'}
MODES = {'wildcard': '', 'static': 'bind-interfaces\n', 'dynamic': 'bind-dynamic\n'}


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, text=True, timeout=5)


def ip(*args):
    return run('ip', *args)


def scenarios():
    rows = []
    def add(profile, mode, config='', actions=None, **extra):
        rows.append(dict(name=profile+'-'+mode, profile=profile, mode=mode,
                         config=MODES[mode]+config, actions=actions or [], **extra))
    for mode in MODES:
        for profile, config in [
            ('ordinary', ''), ('interface', 'interface=lan\n'),
            ('union', 'interface=lan\nlisten-address=10.78.0.1,fd42:78::1\nexcept-interface=wan\n'),
            ('listen-only', 'listen-address=10.77.0.1,fd42:77::1\n'),
            ('empty-interface', 'interface=\n'), ('empty-except', 'except-interface=\n'),
            ('wildcard-names', 'interface=l*ignored\nexcept-interface=w*\n'),
            ('wildcard-empty', 'interface=lan*\n'),
            ('alias', 'interface=lan:0\n'), ('alias-except', 'except-interface=lan:0\n'),
            ('same-link-local', ''), ('cross-ingress', 'interface=lan\n'),
            ('unowned-loopback', 'listen-address=127.0.0.2\n'),
            ('missing', 'interface=absent0\n'), ('no-address', 'interface=barren0\n'),
            ('down-link', 'interface=lan\n'),
        ]:
            add(profile, mode, config)
        for profile in ['address-change', 'recreate']:
            add(profile, mode, 'interface=lan\n', actions=[profile])
        for profile, config in [
            ('tftp', ''), ('tftp-dedicated', 'interface=lan\nenable-tftp=wan\n'),
            ('tftp-except', 'except-interface=wan\n'),
            ('tftp-no-dhcp', 'no-dhcp-interface=lan\n'),
            ('tftp-no-v4', 'no-dhcpv4-interface=lan\n'),
            ('tftp-alias', 'interface=lan:0\nenable-tftp=lan\n'),
        ]:
            add(profile, mode, config+'enable-tftp\ntftp-root=/m2/tftp\n', tftp=True)
        add('tftp-change', mode, 'interface=lan\nenable-tftp\ntftp-root=/m2/tftp\n',
            actions=['address-change'], tftp=True)
    for mode in ['static', 'dynamic']:
        for profile, extra in [('dad', ''), ('dad-explicit', 'listen-address=fd42:77::9\n'),
                               ('dad-failed', ''), ('dad-low-port', 'user=nobody\ngroup=nogroup\n')]:
            add(profile, mode, 'interface=lan\n'+extra, actions=['dad'], dad=True,
                port=53 if profile == 'dad-low-port' else DNS_PORT)
        add('tftp-dad', mode, 'interface=lan\nenable-tftp\ntftp-root=/m2/tftp\n',
            actions=['dad'], dad=True, tftp=True)
        add('missing-address', mode, 'listen-address=192.0.2.111\n')
        for transport in ['udp', 'tcp', 'tftp']:
            add('occupied-'+transport, mode, 'interface=lan\n'+(
                'enable-tftp\ntftp-root=/m2/tftp\n' if transport == 'tftp' else ''), blocker=transport)
    for profile in ['late-interface', 'late-address', 'duplicate-address',
                    'runtime-occupied-udp', 'runtime-occupied-tcp']:
        add(profile, 'dynamic', 'interface=lan,late0\n'+(
            'listen-address=192.0.2.111\n' if profile == 'late-address' else ''), actions=[profile])
    add('conflicting-modes', 'static', 'bind-dynamic\n')
    for mode in MODES:
        for profile, config in [('relay', 'interface=client0\n'),
                                ('relay-union', 'interface=absent0\nlisten-address=10.77.0.1\n'),
                                ('relay-except', 'except-interface=client0\n'),
                                ('relay-no-dhcp', 'no-dhcp-interface=client0\n'),
                                ('relay-recreate', 'interface=client0\n')]:
            # Static absent0 is correctly fatal; use an existing unrelated
            # interface to test the union without that separate failure.
            if profile == 'relay-union': config = 'interface=server0\nlisten-address=10.77.0.1\n'
            add(profile, mode, config+'dhcp-relay=10.77.0.1,10.78.0.2\n', relay=True)
    return rows


class Network:
    def __init__(self):
        self.holder = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'], start_new_session=True)
        deadline = time.monotonic()+3
        while os.readlink(f'/proc/{self.holder.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
            assert self.holder.poll() is None and time.monotonic()<deadline, 'peer namespace readiness'
            time.sleep(.01)
        self.exec('ip', 'link', 'set', 'lo', 'up')
        for link in ['lan', 'wan']:
            self.create(link)
        ip('link', 'add', 'barren0', 'type', 'dummy')
        ip('link', 'set', 'barren0', 'addrgenmode', 'none')
        ip('link', 'set', 'barren0', 'up')

    def argv(self, *args):
        return ['nsenter', '-t', str(self.holder.pid), '-n', *map(str, args)]

    def exec(self, *args):
        return run(*self.argv(*args))

    def create(self, link):
        peer = PEER[link]
        ip('link', 'add', link, 'type', 'veth', 'peer', 'name', peer)
        ip('link', 'set', link, 'addrgenmode', 'none')
        ip('link', 'set', peer, 'netns', self.holder.pid)
        self.exec('ip', 'link', 'set', peer, 'addrgenmode', 'none')
        ip('link', 'set', link, 'up')
        self.exec('ip', 'link', 'set', peer, 'up')
        for address in [V4[link]+'/24', V6[link]+'/64', 'fe80::1/64']:
            ip('addr', 'add', address, 'dev', link, *(['nodad'] if ':' in address else []))
        ip('addr', 'add', V4[link][:-1]+'3/24', 'dev', link, 'label', link+':0')
        for address in [V4[link][:-1]+'2/24', V6[link][:-1]+'2/64', 'fe80::2/64']:
            self.exec('ip', 'addr', 'add', address, 'dev', peer, *(['nodad'] if ':' in address else []))

    def close(self):
        result = stop(self.holder)
        for link in ['lan', 'wan', 'barren0', 'late0', 'dup0']:
            if subprocess.run(['ip', 'link', 'show', link], capture_output=True).returncode == 0:
                ip('link', 'del', link)
        return result


def wire_probe(item):
    """Executed inside a peer namespace; no external endpoint is accepted."""
    dest, link = item['destination'], item.get('link')
    family = socket.AF_INET6 if ':' in dest else socket.AF_INET
    kind = socket.SOCK_STREAM if item['transport']=='tcp' else socket.SOCK_DGRAM
    packet = b'\0\1boot.bin\0octet\0' if item['transport']=='tftp' else query('ready.test', ident=0x5e01)
    result = dict(request=packet.hex(), reply=None)
    with socket.socket(family, kind) as endpoint:
        endpoint.settimeout(.3)
        if link: endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, link.encode()+b'\0')
        target = (dest, item['port'])
        if family == socket.AF_INET6 and dest.startswith('fe80:'):
            target = (dest, item['port'], 0, socket.if_nametoindex(link))
        try:
            if kind == socket.SOCK_STREAM:
                endpoint.connect(target)
                endpoint.sendall(struct.pack('!H',len(packet))+packet)
                response = exact_read(endpoint, struct.unpack('!H',exact_read(endpoint,2))[0])
                peer = endpoint.getpeername()
            else:
                endpoint.sendto(packet, target)
                response, peer = endpoint.recvfrom(65535)
            result.update(reply=response.hex(), peer=list(peer))
            if item['transport']=='tftp' and response[:2]==b'\0\3':
                endpoint.sendto(b'\0\4'+response[2:4],peer)
        except OSError as error:
            result['error'] = type(error).__name__
    return result


def inventory(pid):
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        with contextlib.suppress(FileNotFoundError):
            target = os.readlink(fd)
            if target.startswith('socket:['): inodes.add(target[8:-1])
    result=[]
    for filename in ['udp','udp6','tcp','tcp6']:
        for line in Path('/proc/net/'+filename).read_text().splitlines()[1:]:
            parts=line.split()
            if parts[9] not in inodes or filename.startswith('tcp') and parts[3]!='0A': continue
            addr,port=parts[1].split(':')
            port=int(port,16)
            if port not in [DNS_PORT,53,69,67,4011]: continue
            raw=bytes.fromhex(addr)
            raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4))
            result.append(dict(transport=filename[:3],address=str(ipaddress.ip_address(raw)),port=port))
    return sorted(result,key=lambda row:(row['transport'],row['address'],row['port']))


def snapshot(path):
    save(path, {'links': json.loads(ip('-j','link').stdout), 'addresses': json.loads(ip('-j','addr').stdout),
                'ipv6_flags': Path('/proc/net/if_inet6').read_text()})


class Observer:
    def __init__(self, net, process, out, port):
        self.net,self.process,self.out,self.port=net,process,out,port
        self.rows=[]
    def sockets(self, label, delay=.25):
        time.sleep(delay)
        assert self.process.poll() is None, 'daemon exited during '+label
        value=inventory(self.process.pid)
        self.rows.append(dict(case=label, sockets=value))
        snapshot(self.out/(label+'-network.json'))
        return value
    def ask(self,label,dest,transport='udp',link=None,local=False):
        item=dict(destination=dest,transport=transport,link=link,port=69 if transport=='tftp' else self.port)
        if local: value=wire_probe(item)
        else: value=json.loads(self.net.exec(sys.executable, __file__, '--probe', json.dumps(item)).stdout)
        save(self.out/(label+'-wire.json'), value)
        for key in ['request','reply']:
            if value.get(key): (self.out/(label+'.'+key)).write_bytes(bytes.fromhex(value[key]))
        row=dict(case=label, answer=None)
        if value.get('reply'):
            reply=bytes.fromhex(value['reply'])
            if transport=='tftp': row['answer']=dict(packet=reply.hex(),source=value['peer'][0],dedicated=value['peer'][1]!=69)
            else: row['answer']=dict(semantic=semantics(reply),source=value['peer'][0])
        self.rows.append(row)
        return row
    def ordinary(self, tftp=False):
        self.sockets('initial')
        for link in ['lan','wan']:
            for dest,tag in [(V4[link],'v4'),(V6[link],'v6'),('fe80::1','scope'),(V4[link][:-1]+'3','alias')]:
                for transport in ['udp','tcp']+(['tftp'] if tftp else []):
                    self.ask(link+'-'+tag+'-'+transport,dest,transport,PEER[link])
        for dest,tag in [('127.0.0.1','lo4'),('::1','lo6'),('127.0.0.2','lo-extra')]:
            for transport in ['udp','tcp']+(['tftp'] if tftp else []):
                self.ask(tag+'-'+transport,dest,transport,local=True)


def relay_run(root,side,item,out):
    from m5_relay import Peer, packet, DOWN, UP, CLIENT, SERVER
    client=server=process=None
    rows=[]
    try:
        client,server=Peer('client0',DOWN,CLIENT),Peer('server0',UP,SERVER)
        config='port=15353\nno-hosts\nno-resolv\nuser=root\ngroup=root\npid-file=/m2/pid\nhost-record=ready.test,192.0.2.53\n'+item['config']
        (root/'m2/listeners.conf').write_text(config);(out/'config').write_text(config)
        with (out/'stderr').open('w') as stderr, (out/'stdout').open('w') as stdout:
            process=subprocess.Popen(command(root,side,'-d','-C','/m2/listeners.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
            time.sleep(.3)
            assert process.poll() is None, 'relay startup failed'
            save(out/'identity.json',process_identity(process.pid))
            def request(label):
                value=packet(xid=0x5e001122)
                (out/(label+'.request')).write_bytes(value)
                client.call(op='send',packet=value.hex(),destination=[DOWN,67],port=68)
                time.sleep(.35)
                incoming=server.call(op='take')['packets']
                save(out/(label+'-upstream.json'),incoming)
                rows.append(dict(case=label,packets=[dict(packet=p['packet'],source=p['source'],destination=p['destination']) for p in incoming]))
                if incoming:
                    response=packet(xid=0x5e001122,op=2,giaddr=DOWN)
                    server.call(op='send',packet=response.hex(),destination=[UP,67],port=67)
                    time.sleep(.35)
                    received=client.call(op='take')['packets']
                    save(out/(label+'-downstream.json'),received)
                    rows.append(dict(case=label+'-reply',packets=[dict(packet=p['packet'],source=p['source'],destination=p['destination']) for p in received]))
            request('relay-initial')
            if item['profile']=='relay-recreate':
                save(out/'recreate.json',client.recreate_client_link())
                time.sleep(.3);request('relay-recreated')
            rows.append(dict(case='sockets',sockets=inventory(process.pid)))
    finally:
        ended=stop(process)
        cleanup=dict(daemon=ended,client=client.close() if client else None,server=server.close() if server else None)
        save(out/'cleanup.json',cleanup)
    rows.append(dict(case='exit',exit=ended['returncode'],forced=ended['forced']))
    return rows


def execute(root,side,item,out):
    if item.get('relay'): return relay_run(root,side,item,out)
    net=process=blocker=None
    observer=None
    rows=[]
    try:
        net=Network()
        profile,mode=item['profile'],item['mode']
        if profile=='down-link': ip('link','set','lan','down')
        if item.get('dad'):
            Path('/proc/sys/net/ipv6/neigh/lan/retrans_time_ms').write_text('3000')
            Path('/proc/sys/net/ipv6/conf/lan/dad_transmits').write_text('1')
            if profile=='dad-failed':
                net.exec('ip','-6','addr','add','fd42:77::9/64','dev','lpeer','nodad')
            ip('-6','addr','add','fd42:77::9/64','dev','lan')
        snapshot(out/'startup-network.json')
        port=item.get('port',DNS_PORT)
        if item.get('blocker'):
            transport=item['blocker']
            blocker=socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM)
            blocker.bind((V4['lan'],69 if transport=='tftp' else port))
            if transport=='tcp': blocker.listen(1)
        config=f'port={port}\nno-hosts\nno-resolv\nuser=root\ngroup=root\npid-file=/m2/pid\nhost-record=ready.test,192.0.2.53\n'+item['config']
        (root/'m2/listeners.conf').write_text(config);(out/'config').write_text(config)
        with (out/'stderr').open('w') as stderr,(out/'stdout').open('w') as stdout:
            process=subprocess.Popen(command(root,side,'-d','-C','/m2/listeners.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
            observer=Observer(net,process,out,port)
            time.sleep(.2)
            rows.append(dict(case='startup',exit=process.poll()))
            if process.poll() is not None:
                return rows
            save(out/'identity.json',process_identity(process.pid))
            if item.get('dad'):
                sockets=observer.sockets('dad-tentative',.01)
                assert any('tentative' in a.get('flags',[]) for link in json.loads(ip('-j','addr','show','dev','lan').stdout) for a in link['addr_info'] if a['local']=='fd42:77::9'), 'DAD matured before witness'
                assert not any(row['address']=='fd42:77::9' for row in sockets),'bound a tentative address'
                observer.ask('dad-live-udp',V4['lan'],link='lpeer')
                time.sleep(4)
                observer.sockets('dad-finished',0)
                for transport in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):
                    observer.ask('dad-final-'+transport,'fd42:77::9',transport,'lpeer')
                observer.ask('dad-surviving-udp',V4['lan'],link='lpeer')
            elif profile.startswith('runtime-occupied-'):
                transport=profile.rsplit('-',1)[1]
                observer.sockets('before-occupied')
                blocker=socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM)
                blocker.setsockopt(socket.SOL_IP,15,1) # IP_FREEBIND: block before address addition.
                blocker.bind(('10.77.0.9',port))
                if transport=='tcp':blocker.listen(1)
                ip('addr','add','10.77.0.9/24','dev','lan')
                observer.sockets('partial-occupied')
                for proto in ['udp','tcp']: observer.ask('partial-'+proto,'10.77.0.9',proto,'lpeer')
                blocker.close();blocker=None
                observer.sockets('after-blocker-release')
                ip('addr','del','10.77.0.9/24','dev','lan')
                observer.sockets('partial-removed')
            else:
                observer.ordinary(item.get('tftp',False))
                for action in item['actions']:
                    if action=='address-change':
                        for addr in ['10.77.0.9/24','fd42:77::9/64']:
                            ip('addr','add',addr,'dev','lan',*(['nodad'] if ':' in addr else []))
                        observer.sockets('added')
                        for addr,tag in [('10.77.0.9','v4'),('fd42:77::9','v6')]:
                            for proto in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):observer.ask('added-'+tag+'-'+proto,addr,proto,'lpeer')
                        ip('addr','del','10.77.0.9/24','dev','lan');ip('-6','addr','del','fd42:77::9/64','dev','lan')
                        observer.sockets('removed')
                        observer.ask('surviving',V4['lan'],link='lpeer')
                    elif action=='recreate':
                        old=socket.if_nametoindex('lan');ip('link','del','lan');observer.sockets('link-deleted')
                        net.create('lan');assert socket.if_nametoindex('lan')!=old,'ifindex reused'
                        observer.sockets('link-recreated')
                        for dest,tag in [(V4['lan'],'v4'),(V6['lan'],'v6'),('fe80::1','scope')]:
                            for proto in ['udp','tcp']:observer.ask('recreated-'+tag+'-'+proto,dest,proto,'lpeer')
                    elif action in ['late-interface','late-address']:
                        ip('link','add','late0','type','dummy');ip('link','set','late0','addrgenmode','none');ip('link','set','late0','up')
                        ip('addr','add','192.0.2.111/24','dev','late0')
                        observer.sockets('late-created')
                        for proto in ['udp','tcp']:observer.ask('late-'+proto,'192.0.2.111',proto,local=True)
                        ip('link','del','late0');observer.sockets('late-removed')
                    elif action=='duplicate-address':
                        ip('link','add','dup0','type','dummy');ip('link','set','dup0','addrgenmode','none');ip('link','set','dup0','up')
                        ip('addr','add',V4['lan']+'/24','dev','dup0');observer.sockets('duplicate-added')
                        ip('addr','del',V4['lan']+'/24','dev','lan');observer.sockets('first-owner-removed')
                        observer.ask('duplicate-owner',V4['lan'],local=True)
                        ip('link','del','dup0');observer.sockets('last-owner-removed')
                if profile=='cross-ingress':
                    net.exec('ip','route','add',V4['lan']+'/32','dev','wpeer')
                    net.exec('ip','-6','route','add',V6['lan']+'/128','dev','wpeer')
                    for dest,tag in [(V4['lan'],'v4'),(V6['lan'],'v6')]:
                        for proto in ['udp','tcp']:observer.ask('cross-'+tag+'-'+proto,dest,proto,'wpeer')
            rows.extend(observer.rows)
    finally:
        ended=stop(process)
        if blocker: blocker.close()
        peer=net.close() if net else None
        save(out/'cleanup.json',dict(daemon=ended,peer=peer))
    rows.append(dict(case='exit',exit=ended['returncode'],forced=ended['forced']))
    return rows


def side_run(args):
    cases=scenarios()
    if args.select: cases=[item for item in cases if item['name'] in args.select]
    args.out.mkdir(parents=True,exist_ok=False)
    root=prepare(args.image_root,None,args.out/args.side,args.rust_binary)
    (root/'m2/tftp').mkdir();(root/'m2/tftp/boot.bin').write_bytes(b'synthetic listener boot\n')
    (root/'m2/tftp/boot.bin').chmod(0o644)
    rows=[]
    failures=[]
    for item in cases:
        out=args.out/item['name'];out.mkdir()
        try:
            observed=execute(root,args.side,item,out)
            rows.append(dict(name=item['name'],rows=observed))
            print(json.dumps(dict(side=args.side,case=item['name'],rows=len(observed))),flush=True)
        except Exception as error:
            save(out/'failure.json',dict(error=repr(error)))
            failures.append(dict(name=item['name'],error=repr(error)))
            print(json.dumps(failures[-1]),flush=True)
    result=dict(side=args.side,rows=rows,failures=failures,selected=args.select,
                binary_sha256=sha256(args.rust_binary if args.side=='rust' else args.image_root/'usr/sbin/dnsmasq'))
    save(args.out/'observed.json',result)
    return bool(failures)


def validate(result,cases):
    failures=[]
    if result.get('failures')!=[]: failures.append('runtime failures')
    if [row['name'] for row in result.get('rows',[])]!=[item['name'] for item in cases]: failures.append('missing/extra/reordered cases')
    for value,item in zip(result.get('rows',[]),cases):
        observations=value['rows']
        if not observations:failures.append(item['name']+': empty observation')
        startup=next((row for row in observations if row['case']=='startup'),None)
        expected_failure=(item['profile'] in ['conflicting-modes'] or item.get('blocker') or
                          item['mode']=='static' and item['profile'] in ['missing','no-address','missing-address'])
        if startup and (startup['exit'] is not None)!=bool(expected_failure): failures.append(item['name']+': unexpected startup')
        if startup and expected_failure and startup['exit']!= (1 if item['profile']=='conflicting-modes' else 2):failures.append(item['name']+': wrong startup exit')
        if not expected_failure:
            ended=next((row for row in observations if row['case']=='exit'),None)
            if not ended or ended.get('exit')!=0 or ended.get('forced'): failures.append(item['name']+': incomplete cleanup')
    return failures


def compare(left,right,cases):
    failures=[dict(side=side,error=error) for side,value in [('c',left),('rust',right)] for error in validate(value,cases)]
    for c,r in zip(left.get('rows',[]),right.get('rows',[])):
        if c!=r: failures.append(dict(name=c['name'],c=c,rust=r))
    return failures


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path)
    parser.add_argument('--rust-binary',type=Path)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--side',choices=['c','rust'])
    parser.add_argument('--select',action='append')
    parser.add_argument('--probe')
    parser.add_argument('--freeze',action='store_true')
    args=parser.parse_args()
    if args.probe: print(json.dumps(wire_probe(json.loads(args.probe))));return 0
    checklist=json.loads((HERE/'m5_listeners.json').read_text())
    cases=scenarios()
    if args.freeze:
        checklist['required_cases']=[item['name'] for item in cases]
        checklist['cases']=cases
        save(HERE/'m5_listeners.json',checklist)
        return 0
    assert checklist['required_cases']==[item['name'] for item in cases], 'case inventory differs from frozen C checklist'
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1' and os.geteuid()==0,'use run_isolated.sh'
    assert args.image_root and args.rust_binary and args.out
    if args.side:return side_run(args)
    args.out.mkdir(parents=True,exist_ok=False)
    save(args.out/'plan.json',checklist)
    save(args.out/'tools.json',{name:sha256(HERE/name) for name in ['m5_listeners.py','m5_listeners.json','m2_rootfs.py','run_isolated.sh']})
    exits={}
    for side in ['c','rust']:
        argv=['sh',str(HERE/'run_isolated.sh'),sys.executable,str(Path(__file__).resolve()),
              '--side',side,'--image-root',str(args.image_root),'--rust-binary',str(args.rust_binary),'--out',str(args.out/side)]
        for name in args.select or []:argv.extend(['--select',name])
        process=subprocess.run(argv)
        exits[side]=process.returncode
    selected=[item for item in cases if not args.select or item['name'] in args.select]
    left,right=[json.loads((args.out/side/'observed.json').read_text()) for side in ['c','rust']]
    failures=compare(left,right,selected)
    controls=[]
    if not failures:
        corrupt=copy.deepcopy(right)
        corrupt['rows'].pop()
        controls.append(dict(name='missing-case',rejected=bool(compare(left,corrupt,selected))))
        corrupt=copy.deepcopy(right);corrupt['failures']=[dict(error='injected')]
        controls.append(dict(name='failure-inventory',rejected=bool(compare(left,corrupt,selected))))
        for index,row in enumerate(right['rows']):
            reply=next((row for row in row['rows'] if row.get('answer')),None)
            if reply:
                corrupt=copy.deepcopy(right)
                target=next(row for row in corrupt['rows'][index]['rows'] if row.get('answer'))
                target['answer']=None
                controls.append(dict(name='lost-service-'+row['name'],rejected=bool(compare(left,corrupt,selected))))
    result=dict(cases=len(selected),observations=sum(len(row['rows']) for row in right['rows']),failures=failures,
                exits=exits,negative_controls=controls,binary_sha256=right['binary_sha256'],bytes=args.rust_binary.stat().st_size,
                qualified=not failures and not args.select and all(row['rejected'] for row in controls))
    save(args.out/'result.json',result)
    print(json.dumps(dict(cases=result['cases'],observations=result['observations'],failures=len(failures),qualified=result['qualified'])))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
