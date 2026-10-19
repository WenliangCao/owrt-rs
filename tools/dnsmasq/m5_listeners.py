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
import ctypes
import hashlib
import ipaddress
import json
import os
import platform
import re
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import exact_read, query, semantics
from m2_rootfs import bind_unix_socket, command, prepare, process_identity, sha256
from test_single_poll_service import stop

HERE = Path(__file__).resolve().parent
DNS_PORT = 15353
V4 = {'lan': '10.77.0.1', 'wan': '10.78.0.1'}
V6 = {'lan': 'fd42:77::1', 'wan': 'fd42:78::1'}
PEER = {'lan': 'lpeer', 'wan': 'wpeer'}
MODES = {'wildcard': '', 'static': 'bind-interfaces\n', 'dynamic': 'bind-dynamic\n'}
RECOVERY_PROFILES = {'runtime-shared-dns-both', 'runtime-shared-all'}


def recovery_case(item):
    return item['mode']=='dynamic' and item['profile'] in RECOVERY_PROFILES


def recovery_sockets(item, label, side):
    """Exact fixture inventories; C keeps its documented iface->done defect."""
    protocols = [('tcp', DNS_PORT), ('udp', 69), ('udp', DNS_PORT)]
    rows = [dict(transport=proto, address=address, port=port)
            for address in [V4['lan'], '127.0.0.1', '::1', V6['lan'], 'fe80::1']
            for proto,port in protocols]
    if label not in ['shared-before', 'shared-removed']:
        recovered = (label=='shared-released' and side=='rust' or
                     label=='shared-trigger' and (side=='rust' or item['profile']=='runtime-shared-all'))
        added = protocols if recovered else [('udp', 69)] if item['profile']=='runtime-shared-dns-both' else []
        rows.extend(dict(transport=proto, address='10.77.0.9', port=port) for proto,port in added)
    if label=='shared-trigger':
        rows.extend(dict(transport=proto, address='10.77.0.10', port=port) for proto,port in protocols)
    return sorted(rows, key=lambda row:(row['transport'],row['address'],row['port']))


def recovery_reply(case):
    source=V4['lan'] if case.startswith('shared-healthy-') else '10.77.0.9'
    if case.endswith('-tftp'):
        return dict(packet=(b'\0\3\0\1synthetic listener boot\n').hex(), source=source, dedicated=True)
    return {'source':source, 'semantic':{'flags':0x8580, 'id':0x5e01,
        'questions':[['ready.test',1,1]], 'records':[{'section':'answer','name':'ready.test',
        'type':1,'class':1,'ttl':0,'data':'192.0.2.53'}]}}


def recovery_difference(item, c, rust):
    if not recovery_case(item) or c==rust or c['case']!=rust['case']:return False
    case=c['case']
    if case in ['shared-released','shared-trigger']:
        return (set(c)==set(rust)=={'case','sockets','preserved_healthy_sockets'} and
                c['preserved_healthy_sockets'] is rust['preserved_healthy_sockets'] is True and
                c['sockets']==recovery_sockets(item,case,'c') and
                rust['sockets']==recovery_sockets(item,case,'rust'))
    if (case.startswith(('shared-after-release-','shared-after-trigger-')) and
            not expected_answer(item,case,'c') and expected_answer(item,case,'rust')):
        return c==dict(case=case,answer=None) and rust==dict(case=case,answer=recovery_reply(case))
    return False


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
        for label,number in [('einval',22),('eafnosupport',97),('eprotonosupport',93)]:
            add('socket-unsupported-'+label,mode,'enable-tftp\ntftp-root=/m2/tftp\n',tftp=True,socket_errno=number)
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
            ('explicit-any4', 'listen-address=0.0.0.0\n'),
            ('explicit-any6', 'listen-address=::\n'),
            ('unowned-scope', 'listen-address=fe80::ff\n'),
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
        add('tftp-single-scope', mode, 'enable-tftp\ntftp-root=/m2/tftp\ntftp-single-port\n', tftp=True)
        add('tftp-only', mode, 'interface=lan\nenable-tftp\ntftp-root=/m2/tftp\n', tftp=True,port=0)
        add('unowned-loopback-change',mode,'listen-address=127.0.0.2\n',actions=['unowned-loopback-change'])
        add('tftp-unowned-loopback-change',mode,'listen-address=127.0.0.2\nenable-tftp\ntftp-root=/m2/tftp\n',actions=['unowned-loopback-change'],tftp=True)
    add('socket-unsupported-udp','static','enable-tftp\ntftp-root=/m2/tftp\n',tftp=True,socket_errno=22,socket_kind=2)
    add('socket-unsupported-tcp','dynamic','enable-tftp\ntftp-root=/m2/tftp\n',tftp=True,socket_errno=97,socket_kind=1)
    for mode in ['static', 'dynamic']:
        for profile, extra in [('dad', ''), ('dad-explicit', 'listen-address=fd42:77::9\n'),
                               ('dad-failed', ''), ('dad-low-port', 'user=nobody\ngroup=nogroup\n')]:
            add(profile, mode, 'interface=lan\n'+extra, actions=['dad'], dad=True,
                port=53 if profile == 'dad-low-port' else DNS_PORT)
        add('tftp-dad', mode, 'interface=lan\nenable-tftp\ntftp-root=/m2/tftp\n',
            actions=['dad'], dad=True, tftp=True)
        add('tftp-dad-low-port', mode, 'interface=lan\nenable-tftp\ntftp-root=/m2/tftp\nuser=nobody\ngroup=nogroup\n',
            actions=['dad'], dad=True, tftp=True,port=0)
        add('missing-address', mode, 'listen-address=192.0.2.111\n')
        add('missing-address-v6', mode, 'listen-address=fd42:ffff::1\n')
        for transport in ['udp', 'tcp', 'tftp']:
            add('occupied-'+transport, mode, 'interface=lan\n'+(
                'enable-tftp\ntftp-root=/m2/tftp\n' if transport == 'tftp' else ''), blocker=transport)
            add('occupied-'+transport+'-v6', mode, 'interface=lan\n'+(
                'enable-tftp\ntftp-root=/m2/tftp\n' if transport == 'tftp' else ''), blocker=transport,blocker_v6=True)
    for profile in ['late-interface', 'late-address', 'duplicate-address',
                    'runtime-occupied-udp', 'runtime-occupied-tcp']:
        add(profile, 'dynamic', 'interface=lan,'+('dup0' if profile=='duplicate-address' else 'late0')+'\n'+(
            'listen-address=192.0.2.111\n' if profile == 'late-address' else ''), actions=[profile])
    add('conflicting-modes', 'static', 'bind-dynamic\n')
    add('tftp-unowned-dedicated','static','listen-address=127.0.0.2\nenable-tftp=wan\ntftp-root=/m2/tftp\n',tftp=True)
    add('tftp-unowned-dedicated','dynamic','listen-address=127.0.0.2\nenable-tftp=wan\ntftp-root=/m2/tftp\n',tftp=True)
    add('tftp-static-renamed','static','interface=lan\nenable-tftp=lan\ntftp-root=/m2/tftp\ntftp-root=/m2/tftp/lan,lan\n',tftp=True)
    add('tftp-late-address','dynamic','interface=lan,late0\nlisten-address=192.0.2.111\nenable-tftp\ntftp-root=/m2/tftp\n',actions=['late-address'],tftp=True)
    for profile in ['runtime-shared-tftp','runtime-shared-dns-both','runtime-shared-all']:
        add(profile,'dynamic','interface=lan\nenable-tftp\ntftp-root=/m2/tftp\n',tftp=True)
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
        try:
            for link in ['lan', 'wan']:
                self.create(link)
            ip('link', 'add', 'barren0', 'type', 'dummy')
            ip('link', 'set', 'barren0', 'addrgenmode', 'none')
            ip('link', 'set', 'barren0', 'up')
        except Exception:
            self.close()
            raise

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
        for link in ['lan', 'wan', 'barren0', 'late0', 'dup0','retired0']:
            if subprocess.run(['ip', 'link', 'show', link], capture_output=True).returncode == 0:
                deleted=subprocess.run(['ip','link','del',link],capture_output=True)
                if deleted.returncode and subprocess.run(['ip','link','show',link],capture_output=True).returncode==0:
                    deleted.check_returncode()
        return result


class Syslog:
    def __init__(self,root,out):
        self.path=root/'dev/log'
        self.out=out
        self.endpoint=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
        bind_unix_socket(self.endpoint,self.path)
        self.path.chmod(0o666)
        self.endpoint.setblocking(False)
        self.packets=[]
    def drain(self):
        while True:
            try:self.packets.append(self.endpoint.recv(65535))
            except BlockingIOError:break
    def close(self):
        self.drain();self.endpoint.close();self.path.unlink()
        save(self.out/'syslog.json',[dict(packet=value.hex(),text=value.decode('utf-8','replace')) for value in self.packets])
        messages=[]
        for value in self.packets:
            text=value.decode('utf-8','replace')
            if 'failed to create listening socket for ' in text:
                match=re.search(r'<(\d+)>',text)
                messages.append(dict(priority=int(match.group(1)) if match else None,
                    text=text[text.index('failed to create listening socket for '):].rstrip('\x00\n')))
        return messages


def wire_probe(item):
    """Executed inside a peer namespace; no external endpoint is accepted."""
    dest, link = item['destination'], item.get('link')
    allowed=set(V4.values())|set(V6.values())|{'10.77.0.3','10.78.0.3','10.77.0.9','fd42:77::9','192.0.2.111','fe80::1','127.0.0.1','127.0.0.2','::1'}
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1' and dest in allowed and link in [None,'lpeer','wpeer'],'fixed isolated endpoints required'
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


def exec_socket_fault(number,kind,argv):
    """Real socket(AF_INET6) error, leaving bind errors and all other syscalls intact."""
    number=int(number)
    kind=int(kind)
    assert number in [22,93,97] and platform.machine()=='aarch64'
    assert kind in [0,1,2]
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert argv[0]=='chroot' and 'private' in Path(argv[1]).parts and argv[2] in ['/usr/sbin/dnsmasq','/usr/sbin/dnsmasq-rs']
    class Filter(ctypes.Structure):
        _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
    # AArch64 asm-generic __NR_socket=198; seccomp_data.args[0] starts at 16.
    if kind:
        filters=(Filter*9)(Filter(0x20,0,0,0),Filter(0x15,0,6,198),
            Filter(0x20,0,0,16),Filter(0x15,0,4,10),Filter(0x20,0,0,24),
            Filter(0x54,0,0,15),Filter(0x15,0,1,kind),Filter(0x06,0,0,0x50000|number),Filter(0x06,0,0,0x7fff0000))
    else:
        filters=(Filter*6)(Filter(0x20,0,0,0),Filter(0x15,0,3,198),
            Filter(0x20,0,0,16),Filter(0x15,0,1,10),Filter(0x06,0,0,0x50000|number),Filter(0x06,0,0,0x7fff0000))
    program=Program(len(filters),filters)
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.prctl(38,1,0,0,0) or libc.prctl(22,2,ctypes.byref(program),0,0):
        raise OSError(ctypes.get_errno(),'socket seccomp setup')
    os.execvp(argv[0],argv)


def inventory(pid, include_inode=False):
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
            row=dict(transport=filename[:3],address=str(ipaddress.ip_address(raw)),port=port)
            if include_inode:row['inode']=parts[9]
            result.append(row)
    return sorted(result,key=lambda row:(row['transport'],row['address'],row['port']))


def snapshot(path):
    save(path, {'links': json.loads(ip('-j','link').stdout), 'addresses': json.loads(ip('-j','addr').stdout),
                'ipv6_flags': Path('/proc/net/if_inet6').read_text()})


class Observer:
    def __init__(self, net, process, out, port, log=None):
        self.net,self.process,self.out,self.port=net,process,out,port
        self.log=log
        self.rows=[]
        self.socket_identities={}
    def sockets(self, label, delay=.25, retain=False, retired=()):
        time.sleep(delay)
        if self.log:self.log.drain()
        assert self.process.poll() is None, 'daemon exited during '+label
        value=inventory(self.process.pid, include_inode=retain)
        row=dict(case=label, sockets=value)
        if retain:
            save(self.out/(label+'-socket-identities.json'),value)
            current={(entry['transport'],entry['address'],entry['port']):entry['inode'] for entry in value}
            row['preserved_healthy_sockets']=all(current.get(key)==inode
                for key,inode in self.socket_identities.items() if key[1] not in retired)
            self.socket_identities=current
            row['sockets']=[{key:item for key,item in entry.items() if key!='inode'} for entry in value]
        self.rows.append(row)
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
        if self.log:self.log.drain()
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
        def no_ipv6(peer):
            ip('link','set',peer.role,'addrgenmode','none');ip('-6','addr','flush','dev',peer.role)
            peer.run('ip','link','set','peer0','addrgenmode','none');peer.run('ip','-6','addr','flush','dev','peer0')
        no_ipv6(client);no_ipv6(server)
        config='port=15353\nno-hosts\nno-resolv\nuser=root\ngroup=root\npid-file=/m2/pid\nhost-record=ready.test,192.0.2.53\n'+item['config']
        (root/'m2/listeners.conf').write_text(config);(out/'config').write_text(config)
        with (out/'stderr').open('w') as stderr, (out/'stdout').open('w') as stdout:
            process=subprocess.Popen(command(root,side,'-d','-C','/m2/listeners.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
            time.sleep(.3)
            assert process.poll() is None, 'relay startup failed'
            save(out/'identity.json',process_identity(root,process.pid))
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
                    received=[]
                    deadline=time.monotonic()+2
                    while not received and time.monotonic()<deadline:
                        time.sleep(.05)
                        received.extend(client.call(op='take')['packets'])
                    save(out/(label+'-downstream.json'),received)
                    rows.append(dict(case=label+'-reply',packets=[dict(packet=p['packet'],source=p['source'],destination=p['destination']) for p in received]))
            request('relay-initial')
            if item['profile']=='relay-recreate':
                save(out/'recreate.json',client.recreate_client_link())
                no_ipv6(client)
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
    log=None
    blockers=[]
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
            blocker=socket.socket(socket.AF_INET6 if item.get('blocker_v6') else socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM)
            blocker.bind((V6['lan'] if item.get('blocker_v6') else V4['lan'],69 if transport=='tftp' else port))
            if transport=='tcp': blocker.listen(1)
        identity=('' if 'user=' in item['config'] else 'user=root\n')+('' if 'group=' in item['config'] else 'group=root\n')
        config=f'port={port}\nno-hosts\nno-resolv\n'+identity+'pid-file=/m2/pid\nhost-record=ready.test,192.0.2.53\n'+item['config']
        (root/'m2/listeners.conf').write_text(config);(out/'config').write_text(config)
        if profile.startswith('runtime-') or item.get('dad') or item.get('socket_errno') or profile.startswith('missing-address'):
            log=Syslog(root,out)
        with (out/'stderr').open('w') as stderr,(out/'stdout').open('w') as stdout:
            argv=command(root,side,'-d','-C','/m2/listeners.conf')
            if item.get('socket_errno'):
                argv=[sys.executable,__file__,'--fault-exec',str(item['socket_errno']),str(item.get('socket_kind',0)),*argv]
                save(out/'socket-fault.json',dict(syscall=198,family=10,kind=item.get('socket_kind',0),errno=item['socket_errno'],abi='aarch64',filter='errno only matching socket(AF_INET6)'))
            process=subprocess.Popen(argv,stderr=stderr,stdout=stdout,start_new_session=True)
            observer=Observer(net,process,out,port,log)
            time.sleep(.2)
            rows.append(dict(case='startup',exit=process.poll()))
            if process.poll() is not None:
                return rows
            save(out/'identity.json',process_identity(root,process.pid))
            if profile=='tftp-unowned-dedicated':
                observer.sockets('initial')
                observer.ask('unowned-check-tftp','127.0.0.2','tftp',local=True)
                if mode=='dynamic':
                    ip('addr','add','127.0.0.2/8','dev','lo');observer.sockets('unowned-added')
                    observer.ask('unowned-added-tftp','127.0.0.2','tftp',local=True)
                    ip('addr','del','127.0.0.2/8','dev','lo');observer.sockets('unowned-removed')
                    observer.ask('unowned-removed-tftp','127.0.0.2','tftp',local=True)
            elif profile=='tftp-static-renamed':
                observer.sockets('initial')
                observer.ask('cached-before-tftp',V4['lan'],'tftp','lpeer')
                ip('link','set','lan','name','retired0')
                observer.sockets('renamed')
                observer.ask('cached-after-tftp',V4['lan'],'tftp','lpeer')
            elif item.get('dad'):
                sockets=observer.sockets('dad-tentative',.01)
                assert any(a.get('tentative') for link in json.loads(ip('-j','addr','show','dev','lan').stdout) for a in link['addr_info'] if a['local']=='fd42:77::9'), 'DAD matured before witness'
                assert not any(row['address']=='fd42:77::9' for row in sockets),'bound a tentative address'
                observer.ask('dad-live-udp',V4['lan'],link='lpeer')
                deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    flags=next(a for link in json.loads(ip('-j','addr','show','dev','lan').stdout) for a in link['addr_info'] if a['local']=='fd42:77::9')
                    if flags.get('dadfailed') or not flags.get('tentative'):break
                    time.sleep(.05)
                else:raise AssertionError('DAD never completed or failed')
                if not flags.get('dadfailed'):
                    deadline=time.monotonic()+2
                    while not any(row['address']=='fd42:77::9' for row in inventory(process.pid)):
                        assert process.poll() is None and time.monotonic()<deadline,'mature DAD address never bound'
                        time.sleep(.05)
                observer.sockets('dad-finished',0)
                for transport in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):
                    observer.ask('dad-final-'+transport,'fd42:77::9',transport,'lpeer')
                observer.ask('dad-surviving-udp',V4['lan'],link='lpeer')
            elif profile.startswith('runtime-shared-'):
                recovering=recovery_case(item)
                def healthy(phase):
                    if recovering:
                        for proto in ['udp','tcp','tftp']:
                            observer.ask('shared-healthy-'+phase+'-'+proto,V4['lan'],proto,'lpeer')
                blocked=[]
                if profile in ['runtime-shared-dns-both','runtime-shared-all']:blocked.extend([('udp',port),('tcp',port)])
                if profile in ['runtime-shared-tftp','runtime-shared-all']:blocked.append(('udp',69))
                observer.sockets('shared-before',retain=recovering)
                for proto,blocked_port in blocked:
                    endpoint=socket.socket(socket.AF_INET,socket.SOCK_STREAM if proto=='tcp' else socket.SOCK_DGRAM)
                    endpoint.setsockopt(socket.SOL_IP,15,1)
                    endpoint.bind(('10.77.0.9',blocked_port))
                    if proto=='tcp':endpoint.listen(1)
                    blockers.append(endpoint)
                ip('addr','add','10.77.0.9/24','dev','lan')
                observer.sockets('shared-partial',retain=recovering)
                healthy('partial')
                for proto in ['udp','tcp','tftp']:observer.ask('shared-before-release-'+proto,'10.77.0.9',proto,'lpeer')
                for endpoint in blockers:endpoint.close()
                blockers.clear()
                # F23 retries every second. Observe after two retry deadlines,
                # rather than let the old .25s query series straddle recovery.
                observer.sockets('shared-released',2.2 if recovering else .25,retain=recovering)
                healthy('released')
                for proto in ['udp','tcp','tftp']:observer.ask('shared-after-release-'+proto,'10.77.0.9',proto,'lpeer')
                ip('addr','add','10.77.0.10/24','dev','lan')
                observer.sockets('shared-trigger',retain=recovering)
                healthy('trigger')
                for proto in ['udp','tcp','tftp']:observer.ask('shared-after-trigger-'+proto,'10.77.0.9',proto,'lpeer')
                ip('addr','del','10.77.0.9/24','dev','lan');ip('addr','del','10.77.0.10/24','dev','lan')
                observer.sockets('shared-removed',retain=recovering,retired=('10.77.0.9','10.77.0.10'))
                healthy('removed')
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
                if profile=='tftp-single-scope':
                    observer.sockets('initial')
                    for link in ['lan','wan']:
                        for dest,tag in [(V6[link],'v6'),('fe80::1','scope')]:
                            observer.ask(link+'-'+tag+'-tftp',dest,'tftp',PEER[link])
                else: observer.ordinary(item.get('tftp',False))
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
                        for proto in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):observer.ask('late-'+proto,'192.0.2.111',proto,local=True)
                        ip('link','del','late0');observer.sockets('late-removed')
                    elif action=='unowned-loopback-change':
                        ip('addr','add','127.0.0.2/8','dev','lo');observer.sockets('unowned-added')
                        for proto in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):observer.ask('unowned-added-'+proto,'127.0.0.2',proto,local=True)
                        ip('addr','del','127.0.0.2/8','dev','lo');observer.sockets('unowned-removed')
                        for proto in ['udp','tcp']+(['tftp'] if item.get('tftp') else []):observer.ask('unowned-removed-'+proto,'127.0.0.2',proto,local=True)
                    elif action=='duplicate-address':
                        ip('link','add','dup0','type','dummy');ip('link','set','dup0','addrgenmode','none');ip('link','set','dup0','up')
                        ip('addr','add',V4['lan']+'/24','dev','dup0');observer.sockets('duplicate-added')
                        ip('addr','del',V4['lan']+'/24','dev','lan');observer.sockets('first-owner-removed')
                        observer.ask('duplicate-owner',V4['lan'],local=True)
                        ip('link','del','dup0');observer.sockets('last-owner-removed')
                if profile=='cross-ingress':
                    net.exec('ip','route','add',V4['lan']+'/32','dev','wpeer')
                    net.exec('ip','-6','route','add',V6['lan']+'/128','dev','wpeer')
                    # IPv6 ND only answers for addresses on that link. The
                    # fixed neighbor makes this an ingress-admission test.
                    mac=json.loads(ip('-j','link','show','dev','wan').stdout)[0]['address']
                    net.exec('ip','-6','neigh','replace',V6['lan'],'lladdr',mac,'nud','permanent','dev','wpeer')
                    for dest,tag in [(V4['lan'],'v4'),(V6['lan'],'v6')]:
                        for proto in ['udp','tcp']:observer.ask('cross-'+tag+'-'+proto,dest,proto,'wpeer')
            rows.extend(observer.rows)
    finally:
        if log:log.drain()
        ended=stop(process)
        diagnostics=log.close() if log else []
        if blocker: blocker.close()
        for endpoint in blockers:endpoint.close()
        peer=net.close() if net else None
        save(out/'cleanup.json',dict(daemon=ended,peer=peer))
    rows.append(dict(case='exit',exit=ended['returncode'],forced=ended['forced']))
    if log:rows.append(dict(case='listener-warnings',messages=diagnostics))
    return rows


def side_run(args):
    cases=scenarios()
    if args.select: cases=[item for item in cases if item['name'] in args.select]
    args.out.mkdir(parents=True,exist_ok=False)
    root=prepare(args.image_root,None,args.out/args.side,args.rust_binary)
    (root/'m2/tftp').mkdir();(root/'m2/tftp/boot.bin').write_bytes(b'synthetic listener boot\n')
    (root/'m2/tftp/boot.bin').chmod(0o644)
    (root/'m2/tftp/lan').mkdir();(root/'m2/tftp/lan/boot.bin').write_bytes(b'synthetic cached owner\n')
    (root/'m2/tftp/lan/boot.bin').chmod(0o644)
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
        if [row['case'] for row in observations]!=expected_labels(item):
            failures.append(item['name']+': missing/extra/reordered observations')
        if not observations:failures.append(item['name']+': empty observation')
        startup=next((row for row in observations if row['case']=='startup'),None)
        expected_failure=(item['profile'] in ['conflicting-modes'] or item.get('blocker') or
                          item['mode']=='static' and item['profile'] in ['missing','no-address','missing-address','missing-address-v6'] or
                          item['mode']!='wildcard' and item['profile']=='unowned-scope')
        if startup and (startup['exit'] is not None)!=bool(expected_failure): failures.append(item['name']+': unexpected startup')
        if startup and expected_failure and startup['exit']!= (1 if item['profile']=='conflicting-modes' else 2):failures.append(item['name']+': wrong startup exit')
        if not expected_failure:
            ended=next((row for row in observations if row['case']=='exit'),None)
            if not ended or ended.get('exit')!=0 or ended.get('forced'): failures.append(item['name']+': incomplete cleanup')
        for row in observations:
            if recovery_case(item) and row['case'] in ['shared-before','shared-partial','shared-released','shared-trigger','shared-removed']:
                if row.get('sockets')!=recovery_sockets(item,row['case'],result.get('side','c')):
                    failures.append(item['name']+': recovery socket inventory '+row['case'])
                if row.get('preserved_healthy_sockets') is not True:
                    failures.append(item['name']+': healthy socket replaced '+row['case'])
            if 'answer' not in row: continue
            expected = expected_answer(item, row['case'], result.get('side','c'))
            if expected is not None and bool(row['answer']) != expected:
                failures.append(item['name']+': reference guard '+row['case'])
            if recovery_case(item) and row['answer'] and row['answer']!=recovery_reply(row['case']):
                failures.append(item['name']+': exact recovery reply '+row['case'])
            if row['answer'] and 'semantic' in row['answer']:
                semantic=row['answer']['semantic']
                if semantic['flags']&15 or not any(rr['type']==1 and rr['data']=='192.0.2.53' for rr in semantic['records']):
                    failures.append(item['name']+': wrong ready.test answer '+row['case'])
            if row['answer'] and 'packet' in row['answer']:
                payload=b'synthetic cached owner\n' if item['profile']=='tftp-static-renamed' else b'synthetic listener boot\n'
                expected_packet=(b'\0\3\0\1'+payload).hex()
                if row['answer']['packet']!=expected_packet or row['answer']['dedicated']==(item['profile']=='tftp-single-scope'):
                    failures.append(item['name']+': wrong TFTP data/port '+row['case'])
                if '-scope-tftp' in row['case'] and row['answer']['source']!='fe80::1':
                    failures.append(item['name']+': wrong scoped TFTP source '+row['case'])
        if item.get('relay'):
            for row in observations:
                if row['case'].startswith('relay-'):
                    expected=0 if item['profile'] in ['relay-except','relay-no-dhcp'] else 1
                    if len(row['packets'])!=expected:failures.append(item['name']+': relay packet guard '+row['case'])
        warnings=next((row['messages'] for row in observations if row['case']=='listener-warnings'),None)
        if warnings is not None:
            count={'runtime-occupied-udp':1,'runtime-occupied-tcp':1,'runtime-shared-tftp':1,
                   'runtime-shared-dns-both':2,'runtime-shared-all':3}.get(item['profile'],0)
            expected=[dict(priority=132,text='failed to create listening socket for 10.77.0.9: Address in use')]*count
            if warnings!=expected:failures.append(item['name']+': warning priority/text/count guard')
    return failures


def expected_labels(item):
    """Frozen per-observation inventory, independent of either observed side."""
    profile,mode=item['profile'],item['mode']
    failed=(profile=='conflicting-modes' or item.get('blocker') or
        mode=='static' and profile in ['missing','no-address','missing-address','missing-address-v6'] or
        mode!='wildcard' and profile=='unowned-scope')
    if failed:return ['startup']
    if item.get('relay'):
        labels=['relay-initial']
        if profile not in ['relay-except','relay-no-dhcp']:labels.append('relay-initial-reply')
        if profile=='relay-recreate':labels.extend(['relay-recreated','relay-recreated-reply'])
        return labels+['sockets','exit']
    labels=['startup']
    protocols=['udp','tcp']+(['tftp'] if item.get('tftp') else [])
    if profile=='tftp-unowned-dedicated':
        labels.extend(['initial','unowned-check-tftp'])
        if mode=='dynamic':labels.extend(['unowned-added','unowned-added-tftp','unowned-removed','unowned-removed-tftp'])
    elif profile=='tftp-static-renamed':labels.extend(['initial','cached-before-tftp','renamed','cached-after-tftp'])
    elif item.get('dad'):
        labels.extend(['dad-tentative','dad-live-udp','dad-finished'])
        labels.extend('dad-final-'+proto for proto in protocols)
        labels.append('dad-surviving-udp')
    elif profile.startswith('runtime-shared-'):
        labels.extend(['shared-before','shared-partial'])
        if recovery_case(item):labels.extend('shared-healthy-partial-'+proto for proto in ['udp','tcp','tftp'])
        labels.extend('shared-before-release-'+proto for proto in ['udp','tcp','tftp'])
        labels.append('shared-released')
        if recovery_case(item):labels.extend('shared-healthy-released-'+proto for proto in ['udp','tcp','tftp'])
        labels.extend('shared-after-release-'+proto for proto in ['udp','tcp','tftp'])
        labels.append('shared-trigger')
        if recovery_case(item):labels.extend('shared-healthy-trigger-'+proto for proto in ['udp','tcp','tftp'])
        labels.extend('shared-after-trigger-'+proto for proto in ['udp','tcp','tftp'])
        labels.append('shared-removed')
        if recovery_case(item):labels.extend('shared-healthy-removed-'+proto for proto in ['udp','tcp','tftp'])
    elif profile.startswith('runtime-occupied-'):
        labels.extend(['before-occupied','partial-occupied','partial-udp','partial-tcp','after-blocker-release','partial-removed'])
    elif profile=='tftp-single-scope':
        labels.append('initial')
        labels.extend(link+'-'+tag+'-tftp' for link in ['lan','wan'] for tag in ['v6','scope'])
    else:
        labels.append('initial')
        labels.extend(link+'-'+tag+'-'+proto for link in ['lan','wan'] for tag in ['v4','v6','scope','alias'] for proto in protocols)
        labels.extend(tag+'-'+proto for tag in ['lo4','lo6','lo-extra'] for proto in protocols)
        for action in item['actions']:
            if action=='address-change':
                labels.append('added')
                labels.extend('added-'+tag+'-'+proto for tag in ['v4','v6'] for proto in protocols)
                labels.extend(['removed','surviving'])
            elif action=='recreate':
                labels.extend(['link-deleted','link-recreated'])
                labels.extend('recreated-'+tag+'-'+proto for tag in ['v4','v6','scope'] for proto in ['udp','tcp'])
            elif action in ['late-interface','late-address']:
                labels.append('late-created');labels.extend('late-'+proto for proto in protocols);labels.append('late-removed')
            elif action=='unowned-loopback-change':
                labels.append('unowned-added');labels.extend('unowned-added-'+proto for proto in protocols)
                labels.append('unowned-removed');labels.extend('unowned-removed-'+proto for proto in protocols)
            elif action=='duplicate-address':labels.extend(['duplicate-added','first-owner-removed','duplicate-owner','last-owner-removed'])
        if profile=='cross-ingress':labels.extend('cross-'+tag+'-'+proto for tag in ['v4','v6'] for proto in ['udp','tcp'])
    labels.append('exit')
    if profile.startswith('runtime-') or item.get('dad') or item.get('socket_errno') or profile.startswith('missing-address'):
        labels.append('listener-warnings')
    return labels


def expected_answer(item,case,side='c'):
    """Source-derived reachability guards, independent of observed Rust data."""
    profile,mode=item['profile'],item['mode']
    bound=mode!='wildcard'
    proto=case.rsplit('-',1)[-1]
    if item.get('port')==0 and proto!='tftp':return False
    if case.startswith('shared-'):
        if case.startswith('shared-healthy-'):return True
        if recovery_case(item) and side=='rust' and case.startswith(('shared-after-release-','shared-after-trigger-')):
            return True
        if profile=='runtime-shared-all':return case.startswith('shared-after-trigger-')
        return (proto=='tftp')==(profile=='runtime-shared-dns-both')
    if case.startswith('dad-'):
        return profile!='dad-failed' or not case.startswith('dad-final-')
    if case.startswith('partial-'):
        return case.rsplit('-',1)[1]!=profile.rsplit('-',1)[1]
    if case=='surviving':return True
    if case.startswith('added-'):return mode!='static'
    if case.startswith('recreated-'):return mode!='static' or '-scope-' not in case
    if case.startswith('late-') or case=='duplicate-owner':return True
    if case.startswith('unowned-'):return profile!='tftp-unowned-dedicated' or mode!='dynamic'
    if case.startswith('cached-'):return True
    if case.startswith('cross-'):
        return case.endswith('-tcp') and bound or case.startswith('cross-v4-') and mode=='static'
    if proto not in ['udp','tcp','tftp']:return None
    if profile in ['missing-address','missing-address-v6','unowned-scope']:return False
    if case.startswith('lo'):
        tag=case.rsplit('-',1)[0]
        if profile.startswith('socket-unsupported-'):
            if tag=='lo-extra':return not bound
            return tag!='lo6' or item.get('socket_kind',0) not in [0,1 if proto=='tcp' else 2]
        if profile in ['explicit-any4','explicit-any6']:
            family4=tag!='lo6'
            return family4==(profile=='explicit-any4') and (proto=='tcp' and bound or mode=='static' and family4 and proto=='udp')
        unowned=profile in ['unowned-loopback','unowned-loopback-change','tftp-unowned-loopback-change']
        selected=profile!='listen-only' and not unowned
        if unowned:selected=tag=='lo-extra'
        elif tag=='lo-extra':selected=selected and not bound
        if proto=='tftp' and profile in ['tftp-dedicated','tftp-alias']:return False
        return selected
    link,tag,_=case.split('-')
    if link not in ['lan','wan']:return None
    if profile.startswith('socket-unsupported-'):
        if tag in ['v4','alias']:return True
        if tag=='scope' and proto=='tftp' and side=='c':return False
        return item.get('socket_kind',0) not in [0,1 if proto=='tcp' else 2]
    if profile=='tftp-single-scope':return True
    # tftp.c:295-296 resets the dedicated transfer scope to zero. This is a
    # separately proved original defect, never an ordinary equivalence pass.
    if proto=='tftp' and tag=='scope' and side=='c':return False
    if profile in ['explicit-any4','explicit-any6']:
        family4=tag in ['v4','alias']
        return family4==(profile=='explicit-any4') and (proto=='tcp' and bound or mode=='static' and family4 and proto=='udp')
    if profile=='down-link' and link=='lan':return False
    if proto=='tftp':
        if profile=='tftp-dedicated':return not bound and link=='wan'
        if profile=='tftp-alias':return link=='lan' and (not bound or tag=='alias')
        if profile=='tftp-no-dhcp' or profile=='tftp-no-v4' and bound:
            if link=='lan':return False
    if profile in ['ordinary','empty-except','same-link-local','tftp','tftp-no-dhcp','tftp-no-v4']:
        return True
    if profile in ['empty-interface','missing','no-address','unowned-loopback','unowned-loopback-change','tftp-unowned-loopback-change']:
        return False
    if profile=='listen-only':return link=='lan' and tag in ['v4','v6']
    if profile in ['alias','wildcard-empty','tftp-alias']:
        return link=='lan' and tag=='alias' and (bound or proto!='tcp')
    if profile in ['interface','cross-ingress','address-change','recreate','down-link','tftp-change','tftp-only']:
        return link=='lan' and (tag!='alias' or not bound)
    if profile=='union':return link=='wan' and tag in ['v4','v6'] or link=='lan' and (tag!='alias' or not bound)
    if profile=='wildcard-names':return link=='lan'
    if profile=='alias-except':return link!='lan' or tag!='alias' or not bound
    if profile=='tftp-dedicated':return link=='lan' and (tag!='alias' or not bound)
    if profile=='tftp-except':return link=='lan' or tag=='alias' and (bound or proto!='tcp')
    if profile in ['late-interface','late-address','duplicate-address','tftp-late-address']:
        return link=='lan' and (tag!='alias' or not bound)
    return None


def compare(left,right,cases):
    failures=[dict(side=side,error=error) for side,value in [('c',left),('rust',right)] for error in validate(value,cases)]
    by_name={item['name']:item for item in cases}
    for c,r in zip(left.get('rows',[]),right.get('rows',[])):
        normalized=copy.deepcopy(r)
        item=by_name[c['name']]
        if len(c['rows'])==len(r['rows']):
            for index,(cr,rr) in enumerate(zip(c['rows'],r['rows'])):
                case=cr['case']
                if '-scope-tftp' in case and item['profile']!='tftp-single-scope' and expected_answer(item,case,'rust'):
                    if cr.get('answer') is None and rr.get('answer'):
                        normalized['rows'][index]['answer']=None
                if recovery_difference(item,cr,rr):
                    # Both exact side-specific contracts were checked above.
                    # Normalize only the prescribed recovery fields; any other
                    # row/key difference still rejects the complete case.
                    if 'sockets' in cr:
                        normalized['rows'][index]['sockets']=cr['sockets']
                    if 'answer' in cr:
                        normalized['rows'][index]['answer']=None
        if c!=normalized: failures.append(dict(name=c['name'],c=c,rust=r))
    return failures


def reference_differences(left,right,cases):
    classified=[]
    by_name={item['name']:item for item in cases}
    for c,r in zip(left.get('rows',[]),right.get('rows',[])):
        item=by_name[c['name']]
        for cr,rr in zip(c['rows'],r['rows']):
            case=cr['case']
            if '-scope-tftp' in case and item['profile']!='tftp-single-scope' and expected_answer(item,case,'rust'):
                if cr.get('answer') is None and rr.get('answer'):
                    classified.append(dict(name=c['name'],case=case,c=cr,rust=rr,
                        classification='original-defect-ipv6-transfer-scope-cleared',
                        source='dnsmasq-2.93/src/tftp.c:291-296,347-374',
                        positive_control='tftp-single-scope-'+item['mode']))
            if recovery_difference(item,cr,rr):
                classified.append(dict(name=c['name'],case=case,c=cr,rust=rr,
                    classification='F23-retry-missing-bound-transports',
                    source='dnsmasq-2.93/src/network.c:1177-1200; Rust main.rs InterfaceRefresh 1s retry',
                    positive_control='exact side-specific replies/inventories and retained healthy socket inodes'))
    return classified


def recovery_negative_controls(left, right, cases):
    controls=[]
    by_name={item['name']:item for item in cases}
    for index,observed in enumerate(right['rows']):
        item=by_name[observed['name']]
        if not recovery_case(item):continue
        def reject(name, label, mutate, side='rust'):
            changed=copy.deepcopy(right if side=='rust' else left)
            row=next(row for row in changed['rows'][index]['rows'] if row['case']==label)
            mutate(row)
            failures=compare(left,changed,cases) if side=='rust' else compare(changed,right,cases)
            controls.append(dict(name=name+'-'+item['name'],rejected=bool(failures)))
        reject('missing-recovery','shared-after-release-udp',lambda row:row.update(answer=None))
        reject('changed-C-defect','shared-after-release-udp',
               lambda row:row.update(answer=recovery_reply(row['case'])),'c')
        reject('wrong-recovery-id','shared-after-release-udp',
               lambda row:row['answer']['semantic'].update(id=0))
        reject('extra-recovery-record','shared-after-release-tcp',
               lambda row:row['answer']['semantic']['records'].append(dict(row['answer']['semantic']['records'][0])))
        reject('wrong-recovery-source','shared-after-release-tftp',
               lambda row:row['answer'].update(source='10.77.0.254'))
        reject('wrong-recovery-packet','shared-after-release-tftp',
               lambda row:row['answer'].update(packet='00050001'))
        reject('missing-recovery-socket','shared-released',lambda row:row['sockets'].pop())
        reject('extra-recovery-socket','shared-released',
               lambda row:row['sockets'].append(dict(transport='udp',address=V4['wan'],port=DNS_PORT)))
        reject('replaced-healthy-socket','shared-released',
               lambda row:row.update(preserved_healthy_sockets=False))
        reject('lost-healthy-reply','shared-healthy-released-udp',lambda row:row.update(answer=None))
        reject('unknown-recovery-difference','shared-released',lambda row:row.update(unexpected=True))
        reject('forced-recovery-cleanup','exit',lambda row:row.update(forced=True))
    return controls


def negative_controls(left, right, cases):
    controls=[]
    corrupt=copy.deepcopy(right)
    corrupt['rows'].pop()
    controls.append(dict(name='missing-case',rejected=bool(compare(left,corrupt,cases))))
    corrupt=copy.deepcopy(right);corrupt['failures']=[dict(error='injected')]
    controls.append(dict(name='failure-inventory',rejected=bool(compare(left,corrupt,cases))))
    for index,row in enumerate(right['rows']):
        reply=next((row for row in row['rows'] if row.get('answer')),None)
        if reply:
            corrupt=copy.deepcopy(right)
            target=next(row for row in corrupt['rows'][index]['rows'] if row.get('answer'))
            target['answer']=None
            controls.append(dict(name='lost-service-'+row['name'],rejected=bool(compare(left,corrupt,cases))))
        warning=next((item for item in row['rows'] if item.get('messages')),None)
        if warning:
            corrupt=copy.deepcopy(right)
            target=next(item for item in corrupt['rows'][index]['rows'] if item.get('messages'))
            target['messages'][0]['priority']=31
            controls.append(dict(name='warning-priority-'+row['name'],rejected=bool(compare(left,corrupt,cases))))
    controls.extend(recovery_negative_controls(left,right,cases))
    return controls


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--fault-exec':
        return exec_socket_fault(sys.argv[2],sys.argv[3],sys.argv[4:])
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
        for requirement in checklist['requirements']:
            if requirement['id']=='partial-dynamic-listener':
                requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['runtime-shared-tftp','runtime-shared-dns-both','runtime-shared-all']))
                requirement['boundary']='C: a successful UDP, TCP or TFTP transport sets iface->done for all three; missing transports do not reappear after blocker release. If all fail, an interface event retries the group. Authorized Rust F23: runtime-shared-dns-both/all recover every missing transport after a 2.2s retry window, retain healthy socket inodes and exact replies, and retire added addresses. Other profiles retain the C contract.'
            if requirement['id']=='tftp-selection':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['tftp-only']))
            if requirement['id']=='tftp-selection':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['tftp-unowned-dedicated','tftp-static-renamed']))
            if requirement['id']=='dad-capabilities':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['tftp-dad-low-port']))
            if requirement['id']=='startup-failures':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['missing-address-v6','unowned-scope','occupied-udp-v6','occupied-tcp-v6','occupied-tftp-v6']))
            if requirement['id']=='startup-failures':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['socket-unsupported-einval','socket-unsupported-eafnosupport','socket-unsupported-eprotonosupport']))
            if requirement['id']=='partial-dynamic-listener':requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['socket-unsupported-udp','socket-unsupported-tcp']))
            if requirement['id']=='unowned-address':
                requirement['profiles']=list(dict.fromkeys(requirement['profiles']+['unowned-loopback-change','tftp-unowned-loopback-change','tftp-late-address']))
                requirement['boundary']='Explicit addresses absent from snapshots are attempted. Successfully created unowned listeners remain unowned even if the address later gains/loses an interface; failed unowned addresses first created on a real interface are retired with the last owner. INAME_USED forbids recreating the latter as a fallback.'
        checklist['required_cases']=[item['name'] for item in cases]
        checklist['cases']=cases
        checklist['required_observations']={item['name']:expected_labels(item) for item in cases}
        save(HERE/'m5_listeners.json',checklist)
        return 0
    assert checklist['required_cases']==[item['name'] for item in cases], 'case inventory differs from frozen C checklist'
    assert checklist['required_observations']=={item['name']:expected_labels(item) for item in cases},'observation inventory differs from frozen C checklist'
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
    controls=negative_controls(left,right,selected) if not failures else []
    result=dict(cases=len(selected),observations=sum(len(row['rows']) for row in right['rows']),failures=failures,
                exits=exits,negative_controls=controls,binary_sha256=right['binary_sha256'],bytes=args.rust_binary.stat().st_size,
                reference_differences=reference_differences(left,right,selected),
                requirements=[dict(id=req['id'],source=req['source'],
                    cases=[item['name'] for item in selected if 'all' in req['profiles'] or item['profile'] in req['profiles']],
                    complete=not args.select and not failures) for req in checklist['requirements']],
                qualified=not failures and not args.select and all(row['rejected'] for row in controls))
    save(args.out/'result.json',result)
    print(json.dumps(dict(cases=result['cases'],observations=result['observations'],failures=len(failures),qualified=result['qualified'])))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
