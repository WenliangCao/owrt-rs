#!/usr/bin/env python3
"""Exact-image lease recovery family. Run only in run_isolated.sh."""
from __future__ import annotations

import argparse
import copy
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

from dns_service_probe import exact_read, query, semantics
from dhcp_daemon_smoke import decode
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, process_identity, sha256

DEFAULT = '/var/lib/misc/dnsmasq.leases'
BASE = ['--conf-file=', '--no-hosts', '--no-resolv', '--no-ping', '--no-0x20-encode',
        '--no-round-robin', '--user=root', '--group=root', '--listen-address=127.0.0.1',
        '--port=15353', '--pid-file=/m2/daemon.pid', '--host-record=ready.lease.test,8.8.8.8']
RANGE = '--dhcp-range=127.0.0.10,127.0.0.30,255.0.0.0,600s'
DEPENDENCIES = ['dns_service_probe.py', 'dhcp_daemon_smoke.py', 'm2_rootfs.py', 'run_isolated.sh']


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def row(client=1, address=10, name='first', expiry='0', clid=None):
    return f'{expiry} 02:00:00:00:00:{client:02x} 127.0.0.{address} {name} {clid or "*"}\n'


def dhcp(kind, client=1, address=10, clid=None, name=None, htype=1):
    return dict(op='dhcp', kind=kind, client=client, address=address, clid=clid, name=name, htype=htype)


def scenarios():
    cases = []
    def add(ident, leases='', **kw):
        cases.append(dict(dict(id=ident, leases=leases, helper=True, probes=[], actions=[]), **kw))
    duplicate = row() + row(2, name='second')
    probes = [dict(name='first', type=1), dict(name='second', type=1),
              dict(name='10.0.0.127.in-addr.arpa', type=12)]
    add('inactive-dns', row(), inactive=True)
    add('create-missing', missing=True)
    add('missing-parent', path='/m2/missing/leases', expected_exit=3)
    add('directory', path='/m2/directory', directory=True, expected_exit=3)
    add('permission', row(), userspec='453:453', mode=0o400, expected_exit=3)
    add('readonly-fs', row(), readonly_fs=True, path='/m2/rofs/leases', expected_exit=3)
    add('relative-link', row(), link='target', actions=[dhcp(3, name='renewed')])
    add('absolute-link', row(), link='/m2/target', actions=[dhcp(3, name='renewed')])
    add('dangling-link', missing=True, link='target')
    add('loop-link', link='leases', expected_exit=3)
    add('held-inode', row(), actions=[dict(op='replace', text=row(9, name='foreign')),
                                     dhcp(3, name='renewed')])
    add('ro-no-script', row(), ro=True, helper=False, probes=[dict(name='first')])
    add('ro-init', duplicate, ro=True, probes=probes,
        actions=[dhcp(3), dict(op='hup'), dhcp(7, client=2)])
    add('ro-capacity', duplicate, ro=True, maximum=1, expected_exit=5)
    add('ro-capacity-warning', '0 01 invalid bad *\n'+duplicate, ro=True, maximum=1, expected_exit=5)
    add('ro-malformed', '0 01 invalid bad *\n'+row()+'trailing', ro=True, probes=[dict(name='first')])
    add('ro-partial-record', row()+'0 02 127.0.0.11 unfinished', ro=True, probes=[dict(name='first')])
    add('capacity-warning', '0 01 invalid bad *\n'+duplicate, maximum=1, expected_exit=5)
    add('scanf-space', '0\v02:00:00:00:00:01\f127.0.0.10\nfirst\t*\r\n', probes=[dict(name='first')])
    add('scanf-width', row() + '0 ' + 'a'*256 + ' 127.0.0.11 wide *\n', probes=[dict(name='first')])
    add('scanf-nul', '0 02:00:00:00:00:01\0ignored 127.0.0.10 first\0ignored *\n', probes=[dict(name='first')])
    add('partial-first', row() + 'tail', probes=[dict(name='first')])
    add('partial-record', row() + '0 02 127.0.0.11 unfinished', probes=[dict(name='first')])
    add('bad-address', '0 02 invalid bad *\n0 02 ::1 badv6 *\n' + row(), probes=[dict(name='first')])
    add('bad-hardware', '0 gg 127.0.0.10 nohw *\n0 01- 127.0.0.11 typed *\n',
        probes=[dict(name='nohw'), dict(name='typed')], actions=[dict(op='hup')])
    add('hex-identities', '0 06-abc:1:: 127.0.0.10 typed 01:*\n0 01:' + 'ab'*17 +
        'junk 127.0.0.11 truncated ' + '02:'*255 + 'junk\n', actions=[dict(op='hup')])
    add('bad-client-id', row(clid='gg') + row(2,11,'second',clid='*'), actions=[dhcp(1, clid='01')])
    add('expiry-integers', row(expiry='-1') + row(2,11,'zero','junk') + row(3,12,'forever','+0junk') +
        row(4,13,'saturated','9223372036854775808') + row(5,14,'negative','-9223372036854775809'),
        probes=[dict(name=name) for name in ['first','zero','forever','saturated','negative']], expiry_environment=True,
        actions=[dhcp(8,client=4,address=13),dhcp(8,client=5,address=14)])
    add('expiry-prune', row(expiry='PAST') + row(2,name='second',expiry='NOW') + row(3,name='third'), probes=probes)
    add('expiry-timer', row(expiry='SOON') + row(2,name='second'), probes=probes,
        actions=[dict(op='wait', seconds=3), dict(op='probes')])
    add('capacity-expired', row(expiry='PAST') + row(2,11,'second','PAST'), maximum=1, expected_exit=5)
    add('capacity-duplicate', duplicate, maximum=1, expected_exit=5)
    add('capacity-invalid', '0 01 invalid invalid *\n' + row(), maximum=1, probes=[dict(name='first')])
    add('duplicates', duplicate, probes=probes)
    add('duplicate-client', row(clid='01') + row(2,11,'second',clid='01'), probes=probes,
        actions=[dhcp(1, client=9, address=None, clid='01'), dhcp(7,client=9,address=11,clid='01')])
    add('client-fallback', row(clid='01') + row(1,11,'second',clid='02'),
        actions=[dhcp(1,address=None), dhcp(1,address=None,clid='03'), dhcp(1,address=None,clid='01',htype=6)])
    add('duplicate-renew', duplicate, probes=probes,
        actions=[dhcp(3,name='renewed'), dict(op='probes'), dhcp(1,client=2,address=None)])
    add('duplicate-release', duplicate, probes=probes,
        actions=[dhcp(7,client=9), dhcp(7), dict(op='probes'), dhcp(7,client=2)])
    add('duplicate-decline', duplicate, probes=probes, actions=[dhcp(4), dict(op='probes')])
    add('duplicate-inform', row(expiry='FUTURE') + row(2,name='second'),
        actions=[dhcp(8), dhcp(8,client=2)])
    add('name-collision', row(name='same') + row(2,11,'SAME'),
        probes=[dict(name='same'),dict(name='10.0.0.127.in-addr.arpa',type=12)])
    add('fqdn-scope', row(name='same') + row(2,11,'same'), config=['--dhcp-fqdn', '--domain=lease.test'],
        probes=[dict(name='same'),dict(name='same.lease.test')])
    add('configured-names', duplicate, config=['--dhcp-host=02:00:00:00:00:01,fixed1',
        '--dhcp-host=02:00:00:00:00:02,fixed2'], probes=[dict(name='fixed1'),dict(name='fixed2')],
        actions=[dict(op='hup'),dict(op='probes')])
    add('extensions', duplicate + 'agent-info 127.0.0.10 01:02\nvendorclass 127.0.0.10 74:65:73:74\n'
        'agent-info 127.0.0.10 gg\nagent-info 127.0.0.99 01\nvendorclass invalid 01\n',
        config=['--leasequery'], actions=[dhcp(3,name='renewed')])
    add('sighup', duplicate, probes=probes,
        actions=[dict(op='replace',text=row(9,name='foreign')),dict(op='hup'),dict(op='probes')])
    add('restart', duplicate, probes=probes,
        actions=[dhcp(3,name='renewed'),dict(op='restart'),dict(op='probes'),dhcp(7,client=2)])
    add('write-failure', row(), limited_write=True, helper=False,
        actions=[dhcp(3),dict(op='lift-write-limit'),dict(op='wait-file',seconds=65)])
    add('partial-eio', row(), fifo=True, expected_exit=3)
    add('partial-eio-warning', '0 01 invalid bad *\n'+row(), fifo=True, expected_exit=3)
    add('optional-long', row(), spelling=['--dhcp-leasefile'], path=DEFAULT)
    add('optional-empty', row(), spelling=['--dhcp-leasefile='], path=DEFAULT)
    add('optional-separated', spelling=['--dhcp-leasefile','/m2/leases'], expected_test=1, expected_exit=1)
    add('alias', duplicate, spelling=['--dhcp-lease=/m2/leases'], probes=probes)
    add('alias-empty', row(), spelling=['--dhcp-lease='], path=DEFAULT)
    add('alias-required', spelling=['--dhcp-lease'], expected_test=1, expected_exit=1)
    add('short', duplicate, spelling=['-l','/m2/leases'], probes=probes)
    add('short-required', spelling=['-l'], expected_test=1, expected_exit=1)
    add('file-optional', row(), spelling=['--conf-file=/m2/config'], path=DEFAULT,
        files={'config':'dhcp-leasefile\n'})
    add('file-alias-required', spelling=['--conf-file=/m2/config'],
        files={'config':'dhcp-lease\n'}, expected_test=1, expected_exit=1)
    add('short-empty', row(), spelling=['-l',''], path=DEFAULT)
    add('cli-file-origin', row(), spelling=['--dhcp-leasefile=/m2/leases','--conf-file=/m2/config'],
        files={'config':'dhcp-lease=/m2/other\n','other':row(9,name='foreign')},
        probes=[dict(name='first'),dict(name='foreign')])
    add('file-cli-origin', row(), spelling=['--conf-file=/m2/config','--dhcp-leasefile=/m2/leases'],
        files={'config':'dhcp-lease=/m2/other\n','other':row(9,name='foreign')},
        probes=[dict(name='first'),dict(name='foreign')])
    add('file-occurrence', spelling=['--conf-file=/m2/config'],
        files={'config':'dhcp-leasefile=/m2/leases\ndhcp-lease=/m2/other\n'}, expected_test=1, expected_exit=1)
    add('capacity-zero', row(), maximum=0, expected_exit=5)
    add('capacity-zero-empty', maximum=0)
    add('occurrence', spelling=['--dhcp-leasefile=/m2/leases','--dhcp-lease=/m2/other'],
        expected_test=1, expected_exit=1)
    return cases


def packet(action, xid):
    value=bytearray(240);value[:3]=bytes([1,action['htype'],6]);value[4:8]=struct.pack('!I',xid)
    kind=action['kind'];address=action.get('address');value[28:34]=bytes([2,0,0,0,0,action['client']])
    value[236:240]=bytes([99,130,83,99]);opts=bytearray([53,1,kind,55,7,1,3,6,12,51,58,59])
    if kind==1:value[10:12]=b'\x80\0'
    if address is not None:
        raw=socket.inet_aton(f'127.0.0.{address}')
        if kind in (1,4):opts+=bytes([50,4])+raw
        else:value[12:16]=raw
    if kind in (4,7):opts+=bytes([54,4])+socket.inet_aton('127.0.0.1')
    if action.get('clid'):
        raw=bytes.fromhex(action['clid']);opts+=bytes([61,len(raw)])+raw
    if action.get('name'):
        raw=action['name'].encode();opts+=bytes([12,len(raw)])+raw
    return bytes(value+opts+b'\xff')


def dns(probe, ident, transport):
    wire=query(probe['name'],probe.get('type',1),ident)
    if transport=='udp':
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
            endpoint.settimeout(.2);endpoint.sendto(wire,('127.0.0.1',15353));reply=endpoint.recv(65535)
    else:
        with socket.create_connection(('127.0.0.1',15353),.5) as endpoint:
            endpoint.sendall(struct.pack('!H',len(wire))+wire)
            reply=exact_read(endpoint,struct.unpack('!H',exact_read(endpoint,2))[0])
    if reply[:2]!=wire[:2]:raise AssertionError('DNS transaction mismatch')
    return semantics(reply), dict(request=wire.hex(),response=reply.hex(),transport=transport)


def wait(predicate, seconds, label):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=predicate()
        if result:return result
        time.sleep(.01)
    raise AssertionError(label)


def file_rows(raw, epochs, now):
    # Only the finite wall-clock values are normalized; ordering and all bytes
    # of hardware/name/client/extension fields remain part of the comparison.
    values=[]
    for line in raw.splitlines():
        fields=line.split()
        if len(fields)==5:
            try:
                expiry=int(fields[0])
                if expiry in epochs:fields[0]=epochs[expiry].encode()
                elif now+597<=expiry<=now+603:fields[0]=b'RENEWED600'
            except ValueError:pass
        values.append([field.hex() for field in fields])
    return values


def diagnostics(raw):
    rows=[]
    for line in raw.decode(errors='backslashreplace').splitlines():
        match=re.search(r'(ignoring invalid line in lease database.*|failed to parse lease database.*|'
                        r'cannot open or create lease file.*|failed to read lease file.*|too many stored leases.*)',line)
        if match:rows.append(match.group())
    return rows


def trace_read_error(pid, descriptor, output):
    if platform.machine()!='aarch64':raise RuntimeError('AArch64 ptrace ABI required')
    class Iovec(ctypes.Structure):
        _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
    libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
    def ptrace(request,address=0,data=0):
        ctypes.set_errno(0)
        value=libc.ptrace(ctypes.c_uint(request),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if value==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),'ptrace')
        return value
    registers=(ctypes.c_ulonglong*34)()
    def regs(write=False):
        value=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(value))
    report=dict(pid=pid,descriptor=descriptor,reads=[],injected=False);attached=False
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;ptrace(0x4200,0,1)
        Path(str(output)+'.ready').write_text('attached\n')
        active=fault=consumed=False
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            if not os.WIFSTOPPED(status):
                if report['injected']:attached=False;break
                raise AssertionError('tracee exited before injection')
            if os.WSTOPSIG(status)!=signal.SIGTRAP|0x80:continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                active=registers[8] in (63,65) and registers[0]==descriptor;fault=active and consumed
                if fault:
                    syscall=ctypes.c_int(-1);value=Iovec(ctypes.addressof(syscall),ctypes.sizeof(syscall))
                    ptrace(0x4205,0x404,ctypes.addressof(value))
            elif info[0]==2 and active:
                returned=ctypes.c_longlong(registers[0]).value
                if fault:
                    registers[0]=(1<<64)-errno.EIO;regs(True);returned=-errno.EIO;report['injected']=True
                report['reads'].append(dict(result=returned,injected=fault));save(output,report)
                consumed|=returned>0;active=False
                # scanf may finish its current conversion and retry once after
                # ferror; a permanently failed storage descriptor keeps EIO.
                if len(report['reads'])>16:raise AssertionError('read error did not terminate parser')
    finally:
        if attached:
            try:ptrace(17)
            except OSError:pass
        save(output,report)
    return 0


def run(root, side, case, out):
    out.mkdir();folder=root/'m2';shutil.rmtree(folder);folder.mkdir(mode=0o777)
    (folder/'directory').mkdir();now=int(time.time())
    epochs={now-1:'PAST',now:'NOW',now+2:'SOON',now+300:'FUTURE'}
    text=case['leases']
    for epoch,label in epochs.items():text=text.replace(label,str(epoch))
    path=case.get('path','/m2/leases');target=case.get('link');mounted=False
    if case.get('readonly_fs'):
        (folder/'rofs').mkdir();subprocess.run(['mount','-t','tmpfs','tmpfs',str(folder/'rofs')],check=True);mounted=True
    real=image_path(root,'/m2/target' if target and target!='leases' else path,follow_leaf=False)
    if path==DEFAULT:real.parent.mkdir(parents=True,exist_ok=True)
    if not case.get('missing') and not case.get('directory') and case['id']!='missing-parent' and not case.get('fifo') and target!='leases':
        real.write_bytes(text.encode());real.chmod(case.get('mode',0o644))
    if target:(folder/'leases').symlink_to(target)
    if case.get('fifo'):os.mkfifo(real)
    if mounted:subprocess.run(['mount','-o','remount,ro',str(folder/'rofs')],check=True)
    for name,contents in case.get('files',{}).items():(folder/name).write_text(contents)
    helper=folder/'helper';helper.write_text('#!/bin/sh\nif [ "$1" = init ]; then cat /m2/init; exit; fi\n'
        'printf "%s|%s|%s|%s|%s|%s|%s\\n" "$1" "$2" "$3" "$4" "${DNSMASQ_CLIENT_ID-}" "${DNSMASQ_INTERFACE-}" "${DNSMASQ_OLD_HOSTNAME-}" >> /m2/events\n')
    if case.get('expiry_environment'):
        helper.write_text(helper.read_text().replace('printf "%s|%s|%s|%s|%s|%s|%s',
            'printf "%s|%s|%s|%s|%s|%s|%s|%s|%s').replace(' >> /m2/events',
            ' "${DNSMASQ_LEASE_EXPIRES-}" "${DNSMASQ_TIME_REMAINING-}" >> /m2/events'))
    helper.chmod(0o755);(folder/'init').write_bytes(text.encode())
    argv=BASE+([] if case.get('inactive') else [RANGE,'--dhcp-authoritative'])
    argv+=case.get('config',[])
    if case.get('maximum') is not None:argv+=['--dhcp-lease-max='+str(case['maximum'])]
    if case.get('ro'):argv+=['--leasefile-ro']
    if case['helper']:argv+=['--dhcp-script=/m2/helper']
    argv+=case.get('spelling',['--dhcp-leasefile='+path])
    binary='/usr/sbin/dnsmasq'+('-rs' if side=='rust' else '')
    syslog=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);syslog.setblocking(False)
    (root/'dev/log').unlink(missing_ok=True);syslog.bind(str(root/'dev/log'))
    syntax=subprocess.run(command(root,binary,'--test',*argv),capture_output=True,timeout=3)
    observed={'syntax':dict(exit=syntax.returncode,stdout=syntax.stdout.decode(errors='backslashreplace').replace('dnsmasq-rs:','dnsmasq:'),
                           stderr=syntax.stderr.decode(errors='backslashreplace').replace('dnsmasq-rs:','dnsmasq:')),
              'ready':False,'snapshots':[],'dns':[],'dhcp':[],'exit':None,'diagnostics':[], 'forced':False,'invalid_timers':[]}
    save(out/'fixture.json',dict(case=case,epochs=epochs,argv=argv));trace={'processes':[],'queries':[],'packets':[]}
    endpoint=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
    endpoint.setsockopt(socket.SOL_SOCKET,25,b'lo\0');endpoint.bind(('0.0.0.0',68));endpoint.settimeout(.4)
    log=(out/'stderr').open('wb');stdout=(out/'stdout').open('wb');process=None;tracer=None
    syslog_packets=[]
    def drain_syslog():
        while True:
            try:syslog_packets.append(syslog.recv(65535))
            except BlockingIOError:break
    def limits():
        if case.get('limited_write'):
            signal.signal(signal.SIGXFSZ,signal.SIG_IGN);resource.setrlimit(resource.RLIMIT_FSIZE,(0,resource.RLIM_INFINITY))
    def snapshot(label):
        drain_syslog();time.sleep(.12);drain_syslog()
        record={'id':label,'files':{},'objects':{},'lease_fd_targets':[], 'events':(folder/'events').read_text().splitlines() if (folder/'events').exists() else []}
        for name in [path,'/m2/target','/m2/held','/m2/other']:
            leaf=image_path(root,name,follow_leaf=False)
            if leaf.exists() or leaf.is_symlink():
                info=leaf.lstat()
                record['objects'][name]={'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid,
                    'link':str(leaf.readlink()) if leaf.is_symlink() else None}
            candidate=image_path(root,name)
            if candidate.is_file():
                raw=candidate.read_bytes();(out/(label+'-'+name.replace('/','_'))).write_bytes(raw)
                record['files'][name]=file_rows(raw,epochs,int(time.time()))
        for descriptor in Path(f'/proc/{process.pid}/fd').glob('*'):
            try:
                target=os.readlink(descriptor)
                if target.startswith(str(root)):target=target[len(str(root)):]
                if target in [path,'/m2/target','/m2/held','/m2/other']:
                    record['lease_fd_targets'].append(target)
            except FileNotFoundError:pass
        record['lease_fd_targets'].sort()
        observed['snapshots'].append(record)
    def probes(label):
        for index,probe in enumerate(case['probes']):
            for transport in ['udp','tcp']:
                answer,raw=dns(probe,0x4100+index,transport);trace['queries'].append(raw)
                observed['dns'].append(dict(stage=label,name=probe['name'],transport=transport,response=answer))
    def start():
        nonlocal process
        launch=command(root,binary,'-k',*argv)
        if case.get('userspec'):launch.insert(1,'--userspec='+case['userspec'])
        process=subprocess.Popen(launch,stdout=stdout,stderr=log,preexec_fn=limits,start_new_session=True)
        def ready():
            drain_syslog()
            if process.poll() is not None:return 'exited'
            try:
                answer,_=dns(dict(name='ready.lease.test'),0x4010,'udp')
                if [r['data'] for r in answer['records']]!=['8.8.8.8']:raise AssertionError('wrong health answer')
                return 'ready'
            except (OSError,socket.timeout):return False
        status=wait(ready,4,'startup did not settle')
        if status=='ready':
            identity=process_identity(root,process.pid)
            if identity['sha256']!=(STOCK_SHA256 if side=='c' else sha256(root/'usr/sbin/dnsmasq-rs')):raise AssertionError('running identity mismatch')
            trace['processes'].append(identity);observed['ready']=True
        return status
    def stop():
        drain_syslog()
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:process.wait(3)
            except subprocess.TimeoutExpired:process.kill();process.wait();observed['forced']=True
    try:
        if case.get('fifo'):
            process=subprocess.Popen(command(root,binary,'-k',*argv),stdout=stdout,stderr=log,start_new_session=True)
            def descriptor():
                for candidate in Path(f'/proc/{process.pid}/fd').glob('*'):
                    try:
                        if os.readlink(candidate).endswith('/m2/leases'):return int(candidate.name)
                    except FileNotFoundError:pass
                return None
            fd=wait(descriptor,3,'lease stream fd absent');fault=out/'read-error.json'
            trace['processes'].append(process_identity(root,process.pid))
            tracer=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--trace-read-error',str(process.pid),str(fd),str(fault)])
            wait(lambda:Path(str(fault)+'.ready').exists(),3,'read tracer attach failed')
            writer=os.open(real,os.O_WRONLY|os.O_NONBLOCK)
            for data in [text.encode(),b'0 ',b'uncopied']:
                os.write(writer,data);time.sleep(.1)
                if tracer.poll() is not None:break
            os.close(writer);tracer.wait(4);process.wait(4)
            observed['read_error']=json.loads(fault.read_text())
        else:
            status=start()
            if status=='ready':
                snapshot('startup');probes('startup')
                for index,action in enumerate(case['actions']):
                    label=str(index)+'-'+action['op']
                    if action['op']=='dhcp':
                        wire=packet(action,0x5100+index);endpoint.sendto(wire,('255.255.255.255' if action['kind']==1 else '127.0.0.1',67))
                        reply=None
                        try:reply,peer=endpoint.recvfrom(65535)
                        except socket.timeout:pass
                        trace['packets'].append(dict(request=wire.hex(),response=reply.hex() if reply else None))
                        result={'request':action,'reply':None}
                        if reply:
                            options=decode(reply,0x5100+index)
                            if action['kind'] in (1,3):
                                duration=struct.unpack('!I',options.get(51,b'\0'*4))[0]
                                t1=struct.unpack('!I',options.get(58,b'\0'*4))[0]
                                t2=struct.unpack('!I',options.get(59,b'\0'*4))[0]
                                if not (duration==600 and t2-t1==225 and 263<=t1<=300):
                                    observed['invalid_timers'].append(dict(stage=label,duration=duration,t1=t1,t2=t2))
                            for code in [58,59]:options.pop(code,None)
                            if action['kind']==8 and 51 in options:
                                duration=struct.unpack('!I',options[51])[0]
                                if 295<=duration<=300:options[51]=b'FUTURE'
                            result['reply']={'header':reply[:240].hex(),'options':{str(k):v.hex() for k,v in options.items()},'peer':list(peer),'length':len(reply)}
                        observed['dhcp'].append(result)
                    elif action['op']=='replace':
                        held=folder/'held';image_path(root,path).rename(held);image_path(root,path).write_text(action['text'])
                    elif action['op']=='hup':process.send_signal(signal.SIGHUP)
                    elif action['op']=='probes':probes(label)
                    elif action['op']=='wait':time.sleep(action['seconds'])
                    elif action['op']=='lift-write-limit':resource.prlimit(process.pid,resource.RLIMIT_FSIZE,(resource.RLIM_INFINITY,resource.RLIM_INFINITY))
                    elif action['op']=='wait-file':wait(lambda:image_path(root,path).stat().st_size>0,action['seconds'],'idle write retry absent')
                    elif action['op']=='restart':stop();start()
                    else:raise ValueError(action)
                    snapshot(label)
                stop()
        observed['exit']=process.poll()
    finally:
        if tracer and tracer.poll() is None:tracer.kill();tracer.wait()
        stop();endpoint.close();log.close();stdout.close()
        drain_syslog()
        syslog.close();trace['syslog']=[value.hex() for value in syslog_packets]
        syslog_diagnostics=diagnostics(b'\n'.join(syslog_packets))
        observed['diagnostics']=syslog_diagnostics or diagnostics((out/'stderr').read_bytes())
        observed['pid_file']=(folder/'daemon.pid').exists()
        def image_children():
            result=[]
            for candidate in Path('/proc').iterdir():
                if not candidate.name.isdigit():continue
                try:
                    if os.readlink(candidate/'root')==str(root):result.append(int(candidate.name))
                except (FileNotFoundError,PermissionError):pass
            return result
        deadline=time.monotonic()+1
        while image_children() and time.monotonic()<deadline:time.sleep(.01)
        observed['process_live']=bool(process and Path(f'/proc/{process.pid}').exists())
        observed['live_children']=image_children()
        for pid in observed['live_children']:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        save(out/'observed.json',observed);save(out/'trace.json',trace)
        if mounted:
            subprocess.run(['mount','-o','remount,rw',str(folder/'rofs')],check=True)
            subprocess.run(['umount',str(folder/'rofs')],check=True)
    return observed


def compare(c,rust,case):
    failures=[]
    for side,value in [('c',c),('rust',rust)]:
        if value['syntax']['exit']!=case.get('expected_test',0):failures.append(dict(side=side,kind='syntax-exit'))
        if value['exit']!=case.get('expected_exit',0):failures.append(dict(side=side,kind='startup-exit',actual=value['exit']))
        if value['ready']!=(case.get('expected_exit',0)==0):failures.append(dict(side=side,kind='ready'))
        if value['forced'] or value['pid_file'] or value['process_live'] or value.get('live_children'):failures.append(dict(side=side,kind='lifecycle'))
        if value.get('invalid_timers'):failures.append(dict(side=side,kind='timer-bounds',actual=value['invalid_timers']))
        if value['ready']:
            if len(value['snapshots'])!=1+len(case.get('actions',[])):failures.append(dict(side=side,kind='missing-snapshot'))
            expected_dns=len(case.get('probes',[]))*2*(1+sum(a['op']=='probes' for a in case.get('actions',[])))
            if len(value['dns'])!=expected_dns:failures.append(dict(side=side,kind='missing-DNS-observation'))
            actions=[a for a in case.get('actions',[]) if a['op']=='dhcp']
            if len(value['dhcp'])!=len(actions):failures.append(dict(side=side,kind='missing-DHCP-observation'))
            for action,result in zip(actions,value['dhcp']):
                status=result.get('reply',{}).get('options',{}).get('53') if result.get('reply') else None
                expected={1:'02',3:'05',4:None,7:None,8:'05'}[action['kind']]
                if status!=expected:failures.append(dict(side=side,kind='DHCP-calibration',actual=status,expected=expected))
        if case.get('fifo'):
            proof=value.get('read_error',{})
            if not proof.get('injected') or not any(r['result']>0 for r in proof.get('reads',[])) or not any(r['result']==-errno.EIO and r['injected'] for r in proof.get('reads',[])):
                failures.append(dict(side=side,kind='partial-read-error-witness'))
    for field in ['syntax','ready','snapshots','dns','dhcp','exit','diagnostics']:
        if c[field]!=rust[field]:failures.append(dict(kind='paired-'+field,c=c[field],rust=rust[field]))
    return failures


def controls():
    case=dict(expected_exit=0,actions=[dict(op='dhcp',kind=3)],probes=[dict(name='first')])
    success=dict(syntax=dict(exit=0),ready=True,snapshots=[{'files':{'leases':[1,2]},'events':['old|first','old|second']},{'files':{'leases':[1,2]}}],
        dns=[{'name':'first'},{'name':'first'}],dhcp=[{'reply':{'options':{'53':'05'}}}],exit=0,diagnostics=[],forced=False,pid_file=False,process_live=False)
    rows=[]
    for field,value in [('syntax',dict(exit=1)),('ready',False),('snapshots',[]),('dns',[]),('dhcp',[]),('exit',3),
                        ('diagnostics',['unexpected']),('forced',True),('pid_file',True),('process_live',True)]:
        altered=copy.deepcopy(success);altered[field]=value
        rows.append(dict(id=field,rejected=bool(compare(success,altered,case))))
    if not all(r['rejected'] for r in rows):raise AssertionError('negative comparison control missed corruption')
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path);parser.add_argument('--rust',type=Path)
    parser.add_argument('--rust-sha256');parser.add_argument('--source-commit');parser.add_argument('--output',type=Path)
    parser.add_argument('--scenarios');parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--trace-read-error',nargs=3)
    args=parser.parse_args()
    if args.trace_read_error:return trace_read_error(int(args.trace_read_error[0]),int(args.trace_read_error[1]),Path(args.trace_read_error[2]))
    calibration=controls()
    if args.self_test:print(json.dumps(calibration));return 0
    if not all([args.image_root,args.rust,args.rust_sha256,args.source_commit,args.output]):parser.error('image/candidate/source/output required')
    if os.geteuid()!=0 or os.environ.get('DNSMASQ_TEST_ISOLATED')!='1':parser.error('root isolated namespace required')
    if sha256(args.rust)!=args.rust_sha256:parser.error('candidate identity mismatch')
    out=args.output.resolve()
    if out.exists() or 'private' not in out.parts:parser.error('fresh private output required')
    out.mkdir(parents=True);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    manifest_path=Path(__file__).with_suffix('.json');manifest=json.loads(manifest_path.read_text())
    cases=scenarios()
    if set(manifest['required_scenarios'])-{c['id'] for c in cases}:raise AssertionError('frozen scenario missing in driver')
    if args.scenarios:
        selected=args.scenarios.split(',')
        if set(selected)-{c['id'] for c in cases}:parser.error('unknown scenario')
        cases=[c for c in cases if c['id'] in selected]
    driver=out/'driver';driver.mkdir()
    for name in [Path(__file__).name,manifest_path.name,*DEPENDENCIES]:shutil.copy2(Path(__file__).with_name(name),driver/name)
    roots={side:prepare(args.image_root,None,out/side,args.rust) for side in ['c','rust']}
    result=dict(source_commit=args.source_commit,rust_sha256=args.rust_sha256,c_sha256=STOCK_SHA256,
        driver_sha256=sha256(Path(__file__)),manifest_sha256=sha256(manifest_path),negative_controls=calibration,scenarios=[],boundaries=[],failures=[])
    for case in cases:
        folder=out/case['id'];folder.mkdir();entry=dict(id=case['id'],failures=[])
        try:
            c=run(roots['c'],'c',case,folder/'c');rust=run(roots['rust'],'rust',case,folder/'rust')
            entry['failures']=compare(c,rust,case)
        except Exception as error:entry['failures'].append(dict(kind='infrastructure',error=repr(error)))
        result['scenarios'].append(entry);save(out/'progress.json',result)
        print(json.dumps(dict(case=case['id'],failures=len(entry['failures']))),flush=True)
    executed={c['id']:c for c in result['scenarios']}
    result['boundaries']=[dict(b,checked=all(s in executed and not executed[s]['failures'] for s in b['required_scenarios'])) for b in manifest['boundaries']]
    result['failures']=[dict(case=case['id'],**f) for case in result['scenarios'] for f in case['failures']]
    result['closed']=manifest.get('qualification_ready',False) and all(b['checked'] for b in result['boundaries']) and not result['failures']
    save(out/'result.json',result)
    print(json.dumps(dict(cases=len(cases),boundaries=len(result['boundaries']),failures=len(result['failures']),closed=result['closed'])))
    return int(bool(result['failures']))


if __name__=='__main__':raise SystemExit(main())
