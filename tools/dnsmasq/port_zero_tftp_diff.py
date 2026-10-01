#!/usr/bin/env python3
"""Compare DNS-disabled TFTP-only startup, reload and socket/file cleanup.

The resolver and hosts paths are FIFOs with no writer, so opening them as DNS
input would block. Test networking and files remain private. C provides the
protocol result; separate assertions ensure port=0 creates no DNS listeners.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def ready(pid):
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try: target = fd.readlink().as_posix()
        except FileNotFoundError: continue
        if target.startswith('socket:['): inodes.add(target[8:-1])
    return any(line.split()[1].endswith(':0045') and line.split()[9] in inodes
               for line in Path(f'/proc/{pid}/net/udp').read_text().splitlines()[1:])


def run(binary, config, directory):
    checks=[]
    with (directory/'stderr.log').open('w') as log:
        process=subprocess.Popen([str(binary),'-d','-C',str(config)],stdout=log,stderr=log)
        try:
            until=time.monotonic()+4
            while not ready(process.pid):
                assert process.poll() is None, 'startup failed'
                if time.monotonic()>=until:raise AssertionError('no TFTP listener; DNS-disabled input may have blocked')
                time.sleep(.01)
            for label in ('before-hup','after-hup'):
                if label=='after-hup':
                    process.send_signal(signal.SIGHUP)
                    time.sleep(.15)
                # Exact port absence as an observable behavior, not an empty
                # response timeout that could hide a bound broken listener.
                for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
                    with socket.socket(socket.AF_INET,kind) as probe:
                        probe.bind(('127.0.0.1',53))
                    checks.append({'case':label+'-dns-port-free','socket':kind})
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    request=b'\0\x01fixture.txt\0octet\0'
                    client.sendto(request,('127.0.0.1',69))
                    packet,peer=client.recvfrom(2048)
                    assert packet==b'\0\x03\0\x01isolated-tftp\n'
                    assert peer[0]=='127.0.0.1' and peer[1]!=69
                    checks.append({'case':label+'-transfer','request':request.hex(),'packet':packet.hex(),
                                   'peer_address':peer[0],'dedicated_port':True})
                    client.sendto(b'\0\x04\0\x01',peer)
            process.send_signal(signal.SIGTERM)
            assert process.wait(4)==0
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:probe.bind(('127.0.0.1',69))
            checks.append({'case':'normal-exit-and-port-released'})
        finally:
            if process.poll() is None:process.kill();process.wait(4)
            (directory/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--c',required=True,type=Path);parser.add_argument('--rust',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    assert [name for _,name in socket.if_nameindex()]==['lo']
    out=args.out.resolve();assert 'private' in out.parts;out.mkdir(parents=True,exist_ok=False)
    root=out/'files';root.mkdir();(root/'fixture.txt').write_bytes(b'isolated-tftp\n')
    for name in ('resolver','hosts'):os.mkfifo(out/name)
    config=out/'dnsmasq.conf'
    config.write_text(f'port=0\nlisten-address=127.0.0.1\nresolv-file={out / "resolver"}\naddn-hosts={out / "hosts"}\nenable-tftp\ntftp-root={root}\n')
    report={'status':'failed','identity':{key:hashlib.sha256(getattr(args,key).read_bytes()).hexdigest() for key in ('c','rust')}}
    try:
        results={}
        for key in ('c','rust'):
            directory=out/key;directory.mkdir()
            results[key]=run(getattr(args,key).resolve(),config,directory)
        assert len(results['c'])==len(results['rust'])==7
        assert results['c']==results['rust']
        corrupt=[dict(row) for row in results['c']];corrupt[2]['packet']='00'
        assert corrupt!=results['c']
        report.update(status='passed',matched=7,calibration={'equal':1,'wrong-data-detected':1})
    except Exception as error:report['error']=repr(error)
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
    return int(report['status']!='passed')


if __name__=='__main__':raise SystemExit(main())
