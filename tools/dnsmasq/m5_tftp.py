#!/usr/bin/env python3
"""TFTP family comparison against the exact image ELF in disposable namespaces.

Run through run_isolated.sh. Fixed private bridge/veth endpoints only; the tool
accepts no network target. It reuses the M2 image-root and process cleanup tools.
Raw replies and every unsuccessful run stay in evidence/M5/tftp. The directed
parser cases are bounded corruptions of an ordinary local read request; no
path traversal, out-of-bounds C reproductions or external services are used.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import Network, SERVER, CLIENT, ip, save, stop

V6_SERVER = 'fd42:77::1'
V6_CLIENT = 'fd42:77::2'
ROOT = '/m2/tftp'
MAC = CLIENT['mac'].replace(':', '-')


def scenarios():
    base = 'enable-tftp\ntftp-root=' + ROOT + '/global\n'
    return [
        dict(name='ordinary-dual-stack', config=base, requests=[{}, {'v6': True}, {'mode': 'netascii'}]),
        dict(name='dedicated-interface', config=base.replace('enable-tftp\n', 'enable-tftp=br-lan\n'), requests=[{}, {'v6': True}]),
        dict(name='excluded-interface', config=base.replace('enable-tftp\n', 'enable-tftp=absent0\n'), requests=[{'silent': True}, {'v6': True, 'silent': True}]),
        dict(name='interface-root-earliest', config=base+'tftp-root='+ROOT+'/first,br-lan\ntftp-root='+ROOT+'/last,br-lan\n', requests=[{}, {'v6': True}]),
        dict(name='unique-ip', config=base+'tftp-unique-root=ip\n', requests=[{}, {'v6': True}]),
        dict(name='unique-mac', config=base+'tftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='unique-ip-and-mac', config=base+'tftp-unique-root=ip\ntftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='unique-missing-fallback', config=base.replace('/global', '/first')+'tftp-unique-root=ip\ntftp-unique-root=mac\n', requests=[{}, {'v6': True}]),
        dict(name='lowercase', config=base+'tftp-lowercase\n', requests=[{'filename': 'BOOT.BIN'}]),
        dict(name='secure-ownership', config=base+'tftp-secure\n', requests=[{'filename': 'owned.bin'}, {'filename': 'root.bin'}]),
        dict(name='negotiation-mtu', config=base+'tftp-mtu=1200\n', requests=[{'options': {'blksize': '2000', 'tsize': '0', 'timeout': '2', 'windowsize': '1'}}, {'v6': True, 'options': {'blksize': '2000'}}]),
        dict(name='no-blocksize', config=base+'tftp-no-blocksize\n', requests=[{'options': {'blksize': '128', 'tsize': '0'}}]),
        dict(name='single-port', binding='', config=base+'tftp-single-port\n', requests=[{'single': True}, {'single': True, 'v6': True}]),
        dict(name='port-range', config=base+'tftp-port-range=35000,35003\n', requests=[{'range': [35000, 35003]}, {'range': [35000, 35003], 'v6': True}]),
        dict(name='missing-root-fails', config=base.replace('/global', '/missing'), requests=[], startup_failure=True),
        dict(name='missing-root-no-fail', config=base.replace('/global', '/missing')+'tftp-no-fail\n', requests=[{}]),
        dict(name='sighup-live-transfer', config=base, requests=[{'hold': True}]),
        dict(name='directed-parser-corpus', config=base, requests=[{'corpus': True}]),
    ]


def read_request(item):
    packet = bytearray(b'\0\1')
    for text in [item.get('filename', 'boot.bin'), item.get('mode', 'octet')]:
        packet.extend(text.encode()); packet.append(0)
    for name, value in item.get('options', {}).items():
        packet.extend(name.encode()+b'\0'+value.encode()+b'\0')
    return bytes(packet)


def corpus():
    normal = read_request({})
    # Truncated benign read, invalid mode, bounded option numeric/terminator
    # cases and unrelated opcodes. All paths remain the fixture's boot.bin.
    packets = [normal[:n] for n in range(0, len(normal))]
    packets += [b'\0\1boot.bin\0unknown\0', b'\0\2boot.bin\0octet\0',
                b'\0\7boot.bin\0octet\0', b'\0\4\0\1',
                normal+b'blksize\0', normal+b'blksize\0bad\0',
                normal+b'timeout\00\0', normal+b'windowsize\01\0']
    return packets


def fetch(item, out):
    family = socket.AF_INET6 if item.get('v6') else socket.AF_INET
    target = (V6_SERVER if item.get('v6') else SERVER, 69)
    result = {'kind': 'silent'}
    payload, records, options = bytearray(), [], {}
    with socket.socket(family, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.65 if item.get('silent') else 3)
        request = read_request(item)
        (out/'request.bin').write_bytes(request)
        endpoint.sendto(request, target)
        expected, blocksize, transfer = 1, 512, None
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            try:
                packet, peer = endpoint.recvfrom(65535)
            except socket.timeout:
                if not records:
                    return result
                raise
            (out/f'reply-{len(records):03}.bin').write_bytes(packet)
            if len(packet) < 2:
                raise AssertionError('short TFTP reply')
            opcode = int.from_bytes(packet[:2], 'big')
            if transfer is None:
                transfer = peer
            if peer != transfer or peer[0] != target[0]:
                raise AssertionError('TFTP source changed')
            source = 'single' if peer[1] == 69 else 'dedicated'
            if item.get('range'):
                source = 'range' if item['range'][0] <= peer[1] <= item['range'][1] else 'outside-range'
            records.append({'opcode': opcode, 'length': len(packet)})
            if opcode == 5:
                return {'kind': 'error', 'code': int.from_bytes(packet[2:4], 'big'), 'source': source}
            if opcode == 6:
                fields = packet[2:].split(b'\0')
                if fields[-1] != b'' or len(fields) % 2 != 1:
                    raise AssertionError('malformed OACK')
                options = {fields[i].decode(): fields[i+1].decode() for i in range(0, len(fields)-1, 2)}
                blocksize = int(options.get('blksize', 512))
                endpoint.sendto(b'\0\4\0\0', peer)
                continue
            if opcode != 3 or len(packet) < 4:
                raise AssertionError('expected DATA')
            block = int.from_bytes(packet[2:4], 'big')
            if block != expected:
                if block == ((expected-1) & 0xffff):
                    endpoint.sendto(struct.pack('!HH', 4, block), peer)
                    continue
                raise AssertionError('out of order DATA')
            payload.extend(packet[4:])
            if item.get('hold') and block == 1:
                (out/'hold-ready').write_text('ready\n')
                until = time.monotonic()+3
                while not (out/'hold-release').exists() and time.monotonic() < until:
                    time.sleep(.01)
                if not (out/'hold-release').exists():
                    raise AssertionError('SIGHUP driver did not release')
            endpoint.sendto(struct.pack('!HH', 4, block), peer)
            expected = (expected+1) & 0xffff
            if len(packet)-4 < blocksize:
                return {'kind': 'data', 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                        'source': source, 'options': options, 'blocks': expected-1}
        raise AssertionError('TFTP transfer deadline')


def client(args):
    item = json.loads(args.request)
    args.out.mkdir(parents=True, exist_ok=True)
    result = {}
    try:
        if item.get('corpus'):
            result = {'kind': 'corpus', 'rows': []}
            for index, packet in enumerate(corpus()):
                (args.out/f'corpus-{index:03}.bin').write_bytes(packet)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
                    endpoint.settimeout(.1)
                    endpoint.sendto(packet, (SERVER, 69))
                    try:
                        reply, _ = endpoint.recvfrom(65535)
                        (args.out/f'corpus-{index:03}.reply').write_bytes(reply)
                        row = {'opcode': int.from_bytes(reply[:2], 'big')}
                        if reply[:2] == b'\0\5': row['code'] = int.from_bytes(reply[2:4], 'big')
                        # Ordinary ERROR aborts any transfer created by a
                        # valid prefix; malformed traffic never fills capacity.
                        if reply[:2] in (b'\0\3', b'\0\6'):
                            endpoint.sendto(b'\0\5\0\0done\0', _)
                    except socket.timeout:
                        row = {'silent': True}
                    result['rows'].append(row)
            # A valid transfer after the corpus confirms the daemon remains live.
            good = args.out/'valid-after'; good.mkdir()
            result['valid_after'] = fetch({}, good)
        else:
            result = fetch(item, args.out)
    except Exception as error:
        result['failure'] = repr(error)
    save(args.out/'result.json', result)
    return int('failure' in result)


def files(root):
    run = root/'run/dnsmasq'; run.mkdir(exist_ok=True); os.chown(run,453,453)
    base = root/'m2/tftp'
    variants = {'global': b'global\n'*220, 'first': b'first\r\n'*210, 'last': b'last\n'*260,
                'global/10.77.0.2': b'ip4\n'*320, 'global/'+V6_CLIENT: b'ip6\n'*320,
                'global/'+MAC: b'mac\n'*320,
                'global/10.77.0.2/'+MAC: b'ip4mac\n'*220,
                'global/'+V6_CLIENT+'/'+MAC: b'ip6mac\n'*220}
    for directory, data in variants.items():
        path = base/directory; path.mkdir(parents=True, exist_ok=True)
        (path/'boot.bin').write_bytes(data)
        (path/'boot.bin').chmod(0o644)
    for name, owner in [('owned.bin',453), ('root.bin',0)]:
        path = base/'global'/name; path.write_bytes(b'ownership\n'); path.chmod(0o644); os.chown(path, owner, owner)


def run_side(root, binary, scenario, out, network):
    out.mkdir()
    config = 'port=0\nno-resolv\nno-hosts\n'+scenario.get('binding','bind-interfaces\n')+'interface=br-lan\nuser=dnsmasq\ngroup=dnsmasq\npid-file=/run/dnsmasq/m5-tftp.pid\n'+scenario['config']
    (root/'run/dnsmasq/m5-tftp.pid').unlink(missing_ok=True)
    (root/'m2/tftp.conf').write_text(config)
    (out/'dnsmasq.conf').write_text(config)
    result, process, client_process = {'requests': []}, None, None
    try:
        with (out/'daemon.log').open('w') as log:
            process = subprocess.Popen(command(root,binary,'-k','-C','/m2/tftp.conf'), stdout=log,stderr=log,start_new_session=True)
            time.sleep(.25)
            result['started'] = process.poll() is None
            if not result['started']:
                result['exit'] = process.returncode
                return result
            result['identity'] = process_identity(root,process.pid)
            for index, item in enumerate(scenario['requests']):
                request_out=out/f'request-{index:02}'
                argv=network.argv(sys.executable,Path(__file__).resolve(),'--client','--request',json.dumps(item),'--out',request_out)
                client_process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                if item.get('hold'):
                    deadline=time.monotonic()+4
                    while not (request_out/'hold-ready').exists() and time.monotonic()<deadline and client_process.poll() is None:
                        time.sleep(.01)
                    if not (request_out/'hold-ready').exists(): raise AssertionError('live transfer did not reach hold')
                    os.kill(process.pid,signal.SIGHUP)
                    time.sleep(.05)
                    (request_out/'hold-release').write_text('release\n')
                stdout,stderr=client_process.communicate(timeout=12)
                (out/f'client-{index:02}.log').write_bytes(stdout+stderr)
                if client_process.returncode:
                    raise AssertionError(f'client exit {client_process.returncode}')
                row=json.loads((request_out/'result.json').read_text()); result['requests'].append(row)
                client_process=None
            result['alive_after']=process.poll() is None
            result['threads']=len(list(Path(f'/proc/{process.pid}/task').iterdir()))
    except Exception as error:
        result['failure']=repr(error)
    finally:
        result['client_cleanup']=stop(client_process)
        result['cleanup']=stop(process)
        result['pid_removed']=not (root/'run/dnsmasq/m5-tftp.pid').exists()
        save(out/'result.json',result)
    return result


def executed(result, scenario):
    if 'failure' in result or result.get('started') == scenario.get('startup_failure', False):
        return False
    if not result['started']:
        return True
    if not result.get('alive_after') or result.get('threads') != 1 or not result.get('pid_removed'):
        return False
    if result.get('cleanup', {}).get('forced'):
        return False
    if len(result['requests']) != len(scenario['requests']):
        return False
    for item, row in zip(scenario['requests'], result['requests']):
        kind = 'silent' if item.get('silent') else 'corpus' if item.get('corpus') else 'data'
        if scenario['name'] == 'missing-root-no-fail' or scenario['name'] == 'secure-ownership' and item.get('filename') == 'root.bin':
            kind = 'error'
        if row.get('kind') != kind:
            return False
        if kind == 'corpus' and row.get('valid_after', {}).get('kind') != 'data':
            return False
    return True


def semantic(result):
    if not result.get('started'):
        return {'started': False, 'exit': result.get('exit')}
    return {key:result.get(key) for key in ['started','requests','alive_after','threads','pid_removed','failure']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path)
    parser.add_argument('--rust-binary',type=Path)
    parser.add_argument('--source-commit')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--case',action='append',default=[])
    parser.add_argument('--sides',choices=['c','both'],default='both')
    parser.add_argument('--client',action='store_true')
    parser.add_argument('--request')
    parser.add_argument('--write-corpus',action='store_true')
    args=parser.parse_args()
    if args.client:return client(args)
    if args.write_corpus:
        if 'private' not in args.out.resolve().parts: raise SystemExit('corpus must remain private')
        args.out.mkdir(parents=True,exist_ok=True)
        for index, packet in enumerate([read_request({}), read_request({'mode':'netascii'}), read_request({'options':{'blksize':'1468','tsize':'0','timeout':'2','windowsize':'4'}}), *corpus()]):
            (args.out/f'seed-{index:03}').write_bytes(packet)
        return 0
    if os.environ.get('DNSMASQ_TEST_ISOLATED')!='1' or os.geteuid()!=0:raise SystemExit('run_isolated.sh required')
    if not args.image_root or not args.rust_binary or not args.source_commit:raise SystemExit('image, Rust ELF and source commit required')
    args.out.mkdir(parents=True,exist_ok=False)
    selected=[item for item in scenarios() if not args.case or item['name'] in args.case]
    if args.case and len(selected)!=len(set(args.case)):raise SystemExit('unknown or duplicate scenario')
    save(args.out/'plan.json',{'scenarios':selected,'source_commit':args.source_commit,'rust_sha256':sha256(args.rust_binary),'tool_sha256':sha256(__file__),'deadline_seconds':12,'reference':'image-elf'})
    network=Network();report={'passed':False,'rows':[],'failures':[]}
    try:
        root=prepare(args.image_root,None,args.out/'image',args.rust_binary)
        files(root)
        network.start()
        ip('addr','add',V6_SERVER+'/64','dev','br-lan','nodad')
        network.exec('ip','addr','add',V6_CLIENT+'/64','dev','client0','nodad')
        ip('neigh','replace','10.77.0.2','lladdr',CLIENT['mac'],'nud','permanent','dev','br-lan')
        ip('-6','neigh','replace',V6_CLIENT,'lladdr',CLIENT['mac'],'nud','permanent','dev','br-lan')
        for scenario in selected:
            folder=args.out/scenario['name'];folder.mkdir()
            row={'scenario':scenario['name']}
            for side in ['c'] if args.sides=='c' else ['c','rust']:
                row[side]=run_side(root,side,scenario,folder/side,network)
            if args.sides=='both':
                row['equal']=semantic(row['c'])==semantic(row['rust'])
                if row['c'].get('pid_removed') != row['rust'].get('pid_removed'):
                    row['side_effect_difference']={'pid_removed':{'c':row['c'].get('pid_removed'),'rust':row['rust'].get('pid_removed')},'scope':'startup failure PID residue; retained for explicit review'}
                row['negative_control_detected']=False
                if row['c'].get('requests') and row['rust'].get('requests'):
                    negative=copy.deepcopy(row['rust']); negative['requests'][0]={'kind':'wrong-response'}
                    row['negative_control_detected']=semantic(row['c'])!=semantic(negative)
                else:row['negative_control_detected']=not row['c'].get('requests')
            row['executed']=all(executed(row[side], scenario) for side in (['c'] if args.sides=='c' else ['c','rust']))
            report['rows'].append(row);save(args.out/'result.json',report)
        report['passed']=args.sides=='both' and all(row['executed'] and row['equal'] and row['negative_control_detected'] for row in report['rows'])
    except Exception as error:
        report['failures'].append(repr(error))
    finally:
        report['network_cleanup']=network.close()
        report['remaining_interfaces']=[name for _,name in socket.if_nameindex()]
        if sorted(report['remaining_interfaces'])!=['lo']:report['passed']=False
        save(args.out/'result.json',report)
    print(json.dumps({'passed':report['passed'],'result':str(args.out/'result.json')}))
    return int(not report['passed']) if args.sides=='both' else int(bool(report['failures']) or not all(row['executed'] for row in report['rows']))


if __name__=='__main__':raise SystemExit(main())
