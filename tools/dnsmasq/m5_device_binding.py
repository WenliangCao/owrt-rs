#!/usr/bin/env python3
"""Exact-image DHCP SO_BINDTODEVICE callers, with actual target socket receipts."""
import argparse
import copy
import ctypes
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time

from dns_service_probe import query, semantics
from m2_rootfs import STOCK_SHA256, command, prepare, process_identity, sha256

PORT = 15370
NOTICE = b'DHCP, sockets bound exclusively to interface '
WARNING = b'error binding DHCP socket to device '


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def frozen_cases():
    manifest = json.loads(Path(__file__).with_suffix('.json').read_text())
    if manifest.get('cases')!=scenarios() or manifest.get('stock_c_sha256')!=STOCK_SHA256:
        raise ValueError('driver differs from frozen source cases')
    return manifest['cases']


def scenarios():
    rows = []
    for mode, flag in [('static', 'bind-interfaces'), ('dynamic', 'bind-dynamic')]:
        profiles = [
            ('unique', ['interface=m5a'], 'm5a'),
            ('wildcard-name', ['interface=m5*'], ''),
            ('two', ['interface=m5a', 'interface=m5b'], ''),
            ('listen-only', ['listen-address=192.0.2.1'], ''),
            ('no-dhcpv4-ghost6', ['interface=m5a', 'no-dhcpv4-interface=m5a'], 'm5a'),
            ('two-with-ghost6', ['interface=m5a', 'interface=m5b', 'no-dhcpv4-interface=m5b'], ''),
            ('no-dhcp-both', ['interface=m5a', 'no-dhcp-interface=m5a'], ''),
            ('alias', ['interface=m5a:1'], 'm5a'),
            ('relay-pxe', ['interface=m5a', 'dhcp-relay=192.0.2.1,198.51.100.2', 'pxe-service=0,Binding fixture,boot.bin'], 'm5a'),
            ('relay-only', ['interface=m5a', 'dhcp-relay=192.0.2.1,198.51.100.2'], ''),
            ('runtime-recreate', ['interface=m5a', 'quiet-dhcp'], 'm5a'),
            ('except-listen-override', ['interface=m5a', 'except-interface=m5a', 'listen-address=192.0.2.1'], 'm5a'),
        ]
        for profile, config, device in profiles:
            rows.append(dict(case=mode+'-'+profile, mode=mode, profile=profile,
                             config=[flag]+config, device=device, main=profile not in ('relay-pxe', 'relay-only'),
                             pxe=profile=='relay-pxe', action='recreate' if profile=='runtime-recreate' else None))
    rows.append(dict(case='wildcard-listener-unique', mode='wildcard', profile='unique',
                     config=['interface=m5a'], device='', main=True, pxe=False, action=None))
    rows.append(dict(case='dynamic-missing-late', mode='dynamic', profile='missing-late',
                     config=['bind-dynamic', 'interface=m5a', 'interface=m5b'], device='',
                     main=True, pxe=False, action='late'))
    rows.append(dict(case='static-no-dhcp-service', mode='static', profile='no-service',
                     config=['bind-interfaces', 'interface=m5a'], device='',
                     main=False, pxe=False, action=None, no_service=True))
    return rows


def ip(*args):
    return subprocess.run(['ip', *map(str, args)], check=True, capture_output=True, text=True)


def create(name):
    ip('link', 'add', name, 'type', 'dummy')
    ip('link', 'set', name, 'addrgenmode', 'none')
    ip('link', 'set', name, 'up')
    ip('addr', 'add', '192.0.2.1/24' if name=='m5a' else '198.51.100.1/24', 'dev', name)


def network():
    return dict(links=json.loads(ip('-j', '-d', 'link', 'show').stdout),
                addresses=json.loads(ip('-j', 'addr', 'show').stdout))


def target_sockets(pid):
    """Duplicate only this owned daemon's UDP67/4011 sockets; never mutate them."""
    if os.uname().machine not in ('aarch64', 'x86_64'):
        raise ValueError('pidfd_getfd syscall number is frozen for aarch64/x86_64 only')
    udp = {}
    for line in Path('/proc', str(pid), 'net/udp').read_text().splitlines()[1:]:
        columns = line.split()
        port = int(columns[1].split(':')[1], 16)
        if port in (67, 4011):
            udp[columns[9]] = port
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    pidfd = os.pidfd_open(pid)
    receipts = []
    try:
        for path in sorted(Path('/proc', str(pid), 'fd').iterdir(), key=lambda p:int(p.name)):
            try:
                match = re.fullmatch(r'socket:\[(\d+)\]', os.readlink(path))
            except FileNotFoundError:
                continue
            if not match or match[1] not in udp:
                continue
            ctypes.set_errno(0)
            fd = libc.syscall(ctypes.c_long(438), ctypes.c_int(pidfd), ctypes.c_int(int(path.name)), ctypes.c_uint(0))
            if fd < 0:
                raise OSError(ctypes.get_errno(), 'pidfd_getfd')
            with socket.socket(fileno=fd) as endpoint:
                row = dict(target_fd=int(path.name), inode=match[1], family=endpoint.family,
                           type=endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE),
                           local=list(endpoint.getsockname()), port=udp[match[1]])
                try:
                    row['device_wire'] = endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, 16).hex()
                except OSError as error:
                    row['device_errno'] = error.errno
                receipts.append(row)
    finally:
        os.close(pidfd)
    return sorted(receipts, key=lambda row:row['port'])


def health(folder, label, address):
    packet = query('health.bind.test', ident=0x7100)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(2)
        endpoint.sendto(packet, (address, PORT))
        reply, peer = endpoint.recvfrom(4096)
    (folder/(label+'.query')).write_bytes(packet)
    (folder/(label+'.reply')).write_bytes(reply)
    result = semantics(reply)
    if reply[:2]!=packet[:2] or peer!=(address, PORT):
        raise AssertionError('health reply identity')
    return dict(peer=list(peer), semantic=result, query_sha256=sha256(folder/(label+'.query')),
                reply_sha256=sha256(folder/(label+'.reply')))


def wait_ready(process, root):
    until = time.monotonic()+4
    while time.monotonic()<until:
        if process.poll() is not None:
            raise AssertionError('startup exited '+str(process.returncode))
        if (root/'m2/device-binding.pid').exists():
            return
        time.sleep(.01)
    raise AssertionError('startup readiness deadline')


def execute(root, side, spec, folder):
    create('m5a')
    if spec['action']!='late':
        create('m5b')
    if spec['profile']=='alias':
        ip('addr', 'add', '192.0.2.3/24', 'dev', 'm5a', 'label', 'm5a:1')
    config = [f'port={PORT}', 'no-resolv', 'no-hosts', 'no-0x20-encode',
              'host-record=health.bind.test,198.51.100.99', 'local-ttl=600',
              'user=root', 'pid-file=/m2/device-binding.pid', 'log-facility=/m2/device-binding.log']
    if not spec.get('no_service'):
        config += ['dhcp-range=192.0.2.20,192.0.2.40,255.255.255.0,120s',
                   'dhcp-authoritative', 'no-ping', 'dhcp-leasefile=/m2/device-binding.leases']
    config += spec['config']
    (folder/'config').write_text('\n'.join(config)+'\n')
    (root/'m2/device-binding.conf').write_bytes((folder/'config').read_bytes())
    row = dict(case=spec['case'], phases=[], failure=None)
    process = None
    with (folder/'stderr').open('wb') as log:
        try:
            process = subprocess.Popen(command(root, side, '-k', '-C', '/m2/device-binding.conf'),
                                       stdout=log, stderr=log, start_new_session=True)
            wait_ready(process, root)
            row['identity'] = process_identity(root, process.pid)
            def observe(label):
                address='192.0.2.1' if spec['profile']=='listen-only' else '127.0.0.1'
                phase = dict(label=label, network=network(), sockets=target_sockets(process.pid),
                             health=health(folder, label, address))
                row['phases'].append(phase)
                save(folder/(label+'.json'), phase)
            observe('startup')
            if spec['action']=='late':
                create('m5b')
                time.sleep(.15)
                observe('late')
            elif spec['action']=='recreate':
                old = socket.if_nametoindex('m5a')
                ip('link', 'del', 'm5a')
                observe('deleted')
                time.sleep(.15)
                observe('deleted-again')
                create('m5a')
                row['generation'] = dict(old=old, new=socket.if_nametoindex('m5a'))
                time.sleep(.15)
                observe('recreated')
        except Exception as error:
            row['failure'] = repr(error)
        finally:
            if process is not None:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(4)
                    row['forced'] = False
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(2)
                    row['forced'] = True
                row['exit'] = process.returncode
            daemon_log = root/'m2/device-binding.log'
            if daemon_log.exists():
                (folder/'daemon.log').write_bytes(daemon_log.read_bytes())
                daemon_log.unlink()
            text = (folder/'daemon.log').read_bytes() if (folder/'daemon.log').exists() else b''
            row['notices'] = [line.decode('ascii') for line in re.findall(
                rb'(?:DHCP, sockets bound exclusively to interface |error binding DHCP socket to device )[^\r\n]+', text)]
            for name in ['device-binding.pid', 'device-binding.leases']:
                path = root/'m2'/name
                if path.exists():path.unlink()
            for name in ['m5a', 'm5b']:
                if subprocess.run(['ip', 'link', 'show', name], capture_output=True).returncode==0:
                    ip('link', 'del', name)
    save(folder/'result.json', row)
    return row


def run(args):
    if os.geteuid()!=0 or os.environ.get('DNSMASQ_TEST_ISOLATED')!='1':
        raise ValueError('run only through run_isolated.sh')
    if args.out.exists() or 'private' not in args.out.resolve().parts:
        raise ValueError('fresh private output required')
    args.out.mkdir(parents=True)
    root = prepare(args.image_root, None, args.out, args.rust)
    drivers = args.out/'drivers'
    drivers.mkdir()
    for filename in ['m5_device_binding.py', 'm5_device_binding.json', 'm2_rootfs.py', 'dns_service_probe.py']:
        (drivers/filename).write_bytes(Path(__file__).with_name(filename).read_bytes())
    selected = [row for row in frozen_cases() if re.search(args.only or '.', row['case'])]
    report = dict(side=args.side, c_sha256=STOCK_SHA256, candidate_sha256=sha256(args.rust),
                  driver_sha256=sha256(__file__), manifest_sha256=sha256(Path(__file__).with_suffix('.json')),
                  cases=[], failures=[])
    for spec in selected:
        folder=args.out/spec['case'];folder.mkdir()
        row=execute(root, args.side, spec, folder)
        report['cases'].append(row)
        if row['failure']:report['failures'].append(dict(case=spec['case'], error=row['failure']))
        save(args.out/'result.json', report)
        print(json.dumps(dict(side=args.side, case=spec['case'], failure=row['failure'])), flush=True)
    return int(bool(report['failures']))


def row_errors(spec, row, expected_sha):
    errors = []
    if row.get('case')!=spec['case'] or row.get('failure') or row.get('exit')!=0 or row.get('forced'):
        errors.append('execution')
    if row.get('identity', {}).get('sha256')!=expected_sha:
        errors.append('ELF identity')
    labels = ['startup']+(['late'] if spec['action']=='late' else
                         ['deleted', 'deleted-again', 'recreated'] if spec['action']=='recreate' else [])
    if [p.get('label') for p in row.get('phases', [])]!=labels:
        errors.append('phases')
    previous = None
    for phase in row.get('phases', []):
        sockets=phase.get('sockets', [])
        ports=[] if spec.get('no_service') else [67]+([4011] if spec['pxe'] else [])
        if [s.get('port') for s in sockets]!=ports:
            errors.append('socket coverage')
        for endpoint in sockets:
            if (endpoint.get('family')!=socket.AF_INET or endpoint.get('type')!=socket.SOCK_DGRAM
                    or endpoint.get('local')!=['0.0.0.0', endpoint.get('port')]
                    or not isinstance(endpoint.get('target_fd'), int) or not endpoint.get('inode')):
                errors.append('actual socket metadata')
            device=spec['device'] if endpoint.get('port')==4011 or spec['main'] else ''
            if phase.get('label') in ('deleted', 'deleted-again'):
                if device and endpoint.get('device_errno')!=19:
                    errors.append('deleted device kernel result')
            elif endpoint.get('device_wire')!=(device.encode()+b'\0' if device else b'').hex():
                errors.append('actual bound device')
        handles=[(s.get('target_fd'), s.get('inode')) for s in sockets]
        if previous is not None and handles!=previous:
            errors.append('live descriptor continuity')
        previous=handles
        semantic=phase.get('health', {}).get('semantic', {})
        address='192.0.2.1' if spec['profile']=='listen-only' else '127.0.0.1'
        if (phase.get('health', {}).get('peer')!=[address, PORT]
                or semantic.get('id')!=0x7100 or semantic.get('flags', 15)&15
                or not any(r.get('type')==1 and r.get('data')=='198.51.100.99' for r in semantic.get('records', []))):
            errors.append('owner health')
        links={link['ifname']:link for link in phase.get('network', {}).get('links', [])}
        if spec['action']=='late' and (('m5b' in links)!=(phase.get('label')=='late')):
            errors.append('late interface witness')
        if spec['action']=='recreate' and (('m5a' in links)!=(phase.get('label') not in ('deleted', 'deleted-again'))):
            errors.append('deleted interface witness')
    expected_notices=([NOTICE.decode()+spec['device']] if spec['device'] else [])
    if spec['action']=='recreate':expected_notices += [WARNING.decode()+'m5a']
    if row.get('notices')!=expected_notices:
        errors.append('actual binding notices')
    if spec['action']=='recreate':
        generation=row.get('generation', {})
        if not generation.get('old') or not generation.get('new') or generation['old']==generation['new']:
            errors.append('kernel interface generation')
    return errors


def load(folder, side):
    report=json.loads((folder/'result.json').read_text())
    if (report.get('side')!=side or report.get('c_sha256')!=STOCK_SHA256 or report.get('failures')
            or not re.fullmatch('[0-9a-f]{64}', report.get('candidate_sha256', ''))):
        raise ValueError('invalid report identity or runtime failures')
    if report.get('manifest_sha256')!=sha256(Path(__file__).with_suffix('.json')):
        raise ValueError('different frozen source contract')
    if report.get('driver_sha256')!=sha256(folder/'drivers/m5_device_binding.py'):
        raise ValueError('saved driver identity mismatch')
    for row in report['cases']:
        case=folder/row['case']
        if row!=json.loads((case/'result.json').read_text()):raise ValueError('case receipt mismatch')
        log=(case/'daemon.log').read_bytes() if (case/'daemon.log').exists() else b''
        notices=[line.decode('ascii') for line in re.findall(
            rb'(?:DHCP, sockets bound exclusively to interface |error binding DHCP socket to device )[^\r\n]+', log)]
        if row['notices']!=notices:raise ValueError('actual binding log receipt mismatch')
        sources=re.findall(rb'\b(dnsmasq(?:-dhcp)?)\[\d+\]: ((?:DHCP, sockets bound exclusively to interface |error binding DHCP socket to device )[^\r\n]+)', log)
        if (len(sources)!=len(notices)
                or any(program!=(b'dnsmasq-dhcp' if message.startswith(NOTICE) else b'dnsmasq')
                       for program,message in sources)):
            raise ValueError('binding notice service prefix mismatch')
        for phase in row['phases']:
            if phase!=json.loads((case/(phase['label']+'.json')).read_text()):raise ValueError('phase receipt mismatch')
            reply=case/(phase['label']+'.reply');request=case/(phase['label']+'.query')
            if (sha256(reply)!=phase['health']['reply_sha256'] or sha256(request)!=phase['health']['query_sha256']
                    or request.read_bytes()!=query('health.bind.test', ident=0x7100)
                    or semantics(reply.read_bytes())!=phase['health']['semantic'] or reply.read_bytes()[:2]!=request.read_bytes()[:2]):
                raise ValueError('health wire receipt mismatch')
    return report


def compare(args):
    c=load(args.c, 'c');r=load(args.candidate, 'rust');specs=frozen_cases();controls=[];errors=[]
    if c['candidate_sha256']!=r['candidate_sha256']:
        raise ValueError('paired candidate identity mismatch')
    for side, report in [('c', c), ('rust', r)]:
        if [row['case'] for row in report['cases']]!=[spec['case'] for spec in specs]:
            errors.append(side+': missing/extra/reordered cases')
        rows={row['case']:row for row in report['cases']}
        for spec in specs:
            if spec['case'] not in rows:continue
            errors.extend(side+'/'+spec['case']+': '+error for error in row_errors(spec, rows[spec['case']], STOCK_SHA256 if side=='c' else r['candidate_sha256']))
            if side=='c':continue
            for mutation in ['identity', 'missing-socket', 'device', 'health', 'missing-phase', 'notice', 'cleanup',
                             'fd-continuity', 'generation', 'deleted-errno', 'late-interface']:
                wrong=copy.deepcopy(rows[spec['case']])
                if mutation=='identity':wrong['identity']['sha256']=''
                elif mutation=='missing-socket':
                    if not wrong['phases'][0]['sockets']:continue
                    wrong['phases'][0]['sockets'].pop()
                elif mutation=='device':
                    if not wrong['phases'][0]['sockets']:continue
                    wrong['phases'][0]['sockets'][0]['device_wire']='636f727275707400'
                elif mutation=='health':wrong['phases'][0]['health']['semantic']['flags']|=3
                elif mutation=='missing-phase':wrong['phases'].pop()
                elif mutation=='notice':wrong['notices'].append(WARNING.decode()+'unrelated')
                elif mutation=='cleanup':wrong['forced']=True
                elif mutation=='fd-continuity':
                    if len(wrong['phases'])<2:continue
                    wrong['phases'][1]['sockets'][0]['target_fd']+=1
                elif mutation=='generation':
                    if spec['action']!='recreate':continue
                    wrong['generation']['new']=wrong['generation']['old']
                elif mutation=='deleted-errno':
                    if spec['action']!='recreate':continue
                    wrong['phases'][1]['sockets'][0]['device_errno']=1
                else:
                    if spec['action']!='late':continue
                    wrong['phases'][1]['network']['links']=[link for link in wrong['phases'][1]['network']['links'] if link['ifname']!='m5b']
                controls.append(dict(case=spec['case'], control=mutation, rejected=bool(row_errors(spec, wrong, r['candidate_sha256']))))
    cm={row['case']:row for row in c['cases']};rm={row['case']:row for row in r['cases']}
    for spec in specs:
        if spec['case'] not in cm or spec['case'] not in rm:continue
        left=[phase['health']['semantic'] for phase in cm[spec['case']]['phases']]
        right=[phase['health']['semantic'] for phase in rm[spec['case']]['phases']]
        if left!=right:errors.append(spec['case']+': paired owner health wire semantics')
    result=dict(candidate_sha256=r['candidate_sha256'], c_sha256=STOCK_SHA256, required_count=len(specs),
                covered_options=['bind-interfaces', 'bind-dynamic'], failures=errors, negative_controls=controls,
                qualified=not errors and all(x['rejected'] for x in controls),
                c_report_sha256=sha256(args.c/'result.json'), candidate_report_sha256=sha256(args.candidate/'result.json'),
                manifest_sha256=sha256(Path(__file__).with_suffix('.json')), comparator_sha256=sha256(__file__))
    save(args.out, result)
    print(json.dumps(dict(qualified=result['qualified'], cases=len(specs), failures=len(errors), controls=len(controls))))
    return int(not result['qualified'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action', required=True)
    p=sub.add_parser('run');p.add_argument('--side', choices=['c', 'rust'], required=True)
    p.add_argument('--image-root', type=Path, required=True);p.add_argument('--rust', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True);p.add_argument('--only')
    p=sub.add_parser('compare');p.add_argument('--c', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True);p.add_argument('--out', type=Path, required=True)
    args=parser.parse_args();raise SystemExit(run(args) if args.action=='run' else compare(args))


if __name__=='__main__':main()
