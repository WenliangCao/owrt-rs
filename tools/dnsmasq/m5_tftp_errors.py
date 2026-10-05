#!/usr/bin/env python3
"""Bounded TFTP error wire comparison against the exact image in private namespaces."""
from __future__ import annotations
import argparse
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import struct
import subprocess
import sys
import time

from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import stop
from m5_listeners import Network

HERE=Path(__file__).resolve().parent
ROOT='/m2/tftp-errors'
NUMBERS=[
    ('signed-overflow',b'2147483648',2147483648),
    ('unsigned-wrap',b'4294967296',0),
    ('unsigned-wrap-one',b'4294967297',1),
    ('long-wrap',b'9223372036854775808',0),
    ('many-zeroes',b'10000000000000000000000000000000000000000',0),
    ('many-nines',b'99999999999999999999999999999999999999990',4294967286),
    ('negative-overflow',b'-2147483649',2147483647),
    ('negative-wrap',b'-4294967296',0),
    ('prefix',b'+4294967297tail',1),
    ('whitespace-prefix',b' \t+4294967298x',2),
    ('double-sign',b'--1',0),
    ('nonnumeric',b'abc',0),
    ('negative',b'-1',4294967295),
    ('vertical-whitespace',b'\x0b\x0c\r\n+4294967298x',2),
]


def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def frozen_plan():
    plan=json.loads((HERE/'m5_tftp_errors.json').read_text())
    required={name for row in plan['boundaries'] for name in row['required_cases']}
    names={item['name'] for item in cases()}
    assert required==names,dict(missing=sorted(required-names),unmapped=sorted(names-required))
    plan['cases']=[{k:v.hex() if isinstance(v,bytes) else v for k,v in item.items()} for item in cases()]
    plan['driver_sha256']=sha256(Path(__file__))
    plan['manifest_sha256']=sha256(HERE/'m5_tftp_errors.json')
    return plan


def cases():
    values=[
        dict(name='missing-v4',filename=b'missing'),
        dict(name='missing-v6',filename=b'missing',v6=True),
        dict(name='missing-no-root',filename=b'missing',no_root=True),
        dict(name='missing-interface-root',filename=b'missing',interface_root=True),
        dict(name='missing-quiet',filename=b'missing',quiet=True),
        dict(name='mode-denied',filename=b'root-only',code=2),
        dict(name='uid-open-denied',filename=b'private/file',user='nobody',code=2),
        dict(name='secure-owner-denied',filename=b'public',user='nobody',secure=True,code=2),
        dict(name='not-directory',filename=b'public/child',code=0,error='Not a directory'),
        dict(name='directory-read-error',filename=b'directory',code=0,error='Is a directory'),
        dict(name='sanitise-controls',filename=b'missing-\x01\x09\x0a\x7f-name'),
        dict(name='sanitise-high-bytes',filename=b'missing-\x80\xff-name'),
    ]
    stem=b'a'*200+b'/'+b'b'*200+b'/'
    for label,wanted in [('below',498),('at',499),('over',520)]:
        overhead=len(b'file '+ROOT.encode()+b'/'+stem+b' not found for 127.0.0.1')
        values.append(dict(name='message-'+label+'-limit',filename=stem+b'x'*(wanted-overhead)))
    values.extend([
        dict(name='write-request-v4',raw=b'\0\2'),
        dict(name='write-request-v6',raw=b'\0\2',v6=True),
        dict(name='empty-filename',raw=b'\0\1\0octet\0'),
        dict(name='unclosed-filename',raw=b'\0\1public'),
        dict(name='missing-mode',raw=b'\0\1public\0'),
        dict(name='invalid-mode',raw=b'\0\1public\0bad\0'),
        dict(name='option-invalid-mode',raw=b'\0\1public\0bad\0blksize\x001\0'),
        dict(name='unknown-opcode',raw=b'\0\x09',silent=True),
        dict(name='short-request',raw=b'\0',silent=True),
        dict(name='foreign-tid-v4',filename=b'public',tid=True),
        dict(name='foreign-tid-v6',filename=b'public',tid=True,v6=True),
        dict(name='foreign-tid-short',filename=b'public',tid=True,tid_short=True),
        dict(name='missing-single-scope',filename=b'missing',scope=True,single=True),
        dict(name='write-single-scope',raw=b'\0\2',scope=True,single=True),
        dict(name='port-exhausted',filename=b'public',exhausted=True,silent=True),
        dict(name='forbidden-parent',filename=b'../public',code=2),
    ])
    for label,value,number in NUMBERS:
        response=b'\0\6blksize\0'+str(max(1,min(number,1493))).encode()+b'\0'
        values.append(dict(name='numeric-blksize-'+label,raw=b'\0\1public\0octet\0blksize\0'+value+b'\0',response=response))
    for label in ['unsigned-wrap','whitespace-prefix','negative-overflow','many-nines','double-sign']:
        _,value,number=next(row for row in NUMBERS if row[0]==label)
        response=b'\0\6tsize\x006\0timeout\0'+str(min(number,255)).encode()+b'\0windowsize\0'+str(max(1,min(number,32))).encode()+b'\0'
        raw=b'\0\1public\0octet\0windowsize\0'+value+b'\0timeout\0'+value+b'\0tsize\0'+value+b'\0'
        values.append(dict(name='numeric-other-'+label,raw=raw,response=response))
    for limit in [512,4096]:
        values.append(dict(name='numeric-edns-'+str(limit),raw=b'\0\1public\0octet\0blksize\0-1\0',edns=limit,response=b'\0\6blksize\0'+str(limit+261).encode()+b'\0'))
    values.append(dict(name='numeric-no-blocksize',raw=b'\0\1public\0octet\0blksize\0'+NUMBERS[5][1]+b'\0',no_blocksize=True,response=b'\0\3\0\1public'))
    for error,number in [('Input/output error',errno.EIO),('Permission denied',errno.EACCES),('No such file or directory',errno.ENOENT)]:
        values.append(dict(name='fstat-'+str(number),filename=b'public',code=0,error=error,fault='stat',fault_errno=number))
    values.extend([
        dict(name='initial-read-eio',filename=b'public',code=0,error='Input/output error',fault='read',fault_errno=errno.EIO),
        dict(name='oack-read-eio',filename=b'directory',code=0,error='Is a directory',after_oack=True),
        dict(name='window-read-eio',filename=b'large',code=0,error='Input/output error',fault='read',fault_errno=errno.EIO,fault_after=1,window=True),
        dict(name='retry-read-eio',filename=b'public',code=0,error='Input/output error',fault='read',fault_errno=errno.EIO,fault_after=1,retry=True),
    ])
    return values


def expected(item):
    if item.get('silent'):return None
    if 'response' in item:return item['response']
    label=b'fe80::2%lan' if item.get('scope') else b'::1' if item.get('v6') else b'127.0.0.1'
    if item.get('tid'):
        label=b'::1' if item.get('v6') else b'127.0.0.2'
        return b'\0\5\0\5ignoring packet from '+label+b' (TID mismatch)\0'
    if 'raw' in item:
        raw=item['raw']
        message=b'unsupported write request from ' if raw[:2]==b'\0\2' else b'empty filename in request from ' if item['name'] in ['empty-filename','unclosed-filename'] else b'unsupported request from '
        return b'\0\5\0\4'+message+label+b'\0'
    prefix=None if item.get('no_root') else ROOT+('/iface' if item.get('interface_root') else '')
    path=b'/'+item['filename'] if prefix is None else prefix.encode()+b'/'+item['filename']
    path=path[:503]
    path=bytes(byte for byte in path if 0x20<=byte<=0x7e)
    code=item.get('code',1)
    if code==1:message=b'file '+path+b' not found for '+label
    elif code==2:message=b'cannot access '+path+b': Permission denied'
    else:message=b'cannot read '+path+b': '+item['error'].encode()
    return b'\0\5'+struct.pack('!H',code)+message[:499]+b'\0'


def query(item):
    ipv6=item.get('v6') or item.get('scope')
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(.5 if item.get('silent') else 2)
        source='fe80::2' if item.get('scope') else '::1' if ipv6 else '127.0.0.1'
        target='fe80::1' if item.get('scope') else '::1' if ipv6 else '127.0.0.1'
        if item.get('scope'):
            index=socket.if_nametoindex('lpeer');endpoint.bind((source,0,0,index));destination=(target,69,0,index)
        else:endpoint.bind((source,0));destination=(target,69)
        request=item.get('raw',b'\0\1'+item.get('filename',b'public')+b'\0octet\0')
        if item.get('after_oack'):request+=b'blksize\x004\0'
        if item.get('window'):request+=b'blksize\x004\0windowsize\x003\0'
        endpoint.sendto(request,destination)
        try:response,peer=endpoint.recvfrom(65535)
        except socket.timeout:
            if item.get('silent'):return dict(request=request.hex(),packet=None,dedicated=None,peer=None)
            raise
        packets=[response.hex()]
        if item.get('after_oack') or item.get('window'):
            wanted=b'\0\6blksize\x004\0'+(b'windowsize\x003\0' if item.get('window') else b'')
            assert response==wanted,'read fault OACK prime'
            endpoint.sendto(b'\0\4\0\0',peer)
            packets=[]
            for _ in range(3 if item.get('window') else 1):
                packet,origin=endpoint.recvfrom(65535)
                assert origin==peer,'window source changed'
                packets.append(packet.hex())
            response=bytes.fromhex(packets[1 if item.get('window') else 0])
            if item.get('window'):
                assert packets[0]==b'\0\3\0\1abcd'.hex() and packets[2]==b'\0\3\0\3ijkl'.hex(),'DATA/error window order'
        elif item.get('retry'):
            assert response==b'\0\3\0\1public','retry DATA prime'
            query(dict(raw=b'\0\1public\0octet\0blksize\x004\0',response=b'\0\6blksize\x004\0'))
            endpoint.settimeout(5)
            response,origin=endpoint.recvfrom(65535)
            assert origin==peer,'retry source changed'
            packets.append(response.hex())
        elif item.get('tid'):
            assert response==b'\0\3\0\1public','prime DATA'
            with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_DGRAM) as foreign:
                foreign.settimeout(2);foreign.bind(('::1' if ipv6 else '127.0.0.2',0))
                wrong=b'\0' if item.get('tid_short') else b'\0\4\0\1'
                foreign.sendto(wrong,peer);error,origin=foreign.recvfrom(65535)
            endpoint.sendto(b'\0\4\0\1',peer)
            response,peer=error,origin
        elif response[:2]==b'\0\6':endpoint.sendto(b'\0\5\0\0probe complete\0',peer)
        elif response[:2]==b'\0\3':endpoint.sendto(b'\0\4'+response[2:4],peer)
        return dict(request=request.hex(),packet=response.hex(),peer=list(peer),dedicated=peer[1]!=69,packets=packets)


def trace_file_error(pid,operation,filename,error,after,output):
    """Replace one actual image file syscall with errno, preserving raw proof."""
    assert platform.machine()=='aarch64','fault ABI pinned to AArch64 image'
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
        vector=Iovec(ctypes.addressof(registers),ctypes.sizeof(registers))
        ptrace(0x4205 if write else 0x4204,1,ctypes.addressof(vector))
    numbers=(80,79,291) if operation=='stat' else (63,65,67)
    report=dict(pid=pid,operation=operation,path=filename,errno=error,after=after,events=[],injected=False)
    attached=False;active=fault=False;successful=0
    try:
        ptrace(16);os.waitpid(pid,0);attached=True;ptrace(0x4200,0,1)
        Path(str(output)+'.ready').write_text('attached\n')
        while True:
            ptrace(24);_,status=os.waitpid(pid,0)
            assert os.WIFSTOPPED(status),'tracee exited before injection'
            if os.WSTOPSIG(status)!=signal.SIGTRAP|0x80:continue
            info=(ctypes.c_ubyte*128)();ptrace(0x420e,ctypes.sizeof(info),ctypes.addressof(info));regs()
            if info[0]==1:
                try:path=os.readlink('/proc/'+str(pid)+'/fd/'+str(registers[0]))
                except OSError:path=''
                active=registers[8] in numbers and path.endswith(ROOT+'/'+filename)
                fault=active and successful>=after
                if active:report['events'].append(dict(syscall=registers[8],descriptor=registers[0],path=path,injected=fault))
                if fault:
                    syscall=ctypes.c_int(-1);vector=Iovec(ctypes.addressof(syscall),ctypes.sizeof(syscall))
                    ptrace(0x4205,0x404,ctypes.addressof(vector))
            elif info[0]==2 and active:
                returned=ctypes.c_longlong(registers[0]).value
                if fault:
                    registers[0]=(1<<64)-error;regs(True);returned=-error;report['injected']=True
                report['events'][-1]['result']=returned;save(output,report)
                successful+=returned>=0
                if fault:ptrace(17);attached=False;break
                active=False
    finally:
        if attached:
            try:ptrace(17)
            except OSError:pass
        save(output,report)
    return 0


def side(args):
    args.out.mkdir(parents=True,exist_ok=False)
    save(args.out/'plan.json',frozen_plan())
    root=prepare(args.image_root,None,args.out/args.side,args.rust_binary)
    net=Network()
    folder=root/ROOT.lstrip('/');folder.mkdir()
    (folder/'iface').mkdir()
    (folder/'public').write_bytes(b'public');(folder/'public').chmod(0o644)
    (folder/'large').write_bytes(b'abcdefghijklmnop');(folder/'large').chmod(0o644)
    (folder/'root-only').write_bytes(b'private');(folder/'root-only').chmod(0o600)
    (folder/'private').mkdir(mode=0o700)
    (folder/'private/file').write_bytes(b'private')
    (folder/'directory').mkdir(mode=0o755)
    (folder/('a'*200)/('b'*200)).mkdir(parents=True)
    rows=[];failures=[]
    for item in cases():
        out=args.out/item['name'];out.mkdir()
        process=tracer=None
        config='port=0\nno-hosts\nno-resolv\nuser='+item.get('user','root')+'\ngroup='+('nogroup' if item.get('user') else 'root')+'\npid-file=/m2/pid\n'+('' if item.get('scope') else 'bind-interfaces\n')+'listen-address=127.0.0.1,::1'+(',fe80::1' if item.get('scope') else '')+'\nenable-tftp\n'
        if not item.get('no_root'):config+='tftp-root='+ROOT+'\n'
        if item.get('interface_root'):config+='tftp-root='+ROOT+'/iface,lo\n'
        if item.get('quiet'):config+='quiet-tftp\n'
        if item.get('secure'):config+='tftp-secure\n'
        if item.get('single'):config+='tftp-single-port\n'
        if item.get('edns'):config+='edns-packet-max='+str(item['edns'])+'\n'
        if item.get('no_blocksize'):config+='tftp-no-blocksize\n'
        blocker=None
        if item.get('exhausted'):
            config+='tftp-port-range=35000,35000\n'
            blocker=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);blocker.bind(('127.0.0.1',35000))
        (root/'m2/error.conf').write_text(config);(out/'config').write_text(config)
        try:
            with (out/'stderr').open('w') as stderr,(out/'stdout').open('w') as stdout:
                process=subprocess.Popen(command(root,args.side,'-k' if item.get('user') else '-d','-C','/m2/error.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
                time.sleep(.15)
                assert process.poll() is None,'startup failed'
                save(out/'identity.json',process_identity(root,process.pid))
                baseline_fds=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
                if item.get('fault'):
                    tracer=subprocess.Popen([sys.executable,__file__,'--trace-file-error',str(process.pid),item['fault'],item['filename'].decode(),str(item['fault_errno']),str(item.get('fault_after',0)),str(out/'fault.json')])
                    deadline=time.monotonic()+3
                    while not (out/'fault.json.ready').exists() and tracer.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                    assert (out/'fault.json.ready').exists(),'fault tracer did not attach'
                if item.get('scope'):
                    payload={k:(v.hex() if isinstance(v,bytes) else v) for k,v in item.items()}
                    result=json.loads(net.exec(sys.executable,__file__,'--query-json',json.dumps(payload)).stdout)
                else:result=query(item)
                save(out/'wire.json',result)
                if tracer:
                    assert tracer.wait(timeout=3)==0,'fault tracer failed'
                    assert json.loads((out/'fault.json').read_text())['injected'],'file error not injected'
                (out/'request.bin').write_bytes(bytes.fromhex(result['request']))
                if result['packet']:(out/'response.bin').write_bytes(bytes.fromhex(result['packet']))
                wanted=expected(item)
                assert result['packet']==(wanted.hex() if wanted else None),'C-derived wire error guard'
                if wanted:assert result['dedicated']==(not item.get('single')),'source transfer socket role'
                if not item.get('exhausted'):
                    time.sleep(.05)
                    recovery=query(dict(filename=b'public',v6=item.get('v6'),response=b'\0\3\0\1public'))
                    save(out/'recovery.json',recovery)
                    assert recovery['packet']==b'\0\3\0\1public'.hex(),'post-error transfer health'
                    time.sleep(.05)
                    remaining_fds=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
                    save(out/'descriptor-health.json',dict(before=baseline_fds,after=remaining_fds))
                    assert remaining_fds==baseline_fds,'file/transfer descriptor leak'
                row=dict(case=item['name'],packet=result['packet'],source=result['peer'][0] if result['peer'] else None,dedicated=result['dedicated'])
                row['health']=not item.get('exhausted')
                if item.get('fault'):row['fault']=dict(injected=True,errno=item['fault_errno'],after=item.get('fault_after',0))
                if item.get('window') or item.get('retry'):row['packets']=result['packets']
                rows.append(row)
        except Exception as error:
            failures.append(dict(case=item['name'],error=repr(error)));save(out/'failure.json',failures[-1])
        finally:
            if tracer and tracer.poll() is None:
                tracer.terminate()
                try:tracer.wait(timeout=2)
                except subprocess.TimeoutExpired:tracer.kill();tracer.wait()
            cleanup=stop(process);save(out/'cleanup.json',cleanup)
            if blocker:blocker.close()
        if cleanup and (cleanup['forced'] or cleanup['returncode']!=0):failures.append(dict(case=item['name'],cleanup=cleanup))
    result=dict(side=args.side,rows=rows,failures=failures,binary_sha256=sha256(args.rust_binary if args.side=='rust' else args.image_root/'usr/sbin/dnsmasq'))
    save(args.out/'observed.json',result)
    save(args.out/'network-cleanup.json',net.close())
    print(json.dumps(dict(side=args.side,cases=len(rows),failures=len(failures))))
    return bool(failures)


def compare(c,r):
    failures=[]
    names=[item['name'] for item in cases()]
    for name,result in [('c',c),('rust',r)]:
        if result['failures']:failures.append(dict(side=name,failures=result['failures']))
        if [row['case'] for row in result['rows']]!=names:failures.append(dict(side=name,error='incomplete case inventory'))
        for row,item in zip(result['rows'],cases()):
            packet=expected(item)
            if row['packet']!=(packet.hex() if packet else None):failures.append(dict(side=name,error='wire guard '+item['name']))
            if row.get('health')!=(not item.get('exhausted')):failures.append(dict(side=name,error='health guard '+item['name']))
            if item.get('fault') and row.get('fault')!=dict(injected=True,errno=item['fault_errno'],after=item.get('fault_after',0)):failures.append(dict(side=name,error='fault guard '+item['name']))
    if c['rows']!=r['rows']:failures.append(dict(c=c['rows'],rust=r['rows']))
    return failures


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--trace-file-error':return trace_file_error(int(sys.argv[2]),sys.argv[3],sys.argv[4],int(sys.argv[5]),int(sys.argv[6]),sys.argv[7])
    if len(sys.argv)>1 and sys.argv[1]=='--query-json':
        item=json.loads(sys.argv[2])
        for key in ['filename','raw','response']:
            if key in item:item[key]=bytes.fromhex(item[key])
        assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
        print(json.dumps(query(item)));return 0
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True)
    parser.add_argument('--rust-binary',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','rust'])
    args=parser.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','use run_isolated.sh'
    if args.side:return side(args)
    args.out.mkdir(parents=True,exist_ok=False)
    plan=frozen_plan()
    save(args.out/'plan.json',plan)
    exits={}
    for name in ['c','rust']:
        result=subprocess.run(['sh',str(HERE/'run_isolated.sh'),sys.executable,__file__,'--side',name,
            '--image-root',str(args.image_root),'--rust-binary',str(args.rust_binary),'--out',str(args.out/name)])
        exits[name]=result.returncode
    c,r=[json.loads((args.out/name/'observed.json').read_text()) for name in ['c','rust']]
    failures=compare(c,r);controls=[]
    if any(exits.values()):failures.append(dict(error='nonzero side exit',exits=exits))
    if not failures:
        for name in ['missing-case','short-text','wrong-code','missing-zero','wrong-socket-role','missing-health','missing-fault','numeric-overflow-error']:
            mutant=copy.deepcopy(r)
            if name=='missing-case':mutant['rows'].pop()
            elif name=='short-text':mutant['rows'][0]['packet']=b'\0\5\0\1file not found\0'.hex()
            elif name=='wrong-code':mutant['rows'][0]['packet']='00050002'+mutant['rows'][0]['packet'][8:]
            elif name=='missing-zero':mutant['rows'][0]['packet']=mutant['rows'][0]['packet'][:-2]
            elif name=='wrong-socket-role':mutant['rows'][0]['dedicated']=False
            elif name=='missing-health':mutant['rows'][0]['health']=False
            elif name=='missing-fault':next(row for row in mutant['rows'] if row['case']=='fstat-5').pop('fault')
            else:next(row for row in mutant['rows'] if row['case']=='numeric-blksize-signed-overflow')['packet']=b'\0\5\0\4unsupported request from 127.0.0.1\0'.hex()
            controls.append(dict(name=name,rejected=bool(compare(c,mutant))))
    report=dict(cases=len(cases()),failures=failures,exits=exits,negative_controls=controls,
        binary_sha256=sha256(args.rust_binary),bytes=args.rust_binary.stat().st_size,
        boundaries=[dict(id=row['id'],cases=row['required_cases'],passed=not failures) for row in plan['boundaries']],
        unclosed_callers=plan.get('unclosed_callers',[]),
        paired_cases_passed=not failures and len(controls)==8 and all(row['rejected'] for row in controls),
        qualified=not failures and len(controls)==8 and all(row['rejected'] for row in controls) and not plan.get('unclosed_callers'))
    save(args.out/'result.json',report);print(json.dumps(dict(cases=len(cases()),failures=len(failures),qualified=report['qualified'])))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
