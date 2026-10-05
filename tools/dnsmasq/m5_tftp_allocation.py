#!/usr/bin/env python3
"""Exact-image file-record allocation fault; reference evidence, never closure."""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import sys
import time

from m2_rootfs import command, prepare, process_identity, sha256
from test_single_poll_service import stop


def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def trace_allocation(pid,size,kind,offset,output,file_record=True):
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
    maps=Path('/proc/'+str(pid)+'/maps').read_text()
    if kind=='calloc':
        mapping=next(line for line in maps.splitlines() if line.endswith('/lib/libc.so') and line.split()[2]=='00000000')
        address=int(mapping.split('-')[0],16)+offset
    else:
        executable=os.readlink('/proc/'+str(pid)+'/exe')
        mapping=next(line for line in maps.splitlines() if line.endswith(executable) and line.split()[2]=='00000000')
        header=subprocess.run(['readelf','-h',executable],capture_output=True,text=True,check=True).stdout
        address=offset if re.search(r'Type:\s+EXEC',header) else int(mapping.split('-')[0],16)+offset
    report=dict(pid=pid,symbol=kind,symbol_offset=offset,mapping=mapping,address=address,required_size=size,calls=[],injected=False)
    attached=patched=False;original=None
    try:
        ptrace(16);os.waitpid(pid,0);attached=True
        original=ptrace(1,address)&((1<<64)-1)
        breakpoint=(original&0xffffffff00000000)|0xd4200000
        ptrace(4,address,breakpoint);patched=True
        Path(str(output)+'.ready').write_text(kind+' breakpoint installed\n')
        for _ in range(1000):
            ptrace(7);_,status=os.waitpid(pid,0)
            assert os.WIFSTOPPED(status),'tracee ended before allocation fault'
            if os.WSTOPSIG(status)!=signal.SIGTRAP:
                ptrace(7,0,os.WSTOPSIG(status));_,status=os.waitpid(pid,0)
                assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTRAP,'allocation signal forwarding'
            regs();assert registers[32]==address,'breakpoint PC mismatch'
            descriptor_paths=[]
            for descriptor in Path('/proc/'+str(pid)+'/fd').iterdir():
                try:descriptor_paths.append(os.readlink(descriptor))
                except OSError:pass
            row=dict(count=registers[0] if kind=='calloc' else 1,size=registers[1] if kind in ['calloc','realloc'] else registers[0],caller=registers[30],pc=registers[32],descriptor_paths=descriptor_paths)
            report['calls'].append(row)
            ptrace(4,address,original);patched=False
            file_open=any(path.endswith('/m2/tftp-errors/public') for path in descriptor_paths)
            if row['count']==1 and row['size']==size and file_open==file_record:
                registers[0]=0;registers[32]=registers[30];regs(True)
                row['returned']=0;report['injected']=True
                ptrace(17);attached=False;break
            ptrace(9);_,status=os.waitpid(pid,0)
            assert os.WIFSTOPPED(status),'tracee ended while stepping calloc'
            ptrace(4,address,breakpoint);patched=True
        assert report['injected'],'file record allocation not reached'
    finally:
        if attached:
            if patched:ptrace(4,address,original)
            try:ptrace(17)
            except OSError:pass
        save(output,report)
    return 0


def trace_calloc(pid,size,offset,output):
    return trace_allocation(pid,size,'calloc',offset,output)


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--trace-calloc':return trace_calloc(int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),sys.argv[5])
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True)
    parser.add_argument('--rust-binary',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','use run_isolated.sh'
    args.out.mkdir(parents=True,exist_ok=False)
    root=prepare(args.image_root,None,args.out/'c',args.rust_binary)
    folder=root/'m2/tftp-errors';folder.mkdir()
    (folder/'public').write_bytes(b'public');(folder/'public').chmod(0o644)
    config='port=0\nno-resolv\nno-hosts\nuser=root\ngroup=root\nbind-interfaces\nlisten-address=127.0.0.1\nenable-tftp\ntftp-root=/m2/tftp-errors\n'
    (root/'m2/error.conf').write_text(config);(args.out/'config').write_text(config)
    symbols=subprocess.run(['readelf','-Ds',str(args.image_root/'lib/libc.so')],text=True,capture_output=True,check=True).stdout
    (args.out/'libc-dynamic-symbols').write_text(symbols)
    offset=int(re.search(r'^\s*\d+:\s+([0-9a-f]+).*\bcalloc\s*$',symbols,re.M)[1],16)
    # Exact AArch64 image struct tftp_file: 2 ints + 4 64-bit fields = 40.
    path=b'/m2/tftp-errors/public';size=40+len(path)+1
    process=tracer=None;failure=None;packets=[]
    try:
        with (args.out/'stderr').open('w') as stderr,(args.out/'stdout').open('w') as stdout:
            process=subprocess.Popen(command(root,'c','-d','-C','/m2/error.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
            time.sleep(.15);assert process.poll() is None,'startup failed'
            save(args.out/'identity.json',process_identity(root,process.pid))
            baseline=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
            tracer=subprocess.Popen([sys.executable,__file__,'--trace-calloc',str(process.pid),str(size),str(offset),str(args.out/'allocation.json')])
            deadline=time.monotonic()+3
            while not (args.out/'allocation.json.ready').exists() and tracer.poll() is None and time.monotonic()<deadline:time.sleep(.01)
            assert (args.out/'allocation.json.ready').exists(),'calloc tracer did not attach'
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
                endpoint.settimeout(3);endpoint.bind(('127.0.0.1',0))
                for expected in [b'\0\5\0\0cannot read '+path+b': Out of memory\0',b'\0\3\0\1public']:
                    request=b'\0\1public\0octet\0';endpoint.sendto(request,('127.0.0.1',69))
                    packet,peer=endpoint.recvfrom(65535)
                    packets.append(dict(request=request.hex(),packet=packet.hex(),peer=list(peer)))
                    assert packet==expected and peer[1]!=69,'allocation/recovery wire guard'
                    if packet[:2]==b'\0\3':endpoint.sendto(b'\0\4\0\1',peer)
                assert tracer.wait(timeout=3)==0,'calloc tracer failed'
            time.sleep(.05)
            remaining=len(list(Path('/proc/'+str(process.pid)+'/fd').iterdir()))
            assert baseline==remaining,'file/transfer fd leak'
    except Exception as error:failure=repr(error)
    finally:
        if tracer and tracer.poll() is None:tracer.kill();tracer.wait()
        cleanup=stop(process);save(args.out/'cleanup.json',cleanup)
    result=dict(reference_only=True,qualified=False,failure=failure,packets=packets,c_sha256=sha256(args.image_root/'usr/sbin/dnsmasq'),libc_sha256=sha256(args.image_root/'lib/libc.so'))
    save(args.out/'result.json',result);print(json.dumps(result))
    return bool(failure)


if __name__=='__main__':raise SystemExit(main())
