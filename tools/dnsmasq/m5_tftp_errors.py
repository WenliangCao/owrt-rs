#!/usr/bin/env python3
"""Bounded TFTP error wire comparison against the exact image in private namespaces."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
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


def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


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
        dict(name='option-invalid-mode',raw=b'\0\1public\0bad\0blksize\01\0'),
        dict(name='unknown-opcode',raw=b'\0\9',silent=True),
        dict(name='short-request',raw=b'\0',silent=True),
        dict(name='foreign-tid-v4',filename=b'public',tid=True),
        dict(name='foreign-tid-v6',filename=b'public',tid=True,v6=True),
        dict(name='foreign-tid-short',filename=b'public',tid=True,tid_short=True),
        dict(name='missing-single-scope',filename=b'missing',scope=True,single=True),
        dict(name='write-single-scope',raw=b'\0\2',scope=True,single=True),
        dict(name='port-exhausted',filename=b'public',exhausted=True,silent=True),
        dict(name='forbidden-parent',filename=b'../public',code=2),
    ])
    return values


def expected(item):
    if item.get('silent'):return None
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
        endpoint.sendto(request,destination)
        try:response,peer=endpoint.recvfrom(65535)
        except socket.timeout:
            if item.get('silent'):return dict(request=request.hex(),packet=None,dedicated=None,peer=None)
            raise
        if item.get('tid'):
            assert response==b'\0\3\0\1public','prime DATA'
            with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET,socket.SOCK_DGRAM) as foreign:
                foreign.settimeout(2);foreign.bind(('::1' if ipv6 else '127.0.0.2',0))
                wrong=b'\0' if item.get('tid_short') else b'\0\4\0\1'
                foreign.sendto(wrong,peer);error,origin=foreign.recvfrom(65535)
            endpoint.sendto(b'\0\4\0\1',peer)
            response,peer=error,origin
        return dict(request=request.hex(),packet=response.hex(),peer=list(peer),dedicated=peer[1]!=69)


def side(args):
    args.out.mkdir(parents=True,exist_ok=False)
    root=prepare(args.image_root,None,args.out/args.side,args.rust_binary)
    net=Network()
    folder=root/ROOT.lstrip('/');folder.mkdir()
    (folder/'iface').mkdir()
    (folder/'public').write_bytes(b'public');(folder/'public').chmod(0o644)
    (folder/'root-only').write_bytes(b'private');(folder/'root-only').chmod(0o600)
    (folder/'private').mkdir(mode=0o700)
    (folder/'private/file').write_bytes(b'private')
    (folder/'directory').mkdir(mode=0o755)
    (folder/('a'*200)/('b'*200)).mkdir(parents=True)
    rows=[];failures=[]
    for item in cases():
        out=args.out/item['name'];out.mkdir()
        process=None
        config='port=0\nno-hosts\nno-resolv\nuser='+item.get('user','root')+'\ngroup='+('nogroup' if item.get('user') else 'root')+'\npid-file=/m2/pid\n'+('' if item.get('scope') else 'bind-interfaces\n')+'listen-address=127.0.0.1,::1'+(',fe80::1' if item.get('scope') else '')+'\nenable-tftp\n'
        if not item.get('no_root'):config+='tftp-root='+ROOT+'\n'
        if item.get('interface_root'):config+='tftp-root='+ROOT+'/iface,lo\n'
        if item.get('quiet'):config+='quiet-tftp\n'
        if item.get('secure'):config+='tftp-secure\n'
        if item.get('single'):config+='tftp-single-port\n'
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
                if item.get('scope'):
                    payload={k:(v.hex() if isinstance(v,bytes) else v) for k,v in item.items()}
                    result=json.loads(net.exec(sys.executable,__file__,'--query-json',json.dumps(payload)).stdout)
                else:result=query(item)
                save(out/'wire.json',result)
                (out/'request.bin').write_bytes(bytes.fromhex(result['request']))
                if result['packet']:(out/'response.bin').write_bytes(bytes.fromhex(result['packet']))
                wanted=expected(item)
                assert result['packet']==(wanted.hex() if wanted else None),'C-derived wire error guard'
                if wanted:assert result['dedicated']==(not item.get('single')),'source transfer socket role'
                rows.append(dict(case=item['name'],packet=result['packet'],source=result['peer'][0] if result['peer'] else None,dedicated=result['dedicated']))
        except Exception as error:
            failures.append(dict(case=item['name'],error=repr(error)));save(out/'failure.json',failures[-1])
        finally:
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
    if c['rows']!=r['rows']:failures.append(dict(c=c['rows'],rust=r['rows']))
    return failures


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--query-json':
        item=json.loads(sys.argv[2])
        for key in ['filename','raw']:
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
    plan=json.loads((HERE/'m5_tftp_errors.json').read_text());plan['cases']=[{k:v.hex() if isinstance(v,bytes) else v for k,v in item.items()} for item in cases()]
    save(args.out/'plan.json',plan)
    exits={}
    for name in ['c','rust']:
        result=subprocess.run(['sh',str(HERE/'run_isolated.sh'),sys.executable,__file__,'--side',name,
            '--image-root',str(args.image_root),'--rust-binary',str(args.rust_binary),'--out',str(args.out/name)])
        exits[name]=result.returncode
    c,r=[json.loads((args.out/name/'observed.json').read_text()) for name in ['c','rust']]
    failures=compare(c,r);controls=[]
    if not failures:
        for name in ['missing-case','short-text','wrong-code','missing-zero']:
            mutant=copy.deepcopy(r)
            if name=='missing-case':mutant['rows'].pop()
            elif name=='short-text':mutant['rows'][0]['packet']=b'\0\5\0\1file not found\0'.hex()
            elif name=='wrong-code':mutant['rows'][0]['packet']='00050002'+mutant['rows'][0]['packet'][8:]
            else:mutant['rows'][0]['packet']=mutant['rows'][0]['packet'][:-2]
            controls.append(dict(name=name,rejected=bool(compare(c,mutant))))
    report=dict(cases=len(cases()),failures=failures,exits=exits,negative_controls=controls,
        binary_sha256=sha256(args.rust_binary),bytes=args.rust_binary.stat().st_size,
        qualified=not failures and all(row['rejected'] for row in controls))
    save(args.out/'result.json',report);print(json.dumps(dict(cases=len(cases()),failures=len(failures),qualified=report['qualified'])))
    return bool(failures)


if __name__=='__main__':raise SystemExit(main())
