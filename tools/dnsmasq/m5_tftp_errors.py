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
    return values


def expected(item):
    prefix=None if item.get('no_root') else ROOT+('/iface' if item.get('interface_root') else '')
    path=b'/'+item['filename'] if prefix is None else prefix.encode()+b'/'+item['filename']
    path=path[:503]
    path=bytes(byte for byte in path if 0x20<=byte<=0x7e)
    code=item.get('code',1)
    if code==1:message=b'file '+path+b' not found for '+(b'::1' if item.get('v6') else b'127.0.0.1')
    elif code==2:message=b'cannot access '+path+b': Permission denied'
    else:message=b'cannot read '+path+b': '+item['error'].encode()
    return b'\0\5'+struct.pack('!H',code)+message[:499]+b'\0'


def query(item):
    with socket.socket(socket.AF_INET6 if item.get('v6') else socket.AF_INET,socket.SOCK_DGRAM) as endpoint:
        endpoint.settimeout(2)
        endpoint.bind(('::1' if item.get('v6') else '127.0.0.1',0))
        request=b'\0\1'+item['filename']+b'\0octet\0'
        endpoint.sendto(request,('::1' if item.get('v6') else '127.0.0.1',69))
        response,peer=endpoint.recvfrom(65535)
        return dict(request=request.hex(),packet=response.hex(),peer=list(peer),dedicated=peer[1]!=69)


def side(args):
    args.out.mkdir(parents=True,exist_ok=False)
    root=prepare(args.image_root,None,args.out/args.side,args.rust_binary)
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
        config='port=0\nno-hosts\nno-resolv\nuser='+item.get('user','root')+'\ngroup='+('nogroup' if item.get('user') else 'root')+'\npid-file=/m2/pid\nbind-interfaces\nlisten-address=127.0.0.1,::1\nenable-tftp\n'
        if not item.get('no_root'):config+='tftp-root='+ROOT+'\n'
        if item.get('interface_root'):config+='tftp-root='+ROOT+'/iface,lo\n'
        if item.get('quiet'):config+='quiet-tftp\n'
        if item.get('secure'):config+='tftp-secure\n'
        (root/'m2/error.conf').write_text(config);(out/'config').write_text(config)
        try:
            with (out/'stderr').open('w') as stderr,(out/'stdout').open('w') as stdout:
                process=subprocess.Popen(command(root,args.side,'-k' if item.get('user') else '-d','-C','/m2/error.conf'),stderr=stderr,stdout=stdout,start_new_session=True)
                time.sleep(.15)
                assert process.poll() is None,'startup failed'
                save(out/'identity.json',process_identity(root,process.pid))
                result=query(item)
                save(out/'wire.json',result)
                (out/'request.bin').write_bytes(bytes.fromhex(result['request']))
                (out/'response.bin').write_bytes(bytes.fromhex(result['packet']))
                assert bytes.fromhex(result['packet'])==expected(item),'C-derived wire error guard'
                assert result['dedicated'],'expected separate transfer socket'
                rows.append(dict(case=item['name'],packet=result['packet'],source=result['peer'][0],dedicated=True))
        except Exception as error:
            failures.append(dict(case=item['name'],error=repr(error)));save(out/'failure.json',failures[-1])
        finally:
            cleanup=stop(process);save(out/'cleanup.json',cleanup)
        if cleanup and (cleanup['forced'] or cleanup['returncode']!=0):failures.append(dict(case=item['name'],cleanup=cleanup))
    result=dict(side=args.side,rows=rows,failures=failures,binary_sha256=sha256(args.rust_binary if args.side=='rust' else args.image_root/'usr/sbin/dnsmasq'))
    save(args.out/'observed.json',result)
    print(json.dumps(dict(side=args.side,cases=len(rows),failures=len(failures))))
    return bool(failures)


def compare(c,r):
    failures=[]
    names=[item['name'] for item in cases()]
    for name,result in [('c',c),('rust',r)]:
        if result['failures']:failures.append(dict(side=name,failures=result['failures']))
        if [row['case'] for row in result['rows']]!=names:failures.append(dict(side=name,error='incomplete case inventory'))
        for row,item in zip(result['rows'],cases()):
            if row['packet']!=expected(item).hex():failures.append(dict(side=name,error='wire guard '+item['name']))
    if c['rows']!=r['rows']:failures.append(dict(c=c['rows'],rust=r['rows']))
    return failures


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root',type=Path,required=True)
    parser.add_argument('--rust-binary',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--side',choices=['c','rust'])
    args=parser.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1','use run_isolated.sh'
    if args.side:return side(args)
    args.out.mkdir(parents=True,exist_ok=False)
    plan=json.loads((HERE/'m5_tftp_errors.json').read_text());plan['cases']=[dict(item,filename=item['filename'].hex()) for item in cases()]
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
