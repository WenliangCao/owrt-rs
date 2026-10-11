#!/usr/bin/env python3
"""Independent image/Rust DNS, hosts and diagnostic audit. Isolated Linux only."""
import argparse, hashlib, json, os, pathlib, signal, socket, struct, subprocess, time

def query(name, kind=1):
    return struct.pack('!6H',0x1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)

def exchange(wire, tcp=False):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
            s.settimeout(.35)
            if tcp:
                s.connect(('127.0.0.1',15353)); s.sendall(struct.pack('!H',len(wire))+wire)
                def exact(n):
                    out=b''
                    while len(out)<n:
                        part=s.recv(n-len(out))
                        if not part: raise EOFError()
                        out+=part
                    return out
                return exact(struct.unpack('!H',exact(2))[0]).hex()
            s.sendto(wire,('127.0.0.1',15353)); return s.recv(65535).hex()
    except (OSError,EOFError) as e: return type(e).__name__

def run(command, options, out, cases, action=None):
    with out.open('wb') as stream:
        p=subprocess.Popen(command+['-C','/dev/null','-k','--user=root','--group=root','--port=15353','--no-resolv','--no-hosts','--listen-address=127.0.0.1','--bind-interfaces','--pid-file=','--log-facility=-','--log-queries','--host-record=ready.test,192.0.2.123']+options,stdout=stream,stderr=stream)
        try:
            for _ in range(100):
                if exchange(query('ready.test')).endswith('c000027b'):break
                if p.poll() is not None: raise RuntimeError(out.read_text())
                time.sleep(.01)
            if action: action(p)
            result={name:{'udp':exchange(wire),'tcp':exchange(wire,True)} for name,wire in cases}
            p.send_signal(signal.SIGUSR1);time.sleep(.2)
            result['alive']=p.poll() is None
            result['dump']=out.read_text(errors='replace')
            return result
        finally:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()

def main():
    p=argparse.ArgumentParser();p.add_argument('--image-root',type=pathlib.Path,required=True);p.add_argument('--rust',type=pathlib.Path,required=True);p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args()
    assert os.environ.get('DNSMASQ_TEST_ISOLATED')=='1'
    a.out.mkdir(parents=True,exist_ok=False)
    commands={'c':[str(a.image_root/'lib/libc.so'),'--library-path',f'{a.image_root}/lib:{a.image_root}/usr/lib',str(a.image_root/'usr/sbin/dnsmasq')],'rust':[str(a.rust)]}
    rows=[]
    payload=(b'\n#comment\n192.0.2.1 one.test\vvertical.test\fpage.test\rcarriage.test\n'
             b'192.0.2.2 nul.test\x00ignored.test after.test\n'
             b'192.0.2.3\x00invalid ignored.test\n'
             b'192.0.2.4 '+b'a'*100000+b' next.test\n'
             b'#'+b'x'*100000+b'\n192.0.2.5 final.test')
    hosts=a.out/'hosts';hosts.write_bytes(payload)
    cases=[(n,query(n)) for n in ['one.test','vertical.test','page.test','carriage.test','nul.test','ignored.test','after.test','next.test','final.test']]
    cases += [('qd0',struct.pack('!6H',0x1234,0x100,0,0,0,0)),('qd2',struct.pack('!6H',0x1234,0x100,2,0,0,0)+query('one.test')[12:]*2),('badlabel',struct.pack('!6H',0x1234,0x100,1,0,0,0)+b'\x40'+b'x'*64+b'\0\0\1\0\1')]
    for mode in ['addn-hosts','hostsdir']:
        directory=a.out/mode;directory.mkdir();(directory/'file').write_bytes(payload)
        row={'mode':mode}
        for side,command in commands.items():
            row[side]=run(command,[f'--{mode}={hosts if mode=="addn-hosts" else directory}'],a.out/f'{mode}-{side}.log',cases)
        rows.append(row)
    row={'mode':'dump-cnames'}
    options=['--host-record=deep.target.example,192.0.2.2','--cname=valid.alias.example,deep.target.example','--cname=missing.alias.example,absent.target.example']
    for side,command in commands.items():row[side]=run(command,options,a.out/f'dump-{side}.log', [('valid',query('valid.alias.example')),('missing',query('missing.alias.example'))])
    rows.append(row)
    row={'mode':'cache-enabled-malformed-additional'}
    opt=b'\0'+struct.pack('!HHIH',41,1232,0,0)
    cases=[]
    for extra in [b'',opt[:-1],b'\xc0\xff'+opt[1:],opt+opt[:-2],b'garbage']:
        wire=query('upstream.test');header=list(struct.unpack('!6H',wire[:12]));header[5]=1
        cases.append((extra.hex() or 'missing-additional',struct.pack('!6H',*header)+wire[12:]+extra))
    for side,command in commands.items():row[side]=run(command,[],a.out/f'malformed-{side}.log',cases)
    rows.append(row)
    result={'rust_sha256':hashlib.sha256(a.rust.read_bytes()).hexdigest(),'c_sha256':hashlib.sha256((a.image_root/'usr/sbin/dnsmasq').read_bytes()).hexdigest(),'rows':rows}
    (a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'mismatches':[(r['mode'],k,r['c'][k],r['rust'][k]) for r in rows for k in r['c'] if k!='dump' and r['c'][k]!=r['rust'][k]]},indent=2))

if __name__=='__main__':main()
