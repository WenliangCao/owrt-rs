#!/usr/bin/env python3
"""Disposable exact-image system resource fault probes; no router access.

Run under run_isolated.sh. Results record observations, not an overall pass:
ENOMEM intentionally demonstrates a candidate crash. Set --memory-headroom-mib
0 for the otherwise-identical allocation-failure negative control.
"""
import argparse,json,os,re,resource,signal,socket,struct,subprocess,time
from pathlib import Path
from m2_rootfs import prepare,command,sha256,bind_unix_socket
from dns_service_probe import query,semantics,exact_read

def dns(name='ready.test',tcp=False):
    req=query(name,ident=0x7412)
    if tcp:
        with socket.create_connection(('127.0.0.1',15353),.3) as s:
            s.settimeout(.3);s.sendall(struct.pack('!H',len(req))+req)
            ans=exact_read(s,struct.unpack('!H',exact_read(s,2))[0])
    else:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(.3);s.sendto(req,('127.0.0.1',15353));ans=s.recv(65535)
    return semantics(ans)

def safe_dns(**kwargs):
    try:return {'ok':True,'reply':dns(**kwargs)}
    except Exception as e:return {'ok':False,'error':repr(e)}

def status(pid):
    raw=Path(f'/proc/{pid}/status').read_text()
    return {k:int(v) for k,v in re.findall(r'^(VmSize|VmRSS|VmPeak):\s+(\d+)',raw,re.M)}

def run(args,side,kind):
    out=args.output/f'{kind}-{side}';out.mkdir(parents=True)
    root=prepare(args.image_root,None,out/'stage',args.rust)
    data=root/'m2';hosts=data/'hosts';hosts.write_text('192.0.2.42 initial.test\n')
    argv=['-k','--conf-file=','--no-resolv','--no-hosts','--no-ping','--user=root','--group=root','--listen-address=127.0.0.1','--port=15353','--pid-file=/m2/pid','--host-record=ready.test,192.0.2.41','--addn-hosts=/m2/hosts']
    log_socket=None
    tracer=None
    if kind=='logblocked':
        log_socket=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);log_socket.setblocking(False)
        bind_unix_socket(log_socket,root/'dev/log');argv+=['--log-async=25','--log-queries']
    else:argv+=['--log-facility=/dev/null']
    err=(out/'stderr').open('wb');stdout=(out/'stdout').open('wb')
    p=subprocess.Popen(command(root,side,*argv),stdout=stdout,stderr=err)
    result={'side':side,'kind':kind,'argv':argv,'binary_sha256':sha256(root/('usr/sbin/dnsmasq' if side=='c' else 'usr/sbin/dnsmasq-rs'))}
    try:
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if p.poll() is not None:raise RuntimeError(f'early exit {p.returncode}')
            if safe_dns()['ok']:break
        else:raise TimeoutError('ready')
        result['initial']=status(p.pid);result['ready']=safe_dns()
        tracer=subprocess.Popen(['strace','-f','-qq','-p',str(p.pid),'-e','trace=memory,tgkill,accept,accept4','-o',str(out/'syscalls.log')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(.1)
        if kind=='memory':
            # Same bounded additional address-space allowance on both processes.
            before=resource.prlimit(p.pid,resource.RLIMIT_AS)
            limit=result['initial']['VmSize']*1024+args.memory_headroom_mib*1024*1024
            if args.memory_headroom_mib:resource.prlimit(p.pid,resource.RLIMIT_AS,(limit,before[1]))
            result['limit_bytes']=limit if args.memory_headroom_mib else None
            hosts.write_text(''.join(f'192.0.2.{i%250+1} h{i:06d}.test\n' for i in range(30000)))
            p.send_signal(signal.SIGHUP);time.sleep(1)
            result['after_reload_exit']=p.poll()
            result['during_pressure_attempts']=[]
            end=time.monotonic()+10
            while True:
                current=safe_dns();result['during_pressure_attempts'].append(current)
                if current['ok'] or p.poll() is not None or time.monotonic()>=end:break
            result['during_pressure']=current
            result['last_host']=safe_dns(name='h029999.test')
            if p.poll() is None:
                result['pressure_status']=status(p.pid)
                resource.prlimit(p.pid,resource.RLIMIT_AS,before)
                hosts.write_text('192.0.2.44 recovered.test\n');p.send_signal(signal.SIGHUP);time.sleep(.2)
                result['recovered']=safe_dns(name='recovered.test')
        elif kind=='fd':
            before=resource.prlimit(p.pid,resource.RLIMIT_NOFILE)
            fds=sorted(int(x.name) for x in Path(f'/proc/{p.pid}/fd').iterdir())
            limit=next(n for n in range(max(fds)+2) if n not in fds)
            resource.prlimit(p.pid,resource.RLIMIT_NOFILE,(limit,before[1]));result['limit']=limit;result['fds']=fds
            result['tcp_pressure']=safe_dns(tcp=True);result['udp_pressure']=safe_dns()
            resource.prlimit(p.pid,resource.RLIMIT_NOFILE,before)
            result['tcp_recovered']=safe_dns(tcp=True);result['udp_recovered']=safe_dns()
        else:
            # DGRAM receive queue stays undrained until after 300 logged queries.
            result['queries']=[safe_dns()['ok'] for _ in range(300)]
            packets=[]
            while True:
                try:packets.append(log_socket.recv(65535).decode(errors='replace'))
                except BlockingIOError:break
            result['blocked_packets']=len(packets)
            result['recovered']=safe_dns()
            time.sleep(.2)
            while True:
                try:packets.append(log_socket.recv(65535).decode(errors='replace'))
                except BlockingIOError:break
            (out/'syslog.json').write_text(json.dumps(packets,indent=2))
    except Exception as e:result['error']=repr(e)
    finally:
        result['before_stop_exit']=p.poll()
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try:p.wait(2)
            except subprocess.TimeoutExpired:result['forced']=True;p.kill();p.wait()
        result['exit']=p.returncode;err.close();stdout.close()
        if tracer:
            try:tracer.wait(2)
            except subprocess.TimeoutExpired:tracer.terminate();tracer.wait()
        if log_socket:log_socket.close()
        result['stderr']=(out/'stderr').read_text(errors='replace')
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--image-root',type=Path,required=True);ap.add_argument('--rust',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--rust-sha256',required=True);ap.add_argument('--source-commit',required=True);ap.add_argument('--kinds',default='memory,fd,logblocked');ap.add_argument('--memory-headroom-mib',type=int,default=1);args=ap.parse_args()
    assert os.geteuid()==0 and os.environ.get('DNSMASQ_TEST_ISOLATED')=='1', 'root isolated namespace required'
    assert sha256(args.rust)==args.rust_sha256, 'candidate identity mismatch'
    assert not args.output.exists(), 'fresh output required'
    assert set(args.kinds.split(',')) <= {'memory','fd','logblocked'}, 'unknown probe kind'
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));args.output.mkdir(parents=True)
    results=[]
    for kind in args.kinds.split(','):
        for side in ('c','rust'):
            r=run(args,side,kind);results.append(r);print(json.dumps(r),flush=True)
    (args.output/'result.json').write_text(json.dumps(results,indent=2)+'\n')
    (args.output/'manifest.json').write_text(json.dumps({'source_commit':args.source_commit,'rust_sha256':args.rust_sha256,'driver_sha256':sha256(Path(__file__)),'image_root':str(args.image_root),'argv':__import__('sys').argv},indent=2)+'\n')
if __name__=='__main__':main()
