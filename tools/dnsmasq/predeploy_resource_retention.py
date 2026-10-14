#!/usr/bin/env python3
"""Three separately gated 180 s windows on one unchanged test daemon PID."""
import argparse
import hashlib
import json
import subprocess
import time
import uuid
from pathlib import Path
import predeploy_resources as audit


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact',type=Path,required=True)
    parser.add_argument('--helpers',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--implementation',choices=['C','R'],default='R')
    args=parser.parse_args()
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    root='/tmp/dnsmasq-audit-c-'+str(int(time.time()))+'-'+uuid.uuid4().hex[:8]
    name='retention'
    state={'root':root,'smoke':False,'implementation':args.implementation,'windows':[],
           'artifact_sha256':hashlib.sha256(args.artifact.read_bytes()).hexdigest()}
    save=lambda:(args.output/'state.json').write_text(json.dumps(state,indent=2)+'\n')
    baseline=audit.health(args.output,'initial');state['baseline']=baseline;save()
    upload=args.output/'upload';upload.mkdir()
    config,leases=audit.configuration(root,128)
    (upload/'busy.conf').write_text(config);(upload/'busy.leases').write_text(leases)
    (upload/'hosts').write_text('127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n127.0.0.1 router\n::1 router\n')
    created=False
    try:
        audit.remote(f'mkdir {root}');created=True;audit.remote(f'chmod 755 {root}')
        inputs=[(args.artifact,'dnsmasq-rs'),(Path(__file__).with_suffix('.sh'),'retention.sh'),
                *[(args.helpers/n,n) for n in ('bind','probe','upstream','loadgen')],*[(p,p.name) for p in upload.iterdir()]]
        for source,dest in inputs:
            subprocess.run(['scp','-O','-q',str(source),'openwrt:'+root+'/'+dest],check=True,timeout=30)
        audit.remote(f'chmod 755 {root}/dnsmasq-rs {root}/bind {root}/probe {root}/upstream {root}/loadgen')
        state['remote_identities']=audit.remote(f'sha256sum {root}/dnsmasq-rs {root}/bind {root}/probe {root}/upstream {root}/loadgen /usr/sbin/dnsmasq')
        observed={Path(line.split()[1]).name:line.split()[0] for line in state['remote_identities'].splitlines()}
        expected={'dnsmasq-rs':state['artifact_sha256'],'dnsmasq':'097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'}
        expected.update({n:hashlib.sha256((args.helpers/n).read_bytes()).hexdigest() for n in ('bind','probe','upstream','loadgen')})
        if observed!=expected:raise RuntimeError('retention artifact mismatch')
        save()
        with (args.output/'retention.ssh.log').open('w') as log:
            process=subprocess.Popen(audit.SSH+[f'sh {root}/retention.sh {root} {name} {args.implementation}'],stdout=log,stderr=subprocess.STDOUT)
            started=time.time()
            while not audit.remote(f'[ -f {root}/{name}/READY ] && echo ready || :').strip():
                if process.poll() is not None or time.time()-started>20:raise RuntimeError('retention startup failed')
                time.sleep(1)
            state['socket_proof']=audit.socket_proof(root,name,args.output);save()
            audit.remote(f'touch {root}/{name}/GO')
            for index in range(1,4):
                segment=f'segment{index}';label=f'{index:02d}-busy-{args.implementation}'
                start=time.time()
                while not audit.remote(f'[ -f {root}/{name}/{segment}/SEGMENT_READY ] && echo ready || :').strip():
                    if process.poll() is not None or time.time()-start>25:raise RuntimeError('segment not ready')
                    time.sleep(1)
                pid=int(audit.remote(f'cat {root}/{name}/{segment}/SEGMENT_READY').strip())
                if pid!=state['socket_proof']['pid']:raise RuntimeError('daemon PID changed')
                row={'name':label,'profile':'busy','implementation':args.implementation,'same_pid':pid,'health':[]}
                state['windows'].append(row)
                row['health'].append(audit.health(args.output,label+'-before',baseline));save()
                audit.remote(f'touch {root}/{name}/{segment}/GO')
                last_check=0
                while not audit.remote(f'[ -f {root}/{name}/{segment}/COMPLETE ] && echo done || :').strip():
                    if process.poll() is not None or time.time()-start>225:raise RuntimeError('segment failed/expired')
                    if time.time()-last_check>25:
                        row['health'].append(audit.health(args.output,label+f'-during-{len(row["health"])}',baseline));save()
                        last_check=time.time();print(json.dumps({'segment':index,'elapsed':round(time.time()-start),'health':'ok'}),flush=True)
                    time.sleep(5)
                row['health'].append(audit.health(args.output,label+'-after',baseline));save()
                folder=args.output/label;folder.mkdir()
                with (args.output/(label+'.tar')).open('wb') as archive:
                    subprocess.run(audit.SSH+[f'tar -C {root}/{name}/{segment} -cf - .'],stdout=archive,check=True,timeout=30)
                subprocess.run(['tar','-xf',str(args.output/(label+'.tar')),'-C',str(folder)],check=True)
                actual=set(tuple(line.split()) for line in (folder/'leases-final').read_text().splitlines())
                expected=set(tuple(line.split()) for line in leases.splitlines())
                if actual!=expected:raise RuntimeError('retained lease set failed to converge')
                for mode in ('udp','tcp','dhcp'):
                    result=json.loads((folder/(mode+'.json')).read_text())
                    if result['interrupted'] or result['output_failed']:raise RuntimeError('retention workload incomplete')
                    row.setdefault('measurement_counters',{})[mode]=result['measurement']
                save()
                # Evidence copied privately; release completed segment tmpfs files.
                audit.remote(f'rm -rf {root}/{name}/{segment}')
                print(json.dumps({'segment':index,'complete':True,'same_pid':pid}),flush=True)
            process.wait(timeout=15)
            if process.returncode:raise RuntimeError('retention script failed at exit')
        with (args.output/'daemon-evidence.tar').open('wb') as archive:
            subprocess.run(audit.SSH+[f'tar -C {root}/{name} -cf - .'],stdout=archive,check=True,timeout=30)
        state['complete']=True;save()
    finally:
        if created:audit.cleanup(root,args.output)
        state['final_health']=audit.health(args.output,'final',baseline);save()


if __name__=='__main__':main()
