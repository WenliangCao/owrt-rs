#!/usr/bin/env python3
"""Serialized, CPU-pinned full workload screening on Oracle, never a router.

The case script and measurement binaries are those frozen for the device.
Only the root allowlist and the non-production controller guard PID differ.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time

from perf_opt_device_run import SCENES, validate, write


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--cpu',type=int,default=2)
    a=parser.parse_args();out=a.out.resolve()
    assert os.uname().nodename.startswith('instance-') and os.geteuid()==0
    assert re.fullmatch('/home/ubuntu/dnsmasq-perf-20261015/root/private/[a-zA-Z0-9_-]+',str(out))
    out.mkdir();(out/'runs').mkdir()
    def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('m6a_loadgen','m6a_upstream','device_perf_resource_probe','device_perf_lifecycle','device_perf_netns','nice10'):
        shutil.copy2(a.inputs/name,out/name);(out/name).chmod(0o755)
    hashes={}
    for side,path in (('c',a.baseline),('rust',a.candidate)):
        target=out/('dnsmasq-'+side);shutil.copy2(path,target);target.chmod(0o755);hashes[side]=sha(target)
    original=Path(__file__).with_name('perf_opt_device_case.sh').read_text()
    (out/'device_perf_case.sh').write_text(original.replace('/tmp/dnsmasq-perf-20261015',str(out)))
    (out/'guard.pid').write_text(str(os.getpid())+'\n')
    write(out/'identity.json',{'environment':'Oracle AArch64 Linux, isolated loopback, full frozen workloads',
          'comparison':hashes,'affinity':[a.cpu],'production_guard':'not applicable; owned process group with 100s deadline',
          'controller_sha256':sha(Path(__file__)),'case_sha256':sha(out/'device_perf_case.sh'),
          'inputs':{p.name:sha(p) for p in out.iterdir() if p.is_file()}})
    results=[];active=None;label=None
    try:
        for scene in SCENES:
            for number in range(1,6):
                for side in (('c','rust') if number%2 else ('rust','c')):
                    label=f'{scene[0]}-r{number}-{side}'
                    command=['taskset','-c',str(a.cpu),str(out/'nice10'),str(out/'device_perf_netns'),
                             '/bin/sh',str(out/'device_perf_case.sh'),str(out),side,label,*map(str,scene[1:])]
                    with (out/(label+'.controller.log')).open('wb') as log:
                        active=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
                        code=active.wait(timeout=100);active=None
                    folder=out/'runs'/label
                    errors=validate(folder,scene,hashes[side])
                    if code:errors.append('controller exit '+str(code))
                    raw={str(p.relative_to(folder)):sha(p) for p in folder.rglob('*') if p.is_file()}
                    with tarfile.open(out/(label+'.tar.gz'),'w:gz') as archive:
                        archive.add(folder,arcname=label,recursive=True)
                    write(out/(label+'.archive.json'),{'files':raw,'archive_sha256':sha(out/(label+'.tar.gz'))})
                    row={'label':label,'scene':scene[0],'round':number,'side':side,'valid':not errors,'errors':errors,'epoch':time.time()}
                    results.append(row);write(out/'progress.json',results);print(json.dumps(row),flush=True)
                    if code:raise RuntimeError('case process failed')
        write(out/'complete.json',{'complete':True,'windows':len(results),'valid':sum(r['valid'] for r in results)})
    except BaseException as error:
        write(out/'failure.json',{'error':repr(error),'attempt':label,'completed':results})
        raise
    finally:
        if active is not None:
            os.killpg(active.pid,signal.SIGKILL);active.wait()


if __name__=='__main__':main()
