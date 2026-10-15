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
import tempfile
import time

from perf_opt_device_run import SCENES, validate, write


def archive_window(out, folder, label):
    """Retain even incomplete windows before removing their owned /tmp files."""
    folder.mkdir(exist_ok=True)
    sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
    raw={str(p.relative_to(folder)):sha(p) for p in folder.rglob('*') if p.is_file()}
    archive_path=out/(label+'.tar.gz')
    with tarfile.open(archive_path,'w:gz') as archive:
        archive.add(folder,arcname=label,recursive=True)
    retained=out/'runs'/label
    shutil.copytree(folder,retained)
    copied={str(p.relative_to(retained)):sha(p) for p in retained.rglob('*') if p.is_file()}
    assert copied==raw, 'window copy identity mismatch'
    write(out/(label+'.archive.json'),{'files':raw,'archive_sha256':sha(archive_path)})
    shutil.rmtree(folder)
    return retained


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--cpu',type=int,default=2)
    parser.add_argument('--smoke',action='store_true',
                        help='two baseline-only full-duration windows; never timing acceptance')
    a=parser.parse_args();out=a.out.resolve()
    assert os.uname().nodename.startswith('instance-') and os.geteuid()==0
    assert re.fullmatch('/home/ubuntu/dnsmasq-perf-20261015/root/private/[a-zA-Z0-9_-]+',str(out))
    out.mkdir();(out/'runs').mkdir()
    # The frozen lifecycle ELF validates realpath(DIRECTORY) starts with /tmp/.
    # Keep its bytes unchanged and archive each window back into private output.
    runtime=Path(tempfile.mkdtemp(prefix='dnsmasq-perf-oracle-',dir='/tmp'))
    def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ('m6a_loadgen','m6a_upstream','device_perf_resource_probe','device_perf_lifecycle','device_perf_netns','nice10'):
        shutil.copy2(a.inputs/name,out/name);(out/name).chmod(0o755)
    hashes={}
    for side,path in (('c',a.baseline),('rust',a.candidate)):
        target=out/('dnsmasq-'+side);shutil.copy2(path,target);target.chmod(0o755);hashes[side]=sha(target)
    original=Path(__file__).with_name('perf_opt_device_case.sh').read_text()
    assert original.count('out=$root/runs/$label')==1
    (out/'device_perf_case.sh').write_text(original.replace('/tmp/dnsmasq-perf-20261015',str(out))
          .replace('out=$root/runs/$label','out='+str(runtime)+'/$label'))
    (out/'guard.pid').write_text(str(os.getpid())+'\n')
    write(out/'identity.json',{'environment':'Oracle AArch64 Linux, isolated loopback, full frozen workloads',
          'comparison':hashes,'affinity':[a.cpu],'production_guard':'not applicable; owned process group with 100s deadline',
          'runtime_directory':str(runtime),'smoke_only':a.smoke,
          'controller_sha256':sha(Path(__file__)),'case_sha256':sha(out/'device_perf_case.sh'),
          'inputs':{p.name:sha(p) for p in out.iterdir() if p.is_file()}})
    results=[];active=None;label=None
    try:
        for scene in ([SCENES[0],SCENES[7]] if a.smoke else SCENES):
            for number in (range(1,2) if a.smoke else range(1,6)):
                for side in (('c',) if a.smoke else (('c','rust') if number%2 else ('rust','c'))):
                    label=f'{scene[0]}-r{number}-{side}'
                    command=['taskset','-c',str(a.cpu),str(out/'nice10'),str(out/'device_perf_netns'),
                             '/bin/sh',str(out/'device_perf_case.sh'),str(out),side,label,*map(str,scene[1:])]
                    interrupted=None;code=None
                    try:
                        with (out/(label+'.controller.log')).open('wb') as log:
                            active=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
                            code=active.wait(timeout=100);active=None
                    except BaseException as error:
                        interrupted=error
                    finally:
                        if active is not None:
                            try:os.killpg(active.pid,signal.SIGKILL)
                            except ProcessLookupError:pass
                            active.wait();active=None
                    folder=archive_window(out,runtime/label,label)
                    try:errors=validate(folder,scene,hashes[side])
                    except Exception as error:errors=['validation failed: '+repr(error)]
                    if code:errors.append('controller exit '+str(code))
                    if interrupted:errors.append('controller interrupted: '+repr(interrupted))
                    row={'label':label,'scene':scene[0],'round':number,'side':side,'valid':not errors,'errors':errors,'epoch':time.time()}
                    results.append(row);write(out/'progress.json',results);print(json.dumps(row),flush=True)
                    if interrupted:raise interrupted
                    if code:raise RuntimeError('case process failed')
        write(out/'complete.json',{'complete':not a.smoke and len(results)==110,
              'smoke_only':a.smoke,'windows':len(results),'valid':sum(r['valid'] for r in results)})
    except BaseException as error:
        write(out/'failure.json',{'error':repr(error),'attempt':label,'completed':results})
        raise
    finally:
        if active is not None:
            os.killpg(active.pid,signal.SIGKILL);active.wait()
        if not any(runtime.iterdir()):runtime.rmdir()


if __name__=='__main__':main()
