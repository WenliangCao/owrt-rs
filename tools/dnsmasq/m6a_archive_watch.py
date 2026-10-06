#!/usr/bin/env python3
"""Local-only full-fidelity archive verifier for the serial Oracle M6a suite."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import socket
import subprocess
import time

import m5_option_matrix_archive as archive

def remote(command):
    return subprocess.run(['ssh','oracle',shlex.join(command)],check=True,capture_output=True,text=True).stdout

def copy(source,destination):
    if str(destination).startswith('oracle:'):
        subprocess.run(['scp','-p',source,str(destination)],check=True,capture_output=True,text=True)
        return
    target=Path(destination);partial=target.with_suffix(target.suffix+'.part')
    subprocess.run(['scp','-p',source,str(partial)],check=True,capture_output=True,text=True)
    partial.replace(target)

def save(path,value):
    temporary=path.with_suffix(path.suffix+'.new')
    temporary.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');temporary.replace(path)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--remote-root',required=True);p.add_argument('--local-root',type=Path,required=True)
    p.add_argument('--poll-seconds',type=float,default=2);args=p.parse_args()
    local=args.local_root.resolve();local.mkdir(parents=True,exist_ok=True)
    root=Path(args.remote_root);private=root/'private'
    for name in ['manifest.json','state.json']:
        copy('oracle:'+str(private/name),local/name)
    finished=set()
    while True:
        try:
            raw=remote(['cat',str(private/'state.json')]);state=json.loads(raw)
            save(local/'state.json',state)
            gate=state.get('archive_gate')
            if gate:
                job=state['current_job'];number=state['current_attempt'];key=(job,number)
                folder=Path(gate['archive_folder']);dest=local/'archives'/job/f'attempt-{number}'
                dest.mkdir(parents=True,exist_ok=True)
                proof=dest/'local-verification.json'
                if not proof.exists():
                    for name in ['archive.tar.gz','manifest.json']:
                        path=dest/name
                        if not path.exists():copy('oracle:'+str(folder/name),path)
                    report=archive.verify(dest/'archive.tar.gz',dest/'manifest.json',dest/'plain')
                    report.update(local_full_metadata_verified=True,verifier_host=socket.gethostname(),
                                  manifest_sha256=archive.digest(dest/'manifest.json'))
                    save(proof,report)
                else:
                    report=json.loads(proof.read_text())
                    if (not report.get('verified') or not report.get('local_full_metadata_verified')
                            or report['archive_sha256']!=archive.digest(dest/'archive.tar.gz')
                            or report['manifest_sha256']!=archive.digest(dest/'manifest.json')):
                        raise ValueError('existing local archive proof differs')
                if key not in finished:
                    temporary='/home/ubuntu/m6a-proof-'+job+'-'+str(number)+'.json'
                    copy(str(proof),'oracle:'+temporary)
                    remote(['sudo','-n','install','-m','644',temporary,str(folder/'local-verification.json')])
                    print(json.dumps({'job':job,'attempt':number,'local_verified':True,
                        'archive_sha256':report['archive_sha256'],'entries':report['entries']}),flush=True)
                    finished.add(key)
            # Copy completed prune receipts, but never read raw trees during a live window.
            for job,window in state['windows'].items():
                for item in window['attempts']:
                    number=item['attempt'];dest=local/'archives'/job/f'attempt-{number}'
                    path=dest/'prune.json'
                    if item.get('archive',{}).get('pruned') and not path.exists():
                        copy('oracle:'+str(Path(item['archive']['folder'])/'prune.json'),path)
            if state['status'] in ['complete','partial-complete','pilots-complete','failed-tools-or-environment']:
                print(json.dumps({'status':state['status'],'valid_windows':state['formal_valid_windows']}),flush=True)
                return 0 if state['status']!='failed-tools-or-environment' else 1
        except subprocess.CalledProcessError as error:
            # A dropped SSH transport is not a failed measurement; preserve and retry.
            with (local/'archive-watcher-transport-errors.jsonl').open('a') as stream:
                stream.write(json.dumps({'time_ns':time.time_ns(),'returncode':error.returncode,
                                        'stderr':error.stderr})+'\n')
        time.sleep(args.poll_seconds)

if __name__=='__main__':raise SystemExit(main())
