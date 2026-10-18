#!/usr/bin/env python3
"""Explicit-SHA functional qualification only; never a performance run."""
import argparse,hashlib,json,os,platform,subprocess,sys,time
from pathlib import Path


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text())
def save(path,value): path.write_text(json.dumps(value,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('candidate',type=Path)
    parser.add_argument('sha256')
    parser.add_argument('output',type=Path)
    parser.add_argument('--rootfs',type=Path,default=Path('/home/ubuntu/owrt-v023-20261017/private/native-final-0a925bcc/rootfs'))
    args=parser.parse_args()
    assert os.geteuid()==0 and platform.system()=='Linux' and platform.machine()=='aarch64'
    assert not Path('/etc/openwrt_release').exists()
    candidate=args.candidate.resolve();root=args.rootfs.resolve();out=args.output.resolve()
    assert sha(candidate)==args.sha256
    assert args.sha256!='c7c5f1f9e79ea80febe696d6c758db8d3463d1e4b94c7a002f1aa597b9c3ea30','do not re-run the old candidate'
    assert out.is_relative_to(Path('/home/ubuntu/odhcpd-validation-idle-renew-20261018')) and not out.exists()
    assert sha(root/'usr/sbin/odhcpd')=='53e534a12d412b1f138ab95d15431bc109bbb356dbfadfb8625397d585d2be82'
    tool=Path(__file__).parent/'odhcpd_baseline.py'
    out.mkdir(mode=0o700,parents=True)
    logs=out/'logs';logs.mkdir()
    inputs={'candidate':str(candidate),'sha256':args.sha256,'bytes':candidate.stat().st_size,
            'rootfs':str(root),'tool_sha256':sha(tool),'runner_sha256':sha(Path(__file__)),
            'purpose':'existing baseline20 extended62 fable47; functional only'}
    save(out/'inputs.json',inputs)
    completed={}
    for name,expected in [('baseline',20),('extended',62),('fable',47)]:
        cmd=[sys.executable,str(tool),'--rootfs',str(root),'--daemon',str(candidate),'--out',str(out/name),'--case',name]
        start=time.monotonic()
        with (logs/(name+'.log')).open('wb') as stream:
            run=subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,timeout=800,umask=0o022)
        save(logs/(name+'.command.json'),{'argv':cmd,'exit':run.returncode,'duration_s':time.monotonic()-start})
        if run.returncode:
            completed[name]={'passed':False,'exit':run.returncode}
            save(out/'result.json',{'passed':False,'groups':completed,'candidate_sha256':args.sha256})
            raise RuntimeError(f'{name} failed; preserved {out/name}')
        paths=[out/name/'results.json'] if name!='extended' else [out/name/sub/'results.json' for sub in ('finite','link','control','reject')]
        checks={str(path.relative_to(out)):read(path)['checks'] for path in paths}
        count=sum(len(value) for value in checks.values())
        passed=count==expected and all(all(values.values()) for values in checks.values())
        assert passed,(name,count,checks)
        completed[name]={'passed':True,'checks':count,'result_sha256':{key:sha(out/key) for key in checks}}
        save(out/'progress.json',completed)
        print(json.dumps({'group':name,**completed[name]}),flush=True)
    assert sha(candidate)==args.sha256 and sha(tool)==inputs['tool_sha256']
    result={'passed':True,'groups':completed,'checks':sum(v['checks'] for v in completed.values()),
            'candidate_sha256':args.sha256,'tool_sha256':inputs['tool_sha256'],
            'physical_router_accessed':False,'performance_gate_run':False}
    assert result['checks']==129
    save(out/'result.json',result);print(json.dumps(result),flush=True)

if __name__=='__main__':main()
