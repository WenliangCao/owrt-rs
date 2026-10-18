#!/usr/bin/env python3
"""Exact final-image guard/handoff and rollback bundle preparation, offline."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib,json,os,platform,subprocess,sys,tarfile,time,traceback
from pathlib import Path

BASE=Path('/home/ubuntu/odhcpd-image-v030-20261018')
ROLLBACK=Path('/home/ubuntu/owrt-v023-20261017/private/final-inputs-0a925bcc/openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin')
ROLLBACK_SHA='02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606'
HELPER=Path('/home/ubuntu/owrt-v023-20261017/private/recovery-helper/bounded')
HELPER_SHA='21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49'
BACKUP=Path('/home/ubuntu/odhcpd-pretrial-20261018/config-backup.tar.gz')
BACKUP_SHA='b8702654472e3aec26c233e30f1ad2192e351d4d572965768c880c945562b650'
ELF_SHA='589226a178668c0e53fa8db5ff726e2b4e69464f9521355fad229b1862c3043e'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def write(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def identity(root,manifest):
    release=read(root/'usr/share/owrt-control-plane/release.json')
    assert release['layout']=='native-eleven' and release['version']=='0.3.0-r1'
    for key in ('source_commit','components','integration_files','stock_manifest_sha256'): assert release[key]==manifest[key],key
    items=[*manifest['components'].values(),*manifest['integration_files'].values()]
    assert len(manifest['components'])==11 and len(items)==13
    observed={}
    for item in items:
        for p,h in ((item['path'],item.get('rust_sha256',item.get('replacement_sha256'))),(item['recovery_path'],item['stock_sha256'])):
            assert sha(root/p.lstrip('/'))==h,p
            observed[p]=h
    sums=root/'usr/share/owrt-control-plane/stock.sha256'
    assert sha(sums)==manifest['stock_manifest_sha256']
    assert dict(line.split(None,1)[::-1] for line in sums.read_text().splitlines())=={i['recovery_path']:i['stock_sha256'] for i in items}
    observed['/usr/sbin/owrt-recover-c']=sha(root/'usr/sbin/owrt-recover-c')
    return observed

def main():
    p=argparse.ArgumentParser()
    for n in ('rootfs','image','manifest','output'):p.add_argument(n,type=Path)
    p.add_argument('--source-commit',required=True)
    args=p.parse_args()
    assert os.geteuid()==0 and platform.system()=='Linux' and platform.machine()=='aarch64' and not Path('/etc/openwrt_release').exists()
    os.umask(0o022)
    root,image,mp,out=(getattr(args,n).resolve() for n in ('rootfs','image','manifest','output'))
    assert out.is_relative_to(BASE) and not out.exists()
    tools=BASE/'source/tools';manifest=read(mp)
    assert manifest['source_commit']==args.source_commit
    assert manifest['deployment_layout']=='native-eleven' and manifest['packages']['owrt-control-plane']=='0.3.0-r1'
    assert manifest['components']['odhcpd']['rust_sha256']==ELF_SHA
    assert sha(image)==manifest['image']['sha256'] and image.stat().st_size==manifest['image']['size']
    assert sha(ROLLBACK)==ROLLBACK_SHA and sha(HELPER)==HELPER_SHA and sha(BACKUP)==BACKUP_SHA
    before=identity(root,manifest)
    out.mkdir(mode=0o700);logs=out/'logs';logs.mkdir()
    inputs={n:{'path':str(v),'sha256':sha(v),'bytes':v.stat().st_size} for n,v in (('image',image),('manifest',mp),('rollback',ROLLBACK),('helper',HELPER),('backup',BACKUP))}
    toolnames=('native_trial_guard_selftest.py','native_trial_handoff_check.py','native_trial_guard.sh','native_trial_prepare.py','native_trial.init','r84_device_probe.py')
    toolsums={n:sha(tools/n) for n in toolnames}
    write(out/'inputs.json',{'source_commit':args.source_commit,'inputs':inputs,'tool_sha256':toolsums,'runner_sha256':sha(Path(__file__))})
    def run(name,command,timeout=600):
        start=time.monotonic();log=logs/(name+'.log')
        with log.open('wb') as stream:r=subprocess.run(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,timeout=timeout,umask=0o022)
        write(log.with_suffix('.command.json'),{'argv':list(map(str,command)),'exit':r.returncode,'elapsed_s':time.monotonic()-start,'log_sha256':sha(log)})
        if r.returncode:raise RuntimeError(f'{name}: exit{r.returncode}; preserved {log}')
    def guard():
        run('guard',[sys.executable,tools/'native_trial_guard_selftest.py',root,HELPER,out/'guard'])
        r=read(out/'guard/result.json');assert len(r)==23 and all(r.values())
        return {'passed':True,'branches':23}
    def handoff():
        run('handoff',[sys.executable,tools/'native_trial_handoff_check.py',root,ROLLBACK,HELPER,out/'handoff','--image-sha256',ROLLBACK_SHA])
        r=read(out/'handoff/result.json');assert r['passed'] and len(r['cases'])==2 and all(v['passed'] for v in r['cases'].values())
        return {'passed':True,'cases':{k:{'passed':v['passed'],'elapsed_s':v['elapsed_s']} for k,v in r['cases'].items()}}
    results={}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures={executor.submit(job):name for name,job in [('guard',guard),('handoff',handoff)]}
        for future in as_completed(futures):
            name=futures[future]
            try:results[name]=future.result()
            except Exception:results[name]={'passed':False,'error':traceback.format_exc()}
            write(out/'progress.json',results);print(json.dumps({'group':name,**results[name]}),flush=True)
    assert identity(root,manifest)==before
    assert all(sha(Path(v['path']))==v['sha256'] for v in inputs.values())
    assert all(sha(tools/n)==v for n,v in toolsums.items())
    if not all(v['passed'] for v in results.values()):
        write(out/'result.json',{'passed':False,'groups':results});return 1
    prepared=out/'deploy-prepared';prepared.mkdir(mode=0o700)
    archive=prepared/'trial-config.tar.gz'
    run('prepare',[sys.executable,tools/'native_trial_prepare.py',BACKUP,mp,HELPER,archive,'--rootfs',root,'--rollback-image',ROLLBACK,'--rollback-sha256',ROLLBACK_SHA,'--rollback-version','v0.2.3'])
    metadata=read(prepared/'trial-config.tar.json')
    assert metadata['original_members_preserved']==46 and metadata['archive_sha256']==sha(archive)
    with tarfile.open(BACKUP) as old,tarfile.open(archive) as new:
        assert len(old.getmembers())==46
        for member in old:
            other=new.getmember(member.name.lstrip('/'))
            for field in ('mode','uid','gid','mtime','type','linkname','uname','gname','size','pax_headers'):assert getattr(member,field)==getattr(other,field),(member.name,field)
            if member.isfile():assert old.extractfile(member).read()==new.extractfile(other).read(),member.name
        assert new.extractfile('root/owrt-native-trial/rollback-config.tar.gz').read()==BACKUP.read_bytes()
        assert new.extractfile('root/owrt-native-trial/rollback.bin').read()==ROLLBACK.read_bytes()
        recovery=dict(line.split(None,1)[::-1] for line in new.extractfile('root/owrt-native-trial/recovery.sha256').read().decode().splitlines())
        assert len(recovery)==15
        assert recovery['/usr/libexec/owrt-stock/usr/sbin/odhcpd']==manifest['components']['odhcpd']['stock_sha256']
        for path,digest in metadata['payload_sha256'].items():assert hashlib.sha256(new.extractfile(path).read()).hexdigest()==digest,path
    result={'passed':True,'source_commit':args.source_commit,'image_sha256':sha(image),'manifest_sha256':sha(mp),'rollback_sha256':ROLLBACK_SHA,'groups':results,'original_backup_sha256':BACKUP_SHA,'prepared_archive_sha256':sha(archive),'prepared_archive_bytes':archive.stat().st_size,'prepared_metadata_sha256':sha(prepared/'trial-config.tar.json'),'original_members_identical':46,'recovery_files_verified':13,'token_location':'private deploy-prepared/trial-config.tar.json only','inputs_and_source_rootfs_unchanged':True,'physical_router_accessed':False,'physical_flash_tested':False,'stage2_executed':False}
    write(out/'result.json',result);print(json.dumps(result),flush=True)
    return 0

if __name__=='__main__':raise SystemExit(main())
