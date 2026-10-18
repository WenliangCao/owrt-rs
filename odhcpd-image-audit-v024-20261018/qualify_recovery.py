#!/usr/bin/env python3
"""Run existing final-image recovery gates, without any router access."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib,json,os,platform,subprocess,sys,time,traceback
from pathlib import Path

ROLLBACK_SHA='02b6a3283140126a9c7d3ccc0404afe42077924b6b1229b3b96859cf449d8606'
HELPER_SHA='21609fa0e03e4a4595e74d266235a9566f2cc37f71571ad9315900d3def5cb49'
BASE=Path('/home/ubuntu/odhcpd-image-audit-v024-20261018')
STOCK=Path('/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files')
ROLLBACK=Path('/home/ubuntu/owrt-v023-20261017/private/final-inputs-0a925bcc/openwrt-25.12.5-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin')
HELPER=Path('/home/ubuntu/owrt-v023-20261017/private/recovery-helper/bounded')
APK_TOOL=Path('/home/ubuntu/ib/openwrt-imagebuilder-25.12.5-mediatek-filogic.Linux-x86_64/staging_dir/host/bin/apk')

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text())
def write(p,v): p.write_text(json.dumps(v,indent=2)+'\n')
def identity(root,manifest):
    release=read(root/'usr/share/owrt-control-plane/release.json')
    assert release['layout']=='native-eleven'
    for key in ('source_commit','components','integration_files','stock_manifest_sha256'): assert release[key]==manifest[key],key
    items=[*manifest['components'].values(),*manifest['integration_files'].values()]
    observed={}
    for item in items:
        for p,h in ((item['path'],item.get('rust_sha256',item.get('replacement_sha256'))),(item['recovery_path'],item['stock_sha256'])):
            assert sha(root/p.lstrip('/'))==h,p
            observed[p]=h
    sums=root/'usr/share/owrt-control-plane/stock.sha256'
    assert sha(sums)==manifest['stock_manifest_sha256']
    entries=dict(line.split(None,1)[::-1] for line in sums.read_text().splitlines())
    assert len(entries)==13 and entries=={i['recovery_path']:i['stock_sha256'] for i in items}
    return observed

def main():
    ap=argparse.ArgumentParser()
    for name in ('rootfs','image','manifest','native_apk','output'):ap.add_argument(name,type=Path)
    args=ap.parse_args()
    assert os.geteuid()==0 and platform.system()=='Linux' and platform.machine()=='aarch64'
    assert not Path('/etc/openwrt_release').exists()
    os.umask(0o022)
    root,image,mp,apk,out=(getattr(args,k).resolve() for k in ('rootfs','image','manifest','native_apk','output'))
    assert out.is_relative_to(BASE) and not out.exists()
    tools=BASE/'source/tools'
    manifest=read(mp)
    assert manifest['deployment_layout']=='native-eleven' and len(manifest['components'])==11 and len(manifest['integration_files'])==2
    assert manifest['source_commit']=='76705b92f85040d9c9f27f5c7b26a9d733d4675c' and manifest['packages']['owrt-control-plane']=='0.2.4-r1'
    assert sha(image)==manifest['image']['sha256'] and image.stat().st_size==manifest['image']['size']
    assert sha(apk)==manifest['apk_sha256'][apk.name]
    assert sha(ROLLBACK)==ROLLBACK_SHA and sha(HELPER)==HELPER_SHA
    before=identity(root,manifest)
    out.mkdir(mode=0o700)
    logs=out/'logs';logs.mkdir()
    names=('native_image_check.py','native_package_reinstall_selftest.py','native_trial_guard_selftest.py','native_trial_handoff_check.py','native_apk_fixtures.py','native_image.py','native_trial_guard.sh','r84_device_probe.py')
    tool_hashes={n:sha(tools/n) for n in names}
    inputs={n:{'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size} for n,p in (('image',image),('manifest',mp),('native_apk',apk),('rollback',ROLLBACK),('helper',HELPER))}
    write(out/'inputs.json',{'source_commit':manifest['source_commit'],'inputs':inputs,'tools':tool_hashes,'runner_sha256':sha(Path(__file__))})
    def run(name,command,timeout=600):
        started=time.monotonic();log=logs/(name+'.log')
        with log.open('wb') as stream:
            r=subprocess.run(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,timeout=timeout,umask=0o022)
        write(log.with_suffix('.command.json'),{'argv':list(map(str,command)),'returncode':r.returncode,'elapsed_s':time.monotonic()-started,'log_sha256':sha(log)})
        if r.returncode: raise RuntimeError(f'{name}: rc={r.returncode}; see {log}')
    def image_check():
        run('image-check',[sys.executable,tools/'native_image_check.py',root,out/'image-check','--image',image])
        r=read(out/'image-check/result.json');assert len(r)==9 and all(r.values())
        assert r['eleven_component_recovery_cannot_downgrade_to_ten_before_any_replacement']
        return {'passed':True,'checks':len(r)}
    def apk_check():
        fixtures=out/'apk-fixtures'
        run('apk-fixtures',[sys.executable,tools/'native_apk_fixtures.py',STOCK,apk,APK_TOOL,fixtures,'--spec',BASE/'source/packaging/image/native-25.12.5.json'])
        assert 'odhcpd-ipv6only' in read(fixtures/'fixture-provenance.json')['packages']
        run('package-reinstall',[sys.executable,tools/'native_package_reinstall_selftest.py',root,fixtures,out/'package-reinstall'])
        r=read(out/'package-reinstall/result.json');assert len(r['real_reinstalls'])==2 and all(r['real_reinstalls'].values())
        assert len(r['negative_controls'])==8 and all(i['rejected'] for i in r['negative_controls'])
        return {'passed':True,'stock_owner_fixtures':10,'real_reinstalls':2,'negative_controls':8}
    def guard_check():
        run('guard',[sys.executable,tools/'native_trial_guard_selftest.py',root,HELPER,out/'guard'])
        r=read(out/'guard/result.json');assert len(r)==23 and all(r.values())
        return {'passed':True,'branches':len(r)}
    def handoff_check():
        run('handoff',[sys.executable,tools/'native_trial_handoff_check.py',root,ROLLBACK,HELPER,out/'handoff','--image-sha256',ROLLBACK_SHA])
        r=read(out/'handoff/result.json');assert r['passed'] and len(r['cases'])==2 and all(i['passed'] for i in r['cases'].values())
        return {'passed':True,'cases':{n:{'passed':i['passed'],'elapsed_s':i['elapsed_s']} for n,i in r['cases'].items()}}
    results={};started=time.monotonic()
    jobs={'handoff':handoff_check,'image':image_check,'apk':apk_check,'guard':guard_check}
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures={pool.submit(job):name for name,job in jobs.items()}
        for future in as_completed(futures):
            name=futures[future]
            try: results[name]=future.result()
            except Exception: results[name]={'passed':False,'error':traceback.format_exc()}
            write(out/'progress.json',results); print(json.dumps({'group':name,**results[name]}),flush=True)
    assert identity(root,manifest)==before
    assert all(sha(Path(i['path']))==i['sha256'] for i in inputs.values())
    assert all(sha(tools/n)==h for n,h in tool_hashes.items())
    result={'passed':all(i['passed'] for i in results.values()),'source_commit':manifest['source_commit'],'image_sha256':sha(image),'manifest_sha256':sha(mp),'native_apk_sha256':sha(apk),'rollback_sha256':ROLLBACK_SHA,'groups':results,'inputs_and_source_rootfs_unchanged':True,'elapsed_s':time.monotonic()-started,'physical_router_accessed':False,'physical_flash_tested':False,'stage2_executed':False}
    write(out/'result.json',result);print(json.dumps(result),flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
