#!/usr/bin/env python3
"""Research build through the unchanged SDK recipe, with a same-link map.

This produces an unqualified artifact, never deploys, and does not overwrite
release manifests. All code generation, strip and package flags are the recipe's.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import build_package as audit


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--epoch',required=True)
    p.add_argument('--sdk',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--cargo',type=Path,required=True)
    p.add_argument('--expected-baseline-sha')
    a=p.parse_args()
    source,sdk,out,cargo=map(lambda x:audit.safe_path(x.resolve()),(a.source,a.sdk,a.out,a.cargo))
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    report={'source':str(source),'source_commit':a.commit,'features':'','opt_level':'3','status':'building',
            'scope':'SDK recipe research artifact; compatibility and performance pending'}
    def save(): (out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        source_files=audit.inputs(source)
        report['source_files']=source_files
        report['source_digest']=hashlib.sha256(json.dumps(source_files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        archive,expected=json.loads((source/'manifests/release-25.12.5.json').read_text())['inputs']['sdk'].split(' sha256 ')
        assert sdk.name==archive.removesuffix('.tar.zst') and audit.sha(sdk.parent/archive)==expected
        report['sdk']={'archive_sha256':expected,'files':audit.sdk_inputs(sdk)}
        env=os.environ.copy()
        for key in ('CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR'):
            env.pop(key,None)
        env.update(RUSTUP_TOOLCHAIN='1.98.1',SOURCE_DATE_EPOCH=a.epoch,CARGO_BUILD_JOBS='1')
        toolchain=sdk/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl'
        env['PERF_SDK_CC']=str(toolchain/'bin/aarch64-openwrt-linux-musl-gcc')
        env['PERF_LINK_MAP']=str(out/'link.map')
        map_cc=source/'tools/dnsmasq/perf_opt_map_cc.py'
        assert os.access(map_cc,os.X_OK)
        report['toolchain']={
            'cargo':audit.run([str(cargo),'--version'],out/'cargo-version.log',env=env).strip(),
            'rustc':audit.run([str(cargo.with_name('rustc')),'-Vv'],out/'rustc-version.log',env=env).strip(),
            'map_wrapper_sha256':audit.sha(map_cc)}
        build,output=out/'package-build',out/'sdk-output'
        variables=['V=s','-j1','V1_PACKAGE_RELEASE=4',f'OWRT_COMPONENTS_SOURCE={source / "components"}',
                   f'OWRT_DNSMASQ_BUILD_DIR={build}',f'OWRT_DNSMASQ_OUTPUT_DIR={output}',f'V1_CARGO={cargo}',
                   'V1_CARGO_HOME=/home/ubuntu/.cargo','V1_RUSTUP_HOME=/home/ubuntu/.rustup',
                   f'TARGET_CC_NOCACHE={map_cc}']
        report['commands']=[]
        with (sdk/'.owrt-dnsmasq-build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            with audit.package_recipe(sdk,source/'packaging/openwrt/owrt-dnsmasq',out,report):
                target=Path(report['sdk_recipe_path']).relative_to(sdk)
                for stage in ('prepare','compile'):
                    command=['make',f'{target}/{stage}',*variables]
                    report['commands'].append(command);save()
                    audit.run(command,out/(stage+'.log'),cwd=sdk,env=env)
                    if stage=='prepare':
                        for name,digest in source_files.items():
                            if name.startswith('components/'):
                                assert audit.sha(build/name.removeprefix('components/'))==digest
        packages=list(output.rglob('dnsmasq-*.apk'))
        assert len(packages)==1
        artifact=out/packages[0].name;shutil.copy2(packages[0],artifact)
        payload=out/'payload';payload.mkdir()
        apk=sdk/'staging_dir/host/bin/apk'
        audit.run([str(apk),'extract','--allow-untrusted','--no-network','--no-chown','--destination',str(payload),str(artifact)],out/'extract.log')
        report['payload_files']=audit.audit_payload(payload)
        elf=out/'dnsmasq-rs';shutil.copy2(payload/'usr/sbin/dnsmasq',elf)
        layout=audit.run([str(toolchain/'bin/aarch64-openwrt-linux-musl-readelf'),'-W','-h','-l','-d',str(elf)],out/'readelf.log')
        report['elf_layout']=audit.audit_elf(elf.read_bytes(),layout)
        report['artifacts']=[{'path':elf.name,'bytes':elf.stat().st_size,'sha256':audit.sha(elf)}]
        report['link_map']={'path':'link.map','sha256':audit.sha(out/'link.map')}
        report['artifact']={'name':artifact.name,'bytes':artifact.stat().st_size,'sha256':audit.sha(artifact)}
        report['prestrip']={'sha256':audit.sha(build/'dnsmasq/target/aarch64-unknown-linux-musl/release/dnsmasq-rs')}
        report['baseline_expected']=a.expected_baseline_sha
        report['baseline_matches_expected']=(audit.sha(elf)==a.expected_baseline_sha if a.expected_baseline_sha else None)
        report['source_unchanged']=audit.inputs(source)==source_files
        assert report['source_unchanged'] and audit.sdk_inputs(sdk)==report['sdk']['files']
        report['budget']={'elf_max_bytes':2200000,'apk_max_bytes':1200000}
        report['within_existing_budget']=elf.stat().st_size<=2200000 and artifact.stat().st_size<=1200000
        report['status']='built-unqualified'
        save();print(json.dumps({key:report[key] for key in ('status','artifacts','baseline_matches_expected','within_existing_budget')}))
    except BaseException as error:
        report.update(status='failed',error=repr(error));save();raise


if __name__=='__main__': main()
