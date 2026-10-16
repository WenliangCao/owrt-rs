#!/usr/bin/env python3
"""Isolated profile2 receipt copy of the original canonical SDK builder.

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
import shlex
import tomllib
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import build_package as audit


def release_rustc_commands(log):
    """Retain the actual dnsmasq lib/bin invocations printed by Cargo."""
    commands = []
    for line in log.splitlines():
        if 'Running `' not in line:
            continue
        argv = shlex.split(line.split('Running `', 1)[1].rsplit('`', 1)[0])
        if '--crate-name' not in argv or argv[argv.index('--crate-name') + 1] != 'dnsmasq_rs':
            continue
        codegen = [argv[i + 1] if arg == '-C' else arg[2:]
                   for i, arg in enumerate(argv) if arg == '-C' or arg.startswith('-C')]
        commands.append({'argv': argv, 'codegen': codegen,
                         'crate_type': argv[argv.index('--crate-type') + 1]})
    return commands


def verify_profile2_commands(commands):
    assert len(commands) == 2 and {c['crate_type'] for c in commands} == {'lib', 'bin'}
    for command in commands:
        argv, codegen = command['argv'], command['codegen']
        assert argv[argv.index('--target') + 1] == 'aarch64-unknown-linux-musl'
        assert [c for c in codegen if c.startswith('opt-level=')] == ['opt-level=2']
        for key, value in [('codegen-units', '1'), ('panic', 'abort'), ('strip', 'symbols')]:
            assert [c for c in codegen if c.startswith(key + '=')] == [key + '=' + value]
        if command['crate_type'] == 'bin':
            assert [c for c in codegen if c == 'lto' or c.startswith('lto=')] in [['lto'], ['lto=fat']]


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--epoch',required=True)
    p.add_argument('--sdk',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--cargo',type=Path,required=True)
    p.add_argument('--expected-baseline-sha')
    p.add_argument('--build-slot',type=Path)
    p.add_argument('--cargo-target',type=Path)
    a=p.parse_args()
    source,sdk,out=map(lambda x:audit.safe_path(x.resolve()),(a.source,a.sdk,a.out))
    # rustup dispatches by argv[0]; resolving cargo's symlink selects rustup.
    cargo=audit.safe_path(a.cargo.absolute())
    assert 'private' in out.parts and not out.exists()
    out.mkdir(parents=True)
    report={'source':str(source),'source_commit':a.commit,'source_date_epoch':a.epoch,'features':'','opt_level':'2','status':'building',
            'scope':'SDK recipe research artifact; compatibility and performance pending',
            'builder_sha256':audit.sha(Path(__file__)), 'build_helper_sha256':audit.sha(Path(audit.__file__))}
    def save(): (out/'build.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        assert a.commit == '8035114257c8706047d2038c2bb8126391331925'
        overrides = sorted(key for key in os.environ if key.startswith('CARGO_PROFILE_RELEASE_'))
        assert not overrides, 'ambient Cargo release profile overrides: ' + ', '.join(overrides)
        profile = tomllib.loads((source/'components/dnsmasq/Cargo.toml').read_text())['profile']
        assert profile == {'release': {'opt-level': 2, 'lto': True, 'codegen-units': 1,
                                       'panic': 'abort', 'strip': True}}
        report['release_profile'] = profile['release']
        report['ambient_release_profile_overrides'] = overrides
        report['canonical_builder_sha256'] = 'f4540b1cbfd235ab2decde1bf7a09a6326fdb6fda7fe4d906239eac55a785f33'
        source_files=audit.inputs(source)
        identity=json.loads((source/'research-git-identity.json').read_text())
        assert identity['commit']==a.commit and identity['epoch']==a.epoch, 'source Git identity arguments differ'
        assert set(identity['git_blob_sha1'])==set(source_files), 'source Git inventory differs'
        for name,expected_blob in identity['git_blob_sha1'].items():
            data=(source/name).read_bytes()
            actual_blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            assert actual_blob==expected_blob, 'source Git blob differs: '+name
        report['git_identity_sha256']=audit.sha(source/'research-git-identity.json')
        report['source_files']=source_files
        report['source_digest']=hashlib.sha256(json.dumps(source_files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        archive,expected=json.loads((source/'manifests/release-25.12.5.json').read_text())['inputs']['sdk'].split(' sha256 ')
        assert sdk.name==archive.removesuffix('.tar.zst') and audit.sha(sdk.parent/archive)==expected
        report['sdk']={'archive_sha256':expected,'files':audit.sdk_inputs(sdk)}
        env=os.environ.copy()
        for key in ('CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC','RUSTFLAGS','CARGO_BUILD_TARGET','CARGO_TARGET_DIR'):
            env.pop(key,None)
        env.update(RUSTUP_TOOLCHAIN='1.98.1',SOURCE_DATE_EPOCH=a.epoch,CARGO_BUILD_JOBS='1',
                   CARGO_TERM_VERBOSE='true',CARGO_TERM_QUIET='false',CARGO_TERM_COLOR='never')
        toolchain=sdk/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl'
        env['PERF_SDK_CC']=str(toolchain/'bin/aarch64-openwrt-linux-musl-gcc')
        env['PERF_LINK_MAP']=str(out/'link.map')
        map_cc=source/'tools/dnsmasq/perf_opt_map_cc.py'
        assert os.access(map_cc,os.X_OK)
        report['toolchain']={
            'cargo':audit.run([str(cargo),'--version'],out/'cargo-version.log',env=env).strip(),
            'rustc':audit.run([str(cargo.with_name('rustc')),'-Vv'],out/'rustc-version.log',env=env).strip(),
            'map_wrapper_sha256':audit.sha(map_cc)}
        build=audit.safe_path(a.build_slot.resolve()) if a.build_slot else out/'package-build'
        output=out/'sdk-output'
        assert 'private' in build.parts
        variables=['V=s','-j1','CONFIG_AUTOREMOVE=','V1_PACKAGE_RELEASE=4',f'OWRT_COMPONENTS_SOURCE={source / "components"}',
                   f'OWRT_DNSMASQ_BUILD_DIR={build}',f'OWRT_DNSMASQ_OUTPUT_DIR={output}',f'V1_CARGO={cargo}',
                   'V1_CARGO_HOME=/home/ubuntu/.cargo','V1_RUSTUP_HOME=/home/ubuntu/.rustup',
                   f'TARGET_CC_NOCACHE={map_cc}']
        report['commands']=[]
        with (sdk/'.owrt-dnsmasq-build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            # SDK prepare stamps do not track the external component snapshot.
            # Recopy this owned package; its external Cargo cache survives.
            report['invalidated_prepare_stamps']=[]
            for stamp in sorted(build.glob('.prepared_*')):
                assert stamp.is_file() and not stamp.is_symlink()
                report['invalidated_prepare_stamps'].append(stamp.name)
                stamp.unlink()
            save()
            with audit.package_recipe(sdk,source/'packaging/openwrt/owrt-dnsmasq',out,report):
                target=Path(report['sdk_recipe_path']).relative_to(sdk)
                for stage in ('prepare','compile'):
                    command=['make',f'{target}/{stage}',*variables]
                    report['commands'].append(command);save()
                    audit.run(command,out/(stage+'.log'),cwd=sdk,env=env)
                    if stage=='prepare':
                        for name,digest in source_files.items():
                            if name.startswith('components/'):
                                assert audit.sha(build/name.removeprefix('components/'))==digest, 'prepared source differs: '+name
                        if a.cargo_target:
                            cache=audit.safe_path(a.cargo_target.resolve())
                            assert 'private' in cache.parts and not cache.is_relative_to(build)
                            cache.mkdir(parents=True,exist_ok=True)
                            cargo_output=build/'dnsmasq/target'
                            if cargo_output.exists():
                                assert cargo_output.is_symlink() and cargo_output.resolve()==cache
                            else:
                                cargo_output.symlink_to(cache,target_is_directory=True)
                            audit.run([str(cargo),'clean','--manifest-path',str(build/'dnsmasq/Cargo.toml'),
                                       '-p','dnsmasq-rs','--release','--target','aarch64-unknown-linux-musl'],out/'invalidate-product.log',env=env)
                            # SDK stamps do not know that Cargo's product was
                            # invalidated. Rebuild this owned package, retaining
                            # only the external dependency compilation cache.
                            for stamp in ('.built','.built_check'):
                                (build/stamp).unlink(missing_ok=True)
                            if (build/'.pkgdir').exists():
                                assert not (build/'.pkgdir').is_symlink()
                                shutil.rmtree(build/'.pkgdir')
                            report['shared_cargo_target']=str(cache)
        report['effective_rustc_commands'] = release_rustc_commands((out/'compile.log').read_text())
        save()
        verify_profile2_commands(report['effective_rustc_commands'])
        report['effective_profile2_verified'] = True
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
        prestrip=build/'dnsmasq/target/aarch64-unknown-linux-musl/release/dnsmasq-rs'
        retained=out/'dnsmasq-prestrip';shutil.copy2(prestrip,retained)
        report['prestrip']={'sha256':audit.sha(retained),'bytes':retained.stat().st_size}
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
