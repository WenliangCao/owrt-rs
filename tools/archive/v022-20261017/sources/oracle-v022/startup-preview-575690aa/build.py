import hashlib,json,subprocess,os,time
from pathlib import Path
root=Path('/srv/owrt-archive/dnsmasq-work/private/startup-preview-575690aa')
sdk=Path('/srv/owrt-archive/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64')
toolchain=sdk/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl'
cc=toolchain/'bin/aarch64-openwrt-linux-musl-gcc'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(root/'device_selfexec_lifecycle.c')=='ea68d6a8f94db07dacd0e5651155ed503881684185b3d2ab783dd473cd6a9b43'
assert not (root/'build-result.json').exists()
cmd=[str(cc),'-Os','-static','-std=c11','-Wall','-Wextra','-Werror',str(root/'device_selfexec_lifecycle.c'),'-o',str(root/'device_selfexec_lifecycle')]
env=dict(os.environ,STAGING_DIR=str(sdk/'staging_dir'),PATH=str(toolchain/'bin')+':'+os.environ['PATH'])
r={'command':cmd,'compiler_sha256':sha(cc),'source_sha256':sha(root/'device_selfexec_lifecycle.c'),'start':time.time()}
with (root/'build.stdout').open('wb') as stdout,(root/'build.stderr').open('wb') as stderr:r['returncode']=subprocess.run(cmd,env=env,stdout=stdout,stderr=stderr).returncode
r['end']=time.time()
if r['returncode']==0:r.update(elf_sha256=sha(root/'device_selfexec_lifecycle'),elf_bytes=(root/'device_selfexec_lifecycle').stat().st_size)
(root/'build-result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));assert r['returncode']==0
