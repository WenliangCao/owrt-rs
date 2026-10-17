#!/usr/bin/env python3
"""Build only frozen integrated runtime test tools after PGO training is quiet."""
from pathlib import Path
import hashlib,json,os,subprocess,time,re,shutil
ROOT=Path('/srv/owrt-archive/unified-work');SOURCE=ROOT/'source-e21245d2';OUT=ROOT/'private/core-runtime-tools'
SDK=Path('/srv/owrt-archive/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64');TC=SDK/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl';CC=TC/'bin/aarch64-openwrt-linux-musl-gcc'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert json.loads((ROOT/'private/pgo-training/state.json').read_text())['status']=='training-complete-unqualified'
OUT.mkdir();(OUT/'bins').mkdir();(OUT/'examples').mkdir()
source_files={str(p.relative_to(SOURCE)):sha(p) for folder in ['components','tools/benchmark','tools/testsrc'] for p in (SOURCE/folder).rglob('*') if p.is_file() and 'target' not in p.parts and '__pycache__' not in p.parts}
env=os.environ.copy();env.pop('LD_PRELOAD',None);env.update(RUSTUP_TOOLCHAIN='1.98.1',CARGO_BUILD_JOBS='2',CARGO_INCREMENTAL='0',STAGING_DIR=str(TC),CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=str(CC),RUSTFLAGS='-Dwarnings --remap-path-prefix='+str(SOURCE)+'=/build -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Clink-arg=-Wl,-z,pack-relative-relocs')
report={'status':'building-test-tools','source_commit':'e21245d2404f6542759f45d064214ac3696c355f','test_only':True,'shipping':False,'commands':[],'sdk_cc_sha256':sha(CC)}
def save():(OUT/'build.json').write_text(json.dumps(report,indent=2)+'\n')
def run(label,argv,extra=None):
 row={'label':label,'argv':list(map(str,argv)),'start':time.time()};report['commands'].append(row);save()
 with (OUT/(label+'.log')).open('x') as log:result=subprocess.run(row['argv'],cwd=SOURCE,env=dict(env,**(extra or {})),stdout=log,stderr=log)
 row.update(exit=result.returncode,end=time.time(),log_sha256=sha(OUT/(label+'.log')));row['diagnostics']=[l for l in (OUT/(label+'.log')).read_text().splitlines() if 'warning:' in l or 'ERROR:' in l];save();assert result.returncode==0,(label,row['diagnostics'])
try:
 for crate,names in {'procd':['watchdog_status','notifier','ptyhold'],'rpcd':['raw_bytes','output_lifecycle'],'ubusd':['wireprobe','fuzz','bench'],'netifd':['sysprobe','devstatus','ifstatus']}.items():
  target=OUT/('target-'+crate)
  run('examples-'+crate,['/srv/owrt-archive/cargo/bin/cargo','build','--release','--locked','--offline','--target','aarch64-unknown-linux-musl','--manifest-path',str(SOURCE/'components'/crate/'Cargo.toml'),'--target-dir',str(target),'--examples'])
  for name in names:shutil.copy2(target/'aarch64-unknown-linux-musl/release/examples'/name,OUT/'examples'/name)
 target=OUT/'target-benchmark'
 run('benchmark',['/srv/owrt-archive/cargo/bin/cargo','build','--release','--locked','--offline','--target','aarch64-unknown-linux-musl','--manifest-path',str(SOURCE/'tools/benchmark/Cargo.toml'),'--target-dir',str(target)])
 shutil.copy2(target/'aarch64-unknown-linux-musl/release/owrt-benchmark',OUT/'bins/owrt-benchmark')
 run('ns-exec',[CC,'-Os','-static','-Wall','-Wextra','-Werror',SOURCE/'tools/benchmark/ns_exec.c','-o',OUT/'bins/ns-exec'])
 run('helpers',['sh',SOURCE/'tools/r36_build_helpers.sh',OUT/'helpers'],{'OWRT_TEST_CC':str(CC)})
 run('r95-guard',[CC,'-Os','-static','-Wall','-Wextra','-Werror',SOURCE/'tools/testsrc/r95_guard.c','-o',OUT/'bins/r95-guard'])
 run('r131-event-stress',['sh',SOURCE/'tools/benchmark/build-r131-event-stress-libubus.sh',SDK,Path('/srv/owrt-archive/upstream-evidence/ax3000t-stock-openwrt-25.12.5/sources/components'),OUT/'r131-event-stress'])
 assert all(sha(SOURCE/name)==digest for name,digest in source_files.items())
 report.update(status='built-test-tools',source_unchanged=True,artifacts={str(p.relative_to(OUT)):{'sha256':sha(p),'bytes':p.stat().st_size} for folder in ['bins','examples','helpers','r131-event-stress'] for p in (OUT/folder).iterdir() if p.is_file()})
except BaseException as e:report.update(status='failed-preserved',error=repr(e));raise
finally:save()
