import fcntl,hashlib,json,os,shutil,subprocess
from pathlib import Path
base=Path('/home/ubuntu/dnsmasq-perf-20261015/correctness')
source=Path('/home/ubuntu/dnsmasq-perf-20261015/root/source-warm-address-encode');out=base/'private/warm-address-encode-allocation-build';out.mkdir()
import time
while not (base/'private/warm-address-encode-tests/build.json').exists(): time.sleep(5)
target=Path('/home/ubuntu/dnsmasq-cargo-target')
sdk=Path('/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64')
toolchain=sdk/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl'
env=os.environ.copy()
for key in ['CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER']:env.pop(key,None)
env.update(CARGO_TARGET_DIR=str(target),CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1',STAGING_DIR=str(toolchain),CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=str(toolchain/'bin/aarch64-openwrt-linux-musl-gcc'),RUSTFLAGS=json.loads((base/'private/warm-address-encode-tests/build.json').read_text())['rustflags'])
argv=['/home/ubuntu/.cargo/bin/cargo','+1.98.1','test','--frozen','--target','aarch64-unknown-linux-musl','--manifest-path',str(source/'components/dnsmasq/Cargo.toml'),'--test','hosts_allocations','--no-run','--message-format=json']
with (target/'.dnsmasq-build.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 with (out/'build.stdout').open('w') as log,(out/'build.stderr').open('w') as err:
  subprocess.run(argv,env=env,stdout=log,stderr=err,check=True)
 rows=[json.loads(l) for l in (out/'build.stdout').read_text().splitlines()]
 executables=[r['executable'] for r in rows if r.get('executable') and r.get('profile',{}).get('test')]
 assert len(executables)==1
 shutil.copy2(executables[0],out/'hosts_allocations')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(out/'build.json').write_text(json.dumps({'source':str(source),'kind':'hosts-allocations-musl','command':argv,'rustflags':env['RUSTFLAGS'],'sha256':sha(out/'hosts_allocations'),'bytes':(out/'hosts_allocations').stat().st_size},indent=2)+'\n')
print((out/'build.json').read_text())
