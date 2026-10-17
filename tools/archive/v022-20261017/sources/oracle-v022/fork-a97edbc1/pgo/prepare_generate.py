import hashlib,json,shutil,subprocess
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/fork-a97edbc1/pgo';SOURCE=ROOT/'source-a97edbc1'
SDK=Path('/srv/owrt-archive/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64');TC=SDK/'staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
control=BASE/'control-corrected/build.json';receipt=json.loads(control.read_text())
assert receipt['status']=='built-unqualified' and receipt['source_unchanged']
assert receipt['source_commit']=='a97edbc1382fc92b83110ed0822284aafeee7461' and receipt['source_digest']=='c47f95e99a966ec6433f37e0a7d36a8d8a7e9b360f63de6e905e0993e1bfc671'
assert json.loads((BASE.parent/'native-full/summary.json').read_text())['status']=='passed'
assert json.loads((BASE.parent/'ci-plain/verification.json').read_text())['status']=='verified-canonical-plain'
assert json.loads((BASE.parent/'pgo/runtime-authority.json').read_text())['root_authorized_resume'] is True
base=BASE/'generate-stage';inputs=base/'inputs';inputs.mkdir(parents=True,exist_ok=True);assert not (base/'state.json').exists() and not (inputs/'plan.json').exists()
for name in ('pgo_generate.py','pgo_smoke_cargo.py'):
 shutil.copy2(BASE/'original-tools'/name,inputs/name)
shutil.copy2(BASE/'original-tools/exact-original/pgo_sdk_smoke.py',inputs/'pgo_sdk_smoke.py')
cargo=Path('/srv/owrt-archive/rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/bin/cargo');rustc=cargo.with_name('rustc');profdata=cargo.parent.parent/'lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata'
slot=ROOT/'private/sdk-build-slot';builder=BASE/'builders-pgo/perf_opt_sdk_build.py';mapcc=SOURCE/'tools/dnsmasq/perf_opt_map_cc.py';wrapper=base/'wrapper/cargo';output=base/'generate';runtime=base/'smoke-runtime';default=base/'profraw-default'
flags=f'-Cforce-unwind-tables=no --remap-path-prefix={slot}=/build --remap-path-prefix=/srv/owrt-archive/cargo=/cargo -Clink-arg=-fuse-ld=bfd -Clink-arg=-Wl,-z,max-page-size=4096 -Clink-arg=-Wl,-z,now -Clink-arg=-Wl,-z,relro -Crelocation-model=pie -Ctarget-feature=+crt-static -Dwarnings'
assert flags in (BASE/'control-corrected/compile.log').read_text()
plan={key:receipt[key] for key in ('source','source_commit','source_date_epoch','source_digest')}
plan.update(builder_sha256=sha(builder),build_helper_sha256=sha(builder.with_name('build_package.py')),scope='Restored-fork a97 new-source profile-generate and excluded smoke at the frozen v022 build-slot; not training or qualification',attempt=str(base),cpu=0,builder=str(builder),sdk=str(SDK),sdk_cc=str(TC/'bin/aarch64-openwrt-linux-musl-gcc'),sdk_toolchain=str(TC),source_file_count=len(receipt['source_files']),build_slot=str(slot),map_cc=str(mapcc),map_cc_sha256=sha(mapcc),cargo=str(cargo),rustc=str(rustc),recipe_rustflags=flags,static_pie_linker_sha256=sha(SOURCE/'packaging/openwrt/owrt-dnsmasq/static-pie-linker.py'),wrapper_remote_path=str(wrapper),wrapper_sha256=sha(inputs/'pgo_smoke_cargo.py'),baseline_receipt={'path':str(control),'sha256':sha(control)},expected_control_elf_sha256=receipt['artifacts'][0]['sha256'],default_profile_directory=str(default),outputs={'generate':str(output)},cargo_targets={'control':receipt['shared_cargo_target'],'generate':str(base/'cargo-generate')},invocation_receipts={'generate':str(output/'pgo-invocation.json')},isolator={'path':str(SOURCE/'tools/dnsmasq/run_isolated.sh'),'sha256':sha(SOURCE/'tools/dnsmasq/run_isolated.sh')})
plan['input_sha256']={p.name:sha(p) for p in sorted(inputs.iterdir())}
plan['fixed_tool_sha256']={str(p):sha(p) for p in (Path('/srv/owrt-archive/cargo/bin/cargo'),cargo,rustc,profdata)}
argv=['python3',str(builder),'--source',str(SOURCE),'--commit',plan['source_commit'],'--epoch',plan['source_date_epoch'],'--sdk',str(SDK),'--out',str(output),'--cargo',str(wrapper),'--build-slot',str(slot),'--cargo-target',plan['cargo_targets']['generate']]
plan['stages']=[{'mode':'generate','argv':argv,'environment':{'PGO_SMOKE_PLAN':str(inputs/'plan.json'),'PGO_SMOKE_MODE':'generate'}}]
plan['runtime']={'directory':str(runtime),'config_lines':['no-resolv','no-hosts','user=root','group=root','listen-address=127.0.0.1','port=15353','local-ttl=120','host-record=pgo-smoke.test,192.0.2.41,2001:db8::41'], 'queries':[{'name':'pgo-smoke.test','qtype':'A','expected_address':'192.0.2.41'},{'name':'pgo-smoke.test','qtype':'AAAA','expected_address':'2001:db8::41'}],'llvm_profile_file':str(runtime/'%p.profraw'),'daemon_argv':[str(output/'dnsmasq-rs'),'-k','-C',str(runtime/'config')],'readiness_timeout_seconds':5,'normal_exit_timeout_seconds':5,'normal_exit_status':0}
(inputs/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
print(json.dumps({'plan':str(inputs/'plan.json'),'sha256':sha(inputs/'plan.json'),'control_elf':receipt['artifacts'][0],'control_apk':receipt['artifact'],'source_files':len(receipt['source_files']),'build_slot':str(slot)},indent=2))
