import hashlib,json,shutil,sys
from pathlib import Path
ROOT=Path('/srv/owrt-archive/dnsmasq-work');BASE=ROOT/'private/fork-a97edbc1/pgo'
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
gen=BASE/'generate-stage';gp=json.loads((gen/'inputs/plan.json').read_text());state=json.loads((gen/'state.json').read_text());assert state['status']=='complete'
built=json.loads((gen/'generate/build.json').read_text());assert built['source_digest']==gp['source_digest']
base=BASE/'train-stage';inputs=base/'inputs';inputs.mkdir(parents=True)
old=json.loads((BASE/'original-tools/training-plan.json').read_text())
for name,digest in old['input_sha256'].items():
 source=BASE/'original-tools/exact-original'/name;assert sha(source)==digest;shutil.copy2(source,inputs/name)
sys.path.insert(0,str(inputs));import pgo_train
plan={key:gp[key] for key in ('source','source_commit','source_date_epoch','source_digest','source_file_count','sdk','sdk_cc','sdk_toolchain','build_slot','builder','builder_sha256','build_helper_sha256','map_cc','map_cc_sha256','cargo','rustc','recipe_rustflags','static_pie_linker_sha256','baseline_receipt','expected_control_elf_sha256','fixed_tool_sha256','cpu')}
plan.update(scope='Restored-fork a97 one original eleven-scene training pass at new v022 slot, then one profile-use build. Final correctness and canonical x86 warning acceptance remain separate.',attempt=str(base),allowed_modes=['use'],input_sha256=old['input_sha256'],training_seed=old['training_seed'],evaluation_seed=old['evaluation_seed'],scenes=old['scenes'],budget={'elf_max_bytes':2500000,'apk_max_bytes':1400000},wrapper_remote_path=str(base/'wrapper/cargo'),wrapper_sha256=sha(inputs/'pgo_train_cargo.py'),training_directory=str(base/'training'),runtime_directory='/tmp/owrt-archive-v022-slot-06',merged_profile=str(base/'training.profdata'),profile_receipt=str(base/'training-profile.json'),generate_elf={'path':str(gen/'generate/dnsmasq-rs'),'sha256':built['artifacts'][0]['sha256']},generate_build={'path':str(gen/'generate/build.json'),'sha256':sha(gen/'generate/build.json')},smoke_state={'path':str(gen/'state.json'),'sha256':sha(gen/'state.json')},generate_default_profile_directory=gp['default_profile_directory'],outputs={'use':str(base/'use')},cargo_targets={'control':gp['cargo_targets']['control'],'use':str(base/'cargo-use')},invocation_receipts={'use':str(base/'use/pgo-invocation.json')},failure_policy='Stop on any failed scene/exit/profile/build/budget/missing/mismatch gate; preserve failures, never retry or replace a scene.',expected_profile_count=50)
profdata=Path('/srv/owrt-archive/rustup/toolchains/1.98.1-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu/bin/llvm-profdata')
plan['profdata']={'path':str(profdata),'sha256':sha(profdata),'version':'LLVM 22.1.8-rust-1.98.1-stable'}
plan['workload_tools']={}
for name,item in old['workload_tools'].items():
 path=BASE/'workload'/name;assert sha(path)==item['sha256'];plan['workload_tools'][name]={'path':str(path),'sha256':sha(path)}
assert plan['scenes']==[list(scene) for scene in pgo_train.SCENES]
plan['training_case_sha256']=hashlib.sha256(pgo_train.training_case((inputs/'perf_opt_device_case.sh').read_text(),Path(plan['training_directory']),Path(plan['runtime_directory']),plan['training_seed']).encode()).hexdigest()
life=pgo_train.lifecycle_source((inputs/'device_perf_lifecycle.c').read_text(),(inputs/'pgo_lifecycle_exit.c').read_text())
plan['training_lifecycle_source_sha256']=hashlib.sha256(life.encode()).hexdigest();assert plan['training_lifecycle_source_sha256']=='49666bd37b81a2a089db389b6b9543d52156f3c4b865c54f0d5e479b8d27cb48'
plan['helper_build_argv']=[plan['sdk_cc'],'-Os','-static','-Wall','-Wextra','-Werror',str(base/'device_perf_lifecycle.c'),'-o',str(base/'device_perf_lifecycle')]
plan['stages']=[{'mode':'use','environment':{'PGO_SMOKE_PLAN':str(inputs/'plan.json'),'PGO_SMOKE_MODE':'use'},'argv':['python3',plan['builder'],'--source',plan['source'],'--commit',plan['source_commit'],'--epoch',plan['source_date_epoch'],'--sdk',plan['sdk'],'--out',plan['outputs']['use'],'--cargo',plan['wrapper_remote_path'],'--build-slot',plan['build_slot'],'--cargo-target',plan['cargo_targets']['use']]}]
pgo_train.check_baseline_paths(plan,json.loads(Path(plan['baseline_receipt']['path']).read_text()))
assert not Path(plan['runtime_directory']).exists()
assert len(plan['scenes'])==11 and plan['training_seed']==539365398 and plan['build_slot']=='/srv/owrt-archive/dnsmasq-work/private/sdk-build-slot'
(inputs/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
print(json.dumps({'plan':str(inputs/'plan.json'),'plan_sha256':sha(inputs/'plan.json'),'source_commit':plan['source_commit'],'source_digest':plan['source_digest'],'source_files':plan['source_file_count'],'build_slot':plan['build_slot'],'scenes':len(plan['scenes']),'seed':plan['training_seed'],'expected_raw_profiles':50,'recipe_rustflags':plan['recipe_rustflags']},indent=2))
