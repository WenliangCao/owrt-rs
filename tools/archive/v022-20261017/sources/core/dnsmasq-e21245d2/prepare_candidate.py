from pathlib import Path
import json,hashlib,subprocess
ROOT=Path('/srv/owrt-archive/local-repo');BASE=ROOT/'private/dnsmasq-e21245d2';PROFILE=BASE/'profile-upload';sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
training=json.loads((BASE/'training-profile.json').read_text());gen=BASE/'ci39047311771/artifact/manifest.json';m=json.loads(gen.read_text());spec=json.loads((ROOT/'manifests/dnsmasq-pgo-generate-e21245d2.json').read_text())
assert training['status']=='training-complete-unqualified' and training['scene_count']==11 and training['profile_count']==50
assert training['source_commit']==spec['source_commit'] and training['source_digest']==spec['source_digest']
assert training['ci_build']['sha256']==sha(gen) and training['generate_elf']['sha256']==m['elf']['sha256']
profile=BASE/'training.profdata';assert sha(profile)==training['merged_profile']['sha256'] and profile.stat().st_size==training['merged_profile']['bytes']
name='dnsmasq-'+spec['source_commit'][:8]+'-'+sha(profile)+'.profdata'
asset=PROFILE/name;assert not asset.exists();asset.write_bytes(profile.read_bytes())
spec.pop('instrumentation_budget');spec['pgo_stage']='candidate-use';spec['qualification']='Unqualified integrated v0.2.2 candidate; actual final ELF must pass full runtime and unified device acceptance before any publication.'
spec['pgo'].pop('profile_output_dir');spec['pgo'].update(profile_url='https://github.com/WenliangCao/owrt-control-plane-rs/releases/download/dnsmasq-k-pgo-inputs-20261017/'+name,profile_sha256=sha(asset),profile_bytes=asset.stat().st_size,training={'generator_manifest_sha256':sha(gen),'generator_elf_sha256':m['elf']['sha256'],'training_receipt_sha256':sha(BASE/'training-profile.json')})
path=ROOT/'manifests/dnsmasq-pgo-use-e21245d2.json';path.open('x').write(json.dumps(spec,indent=2)+'\n')
print(json.dumps({'asset':str(asset),'name':name,'bytes':asset.stat().st_size,'sha256':sha(asset),'spec':str(path)},indent=2))
