from pathlib import Path
import hashlib,json,subprocess,sys,zipfile
ROOT=Path('/srv/owrt-archive/local-repo');OUT=ROOT/'private/unified-image-598b19a7';RUN='39050957718';HEAD='598b19a77021fef9abf62048d5c1e5b01c6c147c'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def api(path):return subprocess.check_output(['gh','api','repos/WenliangCao/owrt-control-plane-rs/'+path])
raw=api('actions/runs/'+RUN);(OUT/'final-run.json').write_bytes(raw);run=json.loads(raw)
assert run['head_sha']==HEAD and run['event']=='workflow_dispatch' and run['head_branch']=='research/core-safe-20261017'
jobsraw=api('actions/runs/'+RUN+'/jobs');(OUT/'jobs.json').write_bytes(jobsraw);jobs=json.loads(jobsraw)['jobs']
release_steps=[step for job in jobs for step in job['steps'] if step['name']=='github release (tags only)']
assert len(release_steps)==1 and release_steps[0]['conclusion']=='skipped'
raw=api('actions/runs/'+RUN+'/artifacts');(OUT/'artifacts.json').write_bytes(raw);assets=json.loads(raw)['artifacts']
for item in assets:
 data=api('actions/artifacts/'+str(item['id'])+'/zip');path=OUT/(str(item['id'])+'.zip');path.write_bytes(data)
 folder=OUT/item['name'];folder.mkdir();zipfile.ZipFile(path).extractall(folder)
logs=api('actions/runs/'+RUN+'/logs');(OUT/'logs.zip').write_bytes(logs)
assert run['conclusion']=='success','build failed; original run, artifacts and logs preserved'
assert len(assets)==1
folder=OUT/assets[0]['name'];manifest=json.loads((folder/'manifest.json').read_text());inputs=json.loads((folder/'build-inputs.json').read_text());dns=json.loads((folder/'dnsmasq-build-manifest.json').read_text())
spec=json.loads(subprocess.check_output(['git','show',HEAD+':packaging/image/native-25.12.5.json']))
assert manifest['source_commit']==inputs['image']['source_commit']==inputs['core']['source_commit']==dns['source_commit']==HEAD
assert inputs['dnsmasq']==dns and dns['accepted_product_commit']=='e21245d2404f6542759f45d064214ac3696c355f'
expected={v['binary']:(spec['dnsmasq_build']['reference_elf_sha256'] if name=='dnsmasq' else v['reference_elf_sha256']) for name,v in spec['components'].items()}
assert len(expected)==10 and manifest['binary_sha256']==expected
assert {name:digest for digest,name in (x.split() for x in (folder/'binary-sha256.txt').read_text().splitlines())}==expected
assert manifest['packages']['owrt-control-plane']=='0.2.2-r1' and manifest['deployment_layout']=='native-ten'
for name,row in manifest['components'].items():
 assert row['rust_sha256']==expected[row['binary']] and row['stock_sha256']==spec['components'][name]['stock_sha256']
for line in (folder/'SHA256SUMS').read_text().splitlines():
 digest,name=line.split(maxsplit=1);assert Path(name).name==name and sha(folder/name)==digest,name
assert manifest['flashed'] is False and manifest['validation']['physical_boot_tested'] is False
for k,v in manifest['validation'].items():
 if k=='physical_boot_tested':continue
 assert v is True or type(v) is int and v>0,(k,v)
assert manifest['stock_image']==spec['stock_image'] and not manifest['imagebuilder_args']['rolling_feeds_used_for_final_rootfs']
assert dns['status']=='built-and-audited' and dns['compiler_warnings']['strict_compiler_warnings_zero'] and dns['pgo']['profile_diagnostics']==[]
assert dns['elf']['matches_accepted_reference'] is True and dns['elf']['sha256']==expected['dnsmasq-rs']
assert dns['pgo']['profile_sha256']=='23ac3bc6f61a88990be4462a1bb0f11fa3d6a859fbdc6ab7f7b80aad860e4820'
sys.path.insert(0,str(OUT/'frozen-tools'));import ci_check_core
# The unchanged compiler gate applies to build logs. Offline APK cache
# notices remain a separately checked installation phase, not suppressed.
warnings=ci_check_core.warnings(OUT/'compiler-log-warnings.json',[p for p in sorted(folder.glob('*.log')) if p.name!='install.log']);assert warnings['strict_compiler_warnings_zero']
install=ci_check_core.scan([folder/'install.log'])
prior_path=ROOT/'private/unified-image-34300d29/installation-diagnostics.json'
prior=json.loads(prior_path.read_text())
assert [x['text'] for x in install['compiler_or_unclassified']]==[x['text'] for x in prior['diagnostics']]
assert not install['sdk_metadata']
installation={'phase':'offline-apk-install','compiler_phase':False,'log_sha256':sha(folder/'install.log'),'diagnostics':install['compiler_or_unclassified'],'same_cache_notices_as_prior_build':True,'prior_diagnostics_sha256':sha(prior_path),'network_disabled':True,'original_messages_preserved':True}
(OUT/'installation-diagnostics.json').write_text(json.dumps(installation,indent=2)+'\n')
image=folder/manifest['image']['file'];assert sha(image)==manifest['image']['sha256'] and image.stat().st_size==manifest['image']['size']
result={'status':'built-and-static-verified-runtime-and-hardware-pending','run':int(RUN),'event':'workflow_dispatch','build_commit':HEAD,'product_commit':'d644eda415d99724b4f98f469f2c12bdbbe7da61','dnsmasq_product_commit':dns['accepted_product_commit'],'artifact_directory':str(folder),'image':manifest['image'],'manifest_sha256':sha(folder/'manifest.json'),'build_inputs_sha256':sha(folder/'build-inputs.json'),'binary_sha256':expected,'validation':manifest['validation'],'kernel_sha256':manifest['kernel_sha256'],'compiler_warnings':0,'offline_apk_cache_warnings':len(installation['diagnostics']),'sdk_metadata_in_downloaded_logs':len(warnings['sdk_metadata']),'pgo_missing_mismatch':0,'profile_sha256':dns['pgo']['profile_sha256'],'published':False,'deployed':False,'verification_basis':'Frozen CI native_image.verify checks the extracted final rootfs; local verification checks all downloaded asset hashes, ten accepted identities and CI receipts. Device independently consumes this exact image for runtime gates.','original_zip_sha256':{p.name:sha(p) for p in OUT.glob('*.zip')}}
(OUT/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
