from pathlib import Path
import collections,fcntl,hashlib,json,os,re,subprocess,time
root=Path('/home/ubuntu/dnsmasq-perf-20261015');p=root/'correctness/private';source=root/'root/source-cached-hit-9e';out=p/'cached-hit-9e-unit-run';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();j=lambda f:json.loads(f.read_text())
assert j(p/'cached-hit-9e-related-ready.json')=={'source_commit':'9e8459dd704d339b10596721eaa2d3bef1f943c1','state':'five-original-related-groups-complete'};raw=j(out/'result.json');assert raw['source_commit']=='9e8459dd704d339b10596721eaa2d3bef1f943c1' and raw['source']==str(source)
assert sha(p/'e-unit-run/result.json')=='c3dfca57ca73e7ef9f7aa14382b9d964b109c541ede9dc88fee267bae952b52e';old=j(p/'e-unit-run/result.json');assert len(raw['gates'])==len(old['gates'])==5
names_seen={};verified=[]
for original,gate in zip(old['gates'],raw['gates']):
 expected=[a.replace('root/source-e','root/source-cached-hit-9e').replace('/e-tests/','/cached-hit-9e-tests/').replace('/e-allocation-build/','/cached-hit-9e-allocation-build/') for a in original['argv']];assert gate['argv']==expected and gate['gate']==original['gate'] and gate['exit']==0
 name=gate['gate'];log=out/(name+'.log');assert sha(log)==gate['log_sha256'];text=log.read_text();summaries=re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',text,re.M);assert len(summaries)==1;passed,failed,ignored,measured,filtered=map(int,summaries[0]);assert failed==measured==0
 passednames=re.findall(r'^test (.+) \.\.\. ok$',text,re.M);ignorednames=re.findall(r'^test (.+) \.\.\. ignored(?:,.*)?$',text,re.M);rows=[(n,'ok') for n in passednames]+[(n,'ignored') for n in ignorednames];assert len(rows)==passed+ignored and len({n for n,_ in rows})==len(rows);assert collections.Counter(status for _,status in rows)=={**({'ok':passed} if passed else {}),**({'ignored':ignored} if ignored else {})}
 binaries=[Path(a) for a in gate['argv'] if a.endswith(('/lib-dnsmasq_rs','/bin-dnsmasq-rs','/hosts_allocations'))];assert len(binaries)==1;binary=binaries[0];assert sha(binary)==gate['binary_sha256']
 listing=out/(name+'.list');assert not listing.exists();r=subprocess.run(gate['argv']+['--list'],capture_output=True);listing.write_bytes(r.stdout);(out/(name+'.list.stderr')).write_bytes(r.stderr);assert r.returncode==0,r.stderr.decode();listed=re.findall(r'^(.+): test\s*$',r.stdout.decode(),re.M);assert len(listed)==len(set(listed)) and set(listed)=={n for n,_ in rows}
 verified.append({**gate,'passed':passed,'failed':failed,'ignored':ignored,'listed_tests':len(listed),'listed_names_match_actual_log':True,'listing_sha256':sha(listing)});names_seen[name]={n for n,status in rows if status=='ok'}
counts={g['gate']:g['passed'] for g in verified};total_passed=sum(counts.values())
expected_added={'dns::lease_names::tests::direct_slice_lookup_keeps_order_and_expiry_across_retained_views', 'dns::cache::tests::inline_address_details_preserve_record_bytes_and_snapshot_visibility', 'dns::cache::tests::snapshot_metadata_updates_keep_target_and_authority_independent', 'dns::edns_policy::tests::ecs_absence_uses_declared_additional_count_and_accepts_bad_questions'};assert expected_added<=names_seen['lib']
baseline=p/'post185-combined-related-verified.json';assert sha(baseline)=='ff6e767b30e3cde7a68c0640abf61fc4c3ee45bdd59a537db475369e0b311255'
for group in j(baseline)['groups']:assert sha(p/'post185-combined-unit-run'/(group['gate']+'.log'))==group['log_sha256']
old_log=(p/'post185-combined-unit-run/lib.log').read_text();old_names={n for n,status in re.findall(r'^test (.+) \.\.\. (ok|ignored|FAILED)\s*$',old_log,re.M) if status=='ok'};assert len(old_names)==840 and names_seen['lib']-old_names==expected_added and not(old_names-names_seen['lib'])
for name in ['bin','allocations','lib-ignored-live','bin-ignored-live']:
 old_names={n for n,status in re.findall(r'^test (.+) \.\.\. (ok|ignored|FAILED)\s*$',(p/'post185-combined-unit-run'/(name+'.log')).read_text(),re.M) if status=='ok'};assert names_seen[name]==old_names
build=j(p/'cached-hit-9e-tests/build.json');alloc=j(p/'cached-hit-9e-allocation-build/build.json');assert build['source']==alloc['source']==str(source) and build['kind']=='tests' and build['opt_level']=='3' and build['features']=='';assert build['rustflags']==alloc['rustflags']
for a in build['artifacts']:
 f=p/'cached-hit-9e-tests'/a['path'];assert sha(f)==a['sha256'] and f.stat().st_size==a['bytes']
assert sha(p/'cached-hit-9e-allocation-build/hosts_allocations')==alloc['sha256'];assert (p/'cached-hit-9e-allocation-build/hosts_allocations').stat().st_size==alloc['bytes']
manifest=p/'cached-hit-9e-source-files.json';assert sha(manifest)=='2030130c1084fb95e3c973b194b24b761fa48f31d36e3456dd54944e53c37cad';files=j(manifest);identity=source/'research-git-identity.json';assert sha(identity)=='96b05c6a3db323415968341b2852cc4d04ed8a612ea81fb193a26fd27b430b20';git=j(identity);assert len(files)==179 and git['commit']==raw['source_commit']
for name,digest in files.items():
 data=(source/name).read_bytes();assert hashlib.sha256(data).hexdigest()==digest;assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==git['git_blob_sha1'][name]
assert sha(p/'image-runner/dnsmasq-image-runner')=='38ab1fe2268a4efdd6dbf718d528f89cf2bbfb8d5e877f233b3752c023e81cfd';assert sha(Path('/home/ubuntu/dnsmasq-image-bases/d5dd3ffe9243f02d308c08eb76dd4feb1a65da6cd10612808251d2cde5eb3f6c/usr/sbin/dnsmasq'))=='097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87'
launch=j(p/'cached-hit-9e-related-launch.json');assert not Path('/proc/'+str(launch['pid'])).exists()
research=[]
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit():continue
 try:
  state=(proc/'stat').read_text().rsplit(')',1)[1].split()[0];cmd=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode(errors='replace')
  if state!='Z' and str(root) in cmd:research.append({'pid':int(proc.name),'command':cmd})
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
assert not research,research
locks=[]
for path in ['/home/ubuntu/sdk/openwrt-sdk-25.12.5-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64/.owrt-dnsmasq-build.lock','/home/ubuntu/dnsmasq-perf-20261015/root/private/native-hit-build.lock','/home/ubuntu/dnsmasq-cargo-target/.dnsmasq-build.lock']:
 with Path(path).open('a') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(path);fcntl.flock(f,fcntl.LOCK_UN)
report={'status':'PASS_FRESH_ORIGINAL_FIVE_RELATED_GROUPS_AND_QUIET','source_commit':raw['source_commit'],'source':str(source),'total_passed':total_passed,'groups':verified,'added_tests_exactly':sorted(expected_added),'all_original6ab_passed_test_names_retained':True,'remaining4group_names_identical_to6ab':True,'source_files_rehashed':179,'source_manifest_sha256':sha(manifest),'git_identity_sha256':sha(identity),'unit_raw_sha256':sha(out/'result.json'),'build_receipts':{'tests':{'sha256':sha(p/'cached-hit-9e-tests/build.json'),'value':build},'allocations':{'sha256':sha(p/'cached-hit-9e-allocation-build/build.json'),'value':alloc}},'preflight_sha256':sha(p/'cached-hit-9e-related-preflight.json'),'launch_sha256':sha(p/'cached-hit-9e-related-launch.json'),'original_E_raw_receipt_sha256':sha(p/'e-unit-run/result.json'),'wrapper_exited':True,'research':research,'locks_available':locks,'quiet_epoch':time.time(),'shipping_SDK_built':False,'full44_or_corpora_run':False,'performance_accepted':False,'scope':'Original5groups fromfreshsame-source binaries. Listing calls only enumerate tests and do not rerun them. No product/Cexpectation change; no fullqualification inheritance.'}
f=p/'cached-hit-9e-related-verified.json';assert not f.exists();f.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'path':str(f),'sha256':sha(f),'status':report['status'],'counts':counts,'total_passed':total_passed,'source_files_rehashed':179,'quiet_epoch':report['quiet_epoch']}))
