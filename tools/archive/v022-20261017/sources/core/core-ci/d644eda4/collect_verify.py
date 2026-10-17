from pathlib import Path
import hashlib,json,subprocess,zipfile,re
ROOT=Path('/srv/owrt-archive/local-repo');OUT=ROOT/'private/core-ci/d644eda4';RUN='39050152457';HEAD='2b66090994bdcb3771594efbd1e212cfe73874c4'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def api(path):return subprocess.check_output(['gh','api','repos/WenliangCao/owrt-control-plane-rs/'+path])
raw=api('actions/runs/'+RUN);(OUT/'run.json').write_bytes(raw);run=json.loads(raw);assert run['head_sha']==HEAD and run['event']=='push'
raw=api('actions/runs/'+RUN+'/artifacts');(OUT/'artifacts.json').write_bytes(raw);assets=json.loads(raw)['artifacts'];assert len(assets)==2
for item in assets:
 side='host' if item['name'].startswith('core-host-') else 'target';data=api('actions/artifacts/'+str(item['id'])+'/zip');path=OUT/(side+'.zip');path.write_bytes(data);folder=OUT/side;folder.mkdir();zipfile.ZipFile(path).extractall(folder)
assert run['conclusion']=='success','CI failed; full artifacts retained'
host=json.loads((OUT/'host/core-host-check.json').read_text());target=json.loads((OUT/'target/core-target-check.json').read_text())
for report in [host,target]:assert report['source_commit']==HEAD and report['status']=='passed' and report['warnings']['strict_compiler_warnings_zero']
old=json.loads((OUT/'prior-nine-sha256.json').read_text())
frozen=json.loads(subprocess.check_output(['git','show','34300d295e95febbebbe4c2f62e2befbd6d71b17:packaging/image/native-25.12.5.json']))
assert old=={v['binary']:v['reference_elf_sha256'] for k,v in frozen['components'].items() if k!='dnsmasq'}
new=target['binary_sha256'];assert set(new)==set(old)
assert {k:v for k,v in new.items() if k!='procd-rs'}=={k:v for k,v in old.items() if k!='procd-rs'}
assert new['procd-rs']!=old['procd-rs']
for name,digest in new.items():
 p=OUT/'target/core-candidates'/name;assert sha(p)==digest;p.chmod(0o755)
text=(OUT/'host/test-procd.log').read_text();assert re.search(r'test proc::tests::reap_any_collects_an_exited_inittab_session \.\.\. ok',text)
assert host['benchmark_returncode']==0
result={'status':'procd-ci-qualified-runtime-R71-R83-pending','run':int(RUN),'ci_head':HEAD,'product_fix':'d644eda415d99724b4f98f469f2c12bdbbe7da61','host_component_count':len(host['commands']),'host_warnings':0,'target_warnings':0,'benchmark_passed':True,'new_regression':'proc::tests::reap_any_collects_an_exited_inittab_session passed using real setsid spawn_tty subprocess','binary_sha256':new,'other_eight_elfs_unchanged':True,'procd':{'path':str(OUT/'target/core-candidates/procd-rs'),'sha256':new['procd-rs'],'bytes':(OUT/'target/core-candidates/procd-rs').stat().st_size},'host_manifest_sha256':sha(OUT/'host/core-host-check.json'),'target_manifest_sha256':sha(OUT/'target/core-target-check.json'),'dnsmasq_pgo_retrained':False,'release_image_dispatched':False}
(OUT/'qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
